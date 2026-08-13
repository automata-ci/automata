use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::Stdio,
};

use automata_ci_execution::{EnvironmentProfileId, Sha256Digest};
use automata_ci_sandbox_guest::GUEST_PROTOCOL_VERSION;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const TEMPLATE_SCHEMA_VERSION: u16 = 1;
const MAX_TEMPLATE_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_HARDWARE_MODEL_BYTES: usize = 16 * 1024;
const MAX_ENTITLEMENTS_BYTES: usize = 16 * 1024;
const MIN_JOB_UID: u32 = 500;
const VIRTUALIZATION_ENTITLEMENT: &str = "com.apple.security.virtualization";

#[derive(Clone, Debug)]
pub(crate) struct VerifiedTemplate {
    pub(crate) profile_id: EnvironmentProfileId,
    pub(crate) manifest_digest: Sha256Digest,
    pub(crate) macos_version: String,
    pub(crate) macos_build: String,
    pub(crate) disk_image: PathBuf,
    pub(crate) auxiliary_storage: PathBuf,
    pub(crate) hardware_model_base64: String,
    pub(crate) guest_agent_digest: Sha256Digest,
    pub(crate) guest_port: u32,
    pub(crate) job_uid: u32,
    pub(crate) job_gid: u32,
    pub(crate) process_limit: u32,
    pub(crate) minimum_cpu_count: u32,
    pub(crate) minimum_memory_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplateManifest {
    schema_version: u16,
    profile_id: String,
    macos_version: String,
    macos_build: String,
    architecture: String,
    disk_image: RawArtifact,
    auxiliary_storage: RawArtifact,
    hardware_model_base64: String,
    guest_agent_sha256: Sha256Digest,
    guest_protocol: u16,
    guest_port: u32,
    job_uid: u32,
    job_gid: u32,
    process_limit: u32,
    minimum_cpu_count: u32,
    minimum_memory_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    path: PathBuf,
    sha256: Sha256Digest,
}

pub(crate) fn load_template(
    manifest_path: &Path,
    expected_digest: Sha256Digest,
) -> io::Result<VerifiedTemplate> {
    require_root_owned_immutable_file(manifest_path, false)?;
    let metadata = fs::metadata(manifest_path)?;
    if metadata.len() == 0 || metadata.len() > MAX_TEMPLATE_MANIFEST_BYTES {
        return Err(invalid());
    }
    let bytes = fs::read(manifest_path)?;
    if Sha256Digest::from_bytes(Sha256::digest(&bytes).into()) != expected_digest {
        return Err(invalid());
    }
    let raw: RawTemplateManifest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let hardware_model = BASE64
        .decode(&raw.hardware_model_base64)
        .map_err(|_| invalid())?;
    if raw.schema_version != TEMPLATE_SCHEMA_VERSION
        || raw.architecture != "arm64"
        || raw.guest_protocol != GUEST_PROTOCOL_VERSION
        || raw.guest_port <= 1_024
        || !supported_macos_version(&raw.macos_version)
        || raw.macos_version.len() > 64
        || raw.macos_build.is_empty()
        || raw.macos_build.len() > 64
        || hardware_model.is_empty()
        || hardware_model.len() > MAX_HARDWARE_MODEL_BYTES
        || raw.job_uid < MIN_JOB_UID
        || raw.job_gid < MIN_JOB_UID
        || raw.process_limit == 0
        || raw.process_limit > 1_000_000
        || raw.minimum_cpu_count == 0
        || raw.minimum_cpu_count > 1_000
        || raw.minimum_memory_bytes < 16 * 1024 * 1024
        || raw.minimum_memory_bytes > 1024 * 1024 * 1024 * 1024
        || !raw.minimum_memory_bytes.is_multiple_of(1024 * 1024)
    {
        return Err(invalid());
    }
    let profile_id = EnvironmentProfileId::new(raw.profile_id).map_err(|_| invalid())?;
    verify_artifact(&raw.disk_image)?;
    verify_artifact(&raw.auxiliary_storage)?;
    Ok(VerifiedTemplate {
        profile_id,
        manifest_digest: expected_digest,
        macos_version: raw.macos_version,
        macos_build: raw.macos_build,
        disk_image: raw.disk_image.path,
        auxiliary_storage: raw.auxiliary_storage.path,
        hardware_model_base64: raw.hardware_model_base64,
        guest_agent_digest: raw.guest_agent_sha256,
        guest_port: raw.guest_port,
        job_uid: raw.job_uid,
        job_gid: raw.job_gid,
        process_limit: raw.process_limit,
        minimum_cpu_count: raw.minimum_cpu_count,
        minimum_memory_bytes: raw.minimum_memory_bytes,
    })
}

fn supported_macos_version(version: &str) -> bool {
    let mut components = version.split('.');
    let Some(major_component) = components.next() else {
        return false;
    };
    let valid_component = |component: &str| {
        !component.is_empty()
            && component.len() <= 4
            && component.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !valid_component(major_component) {
        return false;
    }
    let Ok(major) = major_component.parse::<u32>() else {
        return false;
    };
    major >= 15 && components.all(valid_component)
}

fn verify_artifact(artifact: &RawArtifact) -> io::Result<()> {
    require_root_owned_immutable_file(&artifact.path, false)?;
    if sha256_file(&artifact.path)? != artifact.sha256 {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn verify_helper(
    path: &Path,
    digest: Sha256Digest,
    code_requirement: &str,
) -> io::Result<()> {
    require_root_owned_immutable_file(path, true)?;
    if sha256_file(path)? != digest {
        return Err(invalid());
    }
    let literal_requirement = format!("={code_requirement}");
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict=all", "-R", &literal_requirement, "--"])
        .arg(path)
        .env_clear()
        .status()?;
    if !status.success() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    verify_exact_entitlements(path)?;
    Ok(())
}

fn verify_exact_entitlements(path: &Path) -> io::Result<()> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["--display", "--xml", "--entitlements", "-", "--"])
        .arg(path)
        .env_clear()
        .output()?;
    let xml = [&output.stdout[..], &output.stderr[..]]
        .into_iter()
        .find_map(entitlements_xml);
    let Some(xml) = xml else {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    };
    let parsed = plist_to_json(xml, MAX_ENTITLEMENTS_BYTES)?;
    let entitlements: BTreeMap<String, bool> =
        serde_json::from_slice(&parsed).map_err(|_| invalid())?;
    if entitlements.len() != 1 || entitlements.get(VIRTUALIZATION_ENTITLEMENT) != Some(&true) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

pub(crate) fn plist_to_json(plist: &[u8], maximum_bytes: usize) -> io::Result<Vec<u8>> {
    if plist.is_empty() || plist.len() > maximum_bytes {
        return Err(invalid());
    }
    let mut plutil = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "-"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    plutil.stdin.take().ok_or_else(invalid)?.write_all(plist)?;
    let parsed = plutil.wait_with_output()?;
    if !parsed.status.success() || parsed.stdout.is_empty() || parsed.stdout.len() > maximum_bytes {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(parsed.stdout)
}

fn entitlements_xml(output: &[u8]) -> Option<&[u8]> {
    const XML_PREFIX: &[u8] = b"<?xml";
    if output.len() > MAX_ENTITLEMENTS_BYTES {
        return None;
    }
    output
        .windows(XML_PREFIX.len())
        .position(|window| window == XML_PREFIX)
        .map(|index| &output[index..])
}

fn require_root_owned_immutable_file(path: &Path, executable: bool) -> io::Result<()> {
    if !normalized_absolute_path(path) {
        return Err(invalid());
    }
    for parent in path.ancestors().skip(1) {
        let symlink = fs::symlink_metadata(parent)?;
        let metadata = fs::metadata(parent)?;
        if symlink.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
    }
    let symlink = fs::symlink_metadata(path)?;
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if symlink.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || mode & 0o022 != 0
        || (executable && mode & 0o111 == 0)
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn normalized_absolute_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && components.clone().next().is_some()
        && components.all(|component| matches!(component, Component::Normal(_)))
        && path.to_str().is_some()
}

pub(crate) fn sha256_file(path: &Path) -> io::Result<Sha256Digest> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::supported_macos_version;

    #[test]
    fn templates_require_macos_15_or_newer() {
        for supported in ["15", "15.0", "15.7.1", "26.0"] {
            assert!(supported_macos_version(supported));
        }
        for unsupported in ["14.7.6", "15.", "15beta", "macOS 15", ""] {
            assert!(!supported_macos_version(unsupported));
        }
    }
}
