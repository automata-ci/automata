//! Secure runner-side enrollment and local TLS credential custody.

use std::{
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use rustls::pki_types::pem::PemObject as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use crate::{
    cli::EnrollArgs,
    product::{RunnerProductConfig, SecretSource},
};

const REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";
const MAX_TOKEN_BYTES: usize = 128;
const MAX_RESPONSE_BYTES: u64 = 512 * 1_024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn enroll(args: &EnrollArgs) -> Result<()> {
    validate_name(&args.name)?;
    let config = RunnerProductConfig::load(&args.config)
        .context("runner enrollment could not load the product configuration")?;
    let destinations = CredentialDestinations::from_config(&config)?;
    let prepared_destinations = destinations.prepare()?;
    let token = load_token(args)?;
    let origin = enrollment_origin(&args.server)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("runner enrollment could not generate the local private key")?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, config.runner_id().to_string());
    let mut parameters = CertificateParams::default();
    parameters.distinguished_name = distinguished_name;
    let csr = parameters
        .serialize_request(&key)
        .context("runner enrollment could not create a certificate request")?
        .pem()
        .context("runner enrollment could not encode the certificate request")?;
    let endpoint = origin
        .join(REDEEM_PATH)
        .context("runner enrollment endpoint is invalid")?;
    let body = RedeemRequest {
        token: token.as_str(),
        runner_name: &args.name,
        capabilities: config.inventory(),
        csr_pem: &csr,
    };
    let client = Client::builder()
        .https_only(origin.scheme() == "https")
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .retry(reqwest::retry::never())
        .no_proxy()
        .build()
        .context("runner enrollment HTTP client could not be configured")?;
    let request_body = Zeroizing::new(
        serde_json::to_vec(&body).context("runner enrollment request could not be encoded")?,
    );
    let response = client
        .post(endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::from_owner(request_body))
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("runner enrollment request failed")?;
    let mut response = response;
    if response.status() != StatusCode::CREATED {
        let status = response.status();
        bail!("runner enrollment was rejected with HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES)
    {
        bail!("runner enrollment response exceeded its size limit");
    }
    if !response.headers().get_all(header::CONTENT_TYPE).iter().eq([
        &header::HeaderValue::from_static("application/json; charset=utf-8"),
    ]) {
        bail!("runner enrollment response has an invalid content type");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .context("runner enrollment response could not be read")?
    {
        if bytes.len().saturating_add(chunk.len())
            > usize::try_from(MAX_RESPONSE_BYTES).expect("response limit fits usize")
        {
            bail!("runner enrollment response exceeded its size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let enrolled: RedeemResponse =
        serde_json::from_slice(&bytes).context("runner enrollment returned an invalid response")?;
    validate_response(&config, &key, &enrolled)?;
    let private_key = Zeroizing::new(key.serialize_pem());
    prepared_destinations.persist(
        enrolled.server_ca_pem.as_bytes(),
        enrolled.certificate_chain_pem.as_bytes(),
        private_key.as_bytes(),
    )?;
    println!(
        "enrolled runner {} in group {} (certificate expires at {})",
        enrolled.runner_id, enrolled.runner_group, enrolled.certificate_expires_at_seconds
    );
    Ok(())
}

fn load_token(args: &EnrollArgs) -> Result<Zeroizing<String>> {
    let bytes = if let Some(path) = &args.token_file {
        SecretSource::File { path: path.clone() }
            .read_scalar(MAX_TOKEN_BYTES)
            .context("runner enrollment token file is unavailable")?
    } else if std::env::var_os("AUTOMATA_RUNNER_ENROLLMENT_TOKEN").is_some() {
        SecretSource::Environment {
            name: "AUTOMATA_RUNNER_ENROLLMENT_TOKEN".to_owned(),
        }
        .read_scalar(MAX_TOKEN_BYTES)
        .context("runner enrollment token environment value is unavailable")?
    } else {
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take(u64::try_from(MAX_TOKEN_BYTES + 2).expect("token bound fits u64"))
            .read_to_end(&mut bytes)
            .context("runner enrollment token could not be read from stdin")?;
        while bytes
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            bytes.pop();
        }
        bytes
    };
    if bytes.is_empty()
        || bytes.len() > MAX_TOKEN_BYTES
        || bytes.iter().any(u8::is_ascii_whitespace)
    {
        bail!("runner enrollment token is invalid");
    }
    String::from_utf8(Vec::from(bytes.as_slice()))
        .map(Zeroizing::new)
        .context("runner enrollment token is invalid")
}

fn enrollment_origin(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("runner enrollment server URL is invalid")?;
    let secure_transport = url.scheme() == "https";
    let loopback_development = url.scheme() == "http"
        && url.host().is_some_and(|host| {
            matches!(host, url::Host::Ipv4(address) if address.is_loopback())
                || matches!(host, url::Host::Ipv6(address) if address.is_loopback())
        });
    if (!secure_transport && !loopback_development)
        || url.cannot_be_a_base()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("runner enrollment requires an exact HTTPS origin or literal loopback HTTP origin");
    }
    Ok(url)
}

fn validate_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("runner name is invalid");
    }
    Ok(())
}

fn validate_response(
    config: &RunnerProductConfig,
    key: &KeyPair,
    response: &RedeemResponse,
) -> Result<()> {
    let expected_group = automata_ci_core::RunnerGroup::new(&response.runner_group)
        .context("runner enrollment returned an invalid group")?;
    if response.runner_id != config.runner_id().as_uuid()
        || response.control_endpoint != config.control_endpoint().to_string()
        || config.inventory().groups() != &std::collections::BTreeSet::from([expected_group])
        || response.certificate_chain_pem.is_empty()
        || response.server_ca_pem.is_empty()
        || response.certificate_expires_at_seconds <= 0
    {
        bail!("runner enrollment response does not match the local configuration");
    }
    validate_certificate_chain(key, response)?;
    let mut server_roots = rustls::RootCertStore::empty();
    let mut server_root_count = 0_usize;
    for certificate in
        rustls::pki_types::CertificateDer::pem_slice_iter(response.server_ca_pem.as_bytes())
    {
        let certificate = certificate.context("runner enrollment returned invalid server roots")?;
        let (remainder, parsed) = parse_x509_certificate(certificate.as_ref())
            .context("runner enrollment returned invalid server roots")?;
        if !remainder.is_empty()
            || !parsed.validity().is_valid()
            || !parsed
                .basic_constraints()
                .context("runner enrollment returned invalid server root constraints")?
                .is_some_and(|constraints| constraints.value.ca)
        {
            bail!("runner enrollment returned an unusable server root");
        }
        server_roots
            .add(certificate)
            .context("runner enrollment returned invalid server roots")?;
        server_root_count += 1;
    }
    if server_root_count == 0 {
        bail!("runner enrollment returned no server roots");
    }
    Ok(())
}

fn validate_certificate_chain(key: &KeyPair, response: &RedeemResponse) -> Result<()> {
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(
        response.certificate_chain_pem.as_bytes(),
    )
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("runner enrollment returned an invalid certificate chain")?;
    let [leaf_der, issuer_der] = certificates.as_slice() else {
        bail!("runner enrollment returned an invalid certificate chain");
    };
    let (leaf_remainder, leaf) = parse_x509_certificate(leaf_der.as_ref())
        .context("runner enrollment returned an invalid leaf certificate")?;
    let (issuer_remainder, issuer) = parse_x509_certificate(issuer_der.as_ref())
        .context("runner enrollment returned an invalid issuing certificate")?;
    let leaf_usage = leaf
        .key_usage()
        .context("runner enrollment returned invalid leaf key usage")?
        .context("runner enrollment leaf certificate has no key usage")?;
    let leaf_extended_usage = leaf
        .extended_key_usage()
        .context("runner enrollment returned invalid leaf extended key usage")?
        .context("runner enrollment leaf certificate has no extended key usage")?;
    let issuer_constraints = issuer
        .basic_constraints()
        .context("runner enrollment returned invalid issuer constraints")?
        .context("runner enrollment issuer has no basic constraints")?;
    let issuer_usage = issuer
        .key_usage()
        .context("runner enrollment returned invalid issuer key usage")?
        .context("runner enrollment issuer has no key usage")?;
    let expected_common_name = response.runner_id.hyphenated().to_string();
    if !leaf_remainder.is_empty()
        || !issuer_remainder.is_empty()
        || leaf.public_key().subject_public_key.data.as_ref() != key.public_key_raw()
        || leaf.issuer() != issuer.subject()
        || !leaf.validity().is_valid()
        || !issuer.validity().is_valid()
        || leaf.validity().not_after.timestamp() != response.certificate_expires_at_seconds
        || leaf
            .subject()
            .iter_common_name()
            .next()
            .and_then(|name| name.as_str().ok())
            != Some(expected_common_name.as_str())
        || leaf
            .basic_constraints()
            .context("runner enrollment returned invalid leaf constraints")?
            .is_some_and(|constraints| constraints.value.ca)
        || !leaf_usage.value.digital_signature()
        || !leaf_extended_usage.value.client_auth
        || leaf_extended_usage.value.server_auth
        || !issuer_constraints.value.ca
        || !issuer_usage.value.key_cert_sign()
        || leaf.verify_signature(Some(issuer.public_key())).is_err()
    {
        bail!("runner enrollment certificate chain does not match the request");
    }
    Ok(())
}

struct CredentialDestinations {
    server_roots: PathBuf,
    certificate_chain: PathBuf,
    private_key: PathBuf,
}

impl CredentialDestinations {
    fn from_config(config: &RunnerProductConfig) -> Result<Self> {
        fn file(source: &SecretSource) -> Result<PathBuf> {
            let SecretSource::File { path } = source else {
                bail!("runner enrollment requires file-backed TLS credential destinations");
            };
            Ok(path.clone())
        }
        Ok(Self {
            server_roots: file(config.tls().server_roots())?,
            certificate_chain: file(config.tls().certificate_chain())?,
            private_key: file(config.tls().private_key())?,
        })
    }

    fn prepare(&self) -> Result<PreparedCredentialDestinations> {
        if self.server_roots == self.certificate_chain
            || self.server_roots == self.private_key
            || self.certificate_chain == self.private_key
        {
            bail!("runner TLS credential destinations must be distinct");
        }
        PreparedCredentialDestinations::new(self)
    }
}

#[cfg(unix)]
struct PreparedDestination {
    parent: rustix::fd::OwnedFd,
    name: std::ffi::OsString,
}

#[cfg(unix)]
struct PreparedCredentialDestinations {
    server_roots: PreparedDestination,
    certificate_chain: PreparedDestination,
    private_key: PreparedDestination,
}

#[cfg(unix)]
impl PreparedCredentialDestinations {
    fn new(destinations: &CredentialDestinations) -> Result<Self> {
        Ok(Self {
            server_roots: prepare_destination(&destinations.server_roots)?,
            certificate_chain: prepare_destination(&destinations.certificate_chain)?,
            private_key: prepare_destination(&destinations.private_key)?,
        })
    }

    fn persist(&self, roots: &[u8], chain: &[u8], key: &[u8]) -> Result<()> {
        publish_credential(&self.server_roots, roots, 0o644)?;
        if let Err(error) = publish_credential(&self.certificate_chain, chain, 0o644) {
            remove_published(&self.server_roots);
            return Err(error);
        }
        if let Err(error) = publish_credential(&self.private_key, key, 0o600) {
            remove_published(&self.certificate_chain);
            remove_published(&self.server_roots);
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn prepare_destination(path: &Path) -> Result<PreparedDestination> {
    use std::path::Component;

    use rustix::fs::{Mode, OFlags, fstat, mkdirat, openat};

    if !path.is_absolute() {
        bail!("runner credential destination must be absolute");
    }
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(value) => Some(Ok(value.to_os_string())),
            _ => Some(Err(())),
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|()| anyhow::anyhow!("runner credential destination is invalid"))?;
    let (name, parents) = components
        .split_last()
        .context("runner credential destination has no file name")?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut parent = rustix::fs::open("/", directory_flags, Mode::empty())
        .context("runner credential root could not be opened")?;
    require_trusted_directory(&parent)?;
    for component in parents {
        parent = match openat(&parent, component, directory_flags, Mode::empty()) {
            Ok(directory) => directory,
            Err(rustix::io::Errno::NOENT) => {
                mkdirat(&parent, component, Mode::from_raw_mode(0o700))
                    .context("runner credential directory could not be created")?;
                rustix::fs::fsync(&parent)
                    .context("runner credential directory could not be synchronized")?;
                openat(&parent, component, directory_flags, Mode::empty())
                    .context("runner credential directory could not be opened")?
            }
            Err(error) => {
                return Err(error).context("runner credential directory is unavailable");
            }
        };
        require_trusted_directory(&parent)?;
    }
    match openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Err(rustix::io::Errno::NOENT) => {}
        Ok(existing) => {
            let _metadata = fstat(&existing);
            bail!("runner TLS credential destination already exists");
        }
        Err(error) => {
            return Err(error).context("runner TLS credential destination is unavailable");
        }
    }
    Ok(PreparedDestination {
        parent,
        name: name.clone(),
    })
}

#[cfg(unix)]
fn require_trusted_directory(directory: &rustix::fd::OwnedFd) -> Result<()> {
    use rustix::fs::{FileType, fstat};

    let metadata =
        fstat(directory).context("runner credential directory could not be inspected")?;
    let effective_user = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || (!matches!(metadata.st_uid, 0) && metadata.st_uid != effective_user)
        || metadata.st_mode & 0o022 != 0
    {
        bail!("runner credential directory is not trusted");
    }
    Ok(())
}

#[cfg(unix)]
fn publish_credential(destination: &PreparedDestination, bytes: &[u8], mode: u32) -> Result<()> {
    use std::{fs::File, io::Write as _};

    use rustix::fs::{AtFlags, Mode, OFlags, fchmod, linkat, openat, unlinkat};

    let staging_name = format!(".automata-enroll-{}.tmp", Uuid::new_v4());
    let staging = openat(
        &destination.parent,
        staging_name.as_str(),
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(mode),
    )
    .context("temporary runner credential could not be created")?;
    let mut published = false;
    let result = (|| -> Result<()> {
        fchmod(&staging, Mode::from_raw_mode(mode))
            .context("runner credential permissions could not be set")?;
        let mut file = File::from(staging);
        file.write_all(bytes)
            .context("runner credential could not be written")?;
        file.sync_all()
            .context("runner credential could not be synchronized")?;
        drop(file);
        linkat(
            &destination.parent,
            staging_name.as_str(),
            &destination.parent,
            &destination.name,
            AtFlags::empty(),
        )
        .context("runner credential destination already exists or is unavailable")?;
        published = true;
        Ok(())
    })();
    let cleanup = unlinkat(&destination.parent, staging_name.as_str(), AtFlags::empty())
        .context("temporary runner credential could not be removed");
    let sync_result = rustix::fs::fsync(&destination.parent)
        .context("runner credential directory could not be synchronized");
    let outcome = result.and(cleanup).and(sync_result);
    if outcome.is_err() && published {
        remove_published(destination);
    }
    outcome
}

#[cfg(unix)]
fn remove_published(destination: &PreparedDestination) {
    let _ignored = rustix::fs::unlinkat(
        &destination.parent,
        &destination.name,
        rustix::fs::AtFlags::empty(),
    );
    let _ignored = rustix::fs::fsync(&destination.parent);
}

#[cfg(not(unix))]
struct PreparedCredentialDestinations;

#[cfg(not(unix))]
impl PreparedCredentialDestinations {
    fn new(_destinations: &CredentialDestinations) -> Result<Self> {
        bail!("runner enrollment credential publication is supported only on Unix hosts")
    }

    fn persist(&self, _roots: &[u8], _chain: &[u8], _key: &[u8]) -> Result<()> {
        unreachable!("non-Unix enrollment is rejected during credential preflight")
    }
}

#[derive(Serialize)]
struct RedeemRequest<'a> {
    token: &'a str,
    runner_name: &'a str,
    capabilities: &'a automata_ci_core::RunnerCapabilities,
    csr_pem: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemResponse {
    runner_id: Uuid,
    runner_group: String,
    control_endpoint: String,
    certificate_chain_pem: String,
    server_ca_pem: String,
    certificate_expires_at_seconds: i64,
}

#[cfg(test)]
mod tests {
    use super::{CredentialDestinations, enrollment_origin};

    #[test]
    fn enrollment_origin_requires_tls_except_for_literal_loopback() {
        assert!(enrollment_origin("https://ci.example.test").is_ok());
        assert!(enrollment_origin("http://127.0.0.1:8080").is_ok());
        assert!(enrollment_origin("http://[::1]:8080").is_ok());
        assert!(enrollment_origin("http://localhost:8080").is_err());
        assert!(enrollment_origin("http://ci.example.test").is_err());
        assert!(enrollment_origin("https://ci.example.test/path").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn credential_preflight_and_publication_are_exclusive_and_owner_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::Builder::new()
            .prefix("runner-enrollment-")
            .tempdir_in(std::env::current_dir().expect("current directory"))
            .expect("trusted temporary root");
        let destinations = CredentialDestinations {
            server_roots: root.path().join("credentials/server-roots.pem"),
            certificate_chain: root.path().join("credentials/client-chain.pem"),
            private_key: root.path().join("credentials/client-key.pem"),
        };
        let prepared = destinations.prepare().expect("safe absent destinations");
        prepared
            .persist(b"roots", b"chain", b"private-key")
            .expect("exclusive credential publication");

        assert_eq!(
            std::fs::read(&destinations.private_key).expect("private key"),
            b"private-key"
        );
        assert_eq!(
            std::fs::metadata(&destinations.private_key)
                .expect("private key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(destinations.prepare().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn credential_preflight_rejects_aliases_and_symlinked_parents() {
        use std::os::unix::fs::symlink;

        let root = tempfile::Builder::new()
            .prefix("runner-enrollment-")
            .tempdir_in(std::env::current_dir().expect("current directory"))
            .expect("trusted temporary root");
        let same = root.path().join("same.pem");
        assert!(
            CredentialDestinations {
                server_roots: same.clone(),
                certificate_chain: same.clone(),
                private_key: same,
            }
            .prepare()
            .is_err()
        );

        let real = root.path().join("real");
        std::fs::create_dir(&real).expect("real directory");
        let alias = root.path().join("alias");
        symlink(&real, &alias).expect("directory symlink");
        assert!(
            CredentialDestinations {
                server_roots: alias.join("roots.pem"),
                certificate_chain: real.join("chain.pem"),
                private_key: real.join("key.pem"),
            }
            .prepare()
            .is_err()
        );
    }
}
