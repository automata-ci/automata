//! Secure runner-side enrollment and local TLS credential custody.

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest::{Client, StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    cli::EnrollArgs,
    product::{RunnerProductConfig, SecretSource},
};

const REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";
const MAX_TOKEN_BYTES: usize = 128;
const MAX_RESPONSE_BYTES: u64 = 512 * 1_024;

pub(super) async fn enroll(args: &EnrollArgs) -> Result<()> {
    validate_name(&args.name)?;
    let config = RunnerProductConfig::load(&args.config)
        .context("runner enrollment could not load the product configuration")?;
    let destinations = CredentialDestinations::from_config(&config)?;
    destinations.require_absent()?;
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
        .build()
        .context("runner enrollment HTTP client could not be configured")?;
    let response = client
        .post(endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("runner enrollment request failed")?;
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
    let bytes = response
        .bytes()
        .await
        .map_err(reqwest::Error::without_url)
        .context("runner enrollment response could not be read")?;
    if bytes.len() > usize::try_from(MAX_RESPONSE_BYTES).expect("response limit fits usize") {
        bail!("runner enrollment response exceeded its size limit");
    }
    let enrolled: RedeemResponse =
        serde_json::from_slice(&bytes).context("runner enrollment returned an invalid response")?;
    validate_response(&config, &enrolled)?;
    destinations.persist(
        enrolled.server_ca_pem.as_bytes(),
        enrolled.certificate_chain_pem.as_bytes(),
        key.serialize_pem().as_bytes(),
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

fn validate_response(config: &RunnerProductConfig, response: &RedeemResponse) -> Result<()> {
    if response.runner_id != config.runner_id().as_uuid()
        || response.control_endpoint != config.control_endpoint().to_string()
        || response.runner_group.is_empty()
        || response.certificate_chain_pem.is_empty()
        || response.server_ca_pem.is_empty()
        || response.certificate_expires_at_seconds <= 0
    {
        bail!("runner enrollment response does not match the local configuration");
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

    fn require_absent(&self) -> Result<()> {
        if [
            &self.server_roots,
            &self.certificate_chain,
            &self.private_key,
        ]
        .into_iter()
        .any(|path| path.exists())
        {
            bail!("runner TLS credential destination already exists");
        }
        Ok(())
    }

    fn persist(&self, roots: &[u8], chain: &[u8], key: &[u8]) -> Result<()> {
        persist_new(&self.server_roots, roots, false)?;
        if let Err(error) = persist_new(&self.certificate_chain, chain, false) {
            remove_created(&self.server_roots);
            return Err(error);
        }
        if let Err(error) = persist_new(&self.private_key, key, true) {
            remove_created(&self.certificate_chain);
            remove_created(&self.server_roots);
            return Err(error);
        }
        Ok(())
    }
}

fn remove_created(path: &Path) {
    let _ignored = fs::remove_file(path);
}

fn persist_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("runner credential path has no parent")?;
    fs::create_dir_all(parent).context("runner credential directory could not be created")?;
    let temporary = parent.join(format!(".automata-enroll-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        let mut file = options
            .open(&temporary)
            .context("temporary runner credential could not be created")?;
        file.write_all(bytes)
            .context("runner credential could not be written")?;
        file.sync_all()
            .context("runner credential could not be synchronized")?;
        drop(file);
        fs::hard_link(&temporary, path)
            .context("runner credential destination already exists or is unavailable")?;
        Ok(())
    })();
    let _ignored = fs::remove_file(&temporary);
    result
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
    use super::enrollment_origin;

    #[test]
    fn enrollment_origin_requires_tls_except_for_literal_loopback() {
        assert!(enrollment_origin("https://ci.example.test").is_ok());
        assert!(enrollment_origin("http://127.0.0.1:8080").is_ok());
        assert!(enrollment_origin("http://[::1]:8080").is_ok());
        assert!(enrollment_origin("http://localhost:8080").is_err());
        assert!(enrollment_origin("http://ci.example.test").is_err());
        assert!(enrollment_origin("https://ci.example.test/path").is_err());
    }
}
