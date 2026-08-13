//! Secure runner-side enrollment and local TLS credential custody.

use std::{io::Read as _, time::Duration};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

mod custody;
mod transport;

use custody::CredentialDestinations;
use transport::read_bounded_response;

use crate::{
    cli::EnrollArgs,
    product::{RunnerProductConfig, SecretSource},
};

const REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";
const TOKEN_PREFIX: &str = "atm_re_";
const TOKEN_BYTES: usize = 32;
const TOKEN_ENCODED_BYTES: usize = 43;
const MAX_TOKEN_BYTES: usize = TOKEN_PREFIX.len() + TOKEN_ENCODED_BYTES;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn enroll(args: &EnrollArgs) -> Result<()> {
    validate_name(&args.name)?;
    let config = RunnerProductConfig::load(&args.config)
        .context("runner enrollment could not load the product configuration")?;
    let destinations = CredentialDestinations::from_config(&config)?;
    let origin = enrollment_origin(&args.server)?;
    if destinations.finish_interrupted_cleanup(&config)? {
        println!("runner enrollment was already completed");
        return Ok(());
    }
    let stage = match destinations.load_stage(&config, &origin, &args.name)? {
        Some(stage) => stage,
        None => destinations.create_stage(
            &config,
            &origin,
            &args.name,
            load_token(args)?,
        )?,
    };
    let bytes = if let Some(bytes) = destinations.load_response()? {
        bytes
    } else {
        let endpoint = origin
            .join(REDEEM_PATH)
            .context("runner enrollment endpoint is invalid")?;
        let body = RedeemRequest {
            operation_id: stage.operation_id,
            token: stage.token.as_str(),
            runner_name: &stage.runner_name,
            capabilities: &stage.capabilities,
            csr_pem: &stage.csr_pem,
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
        if response.status() != StatusCode::CREATED {
            let status = response.status();
            bail!("runner enrollment was rejected with HTTP {status}");
        }
        if !response.headers().get_all(header::CONTENT_TYPE).iter().eq([
            &header::HeaderValue::from_static("application/json; charset=utf-8"),
        ]) {
            bail!("runner enrollment response has an invalid content type");
        }
        let bytes = Zeroizing::new(read_bounded_response(response).await?);
        destinations.persist_response(&bytes)?;
        bytes
    };
    let enrolled: RedeemResponse =
        serde_json::from_slice(&bytes).context("runner enrollment returned an invalid response")?;
    validate_response(&config, &enrolled)?;
    stage.validate_certificate(&config, &enrolled)?;
    destinations.persist_exact(
        enrolled.server_ca_pem.as_bytes(),
        enrolled.certificate_chain_pem.as_bytes(),
        stage.private_key_pem.as_bytes(),
    )?;
    destinations.complete()?;
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
    let token = String::from_utf8(Vec::from(bytes.as_slice()))
        .map(Zeroizing::new)
        .context("runner enrollment token is invalid")?;
    validate_token(token.as_str())?;
    Ok(token)
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

fn validate_token(value: &str) -> Result<()> {
    let decoded = value
        .strip_prefix(TOKEN_PREFIX)
        .filter(|encoded| encoded.len() == TOKEN_ENCODED_BYTES)
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok());
    if decoded.is_none_or(|decoded| decoded.len() != TOKEN_BYTES) {
        bail!("runner enrollment token is invalid");
    }
    Ok(())
}

#[derive(Serialize)]
struct RedeemRequest<'a> {
    operation_id: Uuid,
    token: &'a str,
    runner_name: &'a str,
    capabilities: &'a automata_ci_core::RunnerCapabilities,
    csr_pem: &'a str,
}

#[derive(Deserialize, Serialize)]
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{TOKEN_PREFIX, enrollment_origin, validate_token};

    #[test]
    fn enrollment_origin_requires_tls_except_for_literal_loopback() {
        assert!(enrollment_origin("https://ci.example.test").is_ok());
        assert!(enrollment_origin("http://127.0.0.1:8080").is_ok());
        assert!(enrollment_origin("http://[::1]:8080").is_ok());
        assert!(enrollment_origin("http://localhost:8080").is_err());
        assert!(enrollment_origin("http://ci.example.test").is_err());
        assert!(enrollment_origin("https://ci.example.test/path").is_err());
    }

    #[test]
    fn enrollment_token_requires_the_one_canonical_generated_shape() {
        let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode([7_u8; 32]));
        validate_token(&token).expect("canonical token");
        assert!(validate_token("plain-secret").is_err());
        assert!(validate_token(&format!("{token}A")).is_err());
        assert!(validate_token(&format!("{token}\n")).is_err());
    }
}
