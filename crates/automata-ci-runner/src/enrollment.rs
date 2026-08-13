//! Secure runner-side enrollment and local TLS credential custody.

use std::{
    io::Read as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
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
    let validation_time_seconds = current_unix_time_seconds()?;
    if destinations.finish_interrupted_cleanup(&config, validation_time_seconds)? {
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
        let bytes = read_bounded_response(response).await?;
        destinations.persist_response(&bytes)?;
        bytes
    };
    let enrolled: RedeemResponse =
        serde_json::from_slice(&bytes).context("runner enrollment returned an invalid response")?;
    validate_response(&config, &enrolled, validation_time_seconds)?;
    stage.validate_certificate(&config, &enrolled, validation_time_seconds)?;
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

fn validate_response(
    config: &RunnerProductConfig,
    response: &RedeemResponse,
    validation_time_seconds: i64,
) -> Result<()> {
    let expected_group = automata_ci_core::RunnerGroup::new(&response.runner_group)
        .context("runner enrollment returned an invalid group")?;
    if response.runner_id != config.runner_id().as_uuid()
        || response.control_endpoint != config.control_endpoint().to_string()
        || config.inventory().groups() != &std::collections::BTreeSet::from([expected_group])
        || response.certificate_chain_pem.is_empty()
        || response.server_ca_pem.is_empty()
        || response.certificate_expires_at_seconds <= validation_time_seconds
    {
        bail!("runner enrollment response does not match the local configuration");
    }
    Ok(())
}

fn current_unix_time_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("runner enrollment requires a valid system clock")?
        .as_secs();
    i64::try_from(seconds).context("runner enrollment system time is out of range")
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
