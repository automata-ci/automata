//! Secure runner-side enrollment and local TLS credential custody.

use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::secret::{RunnerEnrollmentToken, SecretString};
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
    cli::{EnrollArgs, EnrollmentTokenSource},
    product::{RunnerProductConfig, ScalarLineEnding, SecretSource, normalize_scalar_bytes},
};

const REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn enroll(args: &EnrollArgs) -> Result<()> {
    validate_name(&args.name)?;
    let config = RunnerProductConfig::load(&args.config)
        .context("runner enrollment could not load the product configuration")?;
    let destinations = CredentialDestinations::from_config(&config)?;
    let origin = enrollment_origin(&args.server)?;
    let stage = match destinations.load_stage(&config, &origin, &args.name)? {
        Some(stage) => stage,
        None => destinations.create_stage(&config, &origin, &args.name, load_token(args)?)?,
    };
    let staged_response = destinations.load_response()?;
    let endpoint = origin
        .join(REDEEM_PATH)
        .context("runner enrollment endpoint is invalid")?;
    let body = RedeemRequest {
        operation_id: stage.operation_id,
        token: stage.token.expose_secret(),
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
    if let Some(staged_response) = staged_response {
        validate_staged_response(&staged_response, &bytes)?;
    } else {
        destinations.persist_response(&bytes)?;
    }
    let response_validation_time_seconds = current_unix_time_seconds()?;
    let enrolled: RedeemResponse =
        serde_json::from_slice(&bytes).context("runner enrollment returned an invalid response")?;
    validate_response(&config, &enrolled, response_validation_time_seconds)?;
    stage.validate_certificate(&config, &enrolled, response_validation_time_seconds)?;
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

fn validate_staged_response(staged: &[u8], replayed: &[u8]) -> Result<()> {
    if staged != replayed {
        bail!("runner enrollment replay did not match its durable response receipt");
    }
    Ok(())
}

fn load_token(args: &EnrollArgs) -> Result<RunnerEnrollmentToken> {
    let bytes = match &args.token_source {
        EnrollmentTokenSource::File(path) => SecretSource::File { path: path.clone() }
            .read_scalar(RunnerEnrollmentToken::BYTE_LENGTH)
            .context("runner enrollment token file is unavailable")?,
        EnrollmentTokenSource::Environment(name) => {
            SecretSource::Environment { name: name.clone() }
                .read_scalar(RunnerEnrollmentToken::BYTE_LENGTH)
                .context("runner enrollment token environment value is unavailable")?
        }
        EnrollmentTokenSource::Stdin => {
            let stdin = std::io::stdin();
            read_stdin_token(&mut stdin.lock())?
        }
        EnrollmentTokenSource::Invalid => bail!("runner enrollment token source is invalid"),
    };
    parse_token(bytes)
}

fn read_stdin_token(reader: &mut dyn Read) -> Result<Zeroizing<Vec<u8>>> {
    let framed_limit = RunnerEnrollmentToken::BYTE_LENGTH
        .checked_add(2)
        .expect("token framing bound fits usize");
    let proof_limit = framed_limit
        .checked_add(1)
        .expect("token overflow probe bound fits usize");
    let mut bytes = Zeroizing::new(Vec::with_capacity(proof_limit));
    reader
        .take(u64::try_from(proof_limit).expect("token overflow probe bound fits u64"))
        .read_to_end(&mut bytes)
        .context("runner enrollment token could not be read from stdin")?;
    normalize_scalar_bytes(
        &mut bytes,
        RunnerEnrollmentToken::BYTE_LENGTH,
        ScalarLineEnding::OptionalSingle,
    )
    .context("runner enrollment token stdin value is invalid")?;
    Ok(bytes)
}

fn parse_token(mut bytes: Zeroizing<Vec<u8>>) -> Result<RunnerEnrollmentToken> {
    let token = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(token) => token,
        Err(error) => {
            let _invalid = Zeroizing::new(error.into_bytes());
            bail!("runner enrollment token is invalid");
        }
    };
    let secret = SecretString::new(token).context("runner enrollment token is invalid")?;
    RunnerEnrollmentToken::from_secret(secret).context("runner enrollment token is invalid")
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
    use std::io::Cursor;

    use super::{enrollment_origin, parse_token, read_stdin_token, validate_staged_response};

    const CANONICAL_TOKEN: &str = "atm_re_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

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
    fn staged_response_requires_a_byte_exact_replay() {
        validate_staged_response(b"exact", b"exact").expect("exact replay");
        assert!(validate_staged_response(b"staged", b"different").is_err());
    }

    #[test]
    fn stdin_token_requires_eof_and_one_exact_optional_line_ending() {
        for input in [
            CANONICAL_TOKEN.as_bytes().to_vec(),
            format!("{CANONICAL_TOKEN}\n").into_bytes(),
            format!("{CANONICAL_TOKEN}\r\n").into_bytes(),
        ] {
            let bytes = read_stdin_token(&mut Cursor::new(input)).expect("canonical stdin token");
            let token = parse_token(bytes).expect("canonical enrollment token");
            assert_eq!(token.expose_secret(), CANONICAL_TOKEN);
        }

        for suffix in ["\r", "\n\n", "\r\r", "\r\n\n", "\r\ntrailing"] {
            let input = format!("{CANONICAL_TOKEN}{suffix}").into_bytes();
            assert!(
                read_stdin_token(&mut Cursor::new(input)).is_err(),
                "invalid stdin suffix {suffix:?} must fail"
            );
        }
    }
}
