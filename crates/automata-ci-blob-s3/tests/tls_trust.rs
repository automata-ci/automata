use std::{sync::Arc, time::Duration};

use automata_ci_blob_s3::{
    EnsureBucketError, EnsureBucketOutcome, S3BlobStoreConfig, S3TlsTrust, StaticS3Credentials,
    ensure_bucket,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use url::Url;

#[tokio::test]
async fn aws_sdk_uses_only_the_selected_exact_private_ca() {
    let trusted = TestAuthority::new("trusted private S3 root");
    let trusted_fixture = TlsS3Fixture::spawn(&trusted).await;
    let trusted_config = https_config(
        trusted_fixture.endpoint.clone(),
        S3TlsTrust::private_ca(trusted.pem()).expect("trusted private CA"),
    );

    assert_eq!(
        ensure_bucket(&sdk_client(&trusted_config), &trusted_config).await,
        Ok(EnsureBucketOutcome::AlreadyExists)
    );

    let wrong = TestAuthority::new("wrong private S3 root");
    let wrong_fixture = TlsS3Fixture::spawn(&trusted).await;
    let wrong_config = https_config(
        wrong_fixture.endpoint.clone(),
        S3TlsTrust::private_ca(wrong.pem()).expect("wrong private CA"),
    );
    assert!(matches!(
        ensure_bucket(&sdk_client(&wrong_config), &wrong_config).await,
        Err(EnsureBucketError::InitialInspection | EnsureBucketError::Deadline)
    ));

    let web_pki_fixture = TlsS3Fixture::spawn(&trusted).await;
    let web_pki_config = https_config(web_pki_fixture.endpoint.clone(), S3TlsTrust::web_pki());
    assert!(matches!(
        ensure_bucket(&sdk_client(&web_pki_config), &web_pki_config).await,
        Err(EnsureBucketError::InitialInspection | EnsureBucketError::Deadline)
    ));
}

fn https_config(endpoint: Url, trust: S3TlsTrust) -> S3BlobStoreConfig {
    S3BlobStoreConfig::new(
        endpoint,
        "us-east-1",
        "automata-tests",
        None,
        true,
        trust,
        Duration::from_secs(1),
    )
    .expect("TLS S3 fixture configuration")
}

fn sdk_client(config: &S3BlobStoreConfig) -> aws_sdk_s3::Client {
    config
        .client(
            StaticS3Credentials::new("test-access", "test-secret", None)
                .expect("TLS fixture credentials"),
        )
        .expect("TLS fixture SDK client")
}

struct TestAuthority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestAuthority {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().expect("generate private CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("private CA params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).expect("self-sign private CA"),
        }
    }

    fn pem(&self) -> Vec<u8> {
        self.issuer.pem().into_bytes()
    }

    fn server_config(&self) -> ServerConfig {
        let key = KeyPair::generate().expect("generate S3 server key");
        let mut params =
            CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("S3 server params");
        params
            .distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params
            .signed_by(&key, &self.issuer)
            .expect("sign S3 server certificate");
        ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.der().as_ref().to_vec())],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("S3 server TLS identity")
    }
}

struct TlsS3Fixture {
    endpoint: Url,
    task: JoinHandle<()>,
}

impl TlsS3Fixture {
    async fn spawn(authority: &TestAuthority) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS S3 fixture");
        let endpoint = Url::parse(&format!(
            "https://{}/",
            listener.local_addr().expect("TLS S3 fixture address")
        ))
        .expect("TLS S3 fixture URL");
        let acceptor = TlsAcceptor::from(Arc::new(authority.server_config()));
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept TLS S3 client");
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4 * 1_024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let received = stream.read(&mut buffer).await.expect("read TLS S3 request");
                    if received == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..received]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\nx-amz-request-id: tls-fixture\r\n\r\n",
                    )
                    .await
                    .expect("write TLS S3 response");
            }
        });
        Self { endpoint, task }
    }
}

impl Drop for TlsS3Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
