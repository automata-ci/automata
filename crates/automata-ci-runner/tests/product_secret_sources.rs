#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use automata_ci_runner::product::{
    ObjectStoreTlsTrust, RunnerProductError, SecretSource, SecureInputError, load_s3_credentials,
    load_s3_tls_trust, load_spool_key,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use uuid::Uuid;

struct SecretFile {
    root: PathBuf,
    source: SecretSource,
}

impl SecretFile {
    fn new(bytes: &[u8]) -> Self {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root")
            .to_path_buf();
        let root = workspace
            .join("target")
            .join("runner-secret-tests")
            .join(Uuid::new_v4().simple().to_string());
        fs::create_dir_all(&root).expect("create secret fixture root");
        let path = root.join("secret");
        fs::write(&path, bytes).expect("write secret fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict secret fixture");
        Self {
            root,
            source: SecretSource::File { path },
        }
    }

    const fn source(&self) -> &SecretSource {
        &self.source
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn scalar_files_accept_one_terminal_line_ending_with_post_normalization_limits() {
    for bytes in [b"12345678".as_slice(), b"12345678\n", b"12345678\r\n"] {
        let fixture = SecretFile::new(bytes);
        assert_eq!(
            fixture
                .source()
                .read_scalar(8)
                .expect("valid scalar")
                .as_slice(),
            b"12345678"
        );
    }

    for bytes in [
        b"\n".as_slice(),
        b"\r\n",
        b"value\n\n",
        b"value\r\n\r\n",
        b"value\ninside",
        b"value\r",
        b"123456789\n",
    ] {
        let fixture = SecretFile::new(bytes);
        assert!(
            fixture.source().read_scalar(8).is_err(),
            "malformed or oversized scalar must fail"
        );
    }

    let fixture = SecretFile::new(b"value\n");
    assert_eq!(
        fixture.source().read_scalar(0),
        Err(SecureInputError::InvalidLimit)
    );
    assert_eq!(
        fixture.source().read_scalar(usize::MAX),
        Err(SecureInputError::InvalidLimit)
    );
}

#[test]
fn s3_credentials_accept_one_file_line_ending_and_reject_extra_or_oversized_input() {
    let access = SecretFile::new(b"access-key\n");
    let secret = SecretFile::new(b"secret-key\r\n");
    let session = SecretFile::new(b"session-token\n");
    load_s3_credentials(access.source(), secret.source(), Some(session.source()))
        .expect("one conventional line ending must be accepted");

    let exact_access = SecretFile::new(&[vec![b'a'; 1_024], b"\r\n".to_vec()].concat());
    load_s3_credentials(exact_access.source(), secret.source(), None)
        .expect("the full scalar limit plus CRLF must be accepted");
    let exact_secret = SecretFile::new(&[vec![b's'; 65_536], b"\n".to_vec()].concat());
    let exact_session = SecretFile::new(&[vec![b't'; 65_536], b"\r\n".to_vec()].concat());
    load_s3_credentials(
        access.source(),
        exact_secret.source(),
        Some(exact_session.source()),
    )
    .expect("the full secret and session-token limits plus line endings must be accepted");

    for invalid_access in [
        [b"access-key".as_slice(), b"\n\n"].concat(),
        [vec![b'a'; 1_025], b"\n".to_vec()].concat(),
    ] {
        let invalid_access = SecretFile::new(&invalid_access);
        assert!(matches!(
            load_s3_credentials(invalid_access.source(), secret.source(), None),
            Err(RunnerProductError::SecureInput(_) | RunnerProductError::InvalidSecretText)
        ));
    }
    for invalid_secret in [
        b"secret-key\r\n\n".to_vec(),
        [vec![b's'; 65_537], b"\n".to_vec()].concat(),
    ] {
        let invalid_secret = SecretFile::new(&invalid_secret);
        assert!(load_s3_credentials(access.source(), invalid_secret.source(), None).is_err());
    }
    for invalid_session in [
        b"session-token\n\n".to_vec(),
        [vec![b't'; 65_537], b"\r\n".to_vec()].concat(),
    ] {
        let invalid_session = SecretFile::new(&invalid_session);
        assert!(
            load_s3_credentials(
                access.source(),
                secret.source(),
                Some(invalid_session.source())
            )
            .is_err()
        );
    }
}

#[test]
fn s3_private_ca_loading_is_bounded_exact_and_sanitized() {
    let key = KeyPair::generate().expect("private CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("private CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let pem = params
        .self_signed(&key)
        .expect("self-signed private CA")
        .pem();
    let certificate = SecretFile::new(pem.as_bytes());
    let policy = ObjectStoreTlsTrust::PrivateCa {
        certificate_source: certificate.source().clone(),
    };
    let trust = load_s3_tls_trust(&policy).expect("one exact private CA");
    let debug = format!("{trust:?}");
    assert_eq!(debug, "S3TlsTrust::PrivateCa([certificate redacted])");
    assert!(!debug.contains(&pem));

    let malformed = SecretFile::new(b"private CA content must never escape");
    let policy = ObjectStoreTlsTrust::PrivateCa {
        certificate_source: malformed.source().clone(),
    };
    assert!(matches!(
        load_s3_tls_trust(&policy),
        Err(RunnerProductError::ObjectStore(
            automata_ci_blob_s3::S3BlobStoreConfigError::InvalidPrivateCa
        ))
    ));

    let oversized = SecretFile::new(&vec![
        b'x';
        automata_ci_blob_s3::MAX_S3_PRIVATE_CA_PEM_BYTES + 1
    ]);
    let policy = ObjectStoreTlsTrust::PrivateCa {
        certificate_source: oversized.source().clone(),
    };
    assert!(matches!(
        load_s3_tls_trust(&policy),
        Err(RunnerProductError::SecureInput(
            SecureInputError::InvalidSize
        ))
    ));
}

#[test]
fn spool_key_accepts_one_file_line_ending_and_rejects_every_non_scalar_hex_shape() {
    let encoded = "ab".repeat(32);
    for suffix in ["", "\n", "\r\n"] {
        let fixture = SecretFile::new(format!("{encoded}{suffix}").as_bytes());
        assert_eq!(
            load_spool_key(fixture.source())
                .expect("valid hexadecimal key")
                .as_slice(),
            &[0xab; 32]
        );
    }

    for invalid in [
        format!("{encoded}\n\n"),
        "ab".repeat(31),
        format!("{}00", "ab".repeat(32)),
        format!("{}zz", "ab".repeat(31)),
    ] {
        let fixture = SecretFile::new(invalid.as_bytes());
        assert!(load_spool_key(fixture.source()).is_err());
    }
}
