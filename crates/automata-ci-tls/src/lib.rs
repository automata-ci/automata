#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Validated TLS trust material for infrastructure adapters.
//!
//! This crate owns only the exact certificate-authority document boundary.
//! Transport clients and trust-policy selection remain with their consuming
//! adapters.

use std::fmt;

use rustls::{RootCertStore, pki_types::CertificateDer};
use thiserror::Error;
use x509_parser::parse_x509_certificate;

/// Maximum accepted size of one exact CA certificate in canonical PEM form.
pub const MAX_CA_CERTIFICATE_PEM_BYTES: usize = 1024 * 1024;

/// One canonical RFC 7468 X.509 certificate authorized to sign certificates.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedCaCertificate {
    certificate_pem: Vec<u8>,
}

impl ValidatedCaCertificate {
    /// Validates one exact CA certificate in canonical RFC 7468 PEM form.
    ///
    /// # Errors
    ///
    /// Rejects oversized input, malformed or non-certificate PEM, malformed
    /// X.509, and certificates that are not marked as certificate authorities.
    /// The source bytes must contain no preamble, use LF line endings, contain
    /// exactly 64 Base64 characters per non-final line, end in one newline, and
    /// contain no trailing data or second document. When `KeyUsage` is present,
    /// it must authorize certificate signing.
    pub fn new(certificate_pem: impl Into<Vec<u8>>) -> Result<Self, CaCertificateError> {
        let certificate_pem = certificate_pem.into();
        if certificate_pem.is_empty() || certificate_pem.len() > MAX_CA_CERTIFICATE_PEM_BYTES {
            return Err(CaCertificateError);
        }
        let (label, certificate_der) =
            pem_rfc7468::decode_vec(&certificate_pem).map_err(|_| CaCertificateError)?;
        if label != "CERTIFICATE" {
            return Err(CaCertificateError);
        }
        let canonical_pem = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &certificate_der,
        )
        .map_err(|_| CaCertificateError)?;
        if canonical_pem.as_bytes() != certificate_pem {
            return Err(CaCertificateError);
        }
        let (remaining, certificate) =
            parse_x509_certificate(&certificate_der).map_err(|_| CaCertificateError)?;
        let key_usage = certificate.key_usage().map_err(|_| CaCertificateError)?;
        if !remaining.is_empty()
            || !certificate.tbs_certificate.is_ca()
            || key_usage.is_some_and(|usage| !usage.value.key_cert_sign())
        {
            return Err(CaCertificateError);
        }
        RootCertStore::empty()
            .add(CertificateDer::from(certificate_der))
            .map_err(|_| CaCertificateError)?;
        Ok(Self { certificate_pem })
    }

    /// Returns the exact validated canonical PEM document.
    #[must_use]
    pub fn as_pem(&self) -> &[u8] {
        &self.certificate_pem
    }
}

impl fmt::Debug for ValidatedCaCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedCaCertificate([certificate redacted])")
    }
}

/// A CA source was not one exact canonical certificate-authority document.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("CA source must contain exactly one valid canonical X.509 CA certificate")]
pub struct CaCertificateError;

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    use super::*;

    fn certificate_pem(is_ca: bool, key_usages: Vec<KeyUsagePurpose>) -> Vec<u8> {
        let key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Automata infrastructure test CA");
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params.key_usages = key_usages;
        params
            .self_signed(&key)
            .expect("self-signed CA")
            .pem()
            .into_bytes()
    }

    fn ca_pem() -> Vec<u8> {
        certificate_pem(
            true,
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        )
    }

    fn certificate_pem_with_malformed_key_usage() -> Vec<u8> {
        let key = KeyPair::generate().expect("certificate key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                // KeyUsage's extnValue must contain a DER BIT STRING, not BOOLEAN.
                vec![0x01, 0x01, 0xff],
            ));
        params
            .self_signed(&key)
            .expect("self-signed certificate")
            .pem()
            .into_bytes()
    }

    #[test]
    fn accepts_one_canonical_ca_and_redacts_debug() {
        let marker = "Automata infrastructure test CA";
        let certificate_pem = ca_pem();
        let certificate = ValidatedCaCertificate::new(certificate_pem.clone()).expect("valid CA");

        assert_eq!(certificate.as_pem(), certificate_pem);
        let debug = format!("{certificate:?}");
        assert_eq!(debug, "ValidatedCaCertificate([certificate redacted])");
        assert!(!debug.contains(marker));
        assert!(!debug.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn rejects_non_ca_noncanonical_and_multiple_documents() {
        let ca_pem = ca_pem();
        ValidatedCaCertificate::new(certificate_pem(true, Vec::new()))
            .expect("a CA without KeyUsage remains a valid trust anchor");
        let mut doubled = ca_pem.clone();
        doubled.extend_from_slice(&ca_pem);
        let mut preamble = b"deployment preamble\n".to_vec();
        preamble.extend_from_slice(&ca_pem);
        let mut trailing_data = ca_pem.clone();
        trailing_data.extend_from_slice(b"trailing data");
        let mut trailing_newline = ca_pem.clone();
        trailing_newline.push(b'\n');
        let mut missing_terminal_newline = ca_pem.clone();
        assert_eq!(missing_terminal_newline.pop(), Some(b'\n'));
        let crlf = String::from_utf8(ca_pem.clone())
            .expect("certificate PEM is ASCII")
            .replace('\n', "\r\n")
            .into_bytes();

        for invalid in [
            Vec::new(),
            b"not a PEM certificate".to_vec(),
            certificate_pem(false, Vec::new()),
            certificate_pem(true, vec![KeyUsagePurpose::DigitalSignature]),
            certificate_pem_with_malformed_key_usage(),
            doubled,
            preamble,
            trailing_data,
            trailing_newline,
            missing_terminal_newline,
            crlf,
            vec![b'a'; MAX_CA_CERTIFICATE_PEM_BYTES + 1],
        ] {
            assert_eq!(
                ValidatedCaCertificate::new(invalid),
                Err(CaCertificateError)
            );
        }
    }
}
