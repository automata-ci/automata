#![allow(dead_code)]

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use automata_ci_core::OperationId;
use automata_ci_runner_spool::{
    ContentCommitmentDomain, ContentProtectionError, ContentProtector, DurableContentPublication,
    DurableContentRef, ProtectionId, RetainedContentError, RetainedContentSource, SpoolRoot,
    endpoint_result_allocation,
};
use sha2::{Digest as _, Sha256};

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/agent-scratch/runner-spool-tests")
            .join(format!("{label}-{}", OperationId::new()));
        fs::create_dir_all(&path).expect("create repository-local spool scratch");
        let path = fs::canonicalize(path).expect("canonical repository-local spool scratch");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn spool_root(&self) -> SpoolRoot {
        SpoolRoot::explicit(self.child("content")).expect("valid spool root")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct TestProtector {
    id: ProtectionId,
    key: [u8; 32],
}

impl TestProtector {
    pub fn new(id: &str, marker: u8) -> Self {
        Self {
            id: ProtectionId::new(id).expect("valid protection identifier"),
            key: [marker; 32],
        }
    }

    fn tag(&self, reference: &DurableContentRef, ciphertext: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(reference.cache_key().as_str().as_bytes());
        digest.update(ciphertext);
        digest.finalize().into()
    }

    fn protected_plaintext(
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let Some(allocation) = reference.endpoint_result_allocation_bytes() else {
            return Ok(plaintext.to_vec());
        };
        let inner_bytes = allocation
            .checked_sub(32)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(ContentProtectionError::Failed)?;
        let required = 44_usize
            .checked_add(plaintext.len())
            .ok_or(ContentProtectionError::Failed)?;
        if required > inner_bytes {
            return Err(ContentProtectionError::Failed);
        }
        let mut inner = Vec::with_capacity(inner_bytes);
        inner.extend_from_slice(b"EPR1");
        inner.extend_from_slice(
            &u64::try_from(plaintext.len())
                .map_err(|_| ContentProtectionError::Failed)?
                .to_be_bytes(),
        );
        inner.extend_from_slice(&Sha256::digest(plaintext));
        inner.extend_from_slice(plaintext);
        inner.resize(inner_bytes, 0);
        Ok(inner)
    }
}

impl fmt::Debug for TestProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestProtector")
            .field("id", &self.id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ContentProtector for TestProtector {
    fn protection_id(&self) -> &ProtectionId {
        &self.id
    }

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        if protection_id != &self.id {
            return Err(ContentProtectionError::KeyUnavailable);
        }
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(domain.separator());
        digest.update(material_digest);
        Ok(digest.finalize().into())
    }

    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        endpoint_result_allocation(plaintext_bytes).map_err(|_| ContentProtectionError::Failed)
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let inner = Self::protected_plaintext(reference, plaintext)?;
        let mut protected = Vec::with_capacity(inner.len() + 32);
        protected.extend(
            inner
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()]),
        );
        let tag = self.tag(reference, &protected);
        protected.extend_from_slice(&tag);
        Ok(protected)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if protected.len() < 32 {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let tag_offset = protected.len() - 32;
        let ciphertext = &protected[..tag_offset];
        if protected[tag_offset..] != self.tag(reference, ciphertext) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let inner: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect();
        if reference.kind() != automata_ci_runner_spool::ContentKind::EndpointResult {
            return Ok(inner);
        }
        if inner.len() < 44 || &inner[..4] != b"EPR1" {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let plaintext_bytes = u64::from_be_bytes(
            inner[4..12]
                .try_into()
                .map_err(|_| ContentProtectionError::AuthenticationFailed)?,
        );
        let plaintext_length = usize::try_from(plaintext_bytes)
            .map_err(|_| ContentProtectionError::AuthenticationFailed)?;
        let end = 44_usize
            .checked_add(plaintext_length)
            .filter(|end| *end <= inner.len())
            .ok_or(ContentProtectionError::AuthenticationFailed)?;
        if inner[end..].iter().any(|byte| *byte != 0) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let plaintext = inner[44..end].to_vec();
        if Sha256::digest(&plaintext).as_slice() != &inner[12..44] {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        Ok(plaintext)
    }
}

pub fn content_path(root: &SpoolRoot, reference: &DurableContentRef) -> PathBuf {
    root.as_path()
        .join(format!("{}.blob", reference.cache_key().as_str()))
}

pub fn adopt(publication: DurableContentPublication<'_>) -> DurableContentRef {
    publication
        .commit_with(|reference| Ok::<_, std::convert::Infallible>(reference.clone()))
        .expect("infallible test adoption")
}

pub struct StaticRetainSet(Vec<DurableContentRef>);

impl StaticRetainSet {
    pub fn new(references: impl IntoIterator<Item = DurableContentRef>) -> Self {
        Self(references.into_iter().collect())
    }
}

impl RetainedContentSource for StaticRetainSet {
    fn retained_content(&self) -> Result<Vec<DurableContentRef>, RetainedContentError> {
        Ok(self.0.clone())
    }
}
