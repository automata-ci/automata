#![allow(dead_code)]

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use automata_ci_core::OperationId;
use automata_ci_runner_spool::{
    ContentProtectionError, ContentProtector, DurableContentPublication, DurableContentRef,
    ProtectionId, RetainedContentError, RetainedContentSource, SpoolRoot,
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

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let mut protected = Vec::with_capacity(plaintext.len() + 36);
        protected.extend_from_slice(b"ATP1");
        protected.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()]),
        );
        let tag = self.tag(reference, &protected[4..]);
        protected.extend_from_slice(&tag);
        Ok(protected)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if protected.len() < 36 || &protected[..4] != b"ATP1" {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let tag_offset = protected.len() - 32;
        let ciphertext = &protected[4..tag_offset];
        if protected[tag_offset..] != self.tag(reference, ciphertext) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        Ok(ciphertext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect())
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
