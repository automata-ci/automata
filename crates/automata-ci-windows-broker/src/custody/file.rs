//! Create-only file adapter for broker-owned custody.

use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};

use automata_ci_core::{Sha256Digest, UnixMillis};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    MAX_ADMISSION_RECEIPT_BYTES, WindowsBrokerAdmissionCustody, WindowsBrokerCustodyError,
    WindowsBrokerCustodyHandle, WindowsBrokerCustodyKind, WindowsBrokerCustodyMetadata,
    WindowsBrokerCustodyProtector,
};

const HANDLE_DOMAIN: &[u8] = b"automata.windows-broker-custody-handle.v1\0";
const RECORD_DOMAIN: &[u8] = b"automata.windows-broker-custody-record.v1\0";
const SEALED_ENVELOPE_DOMAIN: &[u8] = b"automata.windows-broker-custody-sealed-envelope.v1\0";
const SEALED_ENVELOPE_SCHEMA: u16 = 1;
const MAX_RECORD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RECORD_BYTES_USIZE: usize = 2 * 1024 * 1024;
const MAX_ENTRY_COUNT: usize = 4_096;

/// Reparse-safe, create-only file custody owned by the broker service.
pub struct FileWindowsBrokerCustody {
    root: PathBuf,
    protector: Arc<dyn WindowsBrokerCustodyProtector>,
    mutation: Mutex<()>,
}

impl FileWindowsBrokerCustody {
    /// Opens a service-owned custody root and reconciles incomplete temp files.
    ///
    /// # Errors
    ///
    /// Rejects relative, symlink/reparse, unknown-entry, or inaccessible roots.
    pub fn open(
        root: impl Into<PathBuf>,
        protector: Arc<dyn WindowsBrokerCustodyProtector>,
    ) -> Result<Self, WindowsBrokerCustodyError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(WindowsBrokerCustodyError::UnsafePath);
        }
        fs::create_dir_all(&root).map_err(|_| WindowsBrokerCustodyError::Io)?;
        validate_directory(&root)?;
        reconcile_root(&root)?;
        Ok(Self {
            root,
            protector,
            mutation: Mutex::new(()),
        })
    }

    /// Seals and atomically publishes one new custody record.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized material, unsafe roots, capacity exhaustion,
    /// RNG failure, sealing failure, or incomplete durable publication.
    pub fn put(
        &self,
        kind: WindowsBrokerCustodyKind,
        plaintext: &[u8],
        created_at: UnixMillis,
    ) -> Result<WindowsBrokerCustodyHandle, WindowsBrokerCustodyError> {
        let handle = self.reserve_handle(kind)?;
        self.put_reserved(&handle, kind, plaintext, created_at)?;
        Ok(handle)
    }

    /// Reserves a random path-free handle without publishing material.
    ///
    /// This is restricted to broker-owned transactional protocols which first
    /// persist a recoverable publication intent. A reservation conveys no
    /// custody authority until [`Self::put_reserved`] succeeds.
    #[allow(clippy::unused_self)]
    pub(crate) fn reserve_handle(
        &self,
        kind: WindowsBrokerCustodyKind,
    ) -> Result<WindowsBrokerCustodyHandle, WindowsBrokerCustodyError> {
        let mut entropy = Zeroizing::new([0_u8; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| WindowsBrokerCustodyError::Protector)?;
        let handle_digest =
            domain_digest(HANDLE_DOMAIN, &[&[kind.domain_byte()], entropy.as_ref()]);
        entropy.zeroize();
        WindowsBrokerCustodyHandle::parse(&format!("bc1-{handle_digest}"))
    }

    /// Publishes exact material at a previously reserved broker handle.
    ///
    /// An exact already-published record is accepted for crash recovery. A
    /// different record, a completed handle, or any path collision fails
    /// closed.
    pub(crate) fn put_reserved(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        kind: WindowsBrokerCustodyKind,
        plaintext: &[u8],
        created_at: UnixMillis,
    ) -> Result<(), WindowsBrokerCustodyError> {
        if plaintext.is_empty() || plaintext.len() > kind.byte_limit() {
            return Err(WindowsBrokerCustodyError::Capacity);
        }
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        validate_directory(&self.root)?;
        let content_sha256 = sha256(plaintext);
        let target = record_path(&self.root, handle);
        let completed = completed_path(&self.root, handle);
        if completed.exists() {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        if target.exists() {
            let (existing, metadata) =
                self.read_authenticated_path(handle, &target, kind.byte_limit())?;
            if metadata.kind == kind
                && metadata.content_sha256 == content_sha256
                && metadata.created_at == created_at
                && existing.as_slice() == plaintext
            {
                return Ok(());
            }
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        if committed_entry_count(&self.root)? >= MAX_ENTRY_COUNT {
            return Err(WindowsBrokerCustodyError::Capacity);
        }
        let sealed_envelope =
            encode_sealed_envelope(handle.digest, kind, content_sha256, created_at, plaintext)?;
        let mut sealed = self.protector.seal(&sealed_envelope)?;
        if sealed.is_empty() || sealed.len() > MAX_RECORD_BYTES_USIZE {
            sealed.zeroize();
            return Err(WindowsBrokerCustodyError::Capacity);
        }
        let sealed_sha256 = sha256(&sealed);
        let record_digest = record_digest(
            handle.digest,
            kind,
            content_sha256,
            plaintext.len(),
            created_at,
            sealed_sha256,
        );
        let record = CustodyRecord {
            schema: 1,
            handle_digest: handle.digest,
            kind,
            content_sha256,
            byte_len: plaintext.len(),
            created_at,
            sealed_sha256,
            sealed_base64: BASE64.encode(&sealed[..]),
            record_digest,
        };
        sealed.zeroize();
        let encoded = serde_json::to_vec(&record).map_err(|_| WindowsBrokerCustodyError::Io)?;
        if encoded.len() as u64 > MAX_RECORD_BYTES {
            return Err(WindowsBrokerCustodyError::Capacity);
        }
        let temp = temp_path(&self.root, handle)?;
        write_new_synchronized(&temp, &encoded)?;
        if target.exists() || completed.exists() {
            let _ = fs::remove_file(&temp);
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        fs::rename(&temp, &target).map_err(|_| WindowsBrokerCustodyError::Io)?;
        validate_regular_file(&target)?;
        Ok(())
    }

    /// Reauthenticates a record and returns value-free metadata.
    ///
    /// # Errors
    ///
    /// Rejects absent, unsafe, malformed, modified, or unsealable records.
    pub fn inspect(
        &self,
        handle: &WindowsBrokerCustodyHandle,
    ) -> Result<WindowsBrokerCustodyMetadata, WindowsBrokerCustodyError> {
        let (_, metadata) = self.read_authenticated(handle, usize::MAX)?;
        Ok(metadata)
    }

    /// Reauthenticates and opens one exact bounded record.
    ///
    /// # Errors
    ///
    /// Rejects a zero/excessive caller limit and all inspect failures.
    pub fn get(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        byte_limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        if byte_limit == 0 || byte_limit > MAX_ADMISSION_RECEIPT_BYTES {
            return Err(WindowsBrokerCustodyError::Capacity);
        }
        self.read_authenticated(handle, byte_limit)
            .map(|(plaintext, _)| plaintext)
    }

    /// Reauthenticates then atomically turns one exact record into a tombstone.
    ///
    /// # Errors
    ///
    /// An absent record is idempotent. Unsafe or tampered records are retained
    /// for operator investigation and fail closed.
    pub fn remove(
        &self,
        handle: &WindowsBrokerCustodyHandle,
    ) -> Result<(), WindowsBrokerCustodyError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        validate_directory(&self.root)?;
        let path = record_path(&self.root, handle);
        let completed = completed_path(&self.root, handle);
        if completed.exists() {
            if path.exists() {
                return Err(WindowsBrokerCustodyError::Tampered);
            }
            let _ = self.read_authenticated_path(handle, &completed, usize::MAX)?;
            return Ok(());
        }
        if !path.exists() {
            return Ok(());
        }
        let _ = self.read_authenticated(handle, usize::MAX)?;
        fs::rename(&path, &completed).map_err(|_| WindowsBrokerCustodyError::Io)?;
        validate_regular_file(&completed)
    }

    /// Completes one admission receipt using its exact authenticated content digest.
    ///
    /// The encrypted record is atomically renamed to a stable tombstone. Repeating
    /// the same completion after a crash succeeds, while a different digest, kind,
    /// or any attempt to reuse the handle fails closed.
    ///
    /// # Errors
    ///
    /// Rejects an absent live/tombstoned record, the wrong material kind or digest,
    /// and every ordinary authentication or path-safety failure.
    pub fn complete_admission_receipt(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        expected_content_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerCustodyError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        validate_directory(&self.root)?;
        let path = record_path(&self.root, handle);
        let completed = completed_path(&self.root, handle);
        if path.exists() && completed.exists() {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        let selected = if path.exists() {
            &path
        } else if completed.exists() {
            &completed
        } else {
            return Err(WindowsBrokerCustodyError::Absent);
        };
        let (_, metadata) = self.read_authenticated_path(handle, selected, usize::MAX)?;
        if metadata.kind != WindowsBrokerCustodyKind::AdmissionReceipt
            || metadata.content_sha256 != expected_content_sha256
        {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        if selected == &path {
            fs::rename(&path, &completed).map_err(|_| WindowsBrokerCustodyError::Io)?;
            validate_regular_file(&completed)?;
        }
        Ok(())
    }

    /// Opens an admission record only for the dedicated broker authority.
    ///
    /// Generic protocol dispatch never exposes this method. `completed`
    /// selects the live receipt or its durable completion tombstone exactly.
    pub(crate) fn get_admission_receipt(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        completed: bool,
    ) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        let path = if completed {
            completed_path(&self.root, handle)
        } else {
            record_path(&self.root, handle)
        };
        if !path.exists() {
            return Err(WindowsBrokerCustodyError::Absent);
        }
        let (plaintext, metadata) =
            self.read_authenticated_path(handle, &path, MAX_ADMISSION_RECEIPT_BYTES)?;
        if metadata.kind != WindowsBrokerCustodyKind::AdmissionReceipt {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        Ok(plaintext)
    }

    fn read_authenticated(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        byte_limit: usize,
    ) -> Result<(Zeroizing<Vec<u8>>, WindowsBrokerCustodyMetadata), WindowsBrokerCustodyError> {
        validate_directory(&self.root)?;
        let path = record_path(&self.root, handle);
        if !path.exists() {
            return Err(WindowsBrokerCustodyError::Absent);
        }
        self.read_authenticated_path(handle, &path, byte_limit)
    }

    fn read_authenticated_path(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        path: &Path,
        byte_limit: usize,
    ) -> Result<(Zeroizing<Vec<u8>>, WindowsBrokerCustodyMetadata), WindowsBrokerCustodyError> {
        validate_regular_file(path)?;
        let file = File::open(path).map_err(|_| WindowsBrokerCustodyError::Io)?;
        if file
            .metadata()
            .map_err(|_| WindowsBrokerCustodyError::Io)?
            .len()
            > MAX_RECORD_BYTES
        {
            return Err(WindowsBrokerCustodyError::Capacity);
        }
        let mut encoded = Vec::new();
        file.take(MAX_RECORD_BYTES.saturating_add(1))
            .read_to_end(&mut encoded)
            .map_err(|_| WindowsBrokerCustodyError::Io)?;
        if encoded.is_empty() || encoded.len() as u64 > MAX_RECORD_BYTES {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        let record: CustodyRecord =
            serde_json::from_slice(&encoded).map_err(|_| WindowsBrokerCustodyError::Tampered)?;
        if record.schema != 1
            || record.handle_digest != handle.digest
            || record.byte_len == 0
            || record.byte_len > record.kind.byte_limit()
            || record.byte_len > byte_limit
            || record.record_digest
                != record_digest(
                    record.handle_digest,
                    record.kind,
                    record.content_sha256,
                    record.byte_len,
                    record.created_at,
                    record.sealed_sha256,
                )
        {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        let mut sealed = Zeroizing::new(
            BASE64
                .decode(&record.sealed_base64)
                .map_err(|_| WindowsBrokerCustodyError::Tampered)?,
        );
        if sealed.is_empty()
            || sealed.len() > MAX_RECORD_BYTES_USIZE
            || sha256(&sealed) != record.sealed_sha256
        {
            sealed.zeroize();
            return Err(WindowsBrokerCustodyError::Tampered);
        }
        let sealed_envelope = self.protector.open(&sealed)?;
        sealed.zeroize();
        let plaintext = decode_sealed_envelope(&sealed_envelope, &record)?;
        Ok((
            plaintext,
            WindowsBrokerCustodyMetadata {
                kind: record.kind,
                content_sha256: record.content_sha256,
                byte_len: record.byte_len,
                created_at: record.created_at,
            },
        ))
    }
}

impl WindowsBrokerAdmissionCustody for FileWindowsBrokerCustody {
    fn reserve_handle(
        &self,
        kind: WindowsBrokerCustodyKind,
    ) -> Result<WindowsBrokerCustodyHandle, WindowsBrokerCustodyError> {
        Self::reserve_handle(self, kind)
    }

    fn put_reserved(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        kind: WindowsBrokerCustodyKind,
        plaintext: &[u8],
        created_at: UnixMillis,
    ) -> Result<(), WindowsBrokerCustodyError> {
        Self::put_reserved(self, handle, kind, plaintext, created_at)
    }

    fn get_admission_receipt(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        completed: bool,
    ) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        Self::get_admission_receipt(self, handle, completed)
    }

    fn complete_admission_receipt(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        expected_content_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerCustodyError> {
        Self::complete_admission_receipt(self, handle, expected_content_sha256)
    }
}

impl fmt::Debug for FileWindowsBrokerCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileWindowsBrokerCustody")
            .field("root", &"[SERVICE_OWNED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CustodyRecord {
    schema: u16,
    handle_digest: Sha256Digest,
    kind: WindowsBrokerCustodyKind,
    content_sha256: Sha256Digest,
    byte_len: usize,
    created_at: UnixMillis,
    sealed_sha256: Sha256Digest,
    sealed_base64: String,
    record_digest: Sha256Digest,
}

fn record_digest(
    handle: Sha256Digest,
    kind: WindowsBrokerCustodyKind,
    content: Sha256Digest,
    byte_len: usize,
    created_at: UnixMillis,
    sealed: Sha256Digest,
) -> Sha256Digest {
    domain_digest(
        RECORD_DOMAIN,
        &[
            handle.as_bytes(),
            &[kind.domain_byte()],
            content.as_bytes(),
            &(byte_len as u64).to_be_bytes(),
            &created_at.get().to_be_bytes(),
            sealed.as_bytes(),
        ],
    )
}

fn encode_sealed_envelope(
    handle: Sha256Digest,
    kind: WindowsBrokerCustodyKind,
    content: Sha256Digest,
    created_at: UnixMillis,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
    let byte_len =
        u64::try_from(plaintext.len()).map_err(|_| WindowsBrokerCustodyError::Capacity)?;
    let capacity = SEALED_ENVELOPE_DOMAIN
        .len()
        .checked_add(2 + 32 + 1 + 32 + 8 + 8)
        .and_then(|fixed| fixed.checked_add(plaintext.len()))
        .ok_or(WindowsBrokerCustodyError::Capacity)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    encoded.extend_from_slice(SEALED_ENVELOPE_DOMAIN);
    encoded.extend_from_slice(&SEALED_ENVELOPE_SCHEMA.to_be_bytes());
    encoded.extend_from_slice(handle.as_bytes());
    encoded.push(kind.domain_byte());
    encoded.extend_from_slice(content.as_bytes());
    encoded.extend_from_slice(&byte_len.to_be_bytes());
    encoded.extend_from_slice(&created_at.get().to_be_bytes());
    encoded.extend_from_slice(plaintext);
    Ok(encoded)
}

fn decode_sealed_envelope(
    encoded: &[u8],
    record: &CustodyRecord,
) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
    let mut remaining = encoded;
    if take_bytes(&mut remaining, SEALED_ENVELOPE_DOMAIN.len())? != SEALED_ENVELOPE_DOMAIN
        || u16::from_be_bytes(take_array(&mut remaining)?) != SEALED_ENVELOPE_SCHEMA
        || Sha256Digest::from_bytes(take_array(&mut remaining)?) != record.handle_digest
        || u8::from_be_bytes(take_array(&mut remaining)?) != record.kind.domain_byte()
        || Sha256Digest::from_bytes(take_array(&mut remaining)?) != record.content_sha256
        || u64::from_be_bytes(take_array(&mut remaining)?)
            != u64::try_from(record.byte_len).map_err(|_| WindowsBrokerCustodyError::Tampered)?
        || i64::from_be_bytes(take_array(&mut remaining)?) != record.created_at.get()
        || remaining.len() != record.byte_len
        || sha256(remaining) != record.content_sha256
    {
        return Err(WindowsBrokerCustodyError::Tampered);
    }
    Ok(Zeroizing::new(remaining.to_vec()))
}

fn take_array<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], WindowsBrokerCustodyError> {
    take_bytes(remaining, N)?
        .try_into()
        .map_err(|_| WindowsBrokerCustodyError::Tampered)
}

fn take_bytes<'a>(
    remaining: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], WindowsBrokerCustodyError> {
    if remaining.len() < count {
        return Err(WindowsBrokerCustodyError::Tampered);
    }
    let (selected, rest) = remaining.split_at(count);
    *remaining = rest;
    Ok(selected)
}

fn sha256(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value).into())
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn record_path(root: &Path, handle: &WindowsBrokerCustodyHandle) -> PathBuf {
    root.join(format!("{}.custody-v1", handle.digest))
}

fn temp_path(
    root: &Path,
    handle: &WindowsBrokerCustodyHandle,
) -> Result<PathBuf, WindowsBrokerCustodyError> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| WindowsBrokerCustodyError::Protector)?;
    let nonce = lower_hex(&nonce);
    Ok(root.join(format!(".tmp-{}-{nonce}", handle.digest)))
}

fn completed_path(root: &Path, handle: &WindowsBrokerCustodyHandle) -> PathBuf {
    root.join(format!("{}.completed-v1", handle.digest))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn write_new_synchronized(path: &Path, bytes: &[u8]) -> Result<(), WindowsBrokerCustodyError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| WindowsBrokerCustodyError::Io)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| WindowsBrokerCustodyError::Io)
}

fn committed_entry_count(root: &Path) -> Result<usize, WindowsBrokerCustodyError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(root).map_err(|_| WindowsBrokerCustodyError::Io)? {
        let entry = entry.map_err(|_| WindowsBrokerCustodyError::Io)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(WindowsBrokerCustodyError::UnsafePath)?
            .to_owned();
        if name.ends_with(".custody-v1") || name.ends_with(".completed-v1") {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn reconcile_root(root: &Path) -> Result<(), WindowsBrokerCustodyError> {
    let mut handles = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|_| WindowsBrokerCustodyError::Io)? {
        let entry = entry.map_err(|_| WindowsBrokerCustodyError::Io)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(WindowsBrokerCustodyError::UnsafePath)?
            .to_owned();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| WindowsBrokerCustodyError::UnsafePath)?;
        if !metadata.file_type().is_file() || has_reparse_attribute(&metadata) {
            return Err(WindowsBrokerCustodyError::UnsafePath);
        }
        let committed = (name.len() == 64 + ".custody-v1".len() && name.ends_with(".custody-v1")
            || name.len() == 64 + ".completed-v1".len() && name.ends_with(".completed-v1"))
            && name[..64]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let incomplete = name.starts_with(".tmp-")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if incomplete {
            fs::remove_file(entry.path()).map_err(|_| WindowsBrokerCustodyError::Io)?;
        } else if !committed {
            return Err(WindowsBrokerCustodyError::UnsafePath);
        } else if !handles.insert(name[..64].to_owned()) {
            return Err(WindowsBrokerCustodyError::Tampered);
        }
    }
    Ok(())
}

fn validate_directory(path: &Path) -> Result<(), WindowsBrokerCustodyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WindowsBrokerCustodyError::UnsafePath)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || has_reparse_attribute(&metadata)
    {
        return Err(WindowsBrokerCustodyError::UnsafePath);
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), WindowsBrokerCustodyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WindowsBrokerCustodyError::UnsafePath)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || has_reparse_attribute(&metadata)
    {
        return Err(WindowsBrokerCustodyError::UnsafePath);
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn has_reparse_attribute(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestProtector;

    impl WindowsBrokerCustodyProtector for TestProtector {
        fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
            let mut sealed = b"test-v1:".to_vec();
            sealed.extend(plaintext.iter().map(|byte| byte ^ 0x5a));
            Ok(Zeroizing::new(sealed))
        }

        fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
            let ciphertext = sealed
                .strip_prefix(b"test-v1:")
                .ok_or(WindowsBrokerCustodyError::Protector)?;
            Ok(Zeroizing::new(
                ciphertext.iter().map(|byte| byte ^ 0x5a).collect(),
            ))
        }
    }

    fn temp_root() -> PathBuf {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).expect("random temp root");
        let nonce = lower_hex(&nonce);
        std::env::temp_dir().join(format!("automata-custody-{nonce}"))
    }

    #[test]
    fn survives_restart_and_removes_only_exact_handle() {
        let root = temp_root();
        let protector: Arc<dyn WindowsBrokerCustodyProtector> = Arc::new(TestProtector);
        let store = FileWindowsBrokerCustody::open(&root, Arc::clone(&protector)).expect("store");
        let handle = store
            .put(
                WindowsBrokerCustodyKind::EnrollmentSecret,
                b"enrollment-secret",
                UnixMillis::new(123),
            )
            .expect("put");
        let opaque = handle.opaque().to_owned();
        drop(store);

        let restarted = FileWindowsBrokerCustody::open(&root, protector).expect("restart");
        let parsed = WindowsBrokerCustodyHandle::parse(&opaque).expect("parse");
        let metadata = restarted.inspect(&parsed).expect("inspect");
        assert_eq!(metadata.kind(), WindowsBrokerCustodyKind::EnrollmentSecret);
        assert_eq!(metadata.byte_len(), b"enrollment-secret".len());
        assert_eq!(
            restarted.get(&parsed, 64).expect("get").as_slice(),
            b"enrollment-secret"
        );
        restarted.remove(&parsed).expect("remove");
        restarted.remove(&parsed).expect("idempotent remove");
        assert_eq!(
            restarted.inspect(&parsed).expect_err("removed"),
            WindowsBrokerCustodyError::Absent
        );
        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn admission_completion_is_exact_restart_safe_and_tombstoned() {
        let root = temp_root();
        let protector: Arc<dyn WindowsBrokerCustodyProtector> = Arc::new(TestProtector);
        let store = FileWindowsBrokerCustody::open(&root, Arc::clone(&protector)).expect("store");
        let receipt = b"signed-admission-receipt";
        let handle = store
            .put(
                WindowsBrokerCustodyKind::AdmissionReceipt,
                receipt,
                UnixMillis::new(789),
            )
            .expect("put");
        let digest = sha256(receipt);
        assert_eq!(
            store
                .complete_admission_receipt(&handle, sha256(b"wrong"))
                .expect_err("wrong digest"),
            WindowsBrokerCustodyError::Tampered
        );
        store
            .complete_admission_receipt(&handle, digest)
            .expect("complete");
        assert_eq!(
            store.inspect(&handle).expect_err("not live"),
            WindowsBrokerCustodyError::Absent
        );
        drop(store);

        let restarted = FileWindowsBrokerCustody::open(&root, protector).expect("restart");
        restarted
            .complete_admission_receipt(&handle, digest)
            .expect("idempotent exact completion");
        assert_eq!(
            restarted
                .complete_admission_receipt(&handle, sha256(b"different"))
                .expect_err("conflicting completion"),
            WindowsBrokerCustodyError::Tampered
        );
        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn tamper_unknown_fields_and_noncanonical_handles_fail_closed() {
        let root = temp_root();
        let store = FileWindowsBrokerCustody::open(&root, Arc::new(TestProtector)).expect("store");
        let handle = store
            .put(
                WindowsBrokerCustodyKind::AdmissionReceipt,
                b"receipt",
                UnixMillis::new(456),
            )
            .expect("put");
        let path = record_path(&root, &handle);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .insert("unknown".to_owned(), serde_json::json!(true));
        fs::write(&path, serde_json::to_vec(&value).expect("encode")).expect("tamper");
        assert_eq!(
            store.inspect(&handle).expect_err("unknown field"),
            WindowsBrokerCustodyError::Tampered
        );
        assert_eq!(
            WindowsBrokerCustodyHandle::parse(&handle.opaque().to_uppercase())
                .expect_err("noncanonical"),
            WindowsBrokerCustodyError::InvalidHandle
        );
        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn recomputed_outer_metadata_cannot_forge_the_sealed_record() {
        let root = temp_root();
        let store = FileWindowsBrokerCustody::open(&root, Arc::new(TestProtector)).expect("store");
        let handle = store
            .put(
                WindowsBrokerCustodyKind::AdmissionReceipt,
                b"receipt",
                UnixMillis::new(456),
            )
            .expect("put");
        let path = record_path(&root, &handle);
        let mut record: CustodyRecord =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("record");
        record.created_at = UnixMillis::new(999);
        record.record_digest = record_digest(
            record.handle_digest,
            record.kind,
            record.content_sha256,
            record.byte_len,
            record.created_at,
            record.sealed_sha256,
        );
        fs::write(&path, serde_json::to_vec(&record).expect("encode")).expect("forge metadata");

        assert_eq!(
            store
                .get(&handle, 64)
                .expect_err("sealed metadata mismatch"),
            WindowsBrokerCustodyError::Tampered
        );
        fs::remove_dir_all(root).expect("remove temp root");
    }
}
