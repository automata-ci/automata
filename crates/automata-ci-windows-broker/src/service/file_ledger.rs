//! Durable file-ledger adapter for the privileged broker lifecycle.

use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

use super::*;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerPayload {
    sequence: u64,
    entry: BrokerLedgerEntry,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerLine {
    payload: LedgerPayload,
    checksum: Sha256Digest,
}

/// Synchronized, checksummed append-only broker ledger.
#[derive(Debug)]
pub struct FileBrokerLedger {
    path: PathBuf,
    file: Mutex<Option<File>>,
    next_sequence: Mutex<u64>,
}

impl FileBrokerLedger {
    /// Opens an existing ledger or creates a new one at an exact path.
    ///
    /// On Windows the file is opened without write/delete sharing, preventing
    /// a second broker from concurrently consuming the same grant ledger.
    ///
    /// # Errors
    ///
    /// Rejects a non-file path, corrupt data, or an oversized journal.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, BrokerLedgerError> {
        let path = path.into();
        recover_compaction(&path)?;
        let file = open_ledger_file(&path)?;
        let ledger = Self {
            path,
            file: Mutex::new(Some(file)),
            next_sequence: Mutex::new(0),
        };
        let entries = ledger.read_all()?;
        *ledger
            .next_sequence
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            u64::try_from(entries.len()).map_err(|_| BrokerLedgerError::Capacity)?;
        Ok(ledger)
    }

    /// Returns the exact configured journal path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_all(&self) -> Result<Vec<BrokerLedgerEntry>, BrokerLedgerError> {
        let file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = file
            .as_ref()
            .ok_or(BrokerLedgerError::Io)?
            .try_clone()
            .map_err(|_| BrokerLedgerError::Io)?;
        read_ledger_file(&mut file)
    }

    fn compact_locked(
        &self,
        file: &mut Option<File>,
        next_sequence: &mut u64,
        now: UnixMillis,
    ) -> Result<(), BrokerLedgerError> {
        let mut reader = file
            .as_ref()
            .ok_or(BrokerLedgerError::Io)?
            .try_clone()
            .map_err(|_| BrokerLedgerError::Io)?;
        let entries = compacted_ledger_entries(read_ledger_file(&mut reader)?, now)?;
        drop(reader);
        replace_ledger_snapshot(&self.path, file, &entries)?;
        *next_sequence = u64::try_from(entries.len()).map_err(|_| BrokerLedgerError::Capacity)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn compact_at(&self, now: UnixMillis) -> Result<(), BrokerLedgerError> {
        let mut next = self
            .next_sequence
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        self.compact_locked(&mut file, &mut next, now)
    }
}

fn read_ledger_file(file: &mut File) -> Result<Vec<BrokerLedgerEntry>, BrokerLedgerError> {
    let metadata = file.metadata().map_err(|_| BrokerLedgerError::Io)?;
    if metadata.len() > MAX_LEDGER_BYTES {
        return Err(BrokerLedgerError::Capacity);
    }
    // `File::try_clone` shares the cursor on Windows and Unix. Appends leave it at EOF,
    // so every replay must explicitly rewind before rebuilding the durable state.
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BrokerLedgerError::Io)?;
    let mut entries = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|_| BrokerLedgerError::Io)?;
        if line.is_empty() || entries.len() >= MAX_LEDGER_EVENTS {
            return Err(BrokerLedgerError::Capacity);
        }
        let record: LedgerLine =
            serde_json::from_str(&line).map_err(|_| BrokerLedgerError::Corrupt)?;
        let sequence = u64::try_from(entries.len()).map_err(|_| BrokerLedgerError::Capacity)?;
        if record.payload.sequence != sequence
            || ledger_checksum(&record.payload)? != record.checksum
        {
            return Err(BrokerLedgerError::Corrupt);
        }
        entries.push(record.payload.entry);
    }
    Ok(entries)
}

impl BrokerLedger for FileBrokerLedger {
    fn load(&self) -> Result<Vec<BrokerLedgerEntry>, BrokerLedgerError> {
        self.read_all()
    }

    fn append(&self, entry: &BrokerLedgerEntry) -> Result<(), BrokerLedgerError> {
        let mut next = self
            .next_sequence
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let now = system_unix_millis().ok_or(BrokerLedgerError::Io)?;
        let mut encoded = encode_ledger_line(*next, entry)?;
        if ledger_append_exceeds_capacity(file.as_ref(), *next, encoded.len())? {
            self.compact_locked(&mut file, &mut next, now)?;
            encoded = encode_ledger_line(*next, entry)?;
            if ledger_append_exceeds_capacity(file.as_ref(), *next, encoded.len())? {
                return Err(BrokerLedgerError::Capacity);
            }
        }
        let file = file.as_mut().ok_or(BrokerLedgerError::Io)?;
        file.write_all(&encoded)
            .map_err(|_| BrokerLedgerError::Io)?;
        file.write_all(b"\n").map_err(|_| BrokerLedgerError::Io)?;
        file.sync_data().map_err(|_| BrokerLedgerError::Io)?;
        *next = next.checked_add(1).ok_or(BrokerLedgerError::Capacity)?;
        Ok(())
    }
}

fn encode_ledger_line(
    sequence: u64,
    entry: &BrokerLedgerEntry,
) -> Result<Vec<u8>, BrokerLedgerError> {
    let payload = LedgerPayload {
        sequence,
        entry: entry.clone(),
    };
    let line = LedgerLine {
        checksum: ledger_checksum(&payload)?,
        payload,
    };
    serde_json::to_vec(&line).map_err(|_| BrokerLedgerError::Corrupt)
}

fn ledger_append_exceeds_capacity(
    file: Option<&File>,
    next_sequence: u64,
    encoded_length: usize,
) -> Result<bool, BrokerLedgerError> {
    if next_sequence >= u64::try_from(MAX_LEDGER_EVENTS).map_err(|_| BrokerLedgerError::Capacity)? {
        return Ok(true);
    }
    let length = file
        .ok_or(BrokerLedgerError::Io)?
        .metadata()
        .map_err(|_| BrokerLedgerError::Io)?
        .len();
    let additional =
        u64::try_from(encoded_length.saturating_add(1)).map_err(|_| BrokerLedgerError::Capacity)?;
    Ok(length
        .checked_add(additional)
        .is_none_or(|total| total > MAX_LEDGER_BYTES))
}

fn compacted_ledger_entries(
    entries: Vec<BrokerLedgerEntry>,
    now: UnixMillis,
) -> Result<Vec<BrokerLedgerEntry>, BrokerLedgerError> {
    let mut latest = BTreeMap::<Sha256Digest, BrokerLedgerEntry>::new();
    for entry in entries {
        validate_ledger_entry(&entry).map_err(|_| BrokerLedgerError::Corrupt)?;
        if let Some(previous) = latest.get(&entry.grant_digest)
            && !same_durable_identity(previous, &entry)
        {
            return Err(BrokerLedgerError::Corrupt);
        }
        latest.insert(entry.grant_digest, entry);
    }
    latest.retain(|_, entry| {
        !matches!(
            entry.phase,
            BrokerLifecyclePhase::Destroyed | BrokerLifecyclePhase::ConsumedFailed
        ) || now.get()
            <= entry
                .expires_at
                .get()
                .saturating_add(LEDGER_TOMBSTONE_CLOCK_SKEW_MILLIS)
    });
    Ok(latest.into_values().collect())
}

fn replace_ledger_snapshot(
    path: &Path,
    current: &mut Option<File>,
    entries: &[BrokerLedgerEntry],
) -> Result<(), BrokerLedgerError> {
    let (temporary, previous) = ledger_sidecar_paths(path)?;
    if temporary.exists() || previous.exists() {
        return Err(BrokerLedgerError::Corrupt);
    }
    write_ledger_snapshot(&temporary, entries)?;
    sync_parent_directory(path)?;

    drop(current.take());
    let rotation = (|| {
        fs::rename(path, &previous).map_err(|_| BrokerLedgerError::Io)?;
        sync_parent_directory(path)?;
        fs::rename(&temporary, path).map_err(|_| BrokerLedgerError::Io)?;
        sync_parent_directory(path)?;
        Ok::<(), BrokerLedgerError>(())
    })();
    if rotation.is_err() {
        let _ = recover_compaction(path);
        *current = open_ledger_file(path).ok();
        return rotation;
    }

    *current = Some(open_ledger_file(path)?);
    fs::remove_file(&previous).map_err(|_| BrokerLedgerError::Io)?;
    sync_parent_directory(path)
}

fn write_ledger_snapshot(
    path: &Path,
    entries: &[BrokerLedgerEntry],
) -> Result<(), BrokerLedgerError> {
    if entries.len() > MAX_LEDGER_EVENTS {
        return Err(BrokerLedgerError::Capacity);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| BrokerLedgerError::Io)?;
    let mut total = 0_u64;
    for (sequence, entry) in entries.iter().enumerate() {
        let sequence = u64::try_from(sequence).map_err(|_| BrokerLedgerError::Capacity)?;
        let encoded = encode_ledger_line(sequence, entry)?;
        let additional = u64::try_from(encoded.len().saturating_add(1))
            .map_err(|_| BrokerLedgerError::Capacity)?;
        total = total
            .checked_add(additional)
            .ok_or(BrokerLedgerError::Capacity)?;
        if total > MAX_LEDGER_BYTES {
            return Err(BrokerLedgerError::Capacity);
        }
        file.write_all(&encoded)
            .map_err(|_| BrokerLedgerError::Io)?;
        file.write_all(b"\n").map_err(|_| BrokerLedgerError::Io)?;
    }
    file.sync_all().map_err(|_| BrokerLedgerError::Io)
}

fn recover_compaction(path: &Path) -> Result<(), BrokerLedgerError> {
    let (temporary, previous) = ledger_sidecar_paths(path)?;
    let main_exists = path.try_exists().map_err(|_| BrokerLedgerError::Io)?;
    let temporary_exists = temporary.try_exists().map_err(|_| BrokerLedgerError::Io)?;
    let previous_exists = previous.try_exists().map_err(|_| BrokerLedgerError::Io)?;

    if main_exists {
        validate_ledger_path(path)?;
        remove_sidecar_if_present(&temporary, temporary_exists)?;
        remove_sidecar_if_present(&previous, previous_exists)?;
        if temporary_exists || previous_exists {
            sync_parent_directory(path)?;
        }
        return Ok(());
    }

    if temporary_exists {
        validate_ledger_path(&temporary)?;
        fs::rename(&temporary, path).map_err(|_| BrokerLedgerError::Io)?;
        remove_sidecar_if_present(&previous, previous_exists)?;
        sync_parent_directory(path)?;
        return Ok(());
    }
    if previous_exists {
        validate_ledger_path(&previous)?;
        fs::rename(&previous, path).map_err(|_| BrokerLedgerError::Io)?;
        sync_parent_directory(path)?;
    }
    Ok(())
}

fn validate_ledger_path(path: &Path) -> Result<(), BrokerLedgerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BrokerLedgerError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(BrokerLedgerError::Corrupt);
    }
    let mut file = File::open(path).map_err(|_| BrokerLedgerError::Io)?;
    read_ledger_file(&mut file).map(|_| ())
}

fn remove_sidecar_if_present(path: &Path, present: bool) -> Result<(), BrokerLedgerError> {
    if present {
        let metadata = fs::symlink_metadata(path).map_err(|_| BrokerLedgerError::Io)?;
        if !metadata.file_type().is_file() {
            return Err(BrokerLedgerError::Corrupt);
        }
        fs::remove_file(path).map_err(|_| BrokerLedgerError::Io)?;
    }
    Ok(())
}

pub(super) fn ledger_sidecar_paths(path: &Path) -> Result<(PathBuf, PathBuf), BrokerLedgerError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(BrokerLedgerError::Io)?;
    Ok((
        path.with_file_name(format!("{name}.compact.tmp")),
        path.with_file_name(format!("{name}.compact.previous")),
    ))
}

#[cfg(windows)]
fn sync_parent_directory(path: &Path) -> Result<(), BrokerLedgerError> {
    let parent = path.parent().ok_or(BrokerLedgerError::Io)?;
    // `FlushFileBuffers` rejects directory handles on supported Windows
    // filesystems. Each snapshot is fully flushed before the closed-handle
    // rename sequence, and startup accepts every possible old/temp/new
    // combination, so recovery does not depend on a directory flush.
    fs::metadata(parent)
        .map_err(|_| BrokerLedgerError::Io)
        .and_then(|metadata| {
            if metadata.is_dir() {
                Ok(())
            } else {
                Err(BrokerLedgerError::Io)
            }
        })
}

#[cfg(not(windows))]
fn sync_parent_directory(path: &Path) -> Result<(), BrokerLedgerError> {
    let parent = path.parent().ok_or(BrokerLedgerError::Io)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| BrokerLedgerError::Io)
}

#[cfg(windows)]
fn open_ledger_file(path: &Path) -> Result<File, BrokerLedgerError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| BrokerLedgerError::Io)
}

#[cfg(not(windows))]
fn open_ledger_file(path: &Path) -> Result<File, BrokerLedgerError> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|_| BrokerLedgerError::Io)
}

fn ledger_checksum(payload: &LedgerPayload) -> Result<Sha256Digest, BrokerLedgerError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| BrokerLedgerError::Corrupt)?;
    Ok(domain_digest(LEDGER_DOMAIN, &[&encoded]))
}
