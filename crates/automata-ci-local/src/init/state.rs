use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read as _, Write as _},
    os::fd::OwnedFd,
    os::unix::ffi::OsStrExt as _,
    path::{Component, Path},
};

use rustix::fs::{
    self, Dir, FileType, FlockOperation, Mode, OFlags, fstat, mkdirat, openat, renameat_with,
};
use sha2::{Digest as _, Sha256};

use automata_ci_core::Sha256Digest;

use super::{LocalInitError, LocalInitErrorCode};

const OPERATION_LOCK: &str = "operation.lock";
const MATERIAL_ROOT: &str = "material-root";
const EPOCH_RECORD: &str = "epoch.json";
const CERTIFICATE_RECORD: &str = "certificates.json";
const INSTALLATION_SELECTION: &str = "installation-selection.json";
const MATERIALIZATION_RECORD: &str = "materialization.json";
const INIT_RECORDS: [&str; 5] = [
    INSTALLATION_SELECTION,
    MATERIAL_ROOT,
    EPOCH_RECORD,
    CERTIFICATE_RECORD,
    MATERIALIZATION_RECORD,
];
const RESET_INTENT_RECORD: &str = "reset-intent.json";
const MAX_EPOCH_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_RECORD_BYTES: usize = 128 * 1024;
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_CANDIDATE_BYTES: usize = 160 * 1024 * 1024;
const STATE_AUTHORITY_DOMAIN: &[u8] = b"automata/local/state-authority/v1\0";

pub(super) struct StateRoot {
    directory: OwnedFd,
    _operation_lock: OwnedFd,
    authority_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct StateSnapshot {
    pub(super) material_root: Option<Vec<u8>>,
    pub(super) epoch: Option<Vec<u8>>,
    pub(super) certificates: Option<Vec<u8>>,
    pub(super) installation_selection: Option<Vec<u8>>,
    pub(super) materialization: Option<Vec<u8>>,
    pub(super) reset_intent: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ResetRecordObservation {
    present: bool,
    completed_present: bool,
    staged_present: bool,
    completed: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
}

impl ResetRecordObservation {
    pub(super) const fn present(&self) -> bool {
        self.present
    }

    pub(super) const fn completed_present(&self) -> bool {
        self.completed_present
    }

    pub(super) const fn staged_present(&self) -> bool {
        self.staged_present
    }

    pub(super) fn completed(&self) -> Option<&[u8]> {
        self.completed.as_deref()
    }

    pub(super) fn staged(&self) -> Option<&[u8]> {
        self.staged.as_deref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ResetStateSnapshot {
    pub(super) material_root: ResetRecordObservation,
    pub(super) epoch: ResetRecordObservation,
    pub(super) certificates: ResetRecordObservation,
    pub(super) installation_selection: ResetRecordObservation,
    pub(super) materialization: ResetRecordObservation,
    pub(super) reset_intent: ResetRecordObservation,
}

impl ResetStateSnapshot {
    pub(super) fn is_empty(&self) -> bool {
        !self.material_root.present()
            && !self.epoch.present()
            && !self.certificates.present()
            && !self.installation_selection.present()
            && !self.materialization.present()
            && !self.reset_intent.present()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StateRecord {
    Materialization,
    Certificates,
    MaterialRoot,
    InstallationSelection,
    Epoch,
    ResetIntent,
}

impl StateRecord {
    const ALL: [Self; 6] = [
        Self::Materialization,
        Self::Certificates,
        Self::MaterialRoot,
        Self::InstallationSelection,
        Self::Epoch,
        Self::ResetIntent,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Materialization => MATERIALIZATION_RECORD,
            Self::Certificates => CERTIFICATE_RECORD,
            Self::MaterialRoot => MATERIAL_ROOT,
            Self::InstallationSelection => INSTALLATION_SELECTION,
            Self::Epoch => EPOCH_RECORD,
            Self::ResetIntent => RESET_INTENT_RECORD,
        }
    }

    const fn maximum(self) -> usize {
        match self {
            Self::Certificates => MAX_CERTIFICATE_RECORD_BYTES,
            Self::MaterialRoot => 32,
            Self::Materialization
            | Self::InstallationSelection
            | Self::Epoch
            | Self::ResetIntent => MAX_EPOCH_BYTES,
        }
    }
}

impl StateRoot {
    pub(super) fn acquire(path: &Path) -> Result<Self, LocalInitError> {
        let (parent, name) = open_parent(path, true)?;
        match mkdirat(&parent, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(state_path()),
        }
        let directory =
            openat(&parent, &name, directory_flags(), Mode::empty()).map_err(|_| state_path())?;
        let initial_root = private_directory_metadata(&directory)?;
        fs::fsync(&parent).map_err(|_| state_path())?;

        let operation_lock = open_operation_lock(&directory)?;
        lock(&operation_lock, FlockOperation::NonBlockingLockExclusive)?;
        let (root_metadata, lock_metadata) =
            revalidate_root_and_lock(&parent, &name, &directory, &operation_lock, &initial_root)?;
        let authority_sha256 = state_authority_digest(&root_metadata, &lock_metadata);
        let state = Self {
            directory,
            _operation_lock: operation_lock,
            authority_sha256,
        };
        state.validate_replay_layout()?;
        Ok(state)
    }

    pub(super) fn observe_existing(path: &Path) -> Result<Self, LocalInitError> {
        Self::open_existing(path, FlockOperation::NonBlockingLockShared)
    }

    pub(super) fn acquire_existing(path: &Path) -> Result<Self, LocalInitError> {
        Self::open_existing(path, FlockOperation::NonBlockingLockExclusive)
    }

    fn open_existing(path: &Path, operation: FlockOperation) -> Result<Self, LocalInitError> {
        let (parent, name) = open_parent(path, true)?;
        let directory =
            openat(&parent, &name, directory_flags(), Mode::empty()).map_err(|error| {
                if error == rustix::io::Errno::NOENT {
                    reset_required()
                } else {
                    state_path()
                }
            })?;
        let initial_root = private_directory_metadata(&directory)?;
        let operation_lock = open_operation_lock_existing(&directory)?;
        lock(&operation_lock, operation)?;
        let (root_metadata, lock_metadata) =
            revalidate_root_and_lock(&parent, &name, &directory, &operation_lock, &initial_root)?;
        Ok(Self {
            directory,
            _operation_lock: operation_lock,
            authority_sha256: state_authority_digest(&root_metadata, &lock_metadata),
        })
    }

    pub(super) const fn authority_sha256(&self) -> Sha256Digest {
        self.authority_sha256
    }

    /// Requires the exact crash-prefix namespace admitted by initialization.
    /// One fixed temporary may exist only at the next record frontier, or
    /// alongside the last completed record for equal-byte recovery.
    pub(super) fn validate_replay_layout(&self) -> Result<(), LocalInitError> {
        let names = self.entry_names()?;
        validate_init_record_layout(&names, None)
    }

    /// Requires a strict completed-record prefix after every recoverable
    /// fixed temporary has been reconciled by the record loaders.
    pub(super) fn validate_recovered_layout(&self) -> Result<(), LocalInitError> {
        let names = self.entry_names()?;
        validate_init_record_layout(&names, None)?;
        if INIT_RECORDS
            .into_iter()
            .any(|name| names.contains(&temporary_name(name)))
        {
            return Err(reset_required());
        }
        Ok(())
    }

    pub(super) fn reset_intent_present(&self) -> Result<bool, LocalInitError> {
        let temporary = temporary_name(RESET_INTENT_RECORD);
        Ok(self
            .read_private(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?
            .is_some()
            || self.read_private(&temporary, MAX_EPOCH_BYTES)?.is_some())
    }

    pub(super) fn snapshot_read_only(&self) -> Result<StateSnapshot, LocalInitError> {
        let names = self.exact_entry_names(false)?;
        let snapshot = StateSnapshot {
            material_root: self.read_private(MATERIAL_ROOT, 32)?,
            epoch: self.read_private(EPOCH_RECORD, MAX_EPOCH_BYTES)?,
            certificates: self.read_private(CERTIFICATE_RECORD, MAX_CERTIFICATE_RECORD_BYTES)?,
            installation_selection: self.read_private(INSTALLATION_SELECTION, MAX_EPOCH_BYTES)?,
            materialization: self.read_private(MATERIALIZATION_RECORD, MAX_EPOCH_BYTES)?,
            reset_intent: self.read_private(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?,
        };
        let repeated = self.exact_entry_names(false)?;
        if repeated != names {
            return Err(reset_required());
        }
        if snapshot.reset_intent.is_none() {
            validate_init_record_layout(&repeated, None)?;
        }
        Ok(snapshot)
    }

    pub(super) fn snapshot_for_reset(&self) -> Result<ResetStateSnapshot, LocalInitError> {
        let names = self.exact_entry_names(true)?;
        let snapshot = ResetStateSnapshot {
            material_root: self.observe_record_for_reset(StateRecord::MaterialRoot)?,
            epoch: self.observe_record_for_reset(StateRecord::Epoch)?,
            certificates: self.observe_record_for_reset(StateRecord::Certificates)?,
            installation_selection: self
                .observe_record_for_reset(StateRecord::InstallationSelection)?,
            materialization: self.observe_record_for_reset(StateRecord::Materialization)?,
            reset_intent: self.observe_record_for_reset(StateRecord::ResetIntent)?,
        };
        if self.exact_entry_names(true)? != names {
            return Err(reset_required());
        }
        Ok(snapshot)
    }

    pub(super) fn observe_reset_intent_for_reset(
        &self,
    ) -> Result<ResetRecordObservation, LocalInitError> {
        self.observe_record_for_reset(StateRecord::ResetIntent)
    }

    pub(super) fn reconcile_validated_reset_intent(
        &self,
        expected: &[u8],
    ) -> Result<Vec<u8>, LocalInitError> {
        let temporary = temporary_name(RESET_INTENT_RECORD);
        let completed = self.observe_private_for_reset(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?;
        let staged = self.observe_private_for_reset(&temporary, MAX_EPOCH_BYTES)?;
        let completed_bytes = readable_reset_authority(&completed)?;
        let staged_bytes = readable_reset_authority(&staged)?;
        let Some(staged_bytes) = staged_bytes else {
            return match completed_bytes {
                Some(completed_bytes) if completed_bytes == expected => {
                    Ok(completed_bytes.to_vec())
                }
                _ => Err(reset_required()),
            };
        };
        if let Some(completed_bytes) = completed_bytes {
            if completed_bytes != expected || staged_bytes != expected {
                return Err(reset_required());
            }
            self.remove_private_for_reset(&temporary, MAX_EPOCH_BYTES)?;
            let published = self.observe_private_for_reset(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?;
            let residual = self.observe_private_for_reset(&temporary, MAX_EPOCH_BYTES)?;
            if readable_reset_authority(&published)? != Some(expected) || residual.present {
                return Err(reset_required());
            }
            return Ok(expected.to_vec());
        }
        if staged_bytes != expected {
            return Err(reset_required());
        }
        renameat_with(
            &self.directory,
            &temporary,
            &self.directory,
            RESET_INTENT_RECORD,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| reset_required())?;
        fs::fsync(&self.directory).map_err(|_| reset_required())?;
        let published = self.observe_private_for_reset(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?;
        let residual = self.observe_private_for_reset(&temporary, MAX_EPOCH_BYTES)?;
        if readable_reset_authority(&published)? != Some(staged_bytes) || residual.present {
            return Err(reset_required());
        }
        Ok(staged_bytes.to_vec())
    }

    pub(super) fn store_reset_intent(&self, bytes: &[u8]) -> Result<(), LocalInitError> {
        if bytes.is_empty() || bytes.len() > MAX_EPOCH_BYTES {
            return Err(state_path());
        }
        self.exact_entry_names(true)?;
        let completed = self.read_private(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?;
        let recovered = self.recover_temporary(
            RESET_INTENT_RECORD,
            MAX_EPOCH_BYTES,
            completed.as_deref().or(Some(bytes)),
        )?;
        if let Some(existing) = completed.or(recovered) {
            if existing != bytes {
                return Err(reset_required());
            }
        } else {
            let result = match self.create_private(RESET_INTENT_RECORD, bytes) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == LocalInitErrorCode::StateCollision => {
                    if self
                        .read_private(RESET_INTENT_RECORD, MAX_EPOCH_BYTES)?
                        .as_deref()
                        == Some(bytes)
                    {
                        Ok(())
                    } else {
                        Err(reset_required())
                    }
                }
                Err(error) => Err(error),
            };
            result?;
        }
        let snapshot = self.snapshot_for_reset()?;
        if snapshot.reset_intent.completed() != Some(bytes)
            || snapshot.reset_intent.staged_present()
        {
            return Err(reset_required());
        }
        Ok(())
    }

    pub(super) fn remove_record(&self, record: StateRecord) -> Result<(), LocalInitError> {
        let name = record.name();
        let temporary = temporary_name(name);
        for candidate in [&temporary, name] {
            self.remove_private_for_reset(candidate, record.maximum())?;
        }
        if self
            .observe_private_for_reset(name, record.maximum())?
            .present
            || self
                .observe_private_for_reset(&temporary, record.maximum())?
                .present
        {
            return Err(reset_required());
        }
        Ok(())
    }

    /// Requires the four authority/material records and no temporary before
    /// the first durable materialization-complete publication.
    pub(super) fn validate_before_materialization(&self) -> Result<(), LocalInitError> {
        let names = self.entry_names()?;
        validate_init_record_layout(&names, Some(4))
    }

    /// Requires the complete successful initialization namespace, with no
    /// temporary or unknown entry remaining.
    pub(super) fn validate_complete(&self) -> Result<(), LocalInitError> {
        let names = self.entry_names()?;
        validate_init_record_layout(&names, Some(INIT_RECORDS.len()))
    }

    fn remove_private_for_reset(&self, name: &str, maximum: usize) -> Result<(), LocalInitError> {
        if self.observe_private_for_reset(name, maximum)?.present {
            let _attempt = fs::unlinkat(&self.directory, name, fs::AtFlags::empty());
            if self.observe_private_for_reset(name, maximum)?.present
                || fs::fsync(&self.directory).is_err()
            {
                return Err(reset_required());
            }
        }
        Ok(())
    }

    fn exact_entry_names(
        &self,
        allow_temporaries: bool,
    ) -> Result<BTreeSet<String>, LocalInitError> {
        let mut allowed = BTreeSet::from([OPERATION_LOCK.to_owned()]);
        for record in StateRecord::ALL {
            allowed.insert(record.name().to_owned());
            if allow_temporaries {
                allowed.insert(temporary_name(record.name()));
            }
        }
        let names = self.entry_names()?;
        if !names.contains(OPERATION_LOCK) || names.iter().any(|name| !allowed.contains(name)) {
            return Err(reset_required());
        }
        Ok(names)
    }

    fn observe_record_for_reset(
        &self,
        record: StateRecord,
    ) -> Result<ResetRecordObservation, LocalInitError> {
        let completed = self.observe_private_for_reset(record.name(), record.maximum())?;
        let temporary =
            self.observe_private_for_reset(&temporary_name(record.name()), record.maximum())?;
        Ok(ResetRecordObservation {
            present: completed.present || temporary.present,
            completed_present: completed.present,
            staged_present: temporary.present,
            completed: completed.completed,
            staged: temporary.completed,
        })
    }

    pub(super) fn load_material_root(&self) -> Result<Option<[u8; 32]>, LocalInitError> {
        let bytes = self.load_private_record(MATERIAL_ROOT, 32)?;
        if let Some(bytes) = bytes {
            return bytes.try_into().map(Some).map_err(|_| reset_required());
        }
        Ok(None)
    }

    pub(super) fn create_material_root(&self) -> Result<[u8; 32], LocalInitError> {
        self.validate_publication_order(MATERIAL_ROOT)?;
        if let Some(root) = self.load_material_root()? {
            self.validate_record_published(MATERIAL_ROOT)?;
            return Ok(root);
        }
        let mut root = [0_u8; 32];
        getrandom::fill(&mut root).map_err(|_| state_path())?;
        let root = match self.create_private(MATERIAL_ROOT, &root) {
            Ok(()) => Ok(root),
            Err(error) if error.code() == LocalInitErrorCode::StateCollision => {
                self.load_material_root()?.ok_or_else(reset_required)
            }
            Err(error) => Err(error),
        }?;
        self.validate_record_published(MATERIAL_ROOT)?;
        Ok(root)
    }

    pub(super) fn load_epoch(&self) -> Result<Option<Vec<u8>>, LocalInitError> {
        self.load_private_record(EPOCH_RECORD, MAX_EPOCH_BYTES)
    }

    pub(super) fn store_epoch(&self, bytes: &[u8]) -> Result<(), LocalInitError> {
        self.create_or_match_private(EPOCH_RECORD, bytes, MAX_EPOCH_BYTES)
    }

    pub(super) fn load_certificates(&self) -> Result<Option<Vec<u8>>, LocalInitError> {
        self.load_private_record(CERTIFICATE_RECORD, MAX_CERTIFICATE_RECORD_BYTES)
    }

    pub(super) fn store_certificates(&self, bytes: &[u8]) -> Result<(), LocalInitError> {
        self.create_or_match_private(CERTIFICATE_RECORD, bytes, MAX_CERTIFICATE_RECORD_BYTES)
    }

    pub(super) fn load_installation_selection(&self) -> Result<Option<Vec<u8>>, LocalInitError> {
        self.load_private_record(INSTALLATION_SELECTION, MAX_EPOCH_BYTES)
    }

    pub(super) fn store_installation_selection(&self, bytes: &[u8]) -> Result<(), LocalInitError> {
        self.create_or_match_private(INSTALLATION_SELECTION, bytes, MAX_EPOCH_BYTES)
    }

    pub(super) fn load_materialization(&self) -> Result<Option<Vec<u8>>, LocalInitError> {
        self.load_private_record(MATERIALIZATION_RECORD, MAX_EPOCH_BYTES)
    }

    pub(super) fn store_materialization(&self, bytes: &[u8]) -> Result<(), LocalInitError> {
        self.create_or_match_private(MATERIALIZATION_RECORD, bytes, MAX_EPOCH_BYTES)
    }

    fn create_or_match_private(
        &self,
        name: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), LocalInitError> {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(state_path());
        }
        self.validate_publication_order(name)?;
        let completed = self.read_private(name, maximum)?;
        let recovered =
            self.recover_temporary(name, maximum, completed.as_deref().or(Some(bytes)))?;
        if let Some(existing) = completed.or(recovered) {
            return if existing == bytes {
                self.validate_record_published(name)
            } else {
                Err(reset_required())
            };
        }
        let result = match self.create_private(name, bytes) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == LocalInitErrorCode::StateCollision => {
                if self.read_private(name, maximum)?.as_deref() == Some(bytes) {
                    Ok(())
                } else {
                    Err(reset_required())
                }
            }
            Err(error) => Err(error),
        };
        result?;
        self.validate_record_published(name)
    }

    fn load_private_record(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, LocalInitError> {
        self.validate_replay_layout()?;
        let completed = self.read_private(name, maximum)?;
        let recovered = self.recover_temporary(name, maximum, completed.as_deref())?;
        let result = completed.or(recovered);
        self.validate_replay_layout()?;
        Ok(result)
    }

    fn recover_temporary(
        &self,
        name: &str,
        maximum: usize,
        expected: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, LocalInitError> {
        let temporary = temporary_name(name);
        let Some(bytes) = self.read_private(&temporary, maximum)? else {
            return Ok(None);
        };
        if expected.is_some_and(|expected| expected != bytes) {
            return Err(reset_required());
        }
        match renameat_with(
            &self.directory,
            &temporary,
            &self.directory,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                let final_bytes = self
                    .read_private(name, maximum)?
                    .ok_or_else(reset_required)?;
                if final_bytes != bytes {
                    return Err(reset_required());
                }
                fs::unlinkat(&self.directory, &temporary, fs::AtFlags::empty())
                    .map_err(|_| reset_required())?;
            }
            Err(_) => return Err(reset_required()),
        }
        fs::fsync(&self.directory).map_err(|_| reset_required())?;
        self.read_private(name, maximum)
    }

    fn read_private(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>, LocalInitError> {
        let descriptor = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(reset_required()),
        };
        let before = verify_private_regular(&descriptor, None)?;
        let size = usize::try_from(before.st_size).map_err(|_| reset_required())?;
        if size == 0 || size > maximum {
            return Err(reset_required());
        }
        let mut file = File::from(descriptor);
        let mut bytes = Vec::with_capacity(size);
        std::io::Read::by_ref(&mut file)
            .take(u64::try_from(maximum + 1).expect("bounded state file size fits u64"))
            .read_to_end(&mut bytes)
            .map_err(|_| reset_required())?;
        let after = fstat(&file).map_err(|_| reset_required())?;
        if bytes.len() != size || !same_file(&before, &after) {
            return Err(reset_required());
        }
        Ok(Some(bytes))
    }

    fn observe_private_for_reset(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<ResetRecordObservation, LocalInitError> {
        let descriptor = match openat(
            &self.directory,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(ResetRecordObservation::default()),
            Err(_) => return Err(reset_required()),
        };
        let before = verify_safe_reset_regular(&descriptor)?;
        let size = usize::try_from(before.st_size).map_err(|_| reset_required())?;
        if size == 0 || size > maximum || before.st_mode & 0o400 == 0 {
            let after = fstat(&descriptor).map_err(|_| reset_required())?;
            if !same_file(&before, &after) {
                return Err(reset_required());
            }
            return Ok(ResetRecordObservation {
                present: true,
                completed_present: true,
                staged_present: false,
                completed: None,
                staged: None,
            });
        }
        let readable = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| reset_required())?;
        let readable_before = verify_safe_reset_regular(&readable)?;
        if !same_file(&before, &readable_before) {
            return Err(reset_required());
        }
        let mut file = File::from(readable);
        let mut bytes = Vec::with_capacity(size);
        std::io::Read::by_ref(&mut file)
            .take(u64::try_from(maximum + 1).expect("bounded state file size fits u64"))
            .read_to_end(&mut bytes)
            .map_err(|_| reset_required())?;
        let after = fstat(&file).map_err(|_| reset_required())?;
        if bytes.len() != size || !same_file(&readable_before, &after) {
            return Err(reset_required());
        }
        Ok(ResetRecordObservation {
            present: true,
            completed_present: true,
            staged_present: false,
            completed: Some(bytes),
            staged: None,
        })
    }

    fn create_private(&self, name: &str, bytes: &[u8]) -> Result<(), LocalInitError> {
        let temporary = temporary_name(name);
        let descriptor = openat(
            &self.directory,
            &temporary,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                LocalInitError::new(LocalInitErrorCode::StateCollision)
            } else {
                state_path()
            }
        })?;
        let result = (|| {
            fs::fchmod(&descriptor, Mode::from_raw_mode(0o600)).map_err(|_| state_path())?;
            let mut file = File::from(descriptor);
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| state_path())?;
            drop(file);
            renameat_with(
                &self.directory,
                &temporary,
                &self.directory,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    LocalInitError::new(LocalInitErrorCode::StateCollision)
                } else {
                    state_path()
                }
            })?;
            fs::fsync(&self.directory).map_err(|_| state_path())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.directory, &temporary, fs::AtFlags::empty());
            let _ = fs::fsync(&self.directory);
        }
        result
    }

    fn entry_names(&self) -> Result<BTreeSet<String>, LocalInitError> {
        let mut names = BTreeSet::new();
        for entry in Dir::read_from(&self.directory).map_err(|_| reset_required())? {
            let entry = entry.map_err(|_| reset_required())?;
            let name = entry.file_name().to_str().map_err(|_| reset_required())?;
            if matches!(name, "." | "..") {
                continue;
            }
            if !names.insert(name.to_owned()) {
                return Err(reset_required());
            }
        }
        Ok(names)
    }

    fn validate_publication_order(&self, name: &str) -> Result<(), LocalInitError> {
        let index = INIT_RECORDS
            .iter()
            .position(|record| *record == name)
            .ok_or_else(reset_required)?;
        let names = self.entry_names()?;
        validate_init_record_layout(&names, None)?;
        let temporary = temporary_name(name);
        if INIT_RECORDS
            .iter()
            .map(|record| temporary_name(record))
            .any(|candidate| candidate != temporary && names.contains(&candidate))
        {
            return Err(reset_required());
        }
        if names.contains(name) {
            return Ok(());
        }
        let completed = INIT_RECORDS
            .iter()
            .take_while(|record| names.contains(**record))
            .count();
        if completed != index {
            return Err(reset_required());
        }
        Ok(())
    }

    fn validate_record_published(&self, name: &str) -> Result<(), LocalInitError> {
        let names = self.entry_names()?;
        validate_init_record_layout(&names, None)?;
        if !names.contains(name)
            || INIT_RECORDS
                .iter()
                .any(|record| names.contains(&temporary_name(record)))
        {
            return Err(reset_required());
        }
        Ok(())
    }
}

fn validate_init_record_layout(
    names: &BTreeSet<String>,
    exact_completed: Option<usize>,
) -> Result<(), LocalInitError> {
    if !names.contains(OPERATION_LOCK) {
        return Err(reset_required());
    }
    let mut remaining = names.clone();
    remaining.remove(OPERATION_LOCK);
    let completed = INIT_RECORDS
        .into_iter()
        .take_while(|name| remaining.remove(*name))
        .count();
    if INIT_RECORDS[completed..]
        .iter()
        .any(|name| remaining.contains(*name))
    {
        return Err(reset_required());
    }
    let temporary_indexes = INIT_RECORDS
        .into_iter()
        .enumerate()
        .filter_map(|(index, name)| remaining.remove(&temporary_name(name)).then_some(index))
        .collect::<Vec<_>>();
    if !remaining.is_empty()
        || temporary_indexes.len() > 1
        || temporary_indexes
            .first()
            .is_some_and(|index| *index != completed && !(completed > 0 && *index + 1 == completed))
        || exact_completed
            .is_some_and(|expected| completed != expected || !temporary_indexes.is_empty())
    {
        return Err(reset_required());
    }
    Ok(())
}

fn temporary_name(name: &str) -> String {
    format!(".{name}.automata-write")
}

fn open_operation_lock(directory: &OwnedFd) -> Result<OwnedFd, LocalInitError> {
    let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let descriptor = match openat(directory, OPERATION_LOCK, flags, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => match openat(
            directory,
            OPERATION_LOCK,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => {
                fs::fchmod(&descriptor, Mode::from_raw_mode(0o600)).map_err(|_| state_path())?;
                fs::fsync(directory).map_err(|_| state_path())?;
                descriptor
            }
            Err(rustix::io::Errno::EXIST) => {
                openat(directory, OPERATION_LOCK, flags, Mode::empty()).map_err(|_| state_path())?
            }
            Err(_) => return Err(state_path()),
        },
        Err(_) => return Err(state_path()),
    };
    verify_private_regular(&descriptor, Some(0))?;
    Ok(descriptor)
}

fn open_operation_lock_existing(directory: &OwnedFd) -> Result<OwnedFd, LocalInitError> {
    let descriptor = openat(
        directory,
        OPERATION_LOCK,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| reset_required())?;
    verify_private_regular(&descriptor, Some(0))?;
    Ok(descriptor)
}

fn lock(descriptor: &OwnedFd, operation: FlockOperation) -> Result<(), LocalInitError> {
    fs::flock(descriptor, operation).map_err(|error| {
        if error == rustix::io::Errno::AGAIN {
            LocalInitError::new(LocalInitErrorCode::OperationInProgress)
        } else {
            state_path()
        }
    })
}

fn revalidate_root_and_lock(
    parent: &OwnedFd,
    name: &OsStr,
    directory: &OwnedFd,
    operation_lock: &OwnedFd,
    initial_root: &rustix::fs::Stat,
) -> Result<(rustix::fs::Stat, rustix::fs::Stat), LocalInitError> {
    let root_metadata = private_directory_metadata(directory)?;
    let rebound_root =
        openat(parent, name, directory_flags(), Mode::empty()).map_err(|_| reset_required())?;
    let rebound_root_metadata = private_directory_metadata(&rebound_root)?;
    let lock_metadata = verify_private_regular(operation_lock, Some(0))?;
    let rebound_lock = open_operation_lock_existing(directory)?;
    let rebound_lock_metadata = verify_private_regular(&rebound_lock, Some(0))?;
    if !same_inode(initial_root, &root_metadata)
        || !same_inode(&root_metadata, &rebound_root_metadata)
        || !same_inode(&lock_metadata, &rebound_lock_metadata)
        || lock_metadata.st_ctime != rebound_lock_metadata.st_ctime
        || lock_metadata.st_ctime_nsec != rebound_lock_metadata.st_ctime_nsec
    {
        return Err(reset_required());
    }
    Ok((root_metadata, lock_metadata))
}

fn readable_reset_authority(
    observation: &ResetRecordObservation,
) -> Result<Option<&[u8]>, LocalInitError> {
    match (observation.present, observation.completed.as_deref()) {
        (false, None) => Ok(None),
        (true, Some(bytes)) => Ok(Some(bytes)),
        _ => Err(reset_required()),
    }
}

pub(super) struct EvidenceDirectory {
    directory: OwnedFd,
    catalog: Vec<u8>,
}

impl EvidenceDirectory {
    pub(super) fn open(source: &str) -> Result<Self, LocalInitError> {
        let path = source
            .strip_prefix("file:")
            .filter(|path| path.starts_with('/'))
            .map(Path::new)
            .ok_or_else(|| LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource))?;
        let (directory, name) = open_parent(path, false)?;
        let catalog = read_evidence_file(&directory, &name, MAX_CATALOG_BYTES)?;
        Ok(Self { directory, catalog })
    }

    pub(super) fn catalog(&self) -> &[u8] {
        &self.catalog
    }

    pub(super) fn read_candidate(&self, basename: &str) -> Result<Vec<u8>, LocalInitError> {
        if basename.as_bytes().contains(&b'/') || basename.as_bytes().contains(&b'\\') {
            return Err(LocalInitError::new(
                LocalInitErrorCode::InvalidCatalogPayload,
            ));
        }
        read_evidence_file(&self.directory, OsStr::new(basename), MAX_CANDIDATE_BYTES)
            .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalogPayload))
    }
}

fn read_evidence_file(
    directory: &OwnedFd,
    name: &OsStr,
    maximum: usize,
) -> Result<Vec<u8>, LocalInitError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource))?;
    let before = fstat(&descriptor)
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource))?;
    let euid = rustix::process::geteuid().as_raw();
    let size = usize::try_from(before.st_size)
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || (before.st_uid != 0 && before.st_uid != euid)
        || before.st_mode & 0o022 != 0
        || size == 0
        || size > maximum
    {
        return Err(LocalInitError::new(
            LocalInitErrorCode::InvalidCatalogSource,
        ));
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(size);
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(maximum + 1).expect("bounded evidence size fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource))?;
    let after =
        fstat(&file).map_err(|_| LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource))?;
    if bytes.len() != size || !same_file(&before, &after) {
        return Err(LocalInitError::new(
            LocalInitErrorCode::InvalidCatalogSource,
        ));
    }
    Ok(bytes)
}

fn open_parent(path: &Path, state: bool) -> Result<(OwnedFd, OsString), LocalInitError> {
    validate_absolute_path(path, state)?;
    let mut components = path.components().collect::<Vec<_>>();
    let name = match components.pop() {
        Some(Component::Normal(name)) => name.to_owned(),
        _ => return Err(path_error(state)),
    };
    let mut current =
        fs::open("/", directory_flags(), Mode::empty()).map_err(|_| path_error(state))?;
    verify_trusted_ancestor(&current, state)?;
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(name) if !name.is_empty() => {
                current = openat(&current, name, directory_flags(), Mode::empty())
                    .map_err(|_| path_error(state))?;
                verify_trusted_ancestor(&current, state)?;
            }
            _ => return Err(path_error(state)),
        }
    }
    Ok((current, name))
}

fn validate_absolute_path(path: &Path, state: bool) -> Result<(), LocalInitError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes == b"/"
        || bytes.ends_with(b"/")
        || bytes.windows(2).any(|pair| pair == b"//")
        || bytes
            .split(|byte| *byte == b'/')
            .any(|part| matches!(part, b"." | b".."))
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(path_error(state));
    }
    Ok(())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn verify_trusted_ancestor(directory: &OwnedFd, state: bool) -> Result<(), LocalInitError> {
    let metadata = fstat(directory).map_err(|_| path_error(state))?;
    let euid = rustix::process::geteuid().as_raw();
    let writable = metadata.st_mode & 0o022 != 0;
    let root_sticky = metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || (metadata.st_uid != 0 && metadata.st_uid != euid)
        || (writable && !root_sticky)
    {
        return Err(path_error(state));
    }
    Ok(())
}

fn private_directory_metadata(directory: &OwnedFd) -> Result<rustix::fs::Stat, LocalInitError> {
    let metadata = fstat(directory).map_err(|_| state_path())?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(LocalInitError::new(
            LocalInitErrorCode::InvalidStateDirectory,
        ));
    }
    Ok(metadata)
}

fn state_authority_digest(root: &rustix::fs::Stat, lock: &rustix::fs::Stat) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(STATE_AUTHORITY_DOMAIN);
    hasher.update(root.st_dev.to_be_bytes());
    hasher.update(root.st_ino.to_be_bytes());
    hasher.update(root.st_uid.to_be_bytes());
    hasher.update(root.st_gid.to_be_bytes());
    hasher.update(root.st_mode.to_be_bytes());
    hasher.update(lock.st_dev.to_be_bytes());
    hasher.update(lock.st_ino.to_be_bytes());
    hasher.update(lock.st_ctime.to_be_bytes());
    hasher.update(lock.st_ctime_nsec.to_be_bytes());
    hasher.update(lock.st_nlink.to_be_bytes());
    hasher.update(lock.st_mode.to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn verify_private_regular(
    file: &OwnedFd,
    expected_size: Option<u64>,
) -> Result<rustix::fs::Stat, LocalInitError> {
    let metadata = fstat(file).map_err(|_| reset_required())?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != 0o600
        || expected_size.is_some_and(|size| u64::try_from(metadata.st_size).ok() != Some(size))
    {
        return Err(reset_required());
    }
    Ok(metadata)
}

fn verify_safe_reset_regular(file: &OwnedFd) -> Result<rustix::fs::Stat, LocalInitError> {
    let metadata = fstat(file).map_err(|_| reset_required())?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7077 != 0
    {
        return Err(reset_required());
    }
    Ok(metadata)
}

fn same_file(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn same_inode(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn path_error(state: bool) -> LocalInitError {
    if state {
        state_path()
    } else {
        LocalInitError::new(LocalInitErrorCode::InvalidCatalogSource)
    }
}

fn state_path() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::InvalidStateDirectory)
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

#[cfg(test)]
mod tests;
