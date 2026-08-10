use std::{fs::File, io::Read as _, path::Path};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NEEDED: u64 = 1;
const PN_XNUM: u16 = 0xffff;

/// Result of read-only ELF inspection for execution in a scratch container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScratchCompatibility {
    /// The executable is an ELF with no interpreter or needed shared libraries.
    Compatible,
    /// The executable is valid enough to inspect but cannot run in scratch.
    Incompatible(String),
    /// File access, size, or malformed/unsupported ELF data prevented a decision.
    Indeterminate(String),
}

/// Read-only boundary for checking whether a probe executable can run in scratch.
pub trait ScratchExecutableInspector: Send + Sync {
    /// Inspects the bounded executable snapshot without executing it or resolving libraries.
    fn inspect(&self, executable: &[u8]) -> ScratchCompatibility;
}

/// Bounded native ELF inspector used by the production Linux probe.
///
/// It rejects non-regular and non-executable files, reads at most 256 MiB, and
/// treats malformed or unsupported structures as indeterminate.
#[derive(Debug, Default)]
pub struct ElfScratchExecutableInspector;

impl ScratchExecutableInspector for ElfScratchExecutableInspector {
    fn inspect(&self, executable: &[u8]) -> ScratchCompatibility {
        inspect_elf(executable)
    }
}

pub(super) fn load_executable_snapshot(executable: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    let file = {
        let descriptor = rustix::fs::open(
            executable,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| format!("could not securely open probe executable: {error}"))?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = File::open(executable)
        .map_err(|error| format!("could not open probe executable: {error}"))?;
    read_executable_snapshot(file)
}

#[cfg(target_os = "linux")]
pub(super) fn load_running_executable_snapshot() -> Result<Vec<u8>, String> {
    read_executable_snapshot(open_running_executable()?)
}

#[cfg(target_os = "linux")]
fn open_running_executable() -> Result<File, String> {
    let descriptor = rustix::fs::open(
        "/proc/self/exe",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("could not securely open the running probe executable: {error}"))?;
    Ok(File::from(descriptor))
}

fn read_executable_snapshot(mut file: File) -> Result<Vec<u8>, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect probe executable: {error}"))?;
    if !metadata.is_file() {
        return Err("probe executable is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("probe executable is not executable".to_owned());
        }
    }
    if metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err("probe executable exceeds the 256 MiB inspection limit".to_owned());
    }
    let capacity = usize::try_from(metadata.len())
        .unwrap_or(usize::MAX)
        .min(16 * 1024 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read probe executable: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EXECUTABLE_BYTES {
        return Err("probe executable exceeds the 256 MiB inspection limit".to_owned());
    }
    Ok(bytes)
}

fn inspect_elf(executable: &[u8]) -> ScratchCompatibility {
    match inspect_elf_bytes(executable) {
        Ok(()) => ScratchCompatibility::Compatible,
        Err(ElfInspectionError::Incompatible(detail)) => ScratchCompatibility::Incompatible(detail),
        Err(ElfInspectionError::Invalid(detail)) => ScratchCompatibility::Indeterminate(detail),
    }
}

#[derive(Debug)]
enum ElfInspectionError {
    Incompatible(String),
    Invalid(String),
}

fn inspect_elf_bytes(bytes: &[u8]) -> Result<(), ElfInspectionError> {
    if bytes.get(..ELF_MAGIC.len()) != Some(ELF_MAGIC) {
        return Err(ElfInspectionError::Invalid(
            "probe executable is not an ELF file".to_owned(),
        ));
    }
    let class = *bytes
        .get(4)
        .ok_or_else(|| invalid("ELF identification is truncated"))?;
    let endian = match bytes
        .get(5)
        .copied()
        .ok_or_else(|| invalid("ELF identification is truncated"))?
    {
        ELFDATA2LSB => Endian::Little,
        ELFDATA2MSB => Endian::Big,
        _ => return Err(invalid("ELF byte order is unsupported")),
    };
    let reader = ElfReader { bytes, endian };

    let header = match class {
        ELFCLASS32 => ProgramHeaderTable {
            offset: usize::try_from(reader.u32(28)?).map_err(|_| invalid("invalid ELF offset"))?,
            entry_size: usize::from(reader.u16(42)?),
            entry_count: reader.u16(44)?,
            class: ElfClass::Elf32,
        },
        ELFCLASS64 => ProgramHeaderTable {
            offset: usize::try_from(reader.u64(32)?).map_err(|_| invalid("invalid ELF offset"))?,
            entry_size: usize::from(reader.u16(54)?),
            entry_count: reader.u16(56)?,
            class: ElfClass::Elf64,
        },
        _ => return Err(invalid("ELF class is unsupported")),
    };
    if header.entry_count == PN_XNUM {
        return Err(invalid(
            "extended ELF program-header counts are unsupported",
        ));
    }
    if header.entry_size < header.class.minimum_program_header_size() {
        return Err(invalid("ELF program-header entry is too small"));
    }

    for index in 0..usize::from(header.entry_count) {
        let entry_offset = header
            .entry_size
            .checked_mul(index)
            .and_then(|relative| header.offset.checked_add(relative))
            .ok_or_else(|| invalid("ELF program-header offset overflowed"))?;
        let program_type = reader.u32(entry_offset)?;
        if program_type == PT_INTERP {
            return Err(ElfInspectionError::Incompatible(
                "probe executable has a PT_INTERP loader and cannot run in the minimal rootfs"
                    .to_owned(),
            ));
        }
        if program_type == PT_DYNAMIC {
            inspect_dynamic_segment(&reader, header.class, entry_offset)?;
        }
    }
    Ok(())
}

fn inspect_dynamic_segment(
    reader: &ElfReader<'_>,
    class: ElfClass,
    header_offset: usize,
) -> Result<(), ElfInspectionError> {
    let (file_offset, file_size, entry_size) = match class {
        ElfClass::Elf32 => (
            usize::try_from(reader.u32(header_offset + 4)?)
                .map_err(|_| invalid("invalid dynamic-segment offset"))?,
            usize::try_from(reader.u32(header_offset + 16)?)
                .map_err(|_| invalid("invalid dynamic-segment size"))?,
            8,
        ),
        ElfClass::Elf64 => (
            usize::try_from(reader.u64(header_offset + 8)?)
                .map_err(|_| invalid("invalid dynamic-segment offset"))?,
            usize::try_from(reader.u64(header_offset + 32)?)
                .map_err(|_| invalid("invalid dynamic-segment size"))?,
            16,
        ),
    };
    let end = file_offset
        .checked_add(file_size)
        .ok_or_else(|| invalid("dynamic-segment bounds overflowed"))?;
    if end > reader.bytes.len() {
        return Err(invalid("dynamic segment extends beyond the ELF file"));
    }

    let mut offset = file_offset;
    while offset
        .checked_add(entry_size)
        .is_some_and(|entry_end| entry_end <= end)
    {
        let tag = match class {
            ElfClass::Elf32 => u64::from(reader.u32(offset)?),
            ElfClass::Elf64 => reader.u64(offset)?,
        };
        if tag == 0 {
            break;
        }
        if tag == DT_NEEDED {
            return Err(ElfInspectionError::Incompatible(
                "probe executable has DT_NEEDED dependencies and cannot run in the minimal rootfs"
                    .to_owned(),
            ));
        }
        offset += entry_size;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    const fn minimum_program_header_size(self) -> usize {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 56,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug)]
struct ProgramHeaderTable {
    offset: usize,
    entry_size: usize,
    entry_count: u16,
    class: ElfClass,
}

#[derive(Debug)]
struct ElfReader<'a> {
    bytes: &'a [u8],
    endian: Endian,
}

impl ElfReader<'_> {
    fn u16(&self, offset: usize) -> Result<u16, ElfInspectionError> {
        let bytes = self.array::<2>(offset)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32(&self, offset: usize) -> Result<u32, ElfInspectionError> {
        let bytes = self.array::<4>(offset)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    fn u64(&self, offset: usize) -> Result<u64, ElfInspectionError> {
        let bytes = self.array::<8>(offset)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    fn array<const SIZE: usize>(&self, offset: usize) -> Result<[u8; SIZE], ElfInspectionError> {
        self.bytes
            .get(offset..offset.saturating_add(SIZE))
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| invalid("ELF structure is truncated"))
    }
}

fn invalid(detail: &str) -> ElfInspectionError {
    ElfInspectionError::Invalid(detail.to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt as _, symlink},
        path::{Path, PathBuf},
    };

    use uuid::Uuid;

    use super::*;

    #[test]
    fn snapshot_loader_rejects_symlinks_and_oversized_files() {
        let fixture = SnapshotFixture::new();
        let target = fixture.root.join("target");
        fs::write(&target, b"not an ELF").expect("target must be writable");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("target must be executable");
        let alias = fixture.root.join("alias");
        symlink(&target, &alias).expect("symlink must be creatable");
        assert!(load_executable_snapshot(&alias).is_err());

        let oversized = fixture.root.join("oversized");
        let file = File::create(&oversized).expect("oversized fixture must be creatable");
        file.set_len(MAX_EXECUTABLE_BYTES + 1)
            .expect("sparse oversized fixture must be sizable");
        drop(file);
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o700))
            .expect("oversized fixture must be executable");
        let error = load_executable_snapshot(&oversized)
            .expect_err("oversized executable must fail before allocation");
        assert!(error.contains("256 MiB"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn running_snapshot_descriptor_is_bound_to_the_process_executable() {
        use std::os::unix::fs::MetadataExt as _;

        let running = open_running_executable()
            .expect("the running executable must be openable through procfs");
        let running_metadata = running
            .metadata()
            .expect("the open running executable must have metadata");
        let process_metadata = fs::metadata("/proc/self/exe")
            .expect("the process executable link must resolve to metadata");
        assert_eq!(running_metadata.dev(), process_metadata.dev());
        assert_eq!(running_metadata.ino(), process_metadata.ino());
    }

    struct SnapshotFixture {
        root: PathBuf,
    }

    impl SnapshotFixture {
        fn new() -> Self {
            let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("runner crate must be nested beneath the workspace root");
            let root = workspace_root
                .join("target/agent-scratch/runner")
                .join(format!("elf-snapshot-{}", Uuid::new_v4().simple()));
            fs::create_dir_all(&root).expect("snapshot fixture must be creatable");
            Self { root }
        }
    }

    impl Drop for SnapshotFixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }
}
