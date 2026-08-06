use std::{fs, path::Path};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScratchCompatibility {
    Compatible,
    Incompatible(String),
    Indeterminate(String),
}

pub trait ScratchExecutableInspector: Send + Sync {
    fn inspect(&self, executable: &Path) -> ScratchCompatibility;
}

#[derive(Debug, Default)]
pub struct ElfScratchExecutableInspector;

impl ScratchExecutableInspector for ElfScratchExecutableInspector {
    fn inspect(&self, executable: &Path) -> ScratchCompatibility {
        inspect_elf(executable)
    }
}

fn inspect_elf(executable: &Path) -> ScratchCompatibility {
    let metadata = match fs::metadata(executable) {
        Ok(metadata) => metadata,
        Err(error) => {
            return ScratchCompatibility::Indeterminate(format!(
                "could not inspect {}: {error}",
                executable.display()
            ));
        }
    };
    if !metadata.is_file() {
        return ScratchCompatibility::Incompatible(format!(
            "{} is not a regular file",
            executable.display()
        ));
    }
    if metadata.len() > MAX_EXECUTABLE_BYTES {
        return ScratchCompatibility::Indeterminate(format!(
            "{} exceeds the 256 MiB inspection limit",
            executable.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return ScratchCompatibility::Incompatible(format!(
                "{} is not executable",
                executable.display()
            ));
        }
    }

    let bytes = match fs::read(executable) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ScratchCompatibility::Indeterminate(format!(
                "could not read {}: {error}",
                executable.display()
            ));
        }
    };
    match inspect_elf_bytes(&bytes) {
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
                "probe executable has a PT_INTERP loader and cannot run in a scratch image"
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
                "probe executable has DT_NEEDED dependencies and cannot run in a scratch image"
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
