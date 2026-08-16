#![forbid(unsafe_code)]

use std::{env, ffi::OsString, fs::File, io, path::Path, process::ExitCode};

use sha2::{Digest as _, Sha256};

const VERSION: &str = "automata-sha256 1.0.0";
const BUFFER_BYTES: usize = 64 * 1024;

fn main() -> ExitCode {
    match run(
        env::args_os().skip(1).collect(),
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

fn run(
    arguments: Vec<OsString>,
    input: &mut impl io::Read,
    output: &mut impl io::Write,
    error: &mut impl io::Write,
) -> Result<(), ()> {
    if arguments.len() == 1 && arguments[0] == "--version" {
        writeln!(output, "{VERSION}").map_err(|_| ())?;
        return Ok(());
    }
    if arguments.is_empty() {
        writeln!(error, "automata-sha256: at least one file is required").map_err(|_| ())?;
        return Err(());
    }

    let mut used_stdin = false;
    for argument in arguments {
        let label = argument.to_str().filter(|value| {
            !value.is_empty()
                && !value.contains(['\0', '\r', '\n'])
                && (*value == "-" || !value.starts_with('-'))
        });
        let Some(label) = label else {
            writeln!(error, "automata-sha256: invalid file argument").map_err(|_| ())?;
            return Err(());
        };
        let digest = if label == "-" {
            if used_stdin {
                writeln!(
                    error,
                    "automata-sha256: standard input may be read only once"
                )
                .map_err(|_| ())?;
                return Err(());
            }
            used_stdin = true;
            hash_reader(input).map_err(|_| {
                let _ = writeln!(error, "automata-sha256: could not read standard input");
            })?
        } else {
            hash_regular_file(Path::new(label)).map_err(|_| {
                let _ = writeln!(error, "automata-sha256: could not read regular file");
            })?
        };
        write_digest(output, &digest, label).map_err(|_| ())?;
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> io::Result<[u8; 32]> {
    let metadata = path.symlink_metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input is not a regular file",
        ));
    }
    hash_reader(&mut File::open(path)?)
}

fn hash_reader(reader: &mut impl io::Read) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

fn write_digest(output: &mut impl io::Write, digest: &[u8; 32], label: &str) -> io::Result<()> {
    for byte in digest {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output, "  {label}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_probe_matches_windows_admission_contract() {
        let mut output = Vec::new();
        run(
            vec!["--version".into()],
            &mut io::empty(),
            &mut output,
            &mut io::sink(),
        )
        .expect("version probe");
        assert_eq!(output, b"automata-sha256 1.0.0\n");
    }

    #[test]
    fn hashes_standard_input_in_sha256sum_format() {
        let mut output = Vec::new();
        run(
            vec!["-".into()],
            &mut &b"abc"[..],
            &mut output,
            &mut io::sink(),
        )
        .expect("stdin hash");
        assert_eq!(
            output,
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -\n"
        );
    }

    #[test]
    fn rejects_options_and_repeated_standard_input() {
        for arguments in [
            vec!["--help".into()],
            vec!["-".into(), "-".into()],
            vec!["line\nbreak".into()],
        ] {
            assert!(
                run(
                    arguments,
                    &mut io::empty(),
                    &mut io::sink(),
                    &mut io::sink(),
                )
                .is_err()
            );
        }
    }
}
