use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

fn required_argument(
    arguments: &mut impl Iterator<Item = OsString>,
    name: &'static str,
) -> Result<PathBuf, io::Error> {
    arguments.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing required {name} argument"),
        )
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let schema = required_argument(&mut arguments, "schema")?;
    let include_root = required_argument(&mut arguments, "include-root")?;
    let output = required_argument(&mut arguments, "output")?;

    if arguments.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected argument").into());
    }

    let descriptors = protox::compile([schema], [include_root])?;
    let mut config = prost_build::Config::new();
    config.out_dir(output);
    // `protox` preserves the file banner as Unit's leading comment, while the
    // protoc descriptor that established the checked-in v1 DTO did not. Keep
    // that file-level contract in the schema without changing generated API.
    config.disable_comments([".automata.runner.v1.Unit"]);
    config.compile_fds(descriptors)?;
    Ok(())
}
