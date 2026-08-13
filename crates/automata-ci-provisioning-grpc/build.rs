use std::{error::Error, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    const SCHEMA: &str = "proto/automata/management/v1/shard_management.proto";
    const INCLUDE_ROOT: &str = "proto";

    println!("cargo::rerun-if-changed={SCHEMA}");
    println!("cargo::rerun-if-changed={INCLUDE_ROOT}");

    let descriptors = protox::compile([Path::new(SCHEMA)], [Path::new(INCLUDE_ROOT)])?;
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
