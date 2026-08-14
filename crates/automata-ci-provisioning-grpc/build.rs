use std::{error::Error, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    const SCHEMAS: [&str; 2] = [
        "proto/automata/management/v1/shard_management.proto",
        "proto/automata/management/v1/shard_usage.proto",
    ];
    const INCLUDE_ROOT: &str = "proto";

    for schema in SCHEMAS {
        println!("cargo::rerun-if-changed={schema}");
    }
    println!("cargo::rerun-if-changed={INCLUDE_ROOT}");

    let descriptors = protox::compile(SCHEMAS.map(Path::new), [Path::new(INCLUDE_ROOT)])?;
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
