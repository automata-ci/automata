use anyhow::{Context as _, Result};
use automata_ci_blob_s3::S3AtRestEncryption;

use crate::{
    cli::{InternalArgs, InternalCommand, InternalEnsureBucketArgs, InternalObjectStoreCommand},
    server::S3ConnectionConfig,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::cli::InternalLocalCommand;

pub(crate) async fn execute(args: &InternalArgs) -> Result<()> {
    match &args.command {
        InternalCommand::ObjectStore(args) => match &args.command {
            InternalObjectStoreCommand::EnsureBucket(args) => ensure_exact_bucket(args).await,
        },
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        InternalCommand::Local(args) => match args.command {
            InternalLocalCommand::Materialize => automata_ci_local::run_local_init_materializer()
                .context("fixed local materialization failed"),
        },
    }
}

async fn ensure_exact_bucket(args: &InternalEnsureBucketArgs) -> Result<()> {
    let connection = S3ConnectionConfig::from_args(&args.s3, None, S3AtRestEncryption::aes256())
        .context("invalid object-store initialization configuration")?;
    let store = crate::object_store::connect(&connection)
        .context("failed to configure object-store initialization")?;
    store
        .ensure_bucket()
        .await
        .context("failed to initialize object-store bucket")?;
    println!("object-store bucket ready");
    Ok(())
}
