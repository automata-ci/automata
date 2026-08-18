use anyhow::{Context as _, Result};
use automata_ci_blob_s3::S3AtRestEncryption;

use crate::{
    cli::{InternalArgs, InternalCommand, InternalEnsureBucketArgs, InternalObjectStoreCommand},
    server::S3ConnectionConfig,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::cli::{InternalEngineCommand, InternalLocalCommand};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod local_bootstrap;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const fn is_synchronous_engine_operation(args: &InternalArgs) -> bool {
    matches!(args.command, InternalCommand::Engine(_))
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) const fn is_synchronous_engine_operation(_args: &InternalArgs) -> bool {
    false
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn run_synchronous_engine_operation(args: &InternalArgs) -> Result<()> {
    let InternalCommand::Engine(args) = &args.command else {
        unreachable!("synchronous dispatch accepts only a fixed Engine operation")
    };
    match args.command {
        InternalEngineCommand::Relay => automata_ci_local::run_fixed_engine_relay_process()
            .context("fixed local Engine relay failed"),
        InternalEngineCommand::Check => automata_ci_local::check_fixed_engine_relay()
            .context("fixed local Engine relay check failed"),
    }
}

pub(crate) async fn execute(args: &InternalArgs) -> Result<()> {
    match &args.command {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        InternalCommand::Engine(_) => unreachable!(
            "fixed Engine relay operations are dispatched before the async runtime is constructed"
        ),
        InternalCommand::ObjectStore(args) => match &args.command {
            InternalObjectStoreCommand::EnsureBucket(args) => ensure_exact_bucket(args).await,
        },
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        InternalCommand::Local(args) => match &args.command {
            InternalLocalCommand::BootstrapRunner(args) => local_bootstrap::execute(args).await,
            InternalLocalCommand::Materialize => automata_ci_local::run_local_init_materializer()
                .context("fixed local materialization failed"),
            InternalLocalCommand::ReadDesired => automata_ci_local::run_local_desired_reader()
                .context("fixed local Desired read failed"),
            InternalLocalCommand::WriteCas => automata_ci_local::run_local_lifecycle_cas()
                .context("fixed local generated-file CAS failed"),
            InternalLocalCommand::CheckReady => automata_ci_local::run_local_readiness_check()
                .context("fixed local readiness check failed"),
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
