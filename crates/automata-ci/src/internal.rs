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
pub(crate) const fn is_synchronous_operation(args: &InternalArgs) -> bool {
    match &args.command {
        InternalCommand::Engine(_) => true,
        InternalCommand::Local(args) => {
            !matches!(&args.command, InternalLocalCommand::BootstrapRunner(_))
        }
        InternalCommand::ObjectStore(_) => false,
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) const fn is_synchronous_operation(_args: &InternalArgs) -> bool {
    false
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) fn run_synchronous_operation(_args: &InternalArgs) -> Result<()> {
    unreachable!("this platform exposes no synchronous internal operations")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn run_synchronous_operation(args: &InternalArgs) -> Result<()> {
    match &args.command {
        InternalCommand::Engine(args) => match args.command {
            InternalEngineCommand::Relay => automata_ci_local::run_fixed_engine_relay_process()
                .context("fixed local Engine relay failed"),
            InternalEngineCommand::Check => automata_ci_local::check_fixed_engine_relay()
                .context("fixed local Engine relay check failed"),
        },
        InternalCommand::Local(args) => match &args.command {
            InternalLocalCommand::BootstrapRunner(_) => {
                unreachable!("database-backed bootstrap requires asynchronous dispatch")
            }
            InternalLocalCommand::Materialize => automata_ci_local::run_local_init_materializer()
                .context("fixed local materialization failed"),
            InternalLocalCommand::ReadDesired => automata_ci_local::run_local_desired_reader()
                .context("fixed local Desired read failed"),
            InternalLocalCommand::ReadCasDigest => {
                automata_ci_local::run_local_lifecycle_cas_digest_reader()
                    .context("fixed local generated-file CAS digest read failed")
            }
            InternalLocalCommand::WriteCas => automata_ci_local::run_local_lifecycle_cas()
                .context("fixed local generated-file CAS failed"),
            InternalLocalCommand::HoldLock => automata_ci_local::run_local_lifecycle_lock_holder()
                .context("fixed local lifecycle lock holder failed"),
            InternalLocalCommand::CheckReady => automata_ci_local::run_local_readiness_check()
                .context("fixed local readiness check failed"),
        },
        InternalCommand::ObjectStore(_) => {
            unreachable!("object-store initialization requires asynchronous dispatch")
        }
    }
}

pub(crate) async fn execute(args: &InternalArgs) -> Result<()> {
    match &args.command {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        InternalCommand::Engine(_) => unreachable!(
            "fixed synchronous operations are dispatched before the async runtime is constructed"
        ),
        InternalCommand::ObjectStore(args) => match &args.command {
            InternalObjectStoreCommand::EnsureBucket(args) => ensure_exact_bucket(args).await,
        },
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        InternalCommand::Local(args) => match &args.command {
            InternalLocalCommand::BootstrapRunner(args) => local_bootstrap::execute(args).await,
            InternalLocalCommand::Materialize
            | InternalLocalCommand::ReadDesired
            | InternalLocalCommand::ReadCasDigest
            | InternalLocalCommand::WriteCas
            | InternalLocalCommand::HoldLock
            | InternalLocalCommand::CheckReady => unreachable!(
                "fixed synchronous operations are dispatched before the async runtime is constructed"
            ),
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

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command};

    #[test]
    fn every_fixed_process_lifecycle_helper_uses_pre_runtime_dispatch() {
        for command in [
            ["internal", "engine", "relay"].as_slice(),
            ["internal", "engine", "check"].as_slice(),
            ["internal", "local", "materialize"].as_slice(),
            ["internal", "local", "read-desired"].as_slice(),
            ["internal", "local", "read-cas-digest"].as_slice(),
            ["internal", "local", "write-cas"].as_slice(),
            ["internal", "local", "hold-lock"].as_slice(),
            ["internal", "local", "check-ready"].as_slice(),
        ] {
            let arguments = std::iter::once("automata").chain(command.iter().copied());
            let cli = Cli::try_parse_from(arguments).expect("fixed helper must parse");
            let Command::Internal(args) = cli.command else {
                panic!("internal command expected");
            };
            assert!(is_synchronous_operation(&args), "{command:?}");
        }
    }

    #[test]
    fn database_bootstrap_remains_synchronously_awaited_on_the_async_runtime() {
        let cli = Cli::try_parse_from([
            "automata",
            "internal",
            "local",
            "bootstrap-runner",
            "--database-url-source",
            "file:/run/secrets/database-url",
            "--database-private-ca-source",
            "file:/run/secrets/database-private-ca",
            "--request-source",
            "file:/run/automata/bootstrap-request",
            "--runner-enrollment-token-source",
            "file:/run/secrets/runner-enrollment-token",
            "--runner-enrollment-token-target",
            "file:/run/automata/active-runner-enrollment-token",
            "--receipt-target",
            "file:/run/automata/bootstrap-receipt",
        ])
        .expect("fixed bootstrap helper must parse");
        let Command::Internal(args) = cli.command else {
            panic!("internal command expected");
        };
        assert!(!is_synchronous_operation(&args));
    }
}
