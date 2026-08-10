//! Loopback-only fixture used by the real Prometheus CI contract.

use std::{
    env,
    error::Error,
    io::{self, Write as _},
    net::SocketAddr,
};

use automata_ci_metrics::{
    BuildInfo, ExporterLimits, Gauge, MetricsBuilder, ProcessRole, classic_and_native_histogram,
};

const LISTEN_ENVIRONMENT: &str = "AUTOMATA_METRICS_FIXTURE_LISTEN";
const DEFAULT_LISTEN: &str = "127.0.0.1:9464";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = configured()?;
    if !config.listen.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "metrics fixture listen address must be loopback",
        )
        .into());
    }

    let mut builder = MetricsBuilder::new(BuildInfo::new(
        ProcessRole::MetricsFixture,
        env!("CARGO_PKG_VERSION"),
        "unknown",
    ))?;
    let probe: Gauge = Gauge::default();
    probe.set(1);
    builder.registry_mut().register(
        "fixture_probe",
        "Deterministic real-scrape validation probe",
        probe,
    );
    if config.native_probe {
        let native_probe = classic_and_native_histogram([0.1, 1.0, 10.0]);
        for observation in [-4.0, 0.0, 8.0] {
            native_probe.observe(observation);
        }
        builder.registry_mut().register(
            "fixture_native_probe",
            "Deterministic native-histogram scrape validation probe",
            native_probe,
        );
    }
    let metrics = builder.finish(ExporterLimits::default());

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    println!("AUTOMATA_METRICS_FIXTURE_LISTEN={}", listener.local_addr()?);
    io::stdout().flush()?;

    axum::serve(listener, metrics.router())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct FixtureConfig {
    listen: SocketAddr,
    native_probe: bool,
}

fn configured() -> Result<FixtureConfig, io::Error> {
    let mut arguments = env::args().skip(1);
    let mut listen = env::var(LISTEN_ENVIRONMENT).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let mut listen_seen = false;
    let mut native_probe = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" if !listen_seen => {
                listen = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--listen requires an address")
                })?;
                listen_seen = true;
            }
            "--native-probe" if !native_probe => native_probe = true,
            _ => return Err(usage_error()),
        }
    }

    let listen = listen.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "metrics fixture listen address is invalid",
        )
    })?;
    Ok(FixtureConfig {
        listen,
        native_probe,
    })
}

fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: metrics_fixture [--listen LOOPBACK_ADDRESS] [--native-probe]",
    )
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
