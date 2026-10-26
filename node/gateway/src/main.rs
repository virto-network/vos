//! `vos-gateway --config gateway.toml`: serve until interrupted.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use vos_gateway::Gateway;
use vos_gateway::config::{Config, seed};
use vos_gateway::front::{self, Http};
use vos_gateway::limits::Limits;
use vos_gateway::upstream::Upstream;

#[derive(Parser)]
#[command(
    name = "vos-gateway",
    version,
    about = "Serve HTTP, and SSH, in front of VOS nodes' APIs"
)]
struct Cli {
    /// The gateway's TOML file.
    #[arg(long)]
    config: PathBuf,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("vos-gateway: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let config = Config::read(&cli.config)?;
    let secret = seed(&config.key)?;
    let tls = config.http_tls(&secret)?;
    let upstreams = config
        .upstreams()?
        .into_iter()
        .map(|(key, address)| Upstream::new(key, address, secret))
        .collect();
    let gateway = Arc::new(Gateway::new(upstreams));
    let limits = Limits::new(config.per_address());
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(config.http)
            .await
            .map_err(|error| format!("{}: {error}", config.http))?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let public = ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key();
        println!("listening on {address}");
        println!("gateway {}", hex::encode(public.to_bytes()));
        let http = Http {
            tls,
            connections: config.connections.unwrap_or(1024),
        };
        front::serve(gateway, limits, listener, http, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
        Ok(())
    })
}
