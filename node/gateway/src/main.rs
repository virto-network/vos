//! `vos-gateway --config gateway.toml`: serve until interrupted.

use std::path::PathBuf;
#[cfg(feature = "ssh")]
use std::sync::Arc;

use clap::Parser;
use vos_gateway::config::{Config, seed};
use vos_gateway::front::{self, Http};
use vos_gateway::limits::Limits;

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
    config.check()?;
    let secret = seed(&config.key)?;
    let tls = config.http_tls(&secret)?;
    let gateway = config.gateway(secret)?;
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
        // The HTTP and SSH ports are the clearnet's: their clients'
        // addresses bound them, and they cap no calls.
        #[cfg(feature = "ssh")]
        let ssh = vos_gateway::ssh::start(
            &config,
            Arc::clone(&gateway),
            vos_gateway::ssh::Port::new(
                vos_api::Mark::Clearnet,
                Arc::clone(&limits),
                vos_gateway::caps::Caps::none(),
            )
            .with_connections(config.ssh_connections),
            &vos_gateway::ssh::Placeholder,
        )
        .await?;
        #[cfg(feature = "tor")]
        let onion = match &config.onion {
            Some(onion) => {
                let served = vos_gateway::served::onion(
                    &config,
                    onion,
                    Arc::clone(&gateway),
                    &vos_gateway::ssh::Placeholder,
                )
                .await?;
                println!("onion {}", served.hosted.address);
                println!("onion key {}", hex::encode(served.hosted.key));
                Some(served)
            }
            None => None,
        };
        let http = Http {
            tls,
            connections: config.connections.unwrap_or(1024),
        };
        front::serve(gateway, limits, listener, http, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
        #[cfg(feature = "ssh")]
        if let Some(ssh) = ssh {
            ssh.abort();
        }
        #[cfg(feature = "tor")]
        drop(onion);
        Ok(())
    })
}
