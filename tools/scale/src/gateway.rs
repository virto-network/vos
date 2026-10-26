//! The gateway's cost, a row of its own: the node's time asked of the
//! first node's API over QUIC from the coordinator, then as many times
//! through a gateway in front of that API, over HTTP on loopback; each
//! round trip's quantiles and the difference, the gateway's share.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vos_api::Kind;
use vos_gateway::Gateway;
use vos_gateway::front::{self, Http};
use vos_gateway::limits::{Limits, PerAddress};
use vos_gateway::upstream::{Address, Upstream};

use crate::deploy::Deployed;
use crate::inventory::Inventory;
use crate::runs::Run;

/// The requests each way.
const REQUESTS: usize = 500;

/// Round trips' quantiles, in microseconds.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Cost {
    pub requests: usize,
    /// p50 and p99 to the node's API directly.
    pub direct_us: (u64, u64),
    /// p50 and p99 through the gateway.
    pub gateway_us: (u64, u64),
}

impl Cost {
    /// The report's row.
    pub fn line(&self) -> String {
        format!(
            "gateway: {} requests, p50/p99 {}/{} µs through it against {}/{} µs to the node's API, +{}/+{} µs its share",
            self.requests,
            self.gateway_us.0,
            self.gateway_us.1,
            self.direct_us.0,
            self.direct_us.1,
            self.gateway_us.0.saturating_sub(self.direct_us.0),
            self.gateway_us.1.saturating_sub(self.direct_us.1)
        )
    }
}

fn quantiles(mut samples: Vec<u64>) -> (u64, u64) {
    samples.sort_unstable();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    (at(0.5), at(0.99))
}

/// Measure the gateway's cost in front of the deployed space's first node,
/// as the drivers' key, which every node's API admits; written to the
/// run's `gateway.json`.
pub fn measure(inventory: &Inventory, run: &Run) -> Result<Cost, String> {
    let deployed = Deployed::read(inventory)?;
    let node = deployed.nodes.first().ok_or("no node deployed")?;
    let seed = crate::keys::seed(&Deployed::dir(inventory).join(crate::keys::DRIVER))?;
    let address = Address::parse(&node.api)?;
    let key = crate::keys::hex32(&node.key)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let direct = Upstream::new(key, address.clone(), seed);
    let mut samples = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let asked = Instant::now();
        runtime
            .block_on(direct.request(Kind::Time as u16, &[]))
            .map_err(|error| error.to_string())?;
        samples.push(asked.elapsed().as_micros() as u64);
    }
    let direct_us = quantiles(samples);
    let gateway = Arc::new(Gateway::new(vec![Upstream::new(key, address, seed)]));
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .map_err(|error| error.to_string())?;
    let local = listener.local_addr().map_err(|error| error.to_string())?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let limits = Limits::new(PerAddress {
        connections: 4,
        rate: u32::MAX,
        burst: u32::MAX,
    });
    runtime.spawn(front::serve(
        gateway,
        limits,
        listener,
        Http {
            tls: None,
            connections: 4,
        },
        async {
            let _ = stopped.await;
        },
    ));
    let mut stream = TcpStream::connect(local).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let mut samples = Vec::with_capacity(REQUESTS);
    let mut answer = [0u8; 1024];
    for _ in 0..REQUESTS {
        let asked = Instant::now();
        stream
            .write_all(b"GET /time HTTP/1.1\r\nHost: gateway\r\n\r\n")
            .map_err(|error| error.to_string())?;
        // A whole answer: its head, and the clock's eight bytes.
        let mut read = 0;
        loop {
            read += stream
                .read(&mut answer[read..])
                .map_err(|error| error.to_string())?;
            let head = answer[..read].windows(4).position(|w| w == b"\r\n\r\n");
            if head.is_some_and(|head| read >= head + 4 + 8) {
                break;
            }
            if read == answer.len() {
                return Err("an answer past its size".into());
            }
        }
        if !answer.starts_with(b"HTTP/1.1 200") {
            return Err(String::from_utf8_lossy(&answer[..read]).into_owned());
        }
        samples.push(asked.elapsed().as_micros() as u64);
    }
    let _ = stop.send(());
    let cost = Cost {
        requests: REQUESTS,
        direct_us,
        gateway_us: quantiles(samples),
    };
    std::fs::write(
        run.file("gateway.json"),
        serde_json::to_string_pretty(&cost).expect("json"),
    )
    .map_err(|error| error.to_string())?;
    Ok(cost)
}
