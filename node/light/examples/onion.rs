//! The client over arti against a gateway's onion, over the live Tor
//! network: a bootstrap (through pasted bridges if given), its failure
//! named; then a connection a purpose, each its own circuit and SSH key,
//! the spare built ahead and a proven call through it. The phone session's
//! and a desktop's probe of `vos_light::tor`.
//!
//! ```text
//! onion --dir DIR --onion ADDRESS --host-key HEX [--bridge LINE]...
//!       [--rounds N] [--proven N] [--bootstrap-secs S] [--idle-secs S]
//! ```
//!
//! Each measurement is printed as `M <name> <value>` (milliseconds unless
//! named otherwise), each note as `N <text>`, the rendezvous the client
//! opened last (`N rendezvous hour …`, counted as the foreground's); a
//! failed bootstrap ends with
//! `E bootstrap <its name>` and exit code 2, an unreachable gateway with
//! `E <purpose> <why>` and exit code 3.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_light::route::{Purpose, Routes};
use vos_light::tor::{Client, Config, Tor, TorConfig, onion_key};
use vos_light::wire;
use vos_wire::credentials::Onion;

struct Args {
    dir: String,
    onion: String,
    host_key: [u8; 32],
    bridges: Vec<String>,
    rounds: usize,
    proven: usize,
    bootstrap: u64,
    idle: u64,
}

fn args() -> Args {
    let mut args = Args {
        dir: "./tor".into(),
        onion: String::new(),
        host_key: [0; 32],
        bridges: Vec::new(),
        rounds: 5,
        proven: 2,
        bootstrap: 120,
        idle: 0,
    };
    let mut given = std::env::args().skip(1);
    while let Some(flag) = given.next() {
        let mut value = || {
            given
                .next()
                .unwrap_or_else(|| panic!("{flag} takes a value"))
        };
        match flag.as_str() {
            "--dir" => args.dir = value(),
            "--onion" => args.onion = value(),
            "--host-key" => {
                let hex = value();
                assert_eq!(hex.len(), 64, "--host-key: 32 bytes in hex");
                for (at, byte) in args.host_key.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).expect("hex");
                }
            }
            "--bridge" => args.bridges.push(value()),
            "--rounds" => args.rounds = value().parse().expect("a number"),
            "--proven" => args.proven = value().parse().expect("a number"),
            "--bootstrap-secs" => args.bootstrap = value().parse().expect("a number"),
            "--idle-secs" => args.idle = value().parse().expect("a number"),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

fn ms(since: Instant) -> u128 {
    since.elapsed().as_millis()
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|kib| kib.parse().ok())
        .unwrap_or(0)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let start = Instant::now();
    let args = args();
    println!(
        "N onion {} {}",
        std::env::consts::ARCH,
        env!("CARGO_PKG_VERSION")
    );
    let key = onion_key(&args.onion).expect("--onion: a v3 .onion address");
    let warm = std::path::Path::new(&args.dir).join("cache").exists();
    println!("N bootstrap {}", if warm { "warm" } else { "cold" });
    for bridge in &args.bridges {
        println!("N bridge {bridge}");
    }
    let config = TorConfig {
        bridges: args.bridges.clone(),
        bootstrap: Duration::from_secs(args.bootstrap),
        ..TorConfig::new(&args.dir)
    };
    let tor = match Tor::new(&config) {
        Ok(tor) => tor,
        Err(error) => {
            println!("E bootstrap {error}");
            std::process::exit(2);
        }
    };
    let at = Instant::now();
    if let Err(error) = tor.bootstrap().await {
        println!("E bootstrap {error}");
        println!("M bootstrap_failed_ms {}", ms(at));
        std::process::exit(2);
    }
    println!(
        "M bootstrap_{}_ms {}",
        if warm { "warm" } else { "cold" },
        ms(at)
    );
    println!("M rss_bootstrapped_kib {}", rss_kib());

    let client = Client::new(Arc::new(tor), Config::default());
    client.set_foreground(true);
    let space = [1; 32];
    client.set_space(
        space,
        Routes::onions(vec![Onion {
            key,
            ssh_host_key: args.host_key,
        }]),
    );
    let at = Instant::now();
    if args.proven > 0 {
        client.keep_spares(Some(space), &[Purpose::Proven]);
    }

    // A kept-open group each: its first request opens its connection.
    for purpose in [Purpose::Member, Purpose::Personal, Purpose::Feed] {
        let mut times = Vec::new();
        for round in 0..args.rounds.max(1) {
            let asked = Instant::now();
            match client.request(space, purpose, &wire::time_request()).await {
                Ok((_, body)) => {
                    let now = wire::time_answer(&body).expect("a time");
                    times.push(ms(asked));
                    if round == 0 {
                        println!("N {purpose:?} node time {now}");
                    }
                }
                Err(error) => {
                    println!("E {purpose:?} {error}");
                    std::process::exit(3);
                }
            }
        }
        println!("M {purpose:?}_first_ms {}", times[0]);
        if times.len() > 1 {
            let mut rest = times[1..].to_vec();
            rest.sort();
            println!("M {purpose:?}_time_p50_ms {}", rest[rest.len() / 2]);
        }
    }

    // A fetch: a connection of its own, closed once answered.
    let asked = Instant::now();
    match client
        .request(space, Purpose::Fetch, &wire::time_request())
        .await
    {
        Ok(_) => println!("M fetch_ms {}", ms(asked)),
        Err(error) => println!("E Fetch {error}"),
    }

    // Proven calls through the spare: a stand-in body the node refuses,
    // timed to its answer.
    for round in 0..args.proven {
        let waited = Instant::now();
        while !client.spare_ready(Purpose::Proven) && waited.elapsed() < Duration::from_secs(120) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if round == 0 {
            println!("M spare_ready_ms {}", ms(at));
        }
        let ready = client.spare_ready(Purpose::Proven);
        let mut request = (vos_api::Kind::Credentialed as u16).to_le_bytes().to_vec();
        request.extend_from_slice(&1u32.to_le_bytes());
        request.extend_from_slice(&[0; 1024]);
        let asked = Instant::now();
        match client.request(space, Purpose::Proven, &request).await {
            Ok((kind, body)) => println!(
                "M proven_{round}_ms {} spare={ready} kind={kind:#06x} bytes={}",
                ms(asked),
                body.len()
            ),
            Err(error) => println!("E Proven {error}"),
        }
    }

    println!("M rss_active_kib {}", rss_kib());
    if args.idle > 0 {
        tokio::time::sleep(Duration::from_secs(args.idle)).await;
        println!("M rss_idle_kib {}", rss_kib());
        client.set_dormant(true);
        tokio::time::sleep(Duration::from_secs(args.idle)).await;
        println!("M rss_dormant_kib {}", rss_kib());
    }
    for hour in client.opened() {
        println!("N {hour}");
    }
    println!("M wall_ms {}", ms(start));
}
