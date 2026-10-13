//! A peer killed and started again, in a child process: it tells no one,
//! and node 1 keeps its connection to the dead run.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use common::*;
use vos_net::quic::Quic;
use vos_net::{Class, Limits, Peer, public_key};

const PEER: &str = "VOS_NET_RESTARTED_PEER";

/// Node 2, in a child process: it binds its address, knows node 1 at the
/// other, greets node 1 on start if told to, and prints each consensus
/// frame it gets.
fn peer(spec: &str) {
    let fields: Vec<&str> = spec.split(',').collect();
    let [own, other, greet] = fields[..] else {
        panic!("a peer's spec: {spec}");
    };
    smol::block_on(async {
        let (b, arrivals) = rebind(2, own.parse().unwrap()).await;
        b.set_peers(vec![Peer {
            number: 1,
            key: public_key(&secret(1)),
            address: other.parse().unwrap(),
        }]);
        if greet == "greet" {
            send(&b, 1, Class::Consensus, 1, b"hello".to_vec()).await;
        }
        println!("ready");
        while let Ok(incoming) = arrivals.consensus.recv().await {
            println!("got {}", String::from_utf8_lossy(&incoming.frame));
        }
    });
}

/// A run of node 2, killed when dropped.
struct Run {
    process: std::process::Child,
    lines: Receiver<String>,
}

impl Run {
    fn start(test: &str, address: SocketAddr, a: &Quic, greet: bool) -> Self {
        let greet = if greet { "greet" } else { "silent" };
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture"])
            .env(PEER, format!("{address},{},{greet}", a.local_addr()))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let lines = BufReader::new(process.stdout.take().unwrap()).lines();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        let run = Self {
            process,
            lines: receiver,
        };
        // The test harness prints its own lines first.
        while run.lines.recv().unwrap() != "ready" {}
        run
    }

    /// The next frame it got, within `wait`.
    fn got(&self, wait: Duration) -> Option<String> {
        loop {
            match self.lines.recv_timeout(wait) {
                Ok(line) if line.starts_with("got ") => return Some(line[4..].to_string()),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Node 1, configured with node 2 at an address of its own.
fn node_1() -> (Quic, vos_net::Arrivals, SocketAddr) {
    let (a, arrivals) = bind(1, any_port(), Limits::default());
    let address = std::net::UdpSocket::bind(any_port())
        .unwrap()
        .local_addr()
        .unwrap();
    a.set_peers(vec![Peer {
        number: 2,
        key: public_key(&secret(2)),
        address,
    }]);
    (a, arrivals, address)
}

/// Node 2 never sends after its restart: node 1's next frame meets the
/// new run, which resets the old connection, keyed by the node's secret.
#[test]
fn a_killed_peer_resets_the_old_connection_on_its_return() {
    const TEST: &str = "a_killed_peer_resets_the_old_connection_on_its_return";
    if let Ok(spec) = std::env::var(PEER) {
        peer(&spec);
        return;
    }
    let (a, _arrivals, address) = node_1();
    smol::block_on(async {
        let first = Run::start(TEST, address, &a, false);
        send(&a, 2, Class::Consensus, 1, b"first run".to_vec()).await;
        assert_eq!(
            first.got(Duration::from_secs(10)).as_deref(),
            Some("first run")
        );
        drop(first);
        let second = Run::start(TEST, address, &a, false);
        let started = Instant::now();
        let mut sent = 0;
        let arrived = loop {
            let frame = format!("frame {sent}").into_bytes();
            send(&a, 2, Class::Consensus, 1, frame).await;
            sent += 1;
            if let Some(frame) = second.got(Duration::from_millis(20)) {
                break frame;
            }
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "the old connection was not reset"
            );
        };
        println!(
            "reached after {:?}, {sent} sent, {arrived:?} first",
            started.elapsed()
        );
    });
}

/// Node 2 greets node 1 on each start. The greeting from a new run makes
/// node 1 close its connection to the old one, so the very next frame it
/// sends reaches the new run rather than being lost to a reset.
#[test]
fn a_peer_dialing_in_as_a_new_run_ends_the_connection_to_the_old() {
    const TEST: &str = "a_peer_dialing_in_as_a_new_run_ends_the_connection_to_the_old";
    if let Ok(spec) = std::env::var(PEER) {
        peer(&spec);
        return;
    }
    let (a, arrivals, address) = node_1();
    smol::block_on(async {
        let first = Run::start(TEST, address, &a, true);
        assert_eq!(next(&arrivals.consensus).await.frame, b"hello");
        send(&a, 2, Class::Consensus, 1, b"first run".to_vec()).await;
        assert_eq!(
            first.got(Duration::from_secs(10)).as_deref(),
            Some("first run")
        );
        drop(first);
        let second = Run::start(TEST, address, &a, true);
        assert_eq!(next(&arrivals.consensus).await.frame, b"hello");
        send(&a, 2, Class::Consensus, 1, b"welcome".to_vec()).await;
        assert_eq!(
            second.got(Duration::from_secs(1)).as_deref(),
            Some("welcome"),
            "the first frame after the new run dialed in was lost"
        );
    });
}
