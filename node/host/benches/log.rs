//! Durable log appends by entry size, through writers shaped like the node
//! log writer: one thread per node drains every queued append into one
//! batch and one sync, up to a cap in bytes. Three nodes on one disk stand
//! in for a leader and two followers: an entry commits once two of the
//! three writers made it durable.
//!
//! - `log-bench sizes [nodes] [cap]`: entries of 1 KiB to 4 MiB from
//!   closed-loop proposers: commits per second, MiB per second, p50 and p99.
//! - `log-bench mixed <large bytes> [cap]`: 15 agents of 1 KiB entries
//!   beside one agent of large entries: the small entries' p50 and p99.
//!
//! `BLOBS=<bytes>` writes entries at least that large to the node's blob
//! writer, with its own syncs, and logs a 40-byte reference once the blob
//! is durable. `BLOB_LAYOUT` chooses how blob files are made durable:
//!
//! - `append` (default): appended to one file created beforehand, one sync
//!   per group, as a preallocated segment would be;
//! - `file`: a new file per blob, written, synced and renamed into place,
//!   then one directory sync per group;
//! - `group`: one new file per group of blobs, synced, then the directory;
//! - `fjall`: a second fjall database for blobs alone, with its own journal
//!   and key-value separation, one synced batch per group.
//!
//! `ONLY=<KiB>` runs one size of `sizes`.
//!
//! Data goes under `target/`: on the reference laptop `/tmp` is tmpfs.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use vos_node::store::{Fjall, LogEntry, PersistMode};
use vos_wire::ids::AgentId;

const RUN: Duration = Duration::from_secs(4);
const MIB: f64 = 1024.0 * 1024.0;

struct Append {
    agent: AgentId,
    index: u64,
    entry: Arc<Vec<u8>>,
    done: Sender<()>,
}

/// A node's writer: drain what is queued, up to `cap` bytes, into one
/// synced batch, then acknowledge each append.
fn writer(store: Fjall, appends: Receiver<Append>, cap: usize) {
    let mut queued: VecDeque<Append> = VecDeque::new();
    loop {
        if queued.is_empty() {
            match appends.recv() {
                Ok(append) => queued.push_back(append),
                Err(_) => return,
            }
        }
        while let Ok(append) = appends.try_recv() {
            queued.push_back(append);
        }
        let mut batch = store.batch();
        let mut bytes = 0;
        let mut taken = Vec::new();
        while let Some(append) = queued.front() {
            if !taken.is_empty() && bytes + append.entry.len() > cap {
                break;
            }
            let append = queued.pop_front().expect("a queued append");
            bytes += append.entry.len();
            batch.append(
                append.agent,
                append.index,
                &LogEntry::result(1, append.entry.to_vec()),
            );
            taken.push(append);
        }
        batch.commit(PersistMode::SyncAll).expect("a synced commit");
        for append in taken {
            let _ = append.done.send(());
        }
    }
}

#[derive(Clone, Copy)]
enum Layout {
    Append,
    File,
    Group,
    Fjall,
}

/// A node's blob writer: make the queued blobs durable as `layout` says,
/// then hand each blob's reference to the log writer.
fn blob_writer(
    dir: std::path::PathBuf,
    layout: Layout,
    blobs: Receiver<Append>,
    log: Sender<Append>,
) {
    use std::fs::File;
    use std::io::Write;
    std::fs::create_dir_all(&dir).unwrap();
    let sync_dir = || File::open(&dir).unwrap().sync_all().unwrap();
    let mut segment = File::create(dir.join("segment")).unwrap();
    sync_dir();
    let blobs_db = matches!(layout, Layout::Fjall).then(|| {
        let db = fjall::Database::builder(dir.join("db")).open().unwrap();
        let keyspace = db
            .keyspace("blobs", || {
                fjall::KeyspaceCreateOptions::default()
                    .with_kv_separation(Some(fjall::KvSeparationOptions::default()))
            })
            .unwrap();
        (db, keyspace)
    });
    let mut next = 0u64;
    while let Ok(first) = blobs.recv() {
        let mut taken = vec![first];
        while let Ok(append) = blobs.try_recv() {
            taken.push(append);
        }
        match layout {
            Layout::Append => {
                for append in &taken {
                    segment.write_all(&append.entry).unwrap();
                }
                segment.sync_data().unwrap();
            }
            Layout::File => {
                for append in &taken {
                    next += 1;
                    let staged = dir.join(format!("{next}.tmp"));
                    let mut file = File::create(&staged).unwrap();
                    file.write_all(&append.entry).unwrap();
                    file.sync_data().unwrap();
                    std::fs::rename(&staged, dir.join(format!("{next}"))).unwrap();
                }
                sync_dir();
            }
            Layout::Fjall => {
                let (db, keyspace) = blobs_db.as_ref().expect("opened for this layout");
                let mut batch = db.batch();
                for append in &taken {
                    next += 1;
                    batch.insert(keyspace, next.to_be_bytes(), append.entry.as_slice());
                }
                batch
                    .durability(Some(fjall::PersistMode::SyncAll))
                    .commit()
                    .unwrap();
            }
            Layout::Group => {
                next += 1;
                let mut file = File::create(dir.join(format!("{next}"))).unwrap();
                for append in &taken {
                    file.write_all(&append.entry).unwrap();
                }
                file.sync_data().unwrap();
                sync_dir();
            }
        }
        for append in taken {
            let _ = log.send(Append {
                entry: Arc::new(vec![0x5a; 40]),
                ..append
            });
        }
    }
}

struct Cluster {
    writers: Vec<Sender<Append>>,
    blobs: Vec<Sender<Append>>,
    blob_threshold: usize,
    threads: Vec<std::thread::JoinHandle<()>>,
    dir: std::path::PathBuf,
}

impl Cluster {
    fn new(nodes: usize, cap: usize) -> Self {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("log-bench-{}", std::process::id()));
        let mut writers = Vec::new();
        let mut blobs = Vec::new();
        let mut threads = Vec::new();
        let blob_threshold = std::env::var("BLOBS").ok().map_or(usize::MAX, |bytes| {
            bytes.parse().expect("a threshold in bytes")
        });
        let layout = match std::env::var("BLOB_LAYOUT").as_deref() {
            Ok("file") => Layout::File,
            Ok("group") => Layout::Group,
            Ok("fjall") => Layout::Fjall,
            _ => Layout::Append,
        };
        for node in 0..nodes {
            let store = Fjall::open(dir.join(format!("node{node}"))).unwrap();
            let (tx, rx) = channel();
            let (blob_tx, blob_rx) = channel();
            let log = tx.clone();
            let path = dir.join(format!("node{node}")).join("blobs");
            threads.push(std::thread::spawn(move || {
                blob_writer(path, layout, blob_rx, log)
            }));
            writers.push(tx);
            blobs.push(blob_tx);
            threads.push(std::thread::spawn(move || writer(store, rx, cap)));
        }
        Self {
            writers,
            blobs,
            blob_threshold,
            threads,
            dir,
        }
    }

    /// Append `entry` on every node; return once a majority made it
    /// durable.
    fn append(&self, agent: AgentId, index: u64, entry: &Arc<Vec<u8>>) {
        let (done, acks) = channel();
        let queues = if entry.len() >= self.blob_threshold {
            &self.blobs
        } else {
            &self.writers
        };
        for writer in queues {
            writer
                .send(Append {
                    agent,
                    index,
                    entry: Arc::clone(entry),
                    done: done.clone(),
                })
                .unwrap();
        }
        for _ in 0..self.writers.len() / 2 + 1 {
            acks.recv().unwrap();
        }
    }

    fn close(self) {
        drop(self.blobs);
        drop(self.writers);
        for thread in self.threads {
            thread.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Closed-loop proposers, `(agent, entry size)` each, for [`RUN`]: the
/// latencies of each agent's commits.
fn propose(cluster: &Arc<Cluster>, proposers: &[(AgentId, usize)]) -> Vec<Vec<Duration>> {
    let stop = Arc::new(AtomicBool::new(false));
    let next: Arc<Vec<AtomicU64>> = Arc::new((0..256).map(|_| AtomicU64::new(1)).collect());
    let threads: Vec<_> = proposers
        .iter()
        .map(|&(agent, size)| {
            let cluster = Arc::clone(cluster);
            let stop = Arc::clone(&stop);
            let next = Arc::clone(&next);
            std::thread::spawn(move || {
                // Incompressible, as encoded work results mostly are: a
                // constant fill would compress away in the journal and the
                // blob files.
                let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(agent.0);
                let entry = Arc::new(
                    (0..size)
                        .map(|_| {
                            seed ^= seed << 13;
                            seed ^= seed >> 7;
                            seed ^= seed << 17;
                            seed as u8
                        })
                        .collect::<Vec<u8>>(),
                );
                let mut samples = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let index = next[agent.0 as usize].fetch_add(1, Ordering::Relaxed);
                    let started = Instant::now();
                    cluster.append(agent, index, &entry);
                    samples.push(started.elapsed());
                }
                (agent, samples)
            })
        })
        .collect();
    std::thread::sleep(RUN);
    stop.store(true, Ordering::Relaxed);
    let mut by_agent: Vec<Vec<Duration>> = vec![Vec::new(); 256];
    for thread in threads {
        let (agent, samples) = thread.join().unwrap();
        by_agent[agent.0 as usize].extend(samples);
    }
    by_agent
}

fn percentile(sorted: &[Duration], fraction: f64) -> f64 {
    let rank = (sorted.len() as f64 * fraction).ceil() as usize;
    sorted[rank.max(1) - 1].as_secs_f64() * 1e3
}

fn sizes(nodes: usize, cap: usize) {
    let only: Option<usize> = std::env::var("ONLY")
        .ok()
        .map(|kib| kib.parse::<usize>().unwrap() << 10);
    for (size, concurrency) in [
        (1 << 10, 64),
        (16 << 10, 16),
        (64 << 10, 16),
        (256 << 10, 16),
        (1 << 20, 8),
        (4 << 20, 4),
    ] {
        if only.is_some_and(|only| only != size) {
            continue;
        }
        let cluster = Arc::new(Cluster::new(nodes, cap));
        let proposers: Vec<_> = (0..concurrency).map(|_| (AgentId(1), size)).collect();
        let mut samples: Vec<Duration> = propose(&cluster, &proposers).concat();
        Arc::into_inner(cluster).unwrap().close();
        samples.sort();
        let rate = samples.len() as f64 / RUN.as_secs_f64();
        println!(
            "{:>5} KiB × {concurrency:>2} on {nodes} node(s): {rate:>7.0} commits/s ({:>6.1} MiB/s), p50 {:>6.2} ms, p99 {:>6.2} ms",
            size >> 10,
            rate * size as f64 / MIB,
            percentile(&samples, 0.5),
            percentile(&samples, 0.99),
        );
    }
}

fn mixed(large: usize, cap: usize) {
    let cluster = Arc::new(Cluster::new(3, cap));
    let mut proposers: Vec<_> = (1..=15).map(|agent| (AgentId(agent), 1 << 10)).collect();
    if large > 0 {
        proposers.push((AgentId(16), large));
    }
    let by_agent = propose(&cluster, &proposers);
    Arc::into_inner(cluster).unwrap().close();
    let mut small: Vec<Duration> = by_agent[1..=15].concat();
    small.sort();
    let large_commits = by_agent[16].len();
    println!(
        "15 agents of 1 KiB beside one of {} KiB, cap {} KiB: small {:.0} commits/s, p50 {:.2} ms, p99 {:.2} ms; large {:.0} commits/s",
        large >> 10,
        cap >> 10,
        small.len() as f64 / RUN.as_secs_f64(),
        percentile(&small, 0.5),
        percentile(&small, 0.99),
        large_commits as f64 / RUN.as_secs_f64(),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let number = |at: usize, default: usize| {
        args.get(at)
            .map_or(default, |value| value.parse().expect("a number"))
    };
    match args.first().map(String::as_str) {
        Some("sizes") => sizes(number(1, 3), number(2, usize::MAX)),
        Some("mixed") => mixed(number(1, 4 << 20), number(2, usize::MAX)),
        _ => eprintln!("usage: log-bench sizes [nodes] [cap] | mixed <large bytes> [cap]"),
    }
}
