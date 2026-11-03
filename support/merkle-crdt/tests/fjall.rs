//! The fjall store: what a replica writes reads back the same after a
//! reopen, and a process killed at any point leaves each batch whole or
//! absent.

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

use common::{H, Ops, Rng, Step, crdt, generate};
use fjall::Database;
use merkle_crdt::sync::{Feed, Page};
use merkle_crdt::{FjallStore, Replica, Store, rebuild};

type Fjall = Replica<H, Ops, FjallStore>;

fn open(dir: &std::path::Path) -> (Database, Fjall) {
    let db = Database::builder(dir).open().unwrap();
    let replica = Replica::open(FjallStore::open(&db, "scope").unwrap()).unwrap();
    (db, replica)
}

fn rows(store: &FjallStore) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    store
        .rows()
        .iter()
        .map(|row| {
            let (key, value) = row.into_inner().unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

/// A shuffled DAG of 3 authors, numbered as a server would accept it.
fn accepted() -> Vec<(u64, Vec<u8>)> {
    let steps: Vec<Step> = (0..600u64)
        .map(|i| match i % 5 {
            4 => Step::Learn {
                from: i as u8,
                to: (i / 5) as u8,
            },
            3 if i % 45 == 3 => Step::Equivocate {
                author: i as u8,
                value: i,
            },
            _ => Step::Record {
                author: i as u8,
                ops: vec![(i % 11, i), (i % 3, 1)],
                pick: u64::MAX,
            },
        })
        .collect();
    let mut nodes: Vec<Vec<u8>> = generate(3, &steps)
        .nodes
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    Rng(11).shuffle(&mut nodes);
    nodes
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| (i as u64 + 1, bytes))
        .collect()
}

struct Server(Vec<(u64, Vec<u8>)>, usize);

impl Feed for Server {
    type Error = std::convert::Infallible;
    fn since(&mut self, position: Option<u64>) -> Result<Page, Self::Error> {
        let start = position.unwrap_or(0) as usize;
        let end = (start + self.1).min(self.0.len());
        Ok(Page {
            items: self.0[start..end].to_vec(),
            more: end < self.0.len(),
        })
    }
}

#[test]
fn a_reopened_store_is_the_replica_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let items = accepted();
    let (db, mut replica) = open(dir.path());
    let mut server = Server(items[..300].to_vec(), 32);
    replica.catch_up(&mut server, &mut crdt).unwrap();
    replica
        .record(&common::key(7), vec![(1, 1)], &mut crdt)
        .unwrap();
    let (heads, held, cursor) = (replica.heads().clone(), replica.held(), replica.cursor());
    let equivocations = replica.equivocations().clone();
    let have = replica.have();
    drop(replica);
    drop(db);

    let (_db, mut replica) = open(dir.path());
    assert_eq!(replica.heads(), &heads);
    assert_eq!(replica.held(), held);
    assert_eq!(replica.cursor(), cursor);
    assert_eq!(replica.equivocations(), &equivocations);
    assert_eq!(replica.have(), have);
    assert_eq!(replica.outbox().unwrap().len(), 1);

    let mut server = Server(items.clone(), 32);
    replica.catch_up(&mut server, &mut crdt).unwrap();
    assert_eq!(replica.held(), 0);
    let rebuilt = rebuild::<H, Ops, _, _>(replica.store(), &mut crdt).unwrap();
    assert_eq!(rows(replica.store()), rebuilt.rows);
    assert_eq!(replica.heads(), &rebuilt.heads);
    assert!(!rebuilt.equivocations.is_empty());
}

const CHILD: &str = "MERKLE_CRDT_CRASH_DIR";

/// The writer the crash test kills: catches up a page at a time, and
/// records a local node after each page, forever.
#[test]
fn crash_writer() {
    let Ok(dir) = std::env::var(CHILD) else {
        return;
    };
    let items = accepted();
    let (_db, mut replica) = open(dir.as_ref());
    let key = common::key(9);
    let mut i = 0;
    loop {
        let mut server = Server(items.clone(), 7);
        let page = server.since(replica.cursor()).unwrap();
        if page.items.is_empty() {
            replica.record(&key, vec![(i, i)], &mut crdt).unwrap();
            i += 1;
            continue;
        }
        let last = page.items.last().unwrap().0;
        replica
            .ingest(
                page.items.into_iter().map(|(_, b)| b),
                Some(last),
                &mut crdt,
            )
            .unwrap();
        replica.record(&key, vec![(i, i)], &mut crdt).unwrap();
        i += 1;
    }
}

/// Kill the writer at random points; after each kill the store reopens to
/// a replica whose rows are the rebuild of its nodes, whose cursor names
/// exactly the nodes it applied or holds, and which finishes the catch-up.
#[test]
fn a_killed_writer_leaves_whole_batches() {
    let dir = tempfile::tempdir().unwrap();
    // Create the store before any kill.
    drop(open(dir.path()));
    let items = accepted();
    let mut rng = Rng(0x5eed);
    for round in 0..12 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_writer", "--nocapture"])
            .env(CHILD, dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(20 + rng.below(180) as u64));
        child.kill().unwrap();
        child.wait().unwrap();

        let (_db, replica) = open(dir.path());
        let rebuilt = rebuild::<H, Ops, _, _>(replica.store(), &mut crdt).unwrap();
        assert_eq!(rows(replica.store()), rebuilt.rows, "round {round}");
        assert_eq!(replica.heads(), &rebuilt.heads, "round {round}");
        let read = replica.cursor().unwrap_or(0) as usize;
        for (position, bytes) in &items {
            let (cid, _) = merkle_crdt::validate::<H, Ops>(bytes).unwrap();
            let stored = replica.store().contains(&cid).unwrap()
                || Store::<H>::held(replica.store(), &cid).unwrap().is_some();
            assert_eq!(
                stored,
                (*position as usize) <= read,
                "round {round}: position {position}, cursor {read}"
            );
        }
    }
    let (_db, mut replica) = open(dir.path());
    replica.catch_up(&mut Server(items, 64), &mut crdt).unwrap();
    assert_eq!(replica.held(), 0);
    let rebuilt = rebuild::<H, Ops, _, _>(replica.store(), &mut crdt).unwrap();
    assert_eq!(rows(replica.store()), rebuilt.rows);
}
