//! The fjall store: what a replica writes reads back the same after a
//! reopen, and a process killed at any point leaves each batch whole or
//! absent.

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

use std::collections::BTreeSet;

use common::{H, Ops, Replayed, Rng, SCOPE, Server, Step, crdt, generate, read, replay};
use fjall::{Database, KeyspaceCreateOptions};
use merkle_crdt::{Error, Event, FjallError, FjallStore, Node, Replica, Rows, Store};

type Fjall = Replica<H, Ops, FjallStore>;

fn open(dir: &std::path::Path) -> (Database, Fjall) {
    let db = Database::builder(dir).open().unwrap();
    let replica = Replica::open(FjallStore::open(&db, "scope").unwrap(), SCOPE).unwrap();
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

/// The replay of the applied nodes the store `scope` of `db` holds.
fn replayed(db: &Database) -> Replayed {
    let nodes = db
        .keyspace("scope.nodes", KeyspaceCreateOptions::default)
        .unwrap();
    replay(
        nodes.iter().map(|row| row.value().unwrap().to_vec()),
        &mut crdt,
    )
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

fn server(items: &[(u64, Vec<u8>)], page: usize) -> Server {
    Server {
        items: items.to_vec(),
        page,
        trips: 0,
    }
}

#[test]
fn a_reopened_store_is_the_replica_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let items = accepted();
    let (db, mut replica) = open(dir.path());
    read(&mut replica, &mut server(&items[..300], 32));
    replica
        .record(&common::key(7), vec![(1, 1)], &mut crdt)
        .unwrap();
    let (heads, held, cursor) = (replica.heads().clone(), replica.held(), replica.cursor());
    let equivocations = replica.equivocations().clone();
    let have = replica.have();
    drop(replica);
    drop(db);

    let (db, mut replica) = open(dir.path());
    assert_eq!(replica.heads(), &heads);
    assert_eq!(replica.held(), held);
    assert_eq!(replica.cursor(), cursor);
    assert_eq!(replica.equivocations(), &equivocations);
    assert_eq!(replica.have(), have);
    assert_eq!(replica.outbox().unwrap().len(), 1);

    read(&mut replica, &mut server(&items, 32));
    assert_eq!(replica.held(), 0);
    let rebuilt = replayed(&db);
    assert_eq!(rows(replica.store()), rebuilt.rows);
    assert_eq!(replica.heads(), &rebuilt.heads);
    assert!(!rebuilt.equivocations.is_empty());
}

/// A caller's own writes ride in a commit's batch: committed with the
/// scope's changes, in the caller's keyspace.
#[test]
fn a_commit_carries_the_callers_writes() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::builder(dir.path()).open().unwrap();
    let own = db
        .keyspace("own", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    let mut store = FjallStore::open(&db, "scope").unwrap();
    let changes = merkle_crdt::Changes::<H> {
        rows: [(b"row".to_vec(), Some(b"value".to_vec()))].into(),
        ..Default::default()
    };
    store
        .commit_with(changes, |batch| batch.insert(&own, "mine", "yes"))
        .unwrap();
    assert_eq!(rows(&store)[&b"row".to_vec()], b"value");
    assert_eq!(&*own.get("mine").unwrap().unwrap(), b"yes");
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
    let mut server = server(&items, 7);
    loop {
        let (page, _) = server.since(replica.cursor());
        if page.is_empty() {
            replica.record(&key, vec![(i, i)], &mut crdt).unwrap();
            i += 1;
            continue;
        }
        let last = page.last().unwrap().0;
        replica
            .ingest(page.into_iter().map(|(_, b)| b), Some(last), &mut crdt)
            .unwrap();
        replica.record(&key, vec![(i, i)], &mut crdt).unwrap();
        i += 1;
    }
}

/// Kill the writer at random points; after each kill the store reopens to
/// a replica whose rows are the replay of its nodes, whose cursor names
/// exactly the nodes it applied or holds, and which finishes the catch-up.
#[test]
fn a_killed_writer_leaves_whole_batches() {
    let dir = tempfile::tempdir().unwrap();
    // Create the store before any kill.
    drop(open(dir.path()));
    let items = accepted();
    let mut rng = Rng(0x5eed);
    let mut moved = 0;
    let mut cursor = None;
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

        let (db, replica) = open(dir.path());
        let rebuilt = replayed(&db);
        assert_eq!(rows(replica.store()), rebuilt.rows, "round {round}");
        assert_eq!(replica.heads(), &rebuilt.heads, "round {round}");
        if replica.cursor() != cursor {
            moved += 1;
            cursor = replica.cursor();
        }
        let read = replica.cursor().unwrap_or(0) as usize;
        for (position, bytes) in &items {
            let (cid, _) = merkle_crdt::validate::<H, Ops>(&SCOPE, bytes).unwrap();
            let stored = replica.store().contains(&cid).unwrap()
                || Store::<H>::held(replica.store(), &cid).unwrap().is_some();
            assert_eq!(
                stored,
                (*position as usize) <= read,
                "round {round}: position {position}, cursor {read}"
            );
        }
    }
    assert!(moved > 0, "no writer wrote before it was killed");
    let (db, mut replica) = open(dir.path());
    read(&mut replica, &mut server(&items, 64));
    assert_eq!(replica.held(), 0);
    let rebuilt = replayed(&db);
    assert_eq!(rows(replica.store()), rebuilt.rows);
}

/// A row key fjall does not take fails the batch with an error, through a
/// replica and through a commit, and nothing is written.
#[test]
fn a_row_fjall_refuses_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (_db, mut replica) = open(dir.path());
    let long = vec![1; merkle_crdt::MAX_ROW_KEY + 1];
    for bad in [Vec::new(), long] {
        let mut write = |_: Event<'_, H, Ops>, rows: &mut dyn Rows| rows.write(&bad, Some(b"x"));
        let node = Node::<H, Ops>::sign(&common::key(1), &SCOPE, 0, vec![], BTreeSet::new());
        assert!(matches!(
            replica.ingest([node.to_bytes()], None, &mut write),
            Err(Error::Row)
        ));
        let changes = merkle_crdt::Changes::<H> {
            rows: [(bad.clone(), Some(b"x".to_vec()))].into(),
            ..Default::default()
        };
        assert!(matches!(
            replica.store_mut().commit_with(changes, |_| {}),
            Err(FjallError::Row)
        ));
    }
    assert!(replica.heads().is_empty());
    assert!(rows(replica.store()).is_empty());
}
