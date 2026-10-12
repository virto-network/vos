//! A version popped from the history is not dropped under the version lock:
//! the last reference to a flushed memtable can be in it, and freeing a
//! large memtable must not hold every reader of the tree.

use lsm_tree::{
    AbstractTree, Config, InternalValue, Memtable, SeqNo, SequenceNumberCounter, ValueType,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Items in the memtable freed, to start with: doubled until freeing them
/// takes 50 ms or more here, up to `MOST_ITEMS` (about 1 GiB a memtable,
/// the lone one's and then the tree's).
const ITEMS: u64 = 1_500_000;
const MOST_ITEMS: u64 = 6_000_000;

fn key(item: u64) -> [u8; 8] {
    item.to_be_bytes()
}

fn filled(items: u64) -> Memtable {
    let memtable = Memtable::new(0);
    for item in 0..items {
        memtable.insert(InternalValue::from_components(
            key(item),
            key(item),
            item,
            ValueType::Value,
        ));
    }
    memtable
}

#[test]
fn a_popped_memtable_is_freed_outside_the_version_lock() -> lsm_tree::Result<()> {
    // A memtable whose free takes 50 ms or more here, and how long it takes.
    let mut items = ITEMS;
    let free = loop {
        let memtable = filled(items);
        let started = Instant::now();
        drop(memtable);
        let free = started.elapsed();
        if free >= Duration::from_millis(50) {
            break free;
        }
        if items >= MOST_ITEMS {
            eprintln!(
                "skipped: freeing {items} items takes {free:?} here, too short to tell a stall from noise"
            );
            return Ok(());
        }
        items *= 2;
    };

    let folder = tempfile::tempdir()?;
    let seqno = SequenceNumberCounter::default();
    let tree = Arc::new(Config::new(&folder, seqno.clone(), SequenceNumberCounter::default()).open()?);
    for item in 0..items {
        tree.insert(key(item), key(item), seqno.next());
    }
    let memtable = Arc::downgrade(&tree.active_memtable());
    // Flushed with no version below the watermark: the versions holding
    // the memtable stay in the history, as an open snapshot keeps them.
    tree.flush_active_memtable(0)?;
    assert!(memtable.strong_count() > 0, "the history holds the memtable");

    // A small flush with every version below the watermark pops them, and
    // with them the memtable's last reference, while a reader reads until
    // the memtable is gone.
    tree.insert(key(items), key(items), seqno.next());
    let reading = Arc::new(AtomicBool::new(true));
    let reader = {
        let (tree, reading) = (Arc::clone(&tree), Arc::clone(&reading));
        std::thread::spawn(move || {
            let mut longest = Duration::ZERO;
            let mut reads = 0u64;
            while reading.load(Ordering::Relaxed) {
                let started = Instant::now();
                let value = tree.get(key(reads % items), SeqNo::MAX).expect("a read");
                longest = longest.max(started.elapsed());
                assert!(value.is_some());
                reads += 1;
            }
            (longest, reads)
        })
    };
    std::thread::sleep(Duration::from_millis(20));
    tree.flush_active_memtable(SeqNo::MAX)?;
    let until = Instant::now() + Duration::from_secs(30);
    while memtable.strong_count() > 0 {
        assert!(Instant::now() < until, "the memtable is never freed");
        std::thread::sleep(Duration::from_millis(1));
    }
    // The count falls before the free runs: read through all of it.
    std::thread::sleep(free);
    reading.store(false, Ordering::Relaxed);
    let (longest, reads) = reader.join().expect("the reader");

    assert!(reads > 0);
    assert!(
        longest < free / 2,
        "a read waited {longest:?} while a memtable whose free takes {free:?} was freed"
    );
    Ok(())
}
