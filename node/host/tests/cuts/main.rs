//! Window cuts on one replica's store, a work result at a time: where apply
//! records each window's cut, how the node's apply keeps the values a
//! pending cut's build still needs, what the builder targets, and the
//! roots and proofs a cut's build leaves. The terms are the model's
//! ([`model`]).

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod model;

use std::collections::BTreeMap;

use vos_node::roots::{self, AgentStore};
use vos_node::storage::Change;
use vos_tree::BatchProof;
use vos_wire::Encode;
use vos_wire::defaults::MAX_CUTS;
use vos_wire::ids::RequestId;
use vos_wire::keys;
use vos_wire::records::{PendingRead, stored_versioned};
use vos_wire::result::Write;

use model::{
    AGENT, CLOCK, Committed, Entry, History, MAPS, Replica, SPACE, check_proof, cuts, pending,
    replicated, requests, row, undos,
};

/// Keys the results write, over both maps.
const KEYS: u64 = 60;
/// Committed writes a result makes.
const WRITES: u64 = 40;
/// Keys a build batch rebuilds: a cut's build takes several.
const BATCH: usize = 16;

/// Version `version`'s committed writes: each key once, a value or, one in
/// nine, a deletion.
fn writes(version: u64) -> Vec<Committed> {
    (0..WRITES)
        .map(|index| {
            let slot = (version * 7919 + index * 31) % KEYS;
            let value = (!(version + index).is_multiple_of(9)).then(|| version.encode());
            (
                MAPS[(slot % 2) as usize],
                slot.to_be_bytes().to_vec(),
                value,
            )
        })
        .collect()
}

/// Sixteen rows a request reads: twelve the results write, present or
/// deleted, and four they never write, absent.
fn read_rows(offset: u64) -> Vec<Vec<u8>> {
    (0..16u64)
        .map(|index| {
            let slot = if index < 12 {
                (offset + index * 5) % KEYS
            } else {
                KEYS + offset + index
            };
            row(MAPS[(slot % 2) as usize], &slot.to_be_bytes())
        })
        .collect()
}

/// Results at 100 ms a version from the install, version 1, through
/// `through`: windows of a second cut at every tenth version (cut(w) =
/// 10·(w+1) − 1), a request in each window at its third version.
fn history(through: u64) -> History {
    let mut history = History::default();
    history.push(Entry::install(100, SPACE));
    for version in 2..=through {
        let mut entry = Entry::at(100 * version, writes(version));
        if version % 10 == 3 {
            entry.request = Some(pending(version, read_rows(version)));
        }
        history.push(entry);
    }
    history
}

/// Apply versions `from..=to` of `history`.
fn apply(replica: &Replica, history: &History, from: u64, to: u64) {
    for version in from..=to {
        let entry = &history.entries[version as usize - 1];
        assert!(
            replica.apply(version, &entry.result(version - 1)),
            "version {version} applies"
        );
    }
}

/// The undo rows a replica must hold for the pending cuts `windows` once
/// `history` is applied through `version` with no build since `cut(w)`:
/// for each, every row present at the cut and written after it, holding
/// its stored bytes at the cut.
fn expected_undos(
    history: &History,
    windows: &[u64],
    version: u64,
) -> BTreeMap<(u64, Vec<u8>), Vec<u8>> {
    let cuts = history.cuts(version);
    let mut expected = BTreeMap::new();
    for window in windows {
        let cut = cuts[window];
        let at_cut = history.values(cut);
        for later in cut + 1..=version {
            for (map, key, _) in &history.entries[later as usize - 1].committed {
                let row = row(*map, key);
                if let Some((at, value)) = at_cut.get(&row) {
                    expected
                        .entry((*window, row))
                        .or_insert_with(|| stored_versioned(*at, value));
                }
            }
        }
    }
    expected
}

/// A builder lagging across two boundaries, here three, builds each cut in
/// turn: the cut build targets `min(latest, the earliest unbuilt cut)`, so
/// its builds go to cut(0), cut(1), cut(2), then the latest version. Until
/// its build, a cut's undo rows hold every row present at the cut that a
/// later result rewrote, its stored bytes at the cut. Each cut's build
/// leaves, in its own commit, the root at the cut and every pending
/// request's proof of its window, and drops that window's undo rows. The
/// root at each cut, and each proof's bytes, equal a rebuild from a
/// snapshot: a replica that applied the results through the cut alone and
/// built there.
#[test]
fn a_builder_lagging_across_two_boundaries_builds_each_cut_as_a_rebuild_would() {
    let history = history(31);
    let dir = tempfile::tempdir().unwrap();
    let lagging = Replica::open(dir.path());
    apply(&lagging, &history, 1, 31);
    let snapshot = lagging.snapshot();
    assert_eq!(cuts(&snapshot), BTreeMap::from([(0, 9), (1, 19), (2, 29)]));
    assert_eq!(cuts(&snapshot), history.cuts(31));
    assert_eq!(requests(&snapshot), history.requests(31));
    assert_eq!(
        undos(&snapshot),
        expected_undos(&history, &[0, 1, 2], 31),
        "every pending cut's undo rows"
    );
    drop(snapshot);

    let requests = history.requests(31);
    for (built, (window, cut)) in [(0, 9), (1, 19), (2, 29)].into_iter().enumerate() {
        assert_eq!(
            lagging.build(BATCH),
            Some(cut),
            "the build of cut({window})"
        );
        let snapshot = lagging.snapshot();
        assert_eq!(
            roots::cut_root(&snapshot, AGENT, window).unwrap(),
            Some((history.root(cut), cut)),
            "the root at cut({window}), once built"
        );
        let left: Vec<u64> = undos(&snapshot).keys().map(|(window, _)| *window).collect();
        assert!(
            left.iter().all(|left| *left > window),
            "window {window}'s undo rows dropped by its build, the later ones kept: {left:?}"
        );
        for (id, (asked, read)) in &requests {
            let proof = roots::cut_proof_at(&snapshot, AGENT, *id, *asked).unwrap();
            if *asked <= window {
                let proof = proof.expect("a proof once its cut is built");
                check_proof(&history, &proof, *asked, history.cuts(31)[asked], read);
            } else {
                assert!(proof.is_none(), "no proof before its cut is built");
            }
        }
        assert!(
            built < 1
                || roots::cut_root(&snapshot, AGENT, window - 1)
                    .unwrap()
                    .is_some(),
            "the previous cut's root kept"
        );
    }
    assert_eq!(lagging.build(BATCH), Some(31), "then the latest version");
    assert_eq!(lagging.build(BATCH), None);
    let snapshot = lagging.snapshot();
    assert_eq!(
        roots::agent_root(&snapshot, AGENT).unwrap(),
        (history.root(31), 31)
    );
    assert!(undos(&snapshot).is_empty(), "no undo row left");
    assert_eq!(
        roots::cut_root(&snapshot, AGENT, 0).unwrap(),
        None,
        "the root at a cut kept for the two latest cuts alone"
    );
    assert!(roots::rows_match_tree(&snapshot, AGENT).unwrap());

    // The rebuild from a snapshot at each cut: the same results through the
    // cut, built there.
    let fresh = tempfile::tempdir().unwrap();
    let rebuilt = Replica::open(fresh.path());
    let mut applied = 0;
    for (window, cut) in [(0, 9), (1, 19), (2, 29)] {
        apply(&rebuilt, &history, applied + 1, cut);
        applied = cut;
        rebuilt.build_all(BATCH);
        let at_cut = rebuilt.snapshot();
        let (root, version) = roots::agent_root(&at_cut, AGENT).unwrap();
        assert_eq!(version, cut);
        let proof_of = |id: &RequestId, read: &PendingRead| {
            let proof = roots::cut_proof_at(&snapshot, AGENT, *id, window)
                .unwrap()
                .unwrap();
            let tree = AgentStore::open(&at_cut, AGENT).unwrap();
            let fresh = BatchProof::generate(&tree, &read.rows).unwrap();
            (proof, fresh.encode())
        };
        for (id, (asked, read)) in &requests {
            if *asked != window {
                continue;
            }
            let (proof, fresh) = proof_of(id, read);
            assert_eq!(proof.agent_root, root, "the root at cut({window}), rebuilt");
            assert_eq!(proof.rows_proof, fresh, "the proof's bytes, rebuilt");
        }
        if window > 0 {
            assert_eq!(
                roots::cut_root(&snapshot, AGENT, window).unwrap(),
                Some((root, cut)),
                "the root at cut({window}), rebuilt"
            );
        }
    }
}

/// A batch time that jumps Δ, as after a leader's clock ran fast, cuts
/// every window up to `w(t + Δ)` at one version: each window whose
/// boundary the jump crossed gets `cut(w)` = the version before the jumping
/// result. A result exactly at a boundary crosses it; one a millisecond
/// before does not. A later result at the mark, as a trailing leader times
/// its batches, cuts nothing; one timed before the mark applies nothing.
/// A cut, once recorded, never moves. A result crossing more than
/// `MAX_CUTS` boundaries cuts the newest `MAX_CUTS` windows alone.
#[test]
fn a_clock_jump_cuts_every_window_it_crosses_at_one_version() {
    let dir = tempfile::tempdir().unwrap();
    let mut jumps = Jumps {
        replica: Replica::open(dir.path()),
        history: History::default(),
        index: 0,
        recorded: BTreeMap::new(),
    };
    jumps.history.push(Entry::install(500, SPACE));
    jumps.index = 1;
    assert!(jumps.replica.apply(1, &jumps.history.entries[0].result(0)));
    jumps.step(900, true);
    jumps.step(999, true);
    assert!(jumps.recorded.is_empty(), "no boundary crossed yet");
    // Δ: from window 0 into window 4.
    jumps.step(4_250, true);
    assert_eq!(
        jumps.recorded,
        BTreeMap::from([(0, 3), (1, 3), (2, 3), (3, 3)])
    );
    // A trailing leader times its batches at the mark.
    jumps.step(4_250, true);
    assert_eq!(jumps.recorded.len(), 4);
    jumps.step(4_100, false);
    jumps.step(4_999, true);
    assert_eq!(jumps.recorded.len(), 4, "a millisecond before B_4");
    jumps.step(5_000, true);
    assert_eq!(jumps.recorded.get(&4), Some(&6), "exactly at B_4");
    let before = jumps.replica.version();
    jumps.step(5_000 + 10 * CLOCK.length_ms, true);
    for window in 5..=14 {
        assert_eq!(jumps.recorded.get(&window), Some(&before));
    }
    // A jump past `MAX_CUTS` boundaries cuts the newest `MAX_CUTS` alone,
    // and the older windows are never cut.
    let skipped = 5;
    let before = jumps.replica.version();
    let into = 15 + MAX_CUTS + skipped;
    jumps.step(into * CLOCK.length_ms + 500, true);
    let new: Vec<u64> = jumps
        .recorded
        .range(15..)
        .map(|(window, _)| *window)
        .collect();
    assert_eq!(new, (15 + skipped..into).collect::<Vec<_>>());
    assert!(jumps.recorded.range(15..).all(|(_, cut)| *cut == before));
    jumps.step((into + 1) * CLOCK.length_ms, true);
    assert_eq!(
        jumps.recorded.range(15..15 + skipped).count(),
        0,
        "skipped for good"
    );
    assert!(jumps.recorded.contains_key(&into));
}

/// A replica applying results one at a time, and the cuts it recorded.
struct Jumps {
    replica: Replica,
    history: History,
    index: u64,
    recorded: BTreeMap<u64, u64>,
}

impl Jumps {
    /// Apply a result timed `time`, which `applies` or not; its cuts are
    /// the model's, and every earlier cut still kept is where it was.
    fn step(&mut self, time: u64, applies: bool) {
        let entry = Entry::at(time, writes(time));
        self.index += 1;
        let version = self.replica.version();
        let applied = self.replica.apply(self.index, &entry.result(version));
        assert_eq!(applied, applies, "at {time}");
        if applies {
            self.history.push(entry);
        }
        let now = cuts(&self.replica.snapshot());
        assert_eq!(
            now,
            self.history.cuts(self.history.version()),
            "the cuts at {time}"
        );
        for (window, cut) in &self.recorded {
            if let Some(now) = now.get(window) {
                assert_eq!(now, cut, "cut({window}) never moves");
            }
        }
        self.recorded = now;
    }
}

/// An agent of no space, its record naming `SpaceId::NONE`, and an agent
/// with no record at all, record no cut whatever boundaries their results
/// cross: no cut row, no undo row, each build at the latest version, no
/// root at any cut.
#[test]
fn an_agent_of_no_space_runs_no_cuts() {
    for record in [Some(vos_wire::SpaceId::NONE), None] {
        let dir = tempfile::tempdir().unwrap();
        let replica = Replica::open(dir.path());
        let mut history = History::default();
        if let Some(space) = record {
            history.push(Entry::install(100, space));
        }
        for version in history.version() + 1..=35 {
            history.push(Entry::at(100 * version, writes(version)));
        }
        for version in 1..=35 {
            let entry = &history.entries[version as usize - 1];
            assert!(replica.apply(version, &entry.result(version - 1)));
            if version.is_multiple_of(12) {
                assert_eq!(replica.build_all(BATCH), vec![version]);
            }
        }
        let snapshot = replica.snapshot();
        assert!(cuts(&snapshot).is_empty(), "{record:?}: no cut");
        assert!(undos(&snapshot).is_empty(), "{record:?}: no undo row");
        assert!(history.cuts(35).is_empty());
        assert_eq!(replica.build_all(BATCH), vec![35]);
        let snapshot = replica.snapshot();
        for window in 0..4 {
            assert_eq!(roots::cut_root(&snapshot, AGENT, window).unwrap(), None);
        }
        assert_eq!(
            roots::agent_root(&snapshot, AGENT).unwrap(),
            (history.root(35), 35)
        );
    }
}

/// Undo rows are each replica's own: two replicas applying the same
/// results, one building after every result and one lagging across
/// boundaries, hold the same replicated rows (cuts and pending requests
/// among them) at every version, though their undo rows differ; once both
/// have built, the same root at every kept cut, the same proofs byte for
/// byte, and no undo row.
#[test]
fn replicas_agree_whatever_undo_rows_each_holds() {
    let history = history(47);
    let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (eager, lagging) = (Replica::open(one.path()), Replica::open(two.path()));
    let mut differed = false;
    for version in 1..=47 {
        for replica in [&eager, &lagging] {
            apply(replica, &history, version, version);
        }
        eager.build_all(BATCH);
        if version.is_multiple_of(13) {
            lagging.build_all(BATCH);
        }
        let (a, b) = (eager.snapshot(), lagging.snapshot());
        assert_eq!(
            replicated(&a),
            replicated(&b),
            "the replicated rows at version {version}"
        );
        differed |= undos(&a) != undos(&b);
    }
    assert!(differed, "the replicas' undo rows never differed");
    eager.build_all(BATCH);
    lagging.build_all(BATCH);
    let (a, b) = (eager.snapshot(), lagging.snapshot());
    let kept = history.cuts(47);
    for window in kept.keys().rev().take(2) {
        let root = roots::cut_root(&a, AGENT, *window).unwrap();
        assert!(root.is_some(), "cut({window}) kept");
        assert_eq!(root, roots::cut_root(&b, AGENT, *window).unwrap());
    }
    let latest: Vec<u64> = kept.keys().rev().take(2).copied().collect();
    for (id, (window, read)) in history.requests(47) {
        let proof = roots::cut_proof_at(&a, AGENT, id, window).unwrap();
        assert_eq!(
            proof,
            roots::cut_proof_at(&b, AGENT, id, window).unwrap(),
            "{id:?}"
        );
        if latest.contains(&window) {
            let proof = proof.clone().expect("a proof at a kept cut");
            check_proof(&history, &proof, window, kept[&window], &read);
        }
        if !kept.contains_key(&window) {
            assert!(proof.is_none(), "no proof before the cut");
        }
    }
    assert!(undos(&a).is_empty() && undos(&b).is_empty());
    assert_eq!(replicated(&a), replicated(&b));
    assert_eq!(
        a.scan(AGENT, &keys::cut_proofs(), None).count(),
        b.scan(AGENT, &keys::cut_proofs(), None).count()
    );
}

/// A record stored in part, one or two of the target, the space and the
/// clock, is corrupt: the agent's apply applies no later result, crossing
/// a boundary or not, and writes nothing.
#[test]
fn a_record_stored_in_part_applies_nothing() {
    let record = Entry::install(100, SPACE).writes;
    for held in 1..7u8 {
        let dir = tempfile::tempdir().unwrap();
        let replica = Replica::open(dir.path());
        let part = record
            .iter()
            .enumerate()
            .filter(|(at, _)| held & (1 << at) != 0)
            .map(|(_, write)| write.clone())
            .collect();
        let first = Entry {
            time: 100,
            writes: part,
            ..Entry::default()
        };
        assert!(replica.apply(1, &first.result(0)), "the part applies");
        let rows = replicated(&replica.snapshot());
        for (index, time) in [(2, 500), (3, 1_500)] {
            let (_, written, applied) =
                replica.accumulate(&Entry::at(time, writes(time)).result(1));
            assert!(!applied, "{held:03b}: a result at {time}");
            assert!(written.is_empty(), "nothing written");
            assert!(!replica.apply(index, &Entry::at(time, writes(time)).result(1)));
        }
        assert_eq!(replicated(&replica.snapshot()), rows, "{held:03b}");
        assert_eq!(replica.version(), 1);
    }
}

/// A cut whose version the tree is already built at, as when a build at
/// the latest version lands just before the crossing result: its build
/// reads no dirty row and finishes it alone, its root and its window's
/// proofs; the next build goes on to the latest version. A result's
/// writes naming a committed row twice keep one undo row of it.
#[test]
fn a_cut_built_already_is_finished_alone() {
    let history = history(10);
    let dir = tempfile::tempdir().unwrap();
    let replica = Replica::open(dir.path());
    apply(&replica, &history, 1, 9);
    assert_eq!(replica.build_all(BATCH), vec![9]);
    apply(&replica, &history, 10, 10);
    assert_eq!(
        replica.build_read(BATCH),
        Some((9, 0)),
        "the cut, no dirty row read"
    );
    let snapshot = replica.snapshot();
    assert_eq!(
        roots::cut_root(&snapshot, AGENT, 0).unwrap(),
        Some((history.root(9), 9))
    );
    for (id, (window, read)) in history.requests(10) {
        let proof = roots::cut_proof_at(&snapshot, AGENT, id, window)
            .unwrap()
            .expect("a proof");
        check_proof(&history, &proof, window, 9, &read);
    }
    assert_eq!(replica.build(BATCH), Some(10));
    assert_eq!(replica.build(BATCH), None);

    // A cut pending again, and a committed row written twice in one
    // result.
    let snapshot = replica.snapshot();
    let (row, stored) = model::scan(&snapshot, &keys::committed_all())[0].clone();
    let cut = Write {
        key: keys::cut(5),
        value: Some(vos_wire::records::stored(&10u64.encode())),
    };
    let twice = |value: u8| Write {
        key: row.clone(),
        value: Some(vec![value]),
    };
    let undo = roots::undo(&snapshot, AGENT, &[cut, twice(1), twice(2)]).unwrap();
    assert_eq!(
        undo,
        vec![Write {
            key: keys::undo(5, &row),
            value: Some(stored)
        }]
    );
}

/// An undo row of a window already built, as an apply racing the cut's
/// finishing commit leaves, makes a build due, which deletes it.
#[test]
fn an_orphaned_undo_row_is_swept() {
    let history = history(12);
    let dir = tempfile::tempdir().unwrap();
    let replica = Replica::open(dir.path());
    apply(&replica, &history, 1, 12);
    assert_eq!(replica.build_all(BATCH), vec![9, 12]);
    let orphan = Write {
        key: keys::undo(0, &row(MAPS[0], &0u64.to_be_bytes())),
        value: Some(vec![1]),
    };
    let change = Change::Tree {
        agent: AGENT,
        epoch: 0,
        writes: vec![orphan],
    };
    smol::block_on(replica.writer.commit(vec![change])).unwrap();
    assert_eq!(undos(&replica.snapshot()).len(), 1);
    assert_eq!(replica.build(BATCH), Some(12));
    assert!(undos(&replica.snapshot()).is_empty(), "swept");
    assert_eq!(replica.build(BATCH), None);
}

/// A pending request whose row does not decode, names a key that is no
/// committed row, or one whose value is no value row, is left unproved:
/// the cut's root and the other requests' proofs still land, alike on
/// every replica.
#[test]
fn a_request_that_does_not_read_is_left_unproved() {
    let mut history = history(12);
    let bad = |workflow: u64| RequestId {
        workflow: vos_wire::ids::WorkflowId(workflow),
        awaits: 0,
    };
    let malformed = row(MAPS[0], &7u64.to_be_bytes())[..keys::COMMITTED_PREFIX].to_vec();
    let mut short = malformed.clone();
    short.push(1);
    let read = |rows: Vec<Vec<u8>>| {
        PendingRead {
            instance: model::READER,
            rows,
        }
        .encode()
    };
    history.entries[3].writes.extend([
        Write {
            key: keys::request(0, bad(901)),
            value: Some(vec![0xff, 0xff]),
        },
        Write {
            key: keys::request(0, bad(902)),
            value: Some(read(vec![keys::version()])),
        },
        Write {
            key: short.clone(),
            value: Some(vec![1]),
        },
        Write {
            key: keys::request(0, bad(903)),
            value: Some(read(vec![short])),
        },
    ]);
    let dir = tempfile::tempdir().unwrap();
    let replica = Replica::open(dir.path());
    apply(&replica, &history, 1, 12);
    assert_eq!(replica.build_all(BATCH), vec![9, 12]);
    let snapshot = replica.snapshot();
    assert!(roots::cut_root(&snapshot, AGENT, 0).unwrap().is_some());
    for (id, (window, read)) in history.requests(12) {
        let proof = roots::cut_proof_at(&snapshot, AGENT, id, window)
            .unwrap()
            .expect("a proof");
        check_proof(&history, &proof, window, 9, &read);
    }
    for id in [901, 902, 903] {
        assert_eq!(roots::cut_proof(&snapshot, AGENT, bad(id)).unwrap(), None);
    }
}
