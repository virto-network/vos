#![cfg(feature = "prover")]

//! The settlement window's kernel, the `window` test actor's (`just
//! build-test-actors`), under a carried commitment: it opens `c_prev`, the
//! venue's commitment to a pair's running totals at its last settlement,
//! with the totals and the salt, privately; reads the pair's two aggregate
//! rows at one window's cut, served and checked against the space's root by
//! the SDK's prologue; checks no total fell; and states `(net, seq, c_new)`,
//! the net since, the next sequence number and the commitment to the new
//! totals, rooted at the cut and naming no anchor.
//!
//! The agent's map holds a million rows, the pair's two among them, under a
//! representative's tree of 1,024 agents' roots. The method runs live on
//! the agent's reference model at the cut; its kernel re-runs from the
//! attest to the same statement, proves over its shape and verifies as a
//! chain against its program; its leaves and folds prove and verify; and
//! its whole run, folded to one root, wraps under `format::WRAP` and masked
//! under 39, whose statement the model venue judges against the space's
//! anchors: accepted, and refused as each thing it binds is changed.

use crate::common;
use crate::cut::{
    self, AGENT, AGENTS, Cut, INSTANCE, ROWS, Rng, Venue, WINDOW, genesis, read_live, traced,
};

use std::time::Instant;

use cipher_clerk::codec;
use cipher_clerk::conventions::PseudoAccount;
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::types::{Account, Layer};
use vos_pvm_final_verifier::masked;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::program_id::KernelEntry;
use vos_pvm_proof::segment::{SegmentCursor, segment_bounds_budgeted};
use vos_pvm_proof::{Proof, program_commitment_of_proof, prove_kernel};
use vos_pvm_proof_verifier::{verify_kernel_chain, verify_kernel_segment};
use vos_statement::{Pin, ProgramId, Statement};
use vos_testkit::programs::table_tag;
use vos_tree::{Blake2b, Hasher};
use vos_venue::{AnchorRefusal, VenueClient};
use vos_wire::abi::AttestError;
use vos_wire::ids::MapId;
use vos_wire::keys::{self, Transform};
use vos_wire::served::Served;
use vos_wire::vos_anchor::{Migrate, RootRead, VenueId, space_id, space_root};
use vos_wire::{Encode, SpaceId};

const PEER: [u8; 32] = [0xB2; 32];
const OPERATOR: [u8; 32] = [0x0C; 32];
const CURRENCY: u32 = 840;
/// The journal the pair's aggregate rows are kept in (`window::AGGREGATE`).
const AGGREGATE: JournalId = JournalId([0; 16]);
/// The class a run is cut at: segments of up to 2^15 steps.
const CUT: usize = 1;
/// The venue the statements are judged at.
const VENUE: VenueId = VenueId([0x7e; 32]);

/// Spike 6.0a's measured costs of the space path [measured,
/// slice-6-progress.md]: its compressions (with `S_w`'s) and bytes. A
/// row's are `reads`' (`reads_at_a_cut_measure`), the window reading two.
const SPIKE_PATH_COMPRESSIONS: f64 = 15.0;
const SPIKE_PATH_BYTES: f64 = 590.0;

/// A pair's running totals (`window::Totals`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Totals {
    out_dr: u64,
    out_cr: u64,
    in_dr: u64,
    in_cr: u64,
}

impl Totals {
    /// What the space owes the peer at these totals.
    fn owed(&self) -> i128 {
        let wide = i128::from;
        (wide(self.out_cr) - wide(self.out_dr)) - (wide(self.in_dr) - wide(self.in_cr))
    }
}

/// A pair's state as `c_prev` opens it (`window::Carried`): its salt, its
/// totals, its sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Carried {
    salt: [u8; 16],
    totals: Totals,
    seq: u64,
}

impl Carried {
    fn encode(&self) -> Vec<u8> {
        let t = &self.totals;
        (
            (self.salt, (t.out_dr, t.out_cr)),
            ((t.in_dr, t.in_cr), self.seq),
        )
            .encode()
    }

    /// The pair's commitment to it (`window::commitment`).
    fn commitment(&self, peer: &[u8; 32], currency: u32) -> [u8; 32] {
        let t = &self.totals;
        Blake2b.hash(
            b"vos/test/window/pair",
            &[
                peer,
                &currency.to_le_bytes(),
                &self.salt,
                &t.out_dr.to_le_bytes(),
                &t.out_cr.to_le_bytes(),
                &t.in_dr.to_le_bytes(),
                &t.in_cr.to_le_bytes(),
                &self.seq.to_le_bytes(),
            ],
        )
    }
}

/// The rows' totals: the outgoing row's debits and credits, the incoming
/// row's.
const ROWS_TOTALS: Totals = Totals {
    out_dr: 120,
    out_cr: 9_003,
    in_dr: 6_560,
    in_cr: 40,
};

/// The last settlement's state the tests carry: each total below the rows'.
const CARRIED: Carried = Carried {
    salt: [0x11; 16],
    totals: Totals {
        out_dr: 100,
        out_cr: 3_000,
        in_dr: 2_500,
        in_cr: 30,
    },
    seq: 6,
};
/// The next commitment's salt.
const SALT: [u8; 16] = [0x22; 16];

/// The kernel's statement: `(net, seq, c_new)`.
type Settlement = (i128, u64, [u8; 32]);

/// The pair's aggregate rows at [`ROWS_TOTALS`]: what the space sent the
/// peer (its outgoing row, credit-normal) and received (its incoming row,
/// debit-normal), bounces among them.
fn accounts() -> [Account<Value>; 2] {
    let at = |pseudo: PseudoAccount, dr: u64, cr: u64| {
        let mut account: Account<Value> = pseudo.open(OPERATOR);
        let settled = &mut account.balances[Layer::Settled.as_index()];
        settled.dr = Value(dr);
        settled.cr = Value(cr);
        account.timestamp = 1_000;
        account
    };
    let t = ROWS_TOTALS;
    [
        at(
            PseudoAccount::outgoing_to(AGGREGATE, PEER, CURRENCY),
            t.out_dr,
            t.out_cr,
        ),
        at(
            PseudoAccount::incoming_from(AGGREGATE, PEER, CURRENCY),
            t.in_dr,
            t.in_cr,
        ),
    ]
}

/// The window actor's committed map.
fn map() -> MapId {
    MapId {
        instance: INSTANCE,
        tag: table_tag("accounts"),
        transform: Transform::Hashed,
    }
}

/// An account's full row key in the map, by its id.
fn row(id: &[u8]) -> Vec<u8> {
    keys::committed(&map(), &Transform::Hashed.apply(id))
}

/// An account's value as the map stores it: its cipher-clerk encoding,
/// encoded as the SDK encodes a byte vector.
fn value(account: &Account<Value>) -> Vec<u8> {
    codec::to_bytes(account).encode()
}

/// The space the tests' agent belongs to: [`genesis`] 1's.
pub(crate) fn space() -> SpaceId {
    space_id(&genesis(1))
}

/// The agent's map: the pair's two rows among `rows` rows, the others
/// random, under a representative's tree of `agents` agents' roots, the
/// agent's held unless not `reported`.
fn cut_of(rows: usize, agents: u32, reported: bool) -> Cut {
    let accounts = accounts();
    let width = value(&accounts[0]).len();
    let mut rng = Rng(0x5eed_0000 + rows as u64);
    let others = (accounts.len()..rows)
        .map(|_| {
            let (mut id, mut bytes) = ([0u8; 16], vec![0u8; width]);
            rng.fill(&mut id);
            rng.fill(&mut bytes);
            (row(&id), bytes)
        })
        .collect();
    let known = accounts
        .iter()
        .map(|account| (row(&account.id.0), value(account)))
        .collect();
    Cut::new(space(), known, others, agents, reported)
}

/// A small map: the pair's rows among 256.
fn small() -> Cut {
    cut_of(256, 8, true)
}

/// A million rows under 1,024 agents' roots, as spike 6.0a's.
pub(crate) fn large() -> Cut {
    let started = Instant::now();
    let cut = cut_of(ROWS, AGENTS, true);
    eprintln!(
        "the fixture: {ROWS} rows, {AGENTS} agents' roots, built in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    cut
}

/// The arguments of `settle_at_cut` from `carried` to [`SALT`], `c_prev`
/// given.
fn arguments(c_prev: [u8; 32], carried: &Carried) -> Vec<u8> {
    [
        (PEER, CURRENCY, c_prev).encode(),
        carried.encode(),
        SALT.encode(),
    ]
    .concat()
}

/// What the window states from `carried` at the rows' totals, computed
/// here, and the state it reaches.
fn expected(carried: &Carried) -> (Settlement, Carried) {
    let next = Carried {
        salt: SALT,
        totals: ROWS_TOTALS,
        seq: carried.seq + 1,
    };
    let net = ROWS_TOTALS.owed() - carried.totals.owed();
    ((net, next.seq, next.commitment(&PEER, CURRENCY)), next)
}

/// A settlement at the cut through `settle_at_cut`, its rows served from
/// `cut` and changed by `serve`.
fn settle(
    cut: &Cut,
    c_prev: [u8; 32],
    carried: &Carried,
    serve: impl FnOnce(&mut Served),
) -> cut::Live {
    read_live(
        cut,
        "window",
        "settle_at_cut",
        &arguments(c_prev, carried),
        serve,
    )
}

/// The honest settlement from [`CARRIED`].
pub(crate) fn honest(cut: &Cut) -> cut::Live {
    settle(cut, CARRIED.commitment(&PEER, CURRENCY), &CARRIED, |_| {})
}

/// The window settles at a cut: its statement the net since the carried
/// state, the next sequence number and the commitment to the new totals;
/// its public arguments the reader's agent and instance, the peer, the
/// currency and `c_prev`; its one root the space's at the cut; live ≡
/// traced. The next settlement, from the state the first reached and the
/// same rows, states a net of nothing.
#[test]
fn the_window_settles_at_a_cut() {
    let cut = small();
    let c_prev = CARRIED.commitment(&PEER, CURRENCY);
    let live = honest(&cut);
    let (settlement, next) = expected(&CARRIED);
    assert_eq!(live.output::<Settlement>(), Ok(settlement));
    assert!(settlement.0 > 0, "the space owes the peer");
    let attest = live.attest();
    assert_eq!(attest.window, Some(WINDOW));
    assert_eq!(
        attest.public_args,
        [
            (AGENT, INSTANCE).encode(),
            (PEER, CURRENCY, c_prev).encode()
        ]
        .concat()
    );
    assert_eq!(attest.roots, [cut.root()]);
    let (kernel, _) = cut::kernel_of("window", attest);
    traced(attest, &kernel);

    let again = settle(&cut, settlement.2, &next, |_| {});
    let (settlement, _) = expected(&next);
    assert_eq!(settlement.0, 0);
    assert_eq!(again.output::<Settlement>(), Ok(settlement));
    assert_eq!(settlement.1, CARRIED.seq + 2);
}

/// A carried state that does not open `c_prev` traps the kernel, so no
/// statement is made: another salt, each total, another sequence number,
/// and `c_prev` of another peer or of another currency.
#[test]
fn a_carried_state_that_does_not_open_is_refused() {
    let cut = small();
    let c_prev = CARRIED.commitment(&PEER, CURRENCY);
    let totals = CARRIED.totals;
    let with = |totals: Totals| Carried { totals, ..CARRIED };
    let changes = [
        Carried {
            salt: [0x12; 16],
            ..CARRIED
        },
        with(Totals {
            out_dr: totals.out_dr + 1,
            ..totals
        }),
        with(Totals {
            out_cr: totals.out_cr - 1,
            ..totals
        }),
        with(Totals {
            in_dr: totals.in_dr - 1,
            ..totals
        }),
        with(Totals {
            in_cr: totals.in_cr + 1,
            ..totals
        }),
        Carried {
            seq: CARRIED.seq + 1,
            ..CARRIED
        },
    ];
    for carried in changes {
        let live = settle(&cut, c_prev, &carried, |_| {});
        assert_eq!(
            live.output::<Settlement>(),
            Err(AttestError::Failed),
            "{carried:?}"
        );
    }
    for other in [
        CARRIED.commitment(&[0xB3; 32], CURRENCY),
        CARRIED.commitment(&PEER, CURRENCY + 1),
    ] {
        let live = settle(&cut, other, &CARRIED, |_| {});
        assert_eq!(live.output::<Settlement>(), Err(AttestError::Failed));
    }
}

/// A cut older than the carried state's traps the kernel: a carried state
/// that opens its `c_prev` but whose totals, each in turn, are above the
/// rows', as a later settlement's would be, so no settlement goes back to
/// an earlier cut and states a net the pair already settled.
#[test]
fn an_older_cut_is_refused() {
    let cut = small();
    let rows = ROWS_TOTALS;
    let later = [
        Totals {
            out_dr: rows.out_dr + 1,
            ..CARRIED.totals
        },
        Totals {
            out_cr: rows.out_cr + 1,
            ..CARRIED.totals
        },
        Totals {
            in_dr: rows.in_dr + 1,
            ..CARRIED.totals
        },
        Totals {
            in_cr: rows.in_cr + 1,
            ..CARRIED.totals
        },
    ];
    for totals in later {
        let carried = Carried { totals, ..CARRIED };
        let live = settle(&cut, carried.commitment(&PEER, CURRENCY), &carried, |_| {});
        assert_eq!(
            live.output::<Settlement>(),
            Err(AttestError::Failed),
            "{totals:?}"
        );
    }
}

/// Rows the cut does not prove trap the prologue or the view: a row's value
/// tampered; a row the agent's root holds, claimed absent; the agent's root
/// with no row in the representative's tree (it missed the close); and a
/// key the read did not name, which the view refuses.
#[test]
fn rows_off_the_cut_are_refused() {
    let cut = small();
    let c_prev = CARRIED.commitment(&PEER, CURRENCY);
    let refused =
        |serve: &dyn Fn(&mut Served)| settle(&cut, c_prev, &CARRIED, serve).output::<Settlement>();
    assert_eq!(
        refused(&|served| {
            let (_, value) = served.rows[0].1.as_mut().unwrap();
            let last = value.len() - 1;
            value[last] ^= 1;
        }),
        Err(AttestError::Failed),
        "a tampered row"
    );
    assert_eq!(
        refused(&|served| served.rows[0].1 = None),
        Err(AttestError::Failed),
        "a present row claimed absent"
    );
    let missed = cut_of(256, 8, false);
    assert_eq!(
        settle(&missed, c_prev, &CARRIED, |_| {}).output::<Settlement>(),
        Err(AttestError::Failed),
        "the agent's row missing from the representative's"
    );
    // The kernel reads both rows; the read names the outgoing one alone.
    let outgoing = PseudoAccount::outgoing_to(AGGREGATE, PEER, CURRENCY).id().0;
    let live = read_live(
        &cut,
        "window",
        "settle_reading",
        &[arguments(c_prev, &CARRIED), vec![outgoing].encode()].concat(),
        |_| {},
    );
    assert_eq!(
        live.output::<Settlement>(),
        Err(AttestError::Failed),
        "a key outside the read set"
    );
}

/// The window's kernel re-runs from its attest to the window's statement,
/// proves over its shape cut at class 1's budgets, each segment at the
/// first class that holds it, and verifies as a chain against its program,
/// its io-hash over its public arguments, its output and its root.
#[test]
fn the_window_proves_and_verifies_over_its_shape() {
    let started = Instant::now();
    let live = honest(&large());
    let attest = live.attest();
    let (blob, record) = cut::kernel_of("window", attest);
    let trace = traced(attest, &blob);
    let program = common::kernel_program(&blob, &record, &SEGMENT);
    let shape = &program.shape;
    eprintln!(
        "window: {} steps, {} compressions, witness input {} B, kernel {} B, chips {:#x} ({} of \
         {}) ({:.1}s)",
        trace.side_note.steps.len(),
        trace.side_note.blake2b_calls.len(),
        attest.witness_input.len(),
        blob.len(),
        shape.components,
        shape.components.count_ones(),
        vos_pvm_proof::chip_idx::COUNT,
        started.elapsed().as_secs_f64(),
    );
    for (index, class) in shape.classes.iter().enumerate() {
        eprintln!(
            "class {index}: 2^{} steps, {} pages, log sizes {:?}",
            class.log_steps, class.pages, class.log_sizes
        );
    }

    let started = Instant::now();
    let segments = prove_kernel(&trace.side_note, shape, CUT, &SEGMENT).expect("proves");
    eprintln!(
        "proved {} segments in {:.1}s",
        segments.len(),
        started.elapsed().as_secs_f64(),
    );
    for (index, segment) in segments.iter().enumerate() {
        assert_eq!(
            program_commitment_of_proof(&segment.proof),
            program.preprocessed_roots[segment.class]
        );
        eprintln!(
            "segment {index}: steps {:?} ({}), class {}",
            segment.steps,
            segment.steps.1 - segment.steps.0,
            segment.class
        );
    }
    let first = segments[0].proof.clone();
    assert_eq!(
        verify_kernel_segment(first, &program).unwrap(),
        segments[0].class
    );
    let proofs: Vec<Proof> = segments.into_iter().map(|segment| segment.proof).collect();
    let entry = KernelEntry::of(&program, &blob).expect("the program's blob");
    let registers = verify_kernel_chain(proofs, &program, &entry).expect("verifies");
    let io_hash: Vec<u8> = registers[9..13]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    assert_eq!(io_hash, trace.io_hash);
    let roots: Vec<vos_pvm_precompiles::RootRead> = attest
        .roots
        .iter()
        .map(|root| vos_pvm_precompiles::RootRead {
            kind: vos_pvm_precompiles::RootKind::try_from(root.kind as u8).unwrap(),
            space: root.space.0,
            window: root.window,
            root: root.root,
        })
        .collect();
    assert_eq!(
        io_hash,
        vos_pvm_precompiles::compute_io_hash(&attest.public_args, &attest.output, &roots)
    );
}

/// The window's kernel's leaves and folds: its program finalized with its
/// leaf circuits; its run cut at class 1's budgets into three segments
/// (two class-1 windows of the 32k cut, then the halt at class 0), each
/// verified in its class's leaf as natively, the leaf within the padded
/// shape, proved and verified. The first states the entry, the last the
/// halt and the run's io-hash; each segment's exit digest is the next's
/// entry digest. A class-1 leaf proves in at most 4 GiB of heap and in at
/// most the time of its segment's proving.
///
/// The leaves fold: the first two, then their fold with the third, the
/// root of the whole run, each within the padded shape, proved and
/// verified against the fold circuit's hash. The root proves in at most
/// 4 GiB of heap, as a leaf, and in at most the time of a class-1
/// segment's proving.
#[test]
fn the_windows_leaves_and_folds_prove_and_verify() {
    let live = honest(&large());
    let attest = live.attest();
    let (blob, record) = cut::kernel_of("window", attest);
    let trace = traced(attest, &blob);
    let ((program, entry), elapsed, peak) = common::measured(|| {
        vos_pvm_recair::leaf::kernel_program(
            &blob,
            &record,
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .expect("the kernel's program")
    });
    eprintln!(
        "the program with its {} leaf circuits in {:.1}s, its peak heap {peak} MiB, id {:02x?}",
        program.shape.classes.len(),
        elapsed.as_secs_f64(),
        &program.id().to_bytes()[..8]
    );
    let class = &program.shape.classes[CUT];
    let bounds = segment_bounds_budgeted(
        &trace.side_note,
        1 << class.log_steps,
        usize::from(class.pages),
    );
    assert_eq!(bounds.len(), 3, "{bounds:?}");
    let fold = vos_pvm_recair::fold::FoldCircuit::new();
    let (word, elapsed, _) = common::measured(|| fold.hash());
    eprintln!("the fold circuit's hash in {:.1}s", elapsed.as_secs_f64());
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let mut leaves = Vec::new();
    let mut slowest = std::time::Duration::ZERO;
    for (position, &bound) in bounds.iter().enumerate() {
        let ((class, proof), segment, segment_peak) =
            common::measured(|| cut::prove_at_first_class(&mut cursor, bound, &program));
        let leaf = common::prove_leaf(&program, &entry, class, &proof, position as u32, word);
        eprintln!(
            "segment {position} ({bound:?}, class {class}) proved in {:.2}s, its peak heap \
             {segment_peak} MiB; its leaf: {:?} rows ({:?} finalized), proved in {:.2}s ({:.2}× \
             the segment's), its peak heap {} MiB",
            segment.as_secs_f64(),
            leaf.rows,
            leaf.finalized,
            leaf.proving.as_secs_f64(),
            leaf.proving.as_secs_f64() / segment.as_secs_f64(),
            leaf.peak_mib,
        );
        if class == CUT {
            assert!(leaf.peak_mib <= 4 << 10, "{} MiB", leaf.peak_mib);
            assert!(
                leaf.proving <= segment,
                "{:?} against {segment:?}",
                leaf.proving
            );
            slowest = slowest.max(segment);
        }
        leaves.push((class, leaf));
    }
    let outputs: Vec<_> = leaves
        .iter()
        .map(|(class, leaf)| (*class, leaf.node.output))
        .collect();
    let [(first_class, first), (_, second), (_, end)] = outputs[..] else {
        unreachable!()
    };
    assert_eq!(first_class, CUT, "the first segment is a class-1 window");
    assert!(first.entry && !first.halt);
    assert!(!second.entry && !second.halt);
    assert!(!end.entry && end.halt);
    assert_eq!(first.exit_digest, second.entry_digest);
    assert_eq!(second.exit_digest, end.entry_digest);

    let head = common::prove_fold(&fold, &program, &leaves[0].1, &leaves[1].1, word);
    let root = common::prove_fold(&fold, &program, &head, &leaves[2].1, word);
    for (name, run) in [
        ("the fold of leaves 0 and 1", &head),
        ("the fold of that and leaf 2", &root),
    ] {
        eprintln!(
            "{name}: {:?} rows ({:?} finalized), proved in {:.2}s, its peak heap {} MiB",
            run.rows,
            run.finalized,
            run.proving.as_secs_f64(),
            run.peak_mib,
        );
    }
    assert!(root.peak_mib <= 4 << 10, "{} MiB", root.peak_mib);
    assert!(
        root.proving <= slowest,
        "{:?} against {slowest:?}",
        root.proving
    );
    let root = root.node.output;
    assert_eq!((root.first, root.last), (0, 2));
    assert!(root.entry && root.halt, "the whole run");
    assert_eq!(root.entry_digest, first.entry_digest);
    assert_eq!(root.program.0, program.id().0);
    assert_eq!(root.fold_word, word);
    assert_eq!(root.io_hash, trace.io_hash);
    assert_eq!(end.io_hash, trace.io_hash);
}

/// The window end to end on the million-row map: its run, at most 1M
/// steps, its space path within a fifth of spike 6.0a's; proved whole,
/// folded to one root and wrapped under `format::WRAP` and masked under 39; and
/// its statement (the reader's agent and instance, the peer, the currency
/// and `c_prev` public, `(net, seq, c_new)` its output, `S_w` its root)
/// judged at the model venue, which pins the kernel's program and holds
/// `S_w` anchored by the space's founding key.
///
/// Accepted, and then refused as a repeat (6). Then each case, a venue or a
/// statement that differs in one thing, and the check that refuses it:
/// - **an unanchored root** (5): a venue that holds no anchor of the space;
/// - **another window:** the root claimed at the window before, which the
///   venue does not hold (5); and, at a venue whose space anchored that
///   root there too, the io-hash, which binds the root's window: the
///   proof's words (0x108);
/// - **another space:** the statement claiming a space its root is not of,
///   the space rule (4); and its root claimed of a second space of the
///   founder's, anchored there: the io-hash, which binds the root's space
///   (0x108);
/// - **a missing representative row:** `S_w` anchored over a
///   representative's tree without the agent's row, so the statement's
///   `S_w` is not the anchored root: unanchored (5). The served row's
///   absence itself traps the prologue ([`rows_off_the_cut_are_refused`]);
/// - **a tampered output:** the net a tampered row would give, against the
///   proof's words (0x108); the tampered row itself traps the prologue;
/// - **a venue mismatch:** the anchor digest binds the venue, so an anchor
///   signed for this venue is refused at another (`Signature`) and the root
///   is unanchored there (5). The kernel is not venue-bound: code 7 is the
///   golden fixtures';
/// - **a window outside the migration range:** the space migrated away from
///   the statement's window before it was anchored, so the anchor is
///   refused (`Window`) and the root unanchored (5).
///
/// A key outside the read set traps the view, so no statement is made of
/// it ([`rows_off_the_cut_are_refused`]).
#[test]
fn the_window_is_stated_at_the_model_venue() {
    let cut = large();
    let live = honest(&cut);
    let attest = live.attest().clone();
    let path_compressions = cut::path_compressions(&live.served) as f64;
    let path_bytes = cut::path_bytes(&live.served) as f64;
    let representative = cut.representative.clone();
    let missing = cut::Representative::new(AGENT, WINDOW, cut.agent_root, AGENTS, false);
    drop((live, cut));
    let (blob, record) = cut::kernel_of("window", &attest);
    let trace = traced(&attest, &blob);
    let steps = trace.side_note.steps.len();
    eprintln!(
        "the window: {steps} steps, {} compressions, witness input {} B; the path: {} \
         compressions (+1 for S_w), {path_bytes} B",
        trace.side_note.blake2b_calls.len(),
        attest.witness_input.len(),
        path_compressions - 1.0,
    );
    assert!(steps <= 1_000_000, "{steps} steps");
    assert!(
        path_compressions <= SPIKE_PATH_COMPRESSIONS * 1.2,
        "{path_compressions}"
    );
    assert!(path_bytes <= SPIKE_PATH_BYTES * 1.2, "{path_bytes}");

    let started = Instant::now();
    let (program, root, segments, mut totals) =
        cut::prove_whole("the window", &blob, &record, &trace, CUT);
    drop(trace);
    let (_, _, proof) = common::wrap_root("the window", &program, &root, &mut totals.wrap);
    totals.report("the window");
    eprintln!(
        "the window: {segments} segments, proved end to end in {:.0}s",
        started.elapsed().as_secs_f64()
    );

    let program = ProgramId(program.id().0.map(|word| word.0));
    let statement = Statement {
        format: masked::FORMAT,
        program,
        space: space(),
        public_args: attest.public_args.clone(),
        output: attest.output.clone(),
        roots: attest.roots.clone(),
    };
    let root = statement.roots[0];
    assert_eq!(
        root.root,
        space_root(&space(), WINDOW, &representative.root)
    );
    let venue = |id: VenueId| {
        let venue = Venue::new(id, &[genesis(1), genesis(2)]);
        venue.venue.pin(Pin {
            program,
            venue_bound: false,
        });
        venue
    };
    let anchored = || {
        let venue = venue(VENUE);
        venue.anchor(&root).expect("anchored");
        venue
    };
    let code = |venue: &Venue, statement: &Statement| {
        vos_venue::code(&venue.venue.submit(statement, &proof))
    };
    // The proof refused against the words the statement makes.
    const WORDS: u32 = 0x108;

    let accepting = anchored();
    assert_eq!(code(&accepting, &statement), 0, "accepted");
    assert_eq!(code(&accepting, &statement), 6, "a repeat");

    assert_eq!(code(&venue(VENUE), &statement), 5, "an unanchored root");

    let before = RootRead {
        window: WINDOW - 1,
        ..root
    };
    let at_another_window = Statement {
        roots: vec![before],
        ..statement.clone()
    };
    assert_eq!(code(&anchored(), &at_another_window), 5, "another window");
    let both = venue(VENUE);
    both.anchor(&before).expect("anchored at the window before");
    both.anchor(&root).expect("anchored");
    assert_eq!(
        code(&both, &at_another_window),
        WORDS,
        "another window, anchored"
    );

    let second = space_id(&genesis(2));
    let claimed = Statement {
        space: second,
        ..statement.clone()
    };
    assert_eq!(code(&anchored(), &claimed), 4, "another space");
    let of_second = RootRead {
        space: second,
        ..root
    };
    let moved = Statement {
        space: second,
        roots: vec![of_second],
        ..statement.clone()
    };
    let there = anchored();
    there
        .anchor(&of_second)
        .expect("anchored in the second space");
    assert_eq!(code(&there, &moved), WORDS, "another space, anchored");

    let without = venue(VENUE);
    without
        .anchor(&RootRead {
            root: space_root(&space(), WINDOW, &missing.root),
            ..root
        })
        .expect("anchored without the agent's row");
    assert_eq!(
        code(&without, &statement),
        5,
        "a missing representative row"
    );

    let (net, seq, c_new) = vos_wire::Decode::decode(&statement.output)
        .map(|(settlement, _): (Settlement, _)| settlement)
        .expect("the settlement");
    let tampered = Statement {
        output: (net + 1, seq, c_new).encode(),
        ..statement.clone()
    };
    assert_eq!(code(&anchored(), &tampered), WORDS, "a tampered output");

    let elsewhere = venue(VenueId([0x7f; 32]));
    assert_eq!(
        elsewhere.anchor_for(&root, VENUE),
        Err(AnchorRefusal::Signature),
        "an anchor signed for another venue"
    );
    assert_eq!(code(&elsewhere, &statement), 5, "a venue mismatch");

    let migrated = venue(VENUE);
    migrated.set_now(cut::CLOCK.boundary(WINDOW - 2).unwrap() + 1);
    assert_eq!(
        migrated.venue.migrate(&Migrate {
            space: space(),
            from: VENUE,
            to: VenueId([0x7f; 32]),
            from_window: WINDOW,
        }),
        Ok(())
    );
    migrated.set_now(Venue::closed());
    assert_eq!(
        migrated.anchor(&root),
        Err(AnchorRefusal::Window),
        "an anchor past the migration"
    );
    assert_eq!(
        code(&migrated, &statement),
        5,
        "a window outside the migration range"
    );
}
