//! Reads at a window's cut through the SDK's prologue (`&self` attestable
//! methods, `vos_sdk::runtime::verify_served`): the `accounts` test actor's
//! kernels run live on the testkit, at a window's cut, on rows served from
//! an agent's map of a million cipher-clerk accounts under a
//! representative's tree of 1,024 agents, each with its roots of three
//! windows; and re-traced by the prover from their attests.
//!
//! Measured against the budgets (`proving.md` §7): steps, compressions and
//! witness bytes, per row and for the space path; and the sixteen-row
//! kernel's segments at the 32k class, with those its pages cut short.

use std::sync::OnceLock;
use std::time::Instant;

use cipher_clerk::codec;
use cipher_clerk::conventions::PseudoAccount;
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::types::{Account, Layer};
use vos_pvm_proof::kernel::KernelTrace;
use vos_pvm_proof::segment::segment_bounds_budgeted;
use vos_testkit::programs::table_tag;
use vos_wire::ids::MapId;
use vos_wire::keys::{self, Transform};
use vos_wire::result::Attest;
use vos_wire::served::Served;
use vos_wire::{Encode, SpaceId};

use crate::cut::{self, AGENT, AGENTS, Cut, INSTANCE, ROWS, Rng, WINDOW, read_live, traced};

const SPACE: SpaceId = SpaceId([0xA1; 32]);
const PEER: [u8; 32] = [0xB2; 32];
const OPERATOR: [u8; 32] = [0x0C; 32];
const CURRENCY: u32 = 840;
/// The 32k class's cut, as the budgets were measured at.
const LOG_STEPS: u32 = 15;
const PAGES: usize = 8;

/// The budgets: a prototype's costs of the reads (`proving.md` §7).
const BUDGET_ROW_COMPRESSIONS: f64 = 19.07 + 1.0;
const BUDGET_ROW_BYTES: f64 = 842.0;
const BUDGET_PATH_COMPRESSIONS: f64 = 15.0;
const BUDGET_PATH_BYTES: f64 = 590.0;
const BUDGET_SIXTEEN_STEPS: f64 = 205_841.0;

/// Sixteen pseudo-accounts, as the window kernel's: eight journals'
/// outgoing and incoming accounts.
fn accounts() -> Vec<Account<Value>> {
    (0..8u64)
        .flat_map(|k| {
            let mut journal = [0u8; 16];
            journal[..8].copy_from_slice(&(0x4a4f_0000 + k).to_be_bytes());
            journal[8] = 0x5a;
            let journal = JournalId(journal);
            let n = k + 1;
            let at = |pseudo: PseudoAccount, dr: u64, cr: u64| {
                let mut account: Account<Value> = pseudo.open(OPERATOR);
                let settled = &mut account.balances[Layer::Settled.as_index()];
                settled.dr = Value(dr);
                settled.cr = Value(cr);
                account.timestamp = 1_000 + n;
                account
            };
            [
                at(
                    PseudoAccount::outgoing_to(journal, PEER, CURRENCY),
                    0,
                    1_250 * n + 3,
                ),
                at(
                    PseudoAccount::incoming_from(journal, PEER, CURRENCY),
                    820 * n,
                    0,
                ),
            ]
        })
        .collect()
}

/// The accounts actor's committed map.
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

/// A map of `rows` accounts, the sixteen among them, under a
/// representative's tree of `agents` agents' roots at three windows.
fn cut_of(rows: usize, agents: u32) -> Cut {
    let accounts = accounts();
    let width = codec::to_bytes(&accounts[0]).len();
    let mut rng = Rng(0x5eed_0000 + rows as u64);
    let others = (accounts.len()..rows)
        .map(|_| {
            let (mut id, mut bytes) = ([0u8; 32], vec![0u8; width]);
            rng.fill(&mut id);
            rng.fill(&mut bytes);
            (row(&id), bytes.encode())
        })
        .collect();
    let known = accounts
        .iter()
        .map(|account| (row(&account.id.0), value(account)))
        .collect();
    Cut::new(SPACE, known, others, agents, true)
}

fn large() -> &'static Cut {
    static CUT: OnceLock<Cut> = OnceLock::new();
    CUT.get_or_init(|| {
        let started = Instant::now();
        let cut = cut_of(ROWS, AGENTS);
        eprintln!(
            "the fixture: {ROWS} rows, {AGENTS} agents' roots, built in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        cut
    })
}

/// A live read at window `WINDOW`'s cut through the accounts actor's
/// workflow `workflow` on `arguments`, its rows served from `cut`: the
/// attest its resumed step recorded, the served rows, and its kernel.
fn read(cut: &Cut, workflow: &str, arguments: Vec<u8>) -> (Attest, Served, Vec<u8>) {
    let live = read_live(cut, "accounts", workflow, &arguments, |_| {});
    let attest = live.attest().clone();
    let (kernel, _) = cut::kernel_of("accounts", &attest);
    (attest, live.served, kernel)
}

/// live ≡ traced with a served input: a read at a cut's kernel, run live
/// on the testkit, and the prover's re-run from its attest end with the
/// same statement parts and io-hash, the re-run reading its witness input,
/// the arguments then the served rows, whole.
#[test]
fn a_read_at_a_cut_re_runs_as_its_live_run() {
    let cut = cut_of(256, 8);
    let ids: Vec<[u8; 16]> = accounts().iter().map(|account| account.id.0).collect();
    let (attest, _, kernel) = read(&cut, "window_at_cut", ids.encode());
    assert_eq!(attest.window, Some(WINDOW));
    assert_eq!(attest.public_args, (AGENT, INSTANCE).encode());
    traced(&attest, &kernel);
}

/// The costs of reads at a cut on the million-row map: one row (`holds`)
/// and sixteen (`window`), each run live and re-traced. A row's
/// compressions and witness bytes are the sixteen rows' less the one's,
/// over fifteen; the path's, its check's and `S_w`'s, and the bytes of the
/// path, the leaf's salt and the two roots it joins; the sixteen-row
/// prologue's steps, the kernel read through its view or not. Each within a
/// tenth of its budget, a row's compressions with the one its view's
/// read hashes the key with; the sixteen-row kernel's segments at the 32k
/// class, those its eight pages cut short, reported.
#[test]
fn reads_at_a_cut_measure() {
    let cut = large();
    let ids: Vec<[u8; 16]> = accounts().iter().map(|account| account.id.0).collect();
    let (one, one_served, one_kernel) = read(cut, "holds_at_cut", (1_000u64, ids[0]).encode());
    let (sixteen, sixteen_served, sixteen_kernel) = read(cut, "window_at_cut", ids.encode());
    let one_trace = traced(&one, &one_kernel);
    let sixteen_trace = traced(&sixteen, &sixteen_kernel);
    let steps = |trace: &KernelTrace| trace.side_note.steps.len();
    let compressions = |trace: &KernelTrace| trace.side_note.blake2b_calls.len();
    let row_compressions = (compressions(&sixteen_trace) - compressions(&one_trace)) as f64 / 15.0;
    let row_bytes = (sixteen.witness_input.len() - one.witness_input.len()) as f64 / 15.0;
    let row_steps = (steps(&sixteen_trace) - steps(&one_trace)) as f64 / 15.0;
    let path_compressions = cut::path_compressions(&one_served) as f64;
    let path_bytes = cut::path_bytes(&one_served) as f64;
    let bounds = segment_bounds_budgeted(&sixteen_trace.side_note, 1 << LOG_STEPS, PAGES);
    let short = bounds[..bounds.len() - 1]
        .iter()
        .filter(|(from, to)| to - from < 1 << LOG_STEPS)
        .count();
    eprintln!(
        "one row: {} steps, {} compressions, witness {} B; sixteen rows: {} steps, {} \
         compressions, witness {} B",
        steps(&one_trace),
        compressions(&one_trace),
        one.witness_input.len(),
        steps(&sixteen_trace),
        compressions(&sixteen_trace),
        sixteen.witness_input.len(),
    );
    eprintln!(
        "a row: {row_compressions:.2} compressions, {row_bytes:.0} B, {row_steps:.0} steps; the \
         path: {} compressions (+1 for S_w), {path_bytes} B; served {} B and {} B",
        path_compressions - 1.0,
        one_served.encode().len(),
        sixteen_served.encode().len(),
    );
    eprintln!(
        "sixteen rows at the 32k class: {} segments, {short} of them cut short of 2^{LOG_STEPS} \
         steps by its {PAGES} pages: {:?}",
        bounds.len(),
        bounds
            .iter()
            .map(|(from, to)| to - from)
            .collect::<Vec<_>>(),
    );
    let probe = |lookups: bool| {
        let (attest, _, kernel) = read(cut, "probe_at_cut", (ids.clone(), lookups).encode());
        steps(&traced(&attest, &kernel))
    };
    let (bare, looked) = (probe(false), probe(true));
    eprintln!(
        "sixteen rows: the prologue alone {bare} steps; the view's reads and the body {} more, \
         {:.0} a row",
        looked - bare,
        (looked - bare) as f64 / 16.0
    );
    let within = |measured: f64, budget: f64| measured <= budget * 1.1;
    assert!(
        within(row_compressions, BUDGET_ROW_COMPRESSIONS),
        "{row_compressions}"
    );
    assert!(within(row_bytes, BUDGET_ROW_BYTES), "{row_bytes}");
    assert!(
        within(path_compressions, BUDGET_PATH_COMPRESSIONS),
        "{path_compressions}"
    );
    assert!(within(path_bytes, BUDGET_PATH_BYTES), "{path_bytes}");
    // The prototype's kernel read its rows by position; the view reads each
    // by its key, hashing it under the map's transform: the prologue, the
    // prototype's cost, is the run with no read.
    assert!(within(bare as f64, BUDGET_SIXTEEN_STEPS), "{bare}");
}
