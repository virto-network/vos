//! Reads at a window's cut through the SDK's prologue (`&self` attestable
//! methods, `vos_sdk::runtime::verify_served`): the `accounts` test actor's
//! kernels run live on the testkit, at a window's cut, on rows served from
//! an agent's map of a million cipher-clerk accounts under a
//! representative's tree of 1,024 agents, each with its roots of three
//! windows; and re-traced by the prover from their attests.
//!
//! Measured against spike 6.0a's prototype: steps, compressions and
//! witness bytes, per row and for the space path; and the sixteen-row
//! kernel's segments at the 32k class, with those its pages cut short.

use std::cell::Cell;
use std::sync::OnceLock;
use std::time::Instant;

use cipher_clerk::codec;
use cipher_clerk::conventions::PseudoAccount;
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::types::{Account, Layer};
use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
use vos_pvm_proof::segment::segment_bounds_budgeted;
use vos_testkit::Testkit;
use vos_testkit::programs::{derived, method, table_tag};
use vos_tree::{BatchProof, Blake2b, Hash, Hasher, Leaf, MemStore};
use vos_wire::abi::cap::Target;
use vos_wire::ids::{AgentId, InstanceId, MapId, Principal, ProgramHash, RequestId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::PendingRead;
use vos_wire::result::{Attest, KernelReturn, Outcome};
use vos_wire::served::{Served, representative_row};
use vos_wire::vos_anchor::RootKind;
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

const GAS: u64 = 1 << 32;
const ROWS: usize = 1_000_000;
const AGENTS: u32 = 1_024;
const SPACE: SpaceId = SpaceId([0xA1; 32]);
const PEER: [u8; 32] = [0xB2; 32];
const OPERATOR: [u8; 32] = [0x0C; 32];
const CURRENCY: u32 = 840;
/// A window of today at 10-minute windows, as 6.0a's.
const WINDOW: u64 = 2_966_000;
const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 600_000,
};
const AGENT: AgentId = AgentId(517);
const INSTANCE: InstanceId = InstanceId(9);
/// The 32k class's cut, as 6.0a cut its runs.
const LOG_STEPS: u32 = 15;
const PAGES: usize = 8;

/// Spike 6.0a's measured costs [measured, slice-6-progress.md].
const SPIKE_ROW_COMPRESSIONS: f64 = 19.07 + 1.0;
const SPIKE_ROW_BYTES: f64 = 842.0;
const SPIKE_PATH_COMPRESSIONS: f64 = 15.0;
const SPIKE_PATH_BYTES: f64 = 590.0;
const SPIKE_SIXTEEN_STEPS: f64 = 205_841.0;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
    }
}

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

/// A tree over `writes`, salted from `seed`, into `store`: its root.
fn put(store: &mut MemStore, seed: &[u8; 32], writes: &[(Vec<u8>, Vec<u8>)]) -> Hash {
    let mut leaves: Vec<(Vec<u8>, Option<Leaf>)> = writes
        .iter()
        .map(|(key, value)| (key.clone(), Some(Leaf::salted(&Blake2b, seed, key, value))))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let mut root = [0; 32];
    for batch in leaves.chunks(1 << 16) {
        root = vos_tree::update(&Blake2b, store, batch).expect("the tree updates");
    }
    root
}

/// The agent's map, the representative's tree, and the path of the
/// agent's root in it.
struct Fixture {
    agent: MemStore,
    agent_root: Hash,
    rep_root: Hash,
    rep_salt: [u8; 16],
    space_path: Vec<u8>,
    accounts: Vec<Account<Value>>,
    seed: [u8; 32],
}

impl Fixture {
    /// A map of `rows` accounts, the sixteen among them, under a
    /// representative's tree of `agents` agents' roots at three windows.
    fn new(rows: usize, agents: u32) -> Self {
        let accounts = accounts();
        let width = codec::to_bytes(&accounts[0]).len();
        let mut rng = Rng(0x5eed_0000 + rows as u64);
        let mut writes: Vec<(Vec<u8>, Vec<u8>)> = (accounts.len()..rows)
            .map(|_| {
                let (mut id, mut bytes) = ([0u8; 32], vec![0u8; width]);
                rng.fill(&mut id);
                rng.fill(&mut bytes);
                (row(&id), bytes.encode())
            })
            .collect();
        writes.extend(
            accounts
                .iter()
                .map(|account| (row(&account.id.0), value(account))),
        );
        let seed = [2u8; 32];
        let mut agent = MemStore::default();
        let agent_root = put(&mut agent, &seed, &writes);
        let rep_seed = [7u8; 32];
        let mut rep_writes = Vec::with_capacity(3 * agents as usize);
        let others = (1..=agents).filter(|other| *other != AGENT.0);
        for other in others.chain([AGENT.0]) {
            for window in WINDOW - 2..=WINDOW {
                let mut root = [0u8; 32];
                if other == AGENT.0 && window == WINDOW {
                    root = agent_root;
                } else {
                    rng.fill(&mut root);
                }
                let key = representative_row(AgentId(other), RootKind::Space, window);
                rep_writes.push((key, root.to_vec()));
            }
        }
        let mut rep = MemStore::default();
        let rep_root = put(&mut rep, &rep_seed, &rep_writes);
        let key = representative_row(AGENT, RootKind::Space, WINDOW);
        let space_path = BatchProof::generate(&rep, std::slice::from_ref(&key))
            .expect("proves")
            .encode();
        Self {
            agent,
            agent_root,
            rep_root,
            rep_salt: vos_tree::salt(&Blake2b, &rep_seed, &key),
            space_path,
            accounts,
            seed,
        }
    }

    /// The rows `read` names served, with their proof and the path.
    fn served(&self, read: &PendingRead) -> Served {
        let values: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = self
            .accounts
            .iter()
            .map(|account| (row(&account.id.0), value(account)))
            .collect();
        Served {
            space: SPACE,
            window: WINDOW,
            agent: AGENT,
            instance: read.instance,
            agent_root: self.agent_root,
            rep_root: self.rep_root,
            rep_salt: self.rep_salt,
            space_path: self.space_path.clone(),
            rows: read
                .rows
                .iter()
                .map(|key| {
                    let held = values
                        .get(key)
                        .map(|value| (vos_tree::salt(&Blake2b, &self.seed, key), value.clone()));
                    (key.clone(), held)
                })
                .collect(),
            rows_proof: BatchProof::generate(&self.agent, &read.rows)
                .expect("proves")
                .encode(),
        }
    }
}

fn large() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let started = Instant::now();
        let fixture = Fixture::new(ROWS, AGENTS);
        eprintln!(
            "the fixture: {ROWS} rows, {AGENTS} agents' roots, built in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        fixture
    })
}

/// A live read at window `WINDOW`'s cut through the accounts actor's
/// workflow `workflow` on `arguments`, its rows served from `fixture`: the
/// attest its resumed step recorded, the served rows, and its kernel.
fn read_live(fixture: &Fixture, workflow: &str, arguments: Vec<u8>) -> (Attest, Served, Vec<u8>) {
    let derived = derived("accounts");
    let mut kit = Testkit::new(AGENT);
    kit.install_derived_in((SPACE, CLOCK), Target::Vos, INSTANCE, &derived, &[])
        .expect("installs");
    let time = CLOCK.boundary(WINDOW - 1).unwrap() + 5;
    kit.batch(time, [0; 32]);
    let start = kit.command(
        Principal::Client([1; 32]),
        INSTANCE,
        method(&derived.actor, workflow),
        &arguments,
    );
    let Outcome::Started(id) = start.outcome else {
        panic!("not started: {:?}", start.outcome);
    };
    kit.due(time, id);
    let request = RequestId {
        workflow: id,
        awaits: 0,
    };
    let read = PendingRead::decode(kit.get(&keys::request(WINDOW, request)).expect("asked"))
        .unwrap()
        .0;
    let served = fixture.served(&read);
    kit.batch(time + 1, [0; 32]);
    let step = kit.resume_read(WINDOW, request, Some(served.encode()));
    assert!(
        matches!(step.outcome, Outcome::Done(_)),
        "{:?}",
        step.outcome
    );
    let attest = step.attests.into_iter().next().expect("an attest");
    let kernel = derived
        .kernels
        .iter()
        .map(|(_, kernel)| kernel)
        .find(|kernel| ProgramHash::of(kernel) == attest.program)
        .expect("the derived kernel")
        .clone();
    (attest, served, kernel)
}

/// The kernel re-traced from its attest: live ≡ traced, its return its
/// attest's parts and its io-hash theirs.
fn traced(attest: &Attest, kernel: &[u8]) -> KernelTrace {
    let trace = trace_kernel(kernel, &attest.witness_input, GAS).expect("re-runs");
    let parts = KernelReturn::decode(&trace.output).expect("its parts").0;
    assert_eq!(
        parts,
        KernelReturn {
            public_args: attest.public_args.clone(),
            output: attest.output.clone(),
            roots: attest.roots.clone(),
        }
    );
    assert_eq!(trace.io_hash, parts.io_hash());
    let read: usize = trace.reads.iter().map(|read| read.count).sum();
    assert_eq!(read, attest.witness_input.len(), "it reads its input whole");
    trace
}

/// live ≡ traced with a served input: a read at a cut's kernel, run live
/// on the testkit, and the prover's re-run from its attest end with the
/// same statement parts and io-hash, the re-run reading its witness input,
/// the arguments then the served rows, whole.
#[test]
fn a_read_at_a_cut_re_runs_as_its_live_run() {
    let fixture = Fixture::new(256, 8);
    let ids: Vec<[u8; 16]> = fixture
        .accounts
        .iter()
        .map(|account| account.id.0)
        .collect();
    let (attest, _, kernel) = read_live(&fixture, "window_at_cut", ids.encode());
    assert_eq!(attest.window, Some(WINDOW));
    assert_eq!(attest.public_args, (AGENT, INSTANCE).encode());
    traced(&attest, &kernel);
}

/// A compression counted for every block a hash takes.
struct Counting(Cell<u64>);

impl Hasher for Counting {
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash {
        let len = tag.len() + parts.iter().map(|part| part.len()).sum::<usize>();
        self.0.set(self.0.get() + len.div_ceil(128).max(1) as u64);
        Blake2b.hash(tag, parts)
    }
}

/// The compressions of the space path's check, its leaf's value commitment
/// included, and of `S_w`.
fn path_compressions(served: &Served) -> u64 {
    let counting = Counting(Cell::new(0));
    let row = representative_row(served.agent, RootKind::Space, served.window);
    let commitment = vos_tree::value_hash(&counting, &served.rep_salt, &served.agent_root);
    vos_tree::verify_encoded(
        &counting,
        &served.space_path,
        &served.rep_root,
        &[(row.as_slice(), Some(commitment))],
    )
    .unwrap();
    counting.0.get() + 1
}

/// The costs of reads at a cut on the million-row map: one row (`holds`)
/// and sixteen (`window`), each run live and re-traced. A row's
/// compressions and witness bytes are the sixteen rows' less the one's,
/// over fifteen; the path's, its check's and `S_w`'s, and the bytes of the
/// path, the leaf's salt and the two roots it joins; the sixteen-row
/// prologue's steps, the kernel read through its view or not. Each within a
/// tenth of spike 6.0a's, a row's compressions with the one its view's
/// read hashes the key with; the sixteen-row kernel's segments at the 32k
/// class, those its eight pages cut short, reported.
#[test]
fn reads_at_a_cut_measure() {
    let fixture = large();
    let ids: Vec<[u8; 16]> = fixture
        .accounts
        .iter()
        .map(|account| account.id.0)
        .collect();
    let (one, one_served, one_kernel) =
        read_live(fixture, "holds_at_cut", (1_000u64, ids[0]).encode());
    let (sixteen, sixteen_served, sixteen_kernel) =
        read_live(fixture, "window_at_cut", ids.encode());
    let one_trace = traced(&one, &one_kernel);
    let sixteen_trace = traced(&sixteen, &sixteen_kernel);
    let steps = |trace: &KernelTrace| trace.side_note.steps.len();
    let compressions = |trace: &KernelTrace| trace.side_note.blake2b_calls.len();
    let row_compressions = (compressions(&sixteen_trace) - compressions(&one_trace)) as f64 / 15.0;
    let row_bytes = (sixteen.witness_input.len() - one.witness_input.len()) as f64 / 15.0;
    let row_steps = (steps(&sixteen_trace) - steps(&one_trace)) as f64 / 15.0;
    let path_compressions = path_compressions(&one_served) as f64;
    let path_bytes = (one_served.space_path.encode().len() + 16 + 32 + 32) as f64;
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
        let (attest, _, kernel) =
            read_live(fixture, "probe_at_cut", (ids.clone(), lookups).encode());
        steps(&traced(&attest, &kernel))
    };
    let (bare, looked) = (probe(false), probe(true));
    eprintln!(
        "sixteen rows: the prologue alone {bare} steps; the view's reads and the body {} more, \
         {:.0} a row",
        looked - bare,
        (looked - bare) as f64 / 16.0
    );
    let within = |measured: f64, spike: f64| measured <= spike * 1.1;
    assert!(
        within(row_compressions, SPIKE_ROW_COMPRESSIONS),
        "{row_compressions}"
    );
    assert!(within(row_bytes, SPIKE_ROW_BYTES), "{row_bytes}");
    assert!(
        within(path_compressions, SPIKE_PATH_COMPRESSIONS),
        "{path_compressions}"
    );
    assert!(within(path_bytes, SPIKE_PATH_BYTES), "{path_bytes}");
    // The spike's kernel read its rows by position; the view reads each by
    // its key, hashing it under the map's transform: the prologue, the
    // spike's cost, is the run with no read.
    assert!(within(bare as f64, SPIKE_SIXTEEN_STEPS), "{bare}");
}
