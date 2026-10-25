//! A space at a window's cut, for the tests of reads at it: an agent's
//! committed rows in its tree, a representative's tree of many agents'
//! roots holding the agent's, and the rows a read names served from them
//! (`Served`); a kernel's live run at the cut on the testkit; its whole run
//! proved to one root; and the space founded by one key, registered and
//! anchored at the model venue (`vos-venue`).

use std::collections::BTreeMap;
use std::sync::Arc;

use cipher_clerk::kernel::Value;
use cipher_clerk::types::Account;
use ed25519_dalek::{Signer, SigningKey};
use vos_pvm_final_verifier::masked;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
use vos_pvm_proof::program_id::KernelProgram;
use vos_pvm_proof::segment::{SegmentCursor, segment_bounds_budgeted};
use vos_pvm_proof::{Proof, ProvingError, prove_shaped};
use vos_statement::{ProgramId, Statement};
use vos_testkit::Step;
use vos_testkit::Testkit;
use vos_testkit::programs::{derivation, derived, method, package, table_tag};
use vos_tree::{BatchProof, Blake2b, Hash, Leaf, MemStore};
use vos_venue::{ModelVenue, VenueClient};
use vos_wire::abi::cap::Target;
use vos_wire::abi::{AttestError, Failure};
use vos_wire::batch::Body;
use vos_wire::ids::{AgentId, InstanceId, MapId, Principal, ProgramHash, RequestId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{PendingRead, WorkflowState};
use vos_wire::result::{Attest, KernelReturn, Outcome};
use vos_wire::served::{Served, representative_row};
use vos_wire::vos_anchor::venue::{AnchorRefusal, Anchoring};
use vos_wire::vos_anchor::{
    Anchor, GENESIS_VERSION, RootKind, RootRead, SpaceGenesis, VenueId, space_root,
};
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

use crate::common::{self, NodeRun, Totals};

pub const GAS: u64 = 1 << 32;
/// Windows of 10 minutes from the Unix epoch.
pub const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 600_000,
};
/// A window of today at 10-minute windows.
pub const WINDOW: u64 = 2_966_000;
pub const AGENT: AgentId = AgentId(517);
/// The space's representative, which the agent reports to and hears its
/// close from.
pub const REPRESENTATIVE: AgentId = AgentId(0x0900_0000);
pub const INSTANCE: InstanceId = InstanceId(9);
/// The rows of a map read at scale, and the agents whose roots the
/// representative keeps, at the budgets' scale (`proving.md` §7).
pub const ROWS: usize = 1_000_000;
pub const AGENTS: u32 = 1_024;

/// The budgets: a prototype's costs of the reads (`proving.md` §7): a
/// row's compressions and witness bytes, the space path's (its
/// compressions with `S_w`'s), and the sixteen-row kernel's steps.
pub const BUDGET_ROW_COMPRESSIONS: f64 = 19.07 + 1.0;
pub const BUDGET_ROW_BYTES: f64 = 842.0;
pub const BUDGET_PATH_COMPRESSIONS: f64 = 15.0;
pub const BUDGET_PATH_BYTES: f64 = 590.0;
pub const BUDGET_SIXTEEN_STEPS: f64 = 205_841.0;

/// The committed map of accounts the `accounts` and `window` test actors
/// keep.
fn accounts_map() -> MapId {
    MapId {
        instance: INSTANCE,
        tag: table_tag("accounts"),
        transform: Transform::Hashed,
    }
}

/// An account's full row key in the accounts map, by its id.
pub fn account_row(id: &[u8]) -> Vec<u8> {
    keys::committed(&accounts_map(), &Transform::Hashed.apply(id))
}

/// An account's value as the map stores it: its cipher-clerk encoding,
/// encoded as the SDK encodes a byte vector.
pub fn account_value(account: &Account<Value>) -> Vec<u8> {
    cipher_clerk::codec::to_bytes(account).encode()
}

/// The masked statement of `attest` in `space`, its kernel's program
/// `program`.
pub fn masked_statement(attest: &Attest, program: ProgramId, space: SpaceId) -> Statement {
    Statement {
        format: masked::FORMAT,
        program,
        space,
        public_args: attest.public_args.clone(),
        output: attest.output.clone(),
        roots: attest.roots.clone(),
    }
}

/// splitmix64: the other rows' bytes, reproducible.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
    }
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

/// The representative's side of a cut: its root, the agent's leaf's salt
/// and the path of the agent's row (or of its absence).
#[derive(Clone)]
pub struct Representative {
    pub root: Hash,
    pub salt: [u8; 16],
    pub path: Vec<u8>,
}

impl Representative {
    /// A representative's tree of `agents` agents' roots at windows
    /// `window − 2..=window`, the others random; `agent`'s at `window`
    /// `agent_root`, or, unless `reported`, none.
    pub fn new(agent: AgentId, window: u64, agent_root: Hash, agents: u32, reported: bool) -> Self {
        let seed = [7u8; 32];
        let mut rng = Rng(0x7e9_0000 + u64::from(agents));
        let mut writes = Vec::with_capacity(3 * agents as usize);
        let others = (1..=agents).filter(|other| *other != agent.0);
        for other in others.chain([agent.0]) {
            for at in window - 2..=window {
                let mut root = [0u8; 32];
                rng.fill(&mut root);
                if other == agent.0 && at == window {
                    if !reported {
                        continue;
                    }
                    root = agent_root;
                }
                let key = representative_row(AgentId(other), RootKind::Space, at);
                writes.push((key, root.to_vec()));
            }
        }
        let mut store = MemStore::default();
        let root = put(&mut store, &seed, &writes);
        let key = representative_row(agent, RootKind::Space, window);
        Self {
            root,
            salt: vos_tree::salt(&Blake2b, &seed, &key),
            path: BatchProof::generate(&store, std::slice::from_ref(&key))
                .expect("proves")
                .encode(),
        }
    }
}

/// An agent's committed rows at a window's cut, and the representative's
/// tree holding its root.
pub struct Cut {
    pub space: SpaceId,
    agent_tree: MemStore,
    pub agent_root: Hash,
    seed: [u8; 32],
    /// The rows a read may serve, by key: their stored values.
    known: BTreeMap<Vec<u8>, Vec<u8>>,
    pub representative: Representative,
}

impl Cut {
    /// The agent's tree over `known` and `others` (full row keys and the
    /// values the map stores), in `space` at [`WINDOW`], under a
    /// representative's tree of `agents` agents' roots: [`AGENT`]'s held
    /// unless not `reported`.
    pub fn new(
        space: SpaceId,
        known: Vec<(Vec<u8>, Vec<u8>)>,
        mut others: Vec<(Vec<u8>, Vec<u8>)>,
        agents: u32,
        reported: bool,
    ) -> Self {
        let seed = [2u8; 32];
        others.extend(known.iter().cloned());
        let mut agent_tree = MemStore::default();
        let agent_root = put(&mut agent_tree, &seed, &others);
        drop(others);
        Self {
            space,
            agent_tree,
            agent_root,
            seed,
            known: known.into_iter().collect(),
            representative: Representative::new(AGENT, WINDOW, agent_root, agents, reported),
        }
    }

    /// The rows `read` names served, with their proof and the path.
    pub fn served(&self, read: &PendingRead) -> Served {
        Served {
            space: self.space,
            window: WINDOW,
            agent: AGENT,
            instance: read.instance,
            agent_root: self.agent_root,
            rep_root: self.representative.root,
            rep_salt: self.representative.salt,
            space_path: self.representative.path.clone(),
            rows: read
                .rows
                .iter()
                .map(|key| {
                    let held = self
                        .known
                        .get(key)
                        .map(|value| (vos_tree::salt(&Blake2b, &self.seed, key), value.clone()));
                    (key.clone(), held)
                })
                .collect(),
            rows_proof: BatchProof::generate(&self.agent_tree, &read.rows)
                .expect("proves")
                .encode(),
        }
    }

    /// The space's root at the cut, `S_w`.
    pub fn root(&self) -> RootRead {
        RootRead {
            kind: RootKind::Space,
            space: self.space,
            window: WINDOW,
            root: space_root(&self.space, WINDOW, &self.representative.root),
        }
    }
}

/// A read at the cut of [`WINDOW`]'s, live: the step its served rows
/// resumed, how its workflow ended, and the rows served.
pub struct Live {
    pub step: Step,
    pub ended: Outcome,
    pub served: Served,
}

impl Live {
    /// The attest the step recorded.
    pub fn attest(&self) -> &Attest {
        assert!(
            matches!(self.step.outcome, Outcome::Done(_)),
            "{:?}",
            self.step.outcome
        );
        self.step.attests.first().expect("an attest")
    }

    /// The workflow's output: the read's, or why there is none.
    pub fn output<T: Decode>(&self) -> Result<T, AttestError> {
        match &self.ended {
            Outcome::Done(bytes) => Ok(T::decode(bytes).expect("the read's output").0),
            Outcome::Failed {
                code: Failure::Handler,
                detail,
            } => Err(AttestError::decode(detail).expect("the read's error").0),
            other => panic!("{other:?}"),
        }
    }
}

/// A live read at [`WINDOW`]'s cut through `actor`'s workflow `workflow`
/// on `arguments`, installed at [`INSTANCE`] of [`AGENT`] in `cut`'s space:
/// the window cut, the agent's root reported to the representative, its
/// `Closed` of the window from `cut` applied, and the read's rows served from `cut` and
/// changed by `serve`.
pub fn read_live(
    cut: &Cut,
    actor: &str,
    workflow: &str,
    arguments: &[u8],
    serve: impl FnOnce(&mut Served),
) -> Live {
    let derived = derived(actor);
    let mut kit = Testkit::new(AGENT);
    kit.install_derived_in((cut.space, CLOCK), Target::Vos, INSTANCE, &derived, &[])
        .expect("installs");
    let time = CLOCK.boundary(WINDOW - 1).unwrap() + 5;
    kit.batch(time, [0; 32]);
    let start = kit.command(
        Principal::Client([1; 32]),
        INSTANCE,
        method(&derived.actor, workflow),
        arguments,
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
    let mut served = cut.served(&read);
    serve(&mut served);
    kit.batch(time + 1, [0; 32]);
    // The window's cut, which the node's apply records once a result
    // crosses its boundary.
    kit.set_row(keys::cut(WINDOW), 0u64.encode());
    kit.report(REPRESENTATIVE, WINDOW, cut.agent_root);
    let representative = &cut.representative;
    kit.message(
        REPRESENTATIVE,
        &Body::Closed {
            window: WINDOW,
            rep_root: representative.root,
            rep_salt: representative.salt,
            space_path: representative.path.clone(),
        },
    );
    assert!(kit.get(&keys::closed(WINDOW)).is_some(), "closed");
    let step = kit.resume_read(WINDOW, request, Some(served.encode()));
    let ended = match kit.workflow(id).expect("the workflow").state {
        WorkflowState::Ended(outcome) => outcome,
        other => panic!("not ended: {other:?}"),
    };
    Live {
        step,
        ended,
        served,
    }
}

/// `actor`'s kernel that made `attest`, and its install's record of it.
pub fn kernel_of(actor: &str, attest: &Attest) -> (Vec<u8>, vos_wire::records::Kernel) {
    let derived = derived(actor);
    let install = derivation(&package(actor), &derived);
    let blob = derived
        .kernels
        .iter()
        .map(|(_, kernel)| kernel)
        .find(|kernel| ProgramHash::of(kernel) == attest.program)
        .expect("the derived kernel")
        .clone();
    let record = install
        .kernels
        .iter()
        .find(|kernel| kernel.program == attest.program)
        .expect("its install's record")
        .clone();
    (blob, record)
}

/// The kernel re-traced from its attest: live ≡ traced, its return its
/// attest's parts and its io-hash theirs, its witness input read whole.
pub fn traced(attest: &Attest, kernel: &[u8]) -> KernelTrace {
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

/// A compression counted for every block a hash takes.
struct Counting(std::cell::Cell<u64>);

impl vos_tree::Hasher for Counting {
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash {
        let len = tag.len() + parts.iter().map(|part| part.len()).sum::<usize>();
        self.0.set(self.0.get() + len.div_ceil(128).max(1) as u64);
        Blake2b.hash(tag, parts)
    }
}

/// The compressions of the space path's check, its leaf's value commitment
/// included, and of `S_w`.
pub fn path_compressions(served: &Served) -> u64 {
    let counting = Counting(std::cell::Cell::new(0));
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

/// The bytes of the space path's witness: the path, the leaf's salt and
/// the two roots it joins.
pub fn path_bytes(served: &Served) -> usize {
    served.space_path.encode().len() + 16 + 32 + 32
}

/// Window `[a, b)` of the run proved at the first class of `program`'s
/// shape that holds it, as `prove_kernel` proves it, and the class.
pub fn prove_at_first_class(
    cursor: &mut SegmentCursor<'_>,
    (a, b): (usize, usize),
    program: &KernelProgram,
) -> (usize, Proof) {
    let steps = (b - a).next_power_of_two().trailing_zeros();
    for (class, sizes) in program.shape.classes.iter().enumerate() {
        if steps > u32::from(sizes.log_steps) {
            continue;
        }
        let shape = program.shape.segment(class).unwrap();
        match prove_shaped(&mut cursor.side_note(a, b), &shape, &SEGMENT) {
            Ok(proof) => return (class, proof),
            Err(ProvingError::Shape { .. }) => continue,
            Err(error) => panic!("{error}"),
        }
    }
    panic!("no class holds [{a}, {b})")
}

/// `trace`, a whole run of the kernel `blob` (`record` its install's),
/// proved end to end: cut at class `cut`'s budgets, every segment proved in
/// its class and verified in its leaf, the leaves folded in adjacent pairs,
/// an odd node carried up, to one root stating the whole run, its io-hash
/// the run's. The program, the root, its segments' count and the proofs'
/// totals.
pub fn prove_whole(
    name: &str,
    blob: &[u8],
    record: &vos_wire::records::Kernel,
    trace: &KernelTrace,
    cut: usize,
) -> (KernelProgram, NodeRun, usize, Totals) {
    let (program, entry) = vos_pvm_recair::leaf::kernel_program(
        blob,
        record,
        vos_pvm_compiler::TRANSPILER_VERSION,
        &SEGMENT,
    )
    .expect("the kernel's program");
    let class = &program.shape.classes[cut.min(program.shape.classes.len() - 1)];
    let bounds = segment_bounds_budgeted(
        &trace.side_note,
        1 << class.log_steps,
        usize::from(class.pages),
    );
    let fold = vos_pvm_recair::fold::FoldCircuit::new();
    let word = vos_pvm_recair::fold::FoldCircuit::word();
    let mut totals = Totals::default();
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let mut nodes = Vec::with_capacity(bounds.len());
    for (position, &bound) in bounds.iter().enumerate() {
        let ((class, proof), segment, segment_peak) =
            common::measured(|| prove_at_first_class(&mut cursor, bound, &program));
        let leaf = common::prove_leaf(&program, &entry, class, &proof, position as u32, word);
        eprintln!(
            "{name}: segment {position} ({bound:?}, class {class}) proved in {:.2}s, its peak \
             heap {segment_peak} MiB; its leaf in {:.2}s, its peak heap {} MiB",
            segment.as_secs_f64(),
            leaf.proving.as_secs_f64(),
            leaf.peak_mib,
        );
        totals.segments.add(segment, segment_peak);
        totals.leaves.add(leaf.proving, leaf.peak_mib);
        nodes.push(leaf);
    }
    while nodes.len() > 1 {
        let mut level = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut pending = nodes.into_iter();
        while let Some(left) = pending.next() {
            match pending.next() {
                Some(right) => {
                    let node = common::prove_fold(&fold, &program, &left, &right, word);
                    totals.folds.add(node.proving, node.peak_mib);
                    level.push(node);
                }
                None => level.push(left),
            }
        }
        nodes = level;
    }
    let root = nodes.pop().expect("the root");
    let output = root.node.output;
    assert_eq!((output.first, output.last), (0, bounds.len() as u32 - 1));
    assert!(output.entry && output.halt, "the whole run");
    assert_eq!(output.io_hash, trace.io_hash);
    (program, root, bounds.len(), totals)
}

/// The founding key of the tests' spaces.
pub fn founder() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

/// A space founded by [`founder`] alone on [`CLOCK`], told apart by
/// `nonce`.
pub fn genesis(nonce: u8) -> SpaceGenesis {
    SpaceGenesis {
        version: GENESIS_VERSION,
        nodes: vec![(1, founder().verifying_key().to_bytes())],
        clock: CLOCK,
        time: 1_000,
        nonce: [nonce; 16],
    }
}

/// The model venue, its time fixed a second past [`WINDOW`]'s close.
pub struct Venue {
    pub venue: ModelVenue,
}

impl Venue {
    /// A venue of id `id`, its time [`Venue::closed`], with the spaces
    /// `geneses` found registered from the window before [`WINDOW`].
    pub fn new(id: VenueId, geneses: &[SpaceGenesis]) -> Self {
        let venue = ModelVenue::new(id, Arc::new(Self::closed));
        for genesis in geneses {
            venue.seed(genesis, WINDOW - 1);
        }
        Self { venue }
    }

    /// [`Venue::new`], pinning `program`.
    pub fn pinned(id: VenueId, geneses: &[SpaceGenesis], program: ProgramId) -> Self {
        let venue = Self::new(id, geneses);
        venue.venue.pin(program);
        venue
    }

    /// A second past [`WINDOW`]'s close, `B_w + D`.
    pub fn closed() -> u64 {
        let representative = CLOCK.representative().unwrap();
        CLOCK.boundary(WINDOW).unwrap() + representative.origin_ms - CLOCK.origin_ms + 1_000
    }

    /// `root` anchored, signed by the founder for the venue `signed_for`.
    pub fn anchor_for(
        &self,
        root: &RootRead,
        signed_for: VenueId,
    ) -> Result<Anchoring, AnchorRefusal> {
        let key = founder();
        let mut anchor = Anchor {
            space: root.space,
            window: root.window,
            kind: root.kind,
            root: root.root,
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = key.sign(&anchor.digest(&signed_for)).to_bytes();
        self.venue.answer(&anchor)
    }

    /// `root` anchored, signed by the founder for this venue.
    pub fn anchor(&self, root: &RootRead) -> Result<Anchoring, AnchorRefusal> {
        self.anchor_for(root, self.venue.id())
    }
}
