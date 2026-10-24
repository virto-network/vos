//! Values the agent keeps under its system keys ([`crate::keys`]).

use alloc::vec::Vec;

use crate::abi::cap::Target;
use crate::batch::Await;
use crate::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use crate::result::Outcome;
use crate::schema::Schema;
use crate::{Decode, Encode};

/// The programs a node derived from a package's ELF at its install, by
/// their hashes: the actor's program, which holds its handlers and its
/// workflows, and a kernel for each attestable method, by method in
/// ascending order; their provenance, the ELF's hash and the version of
/// the transpiler that derived them; and the pages of the actor's heap its
/// program leaves out. The same ELF and version derive the same bytes on
/// any machine.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Derivation {
    pub program: ProgramHash,
    pub kernels: Vec<Kernel>,
    pub elf: [u8; 32],
    pub transpiler: u32,
    /// The pages of the actor's heap past its program's read-write data,
    /// which a workflow's machine maps there: a handler and a kernel run
    /// on the heap their programs hold, a workflow on the whole.
    pub heap: u32,
}

/// An attestable method's kernel: its program; the root of the page tree
/// over its initial memory, laid out with no arguments, from which a proof
/// of a run of it starts ([`vos_pvm_program::image`]), the same for every
/// run, as its arguments reach it through its witness input; and the shape
/// its proofs take.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Kernel {
    pub method: MethodId,
    pub program: ProgramHash,
    pub image_root: [u8; 32],
    pub shape: Shape,
}

/// The shape of a kernel's segment proofs: the chips of the segment AIR its
/// code can reach, its instructions' and its precompiles', and for each
/// class of segment the log size of each. A verifier of the kernel accepts
/// a segment over exactly these chips at exactly one class's sizes.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Shape {
    /// The version of the policy that chose the classes and sized them
    /// (`vos_pvm_compiler::shape::POLICY`): a new policy derives other
    /// shapes from the same code, so a record names the one it holds.
    pub policy: u32,
    /// Bit i: chip i of the segment AIR, in its order.
    pub chips: u32,
    /// Cheapest first, at most [`MAX_CLASSES`].
    pub classes: Vec<SegmentClass>,
}

/// A class of segment: the cut it holds its segments to, and the log size
/// each chip of its shape is padded to. Fixed-size, so a kernel's record
/// decodes with one allocation, its classes'.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SegmentClass {
    /// At most 2^`log_steps` steps a segment.
    pub log_steps: u8,
    /// At most this many pages touched a segment.
    pub pages: u16,
    /// Chip i's log size, 0 for a chip outside the shape.
    pub log_sizes: [u8; SEGMENT_CHIPS],
}

/// The segment AIR's chips (`vos_pvm_proof::chip_idx::COUNT`).
pub const SEGMENT_CHIPS: usize = 25;

/// The segment AIR's chips by index: bit i of a shape's chips, and
/// [`SegmentClass::log_sizes`]` [i]`. The prover's `chip_idx` and the
/// compiler's shape derivation both read this table.
pub mod segment_chip {
    pub const CPU: usize = 0;
    pub const BLAKE2B: usize = 1;
    pub const BLAKE2B_BOUNDARY: usize = 2;
    pub const MEMORY: usize = 3;
    pub const MEMORY_PAGE: usize = 4;
    pub const MEMORY_MERKLE: usize = 5;
    pub const MEMORY_ROOT_BOUNDARY: usize = 6;
    pub const REGISTER_MEMORY: usize = 7;
    pub const REGISTER_MEMORY_BOUNDARY: usize = 8;
    pub const REGISTER_MEMORY_CLOSING: usize = 9;
    pub const PROGRAM_BOUNDARY: usize = 10;
    pub const PROGRAM_MEMORY: usize = 11;
    pub const JUMP_TABLE: usize = 12;
    pub const WITNESS_INPUT: usize = 13;
    pub const RANGE_MULTIPLICITY_256: usize = 14;
    pub const BITWISE_LOOKUP: usize = 15;
    pub const POWER_OF_TWO: usize = 16;
    pub const POPCOUNT: usize = 17;
    pub const BITCOUNT: usize = 18;
    pub const BYTE_TO_BITS: usize = 19;
    pub const MUL: usize = 20;
    pub const BITWISE: usize = 21;
    pub const COMPARE: usize = 22;
    pub const DIVREM: usize = 23;
    pub const BITWISE_AND_BYTE: usize = 24;
}

const _: () = assert!(segment_chip::BITWISE_AND_BYTE + 1 == SEGMENT_CHIPS);

/// The most classes a kernel's shape has: what decoding a kernel's record
/// within [`DECODE_KERNEL`](crate::defaults::DECODE_KERNEL) covers.
pub const MAX_CLASSES: usize = 4;

impl Derivation {
    /// The derivation of package `elf`: its actor's program and each
    /// attestable method's kernel, by the method's id, with its shape, by
    /// the kernel's position, as version `transpiler` derived them, each
    /// named by its hash, and the `heap` pages its program leaves out. The
    /// one constructor of a VOS node's install and of a JAM builder's, so
    /// the two agree.
    ///
    /// # Panics
    ///
    /// If a kernel is not a standard program, or the shapes are not one a
    /// kernel, which a derivation never makes.
    pub fn new(
        elf: &[u8],
        actor: &[u8],
        kernels: &[(u32, Vec<u8>)],
        shapes: &[Shape],
        transpiler: u32,
        heap: u32,
    ) -> Self {
        assert_eq!(kernels.len(), shapes.len(), "a shape a kernel");
        Self {
            program: ProgramHash::of(actor),
            kernels: kernels
                .iter()
                .zip(shapes)
                .map(|((method, kernel), shape)| Kernel {
                    method: MethodId(*method),
                    program: ProgramHash::of(kernel),
                    image_root: vos_pvm_program::parse_standard_program(kernel)
                        .and_then(|program| program.image_root())
                        .expect("a derived kernel is a standard program"),
                    shape: shape.clone(),
                })
                .collect(),
            elf: crate::result::digest(elf),
            transpiler,
            heap,
        }
    }

    /// The kernel of attestable `method`.
    pub fn kernel(&self, method: MethodId) -> Option<ProgramHash> {
        self.kernels
            .iter()
            .find(|kernel| kernel.method == method)
            .map(|kernel| kernel.program)
    }

    /// Every program it derived, the actor's first: what its agent pins.
    pub fn programs(&self) -> impl Iterator<Item = ProgramHash> + '_ {
        core::iter::once(self.program).chain(self.kernels.iter().map(|kernel| kernel.program))
    }
}

/// An installed instance, under [`crate::keys::installed`]: the programs
/// derived from its package, the agent's role byte for each role name, the
/// actor program's schema, read once at install, and the target whose
/// limits its program was checked against and its steps run within.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Installed {
    pub derivation: Derivation,
    pub roles: Vec<(Vec<u8>, u8)>,
    pub schema: Schema,
    pub target: Target,
}

impl Installed {
    pub fn role(&self, name: &[u8]) -> Option<u8> {
        self.roles
            .iter()
            .find(|(role, _)| role == name)
            .map(|(_, byte)| *byte)
    }

    /// The actor's program: its handlers and its workflows.
    pub fn program(&self) -> ProgramHash {
        self.derivation.program
    }

    /// The kernel of attestable `method`.
    pub fn kernel(&self, method: MethodId) -> Option<ProgramHash> {
        self.derivation.kernel(method)
    }

    /// Every program the instance runs, its own first: what its agent pins.
    pub fn programs(&self) -> impl Iterator<Item = ProgramHash> + '_ {
        self.derivation.programs()
    }
}

/// A workflow, under [`crate::keys::workflow`], from its start until it is
/// collected, some time after it ends.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Workflow {
    /// The record's format, [`Workflow::FORMAT`]: a record of another the
    /// agent refuses to read.
    pub format: u8,
    /// The program it runs, its instance's actor program, which it pins
    /// until it ends, whatever an upgrade does meanwhile.
    pub program: ProgramHash,
    /// The instance whose method it is: its calls' caller, and the state
    /// its sections reach.
    pub instance: InstanceId,
    /// The workflow method it runs, which the program's entry routes to.
    pub method: MethodId,
    /// Who started it, a client's key or an agent: who reads its result.
    pub owner: Principal,
    /// Each step's limit: what its effect-free code may spend in all, and
    /// what each unit may spend from its first effect to its next await. A
    /// step's `gas_used` may so pass it, to about twice it.
    pub gas: u64,
    /// The pages its program may write, which each step arms.
    pub writable: u32,
    /// The awaits it has made: the next one's counter.
    pub awaits: u64,
    /// The batch time of its row in the due index: its next step's, or its
    /// collection's once it has ended.
    pub due: u64,
    /// The owner's await of its result, when the owner is an agent that
    /// waits for it.
    pub waiter: Option<Await>,
    pub state: WorkflowState,
    /// Its machine as its last step left it; none before its first.
    pub snapshot: Option<Snapshot>,
    /// Its instance's target when it started, whose limits its steps run
    /// within.
    pub target: Target,
    /// The batch time from which every page its snapshot holds has been
    /// stored: its start's, then that of the last step after which it
    /// holds no page an earlier step stored.
    pub stored: u64,
}

impl Workflow {
    /// The record's format. The agent reads no other: a record of another
    /// format is data it lost, which halts the node that reads it, so a
    /// new format needs the records migrated before any replica runs it.
    /// The node reads the record too, as its [`WorkflowHead`], to answer
    /// its owner: a new format changes that reader with the agent.
    pub const FORMAT: u8 = 5;

    /// The batch time from which its next step finds its pages no longer
    /// kept, on a target that keeps them for a time and while it holds
    /// any ([`crate::abi::cap::Limits::pages_kept`]).
    pub fn pages_expire(&self) -> Option<u64> {
        let kept = self.target.limits().pages_kept?;
        self.snapshot
            .as_ref()
            .filter(|snapshot| !snapshot.pages.is_empty())
            .map(|_| self.stored.saturating_add(kept))
    }
}

/// A [`Workflow`] record's fields before its snapshot, in its order:
/// decoded from a record's bytes, it reads the workflow's owner and state
/// without its pages' list, as the node does to answer its owner.
#[derive(Clone, Debug, PartialEq, Eq, Decode)]
pub struct WorkflowHead {
    pub format: u8,
    pub program: ProgramHash,
    pub instance: InstanceId,
    pub method: MethodId,
    pub owner: Principal,
    pub gas: u64,
    pub writable: u32,
    pub awaits: u64,
    pub due: u64,
    pub waiter: Option<Await>,
    pub state: WorkflowState,
}

/// Where a workflow stands between its steps.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum WorkflowState {
    /// Due at once: started, its arguments the input of its first step.
    #[codec(index = 0)]
    Ready(Vec<u8>),
    /// Awaiting `agent`'s answer to await `counter` until `deadline`.
    #[codec(index = 1)]
    Awaiting {
        agent: AgentId,
        counter: u64,
        deadline: u64,
    },
    /// Asleep until a batch at or past `until`.
    #[codec(index = 2)]
    Sleeping { until: u64 },
    /// Ended: its result, or why it failed. Its row in the due index
    /// collects it.
    #[codec(index = 3)]
    Ended(Outcome),
    /// Due at once: preempted between two awaits, its last await's input
    /// still the one [`crate::abi::Op::Input`] gives it.
    #[codec(index = 4)]
    Preempted(Vec<u8>),
    /// Awaiting, at await `counter`, its read at window `window`'s cut
    /// ([`crate::abi::Op::AttestAt`]), whose request
    /// ([`crate::keys::request`]) names its rows: once served, its step
    /// runs attestable `method`'s kernel on `arguments` and the served
    /// rows. Unserved by `deadline`, it resumes
    /// [`crate::abi::AttestError::NotClosed`]. Its record never holds the
    /// served rows.
    #[codec(index = 5)]
    Attesting {
        counter: u64,
        window: u64,
        method: MethodId,
        arguments: Vec<u8>,
        deadline: u64,
    },
}

/// A workflow's machine between steps, restored with Gray Paper calls
/// alone: its program counter, its registers, and each page that differs
/// from its base, the program's image or zeros, by its index and the hash
/// of its bytes, which a row holds.
///
/// The gas is the agent's to set, so none is kept: every step starts a
/// unit, given the step's limit. A step preempted at a host call it did not
/// serve keeps the call's id, `pending`, which the next step serves first,
/// the counter past the call and the registers as the call left them.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Snapshot {
    pub counter: u32,
    /// φ0 to φ12.
    pub registers: Vec<u64>,
    pub pages: Vec<(u32, [u8; 32])>,
    pub pending: Option<u64>,
}

/// A session's mark, under [`crate::keys::session`]: the last sequence
/// consumed and the work-result time it was consumed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SessionMark {
    pub sequence: u64,
    pub time: u64,
}

/// A pending request of a window ([`crate::keys::request`]), a workflow's
/// read at the window's cut ([`crate::abi::Op::AttestAt`]): the instance
/// whose committed rows it reads, and the rows, by their full keys
/// ([`crate::keys::committed`]), strictly increasing, each under the
/// instance's prefix. Every replica proves them at the window's cut once
/// its tree is built there.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PendingRead {
    pub instance: InstanceId,
    pub rows: Vec<Vec<u8>>,
}

/// Every value the agent stores begins with this byte. Gray Paper storage
/// deletes a key written with an empty value; the byte keeps an empty
/// value present, as the actor ABI allows.
pub const STORED: u8 = 1;

/// A value as the agent stores it.
pub fn stored(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + value.len());
    bytes.push(STORED);
    bytes.extend_from_slice(value);
    bytes
}

/// A stored value's bytes, or `None` for bytes the agent did not store.
pub fn unstored(bytes: &[u8]) -> Option<&[u8]> {
    match bytes.split_first() {
        Some((&STORED, value)) => Some(value),
        _ => None,
    }
}

/// A committed map's value as its value row holds it
/// ([`crate::keys::committed`]): the state version that wrote it, a
/// little-endian `u64`, then the value.
pub fn versioned(version: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + value.len());
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// [`stored`] of [`versioned`], in one allocation: a value row as the agent
/// writes it.
pub fn stored_versioned(version: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9 + value.len());
    bytes.push(STORED);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// A value row's version and value, or `None` for bytes too short to be one.
pub fn unversioned(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (version, value) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_le_bytes(*version), value))
}

/// The bytes the leaf of the row `key` commits, from the row as stored: a
/// committed row's bare value, without its format byte and the version
/// that wrote it, so its leaf is the same on every host; any other row's
/// stored bytes whole. `None` for a committed row not stored as a value
/// row.
pub fn leaf_value<'a>(key: &[u8], stored: &'a [u8]) -> Option<&'a [u8]> {
    if crate::keys::is_committed(key) {
        unstored(stored)
            .and_then(unversioned)
            .map(|(_, value)| value)
    } else {
        Some(stored)
    }
}
