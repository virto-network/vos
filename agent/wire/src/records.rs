//! Values the agent keeps under its system keys ([`crate::keys`]).

use alloc::vec::Vec;

use crate::batch::Await;
use crate::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use crate::result::Outcome;
use crate::schema::Schema;
use crate::{Decode, Encode};

/// The programs a node derived from a package's ELF at its install, by
/// their hashes: the actor's program, which holds its handlers and its
/// workflows, and a kernel for each attestable method, by method in
/// ascending order; and their provenance, the ELF's hash and the version of
/// the transpiler that derived them. The same ELF and version derive the
/// same bytes on any machine.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Derivation {
    pub program: ProgramHash,
    pub kernels: Vec<(MethodId, ProgramHash)>,
    pub elf: [u8; 32],
    pub transpiler: u32,
}

impl Derivation {
    /// The derivation of package `elf`: its actor's program and each
    /// attestable method's kernel, as version `transpiler` derived them,
    /// each named by its hash. The one constructor of a VOS node's install
    /// and of a JAM builder's, so the two agree.
    pub fn new<'a>(
        elf: &[u8],
        actor: &[u8],
        kernels: impl IntoIterator<Item = (MethodId, &'a [u8])>,
        transpiler: u32,
    ) -> Self {
        let hash = |bytes: &[u8]| ProgramHash(crate::result::digest(bytes));
        Self {
            program: hash(actor),
            kernels: kernels
                .into_iter()
                .map(|(method, kernel)| (method, hash(kernel)))
                .collect(),
            elf: crate::result::digest(elf),
            transpiler,
        }
    }

    /// The kernel of attestable `method`.
    pub fn kernel(&self, method: MethodId) -> Option<ProgramHash> {
        self.kernels
            .iter()
            .find(|(bound, _)| *bound == method)
            .map(|(_, kernel)| *kernel)
    }

    /// Every program it derived, the actor's first: what its agent pins.
    pub fn programs(&self) -> impl Iterator<Item = ProgramHash> + '_ {
        core::iter::once(self.program).chain(self.kernels.iter().map(|(_, kernel)| *kernel))
    }
}

/// An installed instance, under [`crate::keys::installed`]: the programs
/// derived from its package, the agent's role byte for each role name, and
/// the actor program's schema, read once at install.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Installed {
    pub derivation: Derivation,
    pub roles: Vec<(Vec<u8>, u8)>,
    pub schema: Schema,
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
    pub fn attestable(&self, method: MethodId) -> Option<ProgramHash> {
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
}

impl Workflow {
    /// The record's format. The agent reads no other: a record of another
    /// format is data it lost, which halts the node that reads it, so a
    /// new format needs the records migrated before any replica runs it.
    /// The node reads the record too, as its [`WorkflowHead`], to answer
    /// its owner: a new format changes that reader with the agent.
    pub const FORMAT: u8 = 3;
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
    /// still the one `INPUT` gives it.
    #[codec(index = 4)]
    Preempted(Vec<u8>),
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
