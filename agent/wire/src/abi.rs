//! The actor ABI: host calls from an actor's inner machine to the agent
//! program that hosts it.
//!
//! The ids are private to the agent and its actors, in a block that meets no
//! Gray Paper id, node extension or precompile.
//!
//! **Conventions,** for every operation below:
//! - Arguments are in φ7 onwards, in the order listed; results replace φ7,
//!   and φ8 where noted.
//! - A buffer is an address and a length. One the actor cannot read, or for
//!   an output cannot write, fails the invocation.
//! - Outputs copy at most the given capacity and return the whole length
//!   in φ7, as the Gray Paper's `read` does: an actor whose buffer was short
//!   calls again with a larger one, or from an offset where there is one.
//! - A row operation names its [`Rows`] and a key, and the agent keys the
//!   row itself: the struct state at [`crate::keys::instance_struct`], under
//!   the empty key; a table's or committed map's row at its prefix and the
//!   key under the table's [`crate::keys::Transform`]. So an actor reaches
//!   only its own state, and every row key stays prefix-free whatever bytes
//!   it passes. A [`Rows`] the agent does not know, or a struct key that is
//!   not empty, fails the invocation; an ordered key longer than
//!   [`cap::ORDERED_KEY`] exceeds a cap.
//! - Each operation costs its price ([`price::of`]) plus
//!   [`price::PER_BYTE`] for every byte copied either way, and a row
//!   operation [`price::KEY_BYTE`] more for every byte of a key it
//!   transforms or a scan returns, charged from the actor's frame before it
//!   is served (a scan's output, before it is copied).
//! - An id the agent does not serve, including every Gray Paper id and node
//!   extension, costs [`price::OPERATION`], answers [`code::WHAT`] and
//!   execution continues. A served operation outside the invocation's
//!   [`Kind`] fails the invocation.
//! - A [`precompile`] call is served by the agent in every kind, at its
//!   price, as a node serves its own machine's: its output is written into
//!   the caller's memory and every register is left as it was. Any other id
//!   among [`surface::PRECOMPILES`] is unserved, as on JAM.
//! - Exceeding a [`cap`] fails the invocation.
//! - A nested callee that fails or is refused leaves no effects: its
//!   writes, sends and attests, and its share of the step's write cap, are
//!   discarded. [`Op::Random`] draws keep counting.
//! - Roles match exactly: a handler that names a role admits the
//!   principals holding that role byte, and a principal holds one role.

mod codes;

use alloc::vec::Vec;

use scale::{Decode, Encode};

pub use codes::{AttestError, Failure, Refusal, code};

use crate::keys::Transform;

/// The bytes from the start of an actor's heap arena that a handler's or a
/// kernel's program holds: an install's derivation leaves the arena's rest
/// out of its programs, and a workflow's machine maps it. The SDK's
/// allocator gives a handler or a kernel no more, and its default arena is
/// this large.
pub const INVOCATION_HEAP: usize = 512 << 10;

/// The kind of an invocation, which decides the operations it may use.
/// Its index is the kind the agent passes in φ8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Kind {
    /// A `&mut self` handler, through the log.
    #[codec(index = 0)]
    Command = 0,
    /// A `&self` handler, on applied state, outside the log.
    #[codec(index = 1)]
    Query = 1,
    /// An `#[attestable]` method of no public argument that reads no root:
    /// its kernel returns its output alone. No operations at all.
    #[codec(index = 2)]
    Attestable = 2,
    /// A `#[workflow]` method: routed in the actor's program as a handler
    /// is, but run by the agent as a workflow, never as a handler. Its
    /// instance's state it reaches only inside a section ([`Op::Open`]).
    #[codec(index = 3)]
    Workflow = 3,
    /// An `#[attestable]` method that states public arguments, a venue's
    /// or its own `#[public]` ones, and reads no root: its kernel returns
    /// its statement's parts ([`crate::result::KernelReturn`]).
    #[codec(index = 4)]
    Stating = 4,
    /// An `#[attestable]` `&self` method: run at a window's cut
    /// ([`Op::AttestAt`]), its kernel reads the rows served there after its
    /// arguments, and returns its statement's parts, the space's root among
    /// them.
    #[codec(index = 5)]
    Reading = 5,
}

impl Kind {
    /// Its index, its encoding's one byte.
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// Whether a method of this kind runs as a handler of the actor's: a
    /// command or a query. An attestable method runs as its kernel, bound
    /// at install, and a workflow as a workflow.
    pub const fn is_handler(self) -> bool {
        matches!(self, Kind::Command | Kind::Query)
    }

    /// Whether a method of this kind runs as its kernel, bound at install.
    pub const fn is_attestable(self) -> bool {
        matches!(self, Kind::Attestable | Kind::Stating | Kind::Reading)
    }
}

/// The rows a row operation reaches, in its φ7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rows {
    /// The instance's struct state: one row, under the empty key.
    Struct,
    /// A table's rows, by its tag.
    Table { tag: u32, transform: Transform },
    /// A committed map's rows: written, they are marked for the map's
    /// root ([`crate::result::Run::committed`]).
    Committed { tag: u32, transform: Transform },
}

impl Rows {
    /// The register: bits 0..32 the tag, 32..40 the transform's tag, 40..48
    /// the kind (0 the struct, 1 a table, 2 a committed map), the rest 0.
    /// The struct's tag and transform are 0.
    pub const fn register(self) -> u64 {
        let (kind, tag, transform) = match self {
            Rows::Struct => (0u64, 0, 0),
            Rows::Table { tag, transform } => (1, tag, transform.tag()),
            Rows::Committed { tag, transform } => (2, tag, transform.tag()),
        };
        kind << 40 | (transform as u64) << 32 | tag as u64
    }

    pub const fn from_register(register: u64) -> Option<Self> {
        let tag = register as u32;
        let Some(transform) = Transform::from_tag((register >> 32) as u8) else {
            return None;
        };
        match register >> 40 {
            0 if register == 0 => Some(Rows::Struct),
            1 => Some(Rows::Table { tag, transform }),
            2 => Some(Rows::Committed { tag, transform }),
            _ => None,
        }
    }
}

/// An enum over host call ids, each variant its id, with `from_id` for an
/// id an actor passes.
macro_rules! operations {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident = $id:literal,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u64)]
        pub enum $name {
            $($(#[$variant_meta])* $variant = $id,)*
        }

        impl $name {
            /// Every one, in the order of their ids.
            pub const ALL: &[Self] = &[$(Self::$variant),*];

            /// Its host call's id.
            pub const fn id(self) -> u64 {
                self as u64
            }

            /// The one host call `id` names, if any.
            pub const fn from_id(id: u64) -> Option<Self> {
                match id {
                    $($id => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

operations! {
    /// The actor ABI's operations, each by its host call's id.
    pub enum Op {
        /// φ7 output, φ8 offset, φ9 capacity → φ7 the request's arguments'
        /// length.
        Input = 0x500,
        /// φ7/φ8 the reply. The handler's outcome: a second `Reply` or
        /// `Fail` fails the invocation with [`Failure::Trapped`]. Halting
        /// without either replies empty.
        Reply = 0x501,
        /// φ7/φ8 the handler's encoded error: the step fails with
        /// [`Failure::Handler`] and this detail.
        Fail = 0x502,
        /// φ7 level (0 error … 4 trace, as the Gray Paper's `log`), φ8/φ9 the
        /// message.
        Log = 0x503,
        /// φ7 output, φ8 capacity → φ7 the length of the caller's encoded
        /// [`crate::ids::Principal`]: the calling instance for a nested call.
        Caller = 0x504,
        /// → φ7 the batch time, milliseconds since the Unix epoch.
        Now = 0x505,
        /// φ7 output: 32 bytes, BLAKE2b-256 of `vos/random`, the batch seed,
        /// the step's index in the batch (four bytes, little-endian) and how
        /// many the step drew before (eight bytes, little-endian).
        Random = 0x506,
        /// φ7 [`Rows`], φ8/φ9 key, φ10 output, φ11 offset, φ12 capacity → φ7
        /// the value's length, or [`code::NONE`].
        Get = 0x510,
        /// φ7 [`Rows`], φ8/φ9 key, φ10/φ11 value.
        Put = 0x511,
        /// φ7 [`Rows`], φ8/φ9 key.
        Delete = 0x512,
        /// φ7 a table's or committed map's [`Rows`], φ8/φ9 cursor, φ10
        /// output, φ11 capacity, φ12 1 for the rows after the cursor (a key)
        /// or 0 for the table's first rows → φ7 the bytes written: whole rows
        /// back to back in the table's order (hash order for a hashed table,
        /// key order for an ordered one), each the SCALE encoding of `(key,
        /// value)` as two byte vectors, the key as the actor wrote it. 0 when
        /// no rows remain; [`code::FULL`] when the next row alone exceeds the
        /// capacity.
        Scan = 0x513,
        /// The callee runs once: with a smaller output the agent copies what
        /// fits and returns the whole length, and the rest is lost. A caller
        /// passes an output of [`cap::REPLY`] bytes, which always holds the
        /// whole reply.
        ///
        /// φ7 instance, φ8 method, φ9/φ10 arguments, φ11 output, φ12 capacity
        /// → φ7 the length of the callee's reply or error detail, φ8 0 when it
        /// replied, [`Failure::Handler`] when it failed (its writes are
        /// discarded), or [`Failure::Forbidden`] when the calling instance
        /// lacks the callee's role (the callee never ran). Any other failure
        /// of the callee fails the whole step. A query may call only queries.
        Call = 0x520,
        /// φ7 agent, φ8 instance, φ9 method, φ10/φ11 arguments. Delivered
        /// after the step commits.
        Send = 0x521,
        /// φ7 an attestable method of this instance's package, φ8/φ9
        /// arguments, φ10 output, φ11 capacity → φ7 the output's length, φ8 0
        /// or a [`Failure`] code. The agent runs the method's kernel, derived
        /// from the package at install, never a program the caller names. As
        /// with `Call`, the output should hold [`cap::REPLY`] bytes.
        Attest = 0x522,
        /// → φ7 the instance, φ8 the agent.
        SelfId = 0x523,

        /// A workflow's operations, each a pause: the workflow's step ends
        /// there, its effects commit with its snapshot, and the call returns
        /// only when the agent resumes the machine, in a later step, with φ7
        /// the length of the input that resumed it, which `Input` copies out:
        /// an encoded [`crate::batch::Answer`] for an await, nothing for a
        /// sleep. φ8 is 0.
        ///
        /// φ7 agent, φ8 instance, φ9 method, φ10/φ11 arguments, φ12 the
        /// deadline, milliseconds after the batch's time (0 for the default,
        /// [`crate::defaults::AWAIT_MS`]). Sent after the step commits, as a
        /// request: the answer is the callee's outcome, `Started` for a
        /// workflow method, or `Failed` with [`Failure::TimedOut`] once the
        /// deadline passed. The agent is another: a request of this
        /// workflow's own agent fails the invocation, which `Call`s it.
        Request = 0x530,
        /// φ7 another agent, φ8 a workflow it runs, which this workflow
        /// started, φ9 the deadline as `Request`'s: awaits the workflow's
        /// result, its outcome as the answer.
        Result = 0x531,
        /// φ7 a batch time, milliseconds since the Unix epoch: resumes in the
        /// first batch at or past it, and later than the batch that sleeps, so
        /// a sleep's row in the due index always lies ahead of its step.
        Sleep = 0x532,
        /// A read of the workflow's instance's committed rows at its
        /// window's cut, through an attestable `&self` method: φ7 the
        /// method, φ8/φ9 its arguments, φ10/φ11 the rows it reads, the
        /// SCALE encoding of their full keys ([`crate::keys::committed`]),
        /// strictly increasing. Refused at once, without pausing, φ7 0 and
        /// φ8 an [`AttestError`]: an agent of no space, a malformed read
        /// set, an unknown method or arguments past the target's cap.
        /// Otherwise its step records the request of the batch time's
        /// window ([`crate::keys::request`]), and the workflow pauses until
        /// a [`crate::batch::Input::Resume`] serves the rows proved at the
        /// window's cut, or [`crate::defaults::READ_WINDOWS`] windows pass:
        /// its input then an encoded [`crate::result::Attested`], the
        /// kernel's output on the arguments and the served rows, or why
        /// there is none.
        AttestAt = 0x533,

        /// A workflow's section on its instance's state, as the instance
        /// itself, with no role check: φ7 the instance, which must be the
        /// workflow's own. Until [`Op::Close`], the agent serves only that
        /// instance's `Get`, `Put`, `Delete` and `Scan`, and `Now` and `Log`:
        /// any other operation, a second `Open` among them, fails the
        /// invocation, as does a workflow that ends with a section open. A
        /// section is an effect ([`is_effect`]): it runs to the unit's next
        /// await, so it never spans a pause, and its writes commit with the
        /// step.
        Open = 0x540,
        /// Close the open section; with none open, it fails the invocation.
        Close = 0x541,
    }
}

/// Whether operation `op` is an effect a workflow makes: a call, a send, a
/// request or a wait for a result, a read at its window's cut, a section on
/// its instance's state, or its result. A workflow's unit, the code between two awaits, is preempted
/// only before its first effect, and from it runs to its next await with
/// the step's whole limit. A section's reads count too: a value read and
/// then written within one unit stays atomic. Every other operation a
/// workflow may use only reads, sets registers or pauses.
pub const fn is_effect(op: Op) -> bool {
    matches!(
        op,
        Op::Call
            | Op::Send
            | Op::Request
            | Op::Result
            | Op::AttestAt
            | Op::Reply
            | Op::Fail
            | Op::Open
    )
}

/// Whether an invocation of `kind` may use operation `op`. [`Op::Call`]
/// from a query is allowed here; the agent also refuses a query that calls a
/// command. A workflow reaches its instance's state only inside a section,
/// where the agent serves the row operations and refuses the rest
/// ([`in_section`]); outside one, a row operation fails the invocation.
pub const fn allowed(kind: Kind, op: Op) -> bool {
    match kind {
        Kind::Attestable | Kind::Stating | Kind::Reading => false,
        Kind::Workflow => matches!(
            op,
            Op::Input
                | Op::Reply
                | Op::Fail
                | Op::Log
                | Op::Now
                | Op::Random
                | Op::Get
                | Op::Put
                | Op::Delete
                | Op::Scan
                | Op::Call
                | Op::Send
                | Op::SelfId
                | Op::Request
                | Op::Result
                | Op::Sleep
                | Op::AttestAt
                | Op::Open
                | Op::Close
        ),
        Kind::Query => matches!(
            op,
            Op::Input
                | Op::Reply
                | Op::Fail
                | Op::Log
                | Op::Caller
                | Op::Now
                | Op::Random
                | Op::Get
                | Op::Scan
                | Op::Call
                | Op::SelfId
        ),
        Kind::Command => matches!(
            op,
            Op::Input
                | Op::Reply
                | Op::Fail
                | Op::Log
                | Op::Caller
                | Op::Now
                | Op::Random
                | Op::Get
                | Op::Put
                | Op::Delete
                | Op::Scan
                | Op::Call
                | Op::Send
                | Op::Attest
                | Op::SelfId
        ),
    }
}

/// Whether a workflow may use operation `op` with a section open: its
/// instance's row operations, the time, a log and the section's close.
/// The row operations it may use only then.
pub const fn in_section(op: Op) -> bool {
    matches!(
        op,
        Op::Get | Op::Put | Op::Delete | Op::Scan | Op::Now | Op::Log | Op::Close
    )
}

/// Whether a workflow may use operation `op`, one the agent serves, with a
/// section open or not: inside one, what [`in_section`] names; outside
/// one, what its kind may use but the row operations and a close.
pub const fn workflow_may_use(section: bool, op: Op) -> bool {
    if section {
        in_section(op)
    } else {
        allowed(Kind::Workflow, op)
            && !matches!(op, Op::Get | Op::Put | Op::Delete | Op::Scan | Op::Close)
    }
}

/// Gas an operation costs the actor, charged before it is served: the
/// operation's price, then [`price::PER_BYTE`] for every byte copied either
/// way, and [`price::KEY_BYTE`] for every byte of a key a row operation
/// transforms or a scan returns.
/// Each covers what the default agent measurably spends serving it, so a
/// handler's gas limit bounds the agent's work too.
///
/// The testkit's `every_operation_pays_for_its_serving` prints each charge
/// and its cost, and requires a fifth of each charge spare.
pub mod price {
    use super::Op;

    /// An id the agent does not serve, and the operations that only read
    /// or set registers.
    pub const OPERATION: u64 = 2_000;
    /// A section's open, and its close: each a workflow's exit through the
    /// agent's checks of its unit's effects.
    pub const SECTION: u64 = 3_000;
    /// The request's arguments, copied out with a `poke`.
    pub const INPUT: u64 = 2_500;
    pub const RANDOM: u64 = 6_000;
    pub const CALLER: u64 = 6_200;
    pub const LOG: u64 = 4_000;
    pub const SEND: u64 = 5_000;
    /// A pause: its message, its await and its row in the due index.
    pub const PAUSE: u64 = 8_000;
    /// A row operation hashes its key under a hashed table's transform,
    /// and looks it up in the step's overlays at a random place.
    pub const GET: u64 = 30_000;
    pub const SCAN: u64 = 66_000;
    pub const PUT: u64 = 64_000;
    /// A nested call or attest acquires a machine.
    pub const MACHINE: u64 = 60_000;
    /// An attest acquires a machine, and records its statement: its
    /// witness input, its output, its public arguments and its roots.
    pub const ATTEST: u64 = 66_000;
    pub const PER_BYTE: u64 = 24;
    /// A key's transform, hashing it and escaping it, or its inverse: a
    /// zero byte doubles under the escape and costs the most.
    pub const KEY_BYTE: u64 = 90;

    /// What the agent's check of a kernel's statement parts costs the
    /// caller, the parts `len` bytes: their io-hash, a block of 128 bytes a
    /// compression, and two more for its domain and lengths.
    pub const fn io_hash(len: usize) -> u64 {
        IO_HASH_BLOCK * (len as u64 / 128 + 2)
    }

    /// The agent's io-hash of a kernel's statement parts, for each block it
    /// compresses.
    pub const IO_HASH_BLOCK: u64 = 8_000;

    /// An operation's price, before its bytes.
    pub const fn of(op: Op) -> u64 {
        match op {
            Op::Get => GET,
            Op::Put | Op::Delete => PUT,
            Op::Scan => SCAN,
            Op::Send => SEND,
            Op::Request | Op::Result | Op::Sleep | Op::AttestAt => PAUSE,
            Op::Open | Op::Close => SECTION,
            Op::Call => MACHINE,
            Op::Attest => ATTEST,
            Op::Random => RANDOM,
            Op::Caller => CALLER,
            Op::Log => LOG,
            Op::Input => INPUT,
            Op::Reply | Op::Fail | Op::Now | Op::SelfId => OPERATION,
        }
    }
}

/// Per-step limits.
pub mod cap;

/// The precompiles the agent serves its machines, each at the price a
/// node's own machine pays for it, on every host.
pub mod precompile {
    /// One BLAKE2b compression: φ7 h (64 bytes, read and written), φ8 m
    /// (128 bytes), φ9 the counter's low 64 bits, φ10 non-zero for the last
    /// block.
    pub const BLAKE2B_COMPRESS: u64 = 0x400;

    /// A kernel's witness input: φ7 the destination, φ8 the capacity. The
    /// agent writes the next `min(capacity, remaining)` bytes of the input
    /// the attest supplies and returns their count in φ7, 0 at its end, and
    /// records what the kernel read in the attest. It serves it to kernels
    /// alone: a handler's call of it is an id the agent does not serve.
    pub const WITNESS_INPUT: u64 = 0x401;

    /// A witness-input call's price to its kernel, before its bytes: the
    /// copy into the kernel, as an actor's input costs.
    pub const WITNESS_INPUT_CALL: u64 = super::price::INPUT;

    /// A witness-input call's price for each byte it writes.
    pub const WITNESS_INPUT_BYTE: u64 = super::price::PER_BYTE;

    /// The gas a call to precompile `id` costs its caller, beside its
    /// `ecalli`'s block, or `None` if the agent serves no precompile `id`
    /// to every machine: the witness input, which only a kernel has, is
    /// priced by its bytes.
    pub const fn price(id: u64) -> Option<u64> {
        match id {
            BLAKE2B_COMPRESS => Some(600),
            _ => None,
        }
    }
}

/// The host calls each kind of program may make, and what a JAM node does
/// with each. CI lists every `ecalli` in the default agent and the test
/// programs and checks them against these.
///
/// A VOS node serves every call here, with one exception: its refine host
/// answers `fetch` with `WHAT`, so only an agent's accumulate may call it.
/// The table cannot tell refine from accumulate, which share their code.
pub mod surface;
