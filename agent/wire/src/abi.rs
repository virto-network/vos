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

use alloc::vec::Vec;

use scale::{Decode, Encode};

use crate::keys::Transform;

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
    /// An `#[attestable]` method: no operations at all.
    #[codec(index = 2)]
    Attestable = 2,
    /// A `#[workflow]` method: routed in the actor's program as a handler
    /// is, but run by the agent as a workflow, never as a handler. Its
    /// instance's state it reaches only inside a section ([`Op::Open`]).
    #[codec(index = 3)]
    Workflow = 3,
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
/// request or a wait for a result, a section on its instance's state, or
/// its result. A workflow's unit, the code between two awaits, is preempted
/// only before its first effect, and from it runs to its next await with
/// the step's whole limit. A section's reads count too: a value read and
/// then written within one unit stays atomic. Every other operation a
/// workflow may use only reads, sets registers or pauses.
pub const fn is_effect(op: Op) -> bool {
    matches!(
        op,
        Op::Call | Op::Send | Op::Request | Op::Result | Op::Reply | Op::Fail | Op::Open
    )
}

/// Whether an invocation of `kind` may use operation `op`. [`Op::Call`]
/// from a query is allowed here; the agent also refuses a query that calls a
/// command. A workflow reaches its instance's state only inside a section,
/// where the agent serves the row operations and refuses the rest
/// ([`in_section`]); outside one, a row operation fails the invocation.
pub const fn allowed(kind: Kind, op: Op) -> bool {
    match kind {
        Kind::Attestable => false,
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
    pub const CALLER: u64 = 6_000;
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
    pub const PER_BYTE: u64 = 24;
    /// A key's transform, hashing it and escaping it, or its inverse: a
    /// zero byte doubles under the escape and costs the most.
    pub const KEY_BYTE: u64 = 90;

    /// An operation's price, before its bytes.
    pub const fn of(op: Op) -> u64 {
        match op {
            Op::Get => GET,
            Op::Put | Op::Delete => PUT,
            Op::Scan => SCAN,
            Op::Send => SEND,
            Op::Request | Op::Result | Op::Sleep => PAUSE,
            Op::Open | Op::Close => SECTION,
            Op::Call | Op::Attest => MACHINE,
            Op::Random => RANDOM,
            Op::Caller => CALLER,
            Op::Log => LOG,
            Op::Input => INPUT,
            Op::Reply | Op::Fail | Op::Now | Op::SelfId => OPERATION,
        }
    }
}

/// Per-step limits.
pub mod cap {
    use super::price;
    use crate::defaults::MAX_HANDLER_GAS;

    pub const REQUEST: usize = 64 << 10;
    pub const REPLY: usize = 64 << 10;
    pub const KEY: usize = 1 << 10;
    /// An ordered table's key: a tree path through it is then at most
    /// about 1,040 levels deep.
    pub const ORDERED_KEY: usize = 64;
    pub const VALUE: usize = 64 << 10;
    pub const STEP_WRITES: usize = 256 << 10;
    /// One scan's output: room for a row at the key and value caps with
    /// both length prefixes.
    pub const SCAN: usize = KEY + VALUE + 16;
    /// The largest row the agent stores in a table or committed map, framed
    /// as a state scan returns it: both length prefixes, the table's prefix,
    /// a hashed key of `KEY` zero bytes escaped and terminated, and a value
    /// at its cap after the format byte and a committed map's version.
    pub const STORED_ROW: usize = 8 + crate::keys::TABLE_PREFIX + 16 + 2 * KEY + 2 + 1 + 8 + VALUE;
    pub const MESSAGES: usize = 16;
    pub const MESSAGE: usize = 64 << 10;
    pub const ATTESTS: usize = 16;
    pub const WORK_RESULT: usize = 4 << 20;
    /// The pages a workflow's program, its actor's, may write, its data,
    /// heap and stack: a start of a workflow of a larger one fails.
    pub const WORKFLOW_PAGES: usize = 4096;
    /// The raw bytes of the pages one workflow step may write: past it, the
    /// step fails.
    ///
    /// **The budget binds first.** A step is taken its pages from the
    /// batch's budget, whatever host it runs on: it restores the pages its
    /// workflow holds at [`crate::defaults::RESTORED_PAGE`] each, and
    /// writes others at [`crate::defaults::WRITTEN_PAGE`] each, beside its
    /// gas limit and the agent's reserves. So the pages a step restores and
    /// writes satisfy `restored × RESTORED_PAGE + written × WRITTEN_PAGE +
    /// limit + reserves ≤ budget`: in a refine of the default budget
    /// (`REFINE_GAS`), a step that restores no page writes about 800, and
    /// one that restores [`HELD_PAGES`] about 310. Effect-free code that
    /// would pass it ends the step at the first page it cannot pay; once a
    /// unit has made an effect, the step waits for the next batch behind a
    /// step that ran a handler, or fails alone, out of gas.
    pub const STEP_PAGES: usize = 8 << 20;
    /// The pages a workflow's snapshot may hold, 2.25 MiB: a step that
    /// would leave it more fails, so the least budget a node refines with
    /// ([`crate::defaults::min_refine_gas`]) restores any snapshot. On JAM,
    /// the step that ends a workflow holding them all, at the largest
    /// limit, restores every page and drops every page's row, and a
    /// package of that step alone, bar its own effects, fits a work
    /// package's refine gas: an agent's builder asserts it.
    pub const HELD_PAGES: usize = 576;
    /// The raw bytes of the pages one work result's page section may hold:
    /// a step that would pass it waits for the next batch.
    pub const RESULT_PAGES: usize = 16 << 20;
    /// A refine's whole output: the work result, then its page section, in
    /// which a page, LZ4-compressed and framed, may outgrow its 4 KiB by a
    /// few dozen bytes.
    pub const OUTPUT: usize = WORK_RESULT + RESULT_PAGES + RESULT_PAGES / 64;

    /// The most a step of `gas` adds to a work result: its input, a new
    /// session's whole, its reply, writes, messages and attests at their
    /// caps, a request's reply to its sender, with the framing of as many
    /// writes (committed ones, with their map, the larger) and instances as
    /// `gas` can pay for.
    pub const fn step_result(gas: u64) -> usize {
        128 + REPLY
            + STEP_WRITES
            + (gas / price::PUT) as usize * 18
            + (1 + (gas / price::MACHINE) as usize) * 12
            + MESSAGES * (MESSAGE + 40)
            + (REPLY + 40)
            + ATTESTS * (REQUEST + REPLY + 40)
    }

    /// The most a handler's step adds to a work result. An install's record
    /// is under [`STEP_WRITES`] too.
    pub const STEP_RESULT: usize = step_result(MAX_HANDLER_GAS);

    /// What a workflow's step adds beyond its calls' effects: its record,
    /// with its arguments, last input or result and the hash of each page
    /// it holds, the rows beside it, and an entry for each page it stores,
    /// at most those it holds after, and drops, at most those it held
    /// before.
    pub const WORKFLOW_ROWS: usize = 1024 + REQUEST + HELD_PAGES * 36 + 2 * HELD_PAGES * 48;

    /// The most a workflow's step adds to a work result: its calls' effects
    /// at the gas it may use, its limit for its effect-free code and its
    /// limit again from a unit's first effect, and its rows.
    pub const WORKFLOW_STEP_RESULT: usize = step_result(2 * MAX_HANDLER_GAS) + WORKFLOW_ROWS;

    // Every step fits an empty result, so a batch always makes progress.
    const _: () = assert!(STEP_RESULT + 64 <= WORK_RESULT);
    const _: () = assert!(WORKFLOW_STEP_RESULT + 64 <= WORK_RESULT);
}

/// The precompiles the agent serves its machines, each at the price a
/// node's own machine pays for it, on every host.
pub mod precompile {
    /// One BLAKE2b compression: φ7 h (64 bytes, read and written), φ8 m
    /// (128 bytes), φ9 the counter's low 64 bits, φ10 non-zero for the last
    /// block.
    pub const BLAKE2B_COMPRESS: u64 = 0x400;

    /// The gas a call to precompile `id` costs its caller, beside its
    /// `ecalli`'s block, or `None` if the agent serves no precompile `id`.
    pub const fn price(id: u64) -> Option<u64> {
        match id {
            BLAKE2B_COMPRESS => Some(600),
            _ => None,
        }
    }
}

/// Results in φ7: the Gray Paper's host-call results.
pub mod code {
    pub const OK: u64 = 0;
    pub const NONE: u64 = u64::MAX;
    pub const WHAT: u64 = u64::MAX - 1;
    pub const OOB: u64 = u64::MAX - 2;
    pub const WHO: u64 = u64::MAX - 3;
    pub const FULL: u64 = u64::MAX - 4;
    pub const HUH: u64 = u64::MAX - 8;
}

/// A closed set of codes, each a `u32` in registers and on the wire.
macro_rules! codes {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident = $code:literal,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u32)]
        pub enum $name {
            $($(#[$variant_meta])* $variant = $code,)*
        }

        impl $name {
            pub const fn code(self) -> u32 {
                self as u32
            }

            pub const fn from_code(code: u32) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }

        impl Encode for $name {
            fn encode_to(&self, buf: &mut Vec<u8>) {
                self.code().encode_to(buf);
            }
        }

        impl Decode for $name {
            fn decode(data: &[u8]) -> Result<(Self, usize), scale::DecodeError> {
                let (code, used) = u32::decode(data)?;
                let value = Self::from_code(code).ok_or(scale::DecodeError::InvalidCode(code))?;
                Ok((value, used))
            }
        }
    };
}

codes! {
    /// Why a step failed, in [`crate::result::Outcome::Failed`], or why a
    /// call returned an error, in φ8 of `CALL` and `ATTEST`. A failed step
    /// consumes its input.
    pub enum Failure {
        /// The handler failed; the detail is its encoded error.
        Handler = 1,
        /// The invocation trapped, faulted, used an operation outside its
        /// kind or a buffer it could not reach.
        Trapped = 2,
        OutOfGas = 3,
        /// A per-step cap was exceeded.
        Cap = 4,
        /// The caller lacks the handler's role.
        Forbidden = 5,
        /// No such instance or method.
        Unknown = 6,
        /// The callee is already on the call stack.
        Cycle = 7,
        /// No inner machine was left for the callee.
        Depth = 8,
        /// The agent program failed on the message alone, twice, each
        /// time on fresh state: its leader asserted the failure in the
        /// batch, and the handler never ran.
        InRefine = 9,
        /// An await's deadline passed before its answer came.
        TimedOut = 10,
        /// The callee's program could not be loaded: the node lacks a
        /// program the agent's state names, its fault, not the caller's.
        Unloadable = 11,
    }
}

codes! {
    /// Why refine refused an input, in [`crate::result::Step::Refused`]. A
    /// refused input is not consumed: no mark advances.
    pub enum Refusal {
        /// Out of its session's or pair's order.
        Sequence = 1,
        /// Its session expired.
        Expired = 2,
        /// Its session's or pair's mark is state the agent cannot read: an
        /// operator must look, and resending cannot help.
        Unreadable = 3,
        /// A new session whose creation time is too far from the agent's:
        /// start one with a time near it.
        StaleSession = 4,
        /// A new session, while the agent holds as many as it may: none is
        /// created until some are collected.
        SessionsFull = 5,
        /// A new session, while its key holds as many as it may at the
        /// agent.
        KeySessionsFull = 6,
    }
}

/// The host calls each kind of program may make, and what a JAM node does
/// with each. CI lists every `ecalli` in the default agent and the test
/// programs and checks them against these.
///
/// A VOS node serves every call here, with one exception: its refine host
/// answers `fetch` with `WHAT`, so only an agent's accumulate may call it.
/// The table cannot tell refine from accumulate, which share their code.
pub mod surface {
    use core::ops::RangeInclusive;

    /// Precompiles: a VOS node computes an agent's in place, and the agent
    /// its machines' ([`super::precompile`]); a JAM node answers `WHAT`,
    /// and the shims compute in software.
    pub const PRECOMPILES: RangeInclusive<u64> = 0x400..=0x47f;
    /// The actor ABI, which an agent serves; ids it does not serve answer
    /// `WHAT`.
    pub const ACTOR_ABI: RangeInclusive<u64> = 0x500..=0x5ff;

    /// A VOS node's refine extension: a machine of a program the node
    /// holds, from its pool, at a counter. A host that answers `WHAT` leaves
    /// the agent to build the machine from `historical_lookup`.
    pub const INSTANTIATE: u64 = 0x480;
    /// A VOS node's refine extension: a row of the agent's applied state.
    pub const STATE_READ: u64 = 0x481;
    /// A VOS node's refine extension: rows of the agent's applied state
    /// under a prefix, after a key.
    pub const STATE_SCAN: u64 = 0x482;
    /// The agent's report that its state lost data it wrote, φ7/φ8 what: a
    /// VOS node stops the refine at the call and halts, as for a blob it
    /// lost.
    pub const LOST: u64 = 0x483;

    /// What a JAM node does with an agent program's call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum OnJam {
        /// A Gray Paper call, which a JAM node serves (`log` it may ignore).
        Served,
        /// A VOS extension, which a JAM node answers `WHAT`; the agent then
        /// builds the machine itself from `historical_lookup`.
        Loader,
        /// A precompile: the software implementation.
        Software,
        /// Applied state, which on JAM a package's witness gives instead,
        /// or the agent's report that its state lost data it wrote: a
        /// refine that reaches one there traps, so no result is computed on
        /// state that is not there.
        NoResult,
    }

    /// An agent program's call (refine and accumulate share its code):
    /// `None` when it is outside the surface.
    pub fn agent(id: u64) -> Option<OnJam> {
        match id {
            // gas, fetch, read, write, historical_lookup, export,
            // machine..expunge, solicit, log.
            0 | 2 | 4 | 5 | 7..=14 | 24 | 100 => Some(OnJam::Served),
            INSTANTIATE => Some(OnJam::Loader),
            STATE_READ | STATE_SCAN | LOST => Some(OnJam::NoResult),
            _ if PRECOMPILES.contains(&id) => Some(OnJam::Software),
            _ => None,
        }
    }

    /// An actor program's call: the actor ABI or a precompile.
    pub fn actor(id: u64) -> bool {
        ACTOR_ABI.contains(&id) || PRECOMPILES.contains(&id)
    }

    /// An attestable method's kernel's call: a precompile only, as the
    /// prover needs, which its derivation checks.
    pub fn kernel(id: u64) -> bool {
        PRECOMPILES.contains(&id)
    }
}
