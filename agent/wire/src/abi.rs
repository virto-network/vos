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
//! - Keys are relative to the actor's instance; the agent prefixes them
//!   with [`crate::keys::instance_prefix`], so an actor reaches only its own
//!   state. Keys are not empty.
//! - Each operation costs [`price::OPERATION`] plus [`price::PER_BYTE`] for
//!   every byte copied either way, charged from the actor's frame before
//!   it is served.
//! - An id the agent does not serve, including every Gray Paper id and node
//!   extension, costs [`price::OPERATION`], answers [`code::WHAT`] and
//!   execution continues. Precompiles are served as on every machine. A
//!   served operation outside the invocation's [`Kind`] fails the
//!   invocation.
//! - Exceeding a [`cap`] fails the invocation.
//! - A nested callee that fails or is refused leaves no effects: its
//!   writes, sends and attests, and its share of the step's write cap, are
//!   discarded. `RANDOM` draws keep counting.
//! - Roles match exactly: a handler that names a role admits the
//!   principals holding that role byte, and a principal holds one role.

use alloc::vec::Vec;

/// The kind of an invocation, which decides the operations it may use.
/// Its index is the kind the agent passes in φ8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum Kind {
    /// A `&mut self` handler, through the log.
    #[codec(index = 0)]
    Command,
    /// A `&self` handler, on applied state, outside the log.
    #[codec(index = 1)]
    Query,
    /// An `#[attestable]` method: no operations at all.
    #[codec(index = 2)]
    Attestable,
}

pub mod op {
    /// φ7 output, φ8 offset, φ9 capacity → φ7 the request's arguments'
    /// length.
    pub const INPUT: u64 = 0x500;
    /// φ7/φ8 the reply. The handler's outcome: a second `REPLY` or `FAIL`
    /// fails the invocation with [`super::failure::TRAPPED`]. Halting
    /// without either replies empty.
    pub const REPLY: u64 = 0x501;
    /// φ7/φ8 the handler's encoded error: the step fails with
    /// [`super::failure::HANDLER`] and this detail.
    pub const FAIL: u64 = 0x502;
    /// φ7 level (0 error … 4 trace, as the Gray Paper's `log`), φ8/φ9 the
    /// message.
    pub const LOG: u64 = 0x503;
    /// φ7 output, φ8 capacity → φ7 the length of the caller's encoded
    /// [`crate::ids::Principal`]: the calling instance for a nested call.
    pub const CALLER: u64 = 0x504;
    /// → φ7 the batch time, milliseconds since the Unix epoch.
    pub const NOW: u64 = 0x505;
    /// φ7 output: 32 bytes, BLAKE2b-256 of `vos/random`, the batch seed,
    /// the step's index in the batch (four bytes, little-endian) and how
    /// many the step drew before (eight bytes, little-endian).
    pub const RANDOM: u64 = 0x506;
    /// φ7/φ8 key, φ9 output, φ10 offset, φ11 capacity → φ7 the value's
    /// length, or [`super::code::NONE`].
    pub const GET: u64 = 0x510;
    /// φ7/φ8 key, φ9/φ10 value.
    pub const PUT: u64 = 0x511;
    /// φ7/φ8 key.
    pub const DELETE: u64 = 0x512;
    /// φ7/φ8 prefix, φ9/φ10 cursor (rows after it; empty starts at the
    /// prefix), φ11 output, φ12 capacity → φ7 the bytes written: whole rows
    /// back to back, each the SCALE encoding of `(key, value)` as two byte
    /// vectors, keys relative to the instance. 0 when
    /// no rows remain; [`super::code::FULL`] when the next row alone
    /// exceeds the capacity.
    pub const SCAN: u64 = 0x513;
    /// The callee runs once: with a smaller output the agent copies what
    /// fits and returns the whole length, and the rest is lost. A caller
    /// passes an output of [`super::cap::REPLY`] bytes, which always holds
    /// the whole reply.
    ///
    /// φ7 instance, φ8 method, φ9/φ10 arguments, φ11 output, φ12 capacity →
    /// φ7 the length of the callee's reply or error detail, φ8 0 when it
    /// replied, [`super::failure::HANDLER`] when it failed (its writes are
    /// discarded), or [`super::failure::FORBIDDEN`] when the calling
    /// instance lacks the callee's role (the callee never ran). Any other
    /// failure of the callee fails the whole step. A query may call only
    /// queries.
    pub const CALL: u64 = 0x520;
    /// φ7 agent, φ8 instance, φ9 method, φ10/φ11 arguments. Delivered after
    /// the step commits.
    pub const SEND: u64 = 0x521;
    /// φ7 an attestable method of this instance's package, φ8/φ9
    /// arguments, φ10 output, φ11 capacity → φ7 the output's length, φ8 0
    /// or a [`super::failure`] code. The agent runs the program the package
    /// bound to the method at install, never one the caller names. As with
    /// `CALL`, the output should hold [`super::cap::REPLY`] bytes.
    pub const ATTEST: u64 = 0x522;
    /// → φ7 the instance, φ8 the agent.
    pub const SELF_ID: u64 = 0x523;
}

/// Whether an invocation of `kind` may use operation `op`. `CALL` from a
/// query is allowed here; the agent also refuses a query that calls a
/// command.
pub const fn allowed(kind: Kind, op: u64) -> bool {
    match kind {
        Kind::Attestable => false,
        Kind::Query => matches!(
            op,
            op::INPUT
                | op::REPLY
                | op::FAIL
                | op::LOG
                | op::CALLER
                | op::NOW
                | op::RANDOM
                | op::GET
                | op::SCAN
                | op::CALL
                | op::SELF_ID
        ),
        Kind::Command => matches!(
            op,
            op::INPUT
                | op::REPLY
                | op::FAIL
                | op::LOG
                | op::CALLER
                | op::NOW
                | op::RANDOM
                | op::GET
                | op::PUT
                | op::DELETE
                | op::SCAN
                | op::CALL
                | op::SEND
                | op::ATTEST
                | op::SELF_ID
        ),
    }
}

/// Gas an operation costs the actor. Placeholders until 2.4 measures the
/// serving cost.
pub mod price {
    pub const OPERATION: u64 = 500;
    pub const PER_BYTE: u64 = 1;
}

/// Per-step limits.
pub mod cap {
    pub const REQUEST: usize = 64 << 10;
    pub const REPLY: usize = 64 << 10;
    pub const KEY: usize = 1 << 10;
    pub const VALUE: usize = 64 << 10;
    pub const STEP_WRITES: usize = 256 << 10;
    /// One scan's output: room for a row at the key and value caps with
    /// both length prefixes.
    pub const SCAN: usize = KEY + VALUE + 16;
    pub const MESSAGES: usize = 16;
    pub const MESSAGE: usize = 64 << 10;
    pub const WORK_RESULT: usize = 4 << 20;
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

/// Why a step failed, in [`crate::result::Outcome::Failed`], or why a call
/// returned an error, in φ8 of `CALL` and `ATTEST`. A failed step consumes
/// its input.
pub mod failure {
    /// The handler failed; the detail is its encoded error.
    pub const HANDLER: u32 = 1;
    /// The invocation trapped, faulted, used an operation outside its kind
    /// or a buffer it could not reach.
    pub const TRAPPED: u32 = 2;
    pub const OUT_OF_GAS: u32 = 3;
    /// A per-step cap was exceeded.
    pub const CAP: u32 = 4;
    /// The caller lacks the handler's role.
    pub const FORBIDDEN: u32 = 5;
    /// No such instance or method.
    pub const UNKNOWN: u32 = 6;
    /// The callee is already on the call stack.
    pub const CYCLE: u32 = 7;
    /// No inner machine was left for the callee.
    pub const DEPTH: u32 = 8;
}

/// Why refine refused an input, in [`crate::result::Step::Refused`]. A
/// refused input is not consumed: no mark advances.
pub mod refusal {
    /// Out of its session's or pair's order.
    pub const SEQUENCE: u32 = 1;
    /// Its session expired.
    pub const EXPIRED: u32 = 2;
}
