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

use scale::{Decode, Encode};

use crate::keys::Transform;

/// The kind of an invocation, which decides the operations it may use.
/// Its index is the kind the agent passes in φ8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
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

pub mod op {
    /// φ7 output, φ8 offset, φ9 capacity → φ7 the request's arguments'
    /// length.
    pub const INPUT: u64 = 0x500;
    /// φ7/φ8 the reply. The handler's outcome: a second `REPLY` or `FAIL`
    /// fails the invocation with [`super::Failure::Trapped`]. Halting
    /// without either replies empty.
    pub const REPLY: u64 = 0x501;
    /// φ7/φ8 the handler's encoded error: the step fails with
    /// [`super::Failure::Handler`] and this detail.
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
    /// φ7 [`super::Rows`], φ8/φ9 key, φ10 output, φ11 offset, φ12
    /// capacity → φ7 the value's length, or [`super::code::NONE`].
    pub const GET: u64 = 0x510;
    /// φ7 [`super::Rows`], φ8/φ9 key, φ10/φ11 value.
    pub const PUT: u64 = 0x511;
    /// φ7 [`super::Rows`], φ8/φ9 key.
    pub const DELETE: u64 = 0x512;
    /// φ7 a table's or committed map's [`super::Rows`], φ8/φ9 cursor, φ10
    /// output, φ11 capacity, φ12 1 for the rows after the cursor (a key) or
    /// 0 for the table's first rows → φ7 the bytes written: whole rows back
    /// to back in the table's order (hash order for a hashed table, key
    /// order for an ordered one), each the SCALE encoding of `(key, value)`
    /// as two byte vectors, the key as the actor wrote it. 0 when no rows
    /// remain; [`super::code::FULL`] when the next row alone exceeds the
    /// capacity.
    pub const SCAN: u64 = 0x513;
    /// The callee runs once: with a smaller output the agent copies what
    /// fits and returns the whole length, and the rest is lost. A caller
    /// passes an output of [`super::cap::REPLY`] bytes, which always holds
    /// the whole reply.
    ///
    /// φ7 instance, φ8 method, φ9/φ10 arguments, φ11 output, φ12 capacity →
    /// φ7 the length of the callee's reply or error detail, φ8 0 when it
    /// replied, [`super::Failure::Handler`] when it failed (its writes are
    /// discarded), or [`super::Failure::Forbidden`] when the calling
    /// instance lacks the callee's role (the callee never ran). Any other
    /// failure of the callee fails the whole step. A query may call only
    /// queries.
    pub const CALL: u64 = 0x520;
    /// φ7 agent, φ8 instance, φ9 method, φ10/φ11 arguments. Delivered after
    /// the step commits.
    pub const SEND: u64 = 0x521;
    /// φ7 an attestable method of this instance's package, φ8/φ9
    /// arguments, φ10 output, φ11 capacity → φ7 the output's length, φ8 0
    /// or a [`super::Failure`] code. The agent runs the program the package
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
    use super::op;

    /// An id the agent does not serve, and the operations that only read
    /// or set registers.
    pub const OPERATION: u64 = 2_000;
    pub const RANDOM: u64 = 6_000;
    pub const CALLER: u64 = 6_000;
    pub const LOG: u64 = 4_000;
    pub const SEND: u64 = 5_000;
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
    pub const fn of(id: u64) -> u64 {
        match id {
            op::GET => GET,
            op::PUT | op::DELETE => PUT,
            op::SCAN => SCAN,
            op::SEND => SEND,
            op::CALL | op::ATTEST => MACHINE,
            op::RANDOM => RANDOM,
            op::CALLER => CALLER,
            op::LOG => LOG,
            _ => OPERATION,
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

    /// The most one step adds to a work result: its input, a new session's
    /// whole, its reply, writes, messages and attests at their caps, a
    /// request's reply to its sender, with the framing of as many writes
    /// (committed ones, with their map, the larger) and instances as its
    /// gas can pay for. An install's record is under [`STEP_WRITES`] too.
    pub const STEP_RESULT: usize = 128
        + REPLY
        + STEP_WRITES
        + (MAX_HANDLER_GAS / price::PUT) as usize * 18
        + (1 + (MAX_HANDLER_GAS / price::MACHINE) as usize) * 12
        + MESSAGES * (MESSAGE + 40)
        + (REPLY + 40)
        + ATTESTS * (REQUEST + REPLY + 40);

    // Every step fits an empty result, so a batch always makes progress.
    const _: () = assert!(STEP_RESULT + 64 <= WORK_RESULT);
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

    /// Precompiles: the node computes them in place; elsewhere they answer
    /// `WHAT` and the shims compute in software.
    pub const PRECOMPILES: RangeInclusive<u64> = 0x400..=0x47f;
    /// The actor ABI, which an agent serves; ids it does not serve answer
    /// `WHAT`.
    pub const ACTOR_ABI: RangeInclusive<u64> = 0x500..=0x5ff;

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
        /// Applied state, which a JAM node cannot give until witnesses: the
        /// refine traps, so no result is computed on empty state.
        NoResult,
    }

    /// An agent program's call (refine and accumulate share its code):
    /// `None` when it is outside the surface.
    pub fn agent(id: u64) -> Option<OnJam> {
        match id {
            // gas, fetch, read, write, historical_lookup, machine..expunge,
            // log.
            0 | 2 | 4 | 5 | 7 | 9..=14 | 100 => Some(OnJam::Served),
            0x480 => Some(OnJam::Loader),
            0x481 | 0x482 => Some(OnJam::NoResult),
            _ if PRECOMPILES.contains(&id) => Some(OnJam::Software),
            _ => None,
        }
    }

    /// An actor program's call: the actor ABI or a precompile.
    pub fn actor(id: u64) -> bool {
        ACTOR_ABI.contains(&id) || PRECOMPILES.contains(&id)
    }

    /// An attestable program's call: a precompile only, as the prover
    /// needs.
    pub fn attestable(id: u64) -> bool {
        PRECOMPILES.contains(&id)
    }
}
