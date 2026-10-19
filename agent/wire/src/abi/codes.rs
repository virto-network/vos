//! The closed sets of codes the agent and its actors exchange.

use alloc::vec::Vec;

use scale::{Decode, Encode};

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
    /// call returned an error, in φ8 of [`super::Op::Call`] and
    /// [`super::Op::Attest`]. A failed step consumes its input.
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
        /// A workflow's step came past what its target keeps of its pages
        /// ([`super::cap::Limits::pages_kept`]): it ends without them.
        Expired = 12,
        /// An install named another target than its agent's: an agent runs
        /// on one host, and every instance installed into it takes its
        /// target ([`super::cap::Target`]).
        Target = 13,
        /// An install named another space, or another clock, than its
        /// agent's: an agent belongs to one space, whose clock is frozen in
        /// its genesis.
        Space = 14,
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
