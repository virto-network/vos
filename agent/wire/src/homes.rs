//! The home's wire types (`light-node.md` §3.3): what its actor, `Homes`,
//! takes and answers. `Homes` lives in the agent that holds the home's
//! credential actor, keeps a pool of personal agents the keeper made, and
//! assigns one to each claim under `Auth("home")`, indexing it by the
//! claiming device's nullifier and by each recovery kit's key.

use alloc::vec::Vec;

use scale::{Decode, Encode};

use crate::personal::Policy;

/// `Homes`' handlers.
pub mod method {
    methods! {
        CONFIGURE = "configure";
        STOCK = "stock";
        RELEASE = "release";
        CLAIM = "claim";
        RENEW = "renew";
        ASSIGNED = "assigned";
        REFUSED = "refused";
        RECORD = "record";
        FORGET = "forget";
        REKEY = "rekey";
        POOLED = "pooled";
        AGENT = "agent";
        SPENT = "spent";
        FIND = "find";
        STANDING_OF = "standing_of";
        TALLY = "tally";
        AGENTS = "agents";
        CONFIGURED = "configured";
    }
}

/// The auth guard's name, and the scope's, of a claim and a re-proof: the
/// light node proves in it only for these.
pub const SCOPE: &[u8] = b"home";

/// The most agents a `stock` takes, and a page of `agents` answers.
pub const PAGE: usize = 256;

/// Where `Homes` finds `Personal` in its pool's agents, and the policy it
/// configures each with before assigning it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Terms {
    /// `Personal`'s instance in every agent of the pool.
    pub instance: u32,
    pub policy: Policy,
}

/// A pool agent's standing at `Homes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Standing {
    /// Stocked, waiting for a claim.
    #[codec(index = 0)]
    Pooled,
    /// Sent to a claim; `Personal`'s answer not yet in.
    #[codec(index = 1)]
    Claimed,
    /// `Personal` took the claim.
    #[codec(index = 2)]
    Assigned,
    /// `Personal` refused the claim as already assigned, or the operator
    /// released a claim never answered: never pooled again.
    #[codec(index = 3)]
    Retired,
}

/// Why `Homes` refused a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum HomesError {
    /// No pooled agent is left: the keeper tops the pool up, and the
    /// device stays local and retries.
    #[codec(index = 0)]
    PoolEmpty,
    /// The nullifier holds an agent already.
    #[codec(index = 1)]
    Claimed,
    /// A kit's key indexes another agent.
    #[codec(index = 2)]
    KitTaken,
    /// The claiming device's nullifier is not the proof's.
    #[codec(index = 3)]
    Nullifier,
    /// The nullifier is recorded for no such agent.
    #[codec(index = 4)]
    NotRecorded,
    /// No agent of the pool by that id, or not one in the standing asked.
    #[codec(index = 5)]
    Unknown,
    /// More than [`PAGE`] agents in one call.
    #[codec(index = 6)]
    TooMany,
    /// A kit of more entries than `Personal` takes, or one key twice among
    /// the device's and the kit's.
    #[codec(index = 7)]
    Malformed,
    /// No terms set yet: `configure` first.
    #[codec(index = 8)]
    Unconfigured,
    /// Not the proof of a member's pseudonym.
    #[codec(index = 9)]
    Anonymous,
    /// The agent named is not pooled: another claim took it, or it never
    /// was. The device seals its kit to the agent `pooled` answers now.
    #[codec(index = 10)]
    Taken,
    /// The nullifier's device left or was removed within the home's
    /// removal delay: it claims again once `spent` says the delay passed.
    #[codec(index = 11)]
    Spent,
}

/// A page of the pool's agents by id, from after the last one asked:
/// `more` when agents remain past it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AgentsPage {
    pub agents: Vec<(u32, Standing)>,
    pub more: bool,
}

/// The pool's counts: agents pooled, sent and assigned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Counts {
    pub pooled: u32,
    pub claimed: u32,
    pub assigned: u32,
}
