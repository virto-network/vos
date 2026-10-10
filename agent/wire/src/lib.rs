//! Wire types shared by the VOS node, the default agent program and the
//! actor SDK.
//!
//! Everything here is SCALE-coded with the workspace codec, the encoding JAM
//! uses, except the Gray Paper structures in [`jam`], which follow the Gray
//! Paper's own encoding.

#![no_std]

extern crate alloc;

pub mod abi;
pub mod batch;
pub mod ids;
pub mod ingress;
pub mod jam;
pub mod keys;
pub mod peer;
pub mod records;
pub mod result;
pub mod schema;

/// The expiry index's buckets.
pub mod expiry {
    use crate::defaults::{SESSION_BUCKET_MS, SESSION_EXPIRY_MS};

    /// The bucket a time falls in.
    pub const fn bucket(time: u64) -> u64 {
        time / SESSION_BUCKET_MS
    }

    /// The batch time from which every session whose mark lies in
    /// `bucket` has expired.
    pub const fn due(bucket: u64) -> u64 {
        (bucket + 1)
            .saturating_mul(SESSION_BUCKET_MS)
            .saturating_add(SESSION_EXPIRY_MS)
    }
}

pub use scale;
pub use scale::{Decode, DecodeError, Encode};

/// Defaults the owner set for slice 2. Each is a constant, cheap to change.
pub mod defaults {
    /// Replies kept per (session, agent), so a pipelining client can recover
    /// any lost reply.
    pub const REPLY_WINDOW: u64 = 64;
    /// A session expires after this much work-result time without a
    /// request, in milliseconds.
    pub const SESSION_EXPIRY_MS: u64 = 60 * 60 * 1000;
    /// A new session's creation time must be this close to the work
    /// result's time, in milliseconds.
    pub const SESSION_SKEW_MS: u64 = 60 * 1000;
    /// The expiry index files sessions by their time divided by this, in
    /// milliseconds: a session is collected at most this long after it
    /// expires.
    pub const SESSION_BUCKET_MS: u64 = 5 * 60 * 1000;
    /// The most expiry rows one sweep lists.
    pub const SWEEP_LIMIT: usize = 32;
    /// The most sessions an agent holds: more are refused until some are
    /// collected.
    pub const MAX_SESSIONS: u64 = 1 << 16;
    /// The most sessions one key holds at an agent.
    pub const MAX_KEY_SESSIONS: u64 = 64;

    // An expired session's batch time is past its t0 plus the skew: it was
    // created within the skew of t0, so a collected session can never be
    // created again.
    const _: () = assert!(SESSION_EXPIRY_MS >= 2 * SESSION_SKEW_MS);
    /// A handler's gas limit when its schema declares none: about 500
    /// gets, 150 puts or 5,000 register-only operations, or about 16,000
    /// BLAKE2b compressions.
    pub const HANDLER_GAS: u64 = 10_000_000;
    /// The most gas a handler's schema may request: node policy, which
    /// the agent and the testkit read here.
    pub const MAX_HANDLER_GAS: u64 = 100_000_000;
    /// A refine's gas budget: a hundred handlers at their default limit.
    pub const REFINE_GAS: u64 = 1_000_000_000;
    /// Gas a refine keeps for a request or message beyond its handler's
    /// limit, for the agent's own work: at most the first read of an
    /// installed record with a schema of `schema::MAX_LEN` bytes, about
    /// 3.2M, then the top machine and the step's framing. Checked once,
    /// before the step: a refine stops early by at most this much, and the
    /// node need not pack by it. Measured by the testkit's
    /// `the_step_reserve_covers_the_largest_install`.
    pub const STEP_RESERVE: u64 = 4_000_000;
    /// The same for an install: reading, validating and encoding a schema
    /// of `schema::MAX_LEN` bytes from its program's machine, about 6.3M.
    pub const INSTALL_RESERVE: u64 = 8_000_000;
    /// Gas a refine keeps to finish its result once its steps are written.
    pub const FINISH_RESERVE: u64 = 100_000;
    /// The most outbox entries one acknowledgement clears, bounding an ack
    /// step's accumulate work; the node acks again for the rest. Clearing
    /// them is a thousand storage deletions, far inside an accumulate's
    /// gas (`REFINE_GAS` on a node).
    pub const ACK_LIMIT: u64 = 1024;
}
