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
