//! A read at a window's cut as a node serves it to the kernel: the rows,
//! their proof against the agent's root at the cut, and that root's path in
//! the space's representative's tree, from which the kernel's prologue
//! computes the space root `S_w` it states.
//!
//! The representative keeps each agent's root at each window's cut in a
//! committed map of ordered keys, [`representative_map`], each row
//! `RepKey = agent (4, BE) ‖ kind (1) ‖ w (8, BE)` ([`representative_row`]).
//! Its own root at its cut of the window is `A_rep`, and
//! `S_w = BLAKE2b-256("vos/space/v1" ‖ space ‖ w (8, LE) ‖ A_rep)`
//! ([`space_root`], `vos_anchor::space_root` computed through the
//! compression precompile).

use alloc::vec::Vec;

use crate::ids::{AgentId, InstanceId, MapId};
use crate::keys::{self, Transform};
use crate::vos_anchor::{RootKind, SpaceId};
use crate::{Decode, Encode};

/// A row a read names, by its full key, with its leaf's salt and bare value
/// at the cut, or `None` when absent there.
pub type ReadRow = (Vec<u8>, Option<([u8; 16], Vec<u8>)>);

/// The witness of a read at window `window`'s cut, inline in its
/// [`crate::batch::Input::Resume`] and, after the call's arguments, in its
/// kernel's witness input.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Served {
    pub space: SpaceId,
    pub window: u64,
    pub agent: AgentId,
    pub instance: InstanceId,
    /// The agent's root at `cut(w)`.
    pub agent_root: [u8; 32],
    /// The representative's root at its cut of the window, `A_rep`.
    pub rep_root: [u8; 32],
    /// The salt of the representative's leaf of
    /// `RepKey(agent, Space, w)`, which its value's commitment takes.
    pub rep_salt: [u8; 16],
    /// A `vos_tree::BatchProof`'s encoding: `RepKey(agent, Space, w)` holds
    /// `agent_root`, against `rep_root`.
    pub space_path: Vec<u8>,
    /// The rows read, strictly increasing by key.
    pub rows: Vec<ReadRow>,
    /// One `vos_tree::BatchProof`'s encoding of the rows against
    /// `agent_root`.
    pub rows_proof: Vec<u8>,
}

/// The representative's instance in its agent.
pub const REPRESENTATIVE: InstanceId = InstanceId(0);

/// The name of the representative's committed map of agents' roots, its
/// tag's source as `#[actor]` derives one.
pub const REPRESENTATIVE_ROOTS: &str = "roots";

/// The tag [`REPRESENTATIVE_ROOTS`] derives
/// (`crate::ids::derive_id("vos/table/", "roots")`), a constant so a
/// kernel's prologue hashes nothing for it.
pub const REPRESENTATIVE_TAG: u32 = 0x4b14_a09e;

/// The representative's committed map of agents' roots at their cuts.
pub const fn representative_map() -> MapId {
    MapId {
        instance: REPRESENTATIVE,
        tag: REPRESENTATIVE_TAG,
        transform: Transform::Ordered,
    }
}

/// The full key of the representative's row of `agent`'s root of `kind` at
/// window `window`'s cut.
pub fn representative_row(agent: AgentId, kind: RootKind, window: u64) -> Vec<u8> {
    let mut raw = [0u8; 13];
    raw[..4].copy_from_slice(&agent.0.to_be_bytes());
    raw[4] = kind as u8;
    raw[5..].copy_from_slice(&window.to_be_bytes());
    keys::committed(&representative_map(), &Transform::Ordered.apply(&raw))
}

/// The space root of window `window` over the representative's root
/// `rep_root`, as `vos_anchor::space_root`.
pub fn space_root(space: &SpaceId, window: u64, rep_root: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(
        crate::vos_anchor::SPACE_ROOT_DOMAIN,
        &[&space.0, &window.to_le_bytes(), rep_root],
    )
}
