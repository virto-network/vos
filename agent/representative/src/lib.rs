//! The space's representative: the system agent that keeps each agent's
//! root at each window's cut in one committed map, so its own root at its
//! cut of a window, `A_rep`, commits to every agent's, and the space's root
//! of the window is `S_w = BLAKE2b-256("vos/space/v1" ‖ space ‖ w ‖ A_rep)`.
//!
//! Its clock is the space's, its origin later by
//! `D = min(L / 5, 2 min)`, so its own cut of window w, at `B_w + D`, closes
//! the window: the reports applied before it are in `A_rep`, the later
//! ones are not. Each agent's leader reports its root after its cut's
//! build ([`vos_wire::batch::Input::Report`]), which the agent's refine
//! sends as a [`vos_wire::batch::Body::Report`] and the representative's
//! refine stores natively in `roots` and `asked`, so no program's call can
//! write them; the actor declares them for its view. Its node
//! builds its tree at its cut, signs the anchor of `S_w` and sends each
//! agent that asked its row's path ([`vos_wire::batch::Input::Close`]).

#![no_std]

use vos_sdk::prelude::*;

/// An agent's root's row: the agent, the root's kind, the window, as
/// `vos_wire::served::representative_row` keys it.
pub type RepKey = (u32, (u8, u64));

#[actor]
pub struct Representative {
    /// Each agent's root at each window's cut.
    roots: CommittedMap<RepKey, [u8; 32], Ordered>,
    /// The agents whose reads wait on a window's close, by window: the
    /// close sends each its row's path.
    asked: Table<(u64, u32), (), Ordered>,
}

#[messages]
impl Representative {
    pub fn new() -> Self {
        Self {
            roots: CommittedMap::default(),
            asked: Table::default(),
        }
    }
}
