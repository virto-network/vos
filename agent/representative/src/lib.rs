//! The space's representative: the system agent that keeps each agent's
//! root at each window's cut in one committed map, so its own root at its
//! cut of a window, `A_rep`, commits to every agent's, and the space's root
//! of the window is `S_w = BLAKE2b-256("vos/space/v1" ‖ space ‖ w ‖ A_rep)`.
//!
//! Its clock is the space's, its origin later by
//! `D = min(L / 5, 2 min)`, so its own cut of window w, at `B_w + D`, closes
//! the window: the reports applied before it are in `A_rep`, the later
//! ones are not. Each agent's leader reports its root after its cut's
//! build ([`vos_wire::batch::Input::Report`]); the representative's node
//! builds its tree at its cut, signs the anchor of `S_w` and sends each
//! agent that asked its row's path ([`vos_wire::batch::Input::Close`]).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use vos_sdk::prelude::*;

/// An agent's root's row: the agent, the root's kind, the window, as
/// `vos_wire::served::representative_row` keys it.
pub type RepKey = (u32, (u8, u64));

/// How many windows before the one an agent reports its rows are kept:
/// the close of a window reads only that window's rows.
pub const KEPT: u64 = 2;

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

    /// An agent's report of `root`, its root of `kind` at window
    /// `window`'s cut, the agent its sender; with `pending`, its reads wait
    /// on the window's close. Its rows of windows before `window − KEPT`
    /// go, and its asks of those windows with them; no other agent's. A
    /// report from no agent, or of a kind but the space's, is dropped.
    #[msg]
    pub async fn report(
        &mut self,
        ctx: &mut Command<Self>,
        kind: u8,
        window: u64,
        root: [u8; 32],
        pending: bool,
    ) {
        let Principal::Agent(agent) = ctx.caller() else {
            return;
        };
        if kind != 0 {
            return;
        }
        self.roots.insert(&(agent.0, (kind, window)), &root);
        if pending {
            self.asked.insert(&(window, agent.0), &());
        }
        let Some(oldest) = window.checked_sub(KEPT) else {
            return;
        };
        let start = agent
            .0
            .checked_sub(1)
            .map(|before| (before, (u8::MAX, u64::MAX)));
        let stale: Vec<RepKey> = self
            .roots
            .iter(start.as_ref())
            .map(|(key, _)| key)
            .take_while(|(of, (_, at))| *of == agent.0 && *at < oldest)
            .collect();
        // An agent's asks go with its rows: a report touches no other
        // agent's.
        for key in &stale {
            let (of, (_, at)) = *key;
            self.roots.remove(key);
            self.asked.remove(&(at, of));
        }
    }
}
