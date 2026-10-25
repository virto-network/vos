//! [`ModelVenue`], a venue modelled in memory: its spaces, their anchor
//! keys and anchors, and the statements it accepted, judged by
//! `vos_anchor::venue`'s rules (`spaces-pallet.md` §6.1–§6.3) and
//! `vos_statement::judge`. A second root for one `(space, kind, w)` is kept
//! as evidence and ends the space for good. Its anchor keys are kept by
//! space, the founding ones first, added and removed as
//! `spaces-pallet.md`'s controller does.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use vos_anchor::venue::{
    self as rules, Anchoring, Held, RegisterRefusal, Roots, Status as Standing, VenueState,
};
use vos_anchor::{
    Anchor, MAX_FOUNDING_KEYS, RootKind, RootRead, SpaceGenesis, SpaceId, VenueId, WindowClock,
};
use vos_statement::{ProgramId, Statement, StatementId, Venue};

use crate::{AnchorRefusal, Anchored, NotAccepted, Status, VenueClient};

/// A space a venue registered.
struct Registered {
    clock: WindowClock,
    start: u64,
    standing: Standing,
    /// Its anchor keys: the founding ones, then those added.
    keys: Vec<[u8; 32]>,
    last: Option<u64>,
}

#[derive(Default)]
struct State {
    spaces: BTreeMap<SpaceId, Registered>,
    /// The programs whose statements it judges.
    pins: Vec<ProgramId>,
    /// Each equivocation: the anchor held, and the other.
    evidence: Vec<(Anchor, Anchor)>,
    /// The anchors held, by space, kind and window.
    anchors: BTreeMap<(SpaceId, RootKind, u64), Anchor>,
    /// The statements accepted, each with its `Seen` entry's expiry.
    seen: Vec<(StatementId, u64)>,
}

/// A venue modelled in memory, timed by its own clock.
pub struct ModelVenue {
    id: VenueId,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    state: Mutex<State>,
}

/// The venue's state at its time, as the rules read it.
struct View<'a> {
    id: VenueId,
    state: &'a State,
    now: u64,
}

impl Roots for View<'_> {
    fn now(&self) -> u64 {
        self.now
    }

    fn space(&self, space: &SpaceId) -> Option<rules::Space> {
        self.state.spaces.get(space).map(|space| rules::Space {
            clock: space.clock,
            start: space.start,
            status: space.standing,
        })
    }

    fn held(&self, space: &SpaceId, kind: RootKind, window: u64) -> Option<Held> {
        self.state
            .anchors
            .get(&(*space, kind, window))
            .map(|anchor| Held {
                root: anchor.root,
                signer: anchor.signer,
            })
    }
}

impl VenueState for View<'_> {
    fn venue(&self) -> VenueId {
        self.id
    }

    fn listed(&self, space: &SpaceId, key: &[u8; 32]) -> bool {
        self.state
            .spaces
            .get(space)
            .is_some_and(|space| space.keys.contains(key))
    }

    fn last(&self, space: &SpaceId, _: RootKind) -> Option<u64> {
        self.state.spaces.get(space)?.last
    }

    fn verify(&self, key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        crate::verify(key, digest, signature)
    }
}

impl Venue for View<'_> {
    fn accepts(&self, format: u32) -> bool {
        vos_statement::LINKED.contains(&format)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        rules::anchored(self, root)
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.state.seen.iter().any(|(seen, _)| seen == id)
    }
}

impl ModelVenue {
    /// A venue named `id`, accepting final proofs of the formats this
    /// build links, timed by `now` (milliseconds since the Unix epoch).
    pub fn new(id: VenueId, now: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            id,
            now,
            state: Mutex::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn view<'a>(&self, state: &'a State) -> View<'a> {
        View {
            id: self.id,
            state,
            now: (self.now)(),
        }
    }

    /// Register the space `genesis` founds under `controller`, signed by
    /// its founding key `founder_key` (`spaces-pallet.md` §6.2): its id,
    /// anchoring from the venue's next window, its founding keys its anchor
    /// keys.
    pub fn register(
        &self,
        genesis: &SpaceGenesis,
        controller: &[u8; 32],
        founder_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<SpaceId, RegisterRefusal> {
        let registration = rules::registration(
            &self.id,
            genesis,
            controller,
            founder_key,
            signature,
            crate::verify,
        )?;
        let mut state = self.state();
        let start = rules::register(&self.view(&state), &registration)?;
        state.spaces.insert(
            registration.space,
            Registered {
                clock: registration.clock,
                start,
                standing: Standing::Active,
                keys: registration.keys,
                last: None,
            },
        );
        Ok(registration.space)
    }

    /// The space `genesis` founds set registered, anchoring from `start`,
    /// as a test's setup sets a venue's state, no registration's check
    /// made: its id.
    pub fn seed(&self, genesis: &SpaceGenesis, start: u64) -> SpaceId {
        let space = vos_anchor::space_id(genesis);
        self.state().spaces.insert(
            space,
            Registered {
                clock: genesis.clock,
                start,
                standing: Standing::Active,
                keys: genesis.nodes.iter().map(|(_, key)| *key).collect(),
                last: None,
            },
        );
        space
    }

    /// Judge statements of `program`.
    pub fn pin(&self, program: ProgramId) {
        self.state().pins.push(program);
    }

    /// Add `key` to `space`'s anchor keys, as the controller's
    /// `add_authority` pairs one: false when the space is not registered,
    /// the key is registered already or of small order, or it holds
    /// [`MAX_FOUNDING_KEYS`] (Kreivo's `MaxAnchorKeys`).
    pub fn add_anchor_key(&self, space: &SpaceId, key: [u8; 32]) -> bool {
        let mut state = self.state();
        let Some(space) = state.spaces.get_mut(space) else {
            return false;
        };
        if space.keys.contains(&key)
            || space.keys.len() >= MAX_FOUNDING_KEYS
            || rules::small_order(&key)
        {
            return false;
        }
        space.keys.push(key);
        true
    }

    /// Remove `key` from `space`'s anchor keys, as the controller's
    /// `remove_anchor_key` does: false when it is not one.
    pub fn remove_anchor_key(&self, space: &SpaceId, key: &[u8; 32]) -> bool {
        let mut state = self.state();
        let Some(space) = state.spaces.get_mut(space) else {
            return false;
        };
        let before = space.keys.len();
        space.keys.retain(|held| held != key);
        space.keys.len() < before
    }

    /// The equivocations kept: each the anchor held and the other.
    pub fn evidence(&self) -> Vec<(Anchor, Anchor)> {
        self.state().evidence.clone()
    }

    /// `space`'s clock, once registered.
    pub fn clock(&self, space: &SpaceId) -> Option<WindowClock> {
        self.state().spaces.get(space).map(|space| space.clock)
    }

    /// The first window `space` anchors at, once registered.
    pub fn start(&self, space: &SpaceId) -> Option<u64> {
        self.state().spaces.get(space).map(|space| space.start)
    }

    /// The anchors held of `space`, in window order.
    pub fn anchors(&self, space: &SpaceId) -> Vec<Anchor> {
        self.state()
            .anchors
            .iter()
            .filter(|((of, ..), _)| of == space)
            .map(|(_, anchor)| *anchor)
            .collect()
    }
}

impl VenueClient for ModelVenue {
    fn id(&self) -> VenueId {
        self.id
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        let mut state = self.state();
        let anchoring = rules::anchor(&self.view(&state), anchor)?;
        let at = (anchor.space, anchor.kind, anchor.window);
        let space = state.spaces.get_mut(&anchor.space);
        match (anchoring, space) {
            (Anchoring::Again, _) => Ok(Anchored::Again),
            (Anchoring::New, Some(space)) => {
                space.last = Some(anchor.window);
                state.anchors.insert(at, *anchor);
                Ok(Anchored::New)
            }
            (Anchoring::Evidence(_), Some(space)) => {
                space.standing = Standing::Ended;
                let held = state.anchors.get(&at).copied();
                state.evidence.extend(held.map(|held| (held, *anchor)));
                Err(AnchorRefusal::Equivocation)
            }
            (_, None) => Err(AnchorRefusal::Unregistered),
        }
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let mut state = self.state();
        // A program it pinned none for is refused as `judge` refuses another
        // program than the pinned one, after the format: no program id has a
        // word at `u32::MAX`.
        let program = state
            .pins
            .iter()
            .find(|pinned| **pinned == statement.program)
            .copied()
            .unwrap_or(ProgramId([u32::MAX; 8]));
        let view = self.view(&state);
        let id =
            vos_statement::judge(&view, &program, statement, proof).map_err(NotAccepted::from)?;
        let expiry = state
            .spaces
            .get(&statement.space)
            .map_or(u64::MAX, |space| {
                vos_statement::seen_expiry(statement, &space.clock)
            });
        state.seen.push((id, expiry));
        Ok(id)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        rules::anchored(&self.view(&self.state()), root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.state()
            .spaces
            .get(space)
            .map(|space| space.keys.clone())
            .unwrap_or_default()
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.state()
            .spaces
            .get(space)
            .map_or(Status::Unregistered, |space| space.standing.into())
    }

    fn time(&self) -> Option<u64> {
        Some((self.now)())
    }

    /// None: it takes or refuses each anchor at once.
    fn unsettled(&self, _: &SpaceId) -> Vec<Anchor> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
