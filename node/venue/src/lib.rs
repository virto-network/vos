//! A venue as a VOS node reaches it ([`VenueClient`]): the representative's
//! leader anchors the space's root of each window it closes, a prover
//! submits statements, and either asks what is anchored. Its id names the
//! venue in every anchor's digest.
//!
//! [`ModelVenue`] keeps a venue's state as `vos_statement::model` does, its
//! anchors and the statements it accepted as lists, and checks what pin D
//! and pin F say a venue checks: the anchor rule (a registered,
//! unsuspended space; a registered key; the signature; `Last < w < now_w`;
//! the root no older than `MaxRootAge`; the window within the space's
//! range here, which a migration away ends) and `judge`. A second root for
//! one `(space, kind, w)` is kept as evidence and suspends the space. Its
//! anchor keys are kept by space, the founding ones first, added and
//! removed as `spaces-pallet.md`'s controller does, and `resume` lifts a
//! suspension once neither equivocating key is registered.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::{Signature, VerifyingKey};
use vos_anchor::{
    Anchor, MAX_FOUNDING_KEYS, MAX_ROOT_AGE_MS, Migrate, RootRead, SpaceGenesis, SpaceId, VenueId,
    WindowClock,
};
use vos_statement::model::{Policy, Range, Space};
use vos_statement::{Pin, ProgramId, Refusal, Statement, StatementId, Venue};

/// What a node asks of a venue.
pub trait VenueClient: Send + Sync {
    /// The venue's id, which an anchor's signature binds.
    fn id(&self) -> VenueId;
    /// Anchor a space's root of a window.
    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal>;
    /// Submit a statement and its final proof: its id once accepted.
    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, Refusal>;
    /// Whether `root` is anchored, its space's root of its kind at its
    /// window.
    fn anchored(&self, root: &RootRead) -> bool;
    /// The anchor keys `space` has registered here (Kreivo's `AnchorKeys`):
    /// none when it is not registered, or the venue cannot say.
    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]>;
}

/// An anchor the venue took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchored {
    /// Its root is now the space's at its window.
    New,
    /// The venue held that root already: a second leader's anchor, or the
    /// same leader's again.
    Again,
}

/// Why a venue refuses an anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorRefusal {
    /// The space is not registered.
    Unregistered,
    /// The space is suspended: it equivocated.
    Suspended,
    /// The signer is not one of the space's anchor keys.
    Key,
    /// The signature is not the signer's over the anchor's digest.
    Signature,
    /// The window is not past the last anchored, before the space's
    /// start, or at or past its migration away: refused for good.
    Window,
    /// The window is the space's open one, or later, by the venue's clock:
    /// refused until the venue's time passes its boundary.
    Open,
    /// The window's boundary is older than `MaxRootAge`.
    Age,
    /// Another root of the space's kind at the window is anchored: this
    /// one is kept as evidence, and the space is suspended.
    Equivocation,
}

/// Why a venue refuses a space's migration away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrateRefusal {
    /// The space is not registered.
    Unregistered,
    /// It names another venue to leave, or this one to go to.
    Venue,
    /// The space migrated away already.
    AlreadyMigrated,
    /// Its window is at or before one anchored, before the venue's next
    /// window, or before the space's start here.
    Window,
}

/// A space a venue registered.
struct Registered {
    clock: WindowClock,
    /// Its anchor keys: the founding ones, then those added.
    keys: Vec<[u8; 32]>,
    range: Range,
    last: Option<u64>,
    suspended: bool,
}

struct State {
    policy: Policy,
    spaces: BTreeMap<SpaceId, Registered>,
    /// What it pinned for the programs whose statements it judges.
    pins: Vec<Pin>,
    /// Each equivocation: the anchor held, and the other.
    evidence: Vec<(Anchor, Anchor)>,
    /// The anchors held, by space, kind and window.
    anchors: BTreeMap<(SpaceId, u8, u64), Anchor>,
}

/// A venue modelled in memory, timed by its own clock.
pub struct ModelVenue {
    id: VenueId,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    state: Mutex<State>,
}

/// The venue's view a judgement reads: a suspended space's roots are not
/// anchored.
struct View<'a> {
    state: &'a State,
    now: u64,
}

impl Venue for View<'_> {
    fn id(&self) -> VenueId {
        self.state.policy.venue
    }

    fn accepts(&self, format: u32) -> bool {
        self.state.policy.formats.contains(&format)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        held(self.state, root, self.now)
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.state.policy.seen(id)
    }
}

/// Whether `state` holds `root` anchored at `now`: its space registered and
/// not suspended, its window within the space's range here, the root no
/// older than `MaxRootAge`.
fn held(state: &State, root: &RootRead, now: u64) -> bool {
    let Some(space) = state.spaces.get(&root.space) else {
        return false;
    };
    let fresh = space
        .clock
        .boundary(root.window)
        .is_some_and(|boundary| now.saturating_sub(boundary) <= MAX_ROOT_AGE_MS);
    !space.suspended
        && space.range.contains(root.window)
        && fresh
        && state.policy.anchors.contains(root)
}

impl ModelVenue {
    /// A venue named `id`, accepting final proofs of the formats this
    /// build links, timed by `now` (milliseconds since the Unix epoch).
    pub fn new(id: VenueId, now: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        let state = State {
            policy: Policy::new(id, now(), vos_statement::LINKED),
            spaces: BTreeMap::new(),
            pins: Vec::new(),
            evidence: Vec::new(),
            anchors: BTreeMap::new(),
        };
        Self {
            id,
            now,
            state: Mutex::new(state),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Register the space `genesis` founds, anchoring from `start`: its
    /// founding keys its anchor keys. Its id.
    pub fn register(&self, genesis: &SpaceGenesis, start: u64) -> SpaceId {
        let space = vos_anchor::space_id(genesis);
        let range = Range {
            from: start,
            until: None,
        };
        let registered = Registered {
            clock: genesis.clock,
            keys: genesis.nodes.iter().map(|(_, key)| *key).collect(),
            range,
            last: None,
            suspended: false,
        };
        let mut state = self.state();
        state.spaces.insert(space, registered);
        state.policy.spaces.push(Space {
            id: space,
            clock: genesis.clock,
            range,
        });
        space
    }

    /// A space's migration away from this venue, its controller's
    /// (`spaces-pallet.md` call 5): the space's range here ends before
    /// `from_window`, so neither its anchors nor the roots of its
    /// statements at or past it are taken. Refused unless it names a
    /// registered space leaving this venue for another, once, from a window
    /// past every one anchored and not before the venue's next.
    pub fn migrate(&self, migrate: &Migrate) -> Result<(), MigrateRefusal> {
        if migrate.from != self.id || migrate.to == self.id {
            return Err(MigrateRefusal::Venue);
        }
        let now = (self.now)();
        let mut state = self.state();
        let space = state
            .spaces
            .get_mut(&migrate.space)
            .ok_or(MigrateRefusal::Unregistered)?;
        if space.range.until.is_some() {
            return Err(MigrateRefusal::AlreadyMigrated);
        }
        let next = space
            .clock
            .window(now)
            .map_or(0, |open| open.saturating_add(1));
        let anchored = space.last.is_some_and(|last| migrate.from_window <= last);
        if anchored || migrate.from_window < next || migrate.from_window < space.range.from {
            return Err(MigrateRefusal::Window);
        }
        space.range.until = Some(migrate.from_window);
        let range = space.range;
        if let Some(space) = state
            .policy
            .spaces
            .iter_mut()
            .find(|space| space.id == migrate.space)
        {
            space.range = range;
        }
        Ok(())
    }

    /// Judge statements of `pin`'s program.
    pub fn pin(&self, pin: Pin) {
        self.state().pins.push(pin);
    }

    /// Whether `space` is suspended.
    pub fn suspended(&self, space: &SpaceId) -> bool {
        self.state()
            .spaces
            .get(space)
            .is_some_and(|space| space.suspended)
    }

    /// Add `key` to `space`'s anchor keys, as the controller's
    /// `add_authority` pairs one: false when the space is not registered,
    /// the key is registered already, or it holds [`MAX_FOUNDING_KEYS`]
    /// (Kreivo's `MaxAnchorKeys`).
    pub fn add_anchor_key(&self, space: &SpaceId, key: [u8; 32]) -> bool {
        let mut state = self.state();
        let Some(space) = state.spaces.get_mut(space) else {
            return false;
        };
        if space.keys.contains(&key) || space.keys.len() >= MAX_FOUNDING_KEYS {
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

    /// Lift `space`'s suspension, as the controller's `resume` does: only
    /// once neither signer of any of its equivocations is still one of its
    /// anchor keys, which then clears its evidence. Whether it is active.
    pub fn resume(&self, space: &SpaceId) -> bool {
        let mut state = self.state();
        let state = &mut *state;
        let Some(registered) = state.spaces.get_mut(space) else {
            return false;
        };
        let signed_by_a_key = state
            .evidence
            .iter()
            .filter(|(held, _)| held.space == *space)
            .any(|(held, other)| {
                registered.keys.contains(&held.signer) || registered.keys.contains(&other.signer)
            });
        if signed_by_a_key {
            return !registered.suspended;
        }
        registered.suspended = false;
        state.evidence.retain(|(held, _)| held.space != *space);
        true
    }

    /// The equivocations kept: each the anchor held and the other.
    pub fn evidence(&self) -> Vec<(Anchor, Anchor)> {
        self.state().evidence.clone()
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
        let now = (self.now)();
        let mut state = self.state();
        let state = &mut *state;
        let space = state
            .spaces
            .get_mut(&anchor.space)
            .ok_or(AnchorRefusal::Unregistered)?;
        if space.suspended {
            return Err(AnchorRefusal::Suspended);
        }
        if !space.keys.contains(&anchor.signer) {
            return Err(AnchorRefusal::Key);
        }
        let signed = VerifyingKey::from_bytes(&anchor.signer).is_ok_and(|key| {
            key.verify_strict(
                &anchor.digest(&self.id),
                &Signature::from_bytes(&anchor.signature),
            )
            .is_ok()
        });
        if !signed {
            return Err(AnchorRefusal::Signature);
        }
        let at = (anchor.space, anchor.kind as u8, anchor.window);
        if let Some(held) = state.anchors.get(&at) {
            if held.root == anchor.root {
                return Ok(Anchored::Again);
            }
            state.evidence.push((*held, *anchor));
            space.suspended = true;
            return Err(AnchorRefusal::Equivocation);
        }
        let within = space.range.contains(anchor.window)
            && space.last.is_none_or(|last| last < anchor.window);
        if !within {
            return Err(AnchorRefusal::Window);
        }
        if space
            .clock
            .window(now)
            .is_none_or(|open| anchor.window >= open)
        {
            return Err(AnchorRefusal::Open);
        }
        let boundary = space.clock.boundary(anchor.window);
        if boundary.is_none_or(|boundary| now.saturating_sub(boundary) > MAX_ROOT_AGE_MS) {
            return Err(AnchorRefusal::Age);
        }
        space.last = Some(anchor.window);
        state.anchors.insert(at, *anchor);
        state.policy.anchors.push(RootRead {
            kind: anchor.kind,
            space: anchor.space,
            window: anchor.window,
            root: anchor.root,
        });
        Ok(Anchored::New)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, Refusal> {
        let now = (self.now)();
        let mut state = self.state();
        // A program it pinned none for is refused as `judge` refuses
        // another program than the pinned one, after the format.
        let pin = state
            .pins
            .iter()
            .find(|pinned| pinned.program == statement.program)
            .copied()
            .unwrap_or(Pin {
                program: ProgramId([u32::MAX; 8]),
                venue_bound: false,
            });
        let view = View { state: &state, now };
        let id = vos_statement::judge(&view, &pin, statement, proof)?;
        state.policy.now_ms = now;
        state.policy.record(statement);
        Ok(id)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        held(&self.state(), root, (self.now)())
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.state()
            .spaces
            .get(space)
            .map(|space| space.keys.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod kreivo;
#[cfg(test)]
mod tests;
