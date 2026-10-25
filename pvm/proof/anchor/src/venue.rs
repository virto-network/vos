//! A venue's rules, written once (`spaces-pallet.md` §6.1–§6.3): the
//! registration, the anchor rule, what is anchored, a `Seen` entry's expiry
//! and a root's freshness, as pure functions over the venue's state
//! ([`Roots`], [`VenueState`]). Every venue calls them: VOS's model venue,
//! the JAM statements service (its refine and its accumulate) and the
//! reference mock of Kreivo's spaces pallet, which the pallet itself is
//! asked to follow by calling them over its storage. A function decides;
//! the venue writes what it decided, in its own storage.
//!
//! - **Registration** ([`registration`], then [`register`]): a founding key
//!   signs `(venue, space, controller)` ([`crate::register_digest`]); the
//!   genesis holds 1 to [`MAX_FOUNDING_KEYS`] distinct keys, none of small
//!   order, and a window length the venue registers. The space is new at the
//!   venue (an ended one is never forgotten, so a replayed registration is
//!   refused), and it anchors from the venue's next window: no start is
//!   signed, so none can be replayed.
//! - **An anchor** ([`anchor`]): of a registered, active space; signed by a
//!   key it lists, strictly; at a window no older than [`MAX_ROOT_AGE_MS`];
//!   a second root at a window held is the evidence of an equivocation,
//!   which ends the space for good; otherwise the window is at or after the
//!   space's first, past its last anchored (gaps allowed) and closed by the
//!   venue's clock (`w < now_w`).
//! - **Anchored** ([`anchored`]): a root is its space's at its window while
//!   the space is active, the venue holds it, and it is fresh.
//! - **Time** ([`expiry`], [`fresh`], [`aged`], [`seen_expiry`]): a root of
//!   window w is fresh until `B_w + MaxRootAge` by the venue's clock; a
//!   statement's `Seen` entry may be dropped once its newest root is not.
//! - **Keys** ([`add_key`], [`small_order`]): at most
//!   [`MAX_FOUNDING_KEYS`] listed, none twice; a key of small order is never
//!   listed, at registration or later, so a venue whose ed25519 verification is
//!   cofactored still takes no signature such a key "makes" over any
//!   message.
//!
//! An ended space stays recorded at its venue for good: its roots are
//! refused from then on, it never anchors again, and it re-founds under a
//! new genesis to anchor anew.

use alloc::vec::Vec;

use crate::{
    Anchor, MAX_FOUNDING_KEYS, MAX_ROOT_AGE_MS, RootKind, RootRead, SpaceGenesis, SpaceId, VenueId,
    WindowClock, register_digest, space_id,
};

/// Where a registered space stands at a venue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// It anchors, and its roots count.
    Active,
    /// The venue's governance stopped it, for as long as it chooses
    /// (Kreivo's `set_status`): no anchor taken, no root counted.
    Blocked,
    /// It equivocated: no anchor taken and no root counted, for good.
    Ended,
}

/// A registered space as a venue keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Space {
    /// Its clock, from its genesis.
    pub clock: WindowClock,
    /// The first window it anchors at the venue: the venue's next at its
    /// registration.
    pub start: u64,
    pub status: Status,
}

/// A root a venue holds anchored, and the key that signed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Held {
    pub root: [u8; 32],
    pub signer: [u8; 32],
}

/// What a venue holds of its spaces' roots: what [`anchored`] reads.
pub trait Roots {
    /// The venue's time: milliseconds since the Unix epoch, by its own
    /// clock.
    fn now(&self) -> u64;
    /// The space `space`, if registered here, an ended one included.
    fn space(&self, space: &SpaceId) -> Option<Space>;
    /// The root held of `space` and `kind` at `window`.
    fn held(&self, space: &SpaceId, kind: RootKind, window: u64) -> Option<Held>;
}

/// What a venue holds for the anchor rule ([`anchor`]).
pub trait VenueState: Roots {
    /// Its id, which every anchor's signature binds.
    fn venue(&self) -> VenueId;
    /// Whether `key` is one of `space`'s anchor keys.
    fn listed(&self, space: &SpaceId, key: &[u8; 32]) -> bool;
    /// The last window of `space` and `kind` anchored.
    fn last(&self, space: &SpaceId, kind: RootKind) -> Option<u64>;
    /// Whether `signature` is `key`'s over `digest`, verified strictly, as
    /// `ed25519-dalek`'s `verify_strict` does: a canonical `R` and `S`, and
    /// neither `R` nor the key of small order.
    fn verify(&self, key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool;
}

/// Why a venue refuses a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegisterRefusal {
    /// No founding key or more than [`MAX_FOUNDING_KEYS`], a key twice, or
    /// a key of small order.
    Genesis,
    /// A window length the venue does not register ([`WindowClock::registrable`]).
    Clock,
    /// The signing key is not a founding key, or its signature does not
    /// verify over the registration's digest at this venue.
    Founder,
    /// The space is registered here already, ended or not.
    Exists,
}

/// A registration whose genesis and signature passed: what the venue
/// records once [`register`] takes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Registration {
    pub space: SpaceId,
    pub clock: WindowClock,
    /// The founding keys, its first anchor keys, in the genesis's order.
    pub keys: Vec<[u8; 32]>,
}

/// The checks of a registration that read no state: `genesis` holds 1 to
/// [`MAX_FOUNDING_KEYS`] distinct keys, none of small order, and a
/// registrable clock; `founder_key` is one of them, and `signature` its
/// signature over the registration's digest at `venue` under `controller`,
/// checked by `verify` ([`VenueState::verify`]'s contract).
pub fn registration(
    venue: &VenueId,
    genesis: &SpaceGenesis,
    controller: &[u8; 32],
    founder_key: &[u8; 32],
    signature: &[u8; 64],
    verify: impl FnOnce(&[u8; 32], &[u8; 32], &[u8; 64]) -> bool,
) -> Result<Registration, RegisterRefusal> {
    let keys: Vec<[u8; 32]> = genesis.nodes.iter().map(|(_, key)| *key).collect();
    let distinct = keys
        .iter()
        .enumerate()
        .all(|(at, key)| !keys.iter().take(at).any(|before| before == key));
    if keys.is_empty()
        || keys.len() > MAX_FOUNDING_KEYS
        || !distinct
        || keys.iter().any(small_order)
    {
        return Err(RegisterRefusal::Genesis);
    }
    if !genesis.clock.registrable() {
        return Err(RegisterRefusal::Clock);
    }
    let space = space_id(genesis);
    let digest = register_digest(venue, &space, controller);
    if !keys.contains(founder_key) || !verify(founder_key, &digest, signature) {
        return Err(RegisterRefusal::Founder);
    }
    Ok(Registration {
        space,
        clock: genesis.clock,
        keys,
    })
}

/// The checks of a registration that read the venue's state: the space
/// not registered here, ended or not. The first window it anchors, the
/// venue's next by the space's clock (window 0 before the clock's origin).
pub fn register(state: &impl Roots, registration: &Registration) -> Result<u64, RegisterRefusal> {
    if state.space(&registration.space).is_some() {
        return Err(RegisterRefusal::Exists);
    }
    Ok(registration
        .clock
        .window(state.now())
        .map_or(0, |open| open.saturating_add(1)))
}

/// Why a venue refuses to list another anchor key for a space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRefusal {
    /// The key is of small order ([`small_order`]).
    SmallOrder,
    /// The space lists it already.
    Listed,
    /// The space lists [`MAX_FOUNDING_KEYS`] keys already.
    Full,
}

/// Whether a space listing `count` keys, `listed` among them or not, may
/// list `key` too: never one of small order, never twice, at most
/// [`MAX_FOUNDING_KEYS`] in all. A venue that pairs a listed key with an
/// authority rather than listing it again (Kreivo's `add_authority` of a
/// founding key) asks only of a key it does not list.
pub fn add_key(count: usize, listed: bool, key: &[u8; 32]) -> Result<(), KeyRefusal> {
    if small_order(key) {
        return Err(KeyRefusal::SmallOrder);
    }
    if listed {
        return Err(KeyRefusal::Listed);
    }
    if count >= MAX_FOUNDING_KEYS {
        return Err(KeyRefusal::Full);
    }
    Ok(())
}

/// What an anchor a venue takes does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Anchoring {
    /// Its root is now the space's at its window: the venue stores it and
    /// moves the space's last window to it.
    New,
    /// The venue holds that root there already: nothing changes.
    Again,
    /// The venue holds another root there, signed by a listed key: this
    /// anchor is the equivocation's evidence. The venue keeps both roots
    /// as evidence and ends the space.
    Evidence(Held),
}

/// Why a venue refuses an anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnchorRefusal {
    /// The space is not registered.
    Unregistered,
    /// The space is not active: ended, or blocked by the venue's
    /// governance.
    Stopped,
    /// The signer is not one of the space's anchor keys.
    Key,
    /// The signature is not the signer's over the anchor's digest here.
    Signature,
    /// The window is before the space's first here, or not past its last
    /// anchored: refused for good.
    Window,
    /// The window is not closed by the venue's clock (`w ≥ now_w`, or the
    /// venue's time before the clock's origin): refused until the venue's
    /// time passes its boundary.
    Open,
    /// The window's boundary is older than [`MAX_ROOT_AGE_MS`].
    Age,
}

/// The anchor rule, in its order: the space registered and active; the
/// signer listed; the signature; the window not past `MaxRootAge`; a root
/// held at the window (the same: [`Anchoring::Again`]; another:
/// [`Anchoring::Evidence`]); the window at or after the space's first and
/// past its last; closed by the venue's clock.
///
/// Age comes before the held root, so an aged second root is refused alike
/// whether or not the venue has pruned the first: only a fresh window's
/// second root is evidence.
pub fn anchor(state: &impl VenueState, anchor: &Anchor) -> Result<Anchoring, AnchorRefusal> {
    let space = state
        .space(&anchor.space)
        .ok_or(AnchorRefusal::Unregistered)?;
    if space.status != Status::Active {
        return Err(AnchorRefusal::Stopped);
    }
    if !state.listed(&anchor.space, &anchor.signer) {
        return Err(AnchorRefusal::Key);
    }
    let digest = anchor.digest(&state.venue());
    if !state.verify(&anchor.signer, &digest, &anchor.signature) {
        return Err(AnchorRefusal::Signature);
    }
    let w = anchor.window;
    if aged(&space.clock, w, state.now()) {
        return Err(AnchorRefusal::Age);
    }
    if let Some(held) = state.held(&anchor.space, anchor.kind, w) {
        return Ok(if held.root == anchor.root {
            Anchoring::Again
        } else {
            Anchoring::Evidence(held)
        });
    }
    let stale = state
        .last(&anchor.space, anchor.kind)
        .is_some_and(|last| w <= last);
    if w < space.start || stale {
        return Err(AnchorRefusal::Window);
    }
    if space.clock.window(state.now()).is_none_or(|open| w >= open) {
        return Err(AnchorRefusal::Open);
    }
    Ok(Anchoring::New)
}

/// Whether `root` is anchored at the venue: its space registered and
/// active, the venue holding that root of its kind at its window, and the
/// root fresh by the venue's time.
pub fn anchored(state: &impl Roots, root: &RootRead) -> bool {
    let Some(space) = state.space(&root.space) else {
        return false;
    };
    space.status == Status::Active
        && fresh(&space.clock, root.window, state.now())
        && state
            .held(&root.space, root.kind, root.window)
            .is_some_and(|held| held.root == root.root)
}

/// When a root of window `window` stops being fresh: `B_w + MaxRootAge`,
/// the last millisecond it is. None past `u64`'s range.
pub fn expiry(clock: &WindowClock, window: u64) -> Option<u64> {
    clock.boundary(window)?.checked_add(MAX_ROOT_AGE_MS)
}

/// Whether a root of window `window` is fresh at the venue's time `now`:
/// `now ≤ B_w + MaxRootAge`. A window whose expiry is past `u64`'s range is
/// not.
pub fn fresh(clock: &WindowClock, window: u64, now: u64) -> bool {
    expiry(clock, window).is_some_and(|last| now <= last)
}

/// Whether a root of window `window` is past `MaxRootAge` at `now`: never
/// to be anchored, nor to count. A window whose expiry is past `u64`'s
/// range is not.
pub fn aged(clock: &WindowClock, window: u64, now: u64) -> bool {
    expiry(clock, window).is_some_and(|last| now > last)
}

/// Whether a space whose last anchored window is `last` has passed
/// `window`: an anchor of it is refused for good ([`AnchorRefusal::Window`]),
/// so a client stops sending it, as it does one [`aged`].
pub fn passed(last: Option<u64>, window: u64) -> bool {
    last.is_some_and(|last| last >= window)
}

/// When a venue may drop the `Seen` entry of a statement accepted reading
/// roots of `windows`, its space's clock `clock`: its newest root's
/// [`expiry`], past which a replay is refused unanchored. `u64::MAX`, never,
/// when it reads none or that expiry is past `u64`'s range.
pub fn seen_expiry(clock: &WindowClock, windows: impl IntoIterator<Item = u64>) -> u64 {
    windows
        .into_iter()
        .max()
        .and_then(|window| expiry(clock, window))
        .unwrap_or(u64::MAX)
}

/// The encodings of the ed25519 points of small order (the eight-torsion
/// subgroup), each `y` little-endian without its sign bit: 0, 1, the two
/// of order 8, `p − 1`, and the non-canonical `p` and `p + 1`.
pub(crate) const SMALL_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    {
        let mut one = [0; 32];
        one[0] = 1;
        one
    },
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    p_and(0xec),
    p_and(0xed),
    p_and(0xee),
];

/// `p = 2^255 − 19` but its low byte, `low`: `p − 1`, `p` and `p + 1` by
/// `0xec`, `0xed` and `0xee`.
const fn p_and(low: u8) -> [u8; 32] {
    let mut bytes = [0xff; 32];
    bytes[0] = low;
    bytes[31] = 0x7f;
    bytes
}

/// Whether `key` encodes an ed25519 point of small order, whatever its
/// sign bit: a key a venue never lists. The check needs no curve
/// arithmetic.
pub fn small_order(key: &[u8; 32]) -> bool {
    let mut y = *key;
    if let Some(top) = y.last_mut() {
        *top &= 0x7f;
    }
    SMALL_ORDER.contains(&y)
}
