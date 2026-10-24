//! A venue as a VOS node reaches it ([`VenueClient`]): the representative's
//! leader anchors the space's root of each window it closes, a prover
//! submits statements, and either asks what is anchored. Its id names the
//! venue in every anchor's digest. A client that reaches a chain queues its
//! anchors in an [`queue::AnchorQueue`].
//!
//! The node carries no venue's client: venues attach to a node through
//! extensions. What this crate holds of them, no production build enables:
//!
//! - feature `model`: `ModelVenue`, a venue modelled in memory, which the
//!   node's tests anchor and submit at;
//! - feature `kreivo`: `kreivo::KreivoVenue`, the client of Kreivo's spaces
//!   pallet, built only against its mock until the pallet is vetted;
//! - feature `kreivo-mock` (with `kreivo`): `kreivo::mock`, the reference
//!   mock of that pallet and a transport over it.
//!
//! A JAM statements service is a venue only through VOS's development
//! tooling (`vos-jam-dev`'s `JamVenue`).

use vos_anchor::{Anchor, RootRead, SpaceId, VenueId};
use vos_statement::{Refusal, Statement, StatementId};

/// What a node asks of a venue.
pub trait VenueClient: Send + Sync {
    /// The venue's id, which an anchor's signature binds.
    fn id(&self) -> VenueId;
    /// Anchor a space's root of a window. It answers at once: the
    /// representative's leader hands it over inside its batch.
    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal>;
    /// Submit a statement and its final proof: its id once accepted, or
    /// once the venue holds it accepted already.
    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted>;
    /// Whether `root` is anchored, its space's root of its kind at its
    /// window.
    fn anchored(&self, root: &RootRead) -> bool;
    /// The anchor keys `space` has registered here (Kreivo's `AnchorKeys`):
    /// none when it is not registered, or the venue cannot say.
    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]>;
    /// Where `space` stands at the venue, as far as it can say.
    fn status(&self, space: &SpaceId) -> Status;
    /// The venue's time, in milliseconds since the Unix epoch, as last read:
    /// what every deadline between parties is timed by (`proving.md` §7). None
    /// before the client has read it.
    fn time(&self) -> Option<u64>;
    /// The anchors of `space` this client took ([`Anchored::Queued`]) and
    /// then handed back, the venue not listing their keys, that the venue
    /// still needs: the representative's leader signs each root again
    /// with a key it lists. None for a client that queues nothing; a
    /// client that wraps another hands back the other's.
    fn unsettled(&self, space: &SpaceId) -> Vec<Anchor>;
}

/// The first of the codes a venue reports for its failure to judge a
/// statement (on JAM, refine out of gas, a panic, an undecodable verdict):
/// above every [`Refusal::code`].
pub const UNJUDGED_FROM: u32 = 0x1000;

/// Whether a submission refused with `code` may be accepted when sent
/// again: [`Refusal::Unanchored`], a root the venue does not hold anchored
/// now (its anchor yet to land, its space suspended until resumed, a
/// node's view behind the venue's), and a venue's failure to judge it, from
/// [`UNJUDGED_FROM`]. The others are the statement's own, and final.
pub fn transient(code: u32) -> bool {
    code == Refusal::Unanchored.code() || code >= UNJUDGED_FROM
}

/// Whether `code` is a refused proof's ([`Refusal::Proof`]'s class: `0x100`
/// and the final verifier's code).
pub fn proof_refused(code: u32) -> bool {
    code >> 8 == 1
}

/// Where a space stands at a venue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not registered, or not known yet.
    Unregistered,
    /// Anchoring.
    Active,
    /// It equivocated: no anchor is taken until its controller removes
    /// both keys and resumes it.
    Suspended,
    /// The venue's governance blocked it.
    Blocked,
}

impl Status {
    /// Whether the venue takes no anchor of the space until someone acts:
    /// a leader waits, sending nothing.
    pub fn waits(self) -> bool {
        matches!(self, Self::Suspended | Self::Blocked)
    }
}

/// Why a venue did not accept a statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotAccepted {
    /// Judged and refused: [`Refusal::code`]'s class.
    Refused(u32),
    /// Not judged.
    Unjudged(Unjudged),
}

/// Why a venue did not judge a statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unjudged {
    /// The node's configuration at the venue: the paying space unknown or
    /// not active, the node not its authority, submits paused, or a
    /// statement or proof past the venue's bounds.
    Configuration,
    /// The paying space's funds: its sovereign account's balance, or its
    /// spend budget for the window.
    Funding,
    /// Sent, and what became of it unknown: the venue holds no acceptance
    /// of it.
    Unknown,
}

impl From<Refusal> for NotAccepted {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal.code())
    }
}

/// A submission's verdict as every venue reports it
/// ([`vos_statement::code`]): 0 accepted, a refusal's class, and
/// `u32::MAX` unjudged.
pub fn code(verdict: &Result<StatementId, NotAccepted>) -> u32 {
    match verdict {
        Ok(_) => 0,
        Err(NotAccepted::Refused(code)) => *code,
        Err(NotAccepted::Unjudged(_)) => u32::MAX,
    }
}

/// An anchor the venue took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchored {
    /// Its root is now the space's at its window.
    New,
    /// The venue held that root already: a second leader's anchor, or the
    /// same leader's again.
    Again,
    /// The venue's client took it to send, and sends it, in window order,
    /// until the venue holds it or refuses it for good.
    Queued,
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

#[cfg(any(test, feature = "kreivo"))]
pub mod kreivo;
#[cfg(any(test, feature = "model"))]
mod model;
pub mod queue;

#[cfg(any(test, feature = "model"))]
pub use model::ModelVenue;
pub use vos_statement;
