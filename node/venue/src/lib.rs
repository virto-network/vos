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

use ed25519_dalek::{Signature, VerifyingKey};
pub use vos_anchor::venue::{aged, fresh};
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

/// Implements [`VenueClient`] for a wrapper: each method in `forward [..]`
/// answered by the field `$inner`, which is itself a client, and the rest
/// written out in the braces.
///
/// ```text
/// forward_venue!(Timed => inner; forward [id, submit, anchored, anchor_keys, status, time, unsettled] {
///     fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> { .. }
/// });
/// ```
#[macro_export]
macro_rules! forward_venue {
    ($ty:ty => $inner:ident; forward [$($method:ident),* $(,)?] $({ $($item:item)* })?) => {
        impl $crate::VenueClient for $ty {
            $($crate::forward_venue!(@ $method $inner);)*
            $($($item)*)?
        }
    };
    (@ id $inner:ident) => {
        fn id(&self) -> $crate::forward::VenueId {
            use $crate::VenueClient as _;
            self.$inner.id()
        }
    };
    (@ anchor $inner:ident) => {
        fn anchor(
            &self,
            anchor: &$crate::forward::Anchor,
        ) -> ::core::result::Result<$crate::Anchored, $crate::AnchorRefusal> {
            use $crate::VenueClient as _;
            self.$inner.anchor(anchor)
        }
    };
    (@ submit $inner:ident) => {
        fn submit(
            &self,
            statement: &$crate::forward::Statement,
            proof: &[u8],
        ) -> ::core::result::Result<$crate::forward::StatementId, $crate::NotAccepted> {
            use $crate::VenueClient as _;
            self.$inner.submit(statement, proof)
        }
    };
    (@ anchored $inner:ident) => {
        fn anchored(&self, root: &$crate::forward::RootRead) -> bool {
            use $crate::VenueClient as _;
            self.$inner.anchored(root)
        }
    };
    (@ anchor_keys $inner:ident) => {
        fn anchor_keys(&self, space: &$crate::forward::SpaceId) -> ::std::vec::Vec<[u8; 32]> {
            use $crate::VenueClient as _;
            self.$inner.anchor_keys(space)
        }
    };
    (@ status $inner:ident) => {
        fn status(&self, space: &$crate::forward::SpaceId) -> $crate::Status {
            use $crate::VenueClient as _;
            self.$inner.status(space)
        }
    };
    (@ time $inner:ident) => {
        fn time(&self) -> ::core::option::Option<u64> {
            use $crate::VenueClient as _;
            self.$inner.time()
        }
    };
    (@ unsettled $inner:ident) => {
        fn unsettled(
            &self,
            space: &$crate::forward::SpaceId,
        ) -> ::std::vec::Vec<$crate::forward::Anchor> {
            use $crate::VenueClient as _;
            self.$inner.unsettled(space)
        }
    };
}

/// The types [`forward_venue!`] names.
#[doc(hidden)]
pub mod forward {
    pub use vos_anchor::{Anchor, RootRead, SpaceId, VenueId};
    pub use vos_statement::{Statement, StatementId};
}

/// The first of the codes a venue reports for its failure to judge a
/// statement (on JAM, refine out of gas, a panic, an undecodable verdict):
/// above every [`Refusal::code`].
pub const UNJUDGED_FROM: u32 = 0x1000;

/// Whether a submission refused with `code` may be accepted when sent
/// again: [`Refusal::Unanchored`], a root the venue does not hold anchored
/// now (its anchor yet to land, its space blocked until unblocked, a
/// node's view behind the venue's), and a venue's failure to judge it, from
/// [`UNJUDGED_FROM`]. The others are the statement's own, and final.
pub fn transient(code: u32) -> bool {
    code == Refusal::Unanchored.code() || code >= UNJUDGED_FROM
}

/// Whether `signature` is `key`'s over `digest`, strictly
/// (`verify_strict`: `vos_anchor::venue::VenueState::verify`'s contract).
pub fn verify(key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(digest, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// Whether `anchor` is signed by its signer over its digest at `venue`.
pub fn signed(anchor: &Anchor, venue: &VenueId) -> bool {
    verify(&anchor.signer, &anchor.digest(venue), &anchor.signature)
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
    /// It equivocated: it takes no anchor and its roots do not count, for
    /// good. It re-founds under a new genesis to anchor again.
    Ended,
    /// The venue's governance blocked it.
    Blocked,
}

impl Status {
    /// Whether the venue takes no anchor of the space: a leader waits,
    /// sending nothing.
    pub fn waits(self) -> bool {
        matches!(self, Self::Ended | Self::Blocked)
    }
}

impl From<vos_anchor::venue::Status> for Status {
    fn from(status: vos_anchor::venue::Status) -> Self {
        match status {
            vos_anchor::venue::Status::Active => Self::Active,
            vos_anchor::venue::Status::Blocked => Self::Blocked,
            vos_anchor::venue::Status::Ended => Self::Ended,
        }
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
    /// The space is not active: it equivocated and ended, or the venue's
    /// governance blocked it.
    Stopped,
    /// The signer is not one of the space's anchor keys.
    Key,
    /// The signature is not the signer's over the anchor's digest.
    Signature,
    /// The window is before the space's first at the venue, or not past
    /// its last anchored: refused for good.
    Window,
    /// The window is the space's open one, or later, by the venue's clock:
    /// refused until the venue's time passes its boundary.
    Open,
    /// The window's boundary is older than `MaxRootAge`.
    Age,
    /// Another root of the space's kind at the window is anchored, signed
    /// by a listed key: this one is the equivocation's evidence, which
    /// ends the space for good. A client that finds the venue holding
    /// another root sends its node's anchor all the same, as that evidence.
    Equivocation,
}

impl From<vos_anchor::venue::AnchorRefusal> for AnchorRefusal {
    fn from(refusal: vos_anchor::venue::AnchorRefusal) -> Self {
        use vos_anchor::venue::AnchorRefusal as Rule;
        match refusal {
            Rule::Unregistered => Self::Unregistered,
            Rule::Stopped => Self::Stopped,
            Rule::Key => Self::Key,
            Rule::Signature => Self::Signature,
            Rule::Window => Self::Window,
            Rule::Open => Self::Open,
            Rule::Age => Self::Age,
        }
    }
}

#[cfg(any(test, feature = "kreivo"))]
pub mod kreivo;
#[cfg(any(test, feature = "model"))]
mod model;
pub mod queue;

#[cfg(any(test, feature = "model"))]
pub use model::ModelVenue;
pub use vos_statement;
