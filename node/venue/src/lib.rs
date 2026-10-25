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
use vos_statement::{Refusal, Statement};

/// What a node asks of a venue. Its reads (the space's status, its
/// anchor keys, the root held at a window, the venue's time) answer from
/// what the client last read on its own thread, so the representative's
/// leader asks them, and anchors, inside its batch without waiting on the
/// venue.
pub trait VenueClient: Send + Sync {
    /// The venue's id, which an anchor's signature binds.
    fn id(&self) -> VenueId;
    /// Anchor a space's root of a window, answered at once: a client that
    /// reaches a chain queues what it takes and sends it, in window order,
    /// until the venue answers.
    fn anchor(&self, anchor: &Anchor) -> AnchorOutcome;
    /// Submit a statement and its final proof.
    fn submit(&self, statement: &Statement, proof: &[u8]) -> SubmitOutcome;
    /// Whether `root` is anchored, its space's root of its kind at its
    /// window.
    fn anchored(&self, root: &RootRead) -> bool;
    /// The anchor keys `space` has registered here (Kreivo's `AnchorKeys`):
    /// none when it is not registered, or the venue cannot say.
    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]>;
    /// Where `space` stands at the venue, as far as it can say.
    fn status(&self, space: &SpaceId) -> Status;
    /// The space's root the venue holds at `window` (`Anchors[w]`, past
    /// `Last` none), as last read.
    fn held(&self, space: &SpaceId, window: u64) -> Held;
    /// The venue's time, in milliseconds since the Unix epoch, as last read:
    /// what every deadline between parties is timed by (`proving.md` §7). None
    /// before the client has read it.
    fn time(&self) -> Option<u64>;
}

/// Implements [`VenueClient`] for a wrapper: each method in `forward [..]`
/// answered by the field `$inner`, which is itself a client, and the rest
/// written out in the braces.
///
/// ```text
/// forward_venue!(Timed => inner; forward [id, submit, anchored, anchor_keys, status, held, time] {
///     fn anchor(&self, anchor: &Anchor) -> AnchorOutcome { .. }
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
        fn anchor(&self, anchor: &$crate::forward::Anchor) -> $crate::AnchorOutcome {
            use $crate::VenueClient as _;
            self.$inner.anchor(anchor)
        }
    };
    (@ submit $inner:ident) => {
        fn submit(
            &self,
            statement: &$crate::forward::Statement,
            proof: &[u8],
        ) -> $crate::SubmitOutcome {
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
    (@ held $inner:ident) => {
        fn held(&self, space: &$crate::forward::SpaceId, window: u64) -> $crate::Held {
            use $crate::VenueClient as _;
            self.$inner.held(space, window)
        }
    };
    (@ time $inner:ident) => {
        fn time(&self) -> ::core::option::Option<u64> {
            use $crate::VenueClient as _;
            self.$inner.time()
        }
    };
}

/// The types [`forward_venue!`] names.
#[doc(hidden)]
pub mod forward {
    pub use vos_anchor::{Anchor, RootRead, SpaceId, VenueId};
    pub use vos_statement::Statement;
}

/// The first of the codes a venue reports for its failure to judge a
/// statement (on JAM, refine out of gas, a panic, an undecodable verdict):
/// above every [`Refusal::code`].
pub const UNJUDGED_FROM: u32 = 0x1000;

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

/// The code [`SubmitOutcome::Retry`] carries for a statement the venue
/// did not judge: its client could not send it (the paying space's
/// configuration or funds at the venue, alerted), or sent it and lost the
/// answer.
pub const UNJUDGED: u32 = u32::MAX;

/// What became of a statement submitted, for its prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Accepted, now or before: a repeat ([`Refusal::Repeated`]) is the
    /// venue holding it accepted.
    Accepted,
    /// Refused for good: [`Refusal::code`]'s class.
    Refused(u32),
    /// Not accepted now, and sent again later: [`Refusal::Unanchored`] (its
    /// anchor yet to land, its space blocked until unblocked, a node's view
    /// behind the venue's), a venue's failure to judge it (from
    /// [`UNJUDGED_FROM`]), or not judged at all ([`UNJUDGED`]).
    Retry(u32),
}

impl SubmitOutcome {
    /// The outcome of a statement the venue judged `code`: 0 accepted, a
    /// repeat accepted, the transient ones again, the rest refused. The one
    /// place a repeat counts as accepted.
    pub fn judged(code: u32) -> Self {
        if code == 0 || code == Refusal::Repeated.code() {
            Self::Accepted
        } else if code == Refusal::Unanchored.code() || code >= UNJUDGED_FROM {
            Self::Retry(code)
        } else {
            Self::Refused(code)
        }
    }

    /// Its verdict as every venue reports it ([`vos_statement::code`]): 0
    /// accepted, else the code it carries.
    pub fn code(self) -> u32 {
        match self {
            Self::Accepted => 0,
            Self::Refused(code) | Self::Retry(code) => code,
        }
    }
}

/// What a venue client answers an anchor: the leader's one outcome, every
/// venue's codes mapped onto it by one table per client, the raw code kept
/// for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorOutcome {
    /// The venue holds it (new, or the same root again), or its client
    /// queued it to send.
    Taken,
    /// Not now: the window still open by the venue's clock, the space not
    /// registered there yet, anchors paused, the venue unreached or its
    /// funds short. The leader offers it again.
    NotYet,
    /// Never to be taken: the window at or behind the space's last
    /// anchored, past `MaxRootAge`, or a signature the venue refuses.
    /// Settled, alerted.
    Never(u32),
    /// The venue does not list the signer: the leader hands its leadership
    /// to a replica whose key it lists.
    Unlisted(u32),
    /// The space is ended (an equivocation's evidence stored, this node's
    /// own anchor among it) or blocked: no more anchors until an operator
    /// acts.
    Stopped(u32),
}

/// What a client last read of a space's root at a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// Not read yet: the client reads it on its own thread.
    Unread,
    /// The venue holds no root there.
    Nothing,
    /// The venue holds this root there.
    Root([u8; 32]),
}

#[cfg(any(test, feature = "kreivo"))]
pub mod kreivo;
#[cfg(any(test, feature = "model"))]
mod model;
pub mod queue;

#[cfg(any(test, feature = "model"))]
pub use model::ModelVenue;
pub use vos_statement;
