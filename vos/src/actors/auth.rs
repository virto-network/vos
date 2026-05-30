//! Authorization primitives shared by host, registry, and actors.
//!
//! Three types form the foundation of per-actor ACLs:
//!
//! - [`SpaceRole`] — the coarse, space-wide role tier (Admin /
//!   Developer / Member / Guest). One enum the whole space agrees
//!   on; lives in the registry's grant table.
//! - [`Caller`] — who is calling a handler. Variants distinguish
//!   transport / authentication shape (libp2p peer, intra-system
//!   actor, anonymous unauthenticated) so handlers can write
//!   policy against the kind, not just the identity bytes.
//! - [`SpaceRoleMap`] — per-actor mapping from `SpaceRole` to the
//!   actor's own [`Role`](crate::Actor::Role). Declared once on the
//!   [`Actor`] trait as a `const`, giving each actor a stable,
//!   verifiably-static "what does space-Admin mean here?" answer.
//!
//! Role discriminants are bytes. Each actor's [`Role`] enum is
//! independent — the wire / storage carries the byte; the actor
//! interprets it. `SpaceRole`'s discriminants are pinned (changes
//! break on-disk grants) so the host's `lookup_caller_role` can
//! emit the right byte regardless of the actor.

use alloc::vec::Vec;

/// Space-wide role tier. Stored centrally in the space registry;
/// applied to every actor as the *fallback* when no actor-local
/// grant exists. Each actor maps these tiers onto its own
/// [`Role`](crate::Actor::Role) via [`SpaceRoleMap`].
///
/// Discriminants are pinned: changing them invalidates persisted
/// grants and any in-flight wire payloads.
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[repr(u8)]
pub enum SpaceRole {
    /// Lowest tier — no enrollment evidence. Default for any
    /// caller the registry hasn't seen before.
    Guest = 0,
    /// Read-tier member. Allowed to observe space state and call
    /// non-mutating actor handlers.
    Member = 1,
    /// Mutating tier. Allowed to commit, deploy, register —
    /// everything below `Admin` in the host's allow-list.
    Developer = 2,
    /// Highest tier — full control. Auto-granted to the operator
    /// who runs `vosx space new`.
    Admin = 3,
}

impl SpaceRole {
    /// Decode from the raw byte stored in the registry's grant
    /// table. Returns `None` for an unknown discriminant — the
    /// caller treats that as `Guest` (deny mutations) rather
    /// than panicking on a forward-incompatible byte.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Guest),
            1 => Some(Self::Member),
            2 => Some(Self::Developer),
            3 => Some(Self::Admin),
            _ => None,
        }
    }

    /// The raw byte stored in the registry. Pinned per discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Lower-case canonical name, as the CLI prints it. Pairs
    /// with [`Self::parse`] for round-tripping.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Guest => "guest",
            Self::Member => "member",
            Self::Developer => "developer",
            Self::Admin => "admin",
        }
    }

    /// Parse the canonical lower-case name. Accepts the names
    /// emitted by [`Self::name`] and a few CLI-friendly synonyms
    /// (`read`, `readonly` → `Member`; `dev` → `Developer`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "guest" | "none" => Some(Self::Guest),
            "member" | "read" | "readonly" => Some(Self::Member),
            "developer" | "dev" => Some(Self::Developer),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl core::fmt::Display for SpaceRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Per-actor mapping from [`SpaceRole`] to the actor's own
/// [`Role`](crate::Actor::Role). Declared once on the [`Actor`]
/// trait as a `const`, so the mapping is verifiably static —
/// no runtime policy that could vary per-call and surprise the
/// auth gate.
///
/// `None` in a field denies that tier outright: a caller whose
/// space role maps to `None` gets [`Caller::Unauthenticated`]
/// treatment for this actor. Useful for, e.g., a payments actor
/// that wants even `Admin` to go through an explicit local grant.
///
/// Build with struct-literal syntax to keep the mapping
/// self-documenting at the declaration site:
///
/// ```ignore
/// const SPACE_ROLE_MAP: SpaceRoleMap<MyRole> = SpaceRoleMap {
///     admin:     Some(MyRole::Maintainer),
///     developer: Some(MyRole::Contributor),
///     member:    Some(MyRole::Viewer),
///     guest:     None,
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SpaceRoleMap<R: Copy> {
    pub admin: Option<R>,
    pub developer: Option<R>,
    pub member: Option<R>,
    pub guest: Option<R>,
}

impl<R: Copy> SpaceRoleMap<R> {
    /// Look up the actor-local role for a caller whose
    /// space-level role is `sr`. `None` means the caller's space
    /// role doesn't entitle them to *anything* in this actor —
    /// the auth gate denies the call.
    pub const fn lookup(&self, sr: SpaceRole) -> Option<R> {
        match sr {
            SpaceRole::Admin => self.admin,
            SpaceRole::Developer => self.developer,
            SpaceRole::Member => self.member,
            SpaceRole::Guest => self.guest,
        }
    }
}

impl<R: Copy + Ord> SpaceRoleMap<R> {
    /// True iff the caller's space-level role maps to at least
    /// `required` in this actor's local hierarchy. Convenience
    /// for the most common check shape — `ensure_role` is the
    /// real entry point.
    pub fn allows(&self, sr: SpaceRole, required: R) -> bool {
        match self.lookup(sr) {
            Some(local) => local >= required,
            None => false,
        }
    }
}

/// Who is calling a handler. Distinguishes the *kind* of caller
/// (transport / authentication shape) so handlers can write
/// policy without reaching into transport-layer types.
///
/// The binding bytes inside variants like [`Self::Peer`] are
/// kept opaque to actor code — PVM guests don't depend on
/// libp2p; the host translates verified transport identities
/// into the bytes the registry's grant table keys on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// No credentials were presented. The HTTP gateway routes
    /// public requests through here; libp2p inbounds never land
    /// as `Unauthenticated` (libp2p noise always identifies the
    /// peer). Default policy: read handlers may accept; mutating
    /// handlers reject.
    Unauthenticated,
    /// libp2p peer, identity verified by noise at connect time.
    /// The carried bytes are the peer's multihash encoding (the
    /// stable wire form of a libp2p PeerId) — opaque to actor
    /// code, used as the lookup key into the registry's grant
    /// table.
    Peer(Vec<u8>),
    /// Intra-system invoke from another actor on the same node
    /// (or forwarded over the cross-thread channel between
    /// agent threads). The carried `ServiceId` identifies the
    /// calling actor; policy typically allows by virtue of "if
    /// it's already inside the system, it's trusted."
    Actor(crate::actors::context::ServiceId),
    // `Member { session_key, ... }` lands with the per-space ZK
    // login service. Until then the only authenticated-but-
    // anonymous-membership caller is `Peer`.
}

impl Caller {
    /// True iff the caller has any form of verified identity —
    /// i.e. anything except [`Self::Unauthenticated`]. The
    /// macro's default mutation gate uses this as the
    /// minimum bar.
    pub const fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Unauthenticated)
    }

    /// Bytes the registry's grant table keys on. `None` for
    /// callers that don't have a binding (Unauthenticated, or
    /// intra-system Actor calls — those are policy-checked by
    /// kind, not by lookup).
    pub fn grant_key(&self) -> Option<&[u8]> {
        match self {
            Self::Peer(bytes) => Some(bytes.as_slice()),
            Self::Unauthenticated | Self::Actor(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_role_byte_roundtrip() {
        // Discriminants are pinned — any change here invalidates
        // every stored grant on disk. Lock them down.
        for r in [
            SpaceRole::Guest,
            SpaceRole::Member,
            SpaceRole::Developer,
            SpaceRole::Admin,
        ] {
            assert_eq!(SpaceRole::from_u8(r.as_u8()), Some(r));
        }
        assert_eq!(SpaceRole::Guest.as_u8(), 0);
        assert_eq!(SpaceRole::Member.as_u8(), 1);
        assert_eq!(SpaceRole::Developer.as_u8(), 2);
        assert_eq!(SpaceRole::Admin.as_u8(), 3);
    }

    #[test]
    fn space_role_from_u8_unknown_is_none() {
        // Forward-incompatible byte (e.g. a future tier) decodes
        // as None so callers can downgrade gracefully — not
        // panic — when a newer registry granted a role the old
        // code doesn't know about.
        assert_eq!(SpaceRole::from_u8(4), None);
        assert_eq!(SpaceRole::from_u8(255), None);
    }

    #[test]
    fn space_role_name_roundtrip() {
        for r in [
            SpaceRole::Guest,
            SpaceRole::Member,
            SpaceRole::Developer,
            SpaceRole::Admin,
        ] {
            assert_eq!(SpaceRole::parse(r.name()), Some(r));
        }
    }

    #[test]
    fn space_role_parse_synonyms() {
        assert_eq!(SpaceRole::parse("read"), Some(SpaceRole::Member));
        assert_eq!(SpaceRole::parse("readonly"), Some(SpaceRole::Member));
        assert_eq!(SpaceRole::parse("dev"), Some(SpaceRole::Developer));
        assert_eq!(SpaceRole::parse("none"), Some(SpaceRole::Guest));
        assert_eq!(SpaceRole::parse("xyzzy"), None);
    }

    // Toy role enum the SpaceRoleMap tests use. Same shape
    // every actor declaring `type Role` will produce.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(u8)]
    enum TestRole {
        Viewer = 0,
        Contributor = 1,
        Maintainer = 2,
    }

    const MAP: SpaceRoleMap<TestRole> = SpaceRoleMap {
        admin: Some(TestRole::Maintainer),
        developer: Some(TestRole::Contributor),
        member: Some(TestRole::Viewer),
        guest: None,
    };

    #[test]
    fn space_role_map_lookup_covers_all_tiers() {
        assert_eq!(MAP.lookup(SpaceRole::Admin), Some(TestRole::Maintainer));
        assert_eq!(
            MAP.lookup(SpaceRole::Developer),
            Some(TestRole::Contributor)
        );
        assert_eq!(MAP.lookup(SpaceRole::Member), Some(TestRole::Viewer));
        assert_eq!(MAP.lookup(SpaceRole::Guest), None);
    }

    #[test]
    fn space_role_map_allows_respects_ord() {
        // Admin → Maintainer, which is >= every TestRole.
        assert!(MAP.allows(SpaceRole::Admin, TestRole::Viewer));
        assert!(MAP.allows(SpaceRole::Admin, TestRole::Maintainer));
        // Developer → Contributor: enough for Viewer/Contributor,
        // not enough for Maintainer.
        assert!(MAP.allows(SpaceRole::Developer, TestRole::Viewer));
        assert!(MAP.allows(SpaceRole::Developer, TestRole::Contributor));
        assert!(!MAP.allows(SpaceRole::Developer, TestRole::Maintainer));
        // Guest → None: never allows anything.
        assert!(!MAP.allows(SpaceRole::Guest, TestRole::Viewer));
    }

    #[test]
    fn space_role_map_lookup_is_const_callable() {
        // `const fn` shape lets actor authors compose maps at
        // const-eval time. Pin the surface so a refactor doesn't
        // silently drop const-ness.
        const TIER: Option<TestRole> = MAP.lookup(SpaceRole::Developer);
        assert_eq!(TIER, Some(TestRole::Contributor));
    }

    #[test]
    fn caller_is_authenticated() {
        assert!(!Caller::Unauthenticated.is_authenticated());
        assert!(Caller::Peer(alloc::vec![1, 2, 3]).is_authenticated());
        assert!(Caller::Actor(crate::actors::context::ServiceId(42)).is_authenticated());
    }

    #[test]
    fn caller_grant_key_only_for_peer() {
        // The registry's grant table keys on the binding bytes
        // for Peer (and eventually Member). Unauthenticated and
        // intra-system Actor calls are policy-checked by kind,
        // not by per-caller grants — `grant_key` must return
        // None for both so a lookup is structurally impossible.
        assert_eq!(Caller::Unauthenticated.grant_key(), None);
        assert_eq!(
            Caller::Actor(crate::actors::context::ServiceId(7)).grant_key(),
            None
        );
        let bytes = alloc::vec![9, 9, 9];
        assert_eq!(Caller::Peer(bytes.clone()).grant_key(), Some(&bytes[..]));
    }
}
