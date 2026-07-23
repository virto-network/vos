//! Authorization primitives shared by host, registry, and actors.
//!
//! Five types form the foundation of per-agent ACLs:
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
//! - [`RoleByte`] — trait the actor's own `Role` enum implements
//!   so the host can plumb opaque role bytes through dispatch.
//!   Auto-derived by the `#[actor]` macro.
//! - [`NoRoles`] / [`NO_ROLES_MAP`] / [`Forbidden`] — sentinels:
//!   the zero-roles type for actors that opted out of RBAC, the
//!   trivially-permissive map paired with it, and the error
//!   marker for the `ensure_role` family of checks.
//!
//! Role discriminants are bytes. Each actor's [`Role`] enum is
//! independent — the wire / storage carries the byte; the actor
//! interprets it. `SpaceRole`'s discriminants are pinned (changes
//! break on-disk grants) so the host's `lookup_caller_role` can
//! emit the right byte regardless of the actor.

use alloc::string::String;
use alloc::vec::Vec;

/// Space-wide role tier. Stored centrally in the space registry;
/// applied to every actor as the *fallback* when no actor-local
/// grant exists. Each actor maps these tiers onto its own
/// [`Role`](crate::Actor::Role) via [`SpaceRoleMap`].
///
/// Discriminants are pinned: changing them invalidates persisted
/// grants and any in-flight wire payloads.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
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
    /// Host-initiated call from within the daemon process — not
    /// routed through any transport. The `vosx space up`
    /// bootstrap (which grants the operator their initial admin
    /// role *before* any libp2p connection exists), internal
    /// host probes, and other embedder-controlled entry points
    /// land here. Treated as trusted by `has_role` until the v2
    /// authority service replaces bootstrap/replay calls with
    /// explicit capabilities; external peers cannot synthesize
    /// this variant.
    System,
    /// libp2p peer, identity verified by noise at connect time.
    /// The carried bytes are the peer's multihash encoding (the
    /// stable wire form of a libp2p PeerId) — opaque to actor
    /// code, used as the lookup key into the registry's grant
    /// table.
    Peer(Vec<u8>),
    /// Intra-system invoke from another actor on the same node
    /// (or forwarded over the cross-thread channel between
    /// agent threads). The carried `ServiceId` identifies the
    /// calling actor so policy can require an explicit actor grant.
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

    /// True iff the caller is trusted by virtue of originating
    /// inside the daemon process — [`Self::System`] (host-
    /// initiated) or [`Self::Actor`] (intra-system invoke).
    /// `Context::has_role` short-circuits these variants to
    /// `true` until internal callers are migrated to explicit
    /// authority capabilities.
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::System | Self::Actor(_))
    }

    /// Bytes the registry's grant table keys on. `None` for
    /// callers that don't have a binding (Unauthenticated /
    /// System / intra-system Actor calls — those are
    /// policy-checked by kind, not by lookup).
    pub fn grant_key(&self) -> Option<&[u8]> {
        match self {
            Self::Peer(bytes) => Some(bytes.as_slice()),
            Self::Unauthenticated | Self::System | Self::Actor(_) => None,
        }
    }
}

/// Convert an actor's [`Role`](crate::Actor::Role) variant to / from
/// the raw byte the registry's grant table stores. The host plumbs
/// role bytes through the dispatch path without understanding what
/// they mean; the actor's own `Role` enum interprets them via this
/// trait.
///
/// Manually implementing the trait is straightforward — the
/// `#[actor]` macro emits one automatically for the user's
/// `Role` enum (M6).
pub trait RoleByte: Sized + Copy {
    /// Decode the byte form. Returns `None` on an unrecognised byte
    /// — the caller treats that as "no effective role" rather than
    /// panicking on a forward-incompatible discriminant.
    fn from_byte(b: u8) -> Option<Self>;
    /// Encode to byte form for storage / wire.
    fn as_byte(self) -> u8;
}

/// Sentinel role enum for actors that don't yet declare a real
/// `Role`. Acts as a single-variant Top — `NoRoles::Any` satisfies
/// every check. The `#[actor]` macro emits this as the default
/// `type Role` so existing actors keep compiling without source
/// edits when the trait is extended in M1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum NoRoles {
    /// The sole variant. `Any` is named to signal that any check
    /// against this role is trivially satisfied — the actor opted
    /// out of role-based access control.
    Any = 0,
}

impl RoleByte for NoRoles {
    fn from_byte(b: u8) -> Option<Self> {
        if b == 0 { Some(Self::Any) } else { None }
    }
    fn as_byte(self) -> u8 {
        0
    }
}

/// The standard [`SpaceRoleMap`] for actors that use [`NoRoles`] —
/// every space-level tier maps to `Any`, so `SPACE_ROLE_MAP.lookup`
/// always succeeds and `allows` returns `true` for every input. The
/// `#[actor]` macro emits this as the default `const SPACE_ROLE_MAP`.
pub const NO_ROLES_MAP: SpaceRoleMap<NoRoles> = SpaceRoleMap {
    admin: Some(NoRoles::Any),
    developer: Some(NoRoles::Any),
    member: Some(NoRoles::Any),
    guest: Some(NoRoles::Any),
};

/// Marker returned by [`Context::ensure_role`](crate::Context) when
/// the caller's effective role is insufficient. Authors who want
/// `?`-propagation in their handlers `impl From<Forbidden> for
/// MyError`. The macro-emitted check at the dispatch boundary
/// halts the actor directly with `STATUS_FORBIDDEN` and never
/// surfaces `Forbidden` to the handler body, so the `From` impl is
/// only needed for *manual* `ensure_role` calls inside handlers
/// that want fine-grained policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forbidden;

impl core::fmt::Display for Forbidden {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("permission denied: caller lacks the required role")
    }
}

/// A single declared *intra-system capability* for a native
/// extension: the maximum [`SpaceRole`] the extension may relay to
/// a named target actor when forwarding an outbound call.
///
/// Extensions are relays, not principals. Without a declared cap
/// for a target, an extension's outbound calls reach that target as
/// [`Caller::Unauthenticated`], so role-gated handlers refuse them.
/// With a cap, the effective authority of a relayed call is
/// `min(caller's space role, this ceiling)`: the extension can never
/// *amplify* the caller, and the caller can never reach actors the
/// extension didn't declare.
///
/// Declared in the space manifest as `"actor:role"` strings:
///
/// ```toml
/// [[extension]]
/// name = "dev"
/// intra_caps = ["space-registry:admin"]
/// ```
///
/// Wildcards:
/// - `"space-registry:*"` — any role on that actor (uncapped).
/// - `"*:developer"` — developer ceiling on *any* actor.
/// - `"msg-*:member"` — member ceiling on any actor whose instance
///   name starts with `msg-`. The trailing-`*` prefix form is how an
///   extension reaches agents it installs dynamically (per-channel
///   actor pairs), whose exact names don't exist at manifest time.
/// - `"*"` (or `"*:*"`) — any role on any actor. A footgun: the
///   extension becomes a fully-trusted relay. Install-time code
///   emits a loud warning (see [`Self::is_full_wildcard`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntraCap {
    /// Target actor instance name (lower-cased — agent names are
    /// case-insensitive), or `None` for the `*` wildcard matching
    /// every actor.
    pub actor_name: Option<String>,
    /// Ceiling role, or `None` for the `*` wildcard meaning "any
    /// role" (uncapped — equivalent to the maximum tier).
    pub role: Option<SpaceRole>,
}

/// Error parsing an [`IntraCap`] from its `"actor:role"` string
/// form. Carries the offending token so the operator can find it in
/// the manifest. Surfaced (never silently dropped) at install time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntraCapParseError {
    /// The raw token that failed to parse.
    pub token: String,
    /// Human-readable reason, suitable for an operator-facing error.
    pub reason: &'static str,
}

impl core::fmt::Display for IntraCapParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid intra_cap '{}': {}", self.token, self.reason)
    }
}

impl IntraCap {
    /// Parse an `"actor:role"` token. `"*"` alone is shorthand for
    /// `"*:*"`. Either side may be `"*"`. Actor names are
    /// case-folded. Errors (visible to the operator, never silent):
    /// missing colon on a non-`*` token, empty actor/role, or an
    /// unrecognised role name.
    pub fn parse(token: &str) -> Result<Self, IntraCapParseError> {
        let err = |reason| IntraCapParseError {
            token: token.into(),
            reason,
        };
        let trimmed = token.trim();
        if trimmed == "*" {
            return Ok(Self {
                actor_name: None,
                role: None,
            });
        }
        let (actor, role) = trimmed
            .split_once(':')
            .ok_or_else(|| err("expected 'actor:role' (e.g. \"space-registry:admin\")"))?;
        let actor = actor.trim();
        let role = role.trim();
        if actor.is_empty() {
            return Err(err("empty actor name"));
        }
        if role.is_empty() {
            return Err(err("empty role"));
        }
        let actor_name = if actor == "*" {
            None
        } else {
            // `*` inside a name is only meaningful as a trailing
            // prefix wildcard (`msg-*`). Reject other placements
            // loudly — a silently-literal `*` would never match an
            // installed agent and the cap would be dead.
            let stars = actor.matches('*').count();
            if stars > 1 || (stars == 1 && !actor.ends_with('*')) {
                return Err(err(
                    "'*' in an actor name only supports the trailing prefix \
                     form (e.g. \"msg-*\")",
                ));
            }
            Some(actor.to_ascii_lowercase())
        };
        let role =
            if role == "*" {
                None
            } else {
                Some(SpaceRole::parse(role).ok_or_else(|| {
                    err("unknown role (expected guest|member|developer|admin or *)")
                })?)
            };
        Ok(Self { actor_name, role })
    }

    /// `true` when this cap's actor side is a `*` wildcard.
    pub fn is_actor_wildcard(&self) -> bool {
        self.actor_name.is_none()
    }

    /// `true` when this cap's actor side is a trailing-`*` prefix
    /// pattern (`msg-*`). Such caps are forward-looking — they match
    /// agents installed after manifest time — so name-roster
    /// validation doesn't apply to them.
    pub fn is_actor_prefix(&self) -> bool {
        self.actor_name.as_deref().is_some_and(|n| n.ends_with('*'))
    }

    /// `true` when this is the `*:*` footgun (matches every actor at
    /// every role) — install-time code warns on these.
    pub fn is_full_wildcard(&self) -> bool {
        self.actor_name.is_none() && self.role.is_none()
    }

    /// The ceiling role this cap grants: the declared role, or
    /// [`SpaceRole::Admin`] for a `*` (any-role) cap — uncapped is
    /// equivalent to capping at the maximum tier.
    fn ceiling(&self) -> SpaceRole {
        self.role.unwrap_or(SpaceRole::Admin)
    }

    /// Does this cap match `target_name`? Wildcard-actor caps match
    /// every target (including unresolved ones, where `target_name`
    /// is `None`); a trailing-`*` cap (`msg-*`) matches any resolved
    /// name with that (case-folded) prefix; named caps match only
    /// their exact (case-folded) name.
    fn matches(&self, target_name: Option<&str>) -> bool {
        match &self.actor_name {
            None => true,
            Some(pat) => match pat.strip_suffix('*') {
                Some(prefix) => target_name.is_some_and(|t| {
                    t.get(..prefix.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                }),
                None => target_name.is_some_and(|t| t.eq_ignore_ascii_case(pat)),
            },
        }
    }
}

impl core::fmt::Display for IntraCap {
    /// Canonical `"actor:role"` form, with `*` for either wildcard.
    /// `parse(self.to_string())` round-trips (a bare `"*"` canonicalises
    /// to `"*:*"`). Used by the operator-facing boot log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let actor = self.actor_name.as_deref().unwrap_or("*");
        match self.role {
            Some(r) => write!(f, "{actor}:{}", r.name()),
            None => write!(f, "{actor}:*"),
        }
    }
}

/// Resolve the cap ceiling an extension's `intra_caps` grant for a
/// call to `target_name`. Returns the **highest** ceiling among all
/// matching caps (caps are grants of authority — their union
/// applies), or `None` when no cap matches (the relay has no
/// authority for this target, so its call must arrive
/// [`Caller::Unauthenticated`]).
///
/// `target_name == None` models a target whose instance name the
/// host couldn't resolve; only `*` (any-actor) caps match it.
pub fn cap_for(caps: &[IntraCap], target_name: Option<&str>) -> Option<SpaceRole> {
    caps.iter()
        .filter(|c| c.matches(target_name))
        .map(|c| c.ceiling())
        .max()
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
        assert!(Caller::System.is_authenticated());
        assert!(Caller::Peer(alloc::vec![1, 2, 3]).is_authenticated());
        assert!(Caller::Actor(crate::actors::context::ServiceId(42)).is_authenticated());
    }

    #[test]
    fn caller_is_trusted() {
        // Trust shortcut: anything originating inside the
        // daemon process (System, Actor) bypasses role checks.
        // External-identity variants (Unauthenticated, Peer)
        // must NOT bypass — they have to go through the
        // registry's grant lookup.
        assert!(!Caller::Unauthenticated.is_trusted());
        assert!(!Caller::Peer(alloc::vec![1]).is_trusted());
        assert!(Caller::System.is_trusted());
        assert!(Caller::Actor(crate::actors::context::ServiceId(0)).is_trusted());
    }

    #[test]
    fn no_roles_byte_roundtrip() {
        assert_eq!(NoRoles::from_byte(0), Some(NoRoles::Any));
        assert_eq!(NoRoles::from_byte(1), None);
        assert_eq!(NoRoles::Any.as_byte(), 0);
    }

    #[test]
    fn no_roles_map_admits_every_tier() {
        // Sentinel map used by actors that opted out of RBAC:
        // every space tier resolves to `Any`, and `allows` is
        // trivially `true` for any required role. Confirms
        // existing actors don't accidentally deny calls after
        // the trait extension lands.
        for sr in [
            SpaceRole::Guest,
            SpaceRole::Member,
            SpaceRole::Developer,
            SpaceRole::Admin,
        ] {
            assert_eq!(NO_ROLES_MAP.lookup(sr), Some(NoRoles::Any));
            assert!(NO_ROLES_MAP.allows(sr, NoRoles::Any));
        }
    }

    #[test]
    fn forbidden_displays_user_facing_text() {
        // Display text is what bubbles up through anyhow chains
        // and into vosx stderr. Lock the wording.
        let s = alloc::format!("{}", Forbidden);
        assert!(
            s.contains("permission denied"),
            "Forbidden display must contain 'permission denied'; got: {s}",
        );
    }

    #[test]
    fn caller_grant_key_only_for_peer() {
        // The registry's grant table keys on the binding bytes
        // for Peer (and eventually Member). Unauthenticated and
        // intra-system Actor calls are policy-checked by kind,
        // not by per-caller grants — `grant_key` must return
        // None for both so a lookup is structurally impossible.
        assert_eq!(Caller::Unauthenticated.grant_key(), None);
        assert_eq!(Caller::System.grant_key(), None);
        assert_eq!(
            Caller::Actor(crate::actors::context::ServiceId(7)).grant_key(),
            None
        );
        let bytes = alloc::vec![9, 9, 9];
        assert_eq!(Caller::Peer(bytes.clone()).grant_key(), Some(&bytes[..]));
    }

    // ── IntraCap parsing + lookup ───────────────────────────────

    #[test]
    fn intra_cap_parse_exact() {
        let c = IntraCap::parse("space-registry:admin").unwrap();
        assert_eq!(c.actor_name.as_deref(), Some("space-registry"));
        assert_eq!(c.role, Some(SpaceRole::Admin));
        assert!(!c.is_actor_wildcard());
        assert!(!c.is_full_wildcard());

        // Synonyms + case-folding of the actor name.
        let c = IntraCap::parse("Dev-Project:dev").unwrap();
        assert_eq!(c.actor_name.as_deref(), Some("dev-project"));
        assert_eq!(c.role, Some(SpaceRole::Developer));
    }

    #[test]
    fn intra_cap_parse_wildcards() {
        // Any role on a named actor.
        let c = IntraCap::parse("space-registry:*").unwrap();
        assert_eq!(c.actor_name.as_deref(), Some("space-registry"));
        assert_eq!(c.role, None);
        assert_eq!(c.ceiling(), SpaceRole::Admin); // any-role == max tier

        // A role on any actor.
        let c = IntraCap::parse("*:guest").unwrap();
        assert!(c.is_actor_wildcard());
        assert_eq!(c.role, Some(SpaceRole::Guest));
        assert!(!c.is_full_wildcard());

        // Bare `*` and explicit `*:*` are the full-wildcard footgun.
        for tok in ["*", "*:*"] {
            let c = IntraCap::parse(tok).unwrap();
            assert!(c.is_full_wildcard(), "{tok} should be full wildcard");
            assert!(c.is_actor_wildcard());
            assert_eq!(c.role, None);
        }
    }

    #[test]
    fn intra_cap_parse_malformed_is_visible_error() {
        // No colon (and not the bare `*`) — operator typo.
        let e = IntraCap::parse("space-registry").unwrap_err();
        assert_eq!(e.token, "space-registry");
        assert!(e.reason.contains("actor:role"));

        // Empty sides.
        assert!(IntraCap::parse(":admin").is_err());
        assert!(IntraCap::parse("space-registry:").is_err());

        // Unknown role name.
        let e = IntraCap::parse("space-registry:wizard").unwrap_err();
        assert!(e.reason.contains("unknown role"), "{}", e.reason);

        // Display surfaces the offending token + reason for the operator.
        let s = alloc::format!("{e}");
        assert!(s.contains("space-registry:wizard"), "{s}");
    }

    #[test]
    fn cap_for_no_match_is_none() {
        let caps = [IntraCap::parse("space-registry:admin").unwrap()];
        // Unrelated target, and an unresolved target: neither matches
        // a name-pinned cap.
        assert_eq!(cap_for(&caps, Some("dev-project")), None);
        assert_eq!(cap_for(&caps, None), None);
        // Empty caps deny everything.
        assert_eq!(cap_for(&[], Some("space-registry")), None);
    }

    #[test]
    fn cap_for_exact_and_case_insensitive() {
        let caps = [IntraCap::parse("space-registry:developer").unwrap()];
        assert_eq!(
            cap_for(&caps, Some("space-registry")),
            Some(SpaceRole::Developer)
        );
        // Target name matching is case-insensitive (mirrors I4).
        assert_eq!(
            cap_for(&caps, Some("SPACE-REGISTRY")),
            Some(SpaceRole::Developer)
        );
    }

    #[test]
    fn cap_for_prefix_wildcard_matches_named_targets_only() {
        // The dynamic-install shape: one cap covers every
        // per-channel agent pair without knowing channel names at
        // manifest time.
        let caps = [IntraCap::parse("msg-*:member").unwrap()];
        for t in ["msg-general-log", "msg-dev-ctl", "msg-directory", "MSG-X"] {
            assert_eq!(cap_for(&caps, Some(t)), Some(SpaceRole::Member), "{t}");
        }
        // Not a substring match, and never an unresolved target —
        // prefix caps require a resolved instance name.
        assert_eq!(cap_for(&caps, Some("amsg-x")), None);
        assert_eq!(cap_for(&caps, Some("msg")), None);
        assert_eq!(cap_for(&caps, None), None);

        // Degenerate `prefix*` with empty prefix matches any *named*
        // target (still not unresolved ones — that stays `*`-only).
        let caps = [IntraCap::parse("x*:guest").unwrap()];
        assert_eq!(cap_for(&caps, Some("x")), Some(SpaceRole::Guest));
        assert_eq!(cap_for(&caps, Some("y")), None);
    }

    #[test]
    fn intra_cap_parse_rejects_non_trailing_star() {
        for tok in ["m*g:member", "*foo:member", "f**:member", "**:member"] {
            let e = IntraCap::parse(tok).unwrap_err();
            assert!(e.reason.contains("trailing prefix"), "{tok} → {}", e.reason);
        }
        // Trailing form parses and round-trips through Display.
        let c = IntraCap::parse("Msg-*:member").unwrap();
        assert_eq!(c.actor_name.as_deref(), Some("msg-*"));
        let rendered = alloc::format!("{c}");
        assert_eq!(rendered, "msg-*:member");
        assert_eq!(IntraCap::parse(&rendered).unwrap(), c);
    }

    #[test]
    fn cap_for_wildcard_actor_matches_any_including_unresolved() {
        let caps = [IntraCap::parse("*:member").unwrap()];
        assert_eq!(
            cap_for(&caps, Some("space-registry")),
            Some(SpaceRole::Member)
        );
        assert_eq!(cap_for(&caps, Some("anything")), Some(SpaceRole::Member));
        // Unresolved target still matches a `*` actor cap.
        assert_eq!(cap_for(&caps, None), Some(SpaceRole::Member));
    }

    #[test]
    fn intra_cap_display_round_trips() {
        // Canonical form is snapshot-stable (operator boot log) and
        // re-parses to the same cap. Bare "*" canonicalises to "*:*".
        let cases = [
            ("space-registry:admin", "space-registry:admin"),
            ("space-registry:*", "space-registry:*"),
            ("*:guest", "*:guest"),
            ("*", "*:*"),
            ("*:*", "*:*"),
            ("Dev-Project:dev", "dev-project:developer"),
        ];
        for (input, canonical) in cases {
            let c = IntraCap::parse(input).unwrap();
            let rendered = alloc::format!("{c}");
            assert_eq!(rendered, canonical, "display of {input}");
            // Round-trip: rendering re-parses to an equal cap.
            assert_eq!(IntraCap::parse(&rendered).unwrap(), c, "round-trip {input}");
        }
    }

    #[test]
    fn cap_for_takes_max_ceiling_among_matches() {
        // Caps are grants — their union applies, so the highest
        // ceiling among matching entries wins.
        let caps = [
            IntraCap::parse("space-registry:member").unwrap(),
            IntraCap::parse("*:developer").unwrap(),
        ];
        assert_eq!(
            cap_for(&caps, Some("space-registry")),
            Some(SpaceRole::Developer),
        );
        // Wildcard-role cap raises the ceiling to the max tier.
        let caps = [
            IntraCap::parse("space-registry:member").unwrap(),
            IntraCap::parse("space-registry:*").unwrap(),
        ];
        assert_eq!(
            cap_for(&caps, Some("space-registry")),
            Some(SpaceRole::Admin)
        );
    }
}
