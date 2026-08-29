use super::Context;
use super::codec::{Decode, Encode};
use super::run::RunResult;

/// The core actor trait. Defines the full lifecycle of a VOS actor:
/// construction, startup, message dispatch, commit, and error handling.
///
/// Serialization is handled by the `Encode + Decode` supertraits, which
/// are blanket-implemented for any type with rkyv derives. The `#[actor]`
/// macro adds these derives automatically.
///
/// ## Lifecycle hooks
///
/// - [`on_start`](Actor::on_start) — runs once on cold start, after
///   `create()`, before the message loop. Long-running actors place their
///   main loop here; `yield_now`/`sleep` work as usual.
///
/// ## With macros
///
/// `#[actor]` generates rkyv derives + `impl Actor` with:
/// - `type Message` = the `{Name}Msg` enum (from `#[messages]`)
/// - `create` → calls `Self::new()`
/// - `dispatch` → forwards to `msg.deliver(self, ctx)`
/// - `on_start` → forwards to `start` handler if one is defined
///
/// Agent state fields must be named so their names and lane codecs can be
/// authenticated by the signed package schema. A unit struct is the explicit
/// stateless shape and remains fully supported:
///
/// ```
/// use vos::prelude::*;
///
/// #[actor]
/// struct Health;
///
/// #[messages]
/// impl Health {
///     fn new() -> Self {
///         Self
///     }
///
///     #[msg]
///     fn ready(&self) -> bool {
///         true
///     }
/// }
///
/// let _ = <Health as vos::Actor>::create();
/// ```
///
/// Tuple fields have no stable field names and are rejected at compile time:
///
/// ```compile_fail
/// use vos::actor;
///
/// #[actor]
/// struct Coordinates(u64, u64);
/// ```
///
/// ## Without macros
///
/// Add rkyv derives manually and implement `Actor`:
///
/// ```ignore
/// #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
/// struct MyActor { count: i32 }
///
/// impl Actor for MyActor {
///     type Error = ();
///     type Message = MyActorMsg;
///     fn create() -> Self { MyActor { count: 0 } }
///     fn dispatch(&mut self, msg: Self::Message, ctx: &mut Context<Self>) -> RunResult<bool> {
///         vos::try_poll(async { msg.deliver(self, ctx).await })
///     }
/// }
/// ```
pub trait Actor: Sized + Encode + Decode {
    /// Error type for message handlers.
    type Error: core::fmt::Debug;

    /// The message enum dispatched to this actor.
    type Message: super::value::FromDynamic;

    /// The actor's own role hierarchy — the domain-specific tiers
    /// `#[msg(role = X)]` references and `ctx.ensure_role` checks
    /// against. Auto-derived to [`NoRoles`](super::auth::NoRoles)
    /// by the `#[actor]` macro for actors that opted out of RBAC;
    /// override by declaring your own enum with `#[derive(...)]`
    /// (or `#[actor(role = MyRole)]`).
    ///
    /// The bounds are minimal: `Copy + Ord` for the `>=` comparison
    /// inside `ensure_role`, plus `RoleByte` so the host can plumb
    /// the discriminant through dispatch as an opaque byte.
    type Role: Copy + Ord + super::auth::RoleByte;

    /// The role applied when no grant resolves — neither an
    /// actor-local grant for this caller nor a space-level role
    /// mapped via [`SPACE_ROLE_MAP`](Self::SPACE_ROLE_MAP). For
    /// most actors this is the lowest tier (deny-by-default for
    /// gated handlers). [`NoRoles::Any`](super::auth::NoRoles::Any)
    /// for the sentinel case.
    const DEFAULT_ROLE: Self::Role;

    /// Mapping from the space-wide
    /// [`SpaceRole`](super::auth::SpaceRole) hierarchy onto this
    /// actor's own [`Role`](Self::Role). Looked up by the
    /// dispatch-time role check when no actor-local grant exists
    /// for the caller. Authors declare this as a const struct
    /// literal — see [`SpaceRoleMap`](super::auth::SpaceRoleMap).
    const SPACE_ROLE_MAP: super::auth::SpaceRoleMap<Self::Role>;

    /// `#[actor(task, provable)]` — this Task is published as a
    /// provable program: a discovery /
    /// publication mark landing in `.vos_meta` for the pin/verify
    /// tooling. Not a semantic fork — record capture stays the
    /// caller's `spawn_provable` opt-in either way. Only valid
    /// alongside `task` (the macro rejects the flag on non-Task
    /// actors: a proof exists only for the witness-delivered,
    /// refine-pure execution shape).
    const PROVABLE: bool = false;

    /// One-line actor description, surfaced by `vosx <target>` help.
    /// The `#[actor]` macro fills it from the first paragraph of the
    /// struct's `///` doc; empty when undocumented.
    const DOC: &'static str = "";

    /// Whether this actor's replicated state is expressed exclusively through
    /// `vos::crdt` field types. Registration must reject `Consistency::Crdt`
    /// for actors where this is false.
    const CRDT: bool = false;

    /// Explicit version of the actor's persisted state contract.
    ///
    /// `#[actor]` also fingerprints the actor's direct state fields. Bump this
    /// version whenever the archived representation or meaning of a nested
    /// field type changes without changing those direct field declarations.
    /// Native-extension snapshots record and verify both values before rkyv
    /// decoding, so an incompatible snapshot fails closed at startup.
    const STATE_SCHEMA_VERSION: u64 = 0;

    /// Deterministic fingerprint of the actor's direct persisted state shape.
    /// Generated by `#[actor]`; manual `Actor` implementations may override it.
    #[doc(hidden)]
    const STATE_SCHEMA_FINGERPRINT: u64 = 0;

    /// Fingerprints produced by earlier schema encoders that may be migrated
    /// into the current canonical fingerprint. Generated actors list only the
    /// exact legacy rendering of their current declaration, so an actually
    /// different historic schema still fails closed.
    #[doc(hidden)]
    const STATE_SCHEMA_LEGACY_FINGERPRINTS: &'static [u64] = &[];

    /// Conventional execution lane for an unannotated `&mut self` handler.
    /// The actor macro derives this from its fields. Mixed-lane packages must
    /// annotate every mutating method explicitly, so this value is used only
    /// for single-lane actors and source-compatible ordinary actors.
    #[doc(hidden)]
    const DEFAULT_MUTATION_MODE: crate::agent::MethodMode = crate::agent::MethodMode::Linear;

    /// Create a fresh actor instance with default state.
    /// Any initialization data should arrive as a regular message.
    fn create() -> Self;

    /// Point every `#[storage]` field's handle at its key prefix.
    /// Storage handles archive as units (their rows are the data), so
    /// the framework re-initializes them after every `create()` /
    /// decode. Generated by the `#[actor]` macro; the default no-op
    /// covers actors without storage fields.
    #[doc(hidden)]
    fn __init_storage(&mut self) {}

    /// Assign stable generated tags to every replicated CRDT field after
    /// create/decode. Field tags are runtime handles and are not archived in
    /// actor state.
    #[doc(hidden)]
    fn __init_crdt_fields(&mut self) {}

    /// Merge another causal frontier materialization into this actor before a
    /// CRDT handler runs. `#[actor(crdt)]` generates one field-wise merge;
    /// ordinary actors never receive multiple state inputs.
    #[doc(hidden)]
    fn __merge_crdt(&mut self, _other: &Self) -> Result<(), crate::crdt::Error> {
        Ok(())
    }

    /// Reconstruct the actor from independently persisted agent lanes. Manual
    /// Actor implementations keep a linear whole-state fallback; `#[actor]`
    /// generates field-wise loading for all three lanes.
    #[doc(hidden)]
    fn __load_agent_state(
        linear: Option<&[u8]>,
        _merge: Option<&[u8]>,
        _local: Option<&[u8]>,
    ) -> Option<Self> {
        match linear {
            Some(bytes) if !bytes.is_empty() => Self::try_decode(bytes),
            _ => Some(Self::create()),
        }
    }

    /// Encode one independently persisted agent lane. Generated actors emit a
    /// declaration-ordered field sequence; manual actors use whole-state
    /// linear persistence.
    #[doc(hidden)]
    fn __save_agent_lane(&self, lane: crate::agent::StateLane) -> alloc::vec::Vec<u8> {
        if lane == crate::agent::StateLane::Linear {
            self.encode()
        } else {
            alloc::vec::Vec::new()
        }
    }

    /// Whether any `#[storage(committed)]` field exists. A committed
    /// actor anchors its work-results with `anchor_kind 0x02`
    /// composite roots; the cold-start path uses this to know whether
    /// to look for the recorded composite row. Set by the `#[actor]`
    /// macro.
    #[doc(hidden)]
    const COMMITTED: bool = false;

    /// The committed-storage composite root: `state_hash` folded with
    /// each `#[storage(committed)]` field's SMT root in declaration
    /// order (`vos::zk::state::composite_fold`). `None` — the default,
    /// for actors without committed fields — keeps the actor on
    /// blob-hash (`0x01`) anchors. Generated by the `#[actor]` macro;
    /// the halt path calls it after the handler ran, so the field
    /// roots reflect this dispatch's writes through the overlay.
    #[doc(hidden)]
    fn __committed_root(&self, _state_hash: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }

    /// Called once on cold start, after `create()`, before the message
    /// dispatch loop. The default is a no-op.
    ///
    /// Use this for long-running actor loops (`yield_now` / `sleep` work
    /// normally) or one-shot initialization that needs the context.
    ///
    /// The `#[actor]` macro auto-generates this to forward to the `start`
    /// message handler if one is defined via `#[messages]`.
    async fn on_start(
        &mut self,
        _ctx: &mut Context<Self>,
    ) -> core::result::Result<(), Self::Error> {
        Ok(())
    }

    /// Dispatch a typed message to the appropriate handler.
    /// Returns `Complete(true)` to stop, `Complete(false)` to continue, `Yielded` to suspend.
    fn dispatch(&mut self, msg: Self::Message, ctx: &mut Context<Self>) -> RunResult<bool>;

    /// Called when a message handler returns an error. Return `true` to
    /// stop processing remaining messages in this batch, `false` to continue.
    #[allow(unused_variables)]
    fn on_error(&mut self, error: &Self::Error) -> bool {
        #[cfg(feature = "pvm")]
        {
            struct ErrorWriter;
            impl core::fmt::Write for ErrorWriter {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    crate::abi::pvm::hostcalls::debug_write(s.as_bytes());
                    Ok(())
                }
            }
            let _ = core::fmt::write(&mut ErrorWriter, format_args!("error: {:?}\n", error));
        }
        true
    }
}

/// Defines how an actor handles a specific message type.
///
/// `Output` is the raw return type of the handler:
/// - Infallible handlers: `Output = T` (e.g. `u64`)
/// - Fallible handlers: `Output = Result<T, E>`
///
/// The macro generates deliver arms that handle each case appropriately.
pub trait Message<M>: Actor {
    type Output;

    /// Process the message with exclusive mutable access to actor state.
    async fn handle(&mut self, msg: M, ctx: &mut Context<Self>) -> Self::Output;
}
