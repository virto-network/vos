use super::Actor;
use super::auth::{Caller, Forbidden, RoleByte, SpaceRole};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Execution context passed to message handlers.
///
/// Queues effects (transfers, storage writes, spawns) during handler
/// execution. Effects are flushed after each handler via hostcalls.
///
/// Also provides cooperative async primitives:
/// - `tell()` — fire-and-forget dynamic message
/// - `ask()` — query another actor, suspends until reply (returns `Value`)
/// - `yield_now()` — commit state and yield to other actors
/// - `sleep(n)` — commit state and sleep for N ticks
pub struct Context<A: Actor> {
    id: ServiceId,
    actor_id: Option<crate::v2::ActorId>,
    stop_requested: bool,

    /// Identity of whoever invoked the handler currently running.
    /// `Unauthenticated` by default until per-invoke plumbing
    /// overwrites it from the [`InvokeRequest`].
    caller: Caller,
    /// Typed v2 origin. Legacy callers are mapped into this field at the
    /// dispatch boundary; new service code sets it directly from the work
    /// envelope.
    origin: crate::v2::Origin,

    /// Caller's space-wide role byte — a
    /// [`SpaceRole`](super::auth::SpaceRole) discriminant. `None`
    /// when the registry holds no space-level grant for this
    /// caller. M3 ships the field; M5 populates it from
    /// `lookup_caller_role` and `set_caller_roles` plumbs it in.
    space_role: Option<u8>,

    /// Caller's actor-local role byte — a discriminant of this
    /// actor's [`Role`](super::Actor::Role) enum, set when the
    /// registry holds an actor-local grant overriding the
    /// space-level tier. Takes precedence over `space_role` in
    /// [`Self::caller_role`].
    actor_local_role: Option<u8>,

    /// Set by the M6 macro-emitted pre-dispatch check when the
    /// caller's role doesn't satisfy the handler's
    /// `#[msg(role = X)]`. Surfaces upstream via
    /// [`lifecycle::exit_status`](super::lifecycle::exit_status)
    /// as `STATUS_FORBIDDEN` so the wire envelope carries the
    /// refusal and vosx prints "permission denied" — same
    /// surface the Sprint-2 dispatch-layer gate produced.
    forbidden: bool,

    // Effect queues (drained into the refine output payload)
    pending_tells: Vec<PendingTell>,
    pending_writes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    pending_spawns: Vec<[u8; 32]>,
    pending_provides: Vec<([u8; 32], Vec<u8>)>,
    #[cfg(feature = "pvm")]
    pending_actor_calls: Vec<crate::v2::ActorCallRequestV2>,
    #[cfg(feature = "pvm")]
    pending_actor_spawns: Vec<crate::v2::ActorSpawnRequestV2>,
    #[cfg(feature = "pvm")]
    first_await_ordinal: u64,
    #[cfg(feature = "pvm")]
    next_await_ordinal: u64,
    actor_tree: Vec<crate::v2::ActorTreeImportV2>,
    external_actors: Vec<crate::v2::ExternalActorBindingV2>,
    #[cfg(feature = "pvm")]
    active_actor_mask: u64,
    #[cfg(feature = "pvm")]
    actor_change: Option<crate::v2::ChangeId>,
    #[cfg(feature = "pvm")]
    actor_ipc_capacity: usize,
    #[cfg(feature = "pvm")]
    nested_writes: BTreeMap<(crate::v2::ActorId, Vec<u8>), Option<Vec<u8>>>,
    #[cfg(feature = "pvm")]
    nested_actor_calls: Vec<crate::v2::ActorCallRequestV2>,
    #[cfg(feature = "pvm")]
    nested_actor_spawns: Vec<crate::v2::ActorSpawnRequestV2>,
    #[cfg(feature = "pvm")]
    nested_crdt_operations: Vec<crate::v2::CrdtOperationV2>,
    #[cfg(feature = "pvm")]
    nested_crdt_states: BTreeMap<crate::v2::ActorId, crate::v2::ActorCrdtStateV2>,
    pending_attestation_verifications: Vec<crate::v2::AttestationVerificationV2>,
    pending_verification_blobs: BTreeMap<crate::v2::Hash, crate::v2::ImportedBlobV2>,

    // Reply data (rkyv-encoded Value, included in refine output)
    reply: Option<Vec<u8>>,

    // Cooperative scheduling
    self_schedule: bool,
    #[cfg(feature = "pvm")]
    checkpoint: Option<crate::v2::CheckpointTokenV2>,

    // Worker host I/O: the handler yields with a request, the host
    // fulfills it and provides the result before re-polling.
    host_io_request: Option<Vec<u8>>,
    host_io_result: Option<Vec<u8>>,

    _phantom: core::marker::PhantomData<A>,
}

pub use crate::abi::service::ServiceId;

/// A queued transfer to another service (fire-and-forget).
#[allow(dead_code)] // Fields read in cfg(pvm) path
struct PendingTell {
    target: ServiceId,
    payload: Vec<u8>,
}

impl<A: Actor> Context<A> {
    pub fn new(id: ServiceId) -> Self {
        Self {
            id,
            actor_id: None,
            stop_requested: false,
            caller: Caller::Unauthenticated,
            origin: crate::v2::Origin::Anonymous,
            space_role: None,
            actor_local_role: None,
            forbidden: false,
            pending_tells: Vec::new(),
            pending_writes: Vec::new(),
            pending_spawns: Vec::new(),
            pending_provides: Vec::new(),
            #[cfg(feature = "pvm")]
            pending_actor_calls: Vec::new(),
            #[cfg(feature = "pvm")]
            pending_actor_spawns: Vec::new(),
            #[cfg(feature = "pvm")]
            first_await_ordinal: 0,
            #[cfg(feature = "pvm")]
            next_await_ordinal: 0,
            actor_tree: Vec::new(),
            external_actors: Vec::new(),
            #[cfg(feature = "pvm")]
            active_actor_mask: 0,
            #[cfg(feature = "pvm")]
            actor_change: None,
            #[cfg(feature = "pvm")]
            actor_ipc_capacity: 0,
            #[cfg(feature = "pvm")]
            nested_writes: BTreeMap::new(),
            #[cfg(feature = "pvm")]
            nested_actor_calls: Vec::new(),
            #[cfg(feature = "pvm")]
            nested_actor_spawns: Vec::new(),
            #[cfg(feature = "pvm")]
            nested_crdt_operations: Vec::new(),
            #[cfg(feature = "pvm")]
            nested_crdt_states: BTreeMap::new(),
            pending_attestation_verifications: Vec::new(),
            pending_verification_blobs: BTreeMap::new(),
            reply: None,
            self_schedule: false,
            #[cfg(feature = "pvm")]
            checkpoint: None,
            host_io_request: None,
            host_io_result: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get this actor's service ID.
    pub fn id(&self) -> ServiceId {
        self.id
    }

    /// Typed v2 identity of this actor when running under the generic service.
    /// Legacy standalone/service paths do not synthesize an `ActorId` and
    /// therefore return `None`.
    pub fn actor_id(&self) -> Option<crate::v2::ActorId> {
        self.actor_id
    }

    fn resolve_owned_actor_v2(
        &self,
        parent: Option<crate::v2::ActorId>,
        name: &str,
    ) -> Option<crate::v2::ActorId> {
        self.actor_tree
            .iter()
            .find(|actor| actor.parent == parent && actor.name == name)
            .map(|actor| actor.actor)
    }

    fn resolve_external_actor_v2(&self, name: &str) -> Option<crate::v2::ActorId> {
        self.external_actors
            .binary_search_by(|actor| actor.name.as_str().cmp(name))
            .ok()
            .map(|index| self.external_actors[index].actor)
    }

    #[doc(hidden)]
    pub fn __set_actor_id(&mut self, actor: crate::v2::ActorId) {
        self.actor_id = Some(actor);
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __set_actor_tree_v2(
        &mut self,
        actor_tree: Vec<crate::v2::ActorTreeImportV2>,
        external_actors: Vec<crate::v2::ExternalActorBindingV2>,
        change: Option<crate::v2::ChangeId>,
        ipc_capacity: usize,
        first_await_ordinal: u64,
        active_actor_mask: u64,
    ) {
        self.actor_tree = actor_tree;
        self.external_actors = external_actors;
        self.active_actor_mask = active_actor_mask;
        self.actor_change = change;
        self.actor_ipc_capacity = ipc_capacity;
        self.first_await_ordinal = first_await_ordinal;
        self.next_await_ordinal = first_await_ordinal;
    }

    /// Who invoked the currently-running handler. The host writes
    /// this from the [`InvokeRequest`] before each dispatch; PVM
    /// guests receive it via a hostcall (wired in M3).
    ///
    /// Variants:
    /// - [`Caller::Unauthenticated`]: no credentials presented
    ///   (HTTP gateway public routes; host-initiated calls).
    /// - [`Caller::Peer`]: a libp2p peer, noise-verified.
    /// - [`Caller::Actor`]: an intra-system invoke from another
    ///   actor on the same node.
    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// Overwrite the caller for the next handler dispatch. Called
    /// by the host dispatch layer (and the macro-emitted glue) so
    /// each invocation sees the right caller — Context outlives
    /// individual invocations, so this is a per-call slot.
    pub fn set_caller(&mut self, caller: Caller) {
        self.origin = match &caller {
            Caller::Unauthenticated => crate::v2::Origin::Anonymous,
            Caller::System => crate::v2::Origin::System,
            Caller::Peer(bytes) => crate::v2::Origin::Member(crate::v2::SubjectId(
                crate::crypto::blake2b_hash::<32>(b"vos/subject/v2", &[bytes]),
            )),
            Caller::Actor(id) => {
                crate::v2::Origin::Actor(crate::v2::ActorId(crate::crypto::blake2b_hash::<32>(
                    b"vos/legacy-service-actor/v2",
                    &[&id.0.to_le_bytes()],
                )))
            }
        };
        self.caller = caller;
    }

    /// Authenticated, typed origin supplied by `WorkEnvelopeV2`.
    pub fn origin(&self) -> crate::v2::Origin {
        self.origin
    }

    #[doc(hidden)]
    pub fn __set_origin(&mut self, origin: crate::v2::Origin) {
        self.origin = origin;
    }

    /// Overwrite the per-invocation role bytes. Mirrors
    /// [`Self::set_caller`] — called by host glue before each
    /// dispatch so the caller's grants are visible to handler
    /// code. `space_role` is a [`SpaceRole`] discriminant;
    /// `actor_local_role` is an [`A::Role`](Actor::Role)
    /// discriminant (takes precedence when both are present).
    pub fn set_caller_roles(&mut self, space_role: Option<u8>, actor_local_role: Option<u8>) {
        self.space_role = space_role;
        self.actor_local_role = actor_local_role;
    }

    /// Resolve the caller's effective role for *this* actor.
    ///
    /// Lookup precedence (matches the host dispatch path):
    /// 1. If an actor-local grant exists, decode the byte against
    ///    `A::Role` and use that — overrides any space-level
    ///    grant.
    /// 2. Else fall back to the space-level role and map it via
    ///    [`A::SPACE_ROLE_MAP`](Actor::SPACE_ROLE_MAP).
    /// 3. Else `None`. Calls
    ///    [`Self::ensure_role`](Self::ensure_role) at any tier
    ///    higher than `A::DEFAULT_ROLE` will fail.
    ///
    /// Actor and system origins receive no implicit role. Internal callers
    /// must carry an explicit actor grant or authenticated platform
    /// capability just like any other origin.
    pub fn caller_role(&self) -> Option<A::Role> {
        if let Some(b) = self.actor_local_role {
            return A::Role::from_byte(b);
        }
        self.space_role
            .and_then(SpaceRole::from_u8)
            .and_then(|sr| A::SPACE_ROLE_MAP.lookup(sr))
    }

    /// True iff the caller's effective role satisfies `required`
    /// — i.e. `>=` in the actor's role hierarchy.
    /// System and actor origins do not bypass this check. Internal callers
    /// must carry an explicit actor grant or platform capability just like
    /// any other origin.
    pub fn has_role(&self, required: A::Role) -> bool {
        self.caller_role().is_some_and(|r| r >= required)
    }

    /// True iff the authenticated space-wide grant directly satisfies the
    /// requested tier. Actor-local role mappings are deliberately irrelevant
    /// to `#[msg(space_role = ...)]` policies.
    pub fn has_space_role(&self, required: SpaceRole) -> bool {
        self.space_role
            .and_then(SpaceRole::from_u8)
            .is_some_and(|role| role >= required)
    }

    pub fn ensure_space_role(&self, required: SpaceRole) -> Result<(), Forbidden> {
        if self.has_space_role(required) {
            Ok(())
        } else {
            Err(Forbidden)
        }
    }

    /// `?`-friendly role check. Returns [`Forbidden`] when the
    /// caller's effective role is insufficient. Handler authors
    /// who want `?` propagation impl `From<Forbidden>` for their
    /// actor's error type:
    ///
    /// ```ignore
    /// impl From<Forbidden> for MyError { ... }
    ///
    /// async fn merge(&mut self, ctx: &mut Context<Self>) -> Result<(), MyError> {
    ///     ctx.ensure_role(MyRole::Maintainer)?;
    ///     // ...
    /// }
    /// ```
    ///
    /// The M6 macro-emitted check at the dispatch boundary
    /// halts the actor with `STATUS_FORBIDDEN` *before* the
    /// handler runs, so this method is for the *manual*
    /// composability case (e.g.
    /// `ensure_role(Maintainer).or_else(|_| ensure_owner(...))`).
    pub fn ensure_role(&self, required: A::Role) -> Result<(), Forbidden> {
        if self.has_role(required) {
            Ok(())
        } else {
            Err(Forbidden)
        }
    }

    /// Byte-form of [`Self::has_role`] used by the M6 macro-emitted
    /// pre-dispatch check, which only has the raw discriminant
    /// from the message enum's `required_role()` and doesn't want
    /// to round-trip through `A::Role::from_byte`.
    pub fn has_role_byte(&self, required: u8) -> bool {
        match A::Role::from_byte(required) {
            Some(req) => self.has_role(req),
            None => false,
        }
    }

    /// Flag the current dispatch as refused. Called by the M6
    /// macro-emitted pre-handler check when
    /// [`Self::has_role_byte`] returns false — surfaces upstream
    /// via [`lifecycle::exit_status`](super::lifecycle::exit_status)
    /// as `STATUS_FORBIDDEN`. Hidden — actor authors who want
    /// custom policy use [`Self::ensure_role`] instead.
    #[doc(hidden)]
    pub fn __mark_forbidden(&mut self) {
        self.forbidden = true;
    }

    /// Whether the current dispatch was flagged as refused.
    /// Read by [`exit_status`](super::lifecycle::exit_status)
    /// when packing the wire envelope.
    pub fn was_forbidden(&self) -> bool {
        self.forbidden
    }

    /// Reset the forbidden flag between dispatches. The actor
    /// framework calls this on every new invocation so a refused
    /// call doesn't poison subsequent dispatches sharing the same
    /// Context.
    #[doc(hidden)]
    pub fn __reset_forbidden(&mut self) {
        self.forbidden = false;
    }

    // --- Storage ---

    /// Read and decode a typed value from per-service storage.
    /// Overlays this dispatch's own queued mutations ([`store`] /
    /// [`remove`]) so a handler reads what it just wrote — the same
    /// read-your-own-writes semantic the host journal gives across
    /// dispatches.
    ///
    /// [`store`]: Self::store
    /// [`remove`]: Self::remove
    #[cfg(feature = "service")]
    pub fn load<T: super::codec::Decode>(&self, key: &[u8]) -> Option<T> {
        if let Some((_, pending)) = self
            .pending_writes
            .iter()
            .rev()
            .find(|(k, _)| k.as_slice() == key)
        {
            return pending
                .as_deref()
                .and_then(|bytes| super::codec::Decode::try_decode(bytes));
        }
        super::lifecycle::load::<T>(key)
    }

    // --- Fire-and-forget messaging ---

    /// Send raw bytes to another service (fire-and-forget).
    /// Prefer `tell()` for cross-actor dynamic messaging.
    pub fn tell_raw(&mut self, target: ServiceId, payload: &[u8]) {
        self.pending_tells.push(PendingTell {
            target,
            payload: payload.to_vec(),
        });
    }

    /// Send a typed message to another service (auto-encodes).
    pub fn send<M: super::codec::Encode>(&mut self, target: ServiceId, msg: &M) {
        self.tell_raw(target, &msg.encode());
    }

    /// Send a typed message to self (auto-encodes, self-targets).
    pub fn send_self<M: super::codec::Encode>(&mut self, msg: &M) {
        let id = self.id;
        self.tell_raw(id, &msg.encode());
    }

    /// Send a dynamic message to another actor (fire-and-forget).
    ///
    /// The message is encoded with a tag byte so the receiver's `dispatch_one`
    /// decodes it as a `Msg` and converts via `FromDynamic`.
    pub fn tell(&mut self, target: ServiceId, msg: &super::value::Msg) {
        let encoded = super::codec::Encode::encode(msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(super::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.tell_raw(target, &payload);
    }

    // --- Query (ask) ---

    /// Query another actor with a dynamic message. Suspends until reply.
    ///
    /// Returns an `Ask` future — `.await` it to get the reply as a `Value`.
    /// The message is encoded with a tag byte for dynamic dispatch.
    pub fn ask(&mut self, target: ServiceId, msg: &super::value::Msg) -> super::run::Ask {
        let encoded = super::codec::Encode::encode(msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(super::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.ask_raw(target, &payload)
    }

    /// Raw query — takes pre-encoded payload bytes.
    ///
    /// On guest builds (`pvm`) this issues an `INVOKE` hostcall
    /// synchronously: the host runs the child to completion and writes
    /// the reply into our buffer before returning. The returned `Ask`
    /// is `Ready` from the first poll. No replay, no snapshots, no
    /// pending state — the parent PVM is suspended at the ecall by the
    /// host loop and resumes here with the reply already in hand.
    ///
    /// On non-guest builds (host tests, etc.) this returns
    /// `InvokeError::NotFound` since there is no PVM to dispatch into.
    pub fn ask_raw(&mut self, target: ServiceId, payload: &[u8]) -> super::run::Ask {
        #[cfg(feature = "pvm")]
        {
            use super::lifecycle::{InvokeResult, invoke_raw};
            use super::value::InvokeError;
            match invoke_raw(target.0, payload, &[]) {
                InvokeResult::Done { reply, .. } | InvokeResult::Yielded { reply, .. } => {
                    super::run::Ask::ready(reply)
                }
                InvokeResult::Panicked => super::run::Ask::ready_err(InvokeError::Panicked),
                InvokeResult::NotFound => super::run::Ask::ready_err(InvokeError::NotFound),
                InvokeResult::OutOfGas => super::run::Ask::ready_err(InvokeError::OutOfGas),
                InvokeResult::TooBig => super::run::Ask::ready_err(InvokeError::TooBig),
                InvokeResult::Error(s) => super::run::Ask::ready_err(InvokeError::Unknown(s)),
            }
        }
        #[cfg(not(feature = "pvm"))]
        {
            // Worker / WASM: yield to host with an EFFECT_ASK request.
            // Wire format: [tag:u8=EFFECT_ASK][target:u32 LE][payload...]
            let mut request = Vec::with_capacity(5 + payload.len());
            request.push(crate::effects::EFFECT_ASK);
            request.extend_from_slice(&target.0.to_le_bytes());
            request.extend_from_slice(payload);
            super::run::Ask::host_io(self.host_call(request))
        }
    }

    /// Issue a durable v2 call to an actor in another root tree.
    ///
    /// Unlike the legacy route-oriented [`ask`](Self::ask), this call records
    /// a stable await ordinal, checkpoints the exact guest machine before it
    /// observes a result, and resumes only after the owning service injects an
    /// accumulated reply at that same protocol-call boundary.
    pub fn ask_actor(
        &mut self,
        target: crate::v2::ActorId,
        msg: &super::value::Msg,
        deadline_timeslot: Option<u64>,
    ) -> super::run::Ask {
        let encoded = super::codec::Encode::encode(msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(super::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.ask_actor_raw(target, &payload, deadline_timeslot)
    }

    /// Raw durable v2 actor call. This is an advanced runtime primitive;
    /// generated bound handles are the application-facing API.
    pub fn ask_actor_raw(
        &mut self,
        target: crate::v2::ActorId,
        payload: &[u8],
        deadline_timeslot: Option<u64>,
    ) -> super::run::Ask {
        #[cfg(feature = "pvm")]
        {
            if self.actor_id.is_none() || payload.is_empty() {
                return super::run::Ask::ready_err(super::value::InvokeError::NotFound);
            }
            if let Some(inline) = self.__try_inline_actor_v2(target, payload) {
                return inline;
            }
            if self.actor_tree.iter().any(|actor| actor.actor == target) {
                return super::run::Ask::ready_err(super::value::InvokeError::NotFound);
            }
            if self
                .external_actors
                .iter()
                .all(|actor| actor.actor != target)
            {
                return super::run::Ask::ready_err(super::value::InvokeError::NotFound);
            }
            let await_ordinal = self.next_await_ordinal;
            self.next_await_ordinal = self
                .next_await_ordinal
                .checked_add(1)
                .expect("v2 actor await ordinal overflow");
            self.pending_actor_calls
                .push(crate::v2::ActorCallRequestV2 {
                    await_ordinal,
                    from: self.actor_id.expect("v2 actor identity was checked"),
                    to: target,
                    payload: payload.to_vec(),
                    authorization: crate::v2::AuthorizationEvidenceV2::Public,
                    proof_requested: false,
                    deadline_timeslot,
                });

            let mut response = [0u8; crate::v2::CHECKPOINT_TOKEN_CAPACITY];
            let [resume_kind, response_len] = crate::abi::pvm::hostcalls::suspend_await(
                &mut response,
                await_ordinal,
                crate::v2::AWAIT_SUSPEND_MAGIC,
            );
            match resume_kind {
                0 => {
                    let response_len = usize::try_from(response_len)
                        .expect("await checkpoint payload length exceeds guest usize");
                    assert!(
                        response_len <= response.len(),
                        "await checkpoint payload exceeds buffer"
                    );
                    let checkpoint = <crate::v2::CheckpointTokenV2 as crate::v2::V2Wire>::decode(
                        &response[..response_len],
                    )
                    .expect("invalid v2 await checkpoint token");
                    assert!(
                        checkpoint.pending_call.is_some(),
                        "await checkpoint is missing its stable CallId"
                    );
                    self.checkpoint = Some(checkpoint);
                    self.self_schedule = false;
                    super::run::Ask::checkpoint_pending()
                }
                2 => {
                    let response_len = usize::try_from(response_len)
                        .expect("await resume payload length exceeds guest usize");
                    assert!(
                        response_len <= response.len(),
                        "await resume payload exceeds buffer"
                    );
                    let resume = <crate::v2::AwaitResumeV2 as crate::v2::V2Wire>::decode(
                        &response[..response_len],
                    )
                    .expect("invalid v2 accumulated reply");
                    self.__resume_checkpoint_v2(&resume.checkpoint);
                    self.checkpoint = Some(resume.checkpoint);
                    self.self_schedule = false;
                    super::run::Ask::ready(resume.reply.result)
                }
                3 => {
                    let response_len = usize::try_from(response_len)
                        .expect("timeout resume payload length exceeds guest usize");
                    assert!(
                        response_len <= response.len(),
                        "timeout resume payload exceeds buffer"
                    );
                    let checkpoint = <crate::v2::CheckpointTokenV2 as crate::v2::V2Wire>::decode(
                        &response[..response_len],
                    )
                    .expect("invalid v2 accumulated timeout");
                    self.__resume_checkpoint_v2(&checkpoint);
                    self.checkpoint = Some(checkpoint);
                    self.self_schedule = false;
                    super::run::Ask::ready_err(super::value::InvokeError::Timeout)
                }
                _ => panic!("invalid v2 await resume kind"),
            }
        }
        #[cfg(not(feature = "pvm"))]
        {
            let _ = (target, payload, deadline_timeslot);
            super::run::Ask::ready_err(super::value::InvokeError::NotFound)
        }
    }

    /// Issue a durable cross-root call whose committed reply must carry an
    /// attestation package. Generated attested handle methods are the public
    /// surface; this primitive exists so their `AttestationInvoker` impl can
    /// preserve the exact suspension boundary.
    #[doc(hidden)]
    pub fn ask_actor_attested_raw(
        &mut self,
        target: crate::v2::ActorId,
        payload: &[u8],
        deadline_timeslot: Option<u64>,
    ) -> super::client::AttestedAsk {
        #[cfg(feature = "pvm")]
        {
            use super::client::{AttestedInvocationResult, ClientError};

            if self.actor_id.is_none() || payload.is_empty() {
                return super::client::AttestedAsk::ready(Err(ClientError::NotFound));
            }
            if self.actor_tree.iter().any(|actor| actor.actor == target) {
                return super::client::AttestedAsk::ready(Err(ClientError::InvalidAttestation(
                    crate::AttestationError::CannotSuspend,
                )));
            }
            if self
                .external_actors
                .iter()
                .all(|actor| actor.actor != target)
            {
                return super::client::AttestedAsk::ready(Err(ClientError::NotFound));
            }
            let await_ordinal = self.next_await_ordinal;
            self.next_await_ordinal = self
                .next_await_ordinal
                .checked_add(1)
                .expect("v2 actor await ordinal overflow");
            self.pending_actor_calls
                .push(crate::v2::ActorCallRequestV2 {
                    await_ordinal,
                    from: self.actor_id.expect("v2 actor identity was checked"),
                    to: target,
                    payload: payload.to_vec(),
                    authorization: crate::v2::AuthorizationEvidenceV2::Public,
                    proof_requested: true,
                    deadline_timeslot,
                });

            let mut response = [0u8; crate::v2::CHECKPOINT_TOKEN_CAPACITY];
            let [resume_kind, response_len] = crate::abi::pvm::hostcalls::suspend_await(
                &mut response,
                await_ordinal,
                crate::v2::AWAIT_SUSPEND_MAGIC,
            );
            match resume_kind {
                0 => {
                    let response_len = usize::try_from(response_len)
                        .expect("await checkpoint payload length exceeds guest usize");
                    assert!(
                        response_len <= response.len(),
                        "await checkpoint payload exceeds buffer"
                    );
                    let checkpoint = <crate::v2::CheckpointTokenV2 as crate::v2::V2Wire>::decode(
                        &response[..response_len],
                    )
                    .expect("invalid v2 await checkpoint token");
                    assert!(
                        checkpoint.pending_call.is_some(),
                        "await checkpoint is missing its stable CallId"
                    );
                    self.checkpoint = Some(checkpoint);
                    self.self_schedule = false;
                    super::client::AttestedAsk::checkpoint_pending()
                }
                2 => {
                    let response_len = usize::try_from(response_len)
                        .expect("await resume payload length exceeds guest usize");
                    assert!(
                        response_len <= response.len(),
                        "await resume payload exceeds buffer"
                    );
                    let resume = <crate::v2::AwaitResumeV2 as crate::v2::V2Wire>::decode(
                        &response[..response_len],
                    )
                    .expect("invalid v2 accumulated attestation reply");
                    self.__resume_checkpoint_v2(&resume.checkpoint);
                    self.checkpoint = Some(resume.checkpoint);
                    self.self_schedule = false;
                    let Some(attestation) = resume.attestation else {
                        return super::client::AttestedAsk::ready(Err(
                            ClientError::InvalidAttestation(
                                crate::AttestationError::InvalidStatement,
                            ),
                        ));
                    };
                    let proof_offset = usize::try_from(attestation.proof_offset)
                        .expect("attestation proof offset exceeds guest usize");
                    let proof_len = usize::try_from(attestation.proof_len)
                        .expect("attestation proof length exceeds guest usize");
                    let Some(proof_end) = proof_offset.checked_add(proof_len) else {
                        return super::client::AttestedAsk::ready(Err(
                            ClientError::InvalidAttestation(crate::AttestationError::InvalidProof),
                        ));
                    };
                    if proof_end > self.actor_ipc_capacity {
                        return super::client::AttestedAsk::ready(Err(
                            ClientError::InvalidAttestation(crate::AttestationError::InvalidProof),
                        ));
                    }
                    let proof_address =
                        crate::v2::ACTOR_IPC_BASE_PAGE as usize * 4096usize + proof_offset;
                    // SAFETY: the invocation-owned IPC DATA capability is
                    // mapped over `actor_ipc_capacity`; the descriptor was
                    // bounds-checked above and the service writes it before
                    // resuming this exact protocol call.
                    let proof = unsafe {
                        core::slice::from_raw_parts(proof_address as *const u8, proof_len).to_vec()
                    };
                    if !attestation.proof.proof_blob.matches(&proof) {
                        return super::client::AttestedAsk::ready(Err(
                            ClientError::InvalidAttestation(crate::AttestationError::InvalidProof),
                        ));
                    }
                    let value = if resume.reply.result.is_empty() {
                        super::value::Value::Unit
                    } else {
                        let Some(value) = <super::value::Value as super::codec::Decode>::try_decode(
                            &resume.reply.result,
                        ) else {
                            return super::client::AttestedAsk::ready(Err(ClientError::Decode));
                        };
                        value
                    };
                    super::client::AttestedAsk::ready(Ok(AttestedInvocationResult {
                        value,
                        producer_name: attestation.producer_name,
                        producer: attestation.producer,
                        statement: attestation.statement,
                        trace: attestation.proof.trace,
                        proof,
                    }))
                }
                3 => {
                    let response_len = usize::try_from(response_len)
                        .expect("timeout resume payload length exceeds guest usize");
                    assert!(
                        response_len <= response.len(),
                        "timeout resume payload exceeds buffer"
                    );
                    let checkpoint = <crate::v2::CheckpointTokenV2 as crate::v2::V2Wire>::decode(
                        &response[..response_len],
                    )
                    .expect("invalid v2 accumulated timeout");
                    self.__resume_checkpoint_v2(&checkpoint);
                    self.checkpoint = Some(checkpoint);
                    self.self_schedule = false;
                    super::client::AttestedAsk::ready(Err(ClientError::Call(
                        super::client::CallError::Timeout,
                    )))
                }
                _ => panic!("invalid v2 attested await resume kind"),
            }
        }
        #[cfg(not(feature = "pvm"))]
        {
            let _ = (target, payload, deadline_timeslot);
            super::client::AttestedAsk::ready(Err(super::client::ClientError::Unreachable))
        }
    }

    #[cfg(feature = "pvm")]
    fn __try_inline_actor_v2(
        &mut self,
        target: crate::v2::ActorId,
        payload: &[u8],
    ) -> Option<super::run::Ask> {
        let caller = self.actor_id?;
        let index = self
            .actor_tree
            .binary_search_by_key(&target, |actor| actor.actor)
            .ok()?;
        let imported = self.actor_tree[index].clone();
        let callable_slot = crate::v2::ACTOR_CALLABLE_BASE_SLOT.checked_add(index as u8)?;
        let target_mask = 1u64 << index;
        if self.active_actor_mask & target_mask != 0 {
            return Some(super::run::Ask::ready_err(super::value::InvokeError::Cycle));
        }
        if imported.suspended {
            return Some(super::run::Ask::ready_err(
                super::value::InvokeError::NotFound,
            ));
        }

        let child_input = crate::v2::ActorSliceInputV2 {
            actor: target,
            change: self.actor_change,
            state: imported.state,
            causal_states: imported.causal_states,
            actor_tree: self.actor_tree.clone(),
            external_actors: self.external_actors.clone(),
            active_actor_mask: self.active_actor_mask | target_mask,
            first_await_ordinal: self.next_await_ordinal,
            message: payload.to_vec(),
            origin: crate::v2::Origin::Actor(caller),
            space_role: None,
        };
        let encoded = <crate::v2::ActorSliceInputV2 as crate::v2::V2Wire>::encode(&child_input);
        let capacity = self.actor_ipc_capacity;
        if encoded.len() > capacity {
            return Some(super::run::Ask::ready_err(
                super::value::InvokeError::TooBig,
            ));
        }
        let address = crate::v2::ACTOR_IPC_BASE_PAGE as usize * 4096usize;
        // SAFETY: this actor owns the mapped invocation IPC DATA capability.
        // It remains mapped until JAR CALL moves it to the child.
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), address as *mut u8, encoded.len());
        }
        let local_ipc = crate::abi::pvm::ecall::local_cap_ref(0);
        let nested_ipc =
            crate::abi::pvm::ecall::local_cap_ref(crate::v2::ACTOR_NESTED_IPC_CAP_SLOT);
        assert!(crate::abi::pvm::ecall::move_cap(local_ipc, nested_ipc));
        let output_len = crate::abi::pvm::ecall::call_cap(
            crate::abi::pvm::ecall::local_cap_ref(callable_slot),
            crate::v2::ACTOR_NESTED_IPC_CAP_SLOT,
            address as u64,
            encoded.len() as u64,
            capacity as u64,
            crate::v2::NESTED_ACTOR_CALL_MAGIC,
        );
        assert!(crate::abi::pvm::ecall::move_cap(nested_ipc, local_ipc));
        if output_len == u64::MAX - 1 || output_len == 0 || output_len as usize > capacity {
            return Some(super::run::Ask::ready_err(
                super::value::InvokeError::NotFound,
            ));
        }
        // SAFETY: JAR returned and remapped the exclusive IPC cap to this VM.
        let bytes =
            unsafe { core::slice::from_raw_parts(address as *const u8, output_len as usize) };
        let Ok(output) = <crate::v2::ActorSliceOutputV2 as crate::v2::V2Wire>::decode(bytes) else {
            return Some(super::run::Ask::ready_err(
                super::value::InvokeError::Panicked,
            ));
        };
        if output.actor != target
            || output.first_await_ordinal != self.next_await_ordinal
            || output.forbidden
            || (self.actor_change.is_none()
                && (!output.crdt_operations.is_empty() || !output.crdt_states.is_empty()))
            || (self.actor_change.is_some()
                && (output.crdt_states.is_empty() || !output.writes.is_empty()))
        {
            return Some(super::run::Ask::ready_err(
                super::value::InvokeError::Panicked,
            ));
        }
        if output.checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint
                .previously_suspended
                .binary_search(&caller)
                .is_ok()
        }) {
            // A nested child is the active VM which directly receives the
            // scheduler's resume token. Its suspended caller crosses the same
            // durable boundary when JAR returns the child output, before any
            // new-slice effects are aggregated into this restored Context.
            self.__resume_checkpoint_v2(
                output
                    .checkpoint
                    .as_ref()
                    .expect("checked nested checkpoint presence"),
            );
        }
        for requirement in &output.attestation_verifications {
            let key = requirement.replay_key();
            let index = match self
                .pending_attestation_verifications
                .binary_search_by_key(&key, |verification| verification.replay_key())
            {
                Ok(_) => {
                    return Some(super::run::Ask::ready_err(
                        super::value::InvokeError::Panicked,
                    ));
                }
                Err(index) => index,
            };
            self.pending_attestation_verifications
                .insert(index, requirement.clone());
        }
        for candidate in &output.verification_blobs {
            if self
                .pending_verification_blobs
                .get(&candidate.reference.hash)
                .is_some_and(|existing| existing != candidate)
            {
                return Some(super::run::Ask::ready_err(
                    super::value::InvokeError::Panicked,
                ));
            }
            self.pending_verification_blobs
                .insert(candidate.reference.hash, candidate.clone());
        }
        self.next_await_ordinal = output.next_await_ordinal;
        self.nested_crdt_operations.extend(output.crdt_operations);
        for state in output.crdt_states {
            let Ok(index) = self
                .actor_tree
                .binary_search_by_key(&state.actor, |actor| actor.actor)
            else {
                return Some(super::run::Ask::ready_err(
                    super::value::InvokeError::Panicked,
                ));
            };
            self.actor_tree[index].state = state.state.clone();
            self.actor_tree[index].causal_states.clear();
            self.actor_tree[index].next_crdt_ordinal = state.next_ordinal;
            self.nested_crdt_states.insert(state.actor, state);
        }
        for write in output.writes {
            if write.key.as_slice() == crate::lifecycle::STATE_KEY_BYTES
                && let Some(state) = write.value.as_ref()
                && let Ok(index) = self
                    .actor_tree
                    .binary_search_by_key(&write.actor, |actor| actor.actor)
            {
                self.actor_tree[index].state = state.clone();
            }
            self.nested_writes
                .insert((write.actor, write.key), write.value);
        }
        self.nested_actor_calls.extend(output.outbox);
        self.nested_actor_spawns.extend(output.spawns);
        if output.yielded {
            let Some(checkpoint) = output.checkpoint else {
                return Some(super::run::Ask::ready_err(
                    super::value::InvokeError::Panicked,
                ));
            };
            self.checkpoint = Some(checkpoint);
            self.self_schedule = false;
            Some(super::run::Ask::checkpoint_pending())
        } else {
            // A resumed child completes with a checkpoint token whose
            // replacement is `None`. Preserve that continuation deletion on
            // the parent output while still delivering the child's reply to
            // the original suspended caller.
            if let Some(checkpoint) = output.checkpoint {
                if checkpoint.replacement.is_some() {
                    return Some(super::run::Ask::ready_err(
                        super::value::InvokeError::Panicked,
                    ));
                }
                self.checkpoint = Some(checkpoint);
            }
            Some(super::run::Ask::ready(output.reply))
        }
    }

    /// Transport-mode dispatching ask. Like
    /// [`ask_raw`](Self::ask_raw), but resolves to the **raw reply
    /// bytes** wrapped in an `Option` that distinguishes a real reply
    /// from a dispatch failure — mirroring the old
    /// `ServiceCtx::ask_raw -> Option<Vec<u8>>` the http-gateway was
    /// built around:
    ///
    /// - `Some(bytes)` — the target's handler ran and returned;
    ///   `bytes` is its rkyv-encoded `Value` (empty for a `()` return).
    /// - `None` — no route to the target, a non-`DONE` status (panic /
    ///   not-found / forbidden / OOG), or the 10 s ask timeout.
    ///
    /// This is what lets a gateway render a handler panic as `502`
    /// rather than collapsing it into the `200 null` of a `()` return
    /// (which the plain [`ask_raw`](Self::ask_raw) → `Value::Unit` path
    /// cannot tell apart). Only the native transport host
    /// (`run_transport_extension`'s `ConnFulfiller`) fulfils this; on
    /// every other build it resolves to `None`.
    #[cfg(feature = "extension")]
    pub async fn ask_dispatch(&mut self, target: ServiceId, payload: &[u8]) -> Option<Vec<u8>> {
        // Wire format: [tag=EFFECT_ASK_DISPATCH][target:u32 LE][payload].
        let mut request = Vec::with_capacity(5 + payload.len());
        request.push(crate::effects::EFFECT_ASK_DISPATCH);
        request.extend_from_slice(&target.0.to_le_bytes());
        request.extend_from_slice(payload);
        let resp = self.host_call(request).await;
        // Response is [RESP_OK][reply…] on success, [RESP_ERR] on
        // failure — the same status-framing the byte-stream effects use.
        crate::effects::bytestream::decode_resp_bytes(&resp)
    }

    /// Resolve an installed agent's name to its node-local
    /// `ServiceId` (packed as u32) by asking the well-known
    /// `ServiceId::REGISTRY` service. Returns 0 when no agent
    /// with that name is installed **or** when the registry
    /// invoke fails for any reason — the two cases are
    /// indistinguishable from the return value alone, so
    /// failures emit a `log::warn!` for debugging. Callers that
    /// need explicit error handling should use
    /// [`Context::ask`] against `ServiceId::REGISTRY` directly.
    ///
    /// Thin convenience over `ctx.ask(REGISTRY, Msg::new("resolve")…)`
    /// so actor crates don't need to depend on the registry's
    /// typed Ref to use it. The returned id is dispatchable via
    /// `ctx.tell` / `ctx.send` — same formula `space up` uses
    /// when registering installed agents on this node.
    ///
    /// **Eventual consistency**: if the local registry replica
    /// hasn't yet seen a fresh `install` from another node
    /// (CRDT replication lag), `resolve` returns 0 transiently
    /// even though the agent exists in the space. Callers that
    /// need stronger semantics should retry, or watch for the
    /// agent's appearance via subscriptions.
    ///
    /// ```ignore
    /// let counter = ctx.resolve("counter").await;
    /// if counter != 0 {
    ///     ctx.tell(ServiceId(counter), &Msg::new("inc"));
    /// }
    /// ```
    ///
    /// **Hyperspace fall-through**: when the local registry returns 0
    /// (not found), the call unconditionally re-asks
    /// [`ServiceId::HYPERSPACE_REGISTRY`]. On nodes whose space
    /// declared `hyperspace = "name"` in its manifest, that's a real
    /// lookup against the shared cross-space registry. On nodes
    /// without a hyperspace replica the second ask returns
    /// `InvokeError::NotFound` cheaply, surfaced here as 0.
    ///
    /// Cost: every miss now pays two invokes instead of one. PVM
    /// invokes are synchronous so this is small; if it ever shows up
    /// in a profile, an explicit `resolve_in_hyperspace` could
    /// replace the auto-fallthrough.
    pub async fn resolve(&mut self, name: impl Into<alloc::string::String>) -> u32 {
        let name = name.into();
        let prefix = self.id.node_prefix();

        let mut msg = super::value::Msg::new("resolve");
        msg = msg.with("name", name.clone());
        msg = msg.with("caller_prefix", prefix as u64);
        let primary = self.ask(ServiceId::REGISTRY, &msg).await;
        let local = match primary {
            Ok(super::value::Value::U32(n)) => n,
            Ok(other) => {
                crate::log::warn!(
                    "Context::resolve: local registry returned non-U32 reply ({other:?}); treating as not-found",
                );
                0
            }
            Err(e) => {
                crate::log::warn!(
                    "Context::resolve: local registry invoke failed: {e}; treating as not-found",
                );
                0
            }
        };
        if local != 0 {
            return local;
        }

        // Local miss — try the hyperspace registry. On nodes without
        // one this errors with NotFound which we surface as 0.
        let mut msg = super::value::Msg::new("resolve");
        msg = msg.with("name", name);
        msg = msg.with("caller_prefix", prefix as u64);
        match self.ask(ServiceId::HYPERSPACE_REGISTRY, &msg).await {
            Ok(super::value::Value::U32(n)) => n,
            _ => 0,
        }
    }

    /// Consume a previously produced proof package without invoking its
    /// producer. The returned value is transactionally verified: actor code
    /// may use it during this slice, but no writes, messages, or reply become
    /// observable unless guest Accumulate validates the proof and atomically
    /// admits its once-only replay key.
    pub fn verify<T, M>(
        &mut self,
        package: crate::Attestation<T, M>,
    ) -> GuestVerifyAttestation<'_, A, T, M> {
        GuestVerifyAttestation {
            context: self,
            package,
        }
    }

    fn admit_attestation_verification<T, M>(
        &mut self,
        package: crate::Attestation<T, M>,
        source_name: String,
    ) -> Result<crate::Verified<T>, crate::AttestationError>
    where
        M: crate::AttestedMethod<T>,
    {
        let (requirement, candidate, verified) =
            package.into_guest_verification(source_name.clone())?;
        let local = self
            .actor_tree
            .iter()
            .find(|actor| actor.parent.is_none() && actor.name == source_name);
        if let Some(actor) = local {
            if requirement.statement.actor != actor.actor
                || requirement.statement.actor_program != actor.program
            {
                return Err(crate::AttestationError::WrongProducer);
            }
        } else {
            let binding = self
                .external_actors
                .binary_search_by(|actor| actor.name.as_str().cmp(&source_name))
                .ok()
                .map(|index| &self.external_actors[index])
                .ok_or(crate::AttestationError::WrongProducer)?;
            if requirement.statement.actor != binding.actor
                || requirement.statement.actor_program != binding.program
                || requirement.producer != binding.producer
                || requirement.statement.accumulation_receipt.service != binding.service
            {
                return Err(crate::AttestationError::WrongProducer);
            }
        }

        let key = requirement.replay_key();
        let index = match self
            .pending_attestation_verifications
            .binary_search_by_key(&key, |verification| verification.replay_key())
        {
            Ok(_) => return Err(crate::AttestationError::Replay),
            Err(index) => index,
        };
        if self
            .pending_verification_blobs
            .get(&candidate.reference.hash)
            .is_some_and(|existing| existing != &candidate)
        {
            return Err(crate::AttestationError::InvalidProof);
        }
        self.pending_attestation_verifications
            .insert(index, requirement);
        self.pending_verification_blobs
            .insert(candidate.reference.hash, candidate);
        Ok(verified)
    }

    /// Resolve an installed root actor by name and bind its generated typed
    /// reference to this context. Generated handle methods need no separate
    /// `ctx` argument.
    pub async fn actor<'a, R: super::client::ActorReference + 'a>(
        &'a mut self,
        name: impl Into<alloc::string::String>,
    ) -> Result<R::Handle<'a, Self>, super::client::ClientError> {
        let name = name.into();
        if self.actor_id.is_some() {
            let actor = self
                .resolve_owned_actor_v2(None, &name)
                .or_else(|| self.resolve_external_actor_v2(&name))
                .ok_or(super::client::ClientError::NotFound)?;
            return Ok(R::bind(actor, self));
        }
        let id = self.resolve(name).await;
        if id == 0 {
            return Err(super::client::ClientError::NotFound);
        }
        Ok(R::bind_service(ServiceId(id), self))
    }

    /// Resolve an existing actor directly owned by the current actor. Under v2
    /// this consults only the authenticated root-tree import; a same-node
    /// service route cannot masquerade as an owned child.
    pub async fn child<'a, R: super::client::ActorReference + 'a>(
        &'a mut self,
        name: impl Into<alloc::string::String>,
    ) -> Result<R::Handle<'a, Self>, super::client::ClientError> {
        let name = name.into();
        if let Some(parent) = self.actor_id {
            let actor = self
                .resolve_owned_actor_v2(Some(parent), &name)
                .ok_or(super::client::ClientError::NotOwnedChild)?;
            return Ok(R::bind(actor, self));
        }
        let id = self.resolve(name).await;
        if id == 0 {
            return Err(super::client::ClientError::NotFound);
        }
        let target = ServiceId(id);
        if target.node_prefix() != self.id.node_prefix() {
            return Err(super::client::ClientError::NotOwnedChild);
        }
        Ok(R::bind_service(target, self))
    }

    /// Create and initialize an owned child. This is the only beginner API
    /// which creates a child; `actor` and `child` are resolution-only.
    pub async fn spawn<'a, R, T>(
        &'a mut self,
        name: impl Into<alloc::string::String>,
        init: &T,
    ) -> Result<R::Handle<'a, Self>, super::client::ClientError>
    where
        R: super::client::ActorReference + 'a,
        T: super::codec::Encode,
    {
        let name = name.into();
        if let Some(parent) = self.actor_id {
            #[cfg(feature = "pvm")]
            {
                if name.is_empty()
                    || self
                        .actor_tree
                        .binary_search_by_key(&parent, |actor| actor.actor)
                        .is_err()
                    || self.actor_tree.len() + self.pending_actor_spawns.len()
                        >= crate::v2::MAX_ROOT_TREE_ACTORS
                    || self
                        .actor_tree
                        .iter()
                        .any(|actor| actor.parent == Some(parent) && actor.name == name)
                    || self
                        .pending_actor_spawns
                        .iter()
                        .any(|spawn| spawn.parent == parent && spawn.name == name)
                {
                    return Err(super::client::ClientError::SpawnUnavailable);
                }
                let actor = crate::v2::ActorId::owned_child(parent, &name);
                if self
                    .actor_tree
                    .iter()
                    .any(|candidate| candidate.actor == actor)
                {
                    return Err(super::client::ClientError::SpawnUnavailable);
                }
                self.pending_actor_spawns
                    .push(crate::v2::ActorSpawnRequestV2 {
                        actor,
                        name,
                        parent,
                        initial_state: init.encode(),
                    });
                return Ok(R::bind(actor, self));
            }
            #[cfg(not(feature = "pvm"))]
            {
                let _ = (parent, init);
                return Err(super::client::ClientError::SpawnUnavailable);
            }
        }
        let request = super::value::Msg::new("spawn_child")
            .with("owner", self.id.0)
            .with("name", name)
            .with("init", super::value::Value::Bytes(init.encode()));
        let id = match self.ask(ServiceId::REGISTRY, &request).await {
            Ok(super::value::Value::U32(id)) if id != 0 => id,
            _ => return Err(super::client::ClientError::Unreachable),
        };
        Ok(R::bind_service(ServiceId(id), self))
    }

    // --- Host I/O (worker mode) ---

    /// Issue an async host call. The handler future yields `Pending`; the host
    /// reads the effect request from the returned `TaskPoll`, fulfils it, then
    /// re-polls with the result via `vos_extension_task_poll(handle, result)`.
    ///
    /// Used internally by `ask()`, `fetch()`, etc.
    pub fn host_call(&mut self, request: Vec<u8>) -> super::run::HostIo {
        #[cfg(feature = "extension")]
        {
            // Extension build: `HostIo` is the per-task `ExecIo`. It carries the
            // request bytes and, on its first poll, moves them into its
            // `TaskState`'s `request` slot (reached via the task waker) — no ctx
            // slot, so each task can have an op in flight independently.
            super::run::HostIo::new(request)
        }
        #[cfg(not(feature = "extension"))]
        {
            self.host_io_request = Some(request);
            // SAFETY: single-threaded, context outlives the future, one
            // host call in flight at a time.
            let result_slot = &mut self.host_io_result as *mut Option<Vec<u8>>;
            super::run::HostIo::new(result_slot)
        }
    }

    /// Take the pending host I/O request bytes (for the C ABI to expose).
    pub fn take_host_io_request(&mut self) -> Option<Vec<u8>> {
        self.host_io_request.take()
    }

    /// Peek at the pending host I/O request bytes without consuming.
    /// Returns a pointer into the stored bytes — valid until the next
    /// dispatch or take_host_io_request call.
    pub fn peek_host_io_request(&self) -> Option<&[u8]> {
        self.host_io_request.as_deref()
    }

    /// Provide the host I/O result (for the C ABI to inject).
    pub fn set_host_io_result(&mut self, result: Vec<u8>) {
        self.host_io_result = Some(result);
    }

    // --- Byte-stream I/O (native extension host) ---
    //
    // Raw TCP over the host reactor. Each call yields a byte-stream
    // `EFFECT_*` to the host, which runs the matching `smol::Async` op and
    // feeds the result back through the per-task executor — so many such ops
    // can be in flight across tasks without blocking the executor thread.
    // Gated to the extension build: only the native extension host
    // (`node.rs`) fulfils these; WASM / PVM hosts don't.

    /// Bind a TCP listener at `addr` (e.g. `"127.0.0.1:8080"`). Returns an
    /// opaque listener id, or `None` if the bind failed.
    #[cfg(feature = "extension")]
    pub async fn listen(&mut self, addr: &str) -> Option<u64> {
        let resp = self
            .host_call(crate::effects::bytestream::encode_listen(addr))
            .await;
        crate::effects::bytestream::decode_resp_u64(&resp)
    }

    /// Bind a TLS listener at `addr` — the host terminates TLS with its
    /// configured server cert, so `accept`/`read`/`write` see plaintext.
    /// Returns `None` if the bind failed or the host has no TLS cert
    /// configured for this extension.
    #[cfg(feature = "extension")]
    pub async fn listen_tls(&mut self, addr: &str) -> Option<u64> {
        let resp = self
            .host_call(crate::effects::bytestream::encode_listen_tls(addr))
            .await;
        crate::effects::bytestream::decode_resp_u64(&resp)
    }

    /// Accept one inbound connection on `listener_id`, blocking until one
    /// arrives. Returns an opaque connection id, or `None` on error.
    #[cfg(feature = "extension")]
    pub async fn accept(&mut self, listener_id: u64) -> Option<u64> {
        let resp = self
            .host_call(crate::effects::bytestream::encode_accept(listener_id))
            .await;
        crate::effects::bytestream::decode_resp_u64(&resp)
    }

    /// Read up to `max` bytes from `conn_id`, blocking until some arrive.
    /// `Some(empty)` means EOF (peer closed); `None` means error.
    #[cfg(feature = "extension")]
    pub async fn read(&mut self, conn_id: u64, max: u32) -> Option<Vec<u8>> {
        let resp = self
            .host_call(crate::effects::bytestream::encode_read(conn_id, max))
            .await;
        crate::effects::bytestream::decode_resp_bytes(&resp)
    }

    /// Write `data` to `conn_id`. Returns the number of bytes written, or
    /// `None` on error.
    #[cfg(feature = "extension")]
    pub async fn write(&mut self, conn_id: u64, data: &[u8]) -> Option<usize> {
        let resp = self
            .host_call(crate::effects::bytestream::encode_write(conn_id, data))
            .await;
        crate::effects::bytestream::decode_resp_u32(&resp).map(|n| n as usize)
    }

    /// Close `conn_id`. Idempotent; a no-op on an unknown id.
    #[cfg(feature = "extension")]
    pub async fn close(&mut self, conn_id: u64) {
        let _ = self
            .host_call(crate::effects::bytestream::encode_close(conn_id))
            .await;
    }

    // --- Cooperative scheduling ---

    /// Checkpoint state and yield to other actors. Resumes next tick.
    /// Each invocation runs one iteration; state is saved automatically.
    pub fn yield_now(&mut self) -> super::run::Yield {
        #[cfg(feature = "pvm")]
        {
            let restored = if self.actor_id.is_some() {
                let mut token = [0u8; crate::v2::CHECKPOINT_TOKEN_CAPACITY];
                let [resume_kind, token_len] =
                    crate::abi::pvm::hostcalls::suspend_checkpoint(&mut token);
                let token_len = usize::try_from(token_len)
                    .expect("checkpoint token length exceeds guest usize");
                assert!(token_len <= token.len(), "checkpoint token exceeds buffer");
                let checkpoint = <crate::v2::CheckpointTokenV2 as crate::v2::V2Wire>::decode(
                    &token[..token_len],
                )
                .expect("invalid v2 checkpoint token");
                let restored = resume_kind == 1;
                if restored {
                    self.__resume_checkpoint_v2(&checkpoint);
                }
                self.checkpoint = Some(checkpoint);
                restored
            } else {
                crate::abi::pvm::hostcalls::suspend() == 1
            };
            self.self_schedule = !restored;
            super::run::Yield::after_checkpoint(restored)
        }
        #[cfg(not(feature = "pvm"))]
        {
            self.self_schedule = true;
            super::run::Yield::once()
        }
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __take_checkpoint_v2(&mut self) -> Option<crate::v2::CheckpointTokenV2> {
        self.checkpoint.take()
    }

    #[cfg(feature = "pvm")]
    fn __clear_committed_checkpoint_effects_v2(&mut self) {
        self.pending_writes.clear();
        self.pending_tells.clear();
        self.pending_provides.clear();
        self.pending_spawns.clear();
        self.pending_actor_calls.clear();
        self.pending_actor_spawns.clear();
        self.nested_writes.clear();
        self.nested_actor_calls.clear();
        self.nested_actor_spawns.clear();
        self.nested_crdt_operations.clear();
        self.nested_crdt_states.clear();
        self.reply = None;
        let _ = super::storage::end_dispatch();
    }

    #[cfg(feature = "pvm")]
    fn __resume_checkpoint_v2(&mut self, checkpoint: &crate::v2::CheckpointTokenV2) {
        match (self.actor_change, checkpoint.change) {
            (None, None) => {}
            (Some(_), Some(change)) => {
                crate::crdt::rebind_change(crate::crdt::ChangeId(change.0))
                    .expect("restored CRDT continuation has no active change scope");
                self.actor_change = Some(change);
                for actor in &mut self.actor_tree {
                    actor.next_crdt_ordinal = 0;
                }
            }
            _ => panic!("checkpoint consistency changed while the actor was suspended"),
        }
        self.__clear_committed_checkpoint_effects_v2();
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __actor_change_v2(&self) -> Option<crate::v2::ChangeId> {
        self.actor_change
    }

    /// Checkpoint state and yield. `sleep` is an alias for
    /// [`yield_now`](Self::yield_now): no host implements a multi-tick
    /// sleep, so `ticks` is ignored — the actor is simply re-scheduled
    /// next tick. Kept for source compatibility and as the natural name
    /// for a periodic-work loop.
    pub fn sleep(&mut self, _ticks: u32) -> super::run::Yield {
        self.yield_now()
    }

    // --- Storage ---

    /// Queue a key-value write to per-service storage.
    pub fn store(&mut self, key: &[u8], value: &[u8]) {
        self.pending_writes
            .push((key.to_vec(), Some(value.to_vec())));
    }

    /// Queue a key removal from per-service storage. Last-wins per key
    /// alongside [`store`](Self::store), in queue order.
    ///
    /// Panics on the reserved state key: the wire rejects a state-row
    /// delete (`Delete{STATE_KEY}` is malformed), so catching the
    /// programming error here — at the call site — beats the host
    /// discarding the whole dispatch as a malformed work-result.
    pub fn remove(&mut self, key: &[u8]) {
        assert!(
            key != crate::lifecycle::STATE_KEY_BYTES,
            "the actor state row cannot be deleted"
        );
        self.pending_writes.push((key.to_vec(), None));
    }

    /// Queue a new service spawn from a code hash. The code blob must
    /// already be available as a preimage (via [`provide`]).
    ///
    /// The spawn is buffered as an effect; the host assigns the child's
    /// `ServiceId` only when the parent's tick commits, after this
    /// dispatch has returned. So `spawn` does not — and cannot yet —
    /// hand the caller the new id. Returning it needs a deterministic
    /// id reserved at buffer time (and replicated identically across
    /// CRDT/Raft replicas), which lands with the `vos::agent::Tasks`
    /// work that reshapes child identity.
    #[doc(hidden)]
    pub fn spawn_code(&mut self, code_hash: [u8; 32]) {
        self.pending_spawns.push(code_hash);
    }

    /// Store a preimage (code blob, data, etc.) for later retrieval by hash.
    /// Used with [`spawn`] to install a new service: provide the blob first,
    /// then spawn with its hash.
    pub fn provide(&mut self, hash: [u8; 32], data: Vec<u8>) {
        self.pending_provides.push((hash, data));
    }

    /// Install a new child service from a code blob and its content hash.
    /// Convenience that calls [`provide`] + [`spawn`]. Like [`spawn`], it
    /// does not return the child's `ServiceId` — the host assigns that at
    /// commit time (see [`spawn`](Self::spawn)).
    ///
    /// The caller must provide the correct content hash. Use
    /// `blake2b_simd::blake2b(blob).as_bytes()` or the host's hashing
    /// facility to compute it.
    pub fn install(&mut self, hash: [u8; 32], code_blob: Vec<u8>) {
        self.provide(hash, code_blob);
        self.spawn_code(hash);
    }

    /// Request the actor to stop after the current message.
    pub fn stop(&mut self) {
        self.stop_requested = true;
    }

    // --- Reply (framework-internal) ---

    /// Set the reply value for the current invocation.
    /// Called by macro-generated code after the handler returns.
    /// The value is rkyv-encoded and included in the refine output.
    #[doc(hidden)]
    pub fn __set_reply(&mut self, value: super::value::Value) {
        // Don't store Unit replies — they carry no information
        if matches!(value, super::value::Value::Unit) {
            return;
        }
        self.reply = Some(super::codec::Encode::encode(&value));
    }

    /// Take the reply as raw bytes (rkyv-encoded Value).
    /// Used by `run_refine` to pack the output.
    pub fn take_reply_bytes(&mut self) -> Vec<u8> {
        self.reply.take().unwrap_or_default()
    }

    // --- Introspection ---

    /// Check if a stop has been requested.
    pub fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    /// Check if a yield_now or sleep was requested.
    pub fn self_scheduled(&self) -> bool {
        self.self_schedule
    }

    /// Flush all queued effects.
    ///
    /// - **Service builds**: service actors run exclusively in refine,
    ///   which cannot mutate state. The queued effects stay in the
    ///   pending vectors for `run_refine_service` to drain into the
    ///   refine output payload — the host absorbs that payload and
    ///   applies the effects natively.
    /// - **Non-service builds**: effects are dropped (invoked actors
    ///   don't have a host commit stage to flush to).
    pub fn flush_effects(&mut self) {
        #[cfg(not(feature = "service"))]
        {
            self.pending_writes.clear();
            self.pending_tells.clear();
            self.pending_provides.clear();
            self.pending_spawns.clear();
        }
    }

    // ── Refine output packing (framework-internal) ───────────────────

    /// Drain the pending effect queues into a v3 `RefinePayload` ready to
    /// be emitted as the refine output. Used by `run_refine_service`.
    ///
    /// `(anchor_kind, anchor)` commit to the state this refine ran
    /// against; `row_effects` are the dispatch's drained storage-type
    /// mutations ([`crate::storage`]), emitted after the handler's own
    /// `store`/`remove` calls; `state_write` is the post-dispatch
    /// serialized actor state, passed only when it changed — it becomes
    /// the FINAL `Write{STATE_KEY}` within the Write batch (last-wins
    /// per key, so it shadows any handler-issued write on the same
    /// key), ahead of the Transfer/Provide/New batches.
    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn drain_into_refine_payload(
        &mut self,
        anchor_kind: u8,
        anchor: [u8; 32],
        row_effects: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        state_write: Option<Vec<u8>>,
        reply: Vec<u8>,
    ) -> crate::refine_payload::RefinePayload {
        use crate::refine_payload::{Effect, RefinePayload};
        let mut effects: Vec<Effect> = Vec::new();
        for (key, value) in self.pending_writes.drain(..).chain(row_effects) {
            effects.push(match value {
                Some(value) => Effect::Write { key, value },
                None => Effect::Delete { key },
            });
        }
        if let Some(value) = state_write {
            effects.push(Effect::Write {
                key: crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                value,
            });
        }
        for tell in self.pending_tells.drain(..) {
            effects.push(Effect::Transfer {
                target: tell.target.0,
                memo: tell.payload,
            });
        }
        for (hash, data) in self.pending_provides.drain(..) {
            effects.push(Effect::Provide { hash, data });
        }
        for code_hash in self.pending_spawns.drain(..) {
            effects.push(Effect::New { code_hash });
        }
        RefinePayload {
            anchor_kind,
            anchor,
            reply,
            effects,
            continue_next: self.self_schedule,
            forbidden: self.forbidden,
            ..RefinePayload::new()
        }
    }

    /// Drain the state-row effects supported by the v2 nested actor slice.
    /// Messaging and service-management effects are deliberately rejected
    /// until the root-tree scheduler can translate them into typed
    /// inbox/outbox records without falling back to the v1 effect journal.
    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __drain_actor_writes_v2(
        &mut self,
        actor: crate::v2::ActorId,
        row_effects: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        state_write: Option<Vec<u8>>,
    ) -> Result<Vec<crate::v2::ActorWriteV2>, ()> {
        if !self.pending_tells.is_empty()
            || !self.pending_spawns.is_empty()
            || !self.pending_provides.is_empty()
        {
            return Err(());
        }

        let mut writes = Vec::new();
        for (key, value) in self.pending_writes.drain(..).chain(row_effects) {
            if key.is_empty() {
                return Err(());
            }
            writes.push(crate::v2::ActorWriteV2 { actor, key, value });
        }
        if let Some(value) = state_write {
            writes.push(crate::v2::ActorWriteV2 {
                actor,
                key: crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                value: Some(value),
            });
        }
        Ok(writes)
    }

    /// Drain durable cross-root calls separately from actor state writes so
    /// the generic service can derive canonical `CallId`s from its invocation.
    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __drain_actor_calls_v2(&mut self) -> Vec<crate::v2::ActorCallRequestV2> {
        let mut calls = core::mem::take(&mut self.nested_actor_calls);
        calls.append(&mut self.pending_actor_calls);
        calls.sort_by_key(|call| call.await_ordinal);
        calls
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __drain_actor_spawns_v2(&mut self) -> Vec<crate::v2::ActorSpawnRequestV2> {
        let mut spawns = core::mem::take(&mut self.nested_actor_spawns);
        spawns.append(&mut self.pending_actor_spawns);
        spawns.sort_by_key(|spawn| spawn.actor);
        spawns
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __drain_nested_writes_v2(&mut self) -> Vec<crate::v2::ActorWriteV2> {
        core::mem::take(&mut self.nested_writes)
            .into_iter()
            .map(|((actor, key), value)| crate::v2::ActorWriteV2 { actor, key, value })
            .collect()
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __drain_nested_crdt_v2(
        &mut self,
    ) -> (
        Vec<crate::v2::CrdtOperationV2>,
        Vec<crate::v2::ActorCrdtStateV2>,
    ) {
        (
            core::mem::take(&mut self.nested_crdt_operations),
            core::mem::take(&mut self.nested_crdt_states)
                .into_values()
                .collect(),
        )
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __drain_attestation_verifications_v2(
        &mut self,
    ) -> (
        Vec<crate::v2::AttestationVerificationV2>,
        Vec<crate::v2::ImportedBlobV2>,
    ) {
        (
            core::mem::take(&mut self.pending_attestation_verifications),
            core::mem::take(&mut self.pending_verification_blobs)
                .into_values()
                .collect(),
        )
    }

    #[cfg(feature = "pvm")]
    #[doc(hidden)]
    pub fn __await_ordinal_range_v2(&self) -> (u64, u64) {
        (self.first_await_ordinal, self.next_await_ordinal)
    }
}

/// First guest-verifier builder state. A source name is mandatory so the
/// package cannot nominate its own trusted identity.
pub struct GuestVerifyAttestation<'ctx, A: Actor, T, M> {
    context: &'ctx mut Context<A>,
    package: crate::Attestation<T, M>,
}

impl<'ctx, A: Actor, T, M> GuestVerifyAttestation<'ctx, A, T, M> {
    pub fn from(self, source_name: impl Into<String>) -> GuestVerifyAttestationFrom<'ctx, A, T, M> {
        GuestVerifyAttestationFrom {
            context: self.context,
            package: self.package,
            source_name: source_name.into(),
        }
    }
}

/// Guest-verifier builder with an authenticated installation label selected.
pub struct GuestVerifyAttestationFrom<'ctx, A: Actor, T, M> {
    context: &'ctx mut Context<A>,
    package: crate::Attestation<T, M>,
    source_name: String,
}

impl<A: Actor, T, M> GuestVerifyAttestationFrom<'_, A, T, M>
where
    M: crate::AttestedMethod<T>,
{
    pub async fn once(self) -> Result<crate::Verified<T>, crate::AttestationError> {
        self.context
            .admit_attestation_verification(self.package, self.source_name)
    }
}

// ── FetchBuilder ─────────────────────────────────────────────────────

/// Builder returned by [`Context::fetch`].
///
/// Chain method/header/body modifiers, then `.await` to send.
/// Implements [`IntoFuture`] so the builder itself is awaitable.
pub struct FetchBuilder<'ctx, A: Actor> {
    ctx: &'ctx mut Context<A>,
    request: crate::effects::FetchRequest,
}

impl<'ctx, A: Actor> FetchBuilder<'ctx, A> {
    /// Set the HTTP method explicitly.
    pub fn method(mut self, method: crate::effects::HttpMethod) -> Self {
        self.request.method = method;
        self
    }

    pub fn get(self) -> Self {
        self.method(crate::effects::HttpMethod::Get)
    }
    pub fn post(self) -> Self {
        self.method(crate::effects::HttpMethod::Post)
    }
    pub fn put(self) -> Self {
        self.method(crate::effects::HttpMethod::Put)
    }
    pub fn delete(self) -> Self {
        self.method(crate::effects::HttpMethod::Delete)
    }
    pub fn patch(self) -> Self {
        self.method(crate::effects::HttpMethod::Patch)
    }
    pub fn head(self) -> Self {
        self.method(crate::effects::HttpMethod::Head)
    }

    /// Add a header. Repeat to add multiple values.
    pub fn header(
        mut self,
        name: impl Into<alloc::string::String>,
        value: impl Into<alloc::string::String>,
    ) -> Self {
        self.request.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body (raw bytes).
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.request.body = body.into();
        self
    }

    /// Set a JSON body. Adds `Content-Type: application/json` header.
    pub fn json(mut self, body: impl AsRef<str>) -> Self {
        self.request.body = body.as_ref().as_bytes().to_vec();
        self.header("Content-Type", "application/json")
    }

    /// Set a plain text body. Adds `Content-Type: text/plain; charset=utf-8`.
    pub fn text(mut self, body: impl AsRef<str>) -> Self {
        self.request.body = body.as_ref().as_bytes().to_vec();
        self.header("Content-Type", "text/plain; charset=utf-8")
    }
}

// ── Worker-only context extensions ───────────────────────────────────

/// Marker trait declaring an actor is a **native worker** — i.e.,
/// runs as a host plugin (`.so`/dylib) rather than as a deterministic
/// PVM service. Implementations get access to non-deterministic I/O
/// methods via [`ExtensionCtx`]: HTTP `fetch`, raw `host_call`, etc.
///
/// PVM actors deliberately do not implement this. A PVM actor that
/// needs HTTP routes through a worker via `ctx.ask`/`ctx.tell`; the
/// type system enforces this separation by hiding the I/O methods.
///
/// The `#[actor]`/`#[messages]` macro emits the `impl` automatically
/// when the actor crate is built with the `worker` feature on.
pub trait Extension: Actor {}

/// HTTP / host-call API exposed only on actors that implement
/// [`Extension`].
///
/// Bring this trait into scope inside a worker crate to get access
/// to `ctx.fetch(...)` and friends:
///
/// ```ignore
/// use vos::ExtensionCtx;
///
/// #[messages]
/// impl MyWorker {
///     #[msg]
///     async fn lookup(&mut self, ctx: &mut Context<Self>) -> u64 {
///         ctx.fetch("https://api.example.com/rate").await.status as u64
///     }
/// }
/// ```
///
/// In a PVM actor crate the trait is unavailable, so `ctx.fetch`
/// produces a clear "method not found" error at compile time.
pub trait ExtensionCtx<A: Actor> {
    /// Build an HTTP request via the host. Returns a builder that
    /// implements `IntoFuture`, so awaiting it sends the request
    /// and returns the response.
    fn fetch(&mut self, url: impl Into<alloc::string::String>) -> FetchBuilder<'_, A>;

    /// Fetch a content-addressed proof blob from the host's
    /// proof-blob store. The host looks the hash up locally; cross-
    /// node fan-out via libp2p (cycle A2) layers on top without
    /// changing the call site. Returns `None` when no node known to
    /// this host has the blob.
    ///
    /// `hint_prefix = 0` means "no hint" — the host falls straight
    /// through to its fan-out across every known peer. A non-zero
    /// hint asks the host to try that specific peer's `node_prefix`
    /// first; if the hint peer doesn't have the blob (or isn't
    /// connected), the fan-out path still runs as a fallback.
    fn blob_get(
        &mut self,
        hash: [u8; 32],
        hint_prefix: u16,
    ) -> core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = Option<Vec<u8>>> + '_>>;

    /// Store `bytes` into the host's content-addressed proof-blob
    /// store — the same store [`Self::blob_get`] reads — and return
    /// the 32-byte content hash (the node's `put_proof_blob`
    /// addressing). Lets a producer extension publish large payloads
    /// (per-segment STARK proofs, say) as they are produced instead of
    /// buffering them for a host-side requester to publish. The put is
    /// node-local; peers obtain the blob on demand through the
    /// existing cross-node fetch fan-out. Returns `None` when the host
    /// doesn't serve the effect or the store rejected the bytes.
    fn blob_put(
        &mut self,
        bytes: Vec<u8>,
    ) -> core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = Option<[u8; 32]>> + '_>>;
}

impl<A: Extension> ExtensionCtx<A> for Context<A> {
    /// ```ignore
    /// // GET (default method):
    /// let resp = ctx.fetch("https://api.example.com").await;
    ///
    /// // POST with a JSON body and custom header:
    /// let resp = ctx.fetch("https://api.example.com/items")
    ///     .post()
    ///     .header("Authorization", "Bearer xyz")
    ///     .json(r#"{"name":"foo"}"#)
    ///     .await;
    /// ```
    fn fetch(&mut self, url: impl Into<alloc::string::String>) -> FetchBuilder<'_, A> {
        FetchBuilder {
            ctx: self,
            request: crate::effects::FetchRequest::get(url),
        }
    }

    fn blob_get(
        &mut self,
        hash: [u8; 32],
        hint_prefix: u16,
    ) -> core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = Option<Vec<u8>>> + '_>>
    {
        // Wire format: `[EFFECT_BLOB_GET][hash: 32 bytes][hint:u16 LE]`.
        // Host returns the blob bytes; empty bytes signal a miss so
        // the caller can decide whether to fail open (verify-fail)
        // or retry via a different path.
        let mut request = Vec::with_capacity(1 + 32 + 2);
        request.push(crate::effects::EFFECT_BLOB_GET);
        request.extend_from_slice(&hash);
        request.extend_from_slice(&hint_prefix.to_le_bytes());
        let io = self.host_call(request);
        alloc::boxed::Box::pin(async move {
            let bytes = io.await;
            if bytes.is_empty() { None } else { Some(bytes) }
        })
    }

    fn blob_put(
        &mut self,
        bytes: Vec<u8>,
    ) -> core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = Option<[u8; 32]>> + '_>>
    {
        // Wire format: `[EFFECT_BLOB_PUT][bytes…]`. The host stores the
        // bytes into the proof-blob CAS and replies with the 32-byte
        // content hash; anything else (an older host, a store failure)
        // decodes to `None`.
        let mut request = Vec::with_capacity(1 + bytes.len());
        request.push(crate::effects::EFFECT_BLOB_PUT);
        request.extend_from_slice(&bytes);
        let io = self.host_call(request);
        alloc::boxed::Box::pin(async move {
            let resp = io.await;
            let hash: [u8; 32] = resp.as_slice().try_into().ok()?;
            Some(hash)
        })
    }
}

impl<'ctx, A: Actor> core::future::IntoFuture for FetchBuilder<'ctx, A> {
    type Output = crate::effects::FetchResponse;
    type IntoFuture =
        core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = Self::Output> + 'ctx>>;

    fn into_future(self) -> Self::IntoFuture {
        alloc::boxed::Box::pin(async move {
            let bytes = self.request.to_effect_bytes();
            let result = self.ctx.host_call(bytes).await;
            crate::effects::FetchResponse::decode(&result).unwrap_or_else(|| {
                crate::effects::FetchResponse::host_error("malformed host response")
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::auth::{NO_ROLES_MAP, NoRoles};

    // Minimal fixture Actor — just enough to satisfy the trait
    // bounds for Context<A> construction. Roles default to
    // NoRoles via the M1 sentinels.
    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestActor;

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct TestMsg;

    #[derive(Clone, Copy)]
    struct TestRef;

    impl crate::actors::client::ActorReference for TestRef {
        type Handle<'a, I: crate::actors::client::Invoker + 'a> = ();

        fn bind<'a, I: crate::actors::client::Invoker + 'a>(
            _target: crate::v2::ActorId,
            _invoker: &'a mut I,
        ) -> Self::Handle<'a, I> {
        }

        fn bind_service<'a, I: crate::actors::client::Invoker + 'a>(
            _target: ServiceId,
            _invoker: &'a mut I,
        ) -> Self::Handle<'a, I> {
        }
    }

    impl crate::actors::value::FromDynamic for TestMsg {
        fn from_dynamic(_d: &crate::actors::value::Msg) -> Option<Self> {
            None
        }
    }

    impl Actor for TestActor {
        type Error = ();
        type Message = TestMsg;
        type Role = NoRoles;
        const DEFAULT_ROLE: NoRoles = NoRoles::Any;
        const SPACE_ROLE_MAP: crate::actors::auth::SpaceRoleMap<NoRoles> = NO_ROLES_MAP;

        fn create() -> Self {
            TestActor
        }

        fn dispatch(
            &mut self,
            _msg: TestMsg,
            _ctx: &mut Context<Self>,
        ) -> crate::actors::run::RunResult<bool> {
            crate::actors::run::RunResult::Complete(true)
        }
    }

    enum TestClaimMethod {}

    impl crate::AttestedMethod<u64> for TestClaimMethod {
        const METHOD: &'static str = "is_adult";

        fn claim_wire(claim: &u64) -> Vec<u8> {
            crate::Encode::encode(&crate::value::Value::U64(*claim))
        }

        fn decode_claim_wire(wire: &[u8]) -> Option<u64> {
            <crate::value::Value as crate::Decode>::try_decode(wire)?.as_u64()
        }
    }

    #[test]
    fn context_new_defaults_caller_to_unauthenticated() {
        // Fresh Context starts with no caller — the host writes
        // the real one via `set_caller` before each dispatch.
        // Defaulting to Unauthenticated (rather than panicking on
        // missing caller) keeps construction sites that don't yet
        // populate the slot safe.
        let ctx: Context<TestActor> = Context::new(ServiceId(7));
        assert_eq!(ctx.caller(), &Caller::Unauthenticated);
    }

    #[test]
    fn context_set_caller_round_trips_every_variant() {
        // The setter is the single host-side hook; every variant
        // must round-trip exactly. If set_caller silently
        // normalised any variant, role checks would break in
        // surprising ways downstream.
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));

        ctx.set_caller(Caller::Unauthenticated);
        assert_eq!(ctx.caller(), &Caller::Unauthenticated);

        ctx.set_caller(Caller::Peer(alloc::vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(
            ctx.caller(),
            &Caller::Peer(alloc::vec![0xde, 0xad, 0xbe, 0xef])
        );

        ctx.set_caller(Caller::Actor(ServiceId(42)));
        assert_eq!(ctx.caller(), &Caller::Actor(ServiceId(42)));
    }

    #[test]
    fn v2_actor_identity_is_not_truncated_into_a_route_id() {
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));
        let actor = crate::v2::ActorId([0xab; 32]);
        assert_eq!(ctx.actor_id(), None);
        ctx.__set_actor_id(actor);
        assert_eq!(ctx.actor_id(), Some(actor));
        assert_eq!(ctx.id(), ServiceId(0));
    }

    #[test]
    fn v2_child_resolution_requires_the_exact_parent_identity() {
        let root = crate::v2::ActorId([1; 32]);
        let child = crate::v2::ActorId([2; 32]);
        let sibling_child = crate::v2::ActorId([3; 32]);
        let other_root = crate::v2::ActorId([4; 32]);
        let program = crate::v2::ProgramId([9; 32]);
        let actor = |actor, name: &str, parent| crate::v2::ActorTreeImportV2 {
            actor,
            name: name.into(),
            parent,
            program,
            state: alloc::vec![],
            causal_states: alloc::vec![],
            next_crdt_ordinal: 0,
            suspended: false,
        };
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));
        ctx.__set_actor_id(root);
        ctx.actor_tree = alloc::vec![
            actor(root, "root", None),
            actor(child, "worker", Some(root)),
            actor(sibling_child, "worker", Some(other_root)),
            actor(other_root, "other", None),
        ];

        assert_eq!(
            ctx.resolve_owned_actor_v2(Some(root), "worker"),
            Some(child)
        );
        assert_eq!(
            ctx.resolve_owned_actor_v2(Some(other_root), "worker"),
            Some(sibling_child)
        );
        assert_eq!(ctx.resolve_owned_actor_v2(Some(root), "other"), None);
    }

    #[test]
    fn v2_spawn_never_falls_back_to_the_legacy_registry_route() {
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));
        ctx.__set_actor_id(crate::v2::ActorId([1; 32]));

        assert!(matches!(
            crate::block_on(ctx.spawn::<TestRef, _>("child", &TestMsg)),
            Err(crate::ClientError::SpawnUnavailable)
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn v2_spawn_buffers_a_deterministic_owned_child_request() {
        let root = crate::v2::ActorId([1; 32]);
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));
        ctx.__set_actor_id(root);
        ctx.actor_tree = alloc::vec![crate::v2::ActorTreeImportV2 {
            actor: root,
            name: "root".into(),
            parent: None,
            program: crate::v2::ProgramId([9; 32]),
            state: alloc::vec![],
            causal_states: alloc::vec![],
            next_crdt_ordinal: 0,
            suspended: false,
        }];

        assert!(crate::block_on(ctx.spawn::<TestRef, _>("child", &TestMsg)).is_ok());
        let spawns = ctx.__drain_actor_spawns_v2();
        assert_eq!(spawns.len(), 1);
        assert_eq!(
            spawns[0].actor,
            crate::v2::ActorId::owned_child(root, "child")
        );
        assert_eq!(spawns[0].parent, root);
        assert_eq!(spawns[0].name, "child");
        assert_eq!(spawns[0].initial_state, TestMsg.encode());
    }

    #[test]
    fn v2_external_resolution_uses_only_install_time_bindings() {
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));
        let actor = crate::v2::ActorId([41; 32]);
        ctx.__set_actor_id(crate::v2::ActorId([1; 32]));
        ctx.external_actors = alloc::vec![crate::v2::ExternalActorBindingV2 {
            name: "private-age".into(),
            service: crate::v2::ServiceIdentityV2 {
                space: crate::v2::SpaceId([2; 32]),
                root_service: crate::v2::RootServiceId([3; 32]),
                deployment: crate::v2::DeploymentId([4; 32]),
                service_program: crate::v2::ProgramId([5; 32]),
                service_abi: crate::v2::ABI_VERSION,
                execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
            },
            actor,
            producer: crate::v2::ProducerId([6; 32]),
            program: crate::v2::ProgramId([7; 32]),
        }];

        assert_eq!(ctx.resolve_external_actor_v2("private-age"), Some(actor));
        assert_eq!(ctx.resolve_external_actor_v2("package-label"), None);
    }

    #[test]
    fn guest_verify_emits_an_accumulate_owned_proof_requirement() {
        let mut ctx: Context<TestActor> = Context::new(ServiceId(0));
        ctx.__set_actor_id(crate::v2::ActorId([1; 32]));
        let binding = crate::v2::ExternalActorBindingV2 {
            name: "private-age".into(),
            service: crate::v2::ServiceIdentityV2 {
                space: crate::v2::SpaceId([2; 32]),
                root_service: crate::v2::RootServiceId([3; 32]),
                deployment: crate::v2::DeploymentId([4; 32]),
                service_program: crate::v2::ProgramId([5; 32]),
                service_abi: crate::v2::ABI_VERSION,
                execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
            },
            actor: crate::v2::ActorId([41; 32]),
            producer: crate::v2::ProducerId([6; 32]),
            program: crate::v2::ProgramId([7; 32]),
        };
        ctx.external_actors = alloc::vec![binding.clone()];
        let package = || {
            let after = crate::v2::Hash([8; 32]);
            let statement = crate::AttestationStatementV3 {
                statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
                space: binding.service.space,
                actor: binding.actor,
                deployment: binding.service.deployment,
                actor_program: binding.program,
                method: "is_adult".into(),
                schema: crate::v2::Hash([9; 32]),
                invocation: crate::v2::InvocationId([10; 32]),
                before: crate::StateCommitmentV3::Linear(crate::v2::Hash([11; 32])),
                after: crate::StateCommitmentV3::Linear(after),
                claim_commitment: crate::v2::Hash::digest(
                    b"vos/attestation-claim/v3",
                    &[&<TestClaimMethod as crate::AttestedMethod<u64>>::claim_wire(&21)],
                ),
                input_commitment: crate::v2::Hash([12; 32]),
                authorization_policy: crate::v2::Hash([13; 32]),
                accumulation_receipt: crate::v2::AccumulationReceiptV2 {
                    service: binding.service.clone(),
                    accepted_transition: crate::v2::Hash([14; 32]),
                    reply_commitment: None,
                    outbox_commitment: None,
                    resulting_state_root: Some(after),
                    resulting_crdt_heads: alloc::vec![],
                    sequence: 1,
                    checkpoint: 0,
                    consistency: crate::v2::ConsistencyModeV2::Local,
                },
            };
            crate::Attestation::<u64, TestClaimMethod>::__from_runtime(
                binding.name.clone(),
                binding.producer,
                statement,
                crate::v2::Hash([15; 32]),
                21,
                alloc::vec![16],
            )
            .unwrap()
        };

        let verified = crate::block_on(ctx.verify(package()).from("private-age").once()).unwrap();
        assert_eq!(verified.into_inner(), 21);
        assert_eq!(ctx.pending_attestation_verifications.len(), 1);
        assert_eq!(ctx.pending_verification_blobs.len(), 1);
        assert_eq!(
            crate::block_on(ctx.verify(package()).from("private-age").once()),
            Err(crate::AttestationError::Replay)
        );
    }

    // Richer fixture actor with a 3-tier Role enum — exercises
    // the precedence matrix in `caller_role` / `has_role` /
    // `ensure_role` that the M6 macro will emit checks against.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(u8)]
    enum FixtureRole {
        Viewer = 0,
        Contributor = 1,
        Maintainer = 2,
    }

    impl RoleByte for FixtureRole {
        fn from_byte(b: u8) -> Option<Self> {
            match b {
                0 => Some(Self::Viewer),
                1 => Some(Self::Contributor),
                2 => Some(Self::Maintainer),
                _ => None,
            }
        }
        fn as_byte(self) -> u8 {
            self as u8
        }
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct FixtureActor;

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct FixtureMsg;

    impl crate::actors::value::FromDynamic for FixtureMsg {
        fn from_dynamic(_d: &crate::actors::value::Msg) -> Option<Self> {
            None
        }
    }

    impl Actor for FixtureActor {
        type Error = ();
        type Message = FixtureMsg;
        type Role = FixtureRole;
        const DEFAULT_ROLE: FixtureRole = FixtureRole::Viewer;
        const SPACE_ROLE_MAP: crate::actors::auth::SpaceRoleMap<FixtureRole> =
            crate::actors::auth::SpaceRoleMap {
                admin: Some(FixtureRole::Maintainer),
                developer: Some(FixtureRole::Contributor),
                member: Some(FixtureRole::Viewer),
                guest: None,
            };

        fn create() -> Self {
            FixtureActor
        }

        fn dispatch(
            &mut self,
            _msg: FixtureMsg,
            _ctx: &mut Context<Self>,
        ) -> crate::actors::run::RunResult<bool> {
            crate::actors::run::RunResult::Complete(true)
        }
    }

    fn fixture_ctx_with(
        caller: Caller,
        space_role: Option<u8>,
        actor_local_role: Option<u8>,
    ) -> Context<FixtureActor> {
        let mut ctx: Context<FixtureActor> = Context::new(ServiceId(1));
        ctx.set_caller(caller);
        ctx.set_caller_roles(space_role, actor_local_role);
        ctx
    }

    #[test]
    fn caller_role_actor_local_overrides_space() {
        // Actor-local grant must win even when the space role
        // would map to something different — the whole point of
        // letting operators override per-actor.
        let ctx = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Admin.as_u8()),
            Some(FixtureRole::Viewer.as_byte()),
        );
        assert_eq!(ctx.caller_role(), Some(FixtureRole::Viewer));
    }

    #[test]
    fn caller_role_falls_back_to_space_via_map() {
        // No actor-local grant: walk the SPACE_ROLE_MAP.
        // Developer → Contributor in the fixture's map.
        let ctx = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Developer.as_u8()),
            None,
        );
        assert_eq!(ctx.caller_role(), Some(FixtureRole::Contributor));
    }

    #[test]
    fn caller_role_guest_yields_none() {
        // Guest maps to None in this fixture — caller_role
        // returns None and any ensure_role(Viewer) call will
        // fail. Locks in deny-by-default semantics for the
        // lowest tier.
        let ctx = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Guest.as_u8()),
            None,
        );
        assert_eq!(ctx.caller_role(), None);
        assert!(!ctx.has_role(FixtureRole::Viewer));
        assert_eq!(ctx.ensure_role(FixtureRole::Viewer), Err(Forbidden));
    }

    #[test]
    fn direct_space_role_policy_uses_only_the_authenticated_space_grant() {
        let member = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Member.as_u8()),
            None,
        );
        assert!(member.has_space_role(SpaceRole::Member));
        assert!(!member.has_space_role(SpaceRole::Developer));
        assert_eq!(member.ensure_space_role(SpaceRole::Member), Ok(()));

        let guest_with_local_admin = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Guest.as_u8()),
            Some(FixtureRole::Maintainer.as_byte()),
        );
        assert!(guest_with_local_admin.has_role(FixtureRole::Maintainer));
        assert!(!guest_with_local_admin.has_space_role(SpaceRole::Member));
        assert_eq!(
            guest_with_local_admin.ensure_space_role(SpaceRole::Member),
            Err(Forbidden)
        );
    }

    #[test]
    fn actor_and_system_origins_do_not_bypass_direct_space_roles() {
        for caller in [Caller::Actor(ServiceId(99)), Caller::System] {
            let ctx = fixture_ctx_with(caller, None, None);
            assert!(!ctx.has_space_role(SpaceRole::Guest));
            assert_eq!(ctx.ensure_space_role(SpaceRole::Guest), Err(Forbidden));
        }
    }

    #[test]
    fn caller_role_no_grant_at_all_is_none() {
        // No space-level, no actor-local: deny everything.
        let ctx = fixture_ctx_with(Caller::Unauthenticated, None, None);
        assert_eq!(ctx.caller_role(), None);
        assert!(!ctx.has_role(FixtureRole::Viewer));
    }

    #[test]
    fn has_role_respects_ord() {
        // Space-Admin maps to Maintainer — admits every tier
        // including Viewer. Space-Developer maps to Contributor
        // — admits Viewer + Contributor, not Maintainer.
        let ctx_admin = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Admin.as_u8()),
            None,
        );
        assert!(ctx_admin.has_role(FixtureRole::Viewer));
        assert!(ctx_admin.has_role(FixtureRole::Contributor));
        assert!(ctx_admin.has_role(FixtureRole::Maintainer));

        let ctx_dev = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Developer.as_u8()),
            None,
        );
        assert!(ctx_dev.has_role(FixtureRole::Viewer));
        assert!(ctx_dev.has_role(FixtureRole::Contributor));
        assert!(!ctx_dev.has_role(FixtureRole::Maintainer));
    }

    #[test]
    fn intra_system_actor_caller_requires_an_explicit_role() {
        let ctx: Context<FixtureActor> = fixture_ctx_with(Caller::Actor(ServiceId(99)), None, None);
        assert!(!ctx.has_role(FixtureRole::Maintainer));
        assert_eq!(ctx.ensure_role(FixtureRole::Maintainer), Err(Forbidden));
    }

    #[test]
    fn system_caller_requires_an_explicit_role() {
        let ctx: Context<FixtureActor> = fixture_ctx_with(Caller::System, None, None);
        assert!(!ctx.has_role(FixtureRole::Maintainer));
        assert_eq!(ctx.ensure_role(FixtureRole::Maintainer), Err(Forbidden));
    }

    #[test]
    fn ensure_role_returns_forbidden_marker() {
        // Display text on the returned Err is what bubbles to
        // user errors via `From<Forbidden>` impls. Confirm the
        // marker is structurally distinct from Ok.
        let ctx: Context<FixtureActor> = fixture_ctx_with(Caller::Unauthenticated, None, None);
        assert_eq!(ctx.ensure_role(FixtureRole::Viewer), Err(Forbidden));
    }

    #[test]
    fn has_role_byte_round_trips_known_discriminants() {
        // The macro-emitted dispatch check (M6) only has the raw
        // byte from `required_role()`. has_role_byte must handle
        // the round-trip — valid discriminants succeed when the
        // caller has the role; unknown discriminants always fail
        // (forward-incompatible).
        let ctx = fixture_ctx_with(
            Caller::Peer(alloc::vec![1]),
            Some(SpaceRole::Developer.as_u8()),
            None,
        );
        // Caller maps to Contributor. Viewer/Contributor OK,
        // Maintainer denied.
        assert!(ctx.has_role_byte(FixtureRole::Viewer.as_byte()));
        assert!(ctx.has_role_byte(FixtureRole::Contributor.as_byte()));
        assert!(!ctx.has_role_byte(FixtureRole::Maintainer.as_byte()));
        // Unknown discriminant → deny.
        assert!(!ctx.has_role_byte(99));
    }
}
