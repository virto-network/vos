//! Trusted crash-safe coordination of non-management authority operations.
//!
//! The system-authority actor owns policy and its global authorization clock;
//! [`super::authority_operation_issuer`] owns the two authority signatures.
//! This module joins those durable boundaries without treating unsigned AOP1
//! bytes as public authority. It pledges the exact AOC1, authorization
//! [`InvocationContext`], and issuance slot before the first actor dispatch.
//! After that point, retained issuer preimages always take precedence over
//! asking the actor to authorize again.
//!
//! Neither coordinator nor issuer records are compacted. The actor adapter's
//! successful AOI1 reply is durably applied, but this slice has no separately
//! authenticated proof that can be reopened independently of that adapter.
//! Until such a proof exists, retention reaches a bounded fail-closed ceiling.

use core::{convert::Infallible, fmt};

use super::authority_operation_issuer::{
    AuthorityOperationEvidenceSigner, AuthorityOperationIssuerError, AuthorityOperationIssuerStore,
    DurableAuthorityOperationIssuer, IssuedAuthorityOperation,
    MAX_AUTHORITY_OPERATION_ISSUER_RECORDS,
};
use crate::agent::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialVerifier, AuthorityIssuer,
};
use crate::agent::sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIssuanceAck,
    MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES, MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES,
};
use crate::agent::sdk::wire::{CanonicalWire, MAX_INVOCATION_CONTEXT_WIRE_BYTES};
use crate::agent::sdk::{
    ActorId, AgentId, DeploymentId, Hash, InvocationContext, InvocationId, InvocationOrigin,
    InvocationRoleClaims, MethodMode, PrincipalId, ProducerId, ProgramId, SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

pub const MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS: usize =
    MAX_AUTHORITY_OPERATION_ISSUER_RECORDS;
pub const MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES: usize = 2 * 1024 * 1024;
const AUTHORITY_OPERATION_COORDINATOR_MAGIC: [u8; 4] = *b"AOC2";

/// Exact system-authority method selected at the trusted dispatch boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityOperationActorMethod {
    AuthorizeOperation = 0,
    AcknowledgeIssuance = 1,
}

impl AuthorityOperationActorMethod {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthorizeOperation => "authorize_operation",
            Self::AcknowledgeIssuance => "acknowledge_issuance",
        }
    }
}

/// Complete request presented to the authenticated Linear actor dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationActorDispatch {
    pub target: AuthorityActorTarget,
    pub method: AuthorityOperationActorMethod,
    pub context: InvocationContext,
    pub request: Vec<u8>,
}

/// Echoed dispatch identity and its exact, durably applied result bytes.
///
/// The coordinator checks every echoed field. `authenticated` and `durable`
/// are assertions made by the trusted adapter; an implementation must set
/// them only after authenticating the exact installed actor and observing its
/// Linear transition in durable journal/Raft state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperationActorResult {
    pub target: AuthorityActorTarget,
    pub method: AuthorityOperationActorMethod,
    pub context: InvocationContext,
    pub request: Vec<u8>,
    pub authenticated: bool,
    pub durable: bool,
    /// Canonical encoded [`crate::value::Value`] returned by the actor.
    /// The coordinator independently decodes, type-checks, and re-encodes it.
    pub reply: Vec<u8>,
}

/// Trusted adapter from an exact actor route to authenticated durable Linear
/// execution.
///
/// Implementations must not return an affirmative result for a native policy
/// shortcut, an uncommitted preview, or a different actor/method/context. The
/// redundant result metadata lets this coordinator reject accidental routing
/// substitutions, but cannot make a dishonest adapter trustworthy.
pub trait AuthorityOperationActorDispatcher {
    type Error;

    fn dispatch(
        &mut self,
        request: &AuthorityOperationActorDispatch,
    ) -> Result<AuthorityOperationActorResult, Self::Error>;
}

/// Durable whole-image storage for coordinator intent and completion facts.
pub trait AuthorityOperationCoordinatorStore {
    type Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityOperationCoordinatorRejection {
    Poisoned,
    InvalidCall,
    WrongRoute,
    WrongAuthorizationContext,
    IssuanceBeforeAuthorization,
    InvalidIssuanceSlot,
    AuthorizationSlotRegressed,
    IssuanceSlotRegressed,
    DivergentRetry,
    InvocationCollision,
    PendingOperation,
    JournalFull,
    WrongSigner,
    InvalidDispatchResult,
    AuthorizationDenied,
    InvalidApproval,
    AcknowledgementRejected,
}

#[derive(Debug)]
pub enum AuthorityOperationCoordinatorError<
    CoordinatorStorageError,
    IssuerStorageError,
    DispatchError = Infallible,
    SignerError = Infallible,
> {
    Storage(CoordinatorStorageError),
    Issuer(AuthorityOperationIssuerError<IssuerStorageError, SignerError>),
    Dispatch(DispatchError),
    InvalidState,
    Rejected(AuthorityOperationCoordinatorRejection),
}

impl<CoordinatorStorageError, IssuerStorageError, DispatchError, SignerError> fmt::Display
    for AuthorityOperationCoordinatorError<
        CoordinatorStorageError,
        IssuerStorageError,
        DispatchError,
        SignerError,
    >
where
    CoordinatorStorageError: fmt::Display,
    IssuerStorageError: fmt::Display,
    DispatchError: fmt::Display,
    SignerError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "authority coordinator storage: {error}"),
            Self::Issuer(error) => error.fmt(formatter),
            Self::Dispatch(error) => write!(formatter, "authority actor dispatch: {error}"),
            Self::InvalidState => formatter.write_str("invalid authority coordinator state"),
            Self::Rejected(error) => write!(formatter, "authority coordinator rejected: {error:?}"),
        }
    }
}

impl<CoordinatorStorageError, IssuerStorageError, DispatchError, SignerError> core::error::Error
    for AuthorityOperationCoordinatorError<
        CoordinatorStorageError,
        IssuerStorageError,
        DispatchError,
        SignerError,
    >
where
    CoordinatorStorageError: core::error::Error + 'static,
    IssuerStorageError: core::error::Error + 'static,
    DispatchError: core::error::Error + 'static,
    SignerError: core::error::Error + 'static,
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CoordinatorRecord {
    call: Vec<u8>,
    authorization_context: Vec<u8>,
    issued_at: u64,
    consumed_issuance_ack: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthorityOperationCoordinatorImage {
    authority: AuthorityActorTarget,
    authorization_slot_high_water: Option<u64>,
    issuance_slot_high_water: Option<u64>,
    records: Vec<CoordinatorRecord>,
}

impl AuthorityOperationCoordinatorImage {
    fn empty(authority: AuthorityActorTarget) -> Self {
        Self {
            authority,
            authorization_slot_high_water: None,
            issuance_slot_high_water: None,
            records: Vec::new(),
        }
    }

    fn has_valid_envelope(&self) -> bool {
        if !self.authority.is_valid()
            || self.records.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS
            || (self.records.is_empty() != self.authorization_slot_high_water.is_none())
            || (self.records.is_empty() != self.issuance_slot_high_water.is_none())
            || self.records.last().map(|record| record.issued_at) != self.issuance_slot_high_water
            || self.records.iter().any(|record| {
                record.call.len() > MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES
                    || record.authorization_context.len() > MAX_INVOCATION_CONTEXT_WIRE_BYTES
            })
        {
            return false;
        }
        self.records.iter().enumerate().all(|(index, record)| {
            record.consumed_issuance_ack.is_some() || index + 1 == self.records.len()
        })
    }

    fn is_valid(&self) -> bool {
        if !self.has_valid_envelope() {
            return false;
        }
        let verifier = RawEd25519Verifier;
        let mut invocation_ids = Vec::new();
        let mut previous_authorization_slot = None;
        let mut previous_issuance_slot = None;
        for record in &self.records {
            let Ok(call) = AuthorityOperationCall::decode(&record.call) else {
                return false;
            };
            let Ok(context) = InvocationContext::decode(&record.authorization_context) else {
                return false;
            };
            let acknowledgement =
                AuthorityOperationApproval::derive_acknowledgement_invocation(&call);
            if call.encode().ok().as_deref() != Some(record.call.as_slice())
                || context.encode().ok().as_deref() != Some(record.authorization_context.as_slice())
                || call.verify_with(&verifier).is_err()
                || call.authority != self.authority
                || !call.matches_invocation_context(&context)
                || record.issued_at < context.observed_slot
                || record.consumed_issuance_ack == Some(Hash::ZERO)
                || previous_authorization_slot
                    .is_some_and(|previous| previous > context.observed_slot)
                || previous_issuance_slot.is_some_and(|previous| previous > record.issued_at)
                || invocation_ids.contains(&call.invocation)
                || invocation_ids.contains(&acknowledgement)
            {
                return false;
            }
            previous_authorization_slot = Some(context.observed_slot);
            previous_issuance_slot = Some(record.issued_at);
            invocation_ids.push(call.invocation);
            invocation_ids.push(acknowledgement);
        }
        self.records.last().and_then(|record| {
            InvocationContext::decode(&record.authorization_context)
                .ok()
                .map(|context| context.observed_slot)
        }) == self.authorization_slot_high_water
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&AUTHORITY_OPERATION_COORDINATOR_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        encode_authority_target(&mut encoder, self.authority);
        encoder.option(&self.authorization_slot_high_water, |encoder, slot| {
            encoder.u64(*slot)
        });
        encoder.option(&self.issuance_slot_high_water, |encoder, slot| {
            encoder.u64(*slot)
        });
        encoder.list(&self.records, |encoder, record| {
            encoder.bytes(&record.call);
            encoder.bytes(&record.authorization_context);
            encoder.u64(record.issued_at);
            encoder.option(&record.consumed_issuance_ack, |encoder, acknowledgement| {
                encoder.fixed(acknowledgement.as_bytes())
            });
        });
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(AUTHORITY_OPERATION_COORDINATOR_MAGIC.len())?
            != AUTHORITY_OPERATION_COORDINATOR_MAGIC
        {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != crate::agent::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let authority = decode_authority_target(&mut decoder)?;
        let authorization_slot_high_water = decoder.option(Decoder::u64)?;
        let issuance_slot_high_water = decoder.option(Decoder::u64)?;
        let record_count = decoder.u32()? as usize;
        if record_count > MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = Vec::new();
        records
            .try_reserve(record_count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..record_count {
            records.push(CoordinatorRecord {
                call: decoder.bytes_bounded(MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES)?,
                authorization_context: decoder.bytes_bounded(MAX_INVOCATION_CONTEXT_WIRE_BYTES)?,
                issued_at: decoder.u64()?,
                consumed_issuance_ack: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
            });
        }
        let image = Self {
            authority,
            authorization_slot_high_water,
            issuance_slot_high_water,
            records,
        };
        if !decoder.exhausted() || !image.is_valid() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(image)
    }
}

/// Durable coordinator joining one trusted actor dispatcher and one issuer.
pub struct DurableAuthorityOperationCoordinator<
    D: AuthorityOperationActorDispatcher,
    C: AuthorityOperationCoordinatorStore,
    I: AuthorityOperationIssuerStore,
> {
    authority: AuthorityActorTarget,
    dispatcher: D,
    store: C,
    image: AuthorityOperationCoordinatorImage,
    issuer: DurableAuthorityOperationIssuer<I>,
    poisoned: bool,
}

impl<D, C, I> DurableAuthorityOperationCoordinator<D, C, I>
where
    D: AuthorityOperationActorDispatcher,
    C: AuthorityOperationCoordinatorStore,
    I: AuthorityOperationIssuerStore,
{
    pub fn open(
        mut store: C,
        authority: AuthorityActorTarget,
        dispatcher: D,
        issuer: DurableAuthorityOperationIssuer<I>,
    ) -> Result<Self, AuthorityOperationCoordinatorError<C::Error, I::Error>> {
        if !authority.is_valid() || issuer.authority() != authority || issuer.is_poisoned() {
            return Err(AuthorityOperationCoordinatorError::InvalidState);
        }
        let image = match store
            .load()
            .map_err(AuthorityOperationCoordinatorError::Storage)?
        {
            Some(bytes) => {
                let image = AuthorityOperationCoordinatorImage::decode(&bytes)
                    .map_err(|_| AuthorityOperationCoordinatorError::InvalidState)?;
                if image.authority != authority || image.encode() != bytes {
                    return Err(AuthorityOperationCoordinatorError::InvalidState);
                }
                image
            }
            None => AuthorityOperationCoordinatorImage::empty(authority),
        };
        if !coordinator_matches_issuer(&image, &issuer) {
            return Err(AuthorityOperationCoordinatorError::InvalidState);
        }
        Ok(Self {
            authority,
            dispatcher,
            store,
            image,
            issuer,
            poisoned: false,
        })
    }

    pub const fn authority(&self) -> AuthorityActorTarget {
        self.authority
    }

    pub fn retained_operations(&self) -> usize {
        self.image.records.len()
    }

    pub fn has_pending_operation(&self) -> bool {
        self.image
            .records
            .last()
            .is_some_and(|record| record.consumed_issuance_ack.is_none())
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned || self.issuer.is_poisoned()
    }

    pub fn into_parts(self) -> (C, D, DurableAuthorityOperationIssuer<I>) {
        (self.store, self.dispatcher, self.issuer)
    }

    /// Execute one exact credential-authenticated operation through policy,
    /// durable evidence issuance, and durable AOI1 consumption.
    ///
    /// This method is crate-private so callers cannot pair an arbitrary AOP1
    /// with the signer. Only this coordinator may pass the exact canonical
    /// result of its trusted `authorize_operation` dispatch to the issuer.
    pub(crate) fn coordinate<S: AuthorityOperationEvidenceSigner>(
        &mut self,
        call: &AuthorityOperationCall,
        authorization_context: InvocationContext,
        issued_at: u64,
        signer: &mut S,
    ) -> Result<
        IssuedAuthorityOperation,
        AuthorityOperationCoordinatorError<C::Error, I::Error, D::Error, S::Error>,
    > {
        self.ensure_live()?;
        let verifier = RawEd25519Verifier;
        if call.verify_with(&verifier).is_err() {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidCall,
            ));
        }
        if call.authority != self.authority {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::WrongRoute,
            ));
        }
        if !call.matches_invocation_context(&authorization_context) {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::WrongAuthorizationContext,
            ));
        }
        if issued_at < authorization_context.observed_slot {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::IssuanceBeforeAuthorization,
            ));
        }
        if issued_at < call.requested_valid_from || issued_at > call.requested_expires_at {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidIssuanceSlot,
            ));
        }
        let call_bytes = call
            .encode()
            .map_err(|_| AuthorityOperationCoordinatorError::InvalidState)?;
        let context_bytes = authorization_context
            .encode()
            .map_err(|_| AuthorityOperationCoordinatorError::InvalidState)?;

        let existing_index = self.image.records.iter().position(|record| {
            AuthorityOperationCall::decode(&record.call)
                .is_ok_and(|retained| retained.invocation == call.invocation)
        });
        let record_index = if let Some(index) = existing_index {
            let record = &self.image.records[index];
            if record.call != call_bytes
                || record.authorization_context != context_bytes
                || record.issued_at != issued_at
            {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::DivergentRetry,
                ));
            }
            index
        } else {
            if self.has_pending_operation() {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::PendingOperation,
                ));
            }
            if self.image.records.len() == MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::JournalFull,
                ));
            }
            if self
                .image
                .authorization_slot_high_water
                .is_some_and(|slot| authorization_context.observed_slot < slot)
            {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::AuthorizationSlotRegressed,
                ));
            }
            if self
                .image
                .issuance_slot_high_water
                .is_some_and(|slot| issued_at < slot)
            {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::IssuanceSlotRegressed,
                ));
            }
            let acknowledgement =
                AuthorityOperationApproval::derive_acknowledgement_invocation(call);
            if self.image.records.iter().any(|record| {
                retained_invocation_pair(record).is_none_or(|(authorization, retained_ack)| {
                    authorization == call.invocation
                        || retained_ack == call.invocation
                        || authorization == acknowledgement
                        || retained_ack == acknowledgement
                })
            }) {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::InvocationCollision,
                ));
            }
            if signer.public_key() != self.authority.binding.public_key {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::WrongSigner,
                ));
            }
            let mut pledged = self.image.clone();
            pledged.authorization_slot_high_water = Some(authorization_context.observed_slot);
            pledged.issuance_slot_high_water = Some(issued_at);
            pledged.records.push(CoordinatorRecord {
                call: call_bytes.clone(),
                authorization_context: context_bytes,
                issued_at,
                consumed_issuance_ack: None,
            });
            self.commit_candidate::<S::Error>(pledged)?;
            self.image.records.len() - 1
        };

        let recovered = self
            .issuer
            .recover_retained(call.invocation)
            .map_err(|_| AuthorityOperationCoordinatorError::InvalidState)?;
        let approval = match recovered {
            Some(retained) => {
                if retained.call != *call
                    || retained.issued_at != issued_at
                    || retained.approval.authority != self.authority
                    || !retained.approval.matches_call(call)
                {
                    return Err(AuthorityOperationCoordinatorError::InvalidState);
                }
                if !retained.is_complete() {
                    if signer.public_key() != self.authority.binding.public_key {
                        return Err(AuthorityOperationCoordinatorError::Rejected(
                            AuthorityOperationCoordinatorRejection::WrongSigner,
                        ));
                    }
                    let actor_approval =
                        self.authorize_exact::<S::Error>(call, authorization_context, &call_bytes)?;
                    if actor_approval != retained.approval {
                        return Err(AuthorityOperationCoordinatorError::InvalidState);
                    }
                }
                retained.approval
            }
            None => {
                if signer.public_key() != self.authority.binding.public_key {
                    return Err(AuthorityOperationCoordinatorError::Rejected(
                        AuthorityOperationCoordinatorRejection::WrongSigner,
                    ));
                }
                self.authorize_exact::<S::Error>(call, authorization_context, &call_bytes)?
            }
        };

        let issued = self
            .issuer
            .issue(call, &approval, issued_at, signer)
            .map_err(AuthorityOperationCoordinatorError::Issuer)?;
        if self.image.records[record_index]
            .consumed_issuance_ack
            .is_some()
        {
            return Ok(issued);
        }

        let acknowledgement_context = acknowledgement_context(&issued.issuance_ack);
        if !issued
            .issuance_ack
            .matches_invocation_context(&acknowledgement_context)
        {
            return Err(AuthorityOperationCoordinatorError::InvalidState);
        }
        let acknowledgement_bytes = issued
            .issuance_ack
            .encode()
            .map_err(|_| AuthorityOperationCoordinatorError::InvalidState)?;
        let request = AuthorityOperationActorDispatch {
            target: self.authority,
            method: AuthorityOperationActorMethod::AcknowledgeIssuance,
            context: acknowledgement_context,
            request: acknowledgement_bytes,
        };
        match self.dispatch_exact::<S::Error>(&request)? {
            crate::value::Value::Bool(true) => {}
            crate::value::Value::Bool(false) => {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::AcknowledgementRejected,
                ));
            }
            _ => {
                return Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::InvalidDispatchResult,
                ));
            }
        }
        let mut completed = self.image.clone();
        completed.records[record_index].consumed_issuance_ack =
            Some(issued.issuance_ack.commitment());
        self.commit_candidate::<S::Error>(completed)?;
        Ok(issued)
    }

    fn authorize_exact<SignerError>(
        &mut self,
        call: &AuthorityOperationCall,
        context: InvocationContext,
        call_bytes: &[u8],
    ) -> Result<
        AuthorityOperationApproval,
        AuthorityOperationCoordinatorError<C::Error, I::Error, D::Error, SignerError>,
    > {
        let request = AuthorityOperationActorDispatch {
            target: self.authority,
            method: AuthorityOperationActorMethod::AuthorizeOperation,
            context,
            request: call_bytes.to_vec(),
        };
        let reply = self.dispatch_exact::<SignerError>(&request)?;
        let crate::value::Value::Bytes(approval_bytes) = reply else {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidDispatchResult,
            ));
        };
        if approval_bytes.is_empty() {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::AuthorizationDenied,
            ));
        }
        let approval = AuthorityOperationApproval::decode(&approval_bytes).map_err(|_| {
            AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidApproval,
            )
        })?;
        if approval_bytes.len() > MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES
            || approval.encode().ok().as_deref() != Some(approval_bytes.as_slice())
            || approval.authority != self.authority
            || !approval.matches_call(call)
        {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidApproval,
            ));
        }
        Ok(approval)
    }

    fn dispatch_exact<SignerError>(
        &mut self,
        request: &AuthorityOperationActorDispatch,
    ) -> Result<
        crate::value::Value,
        AuthorityOperationCoordinatorError<C::Error, I::Error, D::Error, SignerError>,
    > {
        let result = self
            .dispatcher
            .dispatch(request)
            .map_err(AuthorityOperationCoordinatorError::Dispatch)?;
        if result.target != request.target
            || result.method != request.method
            || result.context != request.context
            || result.request != request.request
            || !result.authenticated
            || !result.durable
            || result.context.mode != MethodMode::Linear
            || result.reply.len() > crate::agent::sdk::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidDispatchResult,
            ));
        }
        let reply = <crate::value::Value as crate::Decode>::try_decode(&result.reply).ok_or(
            AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidDispatchResult,
            ),
        )?;
        if crate::Encode::encode(&reply) != result.reply {
            return Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidDispatchResult,
            ));
        }
        Ok(reply)
    }

    fn ensure_live<SignerError>(
        &self,
    ) -> Result<(), AuthorityOperationCoordinatorError<C::Error, I::Error, D::Error, SignerError>>
    {
        if self.poisoned || self.issuer.is_poisoned() {
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::Poisoned,
            ))
        } else {
            Ok(())
        }
    }

    fn commit_candidate<SignerError>(
        &mut self,
        candidate: AuthorityOperationCoordinatorImage,
    ) -> Result<(), AuthorityOperationCoordinatorError<C::Error, I::Error, D::Error, SignerError>>
    {
        if !candidate.has_valid_envelope() {
            self.poisoned = true;
            return Err(AuthorityOperationCoordinatorError::InvalidState);
        }
        let bytes = candidate.encode();
        if bytes.len() > MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES {
            self.poisoned = true;
            return Err(AuthorityOperationCoordinatorError::InvalidState);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(AuthorityOperationCoordinatorError::Storage(error));
        }
        self.image = candidate;
        Ok(())
    }
}

fn coordinator_matches_issuer<I: AuthorityOperationIssuerStore>(
    image: &AuthorityOperationCoordinatorImage,
    issuer: &DurableAuthorityOperationIssuer<I>,
) -> bool {
    let mut issuer_records = 0usize;
    for record in &image.records {
        let Ok(call) = AuthorityOperationCall::decode(&record.call) else {
            return false;
        };
        let Ok(retained) = issuer.recover_retained(call.invocation) else {
            return false;
        };
        if let Some(retained) = retained {
            issuer_records += 1;
            if retained.call != call || retained.issued_at != record.issued_at {
                return false;
            }
            if let Some(consumed) = record.consumed_issuance_ack {
                if retained
                    .issuance_ack
                    .as_ref()
                    .is_none_or(|ack| ack.commitment() != consumed)
                {
                    return false;
                }
            }
        } else if record.consumed_issuance_ack.is_some() {
            return false;
        }
    }
    issuer_records == issuer.retained_operations()
}

fn retained_invocation_pair(record: &CoordinatorRecord) -> Option<(InvocationId, InvocationId)> {
    let call = AuthorityOperationCall::decode(&record.call).ok()?;
    Some((
        call.invocation,
        AuthorityOperationApproval::derive_acknowledgement_invocation(&call),
    ))
}

fn acknowledgement_context(ack: &AuthorityOperationIssuanceAck) -> InvocationContext {
    InvocationContext {
        invocation: ack.acknowledgement_invocation,
        actor: ack.authority.binding.issuer.actor,
        mode: MethodMode::Linear,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        observed_slot: ack.issued_at,
    }
}

struct RawEd25519Verifier;

impl AuthorityCredentialVerifier for RawEd25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crate::agent::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

impl crate::agent::sdk::authority::AuthorityVerifier for RawEd25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crate::agent::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

fn encode_authority_target(encoder: &mut Encoder<'_>, target: AuthorityActorTarget) {
    encoder.fixed(target.space.as_bytes());
    encoder.fixed(target.system_agent.as_bytes());
    encoder.fixed(target.system_runtime_deployment.as_bytes());
    encode_binding(encoder, target.binding);
}

fn decode_authority_target(decoder: &mut Decoder<'_>) -> Result<AuthorityActorTarget, DecodeError> {
    let target = AuthorityActorTarget {
        space: SpaceId(decoder.fixed()?),
        system_agent: AgentId(decoder.fixed()?),
        system_runtime_deployment: DeploymentId(decoder.fixed()?),
        binding: decode_binding(decoder)?,
    };
    target
        .is_valid()
        .then_some(target)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_binding(encoder: &mut Encoder<'_>, binding: AgentAuthorityBinding) {
    encoder.fixed(binding.policy.as_bytes());
    encode_issuer(encoder, binding.issuer);
    encoder.fixed(&binding.public_key);
    encoder.u64(binding.initial_epoch);
}

fn decode_binding(decoder: &mut Decoder<'_>) -> Result<AgentAuthorityBinding, DecodeError> {
    let binding = AgentAuthorityBinding {
        policy: Hash(decoder.fixed()?),
        issuer: decode_issuer(decoder)?,
        public_key: decoder.fixed()?,
        initial_epoch: decoder.u64()?,
    };
    binding
        .is_valid()
        .then_some(binding)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_issuer(encoder: &mut Encoder<'_>, issuer: AuthorityIssuer) {
    encoder.fixed(issuer.principal.as_bytes());
    encoder.fixed(issuer.actor.as_bytes());
    encoder.fixed(issuer.deployment.as_bytes());
    encoder.fixed(issuer.program.as_bytes());
    encoder.fixed(issuer.producer.as_bytes());
}

fn decode_issuer(decoder: &mut Decoder<'_>) -> Result<AuthorityIssuer, DecodeError> {
    let issuer = AuthorityIssuer {
        principal: PrincipalId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
    };
    issuer
        .is_valid()
        .then_some(issuer)
        .ok_or(DecodeError::NonCanonical)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::authority_operation_issuer::DurableAuthorityOperationIssuer;
    use crate::agent::sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, CREDENTIAL_SIGNATURE_BYTES,
    };
    use crate::agent::sdk::authority_operation::AuthorityOperationIntent;
    use crate::agent::sdk::{CredentialId, InvocationWork, NodeId, RuntimeBlob};

    #[derive(Clone, Debug, Default)]
    struct MemoryImageStore {
        inner: Arc<Mutex<MemoryImageState>>,
    }

    #[derive(Debug, Default)]
    struct MemoryImageState {
        image: Option<Vec<u8>>,
        commits: usize,
        fail_load: bool,
        fail_before: Option<usize>,
        fail_after: Option<usize>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MemoryStoreError;

    impl fmt::Display for MemoryStoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected memory-store failure")
        }
    }

    impl core::error::Error for MemoryStoreError {}

    impl MemoryImageStore {
        fn commits(&self) -> usize {
            self.inner.lock().unwrap().commits
        }

        fn image(&self) -> Option<Vec<u8>> {
            self.inner.lock().unwrap().image.clone()
        }

        fn replace_image(&self, image: Vec<u8>) {
            self.inner.lock().unwrap().image = Some(image);
        }

        fn fail_load(&self) {
            self.inner.lock().unwrap().fail_load = true;
        }

        fn fail_before_commit(&self, offset: usize) {
            let mut state = self.inner.lock().unwrap();
            state.fail_before = Some(state.commits + offset);
        }

        fn fail_after_commit(&self, offset: usize) {
            let mut state = self.inner.lock().unwrap();
            state.fail_after = Some(state.commits + offset);
        }

        fn load_image(&self) -> Result<Option<Vec<u8>>, MemoryStoreError> {
            let mut state = self.inner.lock().unwrap();
            if state.fail_load {
                state.fail_load = false;
                return Err(MemoryStoreError);
            }
            Ok(state.image.clone())
        }

        fn commit_image(&self, image: &[u8]) -> Result<(), MemoryStoreError> {
            let mut state = self.inner.lock().unwrap();
            state.commits += 1;
            let commit = state.commits;
            if state.fail_before == Some(commit) {
                state.fail_before = None;
                return Err(MemoryStoreError);
            }
            state.image = Some(image.to_vec());
            if state.fail_after == Some(commit) {
                state.fail_after = None;
                return Err(MemoryStoreError);
            }
            Ok(())
        }
    }

    impl AuthorityOperationCoordinatorStore for MemoryImageStore {
        type Error = MemoryStoreError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.load_image()
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.commit_image(image)
        }
    }

    impl AuthorityOperationIssuerStore for MemoryImageStore {
        type Error = MemoryStoreError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.load_image()
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.commit_image(image)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestSignerError;

    impl fmt::Display for TestSignerError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected signer failure")
        }
    }

    impl core::error::Error for TestSignerError {}

    struct CountingSigner {
        key: SigningKey,
        receipt_calls: usize,
        acknowledgement_calls: usize,
        fail_receipt: bool,
        fail_acknowledgement: bool,
    }

    impl CountingSigner {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                receipt_calls: 0,
                acknowledgement_calls: 0,
                fail_receipt: false,
                fail_acknowledgement: false,
            }
        }
    }

    impl AuthorityOperationEvidenceSigner for CountingSigner {
        type Error = TestSignerError;

        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }

        fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            self.receipt_calls += 1;
            if self.fail_receipt {
                self.fail_receipt = false;
                return Err(TestSignerError);
            }
            Ok(self.key.sign(message).to_bytes())
        }

        fn sign_issuance_ack(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            self.acknowledgement_calls += 1;
            if self.fail_acknowledgement {
                self.fail_acknowledgement = false;
                return Err(TestSignerError);
            }
            Ok(self.key.sign(message).to_bytes())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DispatchFault {
        WrongTarget,
        WrongMethod,
        WrongContext,
        WrongRequest,
        Unauthenticated,
        NotDurable,
        MalformedReply,
        NonCanonicalReply,
        OversizeReply,
        WrongReplyType,
        EmptyApproval,
        MalformedApproval,
        NonCanonicalApproval,
        MismatchedApproval,
        DifferentMatchingApproval,
        FalseAcknowledgement,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FakeDispatchError;

    impl fmt::Display for FakeDispatchError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected actor result loss")
        }
    }

    impl core::error::Error for FakeDispatchError {}

    #[derive(Clone, Debug)]
    struct PendingActorOperation {
        call_bytes: Vec<u8>,
        approval: AuthorityOperationApproval,
    }

    #[derive(Clone, Copy, Debug)]
    struct RetiredActorOperation {
        authorization_invocation: InvocationId,
        acknowledgement_invocation: InvocationId,
        authorization_sequence: core::num::NonZeroU64,
        issuance_ack: Hash,
    }

    #[derive(Debug, Default)]
    struct FakeActorState {
        authorization_sequence: u64,
        pending: Vec<PendingActorOperation>,
        retired: Vec<RetiredActorOperation>,
        authorization_calls: usize,
        acknowledgement_calls: usize,
        fail_after_authorize: bool,
        fail_after_acknowledgement: bool,
        fault: Option<(AuthorityOperationActorMethod, DispatchFault)>,
    }

    #[derive(Clone)]
    struct FakeDispatcher {
        authority: AuthorityActorTarget,
        state: Arc<Mutex<FakeActorState>>,
    }

    impl FakeDispatcher {
        fn new(authority: AuthorityActorTarget) -> Self {
            Self {
                authority,
                state: Arc::new(Mutex::new(FakeActorState::default())),
            }
        }

        fn counts(&self) -> (usize, usize) {
            let state = self.state.lock().unwrap();
            (state.authorization_calls, state.acknowledgement_calls)
        }

        fn pending(&self) -> usize {
            self.state.lock().unwrap().pending.len()
        }

        fn retired(&self) -> usize {
            self.state.lock().unwrap().retired.len()
        }

        fn lose_next_authorization_result(&self) {
            self.state.lock().unwrap().fail_after_authorize = true;
        }

        fn lose_next_acknowledgement_result(&self) {
            self.state.lock().unwrap().fail_after_acknowledgement = true;
        }

        fn fault_next(&self, fault: DispatchFault) {
            self.state.lock().unwrap().fault =
                Some((AuthorityOperationActorMethod::AuthorizeOperation, fault));
        }

        fn fault_next_acknowledgement(&self, fault: DispatchFault) {
            self.state.lock().unwrap().fault =
                Some((AuthorityOperationActorMethod::AcknowledgeIssuance, fault));
        }

        fn correct_reply(
            &self,
            request: &AuthorityOperationActorDispatch,
            state: &mut FakeActorState,
        ) -> crate::value::Value {
            if request.target != self.authority || request.context.mode != MethodMode::Linear {
                return match request.method {
                    AuthorityOperationActorMethod::AuthorizeOperation => {
                        crate::value::Value::Bytes(Vec::new())
                    }
                    AuthorityOperationActorMethod::AcknowledgeIssuance => {
                        crate::value::Value::Bool(false)
                    }
                };
            }
            match request.method {
                AuthorityOperationActorMethod::AuthorizeOperation => {
                    state.authorization_calls += 1;
                    let Ok(call) = AuthorityOperationCall::decode(&request.request) else {
                        return crate::value::Value::Bytes(Vec::new());
                    };
                    if call.encode().ok().as_deref() != Some(request.request.as_slice())
                        || !call.matches_invocation_context(&request.context)
                        || call.verify_with(&RawEd25519Verifier).is_err()
                    {
                        return crate::value::Value::Bytes(Vec::new());
                    }
                    if let Some(record) = state
                        .pending
                        .iter()
                        .find(|record| record.approval.invocation == call.invocation)
                    {
                        return crate::value::Value::Bytes(
                            (record.call_bytes == request.request)
                                .then(|| record.approval.encode().unwrap())
                                .unwrap_or_default(),
                        );
                    }
                    if state.retired.iter().any(|record| {
                        record.authorization_invocation == call.invocation
                            || record.acknowledgement_invocation == call.invocation
                    }) {
                        return crate::value::Value::Bytes(Vec::new());
                    }
                    let Some(sequence) = state.authorization_sequence.checked_add(1) else {
                        return crate::value::Value::Bytes(Vec::new());
                    };
                    let valid_from = call.requested_valid_from.max(request.context.observed_slot);
                    let Ok(approval) = AuthorityOperationApproval::from_call(
                        &call,
                        core::num::NonZeroU64::new(sequence).unwrap(),
                        AuthorityEvidence {
                            package: None,
                            proof: None,
                            commitment: Hash::digest(
                                b"vos/test/fake-authority-evidence/v1",
                                &[
                                    call.commitment().as_bytes(),
                                    &request.context.observed_slot.to_le_bytes(),
                                ],
                            ),
                        },
                        AuthorityLaneRoots::default(),
                        self.authority.binding.initial_epoch,
                        valid_from,
                        call.requested_expires_at,
                    ) else {
                        return crate::value::Value::Bytes(Vec::new());
                    };
                    state.authorization_sequence = sequence;
                    state.pending.push(PendingActorOperation {
                        call_bytes: request.request.clone(),
                        approval: approval.clone(),
                    });
                    crate::value::Value::Bytes(approval.encode().unwrap())
                }
                AuthorityOperationActorMethod::AcknowledgeIssuance => {
                    state.acknowledgement_calls += 1;
                    let Ok(ack) = AuthorityOperationIssuanceAck::decode(&request.request) else {
                        return crate::value::Value::Bool(false);
                    };
                    if ack.encode().ok().as_deref() != Some(request.request.as_slice())
                        || !ack.matches_invocation_context(&request.context)
                        || ack
                            .verify_with(self.authority.binding, &RawEd25519Verifier)
                            .is_err()
                    {
                        return crate::value::Value::Bool(false);
                    }
                    if let Some(retired) = state.retired.iter().find(|record| {
                        record.acknowledgement_invocation == ack.acknowledgement_invocation
                    }) {
                        return crate::value::Value::Bool(
                            retired.authorization_invocation == ack.authorization_invocation
                                && retired.authorization_sequence == ack.authorization_sequence
                                && retired.issuance_ack == ack.commitment(),
                        );
                    }
                    let Some(index) = state.pending.iter().position(|record| {
                        record.approval.acknowledgement_invocation == ack.acknowledgement_invocation
                    }) else {
                        return crate::value::Value::Bool(false);
                    };
                    let pending = &state.pending[index];
                    let Ok(call) = AuthorityOperationCall::decode(&pending.call_bytes) else {
                        return crate::value::Value::Bool(false);
                    };
                    if !ack.matches_pending(&call, &pending.approval) {
                        return crate::value::Value::Bool(false);
                    }
                    let pending = state.pending.remove(index);
                    state.retired.push(RetiredActorOperation {
                        authorization_invocation: ack.authorization_invocation,
                        acknowledgement_invocation: ack.acknowledgement_invocation,
                        authorization_sequence: pending.approval.authorization_sequence,
                        issuance_ack: ack.commitment(),
                    });
                    crate::value::Value::Bool(true)
                }
            }
        }
    }

    impl AuthorityOperationActorDispatcher for FakeDispatcher {
        type Error = FakeDispatchError;

        fn dispatch(
            &mut self,
            request: &AuthorityOperationActorDispatch,
        ) -> Result<AuthorityOperationActorResult, Self::Error> {
            let mut state = self.state.lock().unwrap();
            let mut reply = self.correct_reply(request, &mut state);
            let lost = match request.method {
                AuthorityOperationActorMethod::AuthorizeOperation if state.fail_after_authorize => {
                    state.fail_after_authorize = false;
                    true
                }
                AuthorityOperationActorMethod::AcknowledgeIssuance
                    if state.fail_after_acknowledgement =>
                {
                    state.fail_after_acknowledgement = false;
                    true
                }
                _ => false,
            };
            if lost {
                return Err(FakeDispatchError);
            }
            let fault = state
                .fault
                .filter(|(method, _)| *method == request.method)
                .map(|(_, fault)| fault);
            if fault.is_some() {
                state.fault = None;
            }
            if fault == Some(DispatchFault::EmptyApproval)
                && request.method == AuthorityOperationActorMethod::AuthorizeOperation
            {
                reply = crate::value::Value::Bytes(Vec::new());
            }
            if fault == Some(DispatchFault::MismatchedApproval)
                && request.method == AuthorityOperationActorMethod::AuthorizeOperation
            {
                if let crate::value::Value::Bytes(bytes) = &reply {
                    if let Ok(mut approval) = AuthorityOperationApproval::decode(bytes) {
                        approval.operation_call = Hash(id(0xa1, 1));
                        reply = crate::value::Value::Bytes(approval.encode().unwrap());
                    }
                }
            }
            if fault == Some(DispatchFault::DifferentMatchingApproval)
                && request.method == AuthorityOperationActorMethod::AuthorizeOperation
            {
                if let crate::value::Value::Bytes(bytes) = &reply {
                    if let Ok(mut approval) = AuthorityOperationApproval::decode(bytes) {
                        approval.selector.evidence.commitment = Hash(id(0xa5, 1));
                        reply = crate::value::Value::Bytes(approval.encode().unwrap());
                    }
                }
            }
            if fault == Some(DispatchFault::MalformedApproval)
                && request.method == AuthorityOperationActorMethod::AuthorizeOperation
            {
                reply = crate::value::Value::Bytes(vec![0xff; 3]);
            }
            if fault == Some(DispatchFault::NonCanonicalApproval)
                && request.method == AuthorityOperationActorMethod::AuthorizeOperation
            {
                if let crate::value::Value::Bytes(bytes) = &mut reply {
                    bytes.push(0);
                }
            }
            if fault == Some(DispatchFault::WrongReplyType) {
                reply = match request.method {
                    AuthorityOperationActorMethod::AuthorizeOperation => {
                        crate::value::Value::Bool(true)
                    }
                    AuthorityOperationActorMethod::AcknowledgeIssuance => {
                        crate::value::Value::Bytes(Vec::new())
                    }
                };
            }
            if fault == Some(DispatchFault::FalseAcknowledgement)
                && request.method == AuthorityOperationActorMethod::AcknowledgeIssuance
            {
                reply = crate::value::Value::Bool(false);
            }
            let mut result = AuthorityOperationActorResult {
                target: request.target,
                method: request.method,
                context: request.context,
                request: request.request.clone(),
                authenticated: true,
                durable: true,
                reply: crate::Encode::encode(&reply),
            };
            match fault {
                Some(DispatchFault::WrongTarget) => result.target.space = SpaceId(id(0xa2, 1)),
                Some(DispatchFault::WrongMethod) => {
                    result.method = match result.method {
                        AuthorityOperationActorMethod::AuthorizeOperation => {
                            AuthorityOperationActorMethod::AcknowledgeIssuance
                        }
                        AuthorityOperationActorMethod::AcknowledgeIssuance => {
                            AuthorityOperationActorMethod::AuthorizeOperation
                        }
                    }
                }
                Some(DispatchFault::WrongContext) => {
                    result.context.observed_slot = result.context.observed_slot.saturating_add(1)
                }
                Some(DispatchFault::WrongRequest) => result.request.push(0xff),
                Some(DispatchFault::Unauthenticated) => result.authenticated = false,
                Some(DispatchFault::NotDurable) => result.durable = false,
                Some(DispatchFault::MalformedReply) => result.reply = vec![0xff; 3],
                Some(DispatchFault::NonCanonicalReply) => result.reply.push(0),
                Some(DispatchFault::OversizeReply) => {
                    result.reply = vec![0; crate::agent::sdk::MAX_INVOCATION_REPLY_BYTES + 1]
                }
                _ => {}
            }
            Ok(result)
        }
    }

    struct Fixture {
        authority: AuthorityActorTarget,
        credential_key: SigningKey,
    }

    impl Fixture {
        fn new(authority_signer: &CountingSigner) -> Self {
            let public_key = authority_signer.public_key();
            Self {
                authority: AuthorityActorTarget {
                    space: SpaceId(id(0x11, 1)),
                    system_agent: AgentId(id(0x12, 1)),
                    system_runtime_deployment: DeploymentId(id(0x13, 1)),
                    binding: AgentAuthorityBinding {
                        policy: Hash(id(0x14, 1)),
                        issuer: AuthorityIssuer {
                            principal: PrincipalId(id(0x15, 1)),
                            actor: ActorId(id(0x16, 1)),
                            deployment: DeploymentId(id(0x17, 1)),
                            program: ProgramId(id(0x18, 1)),
                            producer: ProducerId::of_public_key(&public_key),
                        },
                        public_key,
                        initial_epoch: 2,
                    },
                },
                credential_key: SigningKey::from_bytes(&[0x21; 32]),
            }
        }

        fn call(&self, discriminator: u64) -> AuthorityOperationCall {
            self.call_with_invocation(discriminator, InvocationId::ZERO)
        }

        fn call_with_invocation(
            &self,
            discriminator: u64,
            authorization_invocation: InvocationId,
        ) -> AuthorityOperationCall {
            let credential_public_key = self.credential_key.verifying_key().to_bytes();
            let principal = PrincipalId(id(0x22, 1));
            let credential = CredentialId::of_public_key(&credential_public_key);
            let node = NodeId(id(0x23, 1));
            let work = InvocationWork {
                space: self.authority.space,
                agent: AgentId(id(0x31, discriminator)),
                runtime_deployment: DeploymentId(id(0x32, discriminator)),
                invocation: InvocationId(id(0x33, discriminator)),
                actor: ActorId(id(0x34, discriminator)),
                incarnation: Hash(id(0x35, discriminator)),
                deployment: DeploymentId(id(0x36, discriminator)),
                program: ProgramId(id(0x37, discriminator)),
                mode: MethodMode::Linear,
                origin: InvocationOrigin {
                    principal: Some(principal),
                    transport_node: Some(node),
                    credential: Some(credential),
                    actor: None,
                    capability: None,
                },
                roles: InvocationRoleClaims::none(),
                message: discriminator.to_le_bytes().to_vec(),
                installation_data: None,
                availability: Vec::<RuntimeBlob>::new(),
                gas: 100,
                recovery_only: false,
            };
            let mut call = AuthorityOperationCall {
                invocation: authorization_invocation,
                authority: self.authority,
                principal,
                credential,
                request_sequence: core::num::NonZeroU64::new(discriminator).unwrap(),
                credential_public_key,
                authenticated_node: Some(node),
                requested_valid_from: 10,
                requested_expires_at: 100,
                intent: AuthorityOperationIntent::invoke(&work).unwrap(),
                signature: [0; CREDENTIAL_SIGNATURE_BYTES],
            };
            if call.invocation == InvocationId::ZERO {
                call.invocation = call.expected_invocation();
            }
            call.signature = self.credential_key.sign(&call.signing_bytes()).to_bytes();
            call
        }

        fn context(&self, call: &AuthorityOperationCall, observed_slot: u64) -> InvocationContext {
            InvocationContext {
                invocation: call.invocation,
                actor: self.authority.binding.issuer.actor,
                mode: MethodMode::Linear,
                origin: InvocationOrigin {
                    principal: Some(call.principal),
                    transport_node: call.authenticated_node,
                    credential: Some(call.credential),
                    actor: None,
                    capability: None,
                },
                roles: InvocationRoleClaims::none(),
                observed_slot,
            }
        }
    }

    type TestCoordinator =
        DurableAuthorityOperationCoordinator<FakeDispatcher, MemoryImageStore, MemoryImageStore>;

    fn open(
        coordinator_store: MemoryImageStore,
        issuer_store: MemoryImageStore,
        dispatcher: FakeDispatcher,
        fixture: &Fixture,
    ) -> TestCoordinator {
        let issuer =
            DurableAuthorityOperationIssuer::open(issuer_store, fixture.authority).unwrap();
        DurableAuthorityOperationCoordinator::open(
            coordinator_store,
            fixture.authority,
            dispatcher,
            issuer,
        )
        .unwrap()
    }

    fn id(prefix: u8, number: u64) -> [u8; 32] {
        let mut value = [prefix; 32];
        value[24..].copy_from_slice(&number.to_le_bytes());
        value
    }

    #[test]
    fn exact_retry_and_restart_return_identical_evidence_without_dispatch_or_signing() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);
        let mut coordinator = open(
            coordinator_store.clone(),
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );

        let issued = coordinator
            .coordinate(&call, context, 20, &mut signer)
            .unwrap();
        assert_eq!(dispatcher.counts(), (1, 1));
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
        assert_eq!(
            (coordinator_store.commits(), issuer_store.commits()),
            (2, 3)
        );
        assert_eq!((dispatcher.pending(), dispatcher.retired()), (0, 1));

        assert_eq!(
            coordinator
                .coordinate(&call, context, 20, &mut signer)
                .unwrap(),
            issued
        );
        assert_eq!(dispatcher.counts(), (1, 1));
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));

        let mut reopened = open(
            coordinator_store,
            issuer_store,
            dispatcher.clone(),
            &fixture,
        );
        assert_eq!(
            reopened
                .coordinate(&call, context, 20, &mut signer)
                .unwrap(),
            issued
        );
        assert_eq!(dispatcher.counts(), (1, 1));
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
    }

    #[test]
    fn lost_authorization_result_replays_the_exact_pledged_dispatch_after_restart() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        dispatcher.lose_next_authorization_result();
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);
        let mut coordinator = open(
            coordinator_store.clone(),
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );
        assert!(matches!(
            coordinator.coordinate(&call, context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Dispatch(
                FakeDispatchError
            ))
        ));
        assert_eq!(dispatcher.counts(), (1, 0));
        assert_eq!(dispatcher.pending(), 1);
        assert_eq!(issuer_store.commits(), 0);

        let mut reopened = open(
            coordinator_store,
            issuer_store,
            dispatcher.clone(),
            &fixture,
        );
        reopened
            .coordinate(&call, context, 20, &mut signer)
            .unwrap();
        assert_eq!(dispatcher.counts(), (2, 1));
        assert_eq!((dispatcher.pending(), dispatcher.retired()), (0, 1));
    }

    #[test]
    fn lost_acknowledgement_result_resubmits_retained_aoi_without_reauthorizing() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        dispatcher.lose_next_acknowledgement_result();
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);
        let mut coordinator = open(
            coordinator_store.clone(),
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );
        assert!(matches!(
            coordinator.coordinate(&call, context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Dispatch(
                FakeDispatchError
            ))
        ));
        assert_eq!(dispatcher.counts(), (1, 1));
        assert_eq!((dispatcher.pending(), dispatcher.retired()), (0, 1));
        assert_eq!(issuer_store.commits(), 3);

        // The actor's retirement tombstone deliberately cannot reconstruct
        // unsigned AOP1. Recovery therefore has to consult the issuer first.
        let authorization = AuthorityOperationActorDispatch {
            target: fixture.authority,
            method: AuthorityOperationActorMethod::AuthorizeOperation,
            context,
            request: call.encode().unwrap(),
        };
        let mut direct = dispatcher.clone();
        let denied = direct.dispatch(&authorization).unwrap();
        assert_eq!(
            <crate::value::Value as crate::Decode>::try_decode(&denied.reply),
            Some(crate::value::Value::Bytes(Vec::new()))
        );

        let mut reopened = open(
            coordinator_store,
            issuer_store,
            dispatcher.clone(),
            &fixture,
        );
        reopened
            .coordinate(&call, context, 20, &mut signer)
            .unwrap();
        assert_eq!(dispatcher.counts(), (2, 2));
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
    }

    #[test]
    fn issuer_commit_failpoints_resume_from_every_exact_durable_boundary() {
        for commit in 1..=3 {
            for fail_after in [false, true] {
                let coordinator_store = MemoryImageStore::default();
                let issuer_store = MemoryImageStore::default();
                let mut signer = CountingSigner::new(0x19);
                let fixture = Fixture::new(&signer);
                let dispatcher = FakeDispatcher::new(fixture.authority);
                let call = fixture.call(1);
                let context = fixture.context(&call, 20);
                if fail_after {
                    issuer_store.fail_after_commit(commit);
                } else {
                    issuer_store.fail_before_commit(commit);
                }
                let mut coordinator = open(
                    coordinator_store.clone(),
                    issuer_store.clone(),
                    dispatcher.clone(),
                    &fixture,
                );
                assert!(matches!(
                    coordinator.coordinate(&call, context, 20, &mut signer),
                    Err(AuthorityOperationCoordinatorError::Issuer(
                        AuthorityOperationIssuerError::Storage(MemoryStoreError)
                    ))
                ));
                assert!(coordinator.is_poisoned());
                assert_eq!(dispatcher.counts(), (1, 0));
                assert!(matches!(
                    coordinator.coordinate(&call, context, 20, &mut signer),
                    Err(AuthorityOperationCoordinatorError::Rejected(
                        AuthorityOperationCoordinatorRejection::Poisoned
                    ))
                ));

                let mut reopened = open(
                    coordinator_store,
                    issuer_store,
                    dispatcher.clone(),
                    &fixture,
                );
                reopened
                    .coordinate(&call, context, 20, &mut signer)
                    .unwrap();
                let expected_authorizations = if commit == 3 && fail_after { 1 } else { 2 };
                assert_eq!(dispatcher.counts(), (expected_authorizations, 1));
                assert_eq!((dispatcher.pending(), dispatcher.retired()), (0, 1));
            }
        }
    }

    #[test]
    fn signer_failures_resume_after_exact_actor_approval_revalidation() {
        for fail_acknowledgement in [false, true] {
            let coordinator_store = MemoryImageStore::default();
            let issuer_store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let dispatcher = FakeDispatcher::new(fixture.authority);
            let call = fixture.call(1);
            let context = fixture.context(&call, 20);
            if fail_acknowledgement {
                signer.fail_acknowledgement = true;
            } else {
                signer.fail_receipt = true;
            }
            let mut coordinator = open(
                coordinator_store,
                issuer_store,
                dispatcher.clone(),
                &fixture,
            );
            assert!(matches!(
                coordinator.coordinate(&call, context, 20, &mut signer),
                Err(AuthorityOperationCoordinatorError::Issuer(
                    AuthorityOperationIssuerError::Signer(TestSignerError)
                ))
            ));
            assert_eq!(dispatcher.counts(), (1, 0));
            coordinator
                .coordinate(&call, context, 20, &mut signer)
                .unwrap();
            assert_eq!(dispatcher.counts(), (2, 1));
        }
    }

    #[test]
    fn incomplete_unsigned_approval_is_revalidated_exactly_before_resume() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        signer.fail_receipt = true;
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);
        let mut coordinator = open(
            coordinator_store,
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );
        assert!(matches!(
            coordinator.coordinate(&call, context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Issuer(
                AuthorityOperationIssuerError::Signer(TestSignerError)
            ))
        ));
        assert_eq!(issuer_store.commits(), 1);

        // This alternate AOP1 remains well-shaped and matches the AOC1, but
        // it is not the exact actor result retained before the failed sign.
        dispatcher.fault_next(DispatchFault::DifferentMatchingApproval);
        assert!(matches!(
            coordinator.coordinate(&call, context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));
        assert_eq!(issuer_store.commits(), 1);
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 0));
    }

    #[test]
    fn coordinator_commit_failpoints_poison_then_reconcile_actor_consumption() {
        for fail_after in [false, true] {
            let coordinator_store = MemoryImageStore::default();
            let issuer_store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let dispatcher = FakeDispatcher::new(fixture.authority);
            let call = fixture.call(1);
            let context = fixture.context(&call, 20);
            if fail_after {
                coordinator_store.fail_after_commit(2);
            } else {
                coordinator_store.fail_before_commit(2);
            }
            let mut coordinator = open(
                coordinator_store.clone(),
                issuer_store.clone(),
                dispatcher.clone(),
                &fixture,
            );
            assert!(matches!(
                coordinator.coordinate(&call, context, 20, &mut signer),
                Err(AuthorityOperationCoordinatorError::Storage(
                    MemoryStoreError
                ))
            ));
            assert!(coordinator.is_poisoned());
            assert_eq!((dispatcher.pending(), dispatcher.retired()), (0, 1));

            let mut reopened = open(
                coordinator_store,
                issuer_store,
                dispatcher.clone(),
                &fixture,
            );
            reopened
                .coordinate(&call, context, 20, &mut signer)
                .unwrap();
            assert_eq!(dispatcher.counts(), (1, if fail_after { 1 } else { 2 }));
            assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
        }

        for fail_after in [false, true] {
            let coordinator_store = MemoryImageStore::default();
            let issuer_store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let dispatcher = FakeDispatcher::new(fixture.authority);
            let call = fixture.call(1);
            let context = fixture.context(&call, 20);
            if fail_after {
                coordinator_store.fail_after_commit(1);
            } else {
                coordinator_store.fail_before_commit(1);
            }
            let mut coordinator = open(
                coordinator_store.clone(),
                issuer_store.clone(),
                dispatcher.clone(),
                &fixture,
            );
            assert!(matches!(
                coordinator.coordinate(&call, context, 20, &mut signer),
                Err(AuthorityOperationCoordinatorError::Storage(
                    MemoryStoreError
                ))
            ));
            assert_eq!(dispatcher.counts(), (0, 0));
            let mut reopened = open(
                coordinator_store,
                issuer_store,
                dispatcher.clone(),
                &fixture,
            );
            reopened
                .coordinate(&call, context, 20, &mut signer)
                .unwrap();
            assert_eq!(dispatcher.counts(), (1, 1));
        }
    }

    #[test]
    fn hostile_authorization_dispatch_metadata_and_reply_frames_fail_closed() {
        for fault in [
            DispatchFault::WrongTarget,
            DispatchFault::WrongMethod,
            DispatchFault::WrongContext,
            DispatchFault::WrongRequest,
            DispatchFault::Unauthenticated,
            DispatchFault::NotDurable,
            DispatchFault::MalformedReply,
            DispatchFault::NonCanonicalReply,
            DispatchFault::OversizeReply,
            DispatchFault::WrongReplyType,
        ] {
            let coordinator_store = MemoryImageStore::default();
            let issuer_store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let dispatcher = FakeDispatcher::new(fixture.authority);
            dispatcher.fault_next(fault);
            let call = fixture.call(1);
            let context = fixture.context(&call, 20);
            let mut coordinator = open(
                coordinator_store,
                issuer_store.clone(),
                dispatcher,
                &fixture,
            );
            assert!(matches!(
                coordinator.coordinate(&call, context, 20, &mut signer),
                Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::InvalidDispatchResult
                ))
            ));
            assert_eq!(issuer_store.commits(), 0);
            assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (0, 0));
        }

        for (fault, rejection) in [
            (
                DispatchFault::EmptyApproval,
                AuthorityOperationCoordinatorRejection::AuthorizationDenied,
            ),
            (
                DispatchFault::MismatchedApproval,
                AuthorityOperationCoordinatorRejection::InvalidApproval,
            ),
            (
                DispatchFault::MalformedApproval,
                AuthorityOperationCoordinatorRejection::InvalidApproval,
            ),
            (
                DispatchFault::NonCanonicalApproval,
                AuthorityOperationCoordinatorRejection::InvalidApproval,
            ),
        ] {
            let coordinator_store = MemoryImageStore::default();
            let issuer_store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let dispatcher = FakeDispatcher::new(fixture.authority);
            dispatcher.fault_next(fault);
            let call = fixture.call(1);
            let context = fixture.context(&call, 20);
            let mut coordinator = open(
                coordinator_store,
                issuer_store.clone(),
                dispatcher,
                &fixture,
            );
            assert!(matches!(
                coordinator.coordinate(&call, context, 20, &mut signer),
                Err(AuthorityOperationCoordinatorError::Rejected(actual)) if actual == rejection
            ));
            assert_eq!(issuer_store.commits(), 0);
        }
    }

    #[test]
    fn hostile_acknowledgement_dispatch_metadata_type_and_false_result_fail_closed() {
        for fault in [
            DispatchFault::WrongTarget,
            DispatchFault::WrongMethod,
            DispatchFault::WrongContext,
            DispatchFault::WrongRequest,
            DispatchFault::Unauthenticated,
            DispatchFault::NotDurable,
            DispatchFault::MalformedReply,
            DispatchFault::NonCanonicalReply,
            DispatchFault::OversizeReply,
            DispatchFault::WrongReplyType,
        ] {
            let coordinator_store = MemoryImageStore::default();
            let issuer_store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let dispatcher = FakeDispatcher::new(fixture.authority);
            dispatcher.fault_next_acknowledgement(fault);
            let call = fixture.call(1);
            let context = fixture.context(&call, 20);
            let mut coordinator = open(coordinator_store, issuer_store, dispatcher, &fixture);
            assert!(matches!(
                coordinator.coordinate(&call, context, 20, &mut signer),
                Err(AuthorityOperationCoordinatorError::Rejected(
                    AuthorityOperationCoordinatorRejection::InvalidDispatchResult
                ))
            ));
        }

        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        dispatcher.fault_next_acknowledgement(DispatchFault::FalseAcknowledgement);
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);
        let mut coordinator = open(coordinator_store, issuer_store, dispatcher, &fixture);
        assert!(matches!(
            coordinator.coordinate(&call, context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::AcknowledgementRejected
            ))
        ));
    }

    #[test]
    fn call_route_context_signature_and_slot_substitutions_fail_before_dispatch() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);

        let mut forged = call.clone();
        forged.signature[0] ^= 1;
        let mut coordinator = open(
            coordinator_store.clone(),
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );
        assert!(matches!(
            coordinator.coordinate(&forged, context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidCall
            ))
        ));

        let other_signer = CountingSigner::new(0x72);
        let other_fixture = Fixture::new(&other_signer);
        let wrong_route = other_fixture.call(2);
        let wrong_route_context = other_fixture.context(&wrong_route, 20);
        assert!(matches!(
            coordinator.coordinate(&wrong_route, wrong_route_context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::WrongRoute
            ))
        ));

        let mut wrong_context = context;
        wrong_context.invocation = InvocationId(id(0xa3, 1));
        assert!(matches!(
            coordinator.coordinate(&call, wrong_context, 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::WrongAuthorizationContext
            ))
        ));
        assert!(matches!(
            coordinator.coordinate(&call, context, 19, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::IssuanceBeforeAuthorization
            ))
        ));
        assert!(matches!(
            coordinator.coordinate(&call, context, 101, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidIssuanceSlot
            ))
        ));
        let mut wrong_signer = CountingSigner::new(0x73);
        assert!(matches!(
            coordinator.coordinate(&call, context, 20, &mut wrong_signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::WrongSigner
            ))
        ));
        assert_eq!(dispatcher.counts(), (0, 0));
        assert_eq!(coordinator_store.commits(), 0);
        assert_eq!(issuer_store.commits(), 0);
    }

    #[test]
    fn retries_bind_both_slots_and_fresh_operations_cannot_regress_them() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let first = fixture.call(1);
        let first_context = fixture.context(&first, 25);
        let mut coordinator = open(
            coordinator_store.clone(),
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );
        coordinator
            .coordinate(&first, first_context, 30, &mut signer)
            .unwrap();

        let changed_context = fixture.context(&first, 26);
        assert!(matches!(
            coordinator.coordinate(&first, changed_context, 30, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::DivergentRetry
            ))
        ));
        assert!(matches!(
            coordinator.coordinate(&first, first_context, 31, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::DivergentRetry
            ))
        ));
        let replacement = fixture.call_with_invocation(3, first.invocation);
        assert!(matches!(
            coordinator.coordinate(
                &replacement,
                fixture.context(&replacement, 25),
                30,
                &mut signer
            ),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidCall
            ))
        ));

        let second = fixture.call(2);
        assert!(matches!(
            coordinator.coordinate(&second, fixture.context(&second, 24), 30, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::AuthorizationSlotRegressed
            ))
        ));
        assert!(matches!(
            coordinator.coordinate(&second, fixture.context(&second, 25), 29, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::IssuanceSlotRegressed
            ))
        ));
        assert_eq!(dispatcher.counts(), (1, 1));

        let mut reopened = open(
            coordinator_store,
            issuer_store,
            dispatcher.clone(),
            &fixture,
        );
        assert!(matches!(
            reopened.coordinate(&second, fixture.context(&second, 24), 30, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::AuthorizationSlotRegressed
            ))
        ));
        reopened
            .coordinate(&second, fixture.context(&second, 25), 30, &mut signer)
            .unwrap();
        assert_eq!(dispatcher.counts(), (2, 2));
    }

    #[test]
    fn authorization_and_acknowledgement_invocation_collisions_fail_closed() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let first = fixture.call(1);
        let first_context = fixture.context(&first, 20);
        let mut coordinator = open(
            coordinator_store,
            issuer_store,
            dispatcher.clone(),
            &fixture,
        );
        coordinator
            .coordinate(&first, first_context, 20, &mut signer)
            .unwrap();
        let collision = fixture.call_with_invocation(
            2,
            AuthorityOperationApproval::derive_acknowledgement_invocation(&first),
        );
        assert!(collision.validate_shape().is_err());
        assert!(matches!(
            coordinator.coordinate(&collision, fixture.context(&collision, 20), 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidCall
            ))
        ));

        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let second = fixture.call(4);
        let first = fixture.call_with_invocation(
            3,
            AuthorityOperationApproval::derive_acknowledgement_invocation(&second),
        );
        let mut coordinator = open(coordinator_store, issuer_store, dispatcher, &fixture);
        assert!(first.validate_shape().is_err());
        assert!(matches!(
            coordinator.coordinate(&first, fixture.context(&first, 20), 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::InvalidCall
            ))
        ));
    }

    #[test]
    fn bounded_retention_rejects_capacity_without_dispatch_or_compaction() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let mut coordinator = open(
            coordinator_store,
            issuer_store,
            dispatcher.clone(),
            &fixture,
        );
        for discriminator in 1..=MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS as u64 {
            let call = fixture.call(discriminator);
            coordinator
                .coordinate(&call, fixture.context(&call, 20), 20, &mut signer)
                .unwrap();
        }
        assert_eq!(
            coordinator.retained_operations(),
            MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS
        );
        let before = dispatcher.counts();
        let overflow = fixture.call(MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS as u64 + 1);
        assert!(matches!(
            coordinator.coordinate(&overflow, fixture.context(&overflow, 20), 20, &mut signer),
            Err(AuthorityOperationCoordinatorError::Rejected(
                AuthorityOperationCoordinatorRejection::JournalFull
            ))
        ));
        assert_eq!(dispatcher.counts(), before);
    }

    #[test]
    fn corrupt_noncanonical_wrong_route_and_cross_store_images_fail_to_open() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let call = fixture.call(1);
        let context = fixture.context(&call, 20);
        let mut coordinator = open(
            coordinator_store.clone(),
            issuer_store.clone(),
            dispatcher.clone(),
            &fixture,
        );
        coordinator
            .coordinate(&call, context, 20, &mut signer)
            .unwrap();
        let valid = coordinator_store.image().unwrap();

        let mut corrupt = AuthorityOperationCoordinatorImage::decode(&valid).unwrap();
        *corrupt.records[0].call.last_mut().unwrap() ^= 1;
        coordinator_store.replace_image(corrupt.encode());
        let issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store.clone(),
                fixture.authority,
                dispatcher.clone(),
                issuer
            ),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));

        let mut noncanonical = valid.clone();
        noncanonical.push(0);
        coordinator_store.replace_image(noncanonical);
        let issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store.clone(),
                fixture.authority,
                dispatcher.clone(),
                issuer
            ),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));

        let mut wrong_consumption = AuthorityOperationCoordinatorImage::decode(&valid).unwrap();
        wrong_consumption.records[0].consumed_issuance_ack = Some(Hash(id(0xa6, 1)));
        coordinator_store.replace_image(wrong_consumption.encode());
        let issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store.clone(),
                fixture.authority,
                dispatcher.clone(),
                issuer
            ),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));

        coordinator_store.replace_image(valid.clone());
        let other_signer = CountingSigner::new(0x72);
        let other_fixture = Fixture::new(&other_signer);
        let other_issuer = DurableAuthorityOperationIssuer::open(
            MemoryImageStore::default(),
            other_fixture.authority,
        )
        .unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store.clone(),
                other_fixture.authority,
                FakeDispatcher::new(other_fixture.authority),
                other_issuer
            ),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));

        // A completed coordinator row without its exact retained issuer
        // preimages is not a recoverable acknowledgement fact.
        let empty_issuer =
            DurableAuthorityOperationIssuer::open(MemoryImageStore::default(), fixture.authority)
                .unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store,
                fixture.authority,
                dispatcher,
                empty_issuer
            ),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));
    }

    #[test]
    fn orphan_issuer_records_and_storage_load_errors_fail_closed() {
        let coordinator_store = MemoryImageStore::default();
        let issuer_store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let dispatcher = FakeDispatcher::new(fixture.authority);
        let call = fixture.call(1);
        let approval = AuthorityOperationApproval::from_call(
            &call,
            core::num::NonZeroU64::new(1).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash(id(0xa4, 1)),
            },
            AuthorityLaneRoots::default(),
            fixture.authority.binding.initial_epoch,
            20,
            100,
        )
        .unwrap();
        let mut issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        let issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store.clone(),
                fixture.authority,
                dispatcher.clone(),
                issuer
            ),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));

        coordinator_store.fail_load();
        let issuer =
            DurableAuthorityOperationIssuer::open(MemoryImageStore::default(), fixture.authority)
                .unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(
                coordinator_store,
                fixture.authority,
                dispatcher,
                issuer
            ),
            Err(AuthorityOperationCoordinatorError::Storage(
                MemoryStoreError
            ))
        ));

        let failing_issuer_store = MemoryImageStore::default();
        failing_issuer_store.fail_load();
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(failing_issuer_store, fixture.authority),
            Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
        ));
    }
}
