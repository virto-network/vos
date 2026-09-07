//! Crash-safe host coordination for applying authority-approved Private controls.
//!
//! AOI1 proves receipt issuance, not application. This module first reopens the
//! exact issuer-retained AOC4/AOP4/AOI1 chain and reconstructs that AOC4 intent
//! from the supplied canonical PCTL. It then pledges the exact PCTL and logical
//! application slot before asking the configured Private runtime to apply it.
//! Only an authenticated result which echoes every request field and asserts a
//! durable apply *and* durable reopen can supply the application fact pledged
//! and signed by the issuer as PCA1. Finally, PCA1 is sent to the exact
//! system-authority actor under its derived third Linear invocation and the
//! exact acknowledgement is committed locally. Only then does the coordinator
//! ask the runtime to attach the retained canonical AOI1+PCA1 envelope to the
//! applied PCTL; a final local marker makes lost-result attachment retry exact.
//!
//! Records remain bounded and are never compacted. An affirmative actor reply
//! is durable at the trusted dispatch boundary, but this slice has no separate
//! independently reopenable proof of actor consumption. Retention therefore
//! fails closed at capacity rather than making an unsafe reuse assumption.

use core::{convert::Infallible, fmt};

use super::authority_operation_issuer::{
    AuthorityOperationIssuerError, AuthorityOperationIssuerStore, DurableAuthorityOperationIssuer,
    PrivateControlApplicationEvidenceSigner, private_intent_matches_application,
};
use super::private_sync::PrivateControlAuthorityEvidence;
use crate::agent::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityIssuer, AuthorityVerifier,
    ManagedAgentTarget,
};
#[cfg(test)]
use crate::agent::sdk::authority_operation::PrivateRecoveryAuthorityProof;
use crate::agent::sdk::authority_operation::{
    AuthorityOperationIntent, PrivateControlApplicationAck, PrivateControlApplicationFact,
};
use crate::agent::sdk::private::PrivateControlRecord;
use crate::agent::sdk::wire::{CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES};
use crate::agent::sdk::{
    ActorId, AgentId, DeploymentId, Hash, InvocationContext, InvocationId, InvocationOrigin,
    InvocationRoleClaims, MethodMode, PrincipalId, ProducerId, ProgramId, SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

pub(crate) const MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS: usize =
    super::authority_operation_issuer::MAX_AUTHORITY_OPERATION_ISSUER_RECORDS;
pub(crate) const MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_IMAGE_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_PRIVATE_CONTROL_APPLICATION_FACT_WIRE_BYTES: usize = 512;
const PRIVATE_CONTROL_APPLICATION_COORDINATOR_MAGIC: [u8; 4] = *b"PAJ3";
const PRIVATE_CONTROL_APPLICATION_FACT_MAGIC: [u8; 4] = *b"PCAF";

/// Exact request to the trusted Private-runtime application boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlRuntimeApplicationRequest {
    pub(crate) route: ManagedAgentTarget,
    pub(crate) authority: AuthorityActorTarget,
    pub(crate) control: Vec<u8>,
    pub(crate) receipt: Vec<u8>,
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) applied_at: u64,
}

/// Echoed result of an authenticated, durable Private transition and reopen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlRuntimeApplicationResult {
    pub(crate) route: ManagedAgentTarget,
    pub(crate) authority: AuthorityActorTarget,
    pub(crate) control: Vec<u8>,
    pub(crate) receipt: Vec<u8>,
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) applied_at: u64,
    pub(crate) authenticated: bool,
    pub(crate) durably_applied: bool,
    pub(crate) durably_reopened: bool,
    /// Canonical host-local PCAF frame, independently decoded below.
    pub(crate) application_fact: Vec<u8>,
}

/// Exact post-completion evidence attachment request. This request is emitted
/// only after the coordinator has durably recorded authority consumption of
/// PCA1; it never asks the runtime to regenerate or re-sign either proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlRuntimeEvidenceRequest {
    pub(crate) route: ManagedAgentTarget,
    pub(crate) authority: AuthorityActorTarget,
    pub(crate) control: Vec<u8>,
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) application_ack: Vec<u8>,
    /// Canonical PRA1 for Recover and absent for every other control family.
    pub(crate) recovery_proof: Option<Vec<u8>>,
}

/// Echoed proof that the exact evidence envelope was durably attached and
/// physically reopened by the configured Private runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlRuntimeEvidenceResult {
    pub(crate) route: ManagedAgentTarget,
    pub(crate) authority: AuthorityActorTarget,
    pub(crate) control: Vec<u8>,
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) application_ack: Vec<u8>,
    pub(crate) recovery_proof: Option<Vec<u8>>,
    pub(crate) evidence_commitment: Hash,
    pub(crate) authenticated: bool,
    pub(crate) durably_persisted: bool,
    pub(crate) durably_reopened: bool,
}

/// Trusted adapter to the exact installed Private runtime.
///
/// Implementations may assert success only after authenticating `route`,
/// applying the exact PCTL under the exact issued evidence, durably committing
/// that transition, and reopening the resulting state. Echo fields are an
/// integration guard; they do not turn a dishonest adapter into a capability.
/// `persist_completed_evidence` is called only with coordinator-retained AOI1
/// and PCA1 bytes after durable authority consumption and must atomically
/// attach, reopen, and echo that exact envelope.
pub(crate) trait PrivateControlRuntimeApplicationAdapter {
    type Error;

    fn apply(
        &mut self,
        request: &PrivateControlRuntimeApplicationRequest,
    ) -> Result<PrivateControlRuntimeApplicationResult, Self::Error>;

    fn persist_completed_evidence(
        &mut self,
        request: &PrivateControlRuntimeEvidenceRequest,
    ) -> Result<PrivateControlRuntimeEvidenceResult, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PrivateApplicationAuthorityMethod {
    AcknowledgePrivateApplication = 0,
    /// Cannot be emitted by the coordinator; retained to let adapters report
    /// an accidentally substituted method as data which is then rejected.
    Unexpected = 1,
}

impl PrivateApplicationAuthorityMethod {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::AcknowledgePrivateApplication => "acknowledge_private_application",
            Self::Unexpected => "unexpected_private_application_method",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateApplicationAuthorityDispatch {
    pub(crate) target: AuthorityActorTarget,
    pub(crate) method: PrivateApplicationAuthorityMethod,
    pub(crate) context: InvocationContext,
    pub(crate) request: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateApplicationAuthorityResult {
    pub(crate) target: AuthorityActorTarget,
    pub(crate) method: PrivateApplicationAuthorityMethod,
    pub(crate) context: InvocationContext,
    pub(crate) request: Vec<u8>,
    pub(crate) authenticated: bool,
    pub(crate) durable: bool,
    /// Canonical encoded actor [`crate::value::Value`] reply.
    pub(crate) reply: Vec<u8>,
}

/// Trusted exact-route dispatcher for the system-authority PCA1 method.
pub(crate) trait PrivateApplicationAuthorityDispatcher {
    type Error;

    fn dispatch(
        &mut self,
        request: &PrivateApplicationAuthorityDispatch,
    ) -> Result<PrivateApplicationAuthorityResult, Self::Error>;
}

pub(crate) trait PrivateControlApplicationCoordinatorStore {
    type Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateControlApplicationCoordinatorRejection {
    Poisoned,
    MissingIssuance,
    InvalidControl,
    InvalidControlSignature,
    WrongRoute,
    InvalidApplicationSlot,
    ApplicationSlotRegressed,
    DivergentRetry,
    InvocationCollision,
    PendingApplication,
    JournalFull,
    WrongSigner,
    InvalidRuntimeResult,
    InvalidEvidenceResult,
    ApplicationRejected,
    InvalidAuthorityResult,
    AcknowledgementRejected,
}

#[derive(Debug)]
pub(crate) enum PrivateControlApplicationCoordinatorError<
    CoordinatorStorageError,
    IssuerStorageError,
    RuntimeError = Infallible,
    DispatchError = Infallible,
    SignerError = Infallible,
> {
    Storage(CoordinatorStorageError),
    Issuer(AuthorityOperationIssuerError<IssuerStorageError, SignerError>),
    Runtime(RuntimeError),
    Dispatch(DispatchError),
    InvalidState,
    Rejected(PrivateControlApplicationCoordinatorRejection),
}

impl<CoordinatorStorageError, IssuerStorageError, RuntimeError, DispatchError, SignerError>
    fmt::Display
    for PrivateControlApplicationCoordinatorError<
        CoordinatorStorageError,
        IssuerStorageError,
        RuntimeError,
        DispatchError,
        SignerError,
    >
where
    CoordinatorStorageError: fmt::Display,
    IssuerStorageError: fmt::Display,
    RuntimeError: fmt::Display,
    DispatchError: fmt::Display,
    SignerError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "Private application storage: {error}"),
            Self::Issuer(error) => error.fmt(formatter),
            Self::Runtime(error) => write!(formatter, "Private runtime application: {error}"),
            Self::Dispatch(error) => write!(formatter, "Private authority dispatch: {error}"),
            Self::InvalidState => formatter.write_str("invalid Private application state"),
            Self::Rejected(error) => write!(formatter, "Private application rejected: {error:?}"),
        }
    }
}

impl<CoordinatorStorageError, IssuerStorageError, RuntimeError, DispatchError, SignerError>
    core::error::Error
    for PrivateControlApplicationCoordinatorError<
        CoordinatorStorageError,
        IssuerStorageError,
        RuntimeError,
        DispatchError,
        SignerError,
    >
where
    CoordinatorStorageError: core::error::Error + 'static,
    IssuerStorageError: core::error::Error + 'static,
    RuntimeError: core::error::Error + 'static,
    DispatchError: core::error::Error + 'static,
    SignerError: core::error::Error + 'static,
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApplicationRecord {
    authorization_invocation: InvocationId,
    application_invocation: InvocationId,
    control: Vec<u8>,
    applied_at: u64,
    consumed_application_ack: Option<Hash>,
    persisted_authority_evidence: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateControlApplicationCoordinatorImage {
    authority: AuthorityActorTarget,
    application_slot_high_water: Option<u64>,
    records: Vec<ApplicationRecord>,
}

impl PrivateControlApplicationCoordinatorImage {
    fn empty(authority: AuthorityActorTarget) -> Self {
        Self {
            authority,
            application_slot_high_water: None,
            records: Vec::new(),
        }
    }

    fn has_valid_envelope(&self) -> bool {
        self.authority.is_valid()
            && self.records.len() <= MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS
            && (self.records.is_empty() == self.application_slot_high_water.is_none())
            && self.records.last().map(|record| record.applied_at)
                == self.application_slot_high_water
            && self.records.iter().all(|record| {
                record.control.len() <= MAX_PRIVATE_CONTROL_WIRE_BYTES
                    && record.authorization_invocation != InvocationId::ZERO
                    && record.application_invocation != InvocationId::ZERO
                    && record.authorization_invocation != record.application_invocation
                    && record.consumed_application_ack != Some(Hash::ZERO)
                    && record.persisted_authority_evidence != Some(Hash::ZERO)
            })
            && self.records.iter().enumerate().all(|(index, record)| {
                let is_last = index + 1 == self.records.len();
                (record.persisted_authority_evidence.is_none()
                    || record.consumed_application_ack.is_some())
                    && (is_last
                        || (record.consumed_application_ack.is_some()
                            && record.persisted_authority_evidence.is_some()))
            })
    }

    fn is_valid(&self) -> bool {
        if !self.has_valid_envelope() {
            return false;
        }
        let mut invocations = Vec::new();
        let mut prior_slot = None;
        for record in &self.records {
            let Ok(control) = PrivateControlRecord::decode(&record.control) else {
                return false;
            };
            if control.encode().ok().as_deref() != Some(record.control.as_slice())
                || !verify_private_control_signature(&control)
                || control.space != self.authority.space
                || prior_slot.is_some_and(|prior| prior > record.applied_at)
                || !push_unique(&mut invocations, record.authorization_invocation)
                || !push_unique(&mut invocations, record.application_invocation)
            {
                return false;
            }
            prior_slot = Some(record.applied_at);
        }
        true
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PRIVATE_CONTROL_APPLICATION_COORDINATOR_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        encode_authority_target(&mut encoder, self.authority);
        encoder.option(&self.application_slot_high_water, |encoder, slot| {
            encoder.u64(*slot)
        });
        encoder.list(&self.records, |encoder, record| {
            encoder.fixed(record.authorization_invocation.as_bytes());
            encoder.fixed(record.application_invocation.as_bytes());
            encoder.bytes(&record.control);
            encoder.u64(record.applied_at);
            encoder.option(
                &record.consumed_application_ack,
                |encoder, acknowledgement| encoder.fixed(acknowledgement.as_bytes()),
            );
            encoder.option(&record.persisted_authority_evidence, |encoder, evidence| {
                encoder.fixed(evidence.as_bytes())
            });
        });
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(PRIVATE_CONTROL_APPLICATION_COORDINATOR_MAGIC.len())?
            != PRIVATE_CONTROL_APPLICATION_COORDINATOR_MAGIC
        {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != crate::agent::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let authority = decode_authority_target(&mut decoder)?;
        let application_slot_high_water = decoder.option(Decoder::u64)?;
        let count = decoder.u32()? as usize;
        if count > MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = Vec::new();
        records
            .try_reserve(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            records.push(ApplicationRecord {
                authorization_invocation: InvocationId(decoder.fixed()?),
                application_invocation: InvocationId(decoder.fixed()?),
                control: decoder.bytes_bounded(MAX_PRIVATE_CONTROL_WIRE_BYTES)?,
                applied_at: decoder.u64()?,
                consumed_application_ack: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
                persisted_authority_evidence: decoder
                    .option(|decoder| Ok(Hash(decoder.fixed()?)))?,
            });
        }
        let image = Self {
            authority,
            application_slot_high_water,
            records,
        };
        if !decoder.exhausted() || !image.is_valid() || image.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(image)
    }
}

pub(crate) struct DurablePrivateControlApplicationCoordinator<R, A, C, I>
where
    R: PrivateControlRuntimeApplicationAdapter,
    A: PrivateApplicationAuthorityDispatcher,
    C: PrivateControlApplicationCoordinatorStore,
    I: AuthorityOperationIssuerStore,
{
    authority: AuthorityActorTarget,
    runtime: R,
    dispatcher: A,
    store: C,
    image: PrivateControlApplicationCoordinatorImage,
    issuer: DurableAuthorityOperationIssuer<I>,
    poisoned: bool,
}

impl<R, A, C, I> DurablePrivateControlApplicationCoordinator<R, A, C, I>
where
    R: PrivateControlRuntimeApplicationAdapter,
    A: PrivateApplicationAuthorityDispatcher,
    C: PrivateControlApplicationCoordinatorStore,
    I: AuthorityOperationIssuerStore,
{
    pub(crate) fn open(
        mut store: C,
        authority: AuthorityActorTarget,
        runtime: R,
        dispatcher: A,
        issuer: DurableAuthorityOperationIssuer<I>,
    ) -> Result<Self, PrivateControlApplicationCoordinatorError<C::Error, I::Error>> {
        if !authority.is_valid() || issuer.authority() != authority || issuer.is_poisoned() {
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        let image = match store
            .load()
            .map_err(PrivateControlApplicationCoordinatorError::Storage)?
        {
            Some(bytes) => {
                let image = PrivateControlApplicationCoordinatorImage::decode(&bytes)
                    .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
                if image.authority != authority {
                    return Err(PrivateControlApplicationCoordinatorError::InvalidState);
                }
                image
            }
            None => PrivateControlApplicationCoordinatorImage::empty(authority),
        };
        if !coordinator_matches_issuer(&image, &issuer) {
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        Ok(Self {
            authority,
            runtime,
            dispatcher,
            store,
            image,
            issuer,
            poisoned: false,
        })
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned || self.issuer.is_poisoned()
    }

    pub(crate) fn retained_applications(&self) -> usize {
        self.image.records.len()
    }

    pub(crate) fn has_pending_application(&self) -> bool {
        self.image.records.iter().any(|record| {
            record.consumed_application_ack.is_none()
                || record.persisted_authority_evidence.is_none()
        })
    }

    pub(crate) fn into_parts(self) -> (C, R, A, DurableAuthorityOperationIssuer<I>) {
        (self.store, self.runtime, self.dispatcher, self.issuer)
    }

    /// Apply one exact PCTL and complete its PCA1 acknowledgement pipeline.
    ///
    /// Raw wire and trusted adapter assertions stay crate-private: neither is
    /// an independently authenticated signing capability.
    pub(crate) fn apply<S: PrivateControlApplicationEvidenceSigner>(
        &mut self,
        authorization_invocation: InvocationId,
        control_wire: &[u8],
        applied_at: u64,
        signer: &mut S,
    ) -> Result<
        PrivateControlApplicationAck,
        PrivateControlApplicationCoordinatorError<C::Error, I::Error, R::Error, A::Error, S::Error>,
    > {
        self.ensure_live()?;
        if control_wire.len() > MAX_PRIVATE_CONTROL_WIRE_BYTES {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl,
            ));
        }
        let control = PrivateControlRecord::decode(control_wire).map_err(|_| {
            Self::rejected(PrivateControlApplicationCoordinatorRejection::InvalidControl)
        })?;
        if control.encode().ok().as_deref() != Some(control_wire) || !control.validate_shape() {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl,
            ));
        }
        if !verify_private_control_signature(&control) {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControlSignature,
            ));
        }
        let retained = self
            .issuer
            .recover_retained(authorization_invocation)
            .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?
            .ok_or_else(|| {
                Self::rejected(PrivateControlApplicationCoordinatorRejection::MissingIssuance)
            })?;
        let issuance = retained.issuance_ack.as_ref().ok_or_else(|| {
            Self::rejected(PrivateControlApplicationCoordinatorRejection::MissingIssuance)
        })?;
        if retained.call.authority != self.authority
            || retained.approval.authority != self.authority
            || issuance.authority != self.authority
            || control.space != self.authority.space
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::WrongRoute,
            ));
        }
        if !retained.call.intent.matches_private_control(&control)
            || !retained.approval.matches_private_control(&control)
            || !issuance.matches_pending(&retained.call, &retained.approval)
            || issuance
                .verify_with(self.authority.binding, &RawEd25519Verifier)
                .is_err()
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl,
            ));
        }
        if applied_at < issuance.issued_at || !issuance.receipt.selector.is_live_at(applied_at) {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidApplicationSlot,
            ));
        }
        let application_invocation =
            PrivateControlApplicationAck::derive_application_invocation(issuance);
        let existing_index = self
            .image
            .records
            .iter()
            .position(|record| record.authorization_invocation == authorization_invocation);
        let record_index = if let Some(index) = existing_index {
            let record = &self.image.records[index];
            if record.application_invocation != application_invocation
                || record.control != control_wire
                || record.applied_at != applied_at
            {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::DivergentRetry,
                ));
            }
            index
        } else {
            if self.has_pending_application() {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::PendingApplication,
                ));
            }
            if self.image.records.len() == MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::JournalFull,
                ));
            }
            if self
                .image
                .application_slot_high_water
                .is_some_and(|slot| applied_at < slot)
            {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::ApplicationSlotRegressed,
                ));
            }
            if self.image.records.iter().any(|record| {
                record.authorization_invocation == application_invocation
                    || record.application_invocation == authorization_invocation
                    || record.application_invocation == application_invocation
            }) {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::InvocationCollision,
                ));
            }
            if signer.public_key() != self.authority.binding.public_key {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::WrongSigner,
                ));
            }
            let mut pledged = self.image.clone();
            pledged.application_slot_high_water = Some(applied_at);
            pledged.records.push(ApplicationRecord {
                authorization_invocation,
                application_invocation,
                control: control_wire.to_vec(),
                applied_at,
                consumed_application_ack: None,
                persisted_authority_evidence: None,
            });
            self.commit_candidate::<S::Error>(pledged)?;
            self.image.records.len() - 1
        };

        if retained.application.is_none()
            && signer.public_key() != self.authority.binding.public_key
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::WrongSigner,
            ));
        }

        let application = match retained.application.as_ref() {
            Some(application) => {
                if application.applied_at != applied_at
                    || !private_intent_matches_application(&retained.call.intent, application)
                    || application.control != control.commitment()
                {
                    return Err(PrivateControlApplicationCoordinatorError::InvalidState);
                }
                *application
            }
            None => {
                self.apply_runtime_exact::<S::Error>(&control, control_wire, applied_at, &retained)?
            }
        };
        let issued = self
            .issuer
            .issue_private_application(authorization_invocation, &application, signer)
            .map_err(PrivateControlApplicationCoordinatorError::Issuer)?;
        let acknowledgement = issued.application_ack;
        if acknowledgement.application_invocation != application_invocation
            || !acknowledgement.matches_pending(
                &retained.call,
                &retained.approval,
                issuance,
                &application,
            )
            || acknowledgement
                .verify_pending_with(
                    &retained.call,
                    &retained.approval,
                    issuance,
                    &application,
                    self.authority.binding,
                    &RawEd25519Verifier,
                )
                .is_err()
        {
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        if let Some(consumed) = self.image.records[record_index].consumed_application_ack {
            if consumed != acknowledgement.commitment() {
                return Err(PrivateControlApplicationCoordinatorError::InvalidState);
            }
            self.persist_runtime_evidence_exact::<S::Error>(
                record_index,
                &retained,
                &acknowledgement,
            )?;
            return Ok(acknowledgement);
        }

        let context = application_context(&acknowledgement);
        if !acknowledgement.matches_invocation_context(&context) {
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        let acknowledgement_bytes = acknowledgement
            .encode()
            .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
        let request = PrivateApplicationAuthorityDispatch {
            target: self.authority,
            method: PrivateApplicationAuthorityMethod::AcknowledgePrivateApplication,
            context,
            request: acknowledgement_bytes,
        };
        match self.dispatch_authority_exact::<S::Error>(&request)? {
            crate::value::Value::Bool(true) => {}
            crate::value::Value::Bool(false) => {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::AcknowledgementRejected,
                ));
            }
            _ => {
                return Err(Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidAuthorityResult,
                ));
            }
        }
        let mut completed = self.image.clone();
        completed.records[record_index].consumed_application_ack =
            Some(acknowledgement.commitment());
        self.commit_candidate::<S::Error>(completed)?;
        self.persist_runtime_evidence_exact::<S::Error>(record_index, &retained, &acknowledgement)?;
        Ok(acknowledgement)
    }

    fn persist_runtime_evidence_exact<SignerError>(
        &mut self,
        record_index: usize,
        retained: &super::authority_operation_issuer::RetainedAuthorityOperation,
        acknowledgement: &PrivateControlApplicationAck,
    ) -> Result<
        (),
        PrivateControlApplicationCoordinatorError<
            C::Error,
            I::Error,
            R::Error,
            A::Error,
            SignerError,
        >,
    > {
        let issuance = retained
            .issuance_ack
            .as_ref()
            .ok_or(PrivateControlApplicationCoordinatorError::InvalidState)?;
        let issuance_ack = issuance
            .encode()
            .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
        let application_ack = acknowledgement
            .encode()
            .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
        let recovery_proof = match &retained.call.intent {
            AuthorityOperationIntent::RecoverPrivateAgent { proof } => Some(proof),
            _ => None,
        };
        let recovery_proof_wire = recovery_proof
            .map(|proof| {
                proof
                    .encode()
                    .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)
            })
            .transpose()?;
        let request = PrivateControlRuntimeEvidenceRequest {
            route: retained.call.intent.managed(),
            authority: self.authority,
            control: self
                .image
                .records
                .get(record_index)
                .ok_or(PrivateControlApplicationCoordinatorError::InvalidState)?
                .control
                .clone(),
            issuance_ack,
            application_ack,
            recovery_proof: recovery_proof_wire,
        };
        let expected = PrivateControlAuthorityEvidence::from_acknowledgements(
            issuance,
            acknowledgement,
            recovery_proof,
        )
        .and_then(|evidence| evidence.commitment())
        .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
        if expected == Hash::ZERO {
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        if let Some(commitment) = self.image.records[record_index].persisted_authority_evidence {
            return if commitment == expected {
                Ok(())
            } else {
                Err(PrivateControlApplicationCoordinatorError::InvalidState)
            };
        }
        let result = self
            .runtime
            .persist_completed_evidence(&request)
            .map_err(PrivateControlApplicationCoordinatorError::Runtime)?;
        if result.route != request.route
            || result.authority != request.authority
            || result.control != request.control
            || result.issuance_ack != request.issuance_ack
            || result.application_ack != request.application_ack
            || result.recovery_proof != request.recovery_proof
            || result.evidence_commitment != expected
            || !result.authenticated
            || !result.durably_persisted
            || !result.durably_reopened
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidEvidenceResult,
            ));
        }
        if self.image.records[record_index]
            .persisted_authority_evidence
            .is_none()
        {
            let mut completed = self.image.clone();
            completed.records[record_index].persisted_authority_evidence = Some(expected);
            self.commit_candidate::<SignerError>(completed)?;
        }
        Ok(())
    }

    fn apply_runtime_exact<SignerError>(
        &mut self,
        control: &PrivateControlRecord,
        control_wire: &[u8],
        applied_at: u64,
        retained: &super::authority_operation_issuer::RetainedAuthorityOperation,
    ) -> Result<
        PrivateControlApplicationFact,
        PrivateControlApplicationCoordinatorError<
            C::Error,
            I::Error,
            R::Error,
            A::Error,
            SignerError,
        >,
    > {
        let issuance = retained
            .issuance_ack
            .as_ref()
            .ok_or(PrivateControlApplicationCoordinatorError::InvalidState)?;
        let receipt = issuance
            .receipt
            .encode()
            .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
        let issuance_ack = issuance
            .encode()
            .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
        let request = PrivateControlRuntimeApplicationRequest {
            route: retained.call.intent.managed(),
            authority: self.authority,
            control: control_wire.to_vec(),
            receipt,
            issuance_ack,
            applied_at,
        };
        let result = self
            .runtime
            .apply(&request)
            .map_err(PrivateControlApplicationCoordinatorError::Runtime)?;
        if result.route != request.route
            || result.authority != request.authority
            || result.control != request.control
            || result.receipt != request.receipt
            || result.issuance_ack != request.issuance_ack
            || result.applied_at != request.applied_at
            || !result.authenticated
            || !result.durably_applied
            || !result.durably_reopened
            || result.application_fact.len() > MAX_PRIVATE_CONTROL_APPLICATION_FACT_WIRE_BYTES
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult,
            ));
        }
        let application =
            decode_private_application_fact(&result.application_fact).map_err(|_| {
                Self::rejected(PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult)
            })?;
        if encode_private_application_fact(&application) != result.application_fact
            || application.applied_at != applied_at
            || application.control != control.commitment()
            || !private_intent_matches_application(&retained.call.intent, &application)
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::ApplicationRejected,
            ));
        }
        Ok(application)
    }

    fn dispatch_authority_exact<SignerError>(
        &mut self,
        request: &PrivateApplicationAuthorityDispatch,
    ) -> Result<
        crate::value::Value,
        PrivateControlApplicationCoordinatorError<
            C::Error,
            I::Error,
            R::Error,
            A::Error,
            SignerError,
        >,
    > {
        let result = self
            .dispatcher
            .dispatch(request)
            .map_err(PrivateControlApplicationCoordinatorError::Dispatch)?;
        if result.target != request.target
            || result.method != request.method
            || result.context != request.context
            || result.request != request.request
            || !result.authenticated
            || !result.durable
            || result.context.mode != MethodMode::Linear
            || result.reply.len() > crate::agent::sdk::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidAuthorityResult,
            ));
        }
        let value =
            <crate::value::Value as crate::Decode>::try_decode(&result.reply).ok_or_else(|| {
                Self::rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidAuthorityResult,
                )
            })?;
        if crate::Encode::encode(&value) != result.reply {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidAuthorityResult,
            ));
        }
        Ok(value)
    }

    fn ensure_live<SignerError>(
        &self,
    ) -> Result<
        (),
        PrivateControlApplicationCoordinatorError<
            C::Error,
            I::Error,
            R::Error,
            A::Error,
            SignerError,
        >,
    > {
        if self.poisoned || self.issuer.is_poisoned() {
            Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::Poisoned,
            ))
        } else {
            Ok(())
        }
    }

    fn commit_candidate<SignerError>(
        &mut self,
        candidate: PrivateControlApplicationCoordinatorImage,
    ) -> Result<
        (),
        PrivateControlApplicationCoordinatorError<
            C::Error,
            I::Error,
            R::Error,
            A::Error,
            SignerError,
        >,
    > {
        if !candidate.is_valid() {
            self.poisoned = true;
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        let bytes = candidate.encode();
        if bytes.len() > MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_IMAGE_BYTES {
            self.poisoned = true;
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(PrivateControlApplicationCoordinatorError::Storage(error));
        }
        self.image = candidate;
        Ok(())
    }

    fn rejected<SignerError>(
        rejection: PrivateControlApplicationCoordinatorRejection,
    ) -> PrivateControlApplicationCoordinatorError<
        C::Error,
        I::Error,
        R::Error,
        A::Error,
        SignerError,
    > {
        PrivateControlApplicationCoordinatorError::Rejected(rejection)
    }
}

fn coordinator_matches_issuer<I: AuthorityOperationIssuerStore>(
    image: &PrivateControlApplicationCoordinatorImage,
    issuer: &DurableAuthorityOperationIssuer<I>,
) -> bool {
    let mut issuer_applications = 0usize;
    let verifier = RawEd25519Verifier;
    for record in &image.records {
        let Ok(Some(retained)) = issuer.recover_retained(record.authorization_invocation) else {
            return false;
        };
        let Some(issuance) = retained.issuance_ack.as_ref() else {
            return false;
        };
        let Ok(control) = PrivateControlRecord::decode(&record.control) else {
            return false;
        };
        if !retained.call.intent.matches_private_control(&control)
            || retained.call.authority != image.authority
            || record.application_invocation
                != PrivateControlApplicationAck::derive_application_invocation(issuance)
            || record.applied_at < issuance.issued_at
            || !issuance.receipt.selector.is_live_at(record.applied_at)
            || issuance
                .verify_with(image.authority.binding, &verifier)
                .is_err()
        {
            return false;
        }
        if let Some(application) = retained.application.as_ref() {
            issuer_applications += 1;
            if application.applied_at != record.applied_at
                || application.control != control.commitment()
                || !private_intent_matches_application(&retained.call.intent, application)
            {
                return false;
            }
        }
        if let Some(consumed) = record.consumed_application_ack {
            if retained
                .application_ack
                .as_ref()
                .is_none_or(|acknowledgement| acknowledgement.commitment() != consumed)
            {
                return false;
            }
        }
        if let Some(persisted) = record.persisted_authority_evidence {
            let Some(acknowledgement) = retained.application_ack.as_ref() else {
                return false;
            };
            let recovery_proof = match &retained.call.intent {
                AuthorityOperationIntent::RecoverPrivateAgent { proof } => Some(proof),
                _ => None,
            };
            let Ok(evidence) = PrivateControlAuthorityEvidence::from_acknowledgements(
                issuance,
                acknowledgement,
                recovery_proof,
            ) else {
                return false;
            };
            if evidence.commitment().ok() != Some(persisted) {
                return false;
            }
        }
    }
    issuer_applications == issuer.retained_private_applications()
}

fn application_context(acknowledgement: &PrivateControlApplicationAck) -> InvocationContext {
    InvocationContext {
        invocation: acknowledgement.application_invocation,
        actor: acknowledgement.authority.binding.issuer.actor,
        mode: MethodMode::Linear,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        observed_slot: acknowledgement.application.applied_at,
    }
}

fn verify_private_control_signature(control: &PrivateControlRecord) -> bool {
    control.validate_shape()
        && crate::agent::authority::verify_raw_ed25519(
            &control.signer_public_key,
            &control.signing_bytes(),
            &control.signature,
        )
}

fn push_unique(invocations: &mut Vec<InvocationId>, invocation: InvocationId) -> bool {
    if invocation == InvocationId::ZERO || invocations.contains(&invocation) {
        return false;
    }
    invocations.push(invocation);
    true
}

pub(crate) fn encode_private_application_fact(
    application: &PrivateControlApplicationFact,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PRIVATE_CONTROL_APPLICATION_FACT_MAGIC);
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
    encode_managed_target(&mut encoder, application.managed);
    encoder.u8(application.operation as u8);
    encoder.fixed(application.control.as_bytes());
    encoder.u64(application.control_sequence);
    encoder.option(&application.control_previous, |encoder, previous| {
        encoder.fixed(previous.as_bytes())
    });
    encoder.u64(application.epoch);
    encoder.fixed(application.post_member_set.as_bytes());
    encoder.fixed(application.reopened_control_state.as_bytes());
    encoder.fixed(application.reopened_control_head.as_bytes());
    encoder.u64(application.applied_at);
    bytes
}

pub(crate) fn decode_private_application_fact(
    bytes: &[u8],
) -> Result<PrivateControlApplicationFact, DecodeError> {
    if bytes.len() > MAX_PRIVATE_CONTROL_APPLICATION_FACT_WIRE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(PRIVATE_CONTROL_APPLICATION_FACT_MAGIC.len())?
        != PRIVATE_CONTROL_APPLICATION_FACT_MAGIC
    {
        return Err(DecodeError::InvalidTag);
    }
    if Hash(decoder.fixed()?) != crate::agent::sdk::RUNTIME_ABI_ID {
        return Err(DecodeError::InvalidPlatform);
    }
    let application = PrivateControlApplicationFact {
        managed: decode_managed_target(&mut decoder)?,
        operation: match decoder.u8()? {
            value
                if value
                    == crate::agent::sdk::authority::AuthorityOperationKind::InvitePrivateNode
                        as u8 =>
            {
                crate::agent::sdk::authority::AuthorityOperationKind::InvitePrivateNode
            }
            value
                if value
                    == crate::agent::sdk::authority::AuthorityOperationKind::RevokePrivateNode
                        as u8 =>
            {
                crate::agent::sdk::authority::AuthorityOperationKind::RevokePrivateNode
            }
            value
                if value
                    == crate::agent::sdk::authority::AuthorityOperationKind::RecoverPrivateAgent
                        as u8 =>
            {
                crate::agent::sdk::authority::AuthorityOperationKind::RecoverPrivateAgent
            }
            value
                if value
                    == crate::agent::sdk::authority::AuthorityOperationKind::RotatePrivateKeys
                        as u8 =>
            {
                crate::agent::sdk::authority::AuthorityOperationKind::RotatePrivateKeys
            }
            value
                if value
                    == crate::agent::sdk::authority::AuthorityOperationKind::SetPrivateResourcePolicy
                        as u8 =>
            {
                crate::agent::sdk::authority::AuthorityOperationKind::SetPrivateResourcePolicy
            }
            value
                if value
                    == crate::agent::sdk::authority::AuthorityOperationKind::PrivateActorLifecycle
                        as u8 =>
            {
                crate::agent::sdk::authority::AuthorityOperationKind::PrivateActorLifecycle
            }
            _ => return Err(DecodeError::InvalidTag),
        },
        control: Hash(decoder.fixed()?),
        control_sequence: decoder.u64()?,
        control_previous: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        epoch: decoder.u64()?,
        post_member_set: Hash(decoder.fixed()?),
        reopened_control_state: Hash(decoder.fixed()?),
        reopened_control_head: Hash(decoder.fixed()?),
        applied_at: decoder.u64()?,
    };
    if !decoder.exhausted() || application.validate_shape().is_err() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(application)
}

fn encode_managed_target(encoder: &mut Encoder<'_>, target: ManagedAgentTarget) {
    encoder.fixed(target.space.as_bytes());
    encoder.fixed(target.agent.as_bytes());
    encoder.fixed(target.runtime_deployment.as_bytes());
}

fn decode_managed_target(decoder: &mut Decoder<'_>) -> Result<ManagedAgentTarget, DecodeError> {
    let target = ManagedAgentTarget {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        runtime_deployment: DeploymentId(decoder.fixed()?),
    };
    target
        .is_valid()
        .then_some(target)
        .ok_or(DecodeError::NonCanonical)
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

struct RawEd25519Verifier;

impl AuthorityVerifier for RawEd25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crate::agent::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::authority_operation_issuer::{
        AuthorityOperationEvidenceSigner, AuthorityOperationIssuerRejection,
        AuthorityOperationIssuerStore,
    };
    use crate::agent::private_crypto::{RecoverySigningKey, sign_recovery_control_record};
    use crate::agent::sdk::authority::{
        AuthorityEvidence, AuthorityLaneRoots, AuthorityOperationKind, CREDENTIAL_SIGNATURE_BYTES,
    };
    use crate::agent::sdk::authority_operation::{
        AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIssuanceAck,
    };
    use crate::agent::sdk::private::{
        EncryptedObjectKind, EncryptedPrivateObject, PRIVATE_SIGNATURE_BYTES,
        PrivateControlOperation, PrivateControlSigner, PrivateKeyEpoch, PrivateNodeIdentity,
        PrivateRecoveryKeyringGrant, SealedPrivateKey, SealedRecoveryKey,
    };
    use crate::agent::sdk::{CredentialId, NodeId};

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
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected test failure")
        }
    }

    impl core::error::Error for TestError {}

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

        fn load_inner(&mut self) -> Result<Option<Vec<u8>>, TestError> {
            let mut state = self.inner.lock().unwrap();
            if state.fail_load {
                state.fail_load = false;
                return Err(TestError);
            }
            Ok(state.image.clone())
        }

        fn commit_inner(&mut self, image: &[u8]) -> Result<(), TestError> {
            let mut state = self.inner.lock().unwrap();
            state.commits += 1;
            let commit = state.commits;
            if state.fail_before == Some(commit) {
                state.fail_before = None;
                return Err(TestError);
            }
            state.image = Some(image.to_vec());
            if state.fail_after == Some(commit) {
                state.fail_after = None;
                return Err(TestError);
            }
            Ok(())
        }
    }

    impl AuthorityOperationIssuerStore for MemoryImageStore {
        type Error = TestError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.load_inner()
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.commit_inner(image)
        }
    }

    impl PrivateControlApplicationCoordinatorStore for MemoryImageStore {
        type Error = TestError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.load_inner()
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.commit_inner(image)
        }
    }

    struct CountingSigner {
        key: SigningKey,
        receipt_calls: usize,
        issuance_calls: usize,
        application_calls: usize,
        fail_application: bool,
        corrupt_application: bool,
    }

    impl CountingSigner {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                receipt_calls: 0,
                issuance_calls: 0,
                application_calls: 0,
                fail_application: false,
                corrupt_application: false,
            }
        }

        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }
    }

    impl AuthorityOperationEvidenceSigner for CountingSigner {
        type Error = TestError;

        fn public_key(&self) -> [u8; 32] {
            self.public_key()
        }

        fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            self.receipt_calls += 1;
            Ok(self.key.sign(message).to_bytes())
        }

        fn sign_issuance_ack(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            self.issuance_calls += 1;
            Ok(self.key.sign(message).to_bytes())
        }
    }

    impl PrivateControlApplicationEvidenceSigner for CountingSigner {
        type Error = TestError;

        fn public_key(&self) -> [u8; 32] {
            self.public_key()
        }

        fn sign_private_application_ack(
            &mut self,
            message: &[u8],
        ) -> Result<[u8; 64], Self::Error> {
            self.application_calls += 1;
            if self.fail_application {
                self.fail_application = false;
                return Err(TestError);
            }
            let mut signature = self.key.sign(message).to_bytes();
            if self.corrupt_application {
                signature[0] ^= 1;
            }
            Ok(signature)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum RuntimeMutation {
        Route,
        Authority,
        Control,
        Receipt,
        Issuance,
        Slot,
        Unauthenticated,
        NotApplied,
        NotReopened,
        MalformedFact,
        NonCanonicalFact,
        OversizeFact,
        FactRoute,
        FactControl,
        FactSlot,
    }

    #[derive(Clone, Copy, Debug)]
    enum EvidenceMutation {
        Route,
        Authority,
        Control,
        Issuance,
        Application,
        Commitment,
        Unauthenticated,
        NotPersisted,
        NotReopened,
    }

    #[derive(Clone, Debug, Default)]
    struct FakeRuntime {
        inner: Arc<Mutex<FakeRuntimeState>>,
    }

    #[derive(Debug, Default)]
    struct FakeRuntimeState {
        calls: usize,
        transitions: usize,
        evidence_calls: usize,
        retained_evidence: Vec<(PrivateControlRuntimeEvidenceRequest, Hash)>,
        retained: Vec<(PrivateControlRuntimeApplicationRequest, Vec<u8>)>,
        mutation: Option<RuntimeMutation>,
        evidence_mutation: Option<EvidenceMutation>,
        lose_result_after_apply: bool,
        lose_result_after_evidence: bool,
    }

    impl FakeRuntime {
        fn calls(&self) -> usize {
            self.inner.lock().unwrap().calls
        }

        fn transitions(&self) -> usize {
            self.inner.lock().unwrap().transitions
        }

        fn mutate_once(&self, mutation: RuntimeMutation) {
            self.inner.lock().unwrap().mutation = Some(mutation);
        }

        fn lose_result_after_apply_once(&self) {
            self.inner.lock().unwrap().lose_result_after_apply = true;
        }

        fn evidence_calls(&self) -> usize {
            self.inner.lock().unwrap().evidence_calls
        }

        fn lose_result_after_evidence_once(&self) {
            self.inner.lock().unwrap().lose_result_after_evidence = true;
        }

        fn mutate_evidence_once(&self, mutation: EvidenceMutation) {
            self.inner.lock().unwrap().evidence_mutation = Some(mutation);
        }
    }

    impl PrivateControlRuntimeApplicationAdapter for FakeRuntime {
        type Error = TestError;

        fn apply(
            &mut self,
            request: &PrivateControlRuntimeApplicationRequest,
        ) -> Result<PrivateControlRuntimeApplicationResult, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            state.calls += 1;
            let fact = if let Some((_, fact)) = state
                .retained
                .iter()
                .find(|(retained, _)| retained == request)
            {
                fact.clone()
            } else {
                let control =
                    PrivateControlRecord::decode(&request.control).map_err(|_| TestError)?;
                let application = application_fact(request.route, &control, request.applied_at);
                let fact = encode_private_application_fact(&application);
                state.transitions += 1;
                state.retained.push((request.clone(), fact.clone()));
                fact
            };
            if state.lose_result_after_apply {
                state.lose_result_after_apply = false;
                return Err(TestError);
            }
            let mut result = PrivateControlRuntimeApplicationResult {
                route: request.route,
                authority: request.authority,
                control: request.control.clone(),
                receipt: request.receipt.clone(),
                issuance_ack: request.issuance_ack.clone(),
                applied_at: request.applied_at,
                authenticated: true,
                durably_applied: true,
                durably_reopened: true,
                application_fact: fact,
            };
            match state.mutation.take() {
                None => {}
                Some(RuntimeMutation::Route) => result.route.agent = AgentId(id(0xd1, 1)),
                Some(RuntimeMutation::Authority) => {
                    result.authority.system_agent = AgentId(id(0xd2, 1))
                }
                Some(RuntimeMutation::Control) => result.control.push(0),
                Some(RuntimeMutation::Receipt) => result.receipt.push(0),
                Some(RuntimeMutation::Issuance) => result.issuance_ack.push(0),
                Some(RuntimeMutation::Slot) => result.applied_at += 1,
                Some(RuntimeMutation::Unauthenticated) => result.authenticated = false,
                Some(RuntimeMutation::NotApplied) => result.durably_applied = false,
                Some(RuntimeMutation::NotReopened) => result.durably_reopened = false,
                Some(RuntimeMutation::MalformedFact) => result.application_fact = vec![1, 2, 3],
                Some(RuntimeMutation::NonCanonicalFact) => result.application_fact.push(0),
                Some(RuntimeMutation::OversizeFact) => {
                    result.application_fact =
                        vec![0; MAX_PRIVATE_CONTROL_APPLICATION_FACT_WIRE_BYTES + 1]
                }
                Some(RuntimeMutation::FactRoute) => {
                    let mut fact =
                        decode_private_application_fact(&result.application_fact).unwrap();
                    fact.managed.agent = AgentId(id(0xd3, 1));
                    result.application_fact = encode_private_application_fact(&fact);
                }
                Some(RuntimeMutation::FactControl) => {
                    let mut fact =
                        decode_private_application_fact(&result.application_fact).unwrap();
                    fact.control = Hash(id(0xd4, 1));
                    fact.reopened_control_head = fact.control;
                    result.application_fact = encode_private_application_fact(&fact);
                }
                Some(RuntimeMutation::FactSlot) => {
                    let mut fact =
                        decode_private_application_fact(&result.application_fact).unwrap();
                    fact.applied_at += 1;
                    result.application_fact = encode_private_application_fact(&fact);
                }
            }
            Ok(result)
        }

        fn persist_completed_evidence(
            &mut self,
            request: &PrivateControlRuntimeEvidenceRequest,
        ) -> Result<PrivateControlRuntimeEvidenceResult, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            state.evidence_calls += 1;
            let issuance = AuthorityOperationIssuanceAck::decode(&request.issuance_ack)
                .map_err(|_| TestError)?;
            let application = PrivateControlApplicationAck::decode(&request.application_ack)
                .map_err(|_| TestError)?;
            let recovery_proof = request
                .recovery_proof
                .as_deref()
                .map(PrivateRecoveryAuthorityProof::decode)
                .transpose()
                .map_err(|_| TestError)?;
            let commitment = PrivateControlAuthorityEvidence::from_acknowledgements(
                &issuance,
                &application,
                recovery_proof.as_ref(),
            )
            .and_then(|evidence| evidence.commitment())
            .map_err(|_| TestError)?;
            match state
                .retained_evidence
                .iter()
                .find(|(retained, _)| retained == request)
            {
                Some((_, retained)) if *retained != commitment => return Err(TestError),
                Some(_) => {}
                None => state.retained_evidence.push((request.clone(), commitment)),
            }
            if state.lose_result_after_evidence {
                state.lose_result_after_evidence = false;
                return Err(TestError);
            }
            let mut result = PrivateControlRuntimeEvidenceResult {
                route: request.route,
                authority: request.authority,
                control: request.control.clone(),
                issuance_ack: request.issuance_ack.clone(),
                application_ack: request.application_ack.clone(),
                recovery_proof: request.recovery_proof.clone(),
                evidence_commitment: commitment,
                authenticated: true,
                durably_persisted: true,
                durably_reopened: true,
            };
            match state.evidence_mutation.take() {
                None => {}
                Some(EvidenceMutation::Route) => result.route.agent = AgentId(id(0xd5, 1)),
                Some(EvidenceMutation::Authority) => {
                    result.authority.system_agent = AgentId(id(0xd6, 1))
                }
                Some(EvidenceMutation::Control) => result.control.push(0),
                Some(EvidenceMutation::Issuance) => result.issuance_ack.push(0),
                Some(EvidenceMutation::Application) => result.application_ack.push(0),
                Some(EvidenceMutation::Commitment) => {
                    result.evidence_commitment = Hash(id(0xd7, 1))
                }
                Some(EvidenceMutation::Unauthenticated) => result.authenticated = false,
                Some(EvidenceMutation::NotPersisted) => result.durably_persisted = false,
                Some(EvidenceMutation::NotReopened) => result.durably_reopened = false,
            }
            Ok(result)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ActorMutation {
        Target,
        Method,
        Context,
        Request,
        Unauthenticated,
        NotDurable,
        False,
        WrongType,
        Malformed,
        NonCanonical,
        Oversize,
    }

    #[derive(Clone, Debug, Default)]
    struct FakeAuthorityActor {
        inner: Arc<Mutex<FakeAuthorityState>>,
    }

    #[derive(Debug, Default)]
    struct FakeAuthorityState {
        calls: usize,
        pending: Vec<PendingActorOperation>,
        tombstones: Vec<Vec<u8>>,
        mutation: Option<ActorMutation>,
        lose_result_after_consume: bool,
    }

    #[derive(Clone, Debug)]
    struct PendingActorOperation {
        call: AuthorityOperationCall,
        approval: AuthorityOperationApproval,
        issuance: AuthorityOperationIssuanceAck,
    }

    impl FakeAuthorityActor {
        fn register(
            &self,
            call: AuthorityOperationCall,
            approval: AuthorityOperationApproval,
            issuance: AuthorityOperationIssuanceAck,
        ) {
            self.inner
                .lock()
                .unwrap()
                .pending
                .push(PendingActorOperation {
                    call,
                    approval,
                    issuance,
                });
        }

        fn calls(&self) -> usize {
            self.inner.lock().unwrap().calls
        }

        fn pending(&self) -> usize {
            self.inner.lock().unwrap().pending.len()
        }

        fn tombstones(&self) -> usize {
            self.inner.lock().unwrap().tombstones.len()
        }

        fn mutate_once(&self, mutation: ActorMutation) {
            self.inner.lock().unwrap().mutation = Some(mutation);
        }

        fn lose_result_after_consume_once(&self) {
            self.inner.lock().unwrap().lose_result_after_consume = true;
        }
    }

    impl PrivateApplicationAuthorityDispatcher for FakeAuthorityActor {
        type Error = TestError;

        fn dispatch(
            &mut self,
            request: &PrivateApplicationAuthorityDispatch,
        ) -> Result<PrivateApplicationAuthorityResult, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            state.calls += 1;
            let mut accepted = false;
            if request.method == PrivateApplicationAuthorityMethod::AcknowledgePrivateApplication {
                if state.tombstones.contains(&request.request) {
                    accepted = true;
                } else if let Ok(acknowledgement) =
                    PrivateControlApplicationAck::decode(&request.request)
                {
                    if let Some(index) = state.pending.iter().position(|pending| {
                        acknowledgement.authorization_invocation == pending.call.invocation
                            && acknowledgement.matches_invocation_context(&request.context)
                            && acknowledgement
                                .verify_pending_with(
                                    &pending.call,
                                    &pending.approval,
                                    &pending.issuance,
                                    &acknowledgement.application,
                                    request.target.binding,
                                    &RawEd25519Verifier,
                                )
                                .is_ok()
                    }) {
                        state.pending.remove(index);
                        state.tombstones.push(request.request.clone());
                        accepted = true;
                    }
                }
            }
            if accepted && state.lose_result_after_consume {
                state.lose_result_after_consume = false;
                return Err(TestError);
            }
            let mut result = PrivateApplicationAuthorityResult {
                target: request.target,
                method: request.method,
                context: request.context,
                request: request.request.clone(),
                authenticated: true,
                durable: true,
                reply: crate::Encode::encode(&crate::value::Value::Bool(accepted)),
            };
            match state.mutation.take() {
                None => {}
                Some(ActorMutation::Target) => result.target.system_agent = AgentId(id(0xe1, 1)),
                Some(ActorMutation::Method) => {
                    result.method = PrivateApplicationAuthorityMethod::Unexpected
                }
                Some(ActorMutation::Context) => result.context.observed_slot += 1,
                Some(ActorMutation::Request) => result.request.push(0),
                Some(ActorMutation::Unauthenticated) => result.authenticated = false,
                Some(ActorMutation::NotDurable) => result.durable = false,
                Some(ActorMutation::False) => {
                    result.reply = crate::Encode::encode(&crate::value::Value::Bool(false))
                }
                Some(ActorMutation::WrongType) => {
                    result.reply = crate::Encode::encode(&crate::value::Value::Bytes(vec![1]))
                }
                Some(ActorMutation::Malformed) => result.reply = vec![0xff],
                Some(ActorMutation::NonCanonical) => result.reply.push(0),
                Some(ActorMutation::Oversize) => {
                    result.reply = vec![0; crate::agent::sdk::MAX_INVOCATION_REPLY_BYTES + 1]
                }
            }
            Ok(result)
        }
    }

    struct Fixture {
        authority: AuthorityActorTarget,
        credential_key: SigningKey,
    }

    impl Fixture {
        fn new(signer: &CountingSigner) -> Self {
            let public_key = signer.public_key();
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

        fn control(&self, discriminator: u64) -> PrivateControlRecord {
            private_control(self.authority.space, discriminator)
        }

        fn approved(
            &self,
            discriminator: u64,
            sequence: u64,
            control: &PrivateControlRecord,
        ) -> (AuthorityOperationCall, AuthorityOperationApproval) {
            let intent = AuthorityOperationIntent::private_control(
                DeploymentId(id(0x32, discriminator)),
                control,
            )
            .unwrap();
            self.approved_intent(discriminator, sequence, intent)
        }

        fn approved_intent(
            &self,
            discriminator: u64,
            sequence: u64,
            intent: AuthorityOperationIntent,
        ) -> (AuthorityOperationCall, AuthorityOperationApproval) {
            let public_key = self.credential_key.verifying_key().to_bytes();
            let principal = PrincipalId(id(0x22, 1));
            let credential = CredentialId::of_public_key(&public_key);
            let mut call = AuthorityOperationCall {
                invocation: InvocationId::ZERO,
                authority: self.authority,
                principal,
                credential,
                request_sequence: core::num::NonZeroU64::new(discriminator).unwrap(),
                credential_public_key: public_key,
                authenticated_node: Some(NodeId(id(0x23, 1))),
                requested_valid_from: 10,
                requested_expires_at: 40,
                intent,
                signature: [0; CREDENTIAL_SIGNATURE_BYTES],
            };
            call.invocation = call.expected_invocation();
            call.signature = self.credential_key.sign(&call.signing_bytes()).to_bytes();
            let approval = AuthorityOperationApproval::from_call(
                &call,
                core::num::NonZeroU64::new(sequence).unwrap(),
                AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash(id(0x33, discriminator)),
                },
                AuthorityLaneRoots {
                    control: Some(Hash(id(0x34, discriminator))),
                    linear: Some(Hash(id(0x35, discriminator))),
                    merge: None,
                    local: None,
                },
                3,
                12,
                38,
            )
            .unwrap();
            (call, approval)
        }
    }

    type TestIssuer = DurableAuthorityOperationIssuer<MemoryImageStore>;
    type TestCoordinator = DurablePrivateControlApplicationCoordinator<
        FakeRuntime,
        FakeAuthorityActor,
        MemoryImageStore,
        MemoryImageStore,
    >;

    struct Prepared {
        fixture: Fixture,
        signer: CountingSigner,
        issuer_store: MemoryImageStore,
        issuer: TestIssuer,
        actor: FakeAuthorityActor,
        call: AuthorityOperationCall,
        control: PrivateControlRecord,
    }

    fn prepare(discriminator: u64) -> Prepared {
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let control = fixture.control(discriminator);
        let (call, approval) = fixture.approved(discriminator, discriminator, &control);
        let issuer_store = MemoryImageStore::default();
        let mut issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        let issued = issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        let actor = FakeAuthorityActor::default();
        actor.register(call.clone(), approval, issued.issuance_ack);
        Prepared {
            fixture,
            signer,
            issuer_store,
            issuer,
            actor,
            call,
            control,
        }
    }

    fn prepare_recovery(discriminator: u64) -> Prepared {
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (control, recovery_key) =
            private_recovery_control(fixture.authority.space, discriminator);
        let runtime_deployment = DeploymentId(id(0x32, discriminator));
        let proof = PrivateRecoveryAuthorityProof::from_control(
            runtime_deployment,
            &control,
            control.previous,
            &recovery_key,
        )
        .unwrap();
        let (call, approval) = fixture.approved_intent(
            discriminator,
            discriminator,
            AuthorityOperationIntent::RecoverPrivateAgent { proof },
        );
        let issuer_store = MemoryImageStore::default();
        let mut issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        let issued = issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        let actor = FakeAuthorityActor::default();
        actor.register(call.clone(), approval, issued.issuance_ack);
        Prepared {
            fixture,
            signer,
            issuer_store,
            issuer,
            actor,
            call,
            control,
        }
    }

    fn open_coordinator(
        store: MemoryImageStore,
        runtime: FakeRuntime,
        actor: FakeAuthorityActor,
        issuer: TestIssuer,
        authority: AuthorityActorTarget,
    ) -> TestCoordinator {
        DurablePrivateControlApplicationCoordinator::open(store, authority, runtime, actor, issuer)
            .unwrap()
    }

    fn restart(coordinator: TestCoordinator, authority: AuthorityActorTarget) -> TestCoordinator {
        let (store, runtime, actor, issuer) = coordinator.into_parts();
        let issuer = DurableAuthorityOperationIssuer::open(issuer.into_store(), authority).unwrap();
        open_coordinator(store, runtime, actor, issuer, authority)
    }

    fn id(prefix: u8, number: u64) -> [u8; 32] {
        let mut bytes = [prefix; 32];
        bytes[24..].copy_from_slice(&number.to_le_bytes());
        bytes
    }

    fn private_control(space: SpaceId, discriminator: u64) -> PrivateControlRecord {
        let transport_identity = discriminator.to_le_bytes().to_vec();
        let node = NodeId::of_authenticated_peer(&transport_identity);
        let encryption_public_key = id(0x41, discriminator);
        let identity = PrivateNodeIdentity {
            node,
            principal: PrincipalId(id(0x42, discriminator)),
            transport_identity,
            encryption_public_key,
            authority_binding: Hash(id(0x43, discriminator)),
            transport_signature: [0x44; PRIVATE_SIGNATURE_BYTES],
        };
        let mut control = PrivateControlRecord {
            space,
            agent: AgentId(id(0x45, discriminator)),
            sequence: 1,
            previous: Some(Hash(id(0x46, discriminator))),
            operation: PrivateControlOperation::Invite {
                node: identity,
                epoch: 2,
                sealed_owner_key: SealedPrivateKey {
                    node,
                    recipient_key: encryption_public_key,
                    sealed: vec![0x47; 48],
                },
                sealed_data_key: SealedPrivateKey {
                    node,
                    recipient_key: encryption_public_key,
                    sealed: vec![0x48; 48],
                },
                historical_grants: Vec::new(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; PRIVATE_SIGNATURE_BYTES],
        };
        let key = SigningKey::from_bytes(&id(0x49, discriminator));
        control.signer_public_key = key.verifying_key().to_bytes();
        control.signature = [1; PRIVATE_SIGNATURE_BYTES];
        assert!(control.validate_shape());
        control.signature = key.sign(&control.signing_bytes()).to_bytes();
        control
    }

    fn private_recovery_control(
        space: SpaceId,
        discriminator: u64,
    ) -> (PrivateControlRecord, RecoverySigningKey) {
        let agent = AgentId(id(0x45, discriminator));
        let transport_identity = discriminator.to_le_bytes().to_vec();
        let node = NodeId::of_authenticated_peer(&transport_identity);
        let encryption_public_key = id(0x51, discriminator);
        let identity = PrivateNodeIdentity {
            node,
            principal: PrincipalId(id(0x52, discriminator)),
            transport_identity,
            encryption_public_key,
            authority_binding: Hash(id(0x53, discriminator)),
            transport_signature: [0x54; PRIVATE_SIGNATURE_BYTES],
        };
        let sealed = SealedPrivateKey {
            node,
            recipient_key: encryption_public_key,
            sealed: vec![0x55; 48],
        };
        let next_epoch = PrivateKeyEpoch {
            space,
            agent,
            epoch: 2,
            owner_key_commitment: Hash(id(0x56, discriminator)),
            data_key_commitment: Hash(id(0x57, discriminator)),
            recovery_key_commitment: Hash(id(0x58, discriminator)),
            recovery_encryption_public_key: id(0x59, discriminator),
            sealed_recovery_data_key: SealedRecoveryKey {
                recipient_key: id(0x59, discriminator),
                sealed: vec![0x5a; 48],
            },
            sealed_owner_keys: vec![sealed.clone()],
            sealed_data_keys: vec![sealed.clone()],
        };
        let historical_keyring = PrivateRecoveryKeyringGrant {
            key_commitment: Hash(id(0x5b, discriminator)),
            sealed_keys: vec![sealed],
            ciphertext: EncryptedPrivateObject {
                space,
                agent,
                epoch: 2,
                kind: EncryptedObjectKind::Control,
                content: Hash(id(0x5c, discriminator)),
                nonce: [0x5d; 24],
                ciphertext: vec![0x5e; 48],
            },
        };
        let recovery_key = RecoverySigningKey::from_seed(id(0x5f, discriminator)).unwrap();
        let previous = Hash(id(0x60, discriminator));
        let mut control = PrivateControlRecord {
            space,
            agent,
            sequence: 1,
            previous: Some(previous),
            operation: PrivateControlOperation::Recover {
                superseded_heads: vec![previous],
                next_epoch,
                replacement_nodes: vec![identity],
                historical_keyring,
            },
            signer: PrivateControlSigner::Recovery,
            signer_public_key: [0; 32],
            signature: [0; PRIVATE_SIGNATURE_BYTES],
        };
        sign_recovery_control_record(&mut control, &recovery_key).unwrap();
        assert!(control.validate_shape());
        (control, recovery_key)
    }

    fn application_fact(
        route: ManagedAgentTarget,
        control: &PrivateControlRecord,
        applied_at: u64,
    ) -> PrivateControlApplicationFact {
        let (operation, epoch, post_member_set) = match &control.operation {
            PrivateControlOperation::Invite { epoch, .. } => (
                AuthorityOperationKind::InvitePrivateNode,
                *epoch,
                Hash::digest(
                    b"vos/test/private-post-member-set/v1",
                    &[control.commitment().as_bytes()],
                ),
            ),
            PrivateControlOperation::Recover {
                next_epoch,
                replacement_nodes,
                ..
            } => (
                AuthorityOperationKind::RecoverPrivateAgent,
                next_epoch.epoch,
                crate::agent::sdk::authority_operation::private_member_set_commitment(
                    replacement_nodes.iter().map(|node| node.node),
                )
                .unwrap(),
            ),
            _ => panic!("private coordinator fixture"),
        };
        PrivateControlApplicationFact {
            managed: route,
            operation,
            control: control.commitment(),
            control_sequence: control.sequence,
            control_previous: control.previous,
            epoch,
            post_member_set,
            reopened_control_state: Hash::digest(
                b"vos/test/private-reopened-state/v1",
                &[control.commitment().as_bytes(), &applied_at.to_le_bytes()],
            ),
            reopened_control_head: control.commitment(),
            applied_at,
        }
    }

    fn control_wire(prepared: &Prepared) -> Vec<u8> {
        prepared.control.encode().unwrap()
    }

    #[test]
    fn exact_retry_and_restart_return_identical_pca_without_redispatch_or_resign() {
        let mut prepared = prepare(1);
        let coordinator_store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            coordinator_store.clone(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        assert_eq!(
            PrivateApplicationAuthorityMethod::AcknowledgePrivateApplication.name(),
            "acknowledge_private_application"
        );
        let acknowledgement = coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        let acknowledgement_wire = acknowledgement.encode().unwrap();
        assert_eq!(coordinator_store.commits(), 3);
        assert_eq!(prepared.issuer_store.commits(), 5);
        assert_eq!(
            (
                runtime.calls(),
                runtime.transitions(),
                runtime.evidence_calls()
            ),
            (1, 1, 1)
        );
        assert_eq!(
            (actor.calls(), actor.pending(), actor.tombstones()),
            (1, 0, 1)
        );
        assert_eq!(prepared.signer.application_calls, 1);

        let mut unusable = CountingSigner::new(0x72);
        unusable.fail_application = true;
        assert_eq!(
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut unusable)
                .unwrap()
                .encode()
                .unwrap(),
            acknowledgement_wire
        );
        assert_eq!(unusable.application_calls, 0);
        assert_eq!(
            (runtime.calls(), runtime.evidence_calls(), actor.calls()),
            (1, 1, 1)
        );

        let mut coordinator = restart(coordinator, authority);
        assert_eq!(
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut unusable)
                .unwrap()
                .encode()
                .unwrap(),
            acknowledgement_wire
        );
        assert_eq!(unusable.application_calls, 0);
        assert_eq!(
            (runtime.calls(), runtime.evidence_calls(), actor.calls()),
            (1, 1, 1)
        );
        assert_eq!(coordinator.retained_applications(), 1);
        assert!(!coordinator.has_pending_application());
    }

    #[test]
    fn retained_recover_intent_matches_exact_control_and_carries_pra_to_evidence() {
        let mut prepared = prepare_recovery(14);
        let AuthorityOperationIntent::RecoverPrivateAgent { proof } = &prepared.call.intent else {
            panic!("recovery fixture did not retain RecoverPrivateAgent intent")
        };
        assert!(proof.matches_control(&prepared.control));
        let exact_proof = proof.encode().unwrap();
        let store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            store,
            runtime.clone(),
            prepared.actor.clone(),
            prepared.issuer,
            authority,
        );

        let acknowledgement = coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert_eq!(
            (
                runtime.calls(),
                runtime.transitions(),
                runtime.evidence_calls()
            ),
            (1, 1, 1)
        );
        let retained_proof = runtime.inner.lock().unwrap().retained_evidence[0]
            .0
            .recovery_proof
            .clone();
        assert_eq!(retained_proof.as_deref(), Some(exact_proof.as_slice()));

        let mut coordinator = restart(coordinator, authority);
        let retry = coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert_eq!(retry, acknowledgement);
        assert_eq!(
            (
                runtime.calls(),
                runtime.transitions(),
                runtime.evidence_calls()
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn lost_runtime_result_is_exactly_redispatched_after_restart() {
        let mut prepared = prepare(1);
        let store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        runtime.lose_result_after_apply_once();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            store,
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
            Err(PrivateControlApplicationCoordinatorError::Runtime(
                TestError
            ))
        ));
        assert!(!coordinator.is_poisoned());
        assert_eq!((runtime.calls(), runtime.transitions()), (1, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (0, 0));

        let mut coordinator = restart(coordinator, authority);
        coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert_eq!((runtime.calls(), runtime.transitions()), (2, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (1, 1));
    }

    #[test]
    fn lost_actor_result_retries_identical_pca_against_tombstone() {
        let mut prepared = prepare(1);
        let store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        actor.lose_result_after_consume_once();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            store,
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
            Err(PrivateControlApplicationCoordinatorError::Dispatch(
                TestError
            ))
        ));
        assert_eq!((runtime.calls(), runtime.transitions()), (1, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (1, 1));
        assert_eq!((actor.pending(), actor.tombstones()), (0, 1));

        let mut coordinator = restart(coordinator, authority);
        let acknowledgement = coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert!(
            acknowledgement
                .verify_with(authority.binding, &RawEd25519Verifier)
                .is_ok()
        );
        assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
        assert_eq!(
            (actor.calls(), actor.pending(), actor.tombstones()),
            (2, 0, 1)
        );
    }

    #[test]
    fn lost_evidence_attachment_result_is_exactly_redispatched_after_restart() {
        let mut prepared = prepare(1);
        let store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        runtime.lose_result_after_evidence_once();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            store,
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
            Err(PrivateControlApplicationCoordinatorError::Runtime(
                TestError
            ))
        ));
        assert!(!coordinator.is_poisoned());
        assert!(coordinator.has_pending_application());
        assert_eq!(
            (
                runtime.calls(),
                runtime.transitions(),
                runtime.evidence_calls(),
                actor.calls(),
                actor.tombstones(),
                prepared.signer.application_calls,
            ),
            (1, 1, 1, 1, 1, 1)
        );

        let mut coordinator = restart(coordinator, authority);
        let acknowledgement = coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert!(
            acknowledgement
                .verify_with(authority.binding, &RawEd25519Verifier)
                .is_ok()
        );
        assert_eq!(
            (
                runtime.calls(),
                runtime.transitions(),
                runtime.evidence_calls(),
                actor.calls(),
                prepared.signer.application_calls,
            ),
            (1, 1, 2, 1, 1)
        );
        assert!(!coordinator.has_pending_application());

        // A fully committed retry returns the exact retained PCA1 without
        // touching the runtime, actor, or signer again.
        coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert_eq!((runtime.evidence_calls(), actor.calls()), (2, 1));
        assert_eq!(prepared.signer.application_calls, 1);
    }

    #[test]
    fn hostile_evidence_attachment_echoes_and_durability_flags_are_rejected() {
        for (index, mutation) in [
            EvidenceMutation::Route,
            EvidenceMutation::Authority,
            EvidenceMutation::Control,
            EvidenceMutation::Issuance,
            EvidenceMutation::Application,
            EvidenceMutation::Commitment,
            EvidenceMutation::Unauthenticated,
            EvidenceMutation::NotPersisted,
            EvidenceMutation::NotReopened,
        ]
        .into_iter()
        .enumerate()
        {
            let mut prepared = prepare(index as u64 + 1);
            let store = MemoryImageStore::default();
            let runtime = FakeRuntime::default();
            runtime.mutate_evidence_once(mutation);
            let actor = prepared.actor.clone();
            let authority = prepared.fixture.authority;
            let wire = control_wire(&prepared);
            let mut coordinator = open_coordinator(
                store,
                runtime.clone(),
                actor.clone(),
                prepared.issuer,
                authority,
            );
            assert!(matches!(
                coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidEvidenceResult
                ))
            ));
            assert!(coordinator.has_pending_application());
            assert_eq!(
                (
                    runtime.calls(),
                    runtime.transitions(),
                    runtime.evidence_calls(),
                    actor.calls(),
                    actor.tombstones(),
                    prepared.signer.application_calls,
                ),
                (1, 1, 1, 1, 1, 1),
                "mutation {mutation:?}"
            );
        }
    }

    #[test]
    fn coordinator_commit_failpoints_poison_and_reconcile_before_or_after() {
        for fail_after in [false, true] {
            let mut prepared = prepare(1);
            let store = MemoryImageStore::default();
            if fail_after {
                store.fail_after_commit(1);
            } else {
                store.fail_before_commit(1);
            }
            let runtime = FakeRuntime::default();
            let actor = prepared.actor.clone();
            let authority = prepared.fixture.authority;
            let wire = control_wire(&prepared);
            let mut coordinator =
                open_coordinator(store, runtime.clone(), actor, prepared.issuer, authority);
            assert!(matches!(
                coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                Err(PrivateControlApplicationCoordinatorError::Storage(
                    TestError
                ))
            ));
            assert!(coordinator.is_poisoned());
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (0, 0));
            let mut coordinator = restart(coordinator, authority);
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
                .unwrap();
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
        }

        for fail_after in [false, true] {
            let mut prepared = prepare(1);
            let store = MemoryImageStore::default();
            if fail_after {
                store.fail_after_commit(2);
            } else {
                store.fail_before_commit(2);
            }
            let runtime = FakeRuntime::default();
            let actor = prepared.actor.clone();
            let authority = prepared.fixture.authority;
            let wire = control_wire(&prepared);
            let mut coordinator = open_coordinator(
                store,
                runtime.clone(),
                actor.clone(),
                prepared.issuer,
                authority,
            );
            assert!(matches!(
                coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                Err(PrivateControlApplicationCoordinatorError::Storage(
                    TestError
                ))
            ));
            assert!(coordinator.is_poisoned());
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!(actor.calls(), 1);
            let mut coordinator = restart(coordinator, authority);
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
                .unwrap();
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!(actor.calls(), if fail_after { 1 } else { 2 });
        }

        // The third coordinator commit records that the exact PSE2 was
        // durably attached and reopened. Before/after ambiguity must poison
        // the current handle; restart either re-drives the exact callback or
        // trusts the already committed marker without re-signing.
        for fail_after in [false, true] {
            let mut prepared = prepare(1);
            let store = MemoryImageStore::default();
            if fail_after {
                store.fail_after_commit(3);
            } else {
                store.fail_before_commit(3);
            }
            let runtime = FakeRuntime::default();
            let actor = prepared.actor.clone();
            let authority = prepared.fixture.authority;
            let wire = control_wire(&prepared);
            let mut coordinator = open_coordinator(
                store,
                runtime.clone(),
                actor.clone(),
                prepared.issuer,
                authority,
            );
            assert!(matches!(
                coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                Err(PrivateControlApplicationCoordinatorError::Storage(
                    TestError
                ))
            ));
            assert!(coordinator.is_poisoned());
            assert_eq!(
                (
                    runtime.calls(),
                    runtime.transitions(),
                    runtime.evidence_calls(),
                    actor.calls(),
                    prepared.signer.application_calls,
                ),
                (1, 1, 1, 1, 1)
            );
            let mut coordinator = restart(coordinator, authority);
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
                .unwrap();
            assert_eq!(runtime.evidence_calls(), if fail_after { 1 } else { 2 });
            assert_eq!((runtime.calls(), actor.calls()), (1, 1));
            assert_eq!(prepared.signer.application_calls, 1);
        }
    }

    #[test]
    fn issuer_commit_and_sign_failpoints_resume_without_reapplying() {
        for boundary in [1usize, 2] {
            for fail_after in [false, true] {
                let mut prepared = prepare(1);
                if fail_after {
                    prepared.issuer_store.fail_after_commit(boundary);
                } else {
                    prepared.issuer_store.fail_before_commit(boundary);
                }
                let store = MemoryImageStore::default();
                let runtime = FakeRuntime::default();
                let actor = prepared.actor.clone();
                let authority = prepared.fixture.authority;
                let wire = control_wire(&prepared);
                let mut coordinator = open_coordinator(
                    store,
                    runtime.clone(),
                    actor.clone(),
                    prepared.issuer,
                    authority,
                );
                assert!(matches!(
                    coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                    Err(PrivateControlApplicationCoordinatorError::Issuer(
                        AuthorityOperationIssuerError::Storage(TestError)
                    ))
                ));
                assert!(coordinator.is_poisoned());
                assert_eq!(runtime.transitions(), 1);
                let calls_before = runtime.calls();
                let signs_before = prepared.signer.application_calls;
                let mut coordinator = restart(coordinator, authority);
                coordinator
                    .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
                    .unwrap();
                let expected_runtime_calls = if boundary == 1 && !fail_after {
                    calls_before + 1
                } else {
                    calls_before
                };
                assert_eq!(runtime.calls(), expected_runtime_calls);
                let expected_signs = if boundary == 2 && !fail_after {
                    signs_before + 1
                } else if boundary == 1 {
                    signs_before + 1
                } else {
                    signs_before
                };
                assert_eq!(prepared.signer.application_calls, expected_signs);
                assert_eq!(actor.calls(), 1);
            }
        }

        let mut prepared = prepare(1);
        prepared.signer.fail_application = true;
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            MemoryImageStore::default(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
            Err(PrivateControlApplicationCoordinatorError::Issuer(
                AuthorityOperationIssuerError::Signer(TestError)
            ))
        ));
        assert!(!coordinator.is_poisoned());
        coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert_eq!((runtime.calls(), runtime.transitions()), (1, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (2, 1));

        let mut prepared = prepare(2);
        prepared.signer.corrupt_application = true;
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            MemoryImageStore::default(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
            Err(PrivateControlApplicationCoordinatorError::Issuer(
                AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::WrongSigner
                )
            ))
        ));
        assert!(!coordinator.is_poisoned());
        assert_eq!(
            (runtime.calls(), runtime.transitions(), actor.calls()),
            (1, 1, 0)
        );
        prepared.signer.corrupt_application = false;
        coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        assert_eq!((prepared.signer.application_calls, actor.calls()), (2, 1));
    }

    #[test]
    fn hostile_runtime_echoes_flags_and_bound_fact_fields_are_rejected() {
        let cases = [
            RuntimeMutation::Route,
            RuntimeMutation::Authority,
            RuntimeMutation::Control,
            RuntimeMutation::Receipt,
            RuntimeMutation::Issuance,
            RuntimeMutation::Slot,
            RuntimeMutation::Unauthenticated,
            RuntimeMutation::NotApplied,
            RuntimeMutation::NotReopened,
            RuntimeMutation::MalformedFact,
            RuntimeMutation::NonCanonicalFact,
            RuntimeMutation::OversizeFact,
            RuntimeMutation::FactRoute,
            RuntimeMutation::FactControl,
            RuntimeMutation::FactSlot,
        ];
        for mutation in cases {
            let mut prepared = prepare(1);
            let runtime = FakeRuntime::default();
            runtime.mutate_once(mutation);
            let actor = prepared.actor.clone();
            let authority = prepared.fixture.authority;
            let wire = control_wire(&prepared);
            let mut coordinator = open_coordinator(
                MemoryImageStore::default(),
                runtime.clone(),
                actor.clone(),
                prepared.issuer,
                authority,
            );
            assert!(
                matches!(
                    coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                    Err(PrivateControlApplicationCoordinatorError::Rejected(
                        PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult
                            | PrivateControlApplicationCoordinatorRejection::ApplicationRejected
                    ))
                ),
                "runtime mutation {mutation:?}"
            );
            assert_eq!((prepared.signer.application_calls, actor.calls()), (0, 0));
            // The trusted adapter's exact retry returns its durable unmodified
            // fact and can safely continue from the already pledged intent.
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
                .unwrap();
            assert_eq!(
                (runtime.transitions(), prepared.signer.application_calls),
                (1, 1)
            );
        }
    }

    #[test]
    fn hostile_authority_echoes_types_frames_and_negative_ack_are_rejected() {
        let cases = [
            ActorMutation::Target,
            ActorMutation::Method,
            ActorMutation::Context,
            ActorMutation::Request,
            ActorMutation::Unauthenticated,
            ActorMutation::NotDurable,
            ActorMutation::False,
            ActorMutation::WrongType,
            ActorMutation::Malformed,
            ActorMutation::NonCanonical,
            ActorMutation::Oversize,
        ];
        for mutation in cases {
            let mut prepared = prepare(1);
            let runtime = FakeRuntime::default();
            let actor = prepared.actor.clone();
            actor.mutate_once(mutation);
            let authority = prepared.fixture.authority;
            let wire = control_wire(&prepared);
            let mut coordinator = open_coordinator(
                MemoryImageStore::default(),
                runtime.clone(),
                actor.clone(),
                prepared.issuer,
                authority,
            );
            assert!(
                matches!(
                coordinator.apply(prepared.call.invocation, &wire, 24, &mut prepared.signer),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidAuthorityResult
                        | PrivateControlApplicationCoordinatorRejection::AcknowledgementRejected
                ))
            ),
                "actor mutation {mutation:?}"
            );
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!((actor.pending(), actor.tombstones()), (0, 1));
            // The fake deliberately no longer has pending AOC/AOP/AOI
            // preimages. Exact PCA tombstone retry is therefore required.
            coordinator
                .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
                .unwrap();
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!(actor.calls(), 2);
        }
    }

    #[test]
    fn control_intent_route_signature_slot_and_signer_substitutions_fail_before_apply() {
        let mut prepared = prepare(1);
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            MemoryImageStore::default(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );

        let mut noncanonical = wire.clone();
        noncanonical.push(0);
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &noncanonical,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl
            ))
        ));
        let oversized = vec![0; MAX_PRIVATE_CONTROL_WIRE_BYTES + 1];
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &oversized,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl
            ))
        ));

        let mut bad_signature = prepared.control.clone();
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &bad_signature.encode().unwrap(),
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControlSignature
            ))
        ));
        let substituted = prepared.fixture.control(2).encode().unwrap();
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &substituted,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl
            ))
        ));
        let mut wrong_route = prepared.control.clone();
        wrong_route.space = SpaceId(id(0xf1, 1));
        let key = SigningKey::from_bytes(&id(0x49, 1));
        wrong_route.signature = key.sign(&wrong_route.signing_bytes()).to_bytes();
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &wrong_route.encode().unwrap(),
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::WrongRoute
            ))
        ));
        for slot in [19, 39] {
            assert!(matches!(
                coordinator.apply(prepared.call.invocation, &wire, slot, &mut prepared.signer),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidApplicationSlot
                ))
            ));
        }
        let mut wrong_signer = CountingSigner::new(0x72);
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, 24, &mut wrong_signer),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::WrongSigner
            ))
        ));
        assert_eq!((runtime.calls(), actor.calls()), (0, 0));
    }

    #[test]
    fn divergent_retry_pending_serialization_and_application_clock_are_durable() {
        let mut prepared = prepare(1);
        let second_control = prepared.fixture.control(2);
        let (second_call, second_approval) = prepared.fixture.approved(2, 2, &second_control);
        let second_issued = prepared
            .issuer
            .issue(&second_call, &second_approval, 20, &mut prepared.signer)
            .unwrap();
        prepared.actor.register(
            second_call.clone(),
            second_approval,
            second_issued.issuance_ack,
        );
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let first_wire = control_wire(&prepared);
        let second_wire = second_control.encode().unwrap();
        let mut coordinator = open_coordinator(
            MemoryImageStore::default(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        coordinator
            .apply(
                prepared.call.invocation,
                &first_wire,
                25,
                &mut prepared.signer,
            )
            .unwrap();
        assert!(matches!(
            coordinator.apply(
                second_call.invocation,
                &second_wire,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::ApplicationSlotRegressed
            ))
        ));
        let mut coordinator = restart(coordinator, authority);
        assert!(matches!(
            coordinator.apply(
                second_call.invocation,
                &second_wire,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::ApplicationSlotRegressed
            ))
        ));
        coordinator
            .apply(
                second_call.invocation,
                &second_wire,
                25,
                &mut prepared.signer,
            )
            .unwrap();
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &first_wire,
                26,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::DivergentRetry
            ))
        ));

        let mut third = prepare(3);
        let pending_runtime = FakeRuntime::default();
        pending_runtime.lose_result_after_apply_once();
        let third_wire = control_wire(&third);
        let mut pending = open_coordinator(
            MemoryImageStore::default(),
            pending_runtime,
            third.actor.clone(),
            third.issuer,
            third.fixture.authority,
        );
        assert!(matches!(
            pending.apply(third.call.invocation, &third_wire, 24, &mut third.signer),
            Err(PrivateControlApplicationCoordinatorError::Runtime(
                TestError
            ))
        ));
        // A divergent authorization identity cannot reuse the pending slot.
        assert!(matches!(
            pending.apply(
                InvocationId(id(0xfa, 1)),
                &third_wire,
                24,
                &mut third.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::MissingIssuance
            ))
        ));
    }

    #[test]
    fn corrupt_noncanonical_cross_store_and_wrong_route_images_fail_closed() {
        let mut prepared = prepare(1);
        let store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator =
            open_coordinator(store.clone(), runtime, actor, prepared.issuer, authority);
        coordinator
            .apply(prepared.call.invocation, &wire, 24, &mut prepared.signer)
            .unwrap();
        let (coordinator_store, runtime, actor, issuer) = coordinator.into_parts();
        let issuer_store = issuer.into_store();
        let valid = coordinator_store.image().unwrap();

        let mut old_magic = valid.clone();
        old_magic[..4].copy_from_slice(b"PAJ2");
        coordinator_store.replace_image(old_magic);
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                coordinator_store.clone(),
                authority,
                runtime.clone(),
                actor.clone(),
                reopened_issuer
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        let mut noncanonical = valid.clone();
        noncanonical.push(0);
        coordinator_store.replace_image(noncanonical);
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                coordinator_store.clone(),
                authority,
                runtime.clone(),
                actor.clone(),
                reopened_issuer
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        let mut image = PrivateControlApplicationCoordinatorImage::decode(&valid).unwrap();
        image.records[0].control[wire.len() - 1] ^= 1;
        coordinator_store.replace_image(image.encode());
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                coordinator_store.clone(),
                authority,
                runtime.clone(),
                actor.clone(),
                reopened_issuer
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        let mut image = PrivateControlApplicationCoordinatorImage::decode(&valid).unwrap();
        image.records[0].consumed_application_ack = Some(Hash(id(0xfb, 1)));
        coordinator_store.replace_image(image.encode());
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                coordinator_store.clone(),
                authority,
                runtime.clone(),
                actor.clone(),
                reopened_issuer
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        coordinator_store.replace_image(valid);
        let other_signer = CountingSigner::new(0x72);
        let other = Fixture::new(&other_signer);
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                coordinator_store.clone(),
                other.authority,
                runtime,
                actor,
                reopened_issuer
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        coordinator_store.fail_load();
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store, authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                coordinator_store,
                authority,
                FakeRuntime::default(),
                FakeAuthorityActor::default(),
                reopened_issuer
            ),
            Err(PrivateControlApplicationCoordinatorError::Storage(
                TestError
            ))
        ));
    }

    #[test]
    fn image_capacity_and_invocation_collisions_fail_closed() {
        let prepared = prepare(1);
        let control = control_wire(&prepared);
        let mut image =
            PrivateControlApplicationCoordinatorImage::empty(prepared.fixture.authority);
        for index in 0..MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS as u64 {
            image.records.push(ApplicationRecord {
                authorization_invocation: InvocationId(id(0xc1, index + 1)),
                application_invocation: InvocationId(id(0xc2, index + 1)),
                control: control.clone(),
                applied_at: 24,
                consumed_application_ack: Some(Hash(id(0xc3, index + 1))),
                persisted_authority_evidence: Some(Hash(id(0xc4, index + 1))),
            });
        }
        image.application_slot_high_water = Some(24);
        assert!(image.is_valid());
        image.records.push(ApplicationRecord {
            authorization_invocation: InvocationId(id(0xc1, 10_000)),
            application_invocation: InvocationId(id(0xc2, 10_000)),
            control: control.clone(),
            applied_at: 24,
            consumed_application_ack: Some(Hash(id(0xc3, 10_000))),
            persisted_authority_evidence: Some(Hash(id(0xc4, 10_000))),
        });
        assert!(!image.has_valid_envelope());
        image.records.pop();
        image.records[1].application_invocation = image.records[0].authorization_invocation;
        assert!(!image.is_valid());
        image.records[1].application_invocation = image.records[1].authorization_invocation;
        assert!(!image.has_valid_envelope());
    }
}
