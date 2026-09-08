//! Crash-safe host coordination for applying authority-approved Private controls.
//!
//! AOI1 proves receipt issuance, not application. This module first reopens the
//! exact issuer-retained AOC4/AOP4/AOI1 chain and reconstructs that AOC4 intent
//! from the supplied canonical PCTL. It then pledges the exact PCTL and logical
//! application slot before asking the configured Private runtime to apply it.
//! Only an authenticated result which echoes every request field and asserts a
//! durable apply *and* durable reopen can supply the application fact pledged
//! and signed by the issuer as PCA2. Finally, PCA2 is sent to the exact
//! system-authority actor under its derived third Linear invocation and the
//! exact acknowledgement is committed locally. Only then does the coordinator
//! ask the runtime to attach the retained canonical AOI1+PCA2 envelope to the
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
    PrivateControlApplicationRetirementAck,
};
use crate::agent::sdk::private::PrivateControlRecord;
use crate::agent::sdk::wire::{
    CanonicalWire, MAX_PRIVATE_CONTROL_WIRE_BYTES, MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES,
};
use crate::agent::sdk::{
    ActorId, AgentId, DeploymentId, Hash, InvocationContext, InvocationId, InvocationOrigin,
    InvocationRoleClaims, ManagementRequest, MethodMode, PrincipalId, PrivateRuntimeMutation,
    ProducerId, ProgramId, SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

pub(crate) const MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS: usize =
    super::authority_operation_issuer::MAX_AUTHORITY_OPERATION_ISSUER_RECORDS;
pub(crate) const MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_IMAGE_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_PRIVATE_CONTROL_APPLICATION_FACT_WIRE_BYTES: usize = 512;
const PRIVATE_CONTROL_APPLICATION_COORDINATOR_MAGIC: [u8; 4] = *b"PAJ4";
const PRIVATE_CONTROL_APPLICATION_FACT_MAGIC: [u8; 5] = *b"PCAF2";

/// Exact request to the trusted Private-runtime application boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlRuntimeApplicationRequest {
    pub(crate) route: ManagedAgentTarget,
    pub(crate) authority: AuthorityActorTarget,
    pub(crate) control: Vec<u8>,
    pub(crate) mutation: Option<Vec<u8>>,
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
    pub(crate) mutation: Option<Vec<u8>>,
    pub(crate) receipt: Vec<u8>,
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) applied_at: u64,
    pub(crate) authenticated: bool,
    pub(crate) durably_applied: bool,
    pub(crate) durably_reopened: bool,
    /// Exact commitment of the durably reopened PCRS3 aggregate.
    pub(crate) reopened_runtime_state: Hash,
    /// Exact commitment of the successor PSP1 stable projection.
    pub(crate) stable_projection: Hash,
    /// Canonical host-local PCAF2 frame, independently decoded below.
    pub(crate) application_fact: Vec<u8>,
}

/// Echoed result of an authenticated deterministic denial which durably
/// reopened the byte-identical predecessor. This deliberately has no field in
/// which a guest error, successor, or application fact could be retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateControlRuntimeRetirementResult {
    pub(crate) route: ManagedAgentTarget,
    pub(crate) authority: AuthorityActorTarget,
    pub(crate) control: Vec<u8>,
    pub(crate) mutation: Option<Vec<u8>>,
    pub(crate) receipt: Vec<u8>,
    pub(crate) issuance_ack: Vec<u8>,
    pub(crate) resolved_at: u64,
    pub(crate) authenticated: bool,
    pub(crate) predecessor_unchanged: bool,
    pub(crate) durably_reopened: bool,
}

/// The only two trusted outcomes which may cross the Private runtime boundary.
/// Adapter errors (including traps, exhaustion, I/O, malformed output, or a
/// changed predecessor) remain errors and cannot be relabelled as retirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrivateControlRuntimeApplicationResolution {
    Applied(PrivateControlRuntimeApplicationResult),
    RetiredUnapplied(PrivateControlRuntimeRetirementResult),
}

/// Canonical terminal acknowledgement retained for one coordinator lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrivateControlApplicationResolution {
    Applied(PrivateControlApplicationAck),
    RetiredUnapplied(PrivateControlApplicationRetirementAck),
}

impl PrivateControlApplicationResolution {
    fn invocation(&self) -> InvocationId {
        match self {
            Self::Applied(acknowledgement) => acknowledgement.application_invocation,
            Self::RetiredUnapplied(acknowledgement) => acknowledgement.application_invocation,
        }
    }

    fn resolved_at(&self) -> u64 {
        match self {
            Self::Applied(acknowledgement) => acknowledgement.application.applied_at,
            Self::RetiredUnapplied(acknowledgement) => acknowledgement.resolved_at,
        }
    }

    fn commitment(&self) -> Hash {
        match self {
            Self::Applied(acknowledgement) => acknowledgement.commitment(),
            Self::RetiredUnapplied(acknowledgement) => acknowledgement.commitment(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, crate::agent::sdk::wire::WireError> {
        match self {
            Self::Applied(acknowledgement) => acknowledgement.encode(),
            Self::RetiredUnapplied(acknowledgement) => acknowledgement.encode(),
        }
    }

    fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        match self {
            Self::Applied(acknowledgement) => acknowledgement.matches_invocation_context(context),
            Self::RetiredUnapplied(acknowledgement) => {
                acknowledgement.matches_invocation_context(context)
            }
        }
    }

    #[cfg(test)]
    fn verify_with<V: AuthorityVerifier>(
        &self,
        authority: AgentAuthorityBinding,
        verifier: &V,
    ) -> Result<(), crate::agent::sdk::authority_operation::AuthorityOperationProtocolError> {
        match self {
            Self::Applied(acknowledgement) => acknowledgement.verify_with(authority, verifier),
            Self::RetiredUnapplied(acknowledgement) => {
                acknowledgement.verify_with(authority, verifier)
            }
        }
    }
}

/// Exact post-completion evidence attachment request. This request is emitted
/// only after the coordinator has durably recorded authority consumption of
/// PCA2; it never asks the runtime to regenerate or re-sign either proof.
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
/// and PCA2 bytes after durable authority consumption and must atomically
/// attach, reopen, and echo that exact envelope.
pub(crate) trait PrivateControlRuntimeApplicationAdapter {
    type Error;

    fn apply(
        &mut self,
        request: &PrivateControlRuntimeApplicationRequest,
    ) -> Result<PrivateControlRuntimeApplicationResolution, Self::Error>;

    fn persist_completed_evidence(
        &mut self,
        request: &PrivateControlRuntimeEvidenceRequest,
    ) -> Result<PrivateControlRuntimeEvidenceResult, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PrivateApplicationAuthorityMethod {
    ResolvePrivateApplication = 0,
    /// Cannot be emitted by the coordinator; retained to let adapters report
    /// an accidentally substituted method as data which is then rejected.
    Unexpected = 1,
}

impl PrivateApplicationAuthorityMethod {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ResolvePrivateApplication => "resolve_private_application",
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

/// Trusted exact-route dispatcher for the system-authority PCA2/PAR1 method.
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
enum ApplicationRecordResolution {
    Pending,
    Applied {
        application_ack: Hash,
        actor_consumed: bool,
        persisted_authority_evidence: Option<Hash>,
    },
    RetiredUnapplied {
        retirement_ack: Hash,
        actor_consumed: bool,
    },
}

impl ApplicationRecordResolution {
    const fn is_fully_terminal(&self) -> bool {
        match self {
            Self::Pending => false,
            Self::Applied {
                actor_consumed,
                persisted_authority_evidence,
                ..
            } => *actor_consumed && persisted_authority_evidence.is_some(),
            Self::RetiredUnapplied { actor_consumed, .. } => *actor_consumed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApplicationRecord {
    authorization_invocation: InvocationId,
    application_invocation: InvocationId,
    control: Vec<u8>,
    mutation: Option<Vec<u8>>,
    resolved_at: u64,
    resolution: ApplicationRecordResolution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateControlApplicationCoordinatorImage {
    authority: AuthorityActorTarget,
    resolution_slot_high_water: Option<u64>,
    records: Vec<ApplicationRecord>,
}

impl PrivateControlApplicationCoordinatorImage {
    fn empty(authority: AuthorityActorTarget) -> Self {
        Self {
            authority,
            resolution_slot_high_water: None,
            records: Vec::new(),
        }
    }

    fn has_valid_envelope(&self) -> bool {
        self.authority.is_valid()
            && self.records.len() <= MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS
            && (self.records.is_empty() == self.resolution_slot_high_water.is_none())
            && self.records.last().map(|record| record.resolved_at)
                == self.resolution_slot_high_water
            && self.records.iter().all(|record| {
                record.control.len() <= MAX_PRIVATE_CONTROL_WIRE_BYTES
                    && record.mutation.as_ref().is_none_or(|mutation| {
                        mutation.len() <= MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES
                    })
                    && record.authorization_invocation != InvocationId::ZERO
                    && record.application_invocation != InvocationId::ZERO
                    && record.authorization_invocation != record.application_invocation
                    && match &record.resolution {
                        ApplicationRecordResolution::Pending => true,
                        ApplicationRecordResolution::Applied {
                            application_ack,
                            actor_consumed,
                            persisted_authority_evidence,
                        } => {
                            *application_ack != Hash::ZERO
                                && persisted_authority_evidence != &Some(Hash::ZERO)
                                && (persisted_authority_evidence.is_none() || *actor_consumed)
                        }
                        ApplicationRecordResolution::RetiredUnapplied {
                            retirement_ack, ..
                        } => *retirement_ack != Hash::ZERO,
                    }
            })
            && self.records.iter().enumerate().all(|(index, record)| {
                let is_last = index + 1 == self.records.len();
                is_last || record.resolution.is_fully_terminal()
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
                || !private_mutation_matches_control(&control, record.mutation.as_deref())
                || control.space != self.authority.space
                || prior_slot.is_some_and(|prior| prior > record.resolved_at)
                || !push_unique(&mut invocations, record.authorization_invocation)
                || !push_unique(&mut invocations, record.application_invocation)
            {
                return false;
            }
            prior_slot = Some(record.resolved_at);
        }
        true
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PRIVATE_CONTROL_APPLICATION_COORDINATOR_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        encode_authority_target(&mut encoder, self.authority);
        encoder.option(&self.resolution_slot_high_water, |encoder, slot| {
            encoder.u64(*slot)
        });
        encoder.list(&self.records, |encoder, record| {
            encoder.fixed(record.authorization_invocation.as_bytes());
            encoder.fixed(record.application_invocation.as_bytes());
            encoder.bytes(&record.control);
            encoder.option(&record.mutation, |encoder, mutation| {
                encoder.bytes(mutation)
            });
            encoder.u64(record.resolved_at);
            match &record.resolution {
                ApplicationRecordResolution::Pending => encoder.u8(0),
                ApplicationRecordResolution::Applied {
                    application_ack,
                    actor_consumed,
                    persisted_authority_evidence,
                } => {
                    encoder.u8(1);
                    encoder.fixed(application_ack.as_bytes());
                    encoder.u8(u8::from(*actor_consumed));
                    encoder.option(persisted_authority_evidence, |encoder, evidence| {
                        encoder.fixed(evidence.as_bytes())
                    });
                }
                ApplicationRecordResolution::RetiredUnapplied {
                    retirement_ack,
                    actor_consumed,
                } => {
                    encoder.u8(2);
                    encoder.fixed(retirement_ack.as_bytes());
                    encoder.u8(u8::from(*actor_consumed));
                }
            }
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
        let resolution_slot_high_water = decoder.option(Decoder::u64)?;
        let count = decoder.u32()? as usize;
        if count > MAX_PRIVATE_CONTROL_APPLICATION_COORDINATOR_RECORDS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = Vec::new();
        records
            .try_reserve(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            let authorization_invocation = InvocationId(decoder.fixed()?);
            let application_invocation = InvocationId(decoder.fixed()?);
            let control = decoder.bytes_bounded(MAX_PRIVATE_CONTROL_WIRE_BYTES)?;
            let mutation = decoder
                .option(|decoder| decoder.bytes_bounded(MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES))?;
            let resolved_at = decoder.u64()?;
            let resolution = match decoder.u8()? {
                0 => ApplicationRecordResolution::Pending,
                1 => ApplicationRecordResolution::Applied {
                    application_ack: Hash(decoder.fixed()?),
                    actor_consumed: decode_bool(&mut decoder)?,
                    persisted_authority_evidence: decoder
                        .option(|decoder| Ok(Hash(decoder.fixed()?)))?,
                },
                2 => ApplicationRecordResolution::RetiredUnapplied {
                    retirement_ack: Hash(decoder.fixed()?),
                    actor_consumed: decode_bool(&mut decoder)?,
                },
                _ => return Err(DecodeError::InvalidTag),
            };
            records.push(ApplicationRecord {
                authorization_invocation,
                application_invocation,
                control,
                mutation,
                resolved_at,
                resolution,
            });
        }
        let image = Self {
            authority,
            resolution_slot_high_water,
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
        self.image
            .records
            .iter()
            .any(|record| !record.resolution.is_fully_terminal())
    }

    pub(crate) fn into_parts(self) -> (C, R, A, DurableAuthorityOperationIssuer<I>) {
        (self.store, self.runtime, self.dispatcher, self.issuer)
    }

    /// Resolve one exact PCTL to either its PCA2 applied or PAR1
    /// retired-unapplied acknowledgement pipeline.
    ///
    /// Raw wire and trusted adapter assertions stay crate-private: neither is
    /// an independently authenticated signing capability.
    pub(crate) fn apply<S: PrivateControlApplicationEvidenceSigner>(
        &mut self,
        authorization_invocation: InvocationId,
        control_wire: &[u8],
        mutation_wire: Option<&[u8]>,
        applied_at: u64,
        signer: &mut S,
    ) -> Result<
        PrivateControlApplicationResolution,
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
        if !private_mutation_matches_control(&control, mutation_wire) {
            return Err(Self::rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl,
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
                || record.mutation.as_deref() != mutation_wire
                || record.resolved_at != applied_at
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
                .resolution_slot_high_water
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
            pledged.resolution_slot_high_water = Some(applied_at);
            pledged.records.push(ApplicationRecord {
                authorization_invocation,
                application_invocation,
                control: control_wire.to_vec(),
                mutation: mutation_wire.map(<[u8]>::to_vec),
                resolved_at: applied_at,
                resolution: ApplicationRecordResolution::Pending,
            });
            self.commit_candidate::<S::Error>(pledged)?;
            self.image.records.len() - 1
        };

        let runtime_resolution = match &retained.private_resolution {
            Some(super::authority_operation_issuer::RetainedPrivateResolution::Applied {
                application,
                ..
            }) => {
                if application.applied_at != applied_at
                    || application.control != control.commitment()
                    || !private_intent_matches_application(&retained.call.intent, application)
                {
                    return Err(PrivateControlApplicationCoordinatorError::InvalidState);
                }
                Some(*application)
            }
            Some(
                super::authority_operation_issuer::RetainedPrivateResolution::RetiredUnapplied {
                    resolved_at,
                    ..
                },
            ) => {
                if *resolved_at != applied_at {
                    return Err(PrivateControlApplicationCoordinatorError::InvalidState);
                }
                None
            }
            Some(super::authority_operation_issuer::RetainedPrivateResolution::Pending) => {
                if signer.public_key() != self.authority.binding.public_key {
                    return Err(Self::rejected(
                        PrivateControlApplicationCoordinatorRejection::WrongSigner,
                    ));
                }
                self.apply_runtime_exact::<S::Error>(
                    &control,
                    control_wire,
                    mutation_wire,
                    applied_at,
                    &retained,
                )?
            }
            None => return Err(PrivateControlApplicationCoordinatorError::InvalidState),
        };

        let terminal = if let Some(application) = runtime_resolution {
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
            PrivateControlApplicationResolution::Applied(acknowledgement)
        } else {
            let issued = self
                .issuer
                .retire_private_application(authorization_invocation, applied_at, signer)
                .map_err(PrivateControlApplicationCoordinatorError::Issuer)?;
            let acknowledgement = issued.retirement_ack;
            if acknowledgement.application_invocation != application_invocation
                || acknowledgement.resolved_at != applied_at
                || !acknowledgement.matches_pending(&retained.call, &retained.approval, issuance)
                || acknowledgement
                    .verify_pending_with(
                        &retained.call,
                        &retained.approval,
                        issuance,
                        self.authority.binding,
                        &RawEd25519Verifier,
                    )
                    .is_err()
            {
                return Err(PrivateControlApplicationCoordinatorError::InvalidState);
            }
            PrivateControlApplicationResolution::RetiredUnapplied(acknowledgement)
        };
        if terminal.invocation() != application_invocation || terminal.resolved_at() != applied_at {
            return Err(PrivateControlApplicationCoordinatorError::InvalidState);
        }

        let terminal_commitment = terminal.commitment();
        match (&self.image.records[record_index].resolution, &terminal) {
            (ApplicationRecordResolution::Pending, terminal) => {
                let mut selected = self.image.clone();
                selected.records[record_index].resolution = match terminal {
                    PrivateControlApplicationResolution::Applied(_) => {
                        ApplicationRecordResolution::Applied {
                            application_ack: terminal_commitment,
                            actor_consumed: false,
                            persisted_authority_evidence: None,
                        }
                    }
                    PrivateControlApplicationResolution::RetiredUnapplied(_) => {
                        ApplicationRecordResolution::RetiredUnapplied {
                            retirement_ack: terminal_commitment,
                            actor_consumed: false,
                        }
                    }
                };
                self.commit_candidate::<S::Error>(selected)?;
            }
            (
                ApplicationRecordResolution::Applied {
                    application_ack, ..
                },
                PrivateControlApplicationResolution::Applied(_),
            ) if *application_ack == terminal_commitment => {}
            (
                ApplicationRecordResolution::RetiredUnapplied { retirement_ack, .. },
                PrivateControlApplicationResolution::RetiredUnapplied(_),
            ) if *retirement_ack == terminal_commitment => {}
            _ => return Err(PrivateControlApplicationCoordinatorError::InvalidState),
        }

        let actor_consumed = match &self.image.records[record_index].resolution {
            ApplicationRecordResolution::Applied { actor_consumed, .. }
            | ApplicationRecordResolution::RetiredUnapplied { actor_consumed, .. } => {
                *actor_consumed
            }
            ApplicationRecordResolution::Pending => {
                return Err(PrivateControlApplicationCoordinatorError::InvalidState);
            }
        };
        if !actor_consumed {
            let context = resolution_context(&terminal);
            if !terminal.matches_invocation_context(&context) {
                return Err(PrivateControlApplicationCoordinatorError::InvalidState);
            }
            let acknowledgement_bytes = terminal
                .encode()
                .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?;
            let request = PrivateApplicationAuthorityDispatch {
                target: self.authority,
                method: PrivateApplicationAuthorityMethod::ResolvePrivateApplication,
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
            match &mut completed.records[record_index].resolution {
                ApplicationRecordResolution::Applied { actor_consumed, .. }
                | ApplicationRecordResolution::RetiredUnapplied { actor_consumed, .. } => {
                    *actor_consumed = true;
                }
                ApplicationRecordResolution::Pending => {
                    return Err(PrivateControlApplicationCoordinatorError::InvalidState);
                }
            }
            self.commit_candidate::<S::Error>(completed)?;
        }

        if let PrivateControlApplicationResolution::Applied(acknowledgement) = &terminal {
            let refreshed = self
                .issuer
                .recover_retained(authorization_invocation)
                .map_err(|_| PrivateControlApplicationCoordinatorError::InvalidState)?
                .ok_or(PrivateControlApplicationCoordinatorError::InvalidState)?;
            self.persist_runtime_evidence_exact::<S::Error>(
                record_index,
                &refreshed,
                acknowledgement,
            )?;
        }
        Ok(terminal)
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
        let persisted = match &self.image.records[record_index].resolution {
            ApplicationRecordResolution::Applied {
                application_ack,
                actor_consumed: true,
                persisted_authority_evidence,
            } if *application_ack == acknowledgement.commitment() => *persisted_authority_evidence,
            _ => return Err(PrivateControlApplicationCoordinatorError::InvalidState),
        };
        if let Some(commitment) = persisted {
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
        if persisted.is_none() {
            let mut completed = self.image.clone();
            let ApplicationRecordResolution::Applied {
                persisted_authority_evidence,
                ..
            } = &mut completed.records[record_index].resolution
            else {
                return Err(PrivateControlApplicationCoordinatorError::InvalidState);
            };
            *persisted_authority_evidence = Some(expected);
            self.commit_candidate::<SignerError>(completed)?;
        }
        Ok(())
    }

    fn apply_runtime_exact<SignerError>(
        &mut self,
        control: &PrivateControlRecord,
        control_wire: &[u8],
        mutation_wire: Option<&[u8]>,
        applied_at: u64,
        retained: &super::authority_operation_issuer::RetainedAuthorityOperation,
    ) -> Result<
        Option<PrivateControlApplicationFact>,
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
            mutation: mutation_wire.map(<[u8]>::to_vec),
            receipt,
            issuance_ack,
            applied_at,
        };
        let result = self
            .runtime
            .apply(&request)
            .map_err(PrivateControlApplicationCoordinatorError::Runtime)?;
        match result {
            PrivateControlRuntimeApplicationResolution::Applied(result) => {
                if result.route != request.route
                    || result.authority != request.authority
                    || result.control != request.control
                    || result.mutation != request.mutation
                    || result.receipt != request.receipt
                    || result.issuance_ack != request.issuance_ack
                    || result.applied_at != request.applied_at
                    || !result.authenticated
                    || !result.durably_applied
                    || !result.durably_reopened
                    || result.reopened_runtime_state == Hash::ZERO
                    || result.stable_projection == Hash::ZERO
                    || result.application_fact.len()
                        > MAX_PRIVATE_CONTROL_APPLICATION_FACT_WIRE_BYTES
                {
                    return Err(Self::rejected(
                        PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult,
                    ));
                }
                let application = decode_private_application_fact(&result.application_fact)
                    .map_err(|_| {
                        Self::rejected(
                            PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult,
                        )
                    })?;
                if encode_private_application_fact(&application) != result.application_fact
                    || application.applied_at != applied_at
                    || application.control != control.commitment()
                    || application.reopened_runtime_state != result.reopened_runtime_state
                    || application.stable_projection != result.stable_projection
                    || !private_intent_matches_application(&retained.call.intent, &application)
                {
                    return Err(Self::rejected(
                        PrivateControlApplicationCoordinatorRejection::ApplicationRejected,
                    ));
                }
                Ok(Some(application))
            }
            PrivateControlRuntimeApplicationResolution::RetiredUnapplied(result) => {
                if result.route != request.route
                    || result.authority != request.authority
                    || result.control != request.control
                    || result.mutation != request.mutation
                    || result.receipt != request.receipt
                    || result.issuance_ack != request.issuance_ack
                    || result.resolved_at != request.applied_at
                    || !result.authenticated
                    || !result.predecessor_unchanged
                    || !result.durably_reopened
                {
                    return Err(Self::rejected(
                        PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult,
                    ));
                }
                Ok(None)
            }
        }
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
    let mut issuer_retirements = 0usize;
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
            || record.resolved_at < issuance.issued_at
            || !issuance.receipt.selector.is_live_at(record.resolved_at)
            || issuance
                .verify_with(image.authority.binding, &verifier)
                .is_err()
        {
            return false;
        }
        match (&record.resolution, &retained.private_resolution) {
            (
                ApplicationRecordResolution::Pending,
                Some(super::authority_operation_issuer::RetainedPrivateResolution::Pending),
            ) => {}
            (
                ApplicationRecordResolution::Pending,
                Some(super::authority_operation_issuer::RetainedPrivateResolution::Applied {
                    application,
                    ..
                }),
            ) => {
                issuer_applications += 1;
                if !application_matches_record(&retained.call.intent, &control, record, application)
                {
                    return false;
                }
            }
            (
                ApplicationRecordResolution::Pending,
                Some(
                    super::authority_operation_issuer::RetainedPrivateResolution::RetiredUnapplied {
                        resolved_at, ..
                    },
                ),
            ) => {
                issuer_retirements += 1;
                if *resolved_at != record.resolved_at {
                    return false;
                }
            }
            (
                ApplicationRecordResolution::Applied {
                    application_ack,
                    persisted_authority_evidence,
                    ..
                },
                Some(super::authority_operation_issuer::RetainedPrivateResolution::Applied {
                    application,
                    application_ack: Some(acknowledgement),
                }),
            ) => {
                issuer_applications += 1;
                if *application_ack != acknowledgement.commitment()
                    || !application_matches_record(
                        &retained.call.intent,
                        &control,
                        record,
                        application,
                    )
                    || !acknowledgement.matches_pending(
                        &retained.call,
                        &retained.approval,
                        issuance,
                        application,
                    )
                    || acknowledgement
                        .verify_pending_with(
                            &retained.call,
                            &retained.approval,
                            issuance,
                            application,
                            image.authority.binding,
                            &verifier,
                        )
                        .is_err()
                {
                    return false;
                }
                if let Some(persisted) = persisted_authority_evidence {
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
                    if evidence.commitment().ok() != Some(*persisted) {
                        return false;
                    }
                }
            }
            (
                ApplicationRecordResolution::RetiredUnapplied { retirement_ack, .. },
                Some(
                    super::authority_operation_issuer::RetainedPrivateResolution::RetiredUnapplied {
                        resolved_at,
                        retirement_ack: Some(acknowledgement),
                    },
                ),
            ) => {
                issuer_retirements += 1;
                if *resolved_at != record.resolved_at
                    || *retirement_ack != acknowledgement.commitment()
                    || acknowledgement.resolved_at != record.resolved_at
                    || !acknowledgement.matches_pending(
                        &retained.call,
                        &retained.approval,
                        issuance,
                    )
                    || acknowledgement
                        .verify_pending_with(
                            &retained.call,
                            &retained.approval,
                            issuance,
                            image.authority.binding,
                            &verifier,
                        )
                        .is_err()
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    issuer_applications == issuer.retained_private_applications()
        && issuer_retirements == issuer.retained_private_retirements()
}

fn application_matches_record(
    intent: &AuthorityOperationIntent,
    control: &PrivateControlRecord,
    record: &ApplicationRecord,
    application: &PrivateControlApplicationFact,
) -> bool {
    application.applied_at == record.resolved_at
        && application.control == control.commitment()
        && private_intent_matches_application(intent, application)
}

fn resolution_context(acknowledgement: &PrivateControlApplicationResolution) -> InvocationContext {
    InvocationContext {
        invocation: acknowledgement.invocation(),
        actor: match acknowledgement {
            PrivateControlApplicationResolution::Applied(acknowledgement) => {
                acknowledgement.authority.binding.issuer.actor
            }
            PrivateControlApplicationResolution::RetiredUnapplied(acknowledgement) => {
                acknowledgement.authority.binding.issuer.actor
            }
        },
        mode: MethodMode::Linear,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        observed_slot: acknowledgement.resolved_at(),
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

fn private_mutation_matches_control(
    control: &PrivateControlRecord,
    mutation_wire: Option<&[u8]>,
) -> bool {
    match &control.operation {
        crate::agent::sdk::private::PrivateControlOperation::SetResourcePolicy { .. }
        | crate::agent::sdk::private::PrivateControlOperation::ActorLifecycle { .. } => {
            let Some(mutation_wire) = mutation_wire else {
                return false;
            };
            if mutation_wire.len() > MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES {
                return false;
            }
            let Ok(mutation) = PrivateRuntimeMutation::decode(mutation_wire) else {
                return false;
            };
            let request = ManagementRequest::PrivateControl {
                control: Box::new(control.clone()),
                mutation: Box::new(mutation.clone()),
            };
            mutation.encode().ok().as_deref() == Some(mutation_wire) && request.is_valid()
        }
        crate::agent::sdk::private::PrivateControlOperation::Invite { .. }
        | crate::agent::sdk::private::PrivateControlOperation::Revoke { .. }
        | crate::agent::sdk::private::PrivateControlOperation::RotateKeys { .. }
        | crate::agent::sdk::private::PrivateControlOperation::Recover { .. } => {
            mutation_wire.is_none()
        }
    }
}

fn push_unique(invocations: &mut Vec<InvocationId>, invocation: InvocationId) -> bool {
    if invocation == InvocationId::ZERO || invocations.contains(&invocation) {
        return false;
    }
    invocations.push(invocation);
    true
}

fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool, DecodeError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::InvalidTag),
    }
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
    encoder.fixed(application.reopened_runtime_state.as_bytes());
    encoder.fixed(application.stable_projection.as_bytes());
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
        reopened_runtime_state: Hash(decoder.fixed()?),
        stable_projection: Hash(decoder.fixed()?),
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
    use crate::agent::sdk::contract::RuntimeResourcePolicy;
    use crate::agent::sdk::private::{
        EncryptedObjectKind, EncryptedPrivateObject, PRIVATE_SIGNATURE_BYTES,
        PrivateControlOperation, PrivateControlSigner, PrivateKeyEpoch, PrivateNodeIdentity,
        PrivateRecoveryKeyringGrant, SealedPrivateKey, SealedRecoveryKey,
    };
    use crate::agent::sdk::{BlobRef, CredentialId, NodeId};

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
        retirement_calls: usize,
        fail_application: bool,
        fail_retirement: bool,
        corrupt_application: bool,
        corrupt_retirement: bool,
    }

    impl CountingSigner {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                receipt_calls: 0,
                issuance_calls: 0,
                application_calls: 0,
                retirement_calls: 0,
                fail_application: false,
                fail_retirement: false,
                corrupt_application: false,
                corrupt_retirement: false,
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

        fn sign_private_application_retirement_ack(
            &mut self,
            message: &[u8],
        ) -> Result<[u8; 64], Self::Error> {
            self.retirement_calls += 1;
            if self.fail_retirement {
                self.fail_retirement = false;
                return Err(TestError);
            }
            let mut signature = self.key.sign(message).to_bytes();
            if self.corrupt_retirement {
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
        Mutation,
        Receipt,
        Issuance,
        Slot,
        Unauthenticated,
        NotApplied,
        ChangedPredecessor,
        NotReopened,
        ReopenedRuntimeState,
        StableProjection,
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
        retained_denials: Vec<PrivateControlRuntimeApplicationRequest>,
        mutation: Option<RuntimeMutation>,
        evidence_mutation: Option<EvidenceMutation>,
        lose_result_after_apply: bool,
        lose_result_after_evidence: bool,
        deny_next: bool,
        denial_detail: Vec<u8>,
    }

    impl FakeRuntime {
        fn calls(&self) -> usize {
            self.inner.lock().unwrap().calls
        }

        fn transitions(&self) -> usize {
            self.inner.lock().unwrap().transitions
        }

        fn denials(&self) -> usize {
            self.inner.lock().unwrap().retained_denials.len()
        }

        fn deny_next(&self) {
            self.inner.lock().unwrap().deny_next = true;
        }

        fn deny_next_with_detail(&self, detail: &[u8]) {
            let mut state = self.inner.lock().unwrap();
            state.deny_next = true;
            state.denial_detail = detail.to_vec();
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
        ) -> Result<PrivateControlRuntimeApplicationResolution, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            state.calls += 1;
            let denied = if state.retained_denials.contains(request) {
                true
            } else if state.deny_next {
                state.deny_next = false;
                state.retained_denials.push(request.clone());
                true
            } else {
                false
            };
            if denied {
                if state.lose_result_after_apply {
                    state.lose_result_after_apply = false;
                    return Err(TestError);
                }
                let mut result = PrivateControlRuntimeRetirementResult {
                    route: request.route,
                    authority: request.authority,
                    control: request.control.clone(),
                    mutation: request.mutation.clone(),
                    receipt: request.receipt.clone(),
                    issuance_ack: request.issuance_ack.clone(),
                    resolved_at: request.applied_at,
                    authenticated: true,
                    predecessor_unchanged: true,
                    durably_reopened: true,
                };
                match state.mutation.take() {
                    None => {}
                    Some(RuntimeMutation::Route) => result.route.agent = AgentId(id(0xd1, 1)),
                    Some(RuntimeMutation::Authority) => {
                        result.authority.system_agent = AgentId(id(0xd2, 1))
                    }
                    Some(RuntimeMutation::Control) => result.control.push(0),
                    Some(RuntimeMutation::Mutation) => result.mutation = Some(vec![0]),
                    Some(RuntimeMutation::Receipt) => result.receipt.push(0),
                    Some(RuntimeMutation::Issuance) => result.issuance_ack.push(0),
                    Some(RuntimeMutation::Slot) => result.resolved_at += 1,
                    Some(RuntimeMutation::Unauthenticated) => result.authenticated = false,
                    Some(RuntimeMutation::ChangedPredecessor | RuntimeMutation::NotApplied) => {
                        result.predecessor_unchanged = false
                    }
                    Some(RuntimeMutation::NotReopened) => result.durably_reopened = false,
                    Some(
                        RuntimeMutation::MalformedFact
                        | RuntimeMutation::NonCanonicalFact
                        | RuntimeMutation::OversizeFact
                        | RuntimeMutation::FactRoute
                        | RuntimeMutation::FactControl
                        | RuntimeMutation::FactSlot
                        | RuntimeMutation::ReopenedRuntimeState
                        | RuntimeMutation::StableProjection,
                    ) => return Err(TestError),
                }
                return Ok(PrivateControlRuntimeApplicationResolution::RetiredUnapplied(result));
            }
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
            let application = decode_private_application_fact(&fact).map_err(|_| TestError)?;
            let mut result = PrivateControlRuntimeApplicationResult {
                route: request.route,
                authority: request.authority,
                control: request.control.clone(),
                mutation: request.mutation.clone(),
                receipt: request.receipt.clone(),
                issuance_ack: request.issuance_ack.clone(),
                applied_at: request.applied_at,
                authenticated: true,
                durably_applied: true,
                durably_reopened: true,
                reopened_runtime_state: application.reopened_runtime_state,
                stable_projection: application.stable_projection,
                application_fact: fact,
            };
            match state.mutation.take() {
                None => {}
                Some(RuntimeMutation::Route) => result.route.agent = AgentId(id(0xd1, 1)),
                Some(RuntimeMutation::Authority) => {
                    result.authority.system_agent = AgentId(id(0xd2, 1))
                }
                Some(RuntimeMutation::Control) => result.control.push(0),
                Some(RuntimeMutation::Mutation) => result.mutation = Some(vec![0]),
                Some(RuntimeMutation::Receipt) => result.receipt.push(0),
                Some(RuntimeMutation::Issuance) => result.issuance_ack.push(0),
                Some(RuntimeMutation::Slot) => result.applied_at += 1,
                Some(RuntimeMutation::Unauthenticated) => result.authenticated = false,
                Some(RuntimeMutation::NotApplied) => result.durably_applied = false,
                Some(RuntimeMutation::ChangedPredecessor) => result.durably_applied = false,
                Some(RuntimeMutation::NotReopened) => result.durably_reopened = false,
                Some(RuntimeMutation::ReopenedRuntimeState) => {
                    result.reopened_runtime_state = Hash(id(0xd5, 1))
                }
                Some(RuntimeMutation::StableProjection) => {
                    result.stable_projection = Hash(id(0xd6, 1))
                }
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
            Ok(PrivateControlRuntimeApplicationResolution::Applied(result))
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
        AckType,
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
            if request.method == PrivateApplicationAuthorityMethod::ResolvePrivateApplication {
                if state.tombstones.contains(&request.request) {
                    accepted = true;
                } else {
                    let index = if let Ok(acknowledgement) =
                        PrivateControlApplicationAck::decode(&request.request)
                    {
                        state.pending.iter().position(|pending| {
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
                        })
                    } else if let Ok(acknowledgement) =
                        PrivateControlApplicationRetirementAck::decode(&request.request)
                    {
                        state.pending.iter().position(|pending| {
                            acknowledgement.authorization_invocation == pending.call.invocation
                                && acknowledgement.matches_invocation_context(&request.context)
                                && acknowledgement
                                    .verify_pending_with(
                                        &pending.call,
                                        &pending.approval,
                                        &pending.issuance,
                                        request.target.binding,
                                        &RawEd25519Verifier,
                                    )
                                    .is_ok()
                        })
                    } else {
                        None
                    };
                    if let Some(index) = index {
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
                Some(ActorMutation::AckType) => {
                    if result.request.starts_with(b"PAR1") {
                        result.request[..4].copy_from_slice(b"PCA1");
                    } else {
                        result.request[..4].copy_from_slice(b"PAR1");
                    }
                }
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

    fn prepare_policy(discriminator: u64) -> (Prepared, PrivateRuntimeMutation) {
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (control, mutation) = private_policy_control(&fixture, discriminator);
        let (call, approval) = fixture.approved(discriminator, discriminator, &control);
        let issuer_store = MemoryImageStore::default();
        let mut issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), fixture.authority).unwrap();
        let issued = issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        let actor = FakeAuthorityActor::default();
        actor.register(call.clone(), approval, issued.issuance_ack);
        (
            Prepared {
                fixture,
                signer,
                issuer_store,
                issuer,
                actor,
                call,
                control,
            },
            mutation,
        )
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

    fn private_policy_control(
        fixture: &Fixture,
        discriminator: u64,
    ) -> (PrivateControlRecord, PrivateRuntimeMutation) {
        let policy = RuntimeResourcePolicy::standard();
        let mut control = fixture.control(discriminator);
        control.operation = PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef::of_bytes(&policy.encode().unwrap()),
        };
        let key = SigningKey::from_bytes(&id(0x49, discriminator));
        control.signature = key.sign(&control.signing_bytes()).to_bytes();
        assert!(control.validate_shape());
        (control, PrivateRuntimeMutation::SetResourcePolicy(policy))
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
            PrivateControlOperation::SetResourcePolicy { .. } => (
                AuthorityOperationKind::SetPrivateResourcePolicy,
                2,
                Hash::digest(
                    b"vos/test/private-post-member-set/v1",
                    &[control.commitment().as_bytes()],
                ),
            ),
            PrivateControlOperation::ActorLifecycle { .. } => (
                AuthorityOperationKind::PrivateActorLifecycle,
                2,
                Hash::digest(
                    b"vos/test/private-post-member-set/v1",
                    &[control.commitment().as_bytes()],
                ),
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
            reopened_runtime_state: Hash::digest(
                b"vos/test/private-reopened-state/v1",
                &[control.commitment().as_bytes(), &applied_at.to_le_bytes()],
            ),
            stable_projection: Hash::digest(
                b"vos/test/private-stable-projection/v1",
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
    fn pcaf2_roundtrips_both_runtime_commitments_and_rejects_old_or_trailing_frames() {
        let prepared = prepare(1);
        let fact = application_fact(prepared.call.intent.managed(), &prepared.control, 24);
        let wire = encode_private_application_fact(&fact);
        assert_eq!(
            &wire[..PRIVATE_CONTROL_APPLICATION_FACT_MAGIC.len()],
            b"PCAF2"
        );
        assert_eq!(decode_private_application_fact(&wire), Ok(fact));

        let mut old_frame = wire.clone();
        old_frame.remove(PRIVATE_CONTROL_APPLICATION_FACT_MAGIC.len() - 1);
        assert_eq!(&old_frame[..4], b"PCAF");
        assert!(matches!(
            decode_private_application_fact(&old_frame),
            Err(DecodeError::InvalidTag)
        ));

        let mut trailing = wire;
        trailing.push(0);
        assert!(matches!(
            decode_private_application_fact(&trailing),
            Err(DecodeError::NonCanonical)
        ));
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
            PrivateApplicationAuthorityMethod::ResolvePrivateApplication.name(),
            "resolve_private_application"
        );
        let acknowledgement = coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap();
        let acknowledgement_wire = acknowledgement.encode().unwrap();
        assert_eq!(coordinator_store.commits(), 4);
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
                .apply(prepared.call.invocation, &wire, None, 24, &mut unusable)
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
                .apply(prepared.call.invocation, &wire, None, 24, &mut unusable)
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
    fn deterministic_denial_retires_to_exact_par_without_guest_detail_or_positive_evidence() {
        let mut prepared = prepare(41);
        let coordinator_store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        let detail = b"private guest denial detail must remain memory-only";
        runtime.deny_next_with_detail(detail);
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

        let retirement = match coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap()
        {
            PrivateControlApplicationResolution::RetiredUnapplied(acknowledgement) => {
                acknowledgement
            }
            PrivateControlApplicationResolution::Applied(_) => panic!("denial became PCA"),
        };
        let retirement_wire = retirement.encode().unwrap();
        assert_eq!(&retirement_wire[..4], b"PAR1");
        assert!(
            retirement
                .verify_with(authority.binding, &RawEd25519Verifier)
                .is_ok()
        );
        assert_eq!(coordinator_store.commits(), 3);
        assert_eq!(
            (
                runtime.calls(),
                runtime.denials(),
                runtime.transitions(),
                runtime.evidence_calls(),
                actor.calls(),
                prepared.signer.application_calls,
                prepared.signer.retirement_calls,
            ),
            (1, 1, 0, 0, 1, 0, 1)
        );
        assert!(!coordinator.has_pending_application());
        assert!(
            !coordinator_store
                .image()
                .unwrap()
                .windows(detail.len())
                .any(|window| window == detail)
        );
        assert!(
            !prepared
                .issuer_store
                .image()
                .unwrap()
                .windows(detail.len())
                .any(|window| window == detail)
        );
        assert_eq!(runtime.inner.lock().unwrap().denial_detail, detail);

        let mut unusable = CountingSigner::new(0x72);
        unusable.fail_retirement = true;
        let retry = coordinator
            .apply(prepared.call.invocation, &wire, None, 24, &mut unusable)
            .unwrap();
        assert_eq!(retry.encode().unwrap(), retirement_wire);
        assert_eq!(unusable.retirement_calls, 0);
        assert_eq!(
            (runtime.calls(), runtime.evidence_calls(), actor.calls()),
            (1, 0, 1)
        );

        let mut coordinator = restart(coordinator, authority);
        assert_eq!(
            coordinator
                .apply(prepared.call.invocation, &wire, None, 24, &mut unusable)
                .unwrap()
                .encode()
                .unwrap(),
            retirement_wire
        );
        assert_eq!(unusable.retirement_calls, 0);
        assert_eq!(
            (runtime.calls(), runtime.evidence_calls(), actor.calls()),
            (1, 0, 1)
        );
    }

    #[test]
    fn canonical_private_mutation_is_bound_in_pledge_retry_and_runtime_echo() {
        let (mut prepared, mutation) = prepare_policy(42);
        let mutation_wire = mutation.encode().unwrap();
        let runtime = FakeRuntime::default();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let policy_control_wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            MemoryImageStore::default(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );

        for invalid in [None, Some(&[1, 2, 3][..])] {
            assert!(matches!(
                coordinator.apply(
                    prepared.call.invocation,
                    &policy_control_wire,
                    invalid,
                    24,
                    &mut prepared.signer,
                ),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidControl
                ))
            ));
        }
        assert_eq!(runtime.calls(), 0);

        runtime.mutate_once(RuntimeMutation::Mutation);
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &policy_control_wire,
                Some(&mutation_wire),
                24,
                &mut prepared.signer,
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult
            ))
        ));
        assert_eq!(prepared.signer.application_calls, 0);
        coordinator
            .apply(
                prepared.call.invocation,
                &policy_control_wire,
                Some(&mutation_wire),
                24,
                &mut prepared.signer,
            )
            .unwrap();
        assert_eq!(
            (runtime.calls(), runtime.transitions(), actor.calls()),
            (2, 1, 1)
        );

        let mut control_only = prepare(43);
        let control_only_wire = control_wire(&control_only);
        let control_only_runtime = FakeRuntime::default();
        let mut control_only_coordinator = open_coordinator(
            MemoryImageStore::default(),
            control_only_runtime.clone(),
            control_only.actor.clone(),
            control_only.issuer,
            control_only.fixture.authority,
        );
        assert!(matches!(
            control_only_coordinator.apply(
                control_only.call.invocation,
                &control_only_wire,
                Some(&mutation_wire),
                24,
                &mut control_only.signer,
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::InvalidControl
            ))
        ));
        assert_eq!(control_only_runtime.calls(), 0);
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
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
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
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Runtime(
                TestError
            ))
        ));
        assert!(!coordinator.is_poisoned());
        assert_eq!((runtime.calls(), runtime.transitions()), (1, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (0, 0));

        let mut coordinator = restart(coordinator, authority);
        coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap();
        assert_eq!((runtime.calls(), runtime.transitions()), (2, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (1, 1));
    }

    #[test]
    fn lost_denial_and_actor_results_resume_exact_par_without_application_artifacts() {
        let mut prepared = prepare(44);
        let runtime = FakeRuntime::default();
        runtime.deny_next();
        runtime.lose_result_after_apply_once();
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Runtime(
                TestError
            ))
        ));
        assert_eq!((runtime.calls(), runtime.denials()), (1, 1));
        assert_eq!(
            (
                prepared.signer.application_calls,
                prepared.signer.retirement_calls
            ),
            (0, 0)
        );

        let mut coordinator = restart(coordinator, authority);
        assert!(matches!(
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                )
                .unwrap(),
            PrivateControlApplicationResolution::RetiredUnapplied(_)
        ));
        assert_eq!(
            (runtime.calls(), runtime.denials(), runtime.transitions()),
            (2, 1, 0)
        );
        assert_eq!(
            (
                prepared.signer.application_calls,
                prepared.signer.retirement_calls
            ),
            (0, 1)
        );
        assert_eq!((runtime.evidence_calls(), actor.calls()), (0, 1));

        let mut prepared = prepare(45);
        let runtime = FakeRuntime::default();
        runtime.deny_next();
        let actor = prepared.actor.clone();
        actor.lose_result_after_consume_once();
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Dispatch(
                TestError
            ))
        ));
        assert_eq!((actor.pending(), actor.tombstones()), (0, 1));
        let mut coordinator = restart(coordinator, authority);
        assert!(matches!(
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                )
                .unwrap(),
            PrivateControlApplicationResolution::RetiredUnapplied(_)
        ));
        assert_eq!((runtime.calls(), runtime.evidence_calls()), (1, 0));
        assert_eq!(
            (
                prepared.signer.application_calls,
                prepared.signer.retirement_calls
            ),
            (0, 1)
        );
        assert_eq!(
            (actor.calls(), actor.pending(), actor.tombstones()),
            (2, 0, 1)
        );
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Dispatch(
                TestError
            ))
        ));
        assert_eq!((runtime.calls(), runtime.transitions()), (1, 1));
        assert_eq!((prepared.signer.application_calls, actor.calls()), (1, 1));
        assert_eq!((actor.pending(), actor.tombstones()), (0, 1));

        let mut coordinator = restart(coordinator, authority);
        let acknowledgement = coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
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
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
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

        // A fully committed retry returns the exact retained PCA2 without
        // touching the runtime, actor, or signer again.
        coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
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
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                ),
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
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                ),
                Err(PrivateControlApplicationCoordinatorError::Storage(
                    TestError
                ))
            ));
            assert!(coordinator.is_poisoned());
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (0, 0));
            let mut coordinator = restart(coordinator, authority);
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                )
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
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                ),
                Err(PrivateControlApplicationCoordinatorError::Storage(
                    TestError
                ))
            ));
            assert!(coordinator.is_poisoned());
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!(actor.calls(), 0);
            let mut coordinator = restart(coordinator, authority);
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                )
                .unwrap();
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!(actor.calls(), 1);
        }

        // The third commit records actor consumption and the fourth records
        // exact PSE2 attachment. Every before/after ambiguity poisons the live
        // handle and restart resumes from the durable side of that boundary.
        for (boundary, fail_after) in [3usize, 4]
            .into_iter()
            .flat_map(|boundary| [false, true].map(move |fail_after| (boundary, fail_after)))
        {
            let mut prepared = prepare(1);
            let store = MemoryImageStore::default();
            if fail_after {
                store.fail_after_commit(boundary);
            } else {
                store.fail_before_commit(boundary);
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
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                ),
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
                (1, 1, usize::from(boundary == 4), 1, 1)
            );
            let mut coordinator = restart(coordinator, authority);
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                )
                .unwrap();
            assert_eq!(
                runtime.evidence_calls(),
                if boundary == 4 && !fail_after { 2 } else { 1 }
            );
            assert_eq!(
                (runtime.calls(), actor.calls()),
                (1, if boundary == 3 && !fail_after { 2 } else { 1 })
            );
            assert_eq!(prepared.signer.application_calls, 1);
        }
    }

    #[test]
    fn retirement_coordinator_pledge_selection_and_dispatch_commits_resume_exactly() {
        for boundary in [1usize, 2, 3] {
            for fail_after in [false, true] {
                let mut prepared = prepare(46 + boundary as u64);
                let store = MemoryImageStore::default();
                if fail_after {
                    store.fail_after_commit(boundary);
                } else {
                    store.fail_before_commit(boundary);
                }
                let runtime = FakeRuntime::default();
                runtime.deny_next();
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
                    coordinator.apply(
                        prepared.call.invocation,
                        &wire,
                        None,
                        24,
                        &mut prepared.signer,
                    ),
                    Err(PrivateControlApplicationCoordinatorError::Storage(
                        TestError
                    ))
                ));
                assert!(coordinator.is_poisoned());
                assert_eq!(runtime.calls(), usize::from(boundary != 1));
                let calls = runtime.calls();
                let signs = prepared.signer.retirement_calls;
                let actor_calls = actor.calls();

                let mut coordinator = restart(coordinator, authority);
                let retirement = coordinator
                    .apply(
                        prepared.call.invocation,
                        &wire,
                        None,
                        24,
                        &mut prepared.signer,
                    )
                    .unwrap();
                assert!(matches!(
                    retirement,
                    PrivateControlApplicationResolution::RetiredUnapplied(_)
                ));
                assert_eq!(
                    runtime.calls(),
                    calls + usize::from(boundary == 1),
                    "boundary {boundary} after {fail_after}"
                );
                assert_eq!(
                    prepared.signer.retirement_calls,
                    signs + usize::from(boundary == 1),
                    "boundary {boundary} after {fail_after}"
                );
                assert_eq!(
                    actor.calls(),
                    actor_calls + usize::from(boundary != 3 || !fail_after),
                    "boundary {boundary} after {fail_after}"
                );
                assert_eq!(runtime.evidence_calls(), 0);
                assert!(!coordinator.has_pending_application());
            }
        }
    }

    #[test]
    fn retirement_issuer_pledge_sign_and_commit_failpoints_never_reapply_runtime() {
        for boundary in [1usize, 2] {
            for fail_after in [false, true] {
                let mut prepared = prepare(52 + boundary as u64);
                if fail_after {
                    prepared.issuer_store.fail_after_commit(boundary);
                } else {
                    prepared.issuer_store.fail_before_commit(boundary);
                }
                let runtime = FakeRuntime::default();
                runtime.deny_next();
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
                    coordinator.apply(
                        prepared.call.invocation,
                        &wire,
                        None,
                        24,
                        &mut prepared.signer,
                    ),
                    Err(PrivateControlApplicationCoordinatorError::Issuer(
                        AuthorityOperationIssuerError::Storage(TestError)
                    ))
                ));
                let calls = runtime.calls();
                let signs = prepared.signer.retirement_calls;
                let mut coordinator = restart(coordinator, authority);
                assert!(matches!(
                    coordinator
                        .apply(
                            prepared.call.invocation,
                            &wire,
                            None,
                            24,
                            &mut prepared.signer,
                        )
                        .unwrap(),
                    PrivateControlApplicationResolution::RetiredUnapplied(_)
                ));
                assert_eq!(
                    runtime.calls(),
                    calls + usize::from(boundary == 1 && !fail_after)
                );
                assert_eq!(
                    prepared.signer.retirement_calls,
                    signs + usize::from(boundary == 1 || (boundary == 2 && !fail_after))
                );
                assert_eq!((actor.calls(), runtime.evidence_calls()), (1, 0));
            }
        }

        let mut prepared = prepare(55);
        prepared.signer.fail_retirement = true;
        let runtime = FakeRuntime::default();
        runtime.deny_next();
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            ),
            Err(PrivateControlApplicationCoordinatorError::Issuer(
                AuthorityOperationIssuerError::Signer(TestError)
            ))
        ));
        assert_eq!((runtime.calls(), prepared.signer.retirement_calls), (1, 1));
        coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap();
        assert_eq!((runtime.calls(), prepared.signer.retirement_calls), (1, 2));
        assert_eq!((actor.calls(), runtime.evidence_calls()), (1, 0));
    }

    #[test]
    fn issuer_one_step_ahead_resumes_winning_apply_or_retire_branch_and_loses_opposite_race() {
        let mut prepared = prepare(56);
        let store = MemoryImageStore::default();
        store.fail_after_commit(1);
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            ),
            Err(PrivateControlApplicationCoordinatorError::Storage(
                TestError
            ))
        ));
        let (store, runtime, actor, mut issuer) = coordinator.into_parts();
        let application = application_fact(prepared.call.intent.managed(), &prepared.control, 24);
        issuer
            .issue_private_application(prepared.call.invocation, &application, &mut prepared.signer)
            .unwrap();
        runtime.deny_next();
        let mut coordinator = open_coordinator(store, runtime.clone(), actor, issuer, authority);
        assert!(matches!(
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                )
                .unwrap(),
            PrivateControlApplicationResolution::Applied(_)
        ));
        assert_eq!(
            (runtime.calls(), runtime.transitions(), runtime.denials()),
            (0, 0, 0)
        );
        let (_, _, _, mut issuer) = coordinator.into_parts();
        assert!(matches!(
            issuer.retire_private_application(prepared.call.invocation, 24, &mut prepared.signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::DivergentRetry
            ))
        ));

        let mut prepared = prepare(57);
        let store = MemoryImageStore::default();
        store.fail_after_commit(1);
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            ),
            Err(PrivateControlApplicationCoordinatorError::Storage(
                TestError
            ))
        ));
        let (store, runtime, actor, mut issuer) = coordinator.into_parts();
        issuer
            .retire_private_application(prepared.call.invocation, 24, &mut prepared.signer)
            .unwrap();
        let mut coordinator = open_coordinator(store, runtime.clone(), actor, issuer, authority);
        assert!(matches!(
            coordinator
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer
                )
                .unwrap(),
            PrivateControlApplicationResolution::RetiredUnapplied(_)
        ));
        assert_eq!(
            (runtime.calls(), runtime.transitions(), runtime.denials()),
            (0, 0, 0)
        );
        let (_, _, _, mut issuer) = coordinator.into_parts();
        let application = application_fact(prepared.call.intent.managed(), &prepared.control, 24);
        assert!(matches!(
            issuer.issue_private_application(
                prepared.call.invocation,
                &application,
                &mut prepared.signer
            ),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::DivergentRetry
            ))
        ));
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
                    coordinator.apply(
                        prepared.call.invocation,
                        &wire,
                        None,
                        24,
                        &mut prepared.signer
                    ),
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
                    .apply(
                        prepared.call.invocation,
                        &wire,
                        None,
                        24,
                        &mut prepared.signer,
                    )
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Issuer(
                AuthorityOperationIssuerError::Signer(TestError)
            ))
        ));
        assert!(!coordinator.is_poisoned());
        coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer
            ),
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
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap();
        assert_eq!((prepared.signer.application_calls, actor.calls()), (2, 1));
    }

    #[test]
    fn hostile_runtime_echoes_flags_and_bound_fact_fields_are_rejected() {
        let cases = [
            RuntimeMutation::Route,
            RuntimeMutation::Authority,
            RuntimeMutation::Control,
            RuntimeMutation::Mutation,
            RuntimeMutation::Receipt,
            RuntimeMutation::Issuance,
            RuntimeMutation::Slot,
            RuntimeMutation::Unauthenticated,
            RuntimeMutation::NotApplied,
            RuntimeMutation::ChangedPredecessor,
            RuntimeMutation::NotReopened,
            RuntimeMutation::ReopenedRuntimeState,
            RuntimeMutation::StableProjection,
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
                    coordinator.apply(
                        prepared.call.invocation,
                        &wire,
                        None,
                        24,
                        &mut prepared.signer
                    ),
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
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                )
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
            ActorMutation::AckType,
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
            coordinator.apply(prepared.call.invocation, &wire, None, 24, &mut prepared.signer),
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
                .apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                )
                .unwrap();
            assert_eq!((runtime.calls(), prepared.signer.application_calls), (1, 1));
            assert_eq!(actor.calls(), 2);
        }
    }

    #[test]
    fn hostile_retirement_echoes_unchanged_proof_and_unified_dispatch_are_rejected() {
        for mutation in [
            RuntimeMutation::Route,
            RuntimeMutation::Authority,
            RuntimeMutation::Control,
            RuntimeMutation::Mutation,
            RuntimeMutation::Receipt,
            RuntimeMutation::Issuance,
            RuntimeMutation::Slot,
            RuntimeMutation::Unauthenticated,
            RuntimeMutation::ChangedPredecessor,
            RuntimeMutation::NotReopened,
        ] {
            let mut prepared = prepare(60);
            let runtime = FakeRuntime::default();
            runtime.deny_next();
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
            assert!(matches!(
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                ),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidRuntimeResult
                ))
            ));
            assert_eq!(
                (
                    prepared.signer.application_calls,
                    prepared.signer.retirement_calls,
                    actor.calls(),
                    runtime.evidence_calls(),
                ),
                (0, 0, 0, 0),
                "retirement runtime mutation {mutation:?}"
            );
        }

        for mutation in [
            ActorMutation::Target,
            ActorMutation::Method,
            ActorMutation::Context,
            ActorMutation::Request,
            ActorMutation::AckType,
            ActorMutation::Unauthenticated,
            ActorMutation::NotDurable,
        ] {
            let mut prepared = prepare(61);
            let runtime = FakeRuntime::default();
            runtime.deny_next();
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
            assert!(matches!(
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    24,
                    &mut prepared.signer,
                ),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidAuthorityResult
                ))
            ));
            assert_eq!(
                (
                    prepared.signer.application_calls,
                    prepared.signer.retirement_calls
                ),
                (0, 1)
            );
            assert_eq!((runtime.evidence_calls(), actor.calls()), (0, 1));
        }

        let mut prepared = prepare(62);
        prepared.signer.corrupt_retirement = true;
        let runtime = FakeRuntime::default();
        runtime.deny_next();
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
            coordinator.apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            ),
            Err(PrivateControlApplicationCoordinatorError::Issuer(
                AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::WrongSigner
                )
            ))
        ));
        assert_eq!(
            (runtime.calls(), actor.calls(), runtime.evidence_calls()),
            (1, 0, 0)
        );
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
                24,
                &mut prepared.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Rejected(
                PrivateControlApplicationCoordinatorRejection::WrongRoute
            ))
        ));
        for slot in [19, 39] {
            assert!(matches!(
                coordinator.apply(
                    prepared.call.invocation,
                    &wire,
                    None,
                    slot,
                    &mut prepared.signer
                ),
                Err(PrivateControlApplicationCoordinatorError::Rejected(
                    PrivateControlApplicationCoordinatorRejection::InvalidApplicationSlot
                ))
            ));
        }
        let mut wrong_signer = CountingSigner::new(0x72);
        assert!(matches!(
            coordinator.apply(prepared.call.invocation, &wire, None, 24, &mut wrong_signer),
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
        runtime.deny_next();
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
                None,
                25,
                &mut prepared.signer,
            )
            .unwrap();
        assert!(matches!(
            coordinator.apply(
                second_call.invocation,
                &second_wire,
                None,
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
                None,
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
                None,
                25,
                &mut prepared.signer,
            )
            .unwrap();
        assert!(matches!(
            coordinator.apply(
                prepared.call.invocation,
                &first_wire,
                None,
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
            pending.apply(
                third.call.invocation,
                &third_wire,
                None,
                24,
                &mut third.signer
            ),
            Err(PrivateControlApplicationCoordinatorError::Runtime(
                TestError
            ))
        ));
        // A divergent authorization identity cannot reuse the pending slot.
        assert!(matches!(
            pending.apply(
                InvocationId(id(0xfa, 1)),
                &third_wire,
                None,
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
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap();
        let (coordinator_store, runtime, actor, issuer) = coordinator.into_parts();
        let issuer_store = issuer.into_store();
        let valid = coordinator_store.image().unwrap();

        let mut old_magic = valid.clone();
        old_magic[..4].copy_from_slice(b"PAJ3");
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
        let ApplicationRecordResolution::Applied {
            application_ack, ..
        } = &mut image.records[0].resolution
        else {
            panic!("positive fixture must retain an applied terminal")
        };
        *application_ack = Hash(id(0xfb, 1));
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
    fn retired_image_rejects_invalid_terminal_tag_branch_substitution_and_issuer_divergence() {
        let mut prepared = prepare(63);
        let store = MemoryImageStore::default();
        let runtime = FakeRuntime::default();
        runtime.deny_next();
        let actor = prepared.actor.clone();
        let authority = prepared.fixture.authority;
        let wire = control_wire(&prepared);
        let mut coordinator = open_coordinator(
            store.clone(),
            runtime.clone(),
            actor.clone(),
            prepared.issuer,
            authority,
        );
        coordinator
            .apply(
                prepared.call.invocation,
                &wire,
                None,
                24,
                &mut prepared.signer,
            )
            .unwrap();
        let (store, runtime, actor, issuer) = coordinator.into_parts();
        let issuer_store = issuer.into_store();
        let valid = store.image().unwrap();
        let image = PrivateControlApplicationCoordinatorImage::decode(&valid).unwrap();
        let ApplicationRecordResolution::RetiredUnapplied { retirement_ack, .. } =
            &image.records[0].resolution
        else {
            panic!("denial did not select retirement")
        };
        let retirement_ack = *retirement_ack;

        let offsets: Vec<usize> = valid
            .windows(retirement_ack.as_bytes().len())
            .enumerate()
            .filter_map(|(offset, window)| (window == retirement_ack.as_bytes()).then_some(offset))
            .collect();
        assert_eq!(offsets.len(), 1);
        let mut invalid_tag = valid.clone();
        invalid_tag[offsets[0] - 1] = 9;
        store.replace_image(invalid_tag);
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                store.clone(),
                authority,
                runtime.clone(),
                actor.clone(),
                reopened_issuer,
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        let mut substituted = image.clone();
        substituted.records[0].resolution = ApplicationRecordResolution::Applied {
            application_ack: retirement_ack,
            actor_consumed: true,
            persisted_authority_evidence: Some(Hash(id(0xfc, 1))),
        };
        assert!(substituted.is_valid());
        store.replace_image(substituted.encode());
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store.clone(), authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                store.clone(),
                authority,
                runtime.clone(),
                actor.clone(),
                reopened_issuer,
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
        ));

        let mut divergent = image;
        let ApplicationRecordResolution::RetiredUnapplied { retirement_ack, .. } =
            &mut divergent.records[0].resolution
        else {
            unreachable!()
        };
        *retirement_ack = Hash(id(0xfd, 1));
        store.replace_image(divergent.encode());
        let reopened_issuer =
            DurableAuthorityOperationIssuer::open(issuer_store, authority).unwrap();
        assert!(matches!(
            DurablePrivateControlApplicationCoordinator::open(
                store,
                authority,
                runtime,
                actor,
                reopened_issuer,
            ),
            Err(PrivateControlApplicationCoordinatorError::InvalidState)
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
                mutation: None,
                resolved_at: 24,
                resolution: if index % 2 == 0 {
                    ApplicationRecordResolution::Applied {
                        application_ack: Hash(id(0xc3, index + 1)),
                        actor_consumed: true,
                        persisted_authority_evidence: Some(Hash(id(0xc4, index + 1))),
                    }
                } else {
                    ApplicationRecordResolution::RetiredUnapplied {
                        retirement_ack: Hash(id(0xc3, index + 1)),
                        actor_consumed: true,
                    }
                },
            });
        }
        image.resolution_slot_high_water = Some(24);
        assert!(image.is_valid());
        image.records.push(ApplicationRecord {
            authorization_invocation: InvocationId(id(0xc1, 10_000)),
            application_invocation: InvocationId(id(0xc2, 10_000)),
            control: control.clone(),
            mutation: None,
            resolved_at: 24,
            resolution: ApplicationRecordResolution::RetiredUnapplied {
                retirement_ack: Hash(id(0xc3, 10_000)),
                actor_consumed: true,
            },
        });
        assert!(!image.has_valid_envelope());
        image.records.pop();
        image.records[1].application_invocation = image.records[0].authorization_invocation;
        assert!(!image.is_valid());
        image.records[1].application_invocation = image.records[1].authorization_invocation;
        assert!(!image.has_valid_envelope());
    }
}
