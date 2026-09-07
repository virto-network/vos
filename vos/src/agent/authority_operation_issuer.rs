//! Durable host-side issuance for non-management authority operations.
//!
//! AOC1/AOP1 policy evaluation happens in the system-authority actor. This
//! module owns the narrower crash-consistency boundary between that actor's
//! exact approval and the authority signatures which leave the host: the
//! operation receipt, AOI1 issuance acknowledgement, and (for Private
//! controls) PCA1 durable-application acknowledgement.
//!
//! Records are intentionally never compacted here. AOI1 proves that the host
//! durably issued one receipt and PCA1 proves that a Private runtime durably
//! reopened one control, but neither proves that the authority actor durably
//! consumed the acknowledgement. Until separately reopenable authenticated
//! consumption evidence is available, deleting retained preimages would make
//! exact retry and collision checks unsafe.

use core::{convert::Infallible, fmt};

use crate::agent::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialVerifier, AuthorityIssuer,
    AuthorityOperationKind, AuthorityReceipt, AuthorityVerifier, ManagedAgentTarget,
};
use crate::agent::sdk::authority_operation::{
    AuthorityOperationApproval, AuthorityOperationCall, AuthorityOperationIntent,
    AuthorityOperationIssuanceAck, MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES,
    MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES, MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES,
    MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES, PrivateControlApplicationAck,
    PrivateControlApplicationFact,
};
use crate::agent::sdk::wire::{CanonicalWire, MAX_AUTHORITY_RECEIPT_WIRE_BYTES};
use crate::agent::sdk::{
    ActorId, AgentId, DeploymentId, Hash, InvocationId, PrincipalId, ProducerId, ProgramId, SpaceId,
};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

/// Hard retention ceiling while durable actor-consumption evidence is absent.
pub const MAX_AUTHORITY_OPERATION_ISSUER_RECORDS: usize = 256;
/// Maximum complete canonical whole-image commit accepted from storage.
pub const MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES: usize = 4 * 1024 * 1024;
const AUTHORITY_OPERATION_ISSUER_MAGIC: [u8; 4] = *b"AOJ2";

/// Minimal durable whole-image boundary for operation evidence issuance.
///
/// `commit` may return success only once the exact image is recoverable after
/// restart. A failed commit is an ambiguous durability boundary and poisons
/// the live issuer handle.
pub trait AuthorityOperationIssuerStore {
    type Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

/// External authority signer invoked only after its exact preimage is durable.
///
/// Implementations must be deterministic/idempotent for an exact message: a
/// process may fail after a signature was produced but before its next image
/// commit became durable. Completed exact retries never call this interface.
pub trait AuthorityOperationEvidenceSigner {
    type Error;

    fn public_key(&self) -> [u8; 32];

    fn sign_authority_receipt(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;

    fn sign_issuance_ack(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

/// Distinct signer method for the post-application PCA1 boundary.
///
/// Like the issuance signer, implementations must return the same signature
/// for an exact message after a crash or ambiguous commit. Keeping this method
/// distinct prevents an AOI1 or receipt preimage from being relabelled as a
/// Private application acknowledgement by a signer adapter.
pub trait PrivateControlApplicationEvidenceSigner {
    type Error;

    fn public_key(&self) -> [u8; 32];

    fn sign_private_application_ack(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error>;
}

/// Complete evidence returned for one exact authorized operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedAuthorityOperation {
    pub receipt: AuthorityReceipt,
    pub issuance_ack: AuthorityOperationIssuanceAck,
}

/// Complete authority evidence for one durably reopened Private control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedPrivateControlApplication {
    pub application_ack: PrivateControlApplicationAck,
}

/// Exact durable issuer material reopened by the trusted actor coordinator.
///
/// This stays crate-private: an AOP1 is unsigned actor output and must never
/// become a public capability for reaching the authority signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedAuthorityOperation {
    pub(crate) call: AuthorityOperationCall,
    pub(crate) approval: AuthorityOperationApproval,
    pub(crate) issued_at: u64,
    pub(crate) receipt: Option<AuthorityReceipt>,
    pub(crate) issuance_ack: Option<AuthorityOperationIssuanceAck>,
    pub(crate) application: Option<PrivateControlApplicationFact>,
    pub(crate) application_ack: Option<PrivateControlApplicationAck>,
}

impl RetainedAuthorityOperation {
    pub(crate) const fn is_complete(&self) -> bool {
        self.issuance_ack.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityOperationIssuerRejection {
    Poisoned,
    InvalidCall,
    InvalidApproval,
    WrongRoute,
    WrongSigner,
    InvalidIssuedAt,
    InvalidApplication,
    MissingIssuance,
    IssuanceSlotRegressed,
    ApplicationSlotRegressed,
    DivergentRetry,
    InvocationCollision,
    AuthorizationSequenceCollision,
    PendingOperation,
    PendingApplication,
    JournalFull,
}

/// Open or issuance error. `Signer` remains uninhabited while opening.
#[derive(Debug)]
pub enum AuthorityOperationIssuerError<StorageError, SignerError = Infallible> {
    Storage(StorageError),
    Signer(SignerError),
    InvalidState,
    Rejected(AuthorityOperationIssuerRejection),
}

impl<StorageError: fmt::Display, SignerError: fmt::Display> fmt::Display
    for AuthorityOperationIssuerError<StorageError, SignerError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => {
                write!(formatter, "authority operation issuer storage: {error}")
            }
            Self::Signer(error) => write!(formatter, "authority operation issuer signer: {error}"),
            Self::InvalidState => formatter.write_str("invalid authority operation issuer state"),
            Self::Rejected(error) => {
                write!(formatter, "authority operation issuer rejected: {error:?}")
            }
        }
    }
}

impl<StorageError, SignerError> core::error::Error
    for AuthorityOperationIssuerError<StorageError, SignerError>
where
    StorageError: core::error::Error + 'static,
    SignerError: core::error::Error + 'static,
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedOperation {
    call: Vec<u8>,
    approval: Vec<u8>,
    issued_at: u64,
    receipt: Option<Vec<u8>>,
    issuance_ack: Option<Vec<u8>>,
    application: Option<PrivateControlApplicationFact>,
    application_ack: Option<Vec<u8>>,
}

impl RetainedOperation {
    fn is_complete(&self) -> bool {
        self.issuance_ack.is_some()
    }

    fn has_valid_envelope(&self) -> bool {
        self.call.len() <= MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES
            && self.approval.len() <= MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES
            && self
                .receipt
                .as_ref()
                .is_none_or(|bytes| bytes.len() <= MAX_AUTHORITY_RECEIPT_WIRE_BYTES)
            && self
                .issuance_ack
                .as_ref()
                .is_none_or(|bytes| bytes.len() <= MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES)
            && self
                .application_ack
                .as_ref()
                .is_none_or(|bytes| bytes.len() <= MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES)
            && (self.issuance_ack.is_none() || self.receipt.is_some())
            && (self.application.is_none() || self.issuance_ack.is_some())
            && (self.application_ack.is_none() || self.application.is_some())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthorityOperationIssuerImage {
    authority: AuthorityActorTarget,
    issuance_slot_high_water: Option<u64>,
    application_slot_high_water: Option<u64>,
    records: Vec<RetainedOperation>,
}

impl AuthorityOperationIssuerImage {
    fn empty(authority: AuthorityActorTarget) -> Self {
        Self {
            authority,
            issuance_slot_high_water: None,
            application_slot_high_water: None,
            records: Vec::new(),
        }
    }

    fn has_valid_envelope(&self) -> bool {
        let application_slot_high_water = self
            .records
            .iter()
            .filter_map(|record| record.application.as_ref())
            .map(|application| application.applied_at)
            .max();
        if !self.authority.is_valid()
            || self.records.len() > MAX_AUTHORITY_OPERATION_ISSUER_RECORDS
            || (self.records.is_empty() != self.issuance_slot_high_water.is_none())
            || self.records.last().map(|record| record.issued_at) != self.issuance_slot_high_water
            || self.application_slot_high_water != application_slot_high_water
            || self
                .records
                .iter()
                .any(|record| !record.has_valid_envelope())
            || self
                .records
                .iter()
                .filter(|record| record.application.is_some() && record.application_ack.is_none())
                .count()
                > 1
        {
            return false;
        }
        self.records
            .iter()
            .enumerate()
            .all(|(index, record)| record.is_complete() || index + 1 == self.records.len())
    }

    fn is_valid(&self) -> bool {
        if !self.has_valid_envelope() {
            return false;
        }
        let verifier = RawEd25519Verifier;
        let mut invocation_ids = Vec::new();
        let mut sequences = Vec::new();
        let mut previous_issued_at = None;
        for record in &self.records {
            let Ok(call) = AuthorityOperationCall::decode(&record.call) else {
                return false;
            };
            let Ok(approval) = AuthorityOperationApproval::decode(&record.approval) else {
                return false;
            };
            if call.encode().ok().as_deref() != Some(record.call.as_slice())
                || approval.encode().ok().as_deref() != Some(record.approval.as_slice())
                || call.verify_with(&verifier).is_err()
                || call.authority != self.authority
                || approval.authority != self.authority
                || !approval.matches_call(&call)
                || !approval.selector.is_live_at(record.issued_at)
                || sequences.contains(&approval.authorization_sequence.get())
                || previous_issued_at.is_some_and(|previous| previous > record.issued_at)
            {
                return false;
            }
            if !push_unique_invocation(&mut invocation_ids, call.invocation)
                || !push_unique_invocation(&mut invocation_ids, approval.acknowledgement_invocation)
            {
                return false;
            }
            previous_issued_at = Some(record.issued_at);
            sequences.push(approval.authorization_sequence.get());

            let receipt = match &record.receipt {
                Some(bytes) => {
                    let Ok(receipt) = AuthorityReceipt::decode(bytes) else {
                        return false;
                    };
                    if receipt.encode().ok().as_deref() != Some(bytes.as_slice())
                        || approval
                            .verify_receipt_at(&receipt, record.issued_at, &verifier)
                            .is_err()
                    {
                        return false;
                    }
                    Some(receipt)
                }
                None => None,
            };
            let issuance = match (&record.issuance_ack, receipt.as_ref()) {
                (Some(bytes), Some(receipt)) => {
                    let Ok(ack) = AuthorityOperationIssuanceAck::decode(bytes) else {
                        return false;
                    };
                    if ack.encode().ok().as_deref() != Some(bytes.as_slice())
                        || &ack.receipt != receipt
                        || !ack.matches_pending(&call, &approval)
                        || ack.verify_with(self.authority.binding, &verifier).is_err()
                    {
                        return false;
                    }
                    Some(ack)
                }
                (None, _) => None,
                (Some(_), None) => return false,
            };
            if let Some(issuance) = issuance.as_ref() {
                if is_private_intent(&call.intent)
                    && !push_unique_invocation(
                        &mut invocation_ids,
                        PrivateControlApplicationAck::derive_application_invocation(issuance),
                    )
                {
                    return false;
                }
            }
            match (
                &record.application,
                &record.application_ack,
                issuance.as_ref(),
            ) {
                (None, None, _) => {}
                (Some(application), None, Some(issuance)) => {
                    if !private_intent_matches_application(&call.intent, application)
                        || application.applied_at < issuance.issued_at
                        || !issuance.receipt.selector.is_live_at(application.applied_at)
                    {
                        return false;
                    }
                }
                (Some(application), Some(bytes), Some(issuance)) => {
                    let Ok(ack) = PrivateControlApplicationAck::decode(bytes) else {
                        return false;
                    };
                    if ack.encode().ok().as_deref() != Some(bytes.as_slice())
                        || !ack.matches_pending(&call, &approval, issuance, application)
                        || ack
                            .verify_pending_with(
                                &call,
                                &approval,
                                issuance,
                                application,
                                self.authority.binding,
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
        true
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&AUTHORITY_OPERATION_ISSUER_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        encode_authority_target(&mut encoder, self.authority);
        encoder.option(&self.issuance_slot_high_water, |encoder, slot| {
            encoder.u64(*slot)
        });
        encoder.option(&self.application_slot_high_water, |encoder, slot| {
            encoder.u64(*slot)
        });
        encoder.list(&self.records, |encoder, record| {
            encoder.bytes(&record.call);
            encoder.bytes(&record.approval);
            encoder.u64(record.issued_at);
            encoder.option(&record.receipt, |encoder, value| encoder.bytes(value));
            encoder.option(&record.issuance_ack, |encoder, value| encoder.bytes(value));
            encoder.option(&record.application, encode_application_fact);
            encoder.option(&record.application_ack, |encoder, value| {
                encoder.bytes(value)
            });
        });
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(AUTHORITY_OPERATION_ISSUER_MAGIC.len())? != AUTHORITY_OPERATION_ISSUER_MAGIC
        {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != crate::agent::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let authority = decode_authority_target(&mut decoder)?;
        let issuance_slot_high_water = decoder.option(Decoder::u64)?;
        let application_slot_high_water = decoder.option(Decoder::u64)?;
        let record_count = decoder.u32()? as usize;
        if record_count > MAX_AUTHORITY_OPERATION_ISSUER_RECORDS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = Vec::new();
        records
            .try_reserve(record_count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..record_count {
            records.push(RetainedOperation {
                call: decoder.bytes_bounded(MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES)?,
                approval: decoder.bytes_bounded(MAX_AUTHORITY_OPERATION_APPROVAL_WIRE_BYTES)?,
                issued_at: decoder.u64()?,
                receipt: decoder
                    .option(|decoder| decoder.bytes_bounded(MAX_AUTHORITY_RECEIPT_WIRE_BYTES))?,
                issuance_ack: decoder.option(|decoder| {
                    decoder.bytes_bounded(MAX_AUTHORITY_OPERATION_ISSUANCE_ACK_WIRE_BYTES)
                })?,
                application: decoder.option(decode_application_fact)?,
                application_ack: decoder.option(|decoder| {
                    decoder.bytes_bounded(MAX_PRIVATE_CONTROL_APPLICATION_ACK_WIRE_BYTES)
                })?,
            });
        }
        let image = Self {
            authority,
            issuance_slot_high_water,
            application_slot_high_water,
            records,
        };
        if !decoder.exhausted() || !image.is_valid() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(image)
    }
}

/// Durable issuer for the AOC1 -> AOP1 -> receipt -> AOI1 boundary.
///
/// One image belongs to exactly one independently configured authority actor
/// target. The route encoded by caller-controlled protocol values is never
/// accepted as its own trust anchor.
pub struct DurableAuthorityOperationIssuer<B: AuthorityOperationIssuerStore> {
    store: B,
    image: AuthorityOperationIssuerImage,
    poisoned: bool,
}

impl<B: AuthorityOperationIssuerStore> DurableAuthorityOperationIssuer<B> {
    pub fn open(
        mut store: B,
        authority: AuthorityActorTarget,
    ) -> Result<Self, AuthorityOperationIssuerError<B::Error>> {
        if !authority.is_valid() {
            return Err(AuthorityOperationIssuerError::InvalidState);
        }
        let image = match store
            .load()
            .map_err(AuthorityOperationIssuerError::Storage)?
        {
            Some(bytes) => {
                let image = AuthorityOperationIssuerImage::decode(&bytes)
                    .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
                if image.authority != authority || image.encode() != bytes {
                    return Err(AuthorityOperationIssuerError::InvalidState);
                }
                image
            }
            None => AuthorityOperationIssuerImage::empty(authority),
        };
        Ok(Self {
            store,
            image,
            poisoned: false,
        })
    }

    pub const fn authority(&self) -> AuthorityActorTarget {
        self.image.authority
    }

    /// Exact records retained because AOI1 consumption is not yet observable.
    pub fn retained_operations(&self) -> usize {
        self.image.records.len()
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn has_pending_operation(&self) -> bool {
        self.image
            .records
            .last()
            .is_some_and(|record| !record.is_complete())
    }

    pub fn has_pending_application(&self) -> bool {
        self.image
            .records
            .iter()
            .any(|record| record.application.is_some() && record.application_ack.is_none())
    }

    pub(crate) fn retained_private_applications(&self) -> usize {
        self.image
            .records
            .iter()
            .filter(|record| record.application.is_some())
            .count()
    }

    pub fn into_store(self) -> B {
        self.store
    }

    /// Reopen exact retained preimages before a coordinator considers calling
    /// the authority actor again. In particular, a completed record must
    /// drive an AOI1 retry directly because the actor intentionally cannot
    /// reconstruct AOP1 after consuming that acknowledgement.
    pub(crate) fn recover_retained(
        &self,
        authorization_invocation: InvocationId,
    ) -> Result<Option<RetainedAuthorityOperation>, AuthorityOperationIssuerError<B::Error>> {
        let Some(record) = self.image.records.iter().find(|record| {
            AuthorityOperationCall::decode(&record.call)
                .is_ok_and(|call| call.invocation == authorization_invocation)
        }) else {
            return Ok(None);
        };
        let call = AuthorityOperationCall::decode(&record.call)
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let approval = AuthorityOperationApproval::decode(&record.approval)
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let receipt = record
            .receipt
            .as_ref()
            .map(|bytes| AuthorityReceipt::decode(bytes))
            .transpose()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let issuance_ack = record
            .issuance_ack
            .as_ref()
            .map(|bytes| AuthorityOperationIssuanceAck::decode(bytes))
            .transpose()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let application_ack = record
            .application_ack
            .as_ref()
            .map(|bytes| PrivateControlApplicationAck::decode(bytes))
            .transpose()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        Ok(Some(RetainedAuthorityOperation {
            call,
            approval,
            issued_at: record.issued_at,
            receipt,
            issuance_ack,
            application: record.application,
            application_ack,
        }))
    }

    /// Issue and retain exact receipt evidence for one actor-approved call.
    ///
    /// The caller supplies the logical issuance slot; it is pledged with the
    /// exact AOC1/AOP1 before any signature callback. The receipt is then
    /// committed before AOI1 is constructed or signed. A completed exact
    /// retry returns the retained values without inspecting `signer`.
    /// This entrypoint is crate-private because AOP1 is deliberately unsigned:
    /// only the trusted local actor-dispatch coordinator may pass the exact
    /// AOP1 returned by the configured authority actor transition. Shape and
    /// call matching are necessary substitution checks, not policy proof.
    pub(crate) fn issue<S: AuthorityOperationEvidenceSigner>(
        &mut self,
        call: &AuthorityOperationCall,
        approval: &AuthorityOperationApproval,
        issued_at: u64,
        signer: &mut S,
    ) -> Result<IssuedAuthorityOperation, AuthorityOperationIssuerError<B::Error, S::Error>> {
        self.ensure_live()?;
        let verifier = RawEd25519Verifier;
        if call.verify_with(&verifier).is_err() {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidCall,
            ));
        }
        if approval.validate_shape().is_err() || !approval.matches_call(call) {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidApproval,
            ));
        }
        if call.authority != self.image.authority || approval.authority != self.image.authority {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongRoute,
            ));
        }
        if !approval.selector.is_live_at(issued_at) {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidIssuedAt,
            ));
        }
        let call_bytes = call
            .encode()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let approval_bytes = approval
            .encode()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;

        let existing_index = self.image.records.iter().position(|record| {
            AuthorityOperationCall::decode(&record.call)
                .is_ok_and(|retained| retained.invocation == call.invocation)
        });
        let record_index = if let Some(index) = existing_index {
            let record = &self.image.records[index];
            if record.call != call_bytes
                || record.approval != approval_bytes
                || record.issued_at != issued_at
            {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::DivergentRetry,
                ));
            }
            if record.is_complete() {
                return decode_completed(record).ok_or(AuthorityOperationIssuerError::InvalidState);
            }
            index
        } else {
            if self.has_pending_operation() {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::PendingOperation,
                ));
            }
            if self.image.records.len() == MAX_AUTHORITY_OPERATION_ISSUER_RECORDS {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::JournalFull,
                ));
            }
            if self
                .image
                .issuance_slot_high_water
                .is_some_and(|high_water| issued_at < high_water)
            {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::IssuanceSlotRegressed,
                ));
            }
            if self.image.records.iter().any(|record| {
                retained_invocations(record).is_none_or(|invocations| {
                    invocations.contains(&call.invocation)
                        || invocations.contains(&approval.acknowledgement_invocation)
                })
            }) {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::InvocationCollision,
                ));
            }
            if self.image.records.iter().any(|record| {
                retained_identity(record).is_none_or(|(_, _, sequence)| {
                    sequence == approval.authorization_sequence.get()
                })
            }) {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::AuthorizationSequenceCollision,
                ));
            }
            if signer.public_key() != self.image.authority.binding.public_key {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::WrongSigner,
                ));
            }
            let mut pledged = self.image.clone();
            pledged.issuance_slot_high_water = Some(issued_at);
            pledged.records.push(RetainedOperation {
                call: call_bytes,
                approval: approval_bytes,
                issued_at,
                receipt: None,
                issuance_ack: None,
                application: None,
                application_ack: None,
            });
            self.commit_candidate::<S::Error>(pledged)?;
            self.image.records.len() - 1
        };

        let receipt = match self.image.records[record_index].receipt.as_ref() {
            Some(bytes) => AuthorityReceipt::decode(bytes)
                .map_err(|_| AuthorityOperationIssuerError::InvalidState)?,
            None => {
                if signer.public_key() != self.image.authority.binding.public_key {
                    return Err(AuthorityOperationIssuerError::Rejected(
                        AuthorityOperationIssuerRejection::WrongSigner,
                    ));
                }
                let mut receipt = AuthorityReceipt {
                    selector: approval.selector.clone(),
                    public_key: self.image.authority.binding.public_key,
                    signature: [0; 64],
                };
                let message = receipt.signing_bytes();
                receipt.signature = signer
                    .sign_authority_receipt(&message)
                    .map_err(AuthorityOperationIssuerError::Signer)?;
                if approval
                    .verify_receipt_at(&receipt, issued_at, &verifier)
                    .is_err()
                {
                    return Err(AuthorityOperationIssuerError::Rejected(
                        AuthorityOperationIssuerRejection::WrongSigner,
                    ));
                }
                let receipt_bytes = receipt
                    .encode()
                    .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
                let mut completed_receipt = self.image.clone();
                completed_receipt.records[record_index].receipt = Some(receipt_bytes);
                self.commit_candidate::<S::Error>(completed_receipt)?;
                receipt
            }
        };

        if let Some(bytes) = self.image.records[record_index].issuance_ack.as_ref() {
            let issuance_ack = AuthorityOperationIssuanceAck::decode(bytes)
                .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
            return Ok(IssuedAuthorityOperation {
                receipt,
                issuance_ack,
            });
        }
        if signer.public_key() != self.image.authority.binding.public_key {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner,
            ));
        }
        // This value is deliberately constructed only after the receipt and
        // issuance slot above were durably committed together.
        let mut issuance_ack = AuthorityOperationIssuanceAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: self.image.authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt: receipt.clone(),
            issued_at,
            signature: [0; 64],
        };
        let message = issuance_ack.signing_bytes();
        issuance_ack.signature = signer
            .sign_issuance_ack(&message)
            .map_err(AuthorityOperationIssuerError::Signer)?;
        if !issuance_ack.matches_pending(call, approval)
            || issuance_ack
                .verify_with(self.image.authority.binding, &verifier)
                .is_err()
        {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner,
            ));
        }
        if is_private_intent(&call.intent) {
            let application_invocation =
                PrivateControlApplicationAck::derive_application_invocation(&issuance_ack);
            if application_invocation == call.invocation
                || application_invocation == approval.acknowledgement_invocation
                || self
                    .image
                    .records
                    .iter()
                    .enumerate()
                    .any(|(index, record)| {
                        index != record_index
                            && retained_invocations(record).is_none_or(|invocations| {
                                invocations.contains(&application_invocation)
                            })
                    })
            {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::InvocationCollision,
                ));
            }
        }
        let acknowledgement_bytes = issuance_ack
            .encode()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let mut completed = self.image.clone();
        completed.records[record_index].issuance_ack = Some(acknowledgement_bytes);
        self.commit_candidate::<S::Error>(completed)?;
        Ok(IssuedAuthorityOperation {
            receipt,
            issuance_ack,
        })
    }

    /// Sign PCA1 only from an exact Private application observation which was
    /// pledged after this issuer had durably retained the complete AOI1.
    ///
    /// This raw fact entrypoint is crate-private. A fact is not authenticated
    /// merely because its fields match an AOC1; only the trusted Private
    /// runtime coordinator may pass the exact echoed result of a durable
    /// apply-and-reopen transition. Exact completed retries return retained
    /// PCA1 without consulting the signer.
    pub(crate) fn issue_private_application<S: PrivateControlApplicationEvidenceSigner>(
        &mut self,
        authorization_invocation: InvocationId,
        application: &PrivateControlApplicationFact,
        signer: &mut S,
    ) -> Result<IssuedPrivateControlApplication, AuthorityOperationIssuerError<B::Error, S::Error>>
    {
        self.ensure_live()?;
        let Some(record_index) = self.image.records.iter().position(|record| {
            AuthorityOperationCall::decode(&record.call)
                .is_ok_and(|call| call.invocation == authorization_invocation)
        }) else {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::MissingIssuance,
            ));
        };
        let record = &self.image.records[record_index];
        let call = AuthorityOperationCall::decode(&record.call)
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let approval = AuthorityOperationApproval::decode(&record.approval)
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let issuance = record
            .issuance_ack
            .as_ref()
            .ok_or(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::MissingIssuance,
            ))
            .and_then(|bytes| {
                AuthorityOperationIssuanceAck::decode(bytes)
                    .map_err(|_| AuthorityOperationIssuerError::InvalidState)
            })?;
        let verifier = RawEd25519Verifier;
        if call.authority != self.image.authority
            || approval.authority != self.image.authority
            || issuance.authority != self.image.authority
        {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongRoute,
            ));
        }
        if call.verify_with(&verifier).is_err()
            || !issuance.matches_pending(&call, &approval)
            || issuance
                .verify_with(self.image.authority.binding, &verifier)
                .is_err()
        {
            return Err(AuthorityOperationIssuerError::InvalidState);
        }
        if application.validate_shape().is_err()
            || !private_intent_matches_application(&call.intent, application)
            || application.applied_at < issuance.issued_at
            || !issuance.receipt.selector.is_live_at(application.applied_at)
        {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidApplication,
            ));
        }
        let application_invocation =
            PrivateControlApplicationAck::derive_application_invocation(&issuance);
        if application_invocation == call.invocation
            || application_invocation == issuance.acknowledgement_invocation
            || self
                .image
                .records
                .iter()
                .enumerate()
                .any(|(index, record)| {
                    index != record_index
                        && retained_invocations(record)
                            .is_none_or(|invocations| invocations.contains(&application_invocation))
                })
        {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvocationCollision,
            ));
        }

        match self.image.records[record_index].application.as_ref() {
            Some(retained) if retained != application => {
                return Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::DivergentRetry,
                ));
            }
            Some(_) => {
                if let Some(bytes) = self.image.records[record_index].application_ack.as_ref() {
                    let application_ack = PrivateControlApplicationAck::decode(bytes)
                        .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
                    return Ok(IssuedPrivateControlApplication { application_ack });
                }
            }
            None => {
                if self.has_pending_application() {
                    return Err(AuthorityOperationIssuerError::Rejected(
                        AuthorityOperationIssuerRejection::PendingApplication,
                    ));
                }
                if self
                    .image
                    .application_slot_high_water
                    .is_some_and(|slot| application.applied_at < slot)
                {
                    return Err(AuthorityOperationIssuerError::Rejected(
                        AuthorityOperationIssuerRejection::ApplicationSlotRegressed,
                    ));
                }
                if signer.public_key() != self.image.authority.binding.public_key {
                    return Err(AuthorityOperationIssuerError::Rejected(
                        AuthorityOperationIssuerRejection::WrongSigner,
                    ));
                }
                let mut pledged = self.image.clone();
                pledged.application_slot_high_water = Some(application.applied_at);
                pledged.records[record_index].application = Some(*application);
                self.commit_candidate::<S::Error>(pledged)?;
            }
        }

        if signer.public_key() != self.image.authority.binding.public_key {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner,
            ));
        }
        let mut application_ack = PrivateControlApplicationAck {
            authorization_invocation: call.invocation,
            issuance_invocation: issuance.acknowledgement_invocation,
            application_invocation,
            authority: self.image.authority,
            operation_call: call.commitment(),
            approval: approval.commitment(),
            issuance_ack: issuance.commitment(),
            authorization_sequence: approval.authorization_sequence,
            receipt: issuance.receipt.clone(),
            issued_at: issuance.issued_at,
            application: *application,
            signature: [0; 64],
        };
        let message = application_ack.signing_bytes();
        application_ack.signature = signer
            .sign_private_application_ack(&message)
            .map_err(AuthorityOperationIssuerError::Signer)?;
        if !application_ack.matches_pending(&call, &approval, &issuance, application)
            || application_ack
                .verify_pending_with(
                    &call,
                    &approval,
                    &issuance,
                    application,
                    self.image.authority.binding,
                    &verifier,
                )
                .is_err()
        {
            return Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner,
            ));
        }
        let application_ack_bytes = application_ack
            .encode()
            .map_err(|_| AuthorityOperationIssuerError::InvalidState)?;
        let mut completed = self.image.clone();
        completed.records[record_index].application_ack = Some(application_ack_bytes);
        self.commit_candidate::<S::Error>(completed)?;
        Ok(IssuedPrivateControlApplication { application_ack })
    }

    fn ensure_live<SignerError>(
        &self,
    ) -> Result<(), AuthorityOperationIssuerError<B::Error, SignerError>> {
        if self.poisoned {
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::Poisoned,
            ))
        } else {
            Ok(())
        }
    }

    fn commit_candidate<SignerError>(
        &mut self,
        candidate: AuthorityOperationIssuerImage,
    ) -> Result<(), AuthorityOperationIssuerError<B::Error, SignerError>> {
        if !candidate.has_valid_envelope() {
            self.poisoned = true;
            return Err(AuthorityOperationIssuerError::InvalidState);
        }
        let bytes = candidate.encode();
        if bytes.len() > MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES {
            self.poisoned = true;
            return Err(AuthorityOperationIssuerError::InvalidState);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(AuthorityOperationIssuerError::Storage(error));
        }
        self.image = candidate;
        Ok(())
    }
}

fn retained_identity(record: &RetainedOperation) -> Option<(InvocationId, InvocationId, u64)> {
    let call = AuthorityOperationCall::decode(&record.call).ok()?;
    let approval = AuthorityOperationApproval::decode(&record.approval).ok()?;
    Some((
        call.invocation,
        approval.acknowledgement_invocation,
        approval.authorization_sequence.get(),
    ))
}

fn retained_invocations(record: &RetainedOperation) -> Option<Vec<InvocationId>> {
    let call = AuthorityOperationCall::decode(&record.call).ok()?;
    let approval = AuthorityOperationApproval::decode(&record.approval).ok()?;
    let mut invocations = vec![call.invocation, approval.acknowledgement_invocation];
    if is_private_intent(&call.intent) {
        if let Some(bytes) = record.issuance_ack.as_ref() {
            let issuance = AuthorityOperationIssuanceAck::decode(bytes).ok()?;
            invocations.push(PrivateControlApplicationAck::derive_application_invocation(
                &issuance,
            ));
        }
    }
    Some(invocations)
}

fn push_unique_invocation(invocations: &mut Vec<InvocationId>, invocation: InvocationId) -> bool {
    if invocation == InvocationId::ZERO || invocations.contains(&invocation) {
        return false;
    }
    invocations.push(invocation);
    true
}

fn is_private_intent(intent: &AuthorityOperationIntent) -> bool {
    matches!(
        intent,
        AuthorityOperationIntent::InvitePrivateNode { .. }
            | AuthorityOperationIntent::RevokePrivateNode { .. }
            | AuthorityOperationIntent::RecoverPrivateAgent { .. }
            | AuthorityOperationIntent::RotatePrivateKeys { .. }
            | AuthorityOperationIntent::SetPrivateResourcePolicy { .. }
            | AuthorityOperationIntent::PrivateActorLifecycle { .. }
    )
}

pub(crate) fn private_intent_matches_application(
    intent: &AuthorityOperationIntent,
    application: &PrivateControlApplicationFact,
) -> bool {
    if application.validate_shape().is_err() {
        return false;
    }
    match intent {
        AuthorityOperationIntent::InvitePrivateNode {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            ..
        } => {
            application.managed == *managed
                && application.operation == AuthorityOperationKind::InvitePrivateNode
                && application.control == *control
                && application.control_sequence == *control_sequence
                && application.control_previous == *control_previous
                && application.epoch == *epoch
        }
        AuthorityOperationIntent::RevokePrivateNode {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
            ..
        }
        | AuthorityOperationIntent::RecoverPrivateAgent {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
            ..
        } => {
            application.managed == *managed
                && application.operation == intent.operation()
                && application.control == *control
                && application.control_sequence == *control_sequence
                && application.control_previous == *control_previous
                && application.epoch == *epoch
                && application.post_member_set == *member_set
        }
        AuthorityOperationIntent::RotatePrivateKeys {
            managed,
            control,
            control_sequence,
            control_previous,
            epoch,
            member_set,
        } => {
            application.managed == *managed
                && application.operation == AuthorityOperationKind::RotatePrivateKeys
                && application.control == *control
                && application.control_sequence == *control_sequence
                && application.control_previous == *control_previous
                && application.epoch == *epoch
                && application.post_member_set == *member_set
        }
        AuthorityOperationIntent::SetPrivateResourcePolicy {
            managed,
            control,
            control_sequence,
            control_previous,
            ..
        }
        | AuthorityOperationIntent::PrivateActorLifecycle {
            managed,
            control,
            control_sequence,
            control_previous,
            ..
        } => {
            application.managed == *managed
                && application.operation == intent.operation()
                && application.control == *control
                && application.control_sequence == *control_sequence
                && application.control_previous == *control_previous
        }
        AuthorityOperationIntent::InvokeActor { .. } | AuthorityOperationIntent::Catalog { .. } => {
            false
        }
    }
}

fn encode_application_fact(encoder: &mut Encoder<'_>, application: &PrivateControlApplicationFact) {
    encode_managed_target(encoder, application.managed);
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
}

fn decode_application_fact(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateControlApplicationFact, DecodeError> {
    let application = PrivateControlApplicationFact {
        managed: decode_managed_target(decoder)?,
        operation: match decoder.u8()? {
            value if value == AuthorityOperationKind::InvitePrivateNode as u8 => {
                AuthorityOperationKind::InvitePrivateNode
            }
            value if value == AuthorityOperationKind::RevokePrivateNode as u8 => {
                AuthorityOperationKind::RevokePrivateNode
            }
            value if value == AuthorityOperationKind::RecoverPrivateAgent as u8 => {
                AuthorityOperationKind::RecoverPrivateAgent
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
    application
        .validate_shape()
        .is_ok()
        .then_some(application)
        .ok_or(DecodeError::NonCanonical)
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

fn decode_completed(record: &RetainedOperation) -> Option<IssuedAuthorityOperation> {
    Some(IssuedAuthorityOperation {
        receipt: AuthorityReceipt::decode(record.receipt.as_ref()?).ok()?,
        issuance_ack: AuthorityOperationIssuanceAck::decode(record.issuance_ack.as_ref()?).ok()?,
    })
}

struct RawEd25519Verifier;

impl AuthorityCredentialVerifier for RawEd25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        crate::agent::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

impl AuthorityVerifier for RawEd25519Verifier {
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
    use crate::agent::sdk::authority::{
        AUTHORITY_SIGNATURE_BYTES, AuthorityEvidence, AuthorityLaneRoots,
        CREDENTIAL_SIGNATURE_BYTES,
    };
    use crate::agent::sdk::authority_operation::AuthorityOperationIntent;
    use crate::agent::sdk::private::{
        PRIVATE_SIGNATURE_BYTES, PrivateControlOperation, PrivateControlRecord,
        PrivateControlSigner, PrivateNodeIdentity, SealedPrivateKey,
    };
    use crate::agent::sdk::{
        CredentialId, InvocationOrigin, InvocationRoleClaims, InvocationWork, MethodMode, NodeId,
        RuntimeBlob,
    };

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
    }

    impl AuthorityOperationIssuerStore for MemoryImageStore {
        type Error = MemoryStoreError;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            let mut state = self.inner.lock().unwrap();
            if state.fail_load {
                state.fail_load = false;
                return Err(MemoryStoreError);
            }
            Ok(state.image.clone())
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
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
        application_calls: usize,
        fail_receipt: bool,
        fail_acknowledgement: bool,
        corrupt_receipt: bool,
        corrupt_acknowledgement: bool,
        fail_application: bool,
        corrupt_application: bool,
    }

    impl CountingSigner {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                receipt_calls: 0,
                acknowledgement_calls: 0,
                application_calls: 0,
                fail_receipt: false,
                fail_acknowledgement: false,
                corrupt_receipt: false,
                corrupt_acknowledgement: false,
                fail_application: false,
                corrupt_application: false,
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
            let mut signature = self.key.sign(message).to_bytes();
            if self.corrupt_receipt {
                signature[0] ^= 1;
            }
            Ok(signature)
        }

        fn sign_issuance_ack(&mut self, message: &[u8]) -> Result<[u8; 64], Self::Error> {
            self.acknowledgement_calls += 1;
            if self.fail_acknowledgement {
                self.fail_acknowledgement = false;
                return Err(TestSignerError);
            }
            let mut signature = self.key.sign(message).to_bytes();
            if self.corrupt_acknowledgement {
                signature[0] ^= 1;
            }
            Ok(signature)
        }
    }

    impl PrivateControlApplicationEvidenceSigner for CountingSigner {
        type Error = TestSignerError;

        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }

        fn sign_private_application_ack(
            &mut self,
            message: &[u8],
        ) -> Result<[u8; 64], Self::Error> {
            self.application_calls += 1;
            if self.fail_application {
                self.fail_application = false;
                return Err(TestSignerError);
            }
            let mut signature = self.key.sign(message).to_bytes();
            if self.corrupt_application {
                signature[0] ^= 1;
            }
            Ok(signature)
        }
    }

    struct Fixture {
        authority: AuthorityActorTarget,
        credential_key: SigningKey,
    }

    impl Fixture {
        fn new(authority_signer: &CountingSigner) -> Self {
            let public_key = authority_signer.key.verifying_key().to_bytes();
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

        fn approved(
            &self,
            discriminator: u64,
            authorization_sequence: u64,
        ) -> (AuthorityOperationCall, AuthorityOperationApproval) {
            self.approved_with_invocation(discriminator, authorization_sequence, InvocationId::ZERO)
        }

        fn approved_with_invocation(
            &self,
            discriminator: u64,
            authorization_sequence: u64,
            authorization_invocation: InvocationId,
        ) -> (AuthorityOperationCall, AuthorityOperationApproval) {
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
                requested_expires_at: 30,
                intent: AuthorityOperationIntent::invoke(&work).unwrap(),
                signature: [0; CREDENTIAL_SIGNATURE_BYTES],
            };
            if call.invocation == InvocationId::ZERO {
                call.invocation = call.expected_invocation();
            }
            call.signature = self.credential_key.sign(&call.signing_bytes()).to_bytes();
            let approval = AuthorityOperationApproval::from_call(
                &call,
                core::num::NonZeroU64::new(authorization_sequence).unwrap(),
                AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash(id(0x44, discriminator)),
                },
                AuthorityLaneRoots {
                    control: Some(Hash(id(0x45, discriminator))),
                    linear: Some(Hash(id(0x46, discriminator))),
                    merge: None,
                    local: None,
                },
                3,
                12,
                28,
            )
            .unwrap();
            (call, approval)
        }

        fn approved_private(
            &self,
            discriminator: u64,
            authorization_sequence: u64,
            control: &PrivateControlRecord,
        ) -> (AuthorityOperationCall, AuthorityOperationApproval) {
            let credential_public_key = self.credential_key.verifying_key().to_bytes();
            let principal = PrincipalId(id(0x22, 1));
            let credential = CredentialId::of_public_key(&credential_public_key);
            let node = NodeId(id(0x23, 1));
            let mut call = AuthorityOperationCall {
                invocation: InvocationId::ZERO,
                authority: self.authority,
                principal,
                credential,
                request_sequence: core::num::NonZeroU64::new(discriminator).unwrap(),
                credential_public_key,
                authenticated_node: Some(node),
                requested_valid_from: 10,
                requested_expires_at: 40,
                intent: AuthorityOperationIntent::private_control(
                    DeploymentId(id(0x82, discriminator)),
                    control,
                )
                .unwrap(),
                signature: [0; CREDENTIAL_SIGNATURE_BYTES],
            };
            call.invocation = call.expected_invocation();
            call.signature = self.credential_key.sign(&call.signing_bytes()).to_bytes();
            let approval = AuthorityOperationApproval::from_call(
                &call,
                core::num::NonZeroU64::new(authorization_sequence).unwrap(),
                AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash(id(0x83, discriminator)),
                },
                AuthorityLaneRoots {
                    control: Some(Hash(id(0x84, discriminator))),
                    linear: Some(Hash(id(0x85, discriminator))),
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

    fn id(prefix: u8, number: u64) -> [u8; 32] {
        let mut value = [prefix; 32];
        value[24..].copy_from_slice(&number.to_le_bytes());
        value
    }

    fn private_control(fixture: &Fixture, discriminator: u64) -> PrivateControlRecord {
        let transport_identity = discriminator.to_le_bytes().to_vec();
        let node = NodeId::of_authenticated_peer(&transport_identity);
        let identity = PrivateNodeIdentity {
            node,
            principal: PrincipalId(id(0x86, discriminator)),
            transport_identity,
            encryption_public_key: id(0x87, discriminator),
            authority_binding: Hash(id(0x88, discriminator)),
            transport_signature: [0x89; PRIVATE_SIGNATURE_BYTES],
        };
        let mut control = PrivateControlRecord {
            space: fixture.authority.space,
            agent: AgentId(id(0x8a, discriminator)),
            sequence: 1,
            previous: Some(Hash(id(0x8b, discriminator))),
            operation: PrivateControlOperation::Invite {
                node: identity,
                epoch: 2,
                sealed_owner_key: SealedPrivateKey {
                    node,
                    recipient_key: id(0x87, discriminator),
                    sealed: vec![0x8d; 48],
                },
                sealed_data_key: SealedPrivateKey {
                    node,
                    recipient_key: id(0x87, discriminator),
                    sealed: vec![0x8e; 48],
                },
                historical_grants: Vec::new(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; PRIVATE_SIGNATURE_BYTES],
        };
        let key = SigningKey::from_bytes(&id(0x8f, discriminator));
        control.signer_public_key = key.verifying_key().to_bytes();
        control.signature = [1; PRIVATE_SIGNATURE_BYTES];
        assert!(control.validate_shape());
        control.signature = key.sign(&control.signing_bytes()).to_bytes();
        control
    }

    fn private_application(
        call: &AuthorityOperationCall,
        applied_at: u64,
        discriminator: u64,
    ) -> PrivateControlApplicationFact {
        let AuthorityOperationIntent::InvitePrivateNode {
            control,
            control_sequence,
            control_previous,
            epoch,
            ..
        } = &call.intent
        else {
            panic!("Private Invite fixture")
        };
        PrivateControlApplicationFact {
            managed: call.intent.managed(),
            operation: call.intent.operation(),
            control: *control,
            control_sequence: *control_sequence,
            control_previous: *control_previous,
            epoch: *epoch,
            post_member_set: Hash(id(0x90, discriminator)),
            reopened_control_state: Hash(id(0x91, discriminator)),
            reopened_control_head: *control,
            applied_at,
        }
    }

    fn open(
        store: MemoryImageStore,
        fixture: &Fixture,
    ) -> DurableAuthorityOperationIssuer<MemoryImageStore> {
        DurableAuthorityOperationIssuer::open(store, fixture.authority).unwrap()
    }

    #[test]
    fn exact_retry_and_restart_return_retained_evidence_without_signing() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store.clone(), &fixture);

        let issued = issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        assert_eq!(store.commits(), 3);
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
        assert_eq!(issuer.retained_operations(), 1);
        assert!(!issuer.has_pending_operation());

        let mut unusable_signer = CountingSigner::new(0x7f);
        unusable_signer.fail_receipt = true;
        unusable_signer.fail_acknowledgement = true;
        assert_eq!(
            issuer
                .issue(&call, &approval, 20, &mut unusable_signer)
                .unwrap(),
            issued
        );
        assert_eq!(
            (
                unusable_signer.receipt_calls,
                unusable_signer.acknowledgement_calls
            ),
            (0, 0)
        );
        assert_eq!(store.commits(), 3);

        let mut reopened = open(store, &fixture);
        assert_eq!(
            reopened
                .issue(&call, &approval, 20, &mut unusable_signer)
                .unwrap(),
            issued
        );
        assert_eq!(
            (
                unusable_signer.receipt_calls,
                unusable_signer.acknowledgement_calls
            ),
            (0, 0)
        );
    }

    #[test]
    fn pledge_commit_failures_poison_and_reopen_at_the_exact_boundary() {
        for fail_after in [false, true] {
            let store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let (call, approval) = fixture.approved(1, 1);
            if fail_after {
                store.fail_after_commit(1);
            } else {
                store.fail_before_commit(1);
            }
            let mut issuer = open(store.clone(), &fixture);
            assert!(matches!(
                issuer.issue(&call, &approval, 20, &mut signer),
                Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
            ));
            assert!(issuer.is_poisoned());
            assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (0, 0));
            assert!(matches!(
                issuer.issue(&call, &approval, 20, &mut signer),
                Err(AuthorityOperationIssuerError::Rejected(
                    AuthorityOperationIssuerRejection::Poisoned
                ))
            ));

            let mut reopened = open(store, &fixture);
            assert_eq!(reopened.has_pending_operation(), fail_after);
            reopened.issue(&call, &approval, 20, &mut signer).unwrap();
            assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
        }
    }

    #[test]
    fn receipt_sign_and_commit_failpoints_resume_without_skipping_the_pledge() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store.clone(), &fixture);
        signer.fail_receipt = true;
        assert!(matches!(
            issuer.issue(&call, &approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Signer(TestSignerError))
        ));
        assert!(!issuer.is_poisoned());
        assert!(issuer.has_pending_operation());
        assert_eq!(store.commits(), 1);
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 0));
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (2, 1));

        for fail_after in [false, true] {
            let store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let (call, approval) = fixture.approved(1, 1);
            if fail_after {
                store.fail_after_commit(2);
            } else {
                store.fail_before_commit(2);
            }
            let mut issuer = open(store.clone(), &fixture);
            assert!(matches!(
                issuer.issue(&call, &approval, 20, &mut signer),
                Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
            ));
            assert!(issuer.is_poisoned());
            assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 0));

            let mut reopened = open(store, &fixture);
            reopened.issue(&call, &approval, 20, &mut signer).unwrap();
            assert_eq!(
                (signer.receipt_calls, signer.acknowledgement_calls),
                (if fail_after { 1 } else { 2 }, 1)
            );
        }
    }

    #[test]
    fn acknowledgement_sign_and_commit_failpoints_resume_from_the_receipt() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store.clone(), &fixture);
        signer.fail_acknowledgement = true;
        assert!(matches!(
            issuer.issue(&call, &approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Signer(TestSignerError))
        ));
        assert!(!issuer.is_poisoned());
        assert!(issuer.has_pending_operation());
        assert_eq!(store.commits(), 2);
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 2));

        for fail_after in [false, true] {
            let store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let (call, approval) = fixture.approved(1, 1);
            if fail_after {
                store.fail_after_commit(3);
            } else {
                store.fail_before_commit(3);
            }
            let mut issuer = open(store.clone(), &fixture);
            assert!(matches!(
                issuer.issue(&call, &approval, 20, &mut signer),
                Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
            ));
            assert!(issuer.is_poisoned());
            assert_eq!((signer.receipt_calls, signer.acknowledgement_calls), (1, 1));

            let mut reopened = open(store, &fixture);
            reopened.issue(&call, &approval, 20, &mut signer).unwrap();
            assert_eq!(
                (signer.receipt_calls, signer.acknowledgement_calls),
                (1, if fail_after { 1 } else { 2 })
            );
        }
    }

    #[test]
    fn invalid_calls_approvals_routes_slots_and_signers_fail_closed() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store.clone(), &fixture);

        let mut forged_call = call.clone();
        forged_call.signature[0] ^= 1;
        assert!(matches!(
            issuer.issue(&forged_call, &approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidCall
            ))
        ));
        let (_, unrelated_approval) = fixture.approved(2, 2);
        assert!(matches!(
            issuer.issue(&call, &unrelated_approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidApproval
            ))
        ));
        assert!(matches!(
            issuer.issue(&call, &approval, 11, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidIssuedAt
            ))
        ));

        let mut wrong_signer = CountingSigner::new(0x72);
        assert!(matches!(
            issuer.issue(&call, &approval, 20, &mut wrong_signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner
            ))
        ));
        assert_eq!(store.commits(), 0);

        signer.corrupt_receipt = true;
        assert!(matches!(
            issuer.issue(&call, &approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner
            ))
        ));
        assert_eq!(store.commits(), 1);
        signer.corrupt_receipt = false;
        signer.corrupt_acknowledgement = true;
        assert!(matches!(
            issuer.issue(&call, &approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongSigner
            ))
        ));
        assert_eq!(store.commits(), 2);
        signer.corrupt_acknowledgement = false;
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();

        let mut alternate_signer = CountingSigner::new(0x73);
        let alternate_fixture = Fixture::new(&alternate_signer);
        let (alternate_call, alternate_approval) = alternate_fixture.approved(3, 3);
        assert!(matches!(
            issuer.issue(
                &alternate_call,
                &alternate_approval,
                20,
                &mut alternate_signer
            ),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::WrongRoute
            ))
        ));
    }

    #[test]
    fn divergent_retries_and_both_invocation_collision_directions_are_rejected() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store, &fixture);
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();

        let mut replacement_approval = AuthorityOperationApproval::from_call(
            &call,
            core::num::NonZeroU64::new(1).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash(id(0x74, 1)),
            },
            AuthorityLaneRoots::default(),
            3,
            12,
            28,
        )
        .unwrap();
        assert!(replacement_approval.matches_call(&call));
        assert!(matches!(
            issuer.issue(&call, &replacement_approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::DivergentRetry
            ))
        ));
        replacement_approval = approval.clone();
        assert!(matches!(
            issuer.issue(&call, &replacement_approval, 21, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::DivergentRetry
            ))
        ));

        let (mut authorization_collision, authorization_collision_approval) =
            fixture.approved(2, 2);
        authorization_collision.invocation = approval.acknowledgement_invocation;
        authorization_collision.signature = fixture
            .credential_key
            .sign(&authorization_collision.signing_bytes())
            .to_bytes();
        assert!(authorization_collision.validate_shape().is_err());
        assert!(matches!(
            issuer.issue(
                &authorization_collision,
                &authorization_collision_approval,
                20,
                &mut signer
            ),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidCall
            ))
        ));

        let store = MemoryImageStore::default();
        let mut issuer = open(store, &fixture);
        let (second, second_approval) = fixture.approved(3, 3);
        let (mut first, first_approval) = fixture.approved(2, 2);
        first.invocation = second_approval.acknowledgement_invocation;
        first.signature = fixture
            .credential_key
            .sign(&first.signing_bytes())
            .to_bytes();
        assert!(first.validate_shape().is_err());
        assert!(matches!(
            issuer.issue(&first, &first_approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::InvalidCall
            ))
        ));
        assert!(second.validate_shape().is_ok());
        let (first, first_approval) = fixture.approved(2, 2);
        issuer
            .issue(&first, &first_approval, 20, &mut signer)
            .unwrap();

        let (same_sequence, same_sequence_approval) = fixture.approved(4, 2);
        assert!(matches!(
            issuer.issue(&same_sequence, &same_sequence_approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::AuthorizationSequenceCollision
            ))
        ));
    }

    #[test]
    fn pending_operation_serializes_new_issuance_and_binds_the_slot() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (first, first_approval) = fixture.approved(1, 1);
        let (second, second_approval) = fixture.approved(2, 2);
        signer.fail_receipt = true;
        let mut issuer = open(store, &fixture);
        assert!(matches!(
            issuer.issue(&first, &first_approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Signer(TestSignerError))
        ));
        assert!(matches!(
            issuer.issue(&second, &second_approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::PendingOperation
            ))
        ));
        assert!(matches!(
            issuer.issue(&first, &first_approval, 21, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::DivergentRetry
            ))
        ));
        issuer
            .issue(&first, &first_approval, 20, &mut signer)
            .unwrap();
        issuer
            .issue(&second, &second_approval, 20, &mut signer)
            .unwrap();
    }

    #[test]
    fn fresh_issuance_slots_cannot_regress_across_restart_or_image_corruption() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (first, first_approval) = fixture.approved(1, 1);
        let (second, second_approval) = fixture.approved(2, 2);
        let mut issuer = open(store.clone(), &fixture);
        issuer
            .issue(&first, &first_approval, 20, &mut signer)
            .unwrap();
        assert!(matches!(
            issuer.issue(&second, &second_approval, 19, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::IssuanceSlotRegressed
            ))
        ));

        let mut reopened = open(store.clone(), &fixture);
        assert!(matches!(
            reopened.issue(&second, &second_approval, 19, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::IssuanceSlotRegressed
            ))
        ));
        // Equal observations are valid: monotonicity does not manufacture a
        // total order when two durable decisions share one logical slot.
        reopened
            .issue(&second, &second_approval, 20, &mut signer)
            .unwrap();

        let bytes = store.image().unwrap();
        let mut image = AuthorityOperationIssuerImage::decode(&bytes).unwrap();
        image.issuance_slot_high_water = Some(19);
        store.replace_image(image.encode());
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(store, fixture.authority),
            Err(AuthorityOperationIssuerError::InvalidState)
        ));
    }

    #[test]
    fn corrupt_noncanonical_and_wrong_route_images_do_not_open() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store.clone(), &fixture);
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();

        let valid = store.image().unwrap();
        let mut corrupt_signature = valid.clone();
        *corrupt_signature.last_mut().unwrap() ^= 1;
        store.replace_image(corrupt_signature);
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(store.clone(), fixture.authority),
            Err(AuthorityOperationIssuerError::InvalidState)
        ));

        let mut old_magic = valid.clone();
        old_magic[..4].copy_from_slice(b"AOJ0");
        store.replace_image(old_magic);
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(store.clone(), fixture.authority),
            Err(AuthorityOperationIssuerError::InvalidState)
        ));

        store.replace_image(valid);
        let other_signer = CountingSigner::new(0x72);
        let other = Fixture::new(&other_signer);
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(store.clone(), other.authority),
            Err(AuthorityOperationIssuerError::InvalidState)
        ));

        store.fail_load();
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(store, fixture.authority),
            Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
        ));
    }

    #[test]
    fn retained_journal_is_bounded_and_has_no_unsafe_compaction_path() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let mut issuer = open(store.clone(), &fixture);
        for sequence in 1..=MAX_AUTHORITY_OPERATION_ISSUER_RECORDS as u64 {
            let (call, approval) = fixture.approved(sequence, sequence);
            issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        }
        assert_eq!(
            issuer.retained_operations(),
            MAX_AUTHORITY_OPERATION_ISSUER_RECORDS
        );
        assert!(store.image().unwrap().len() <= MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES);
        let (call, approval) = fixture.approved(10_000, 10_000);
        assert!(matches!(
            issuer.issue(&call, &approval, 20, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::JournalFull
            ))
        ));
        let reopened = open(store, &fixture);
        assert_eq!(
            reopened.retained_operations(),
            MAX_AUTHORITY_OPERATION_ISSUER_RECORDS
        );
    }

    #[test]
    fn receipt_and_ack_signatures_are_exact_ed25519_preimages() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let (call, approval) = fixture.approved(1, 1);
        let mut issuer = open(store, &fixture);
        let issued = issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        assert_eq!(issued.receipt.signature.len(), AUTHORITY_SIGNATURE_BYTES);
        assert_eq!(
            issued.issuance_ack.signature.len(),
            AUTHORITY_SIGNATURE_BYTES
        );
        assert!(crate::agent::authority::verify_raw_ed25519(
            &fixture.authority.binding.public_key,
            &issued.receipt.signing_bytes(),
            &issued.receipt.signature,
        ));
        assert!(crate::agent::authority::verify_raw_ed25519(
            &fixture.authority.binding.public_key,
            &issued.issuance_ack.signing_bytes(),
            &issued.issuance_ack.signature,
        ));
    }

    #[test]
    fn private_application_exact_retry_and_restart_never_resign() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let control = private_control(&fixture, 1);
        let (call, approval) = fixture.approved_private(1, 1, &control);
        let application = private_application(&call, 24, 1);
        let mut issuer = open(store.clone(), &fixture);
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        let issued = issuer
            .issue_private_application(call.invocation, &application, &mut signer)
            .unwrap();
        assert_eq!(store.commits(), 5);
        assert_eq!(signer.application_calls, 1);
        assert!(
            issued
                .application_ack
                .verify_pending_with(
                    &call,
                    &approval,
                    issuer
                        .recover_retained(call.invocation)
                        .unwrap()
                        .unwrap()
                        .issuance_ack
                        .as_ref()
                        .unwrap(),
                    &application,
                    fixture.authority.binding,
                    &RawEd25519Verifier,
                )
                .is_ok()
        );

        let mut unusable = CountingSigner::new(0x72);
        unusable.fail_application = true;
        assert_eq!(
            issuer
                .issue_private_application(call.invocation, &application, &mut unusable)
                .unwrap(),
            issued
        );
        assert_eq!(unusable.application_calls, 0);
        let mut reopened = open(store, &fixture);
        assert_eq!(
            reopened
                .issue_private_application(call.invocation, &application, &mut unusable)
                .unwrap(),
            issued
        );
        assert_eq!(unusable.application_calls, 0);
    }

    #[test]
    fn private_application_failpoints_resume_at_every_signing_boundary() {
        for fail_after in [false, true] {
            let store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let control = private_control(&fixture, 1);
            let (call, approval) = fixture.approved_private(1, 1, &control);
            let application = private_application(&call, 24, 1);
            let mut issuer = open(store.clone(), &fixture);
            issuer.issue(&call, &approval, 20, &mut signer).unwrap();
            if fail_after {
                store.fail_after_commit(1);
            } else {
                store.fail_before_commit(1);
            }
            assert!(matches!(
                issuer.issue_private_application(call.invocation, &application, &mut signer),
                Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
            ));
            assert!(issuer.is_poisoned());
            assert_eq!(signer.application_calls, 0);
            let mut reopened = open(store, &fixture);
            reopened
                .issue_private_application(call.invocation, &application, &mut signer)
                .unwrap();
            assert_eq!(signer.application_calls, 1);
        }

        for fail_after in [false, true] {
            let store = MemoryImageStore::default();
            let mut signer = CountingSigner::new(0x19);
            let fixture = Fixture::new(&signer);
            let control = private_control(&fixture, 1);
            let (call, approval) = fixture.approved_private(1, 1, &control);
            let application = private_application(&call, 24, 1);
            let mut issuer = open(store.clone(), &fixture);
            issuer.issue(&call, &approval, 20, &mut signer).unwrap();
            if fail_after {
                store.fail_after_commit(2);
            } else {
                store.fail_before_commit(2);
            }
            assert!(matches!(
                issuer.issue_private_application(call.invocation, &application, &mut signer),
                Err(AuthorityOperationIssuerError::Storage(MemoryStoreError))
            ));
            assert!(issuer.is_poisoned());
            assert_eq!(signer.application_calls, 1);
            let mut reopened = open(store, &fixture);
            reopened
                .issue_private_application(call.invocation, &application, &mut signer)
                .unwrap();
            assert_eq!(signer.application_calls, if fail_after { 1 } else { 2 });
        }

        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let control = private_control(&fixture, 1);
        let (call, approval) = fixture.approved_private(1, 1, &control);
        let application = private_application(&call, 24, 1);
        let mut issuer = open(store, &fixture);
        issuer.issue(&call, &approval, 20, &mut signer).unwrap();
        signer.fail_application = true;
        assert!(matches!(
            issuer.issue_private_application(call.invocation, &application, &mut signer),
            Err(AuthorityOperationIssuerError::Signer(TestSignerError))
        ));
        assert!(!issuer.is_poisoned());
        assert!(issuer.has_pending_application());
        issuer
            .issue_private_application(call.invocation, &application, &mut signer)
            .unwrap();
        assert_eq!(signer.application_calls, 2);
    }

    #[test]
    fn private_application_rejects_substitution_regression_and_corruption() {
        let store = MemoryImageStore::default();
        let mut signer = CountingSigner::new(0x19);
        let fixture = Fixture::new(&signer);
        let first_control = private_control(&fixture, 1);
        let second_control = private_control(&fixture, 2);
        let (first, first_approval) = fixture.approved_private(1, 1, &first_control);
        let (second, second_approval) = fixture.approved_private(2, 2, &second_control);
        let first_application = private_application(&first, 25, 1);
        let second_application = private_application(&second, 24, 2);
        let mut issuer = open(store.clone(), &fixture);
        issuer
            .issue(&first, &first_approval, 20, &mut signer)
            .unwrap();
        issuer
            .issue_private_application(first.invocation, &first_application, &mut signer)
            .unwrap();
        issuer
            .issue(&second, &second_approval, 20, &mut signer)
            .unwrap();
        assert!(matches!(
            issuer.issue_private_application(second.invocation, &second_application, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::ApplicationSlotRegressed
            ))
        ));

        let mut substituted = first_application;
        substituted.reopened_control_state = Hash(id(0x92, 1));
        assert!(matches!(
            issuer.issue_private_application(first.invocation, &substituted, &mut signer),
            Err(AuthorityOperationIssuerError::Rejected(
                AuthorityOperationIssuerRejection::DivergentRetry
            ))
        ));

        let valid = store.image().unwrap();
        let mut image = AuthorityOperationIssuerImage::decode(&valid).unwrap();
        image.application_slot_high_water = Some(24);
        store.replace_image(image.encode());
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(store, fixture.authority),
            Err(AuthorityOperationIssuerError::InvalidState)
        ));
    }
}
