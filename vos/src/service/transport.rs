//! Local conformance transport for finalized linear-service publications.
//!
//! Transport is deliberately orchestration only. Source effects are recovered
//! from guest-owned publication rows, destination admission executes physical
//! IC-5 Accumulate, and inbox execution returns through Refine plus Accumulate.
//! No native path writes an inbox, consumes a message, or acknowledges effects.

use alloc::vec::Vec;

use crate::attestation::{AttestationProofHost, AttestationProofProducer};

use super::{
    AccumulateProtocolHost, AccumulateRequest, AccumulatedReply, AccumulationEnvelope,
    AccumulationReceipt, AccumulationRejection, AccumulationResult, AttestedServiceError, CallId,
    InvocationId, JamService, LocalJamStoreHost, LocalStoreReadError, LocalWorkScheduler,
    ProofVerificationRequest, PublicationAck, PublicationRecord, PublishedEffects,
    ReceiptVerificationRequest, RefineProtocolHost, RefinedServiceOutput, ScheduleError,
    ServiceDispatchError, ServicePvmError, ServiceWire,
};

type LocalService<R, A> = JamService<R, A>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDelivery {
    pub call: CallId,
    pub receipt: AccumulationReceipt,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedInboxSlice {
    pub call: CallId,
    pub receipt: AccumulationReceipt,
    pub published: PublishedEffects,
    pub refine_gas_used: u64,
    pub accumulate_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedReplyResume {
    pub call: CallId,
    pub caller_invocation: InvocationId,
    pub receipt: AccumulationReceipt,
    pub published: PublishedEffects,
    pub duplicate: bool,
    pub refine_gas_used: u64,
    pub accumulate_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxDrainOutcome {
    Committed(CommittedInboxSlice),
    Retired {
        call: CallId,
        duplicate: bool,
        accumulate_gas_used: u64,
    },
    Deferred {
        call: CallId,
        reason: ScheduleError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTransportError {
    Store(LocalStoreReadError),
    Schedule(ScheduleError),
    Service(ServiceDispatchError),
    Rejected(AccumulationRejection),
    MissingMessage(CallId),
    MissingReply,
    MissingReplyRoute(CallId),
    CallExpired(CallId),
    DivergentReply(CallId),
    MissingAttestationProof(CallId),
    InvalidAttestationProof(CallId),
    NonCanonicalPublication,
    UnexpectedResult,
    TimeslotNotAfterAdmission {
        call: CallId,
        admitted_at: u64,
        requested: u64,
    },
}

impl core::fmt::Display for LocalTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS service local transport failed: {self:?}")
    }
}

impl core::error::Error for LocalTransportError {}

#[derive(Debug)]
pub enum AttestedTransportError<E> {
    Transport(LocalTransportError),
    Attested(AttestedServiceError<ServiceDispatchError, E>),
}

impl<E> From<LocalTransportError> for AttestedTransportError<E> {
    fn from(value: LocalTransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<LocalStoreReadError> for LocalTransportError {
    fn from(value: LocalStoreReadError) -> Self {
        Self::Store(value)
    }
}

impl From<ScheduleError> for LocalTransportError {
    fn from(value: ScheduleError) -> Self {
        Self::Schedule(value)
    }
}

impl From<ServiceDispatchError> for LocalTransportError {
    fn from(value: ServiceDispatchError) -> Self {
        Self::Service(value)
    }
}

pub struct LocalTransport;

impl LocalTransport {
    fn refine_with_storage_witnesses<R, A>(
        service: &LocalService<R, A>,
        mut prepared: super::PreparedWork,
    ) -> Result<(super::PreparedWork, RefinedServiceOutput), LocalTransportError>
    where
        R: RefineProtocolHost,
        A: LocalJamStoreHost + AccumulateProtocolHost,
    {
        let mut discovery_rounds = 0usize;
        loop {
            match service.refine_actor_tree(&prepared.work, &prepared.imports) {
                Ok(refined) => return Ok((prepared, refined)),
                Err(ServiceDispatchError::Pvm(ServicePvmError::ActorStorageWitnessRequired(
                    requests,
                ))) => {
                    if discovery_rounds >= super::MAX_ACTOR_STORAGE_WITNESS_ROUNDS {
                        return Err(ScheduleError::ActorStorageWitnessLimit.into());
                    }
                    discovery_rounds += 1;
                    LocalWorkScheduler::hydrate_actor_storage_rows(
                        service.accumulate_host().local_store(),
                        &mut prepared,
                        &requests,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn retire_expired_inbox<R, A>(
        destination: &mut LocalService<R, A>,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<InboxDrainOutcome, LocalTransportError>
    where
        R: RefineProtocolHost,
        A: LocalJamStoreHost + AccumulateProtocolHost,
    {
        let retirement = LocalWorkScheduler::prepare_inbox_retirement(
            destination.accumulate_host().local_store(),
            call,
            logical_timeslot,
        )?
        .ok_or(LocalTransportError::MissingMessage(call))?;
        let output = destination.accumulate_at(
            &AccumulateRequest::RetireInbox(retirement),
            logical_timeslot,
        )?;
        match output.result {
            AccumulationResult::InboxRetired { call_id, duplicate } if call_id == call => {
                Ok(InboxDrainOutcome::Retired {
                    call,
                    duplicate,
                    accumulate_gas_used: output.gas_used,
                })
            }
            AccumulationResult::Rejected(rejection) => {
                Err(LocalTransportError::Rejected(rejection))
            }
            _ => Err(LocalTransportError::UnexpectedResult),
        }
    }

    /// Recover source effects in canonical guest row order.
    pub fn pending_publications<R, A: LocalJamStoreHost>(
        source: &LocalService<R, A>,
    ) -> Result<Vec<PublicationRecord>, LocalTransportError> {
        Ok(source
            .accumulate_host()
            .local_store()
            .pending_publications()?)
    }

    /// Admit one message selected from a complete committed source outbox.
    ///
    /// The local allowlist stands in for consensus receipt finality only. The
    /// source argument proves the publication is still present in a committed
    /// service image. The destination guest still checks the exact sender,
    /// full-outbox commitment, service identity, deadline, base and call
    /// deduplication.
    pub fn deliver<SR, S, DR, D>(
        source: &LocalService<SR, S>,
        destination: &mut LocalService<DR, D>,
        publication: &PublicationRecord,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<CommittedDelivery, LocalTransportError>
    where
        S: LocalJamStoreHost,
        DR: RefineProtocolHost,
        D: LocalJamStoreHost + AccumulateProtocolHost,
    {
        let canonical = committed_publication(source, publication)?;
        let message = canonical
            .published
            .outbox
            .binary_search_by_key(&call, |message| message.call_id)
            .ok()
            .map(|index| canonical.published.outbox[index].clone())
            .ok_or(LocalTransportError::MissingMessage(call))?;
        destination
            .accumulate_host_mut()
            .local_store_mut()
            .allow_receipt(&ReceiptVerificationRequest {
                expected_producer: message.from,
                receipt: canonical.receipt.clone(),
            });
        let envelope = LocalWorkScheduler::prepare_delivery(
            destination.accumulate_host().local_store(),
            logical_timeslot,
            message,
            canonical.published.outbox,
            canonical.receipt,
        )?;
        let output = destination.accumulate(&AccumulateRequest::Deliver(envelope))?;
        match output.result {
            AccumulationResult::Accepted {
                receipt,
                published,
                duplicate,
            } if published == PublishedEffects::default() => Ok(CommittedDelivery {
                call,
                receipt,
                duplicate,
                accumulate_gas_used: output.gas_used,
            }),
            AccumulationResult::Rejected(rejection) => {
                Err(LocalTransportError::Rejected(rejection))
            }
            _ => Err(LocalTransportError::UnexpectedResult),
        }
    }

    /// Route one committed callee reply into the caller's exact suspended
    /// machine. The caller invocation is recovered from its guest-owned
    /// outbox; no process-local return table is trusted.
    ///
    /// A prior exact admission is returned as a duplicate from the permanent
    /// reply-admission record. This remains possible after later workflow
    /// slices overwrite the latest checkpoint.
    pub fn resume_reply<PR, P, CR, C>(
        producer: &LocalService<PR, P>,
        caller: &mut LocalService<CR, C>,
        publication: &PublicationRecord,
        logical_timeslot: u64,
    ) -> Result<CommittedReplyResume, LocalTransportError>
    where
        CR: RefineProtocolHost,
        P: LocalJamStoreHost + AttestationProofHost,
        C: LocalJamStoreHost + AccumulateProtocolHost + AttestationProofHost,
    {
        let canonical = committed_publication(producer, publication)?;
        let reply = canonical
            .published
            .reply
            .clone()
            .ok_or(LocalTransportError::MissingReply)?;
        let awaited_reply = AccumulatedReply {
            reply: reply.clone(),
            receipt: canonical.receipt,
            attestation: canonical.published.attestation.clone(),
        };
        // The committed producer publication is the local conformance
        // verifier's positive decision for this exact physical receipt. Make
        // it available even when logical reply admission short-circuits actor
        // execution, so an alternate CRDT branch never borrows the first
        // branch's verifier decision.
        caller
            .accumulate_host_mut()
            .local_store_mut()
            .allow_receipt(&ReceiptVerificationRequest {
                expected_producer: reply.producer,
                receipt: awaited_reply.receipt.clone(),
            });
        if let Some((admission, receipt)) = caller
            .accumulate_host()
            .local_store()
            .reply_admission(reply.call_id)?
        {
            return if admission.awaited_reply.logical_identity() == awaited_reply.logical_identity()
            {
                Ok(CommittedReplyResume {
                    call: reply.call_id,
                    caller_invocation: admission.input.invocation,
                    receipt,
                    published: PublishedEffects::default(),
                    duplicate: true,
                    refine_gas_used: 0,
                    accumulate_gas_used: 0,
                })
            } else {
                Err(LocalTransportError::DivergentReply(reply.call_id))
            };
        }

        if caller
            .accumulate_host()
            .local_store()
            .call_expiration(reply.call_id)?
            .is_some()
        {
            return Err(LocalTransportError::CallExpired(reply.call_id));
        }

        let message = caller
            .accumulate_host()
            .local_store()
            .outbox_message(reply.call_id)?
            .ok_or(LocalTransportError::MissingReplyRoute(reply.call_id))?;
        if message.to != reply.producer {
            return Err(LocalTransportError::DivergentReply(reply.call_id));
        }
        if message
            .deadline_timeslot
            .is_some_and(|deadline| logical_timeslot >= deadline)
        {
            return Err(ScheduleError::DeadlineExpired(reply.call_id).into());
        }
        let caller_invocation = message.caller_invocation;
        if let Some(attestation) = awaited_reply.attestation.as_ref() {
            let proof = producer
                .accumulate_host()
                .proof_bytes(&attestation.proof.proof_blob)
                .ok_or(LocalTransportError::MissingAttestationProof(reply.call_id))?;
            let verification = ProofVerificationRequest {
                actor_program: attestation.statement.actor_program,
                execution_semantics: attestation
                    .statement
                    .accumulation_receipt
                    .service
                    .execution_semantics,
                statement: attestation.proof.statement,
                trace: attestation.proof.trace,
                proof_blob: attestation.proof.proof_blob.clone(),
            };
            if !caller
                .accumulate_host_mut()
                .make_proof_available(&verification, &proof)
            {
                return Err(LocalTransportError::InvalidAttestationProof(reply.call_id));
            }
        }
        let prepared = LocalWorkScheduler::prepare_resume(
            caller.accumulate_host().local_store(),
            caller_invocation,
            logical_timeslot,
            Some(awaited_reply.clone()),
        )?;
        let (prepared, refined) = Self::refine_with_storage_witnesses(caller, prepared)?;
        let accumulated = caller.accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
            work: prepared.work,
            transition: refined.transition,
            provided_blobs: refined.exported_blobs,
        }))?;
        let (receipt, published) = match accumulated.result {
            AccumulationResult::Accepted {
                receipt,
                published,
                duplicate: false,
            } => (receipt, published),
            AccumulationResult::Rejected(rejection) => {
                return Err(LocalTransportError::Rejected(rejection));
            }
            _ => return Err(LocalTransportError::UnexpectedResult),
        };
        let Some((admission, committed_receipt)) = caller
            .accumulate_host()
            .local_store()
            .reply_admission(reply.call_id)?
        else {
            return Err(LocalTransportError::UnexpectedResult);
        };
        if admission.awaited_reply.logical_identity() != awaited_reply.logical_identity()
            || admission.input.invocation != caller_invocation
            || committed_receipt != receipt
        {
            return Err(LocalTransportError::UnexpectedResult);
        }
        Ok(CommittedReplyResume {
            call: reply.call_id,
            caller_invocation,
            receipt,
            published,
            duplicate: false,
            refine_gas_used: refined.gas_used,
            accumulate_gas_used: accumulated.gas_used,
        })
    }

    /// Drain every guest-admitted inbox row which is runnable after restart.
    ///
    /// Suspended targets remain committed for later resolution. Expired rows
    /// are retired through a separate slot-authenticated guest transaction;
    /// other scheduling failures indicate corrupt orchestration state.
    pub fn drain_pending<R, A>(
        destination: &mut LocalService<R, A>,
        logical_timeslot: u64,
    ) -> Result<Vec<InboxDrainOutcome>, LocalTransportError>
    where
        R: RefineProtocolHost,
        A: LocalJamStoreHost + AccumulateProtocolHost,
    {
        let pending = destination
            .accumulate_host()
            .local_store()
            .pending_inbox_calls()?;
        let mut outcomes = Vec::with_capacity(pending.len());
        for (call, admitted_at) in pending {
            if logical_timeslot <= admitted_at {
                return Err(LocalTransportError::TimeslotNotAfterAdmission {
                    call,
                    admitted_at,
                    requested: logical_timeslot,
                });
            }
            let prepared = match LocalWorkScheduler::prepare_inbox(
                destination.accumulate_host().local_store(),
                call,
                logical_timeslot,
            ) {
                Ok(prepared) => prepared,
                Err(reason @ ScheduleError::ActorBusy(_)) => {
                    outcomes.push(InboxDrainOutcome::Deferred { call, reason });
                    continue;
                }
                Err(ScheduleError::DeadlineExpired(_)) => {
                    outcomes.push(Self::retire_expired_inbox(
                        destination,
                        call,
                        logical_timeslot,
                    )?);
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let (prepared, refined) = Self::refine_with_storage_witnesses(destination, prepared)?;
            let accumulated =
                destination.accumulate(&AccumulateRequest::Apply(AccumulationEnvelope {
                    work: prepared.work,
                    transition: refined.transition,
                    provided_blobs: refined.exported_blobs,
                }))?;
            match accumulated.result {
                AccumulationResult::Accepted {
                    receipt,
                    published,
                    duplicate: false,
                } => outcomes.push(InboxDrainOutcome::Committed(CommittedInboxSlice {
                    call,
                    receipt,
                    published,
                    refine_gas_used: refined.gas_used,
                    accumulate_gas_used: accumulated.gas_used,
                })),
                AccumulationResult::Rejected(rejection) => {
                    return Err(LocalTransportError::Rejected(rejection));
                }
                _ => return Err(LocalTransportError::UnexpectedResult),
            }
        }
        Ok(outcomes)
    }

    /// Drain authenticated inbox rows, producing a proof before guest
    /// Accumulate whenever the caller selected an attested handle.
    ///
    /// Proof metadata is published by guest Accumulate from the installed
    /// actor descriptor; the transport cannot supply a producer label.
    pub fn drain_pending_attested<R, A, P>(
        destination: &mut LocalService<R, A>,
        logical_timeslot: u64,
        proof_producer: &mut P,
    ) -> Result<Vec<InboxDrainOutcome>, AttestedTransportError<P::Error>>
    where
        R: RefineProtocolHost,
        A: LocalJamStoreHost + AccumulateProtocolHost + AttestationProofHost,
        P: AttestationProofProducer,
    {
        let pending = destination
            .accumulate_host()
            .local_store()
            .pending_inbox_calls()
            .map_err(LocalTransportError::Store)?;
        let mut outcomes = Vec::with_capacity(pending.len());
        for (call, admitted_at) in pending {
            if logical_timeslot <= admitted_at {
                return Err(LocalTransportError::TimeslotNotAfterAdmission {
                    call,
                    admitted_at,
                    requested: logical_timeslot,
                }
                .into());
            }
            let prepared = match LocalWorkScheduler::prepare_inbox(
                destination.accumulate_host().local_store(),
                call,
                logical_timeslot,
            ) {
                Ok(prepared) => prepared,
                Err(reason @ ScheduleError::ActorBusy(_)) => {
                    outcomes.push(InboxDrainOutcome::Deferred { call, reason });
                    continue;
                }
                Err(ScheduleError::DeadlineExpired(_)) => {
                    outcomes.push(
                        Self::retire_expired_inbox(destination, call, logical_timeslot)
                            .map_err(AttestedTransportError::Transport)?,
                    );
                    continue;
                }
                Err(error) => return Err(LocalTransportError::Schedule(error).into()),
            };
            let (prepared, refined) = Self::refine_with_storage_witnesses(destination, prepared)?;
            let envelope = AccumulationEnvelope {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            };
            if envelope.work.proof_requested {
                let committed = destination
                    .accumulate_attested(envelope, &prepared.imports, proof_producer)
                    .map_err(AttestedTransportError::Attested)?;
                outcomes.push(InboxDrainOutcome::Committed(CommittedInboxSlice {
                    call,
                    receipt: committed.preparation.receipt,
                    published: committed.published,
                    refine_gas_used: refined.gas_used,
                    accumulate_gas_used: committed.accumulate_gas_used,
                }));
                continue;
            }
            let accumulated = destination
                .accumulate(&AccumulateRequest::Apply(envelope))
                .map_err(LocalTransportError::Service)?;
            match accumulated.result {
                AccumulationResult::Accepted {
                    receipt,
                    published,
                    duplicate: false,
                } => outcomes.push(InboxDrainOutcome::Committed(CommittedInboxSlice {
                    call,
                    receipt,
                    published,
                    refine_gas_used: refined.gas_used,
                    accumulate_gas_used: accumulated.gas_used,
                })),
                AccumulationResult::Rejected(rejection) => {
                    return Err(LocalTransportError::Rejected(rejection).into());
                }
                _ => return Err(LocalTransportError::UnexpectedResult.into()),
            }
        }
        Ok(outcomes)
    }

    /// Remove one recoverable publication through guest Accumulate after its
    /// external consumer has durably accepted it.
    pub fn acknowledge<R: RefineProtocolHost, A: AccumulateProtocolHost>(
        source: &mut LocalService<R, A>,
        publication: &PublicationRecord,
    ) -> Result<bool, LocalTransportError> {
        let output =
            source.accumulate(&AccumulateRequest::AcknowledgePublication(PublicationAck {
                service: publication.receipt.service.clone(),
                input: publication.input,
                publication: publication.commitment(),
            }))?;
        match output.result {
            AccumulationResult::PublicationAcknowledged { duplicate, .. } => Ok(duplicate),
            AccumulationResult::Rejected(rejection) => {
                Err(LocalTransportError::Rejected(rejection))
            }
            _ => Err(LocalTransportError::UnexpectedResult),
        }
    }
}

fn committed_publication<R, A: LocalJamStoreHost>(
    source: &LocalService<R, A>,
    publication: &PublicationRecord,
) -> Result<PublicationRecord, LocalTransportError> {
    let canonical = PublicationRecord::decode(&publication.encode())
        .map_err(|_| LocalTransportError::NonCanonicalPublication)?;
    let source_header = source
        .accumulate_host()
        .local_store()
        .header()?
        .ok_or(LocalTransportError::NonCanonicalPublication)?;
    if canonical.receipt.service != source_header.service
        || !source
            .accumulate_host()
            .local_store()
            .pending_publications()?
            .iter()
            .any(|committed| committed == &canonical)
    {
        return Err(LocalTransportError::NonCanonicalPublication);
    }
    Ok(canonical)
}
