//! Local conformance transport for finalized linear-service publications.
//!
//! Transport is deliberately orchestration only. Source effects are recovered
//! from guest-owned publication rows, destination admission executes physical
//! IC-5 Accumulate, and inbox execution returns through Refine plus Accumulate.
//! No native path writes an inbox, consumes a message, or acknowledges effects.

use alloc::vec::Vec;

use crate::attestation::{AttestationProofHostV2, AttestationProofProducerV2};

use super::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulatedReplyV2, AccumulationEnvelopeV2,
    AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2, AttestedServiceErrorV2,
    CallId, InvocationId, JamServiceV2, LocalJamStoreHostV2, LocalStoreReadErrorV2,
    LocalWorkSchedulerV2, NoRefineProtocolHostV2, ProofVerificationRequestV2, PublicationAckV2,
    PublicationRecordV2, PublishedEffectsV2, ReceiptVerificationRequestV2, ScheduleErrorV2,
    ServiceDispatchError, V2Wire,
};

type LocalServiceV2<A> = JamServiceV2<NoRefineProtocolHostV2, A>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDeliveryV2 {
    pub call: CallId,
    pub receipt: AccumulationReceiptV2,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedInboxSliceV2 {
    pub call: CallId,
    pub receipt: AccumulationReceiptV2,
    pub published: PublishedEffectsV2,
    pub refine_gas_used: u64,
    pub accumulate_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedReplyResumeV2 {
    pub call: CallId,
    pub caller_invocation: InvocationId,
    pub receipt: AccumulationReceiptV2,
    pub published: PublishedEffectsV2,
    pub duplicate: bool,
    pub refine_gas_used: u64,
    pub accumulate_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxDrainOutcomeV2 {
    Committed(CommittedInboxSliceV2),
    Deferred {
        call: CallId,
        reason: ScheduleErrorV2,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTransportErrorV2 {
    Store(LocalStoreReadErrorV2),
    Schedule(ScheduleErrorV2),
    Service(ServiceDispatchError),
    Rejected(AccumulationRejectionV2),
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

impl core::fmt::Display for LocalTransportErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS v2 local transport failed: {self:?}")
    }
}

impl core::error::Error for LocalTransportErrorV2 {}

#[derive(Debug)]
pub enum AttestedTransportErrorV2<E> {
    Transport(LocalTransportErrorV2),
    Attested(AttestedServiceErrorV2<ServiceDispatchError, E>),
}

impl<E> From<LocalTransportErrorV2> for AttestedTransportErrorV2<E> {
    fn from(value: LocalTransportErrorV2) -> Self {
        Self::Transport(value)
    }
}

impl From<LocalStoreReadErrorV2> for LocalTransportErrorV2 {
    fn from(value: LocalStoreReadErrorV2) -> Self {
        Self::Store(value)
    }
}

impl From<ScheduleErrorV2> for LocalTransportErrorV2 {
    fn from(value: ScheduleErrorV2) -> Self {
        Self::Schedule(value)
    }
}

impl From<ServiceDispatchError> for LocalTransportErrorV2 {
    fn from(value: ServiceDispatchError) -> Self {
        Self::Service(value)
    }
}

pub struct LocalTransportV2;

impl LocalTransportV2 {
    /// Recover source effects in canonical guest row order.
    pub fn pending_publications<A: LocalJamStoreHostV2>(
        source: &LocalServiceV2<A>,
    ) -> Result<Vec<PublicationRecordV2>, LocalTransportErrorV2> {
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
    pub fn deliver<S, D>(
        source: &LocalServiceV2<S>,
        destination: &mut LocalServiceV2<D>,
        publication: &PublicationRecordV2,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<CommittedDeliveryV2, LocalTransportErrorV2>
    where
        S: LocalJamStoreHostV2,
        D: LocalJamStoreHostV2 + AccumulateProtocolHostV2,
    {
        let canonical = committed_publication(source, publication)?;
        let message = canonical
            .published
            .outbox
            .binary_search_by_key(&call, |message| message.call_id)
            .ok()
            .map(|index| canonical.published.outbox[index].clone())
            .ok_or(LocalTransportErrorV2::MissingMessage(call))?;
        destination
            .accumulate_host_mut()
            .local_store_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: message.from,
                receipt: canonical.receipt.clone(),
            });
        let envelope = LocalWorkSchedulerV2::prepare_delivery(
            destination.accumulate_host().local_store(),
            logical_timeslot,
            message,
            canonical.published.outbox,
            canonical.receipt,
        )?;
        let output = destination.accumulate(&AccumulateRequestV2::Deliver(envelope))?;
        match output.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate,
            } if published == PublishedEffectsV2::default() => Ok(CommittedDeliveryV2 {
                call,
                receipt,
                duplicate,
                accumulate_gas_used: output.gas_used,
            }),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalTransportErrorV2::Rejected(rejection))
            }
            _ => Err(LocalTransportErrorV2::UnexpectedResult),
        }
    }

    /// Route one committed callee reply into the caller's exact suspended
    /// machine. The caller invocation is recovered from its guest-owned
    /// outbox; no process-local return table is trusted.
    ///
    /// A prior exact admission is returned as a duplicate from the permanent
    /// reply-admission record. This remains possible after later workflow
    /// slices overwrite the latest checkpoint.
    pub fn resume_reply<P, C>(
        producer: &LocalServiceV2<P>,
        caller: &mut LocalServiceV2<C>,
        publication: &PublicationRecordV2,
        logical_timeslot: u64,
    ) -> Result<CommittedReplyResumeV2, LocalTransportErrorV2>
    where
        P: LocalJamStoreHostV2 + AttestationProofHostV2,
        C: LocalJamStoreHostV2 + AccumulateProtocolHostV2 + AttestationProofHostV2,
    {
        let canonical = committed_publication(producer, publication)?;
        let reply = canonical
            .published
            .reply
            .clone()
            .ok_or(LocalTransportErrorV2::MissingReply)?;
        let awaited_reply = AccumulatedReplyV2 {
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
            .allow_receipt(&ReceiptVerificationRequestV2 {
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
                Ok(CommittedReplyResumeV2 {
                    call: reply.call_id,
                    caller_invocation: admission.input.invocation,
                    receipt,
                    published: PublishedEffectsV2::default(),
                    duplicate: true,
                    refine_gas_used: 0,
                    accumulate_gas_used: 0,
                })
            } else {
                Err(LocalTransportErrorV2::DivergentReply(reply.call_id))
            };
        }

        if caller
            .accumulate_host()
            .local_store()
            .call_expiration(reply.call_id)?
            .is_some()
        {
            return Err(LocalTransportErrorV2::CallExpired(reply.call_id));
        }

        let message = caller
            .accumulate_host()
            .local_store()
            .outbox_message(reply.call_id)?
            .ok_or(LocalTransportErrorV2::MissingReplyRoute(reply.call_id))?;
        if message.to != reply.producer {
            return Err(LocalTransportErrorV2::DivergentReply(reply.call_id));
        }
        if message
            .deadline_timeslot
            .is_some_and(|deadline| logical_timeslot >= deadline)
        {
            return Err(ScheduleErrorV2::DeadlineExpired(reply.call_id).into());
        }
        let caller_invocation = message.caller_invocation;
        if let Some(attestation) = awaited_reply.attestation.as_ref() {
            let proof = producer
                .accumulate_host()
                .proof_bytes(&attestation.proof.proof_blob)
                .ok_or(LocalTransportErrorV2::MissingAttestationProof(
                    reply.call_id,
                ))?;
            let verification = ProofVerificationRequestV2 {
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
                return Err(LocalTransportErrorV2::InvalidAttestationProof(
                    reply.call_id,
                ));
            }
        }
        let prepared = LocalWorkSchedulerV2::prepare_resume(
            caller.accumulate_host().local_store(),
            caller_invocation,
            logical_timeslot,
            Some(awaited_reply.clone()),
        )?;
        let refined = caller.refine_actor_tree(&prepared.work, &prepared.imports)?;
        let accumulated =
            caller.accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))?;
        let (receipt, published) = match accumulated.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate: false,
            } => (receipt, published),
            AccumulationResultV2::Rejected(rejection) => {
                return Err(LocalTransportErrorV2::Rejected(rejection));
            }
            _ => return Err(LocalTransportErrorV2::UnexpectedResult),
        };
        let Some((admission, committed_receipt)) = caller
            .accumulate_host()
            .local_store()
            .reply_admission(reply.call_id)?
        else {
            return Err(LocalTransportErrorV2::UnexpectedResult);
        };
        if admission.awaited_reply.logical_identity() != awaited_reply.logical_identity()
            || admission.input.invocation != caller_invocation
            || committed_receipt != receipt
        {
            return Err(LocalTransportErrorV2::UnexpectedResult);
        }
        Ok(CommittedReplyResumeV2 {
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
    /// Suspended targets and expired rows remain committed for later
    /// resolution; other scheduling failures indicate corrupt orchestration
    /// state and fail the batch.
    pub fn drain_pending<A>(
        destination: &mut LocalServiceV2<A>,
        logical_timeslot: u64,
    ) -> Result<Vec<InboxDrainOutcomeV2>, LocalTransportErrorV2>
    where
        A: LocalJamStoreHostV2 + AccumulateProtocolHostV2,
    {
        let pending = destination
            .accumulate_host()
            .local_store()
            .pending_inbox_calls()?;
        let mut outcomes = Vec::with_capacity(pending.len());
        for (call, admitted_at) in pending {
            if logical_timeslot <= admitted_at {
                return Err(LocalTransportErrorV2::TimeslotNotAfterAdmission {
                    call,
                    admitted_at,
                    requested: logical_timeslot,
                });
            }
            let prepared = match LocalWorkSchedulerV2::prepare_inbox(
                destination.accumulate_host().local_store(),
                call,
                logical_timeslot,
            ) {
                Ok(prepared) => prepared,
                Err(
                    reason @ (ScheduleErrorV2::ActorBusy(_) | ScheduleErrorV2::DeadlineExpired(_)),
                ) => {
                    outcomes.push(InboxDrainOutcomeV2::Deferred { call, reason });
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let refined = destination.refine_actor_tree(&prepared.work, &prepared.imports)?;
            let accumulated =
                destination.accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: prepared.work,
                    transition: refined.transition,
                    provided_blobs: refined.exported_blobs,
                }))?;
            match accumulated.result {
                AccumulationResultV2::Accepted {
                    receipt,
                    published,
                    duplicate: false,
                } => outcomes.push(InboxDrainOutcomeV2::Committed(CommittedInboxSliceV2 {
                    call,
                    receipt,
                    published,
                    refine_gas_used: refined.gas_used,
                    accumulate_gas_used: accumulated.gas_used,
                })),
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalTransportErrorV2::Rejected(rejection));
                }
                _ => return Err(LocalTransportErrorV2::UnexpectedResult),
            }
        }
        Ok(outcomes)
    }

    /// Drain authenticated inbox rows, producing a proof before guest
    /// Accumulate whenever the caller selected an attested handle.
    ///
    /// Proof metadata is published by guest Accumulate from the installed
    /// actor descriptor; the transport cannot supply a producer label.
    pub fn drain_pending_attested<A, P>(
        destination: &mut LocalServiceV2<A>,
        logical_timeslot: u64,
        proof_producer: &mut P,
    ) -> Result<Vec<InboxDrainOutcomeV2>, AttestedTransportErrorV2<P::Error>>
    where
        A: LocalJamStoreHostV2 + AccumulateProtocolHostV2 + AttestationProofHostV2,
        P: AttestationProofProducerV2,
    {
        let pending = destination
            .accumulate_host()
            .local_store()
            .pending_inbox_calls()
            .map_err(LocalTransportErrorV2::Store)?;
        let mut outcomes = Vec::with_capacity(pending.len());
        for (call, admitted_at) in pending {
            if logical_timeslot <= admitted_at {
                return Err(LocalTransportErrorV2::TimeslotNotAfterAdmission {
                    call,
                    admitted_at,
                    requested: logical_timeslot,
                }
                .into());
            }
            let prepared = match LocalWorkSchedulerV2::prepare_inbox(
                destination.accumulate_host().local_store(),
                call,
                logical_timeslot,
            ) {
                Ok(prepared) => prepared,
                Err(
                    reason @ (ScheduleErrorV2::ActorBusy(_) | ScheduleErrorV2::DeadlineExpired(_)),
                ) => {
                    outcomes.push(InboxDrainOutcomeV2::Deferred { call, reason });
                    continue;
                }
                Err(error) => return Err(LocalTransportErrorV2::Schedule(error).into()),
            };
            let refined = destination
                .refine_actor_tree(&prepared.work, &prepared.imports)
                .map_err(LocalTransportErrorV2::Service)?;
            let envelope = AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            };
            if envelope.work.proof_requested {
                let committed = destination
                    .accumulate_attested(envelope, &prepared.imports, proof_producer)
                    .map_err(AttestedTransportErrorV2::Attested)?;
                outcomes.push(InboxDrainOutcomeV2::Committed(CommittedInboxSliceV2 {
                    call,
                    receipt: committed.preparation.receipt,
                    published: committed.published,
                    refine_gas_used: refined.gas_used,
                    accumulate_gas_used: committed.accumulate_gas_used,
                }));
                continue;
            }
            let accumulated = destination
                .accumulate(&AccumulateRequestV2::Apply(envelope))
                .map_err(LocalTransportErrorV2::Service)?;
            match accumulated.result {
                AccumulationResultV2::Accepted {
                    receipt,
                    published,
                    duplicate: false,
                } => outcomes.push(InboxDrainOutcomeV2::Committed(CommittedInboxSliceV2 {
                    call,
                    receipt,
                    published,
                    refine_gas_used: refined.gas_used,
                    accumulate_gas_used: accumulated.gas_used,
                })),
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalTransportErrorV2::Rejected(rejection).into());
                }
                _ => return Err(LocalTransportErrorV2::UnexpectedResult.into()),
            }
        }
        Ok(outcomes)
    }

    /// Remove one recoverable publication through guest Accumulate after its
    /// external consumer has durably accepted it.
    pub fn acknowledge<A: AccumulateProtocolHostV2>(
        source: &mut LocalServiceV2<A>,
        publication: &PublicationRecordV2,
    ) -> Result<bool, LocalTransportErrorV2> {
        let output = source.accumulate(&AccumulateRequestV2::AcknowledgePublication(
            PublicationAckV2 {
                service: publication.receipt.service.clone(),
                input: publication.input,
                publication: publication.commitment(),
            },
        ))?;
        match output.result {
            AccumulationResultV2::PublicationAcknowledged { duplicate, .. } => Ok(duplicate),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalTransportErrorV2::Rejected(rejection))
            }
            _ => Err(LocalTransportErrorV2::UnexpectedResult),
        }
    }
}

fn committed_publication<A: LocalJamStoreHostV2>(
    source: &LocalServiceV2<A>,
    publication: &PublicationRecordV2,
) -> Result<PublicationRecordV2, LocalTransportErrorV2> {
    let canonical = PublicationRecordV2::decode(&publication.encode())
        .map_err(|_| LocalTransportErrorV2::NonCanonicalPublication)?;
    let source_header = source
        .accumulate_host()
        .local_store()
        .header()?
        .ok_or(LocalTransportErrorV2::NonCanonicalPublication)?;
    if canonical.receipt.service != source_header.service
        || !source
            .accumulate_host()
            .local_store()
            .pending_publications()?
            .iter()
            .any(|committed| committed == &canonical)
    {
        return Err(LocalTransportErrorV2::NonCanonicalPublication);
    }
    Ok(canonical)
}
