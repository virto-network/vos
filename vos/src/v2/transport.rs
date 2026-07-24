//! Local conformance transport for finalized linear-service publications.
//!
//! Transport is deliberately orchestration only. Source effects are recovered
//! from guest-owned publication rows, destination admission executes physical
//! IC-5 Accumulate, and inbox execution returns through Refine plus Accumulate.
//! No native path writes an inbox, consumes a message, or acknowledges effects.

use alloc::vec::Vec;

use super::{
    AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2,
    AccumulationResultV2, CallId, JamServiceV2, LocalJamStoreV2, LocalStoreReadErrorV2,
    LocalWorkSchedulerV2, NoRefineProtocolHostV2, PublicationAckV2, PublicationRecordV2,
    PublishedEffectsV2, ReceiptVerificationRequestV2, ScheduleErrorV2, ServiceDispatchError,
    V2Wire,
};

type LocalServiceV2 = JamServiceV2<NoRefineProtocolHostV2, LocalJamStoreV2>;

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
    pub fn pending_publications(
        source: &LocalServiceV2,
    ) -> Result<Vec<PublicationRecordV2>, LocalTransportErrorV2> {
        Ok(source.accumulate_host().pending_publications()?)
    }

    /// Admit one message selected from a complete committed source outbox.
    ///
    /// The local allowlist stands in for consensus receipt finality only. The
    /// source argument proves the publication is still present in a committed
    /// service image. The destination guest still checks the exact sender,
    /// full-outbox commitment, service identity, deadline, base and call
    /// deduplication.
    pub fn deliver(
        source: &LocalServiceV2,
        destination: &mut LocalServiceV2,
        publication: &PublicationRecordV2,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<CommittedDeliveryV2, LocalTransportErrorV2> {
        let canonical = PublicationRecordV2::decode(&publication.encode())
            .map_err(|_| LocalTransportErrorV2::NonCanonicalPublication)?;
        let source_header = source
            .accumulate_host()
            .header()?
            .ok_or(LocalTransportErrorV2::NonCanonicalPublication)?;
        if canonical.receipt.service != source_header.service
            || !source
                .accumulate_host()
                .pending_publications()?
                .iter()
                .any(|committed| committed == &canonical)
        {
            return Err(LocalTransportErrorV2::NonCanonicalPublication);
        }
        let message = canonical
            .published
            .outbox
            .binary_search_by_key(&call, |message| message.call_id)
            .ok()
            .map(|index| canonical.published.outbox[index].clone())
            .ok_or(LocalTransportErrorV2::MissingMessage(call))?;
        destination
            .accumulate_host_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                expected_producer: message.from,
                receipt: canonical.receipt.clone(),
            });
        let envelope = LocalWorkSchedulerV2::prepare_delivery(
            destination.accumulate_host(),
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

    /// Drain every guest-admitted inbox row which is runnable after restart.
    ///
    /// Suspended targets and expired rows remain committed for later
    /// resolution; other scheduling failures indicate corrupt orchestration
    /// state and fail the batch.
    pub fn drain_pending(
        destination: &mut LocalServiceV2,
        logical_timeslot: u64,
    ) -> Result<Vec<InboxDrainOutcomeV2>, LocalTransportErrorV2> {
        let pending = destination.accumulate_host().pending_inbox_calls()?;
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
                destination.accumulate_host(),
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

    /// Remove one recoverable publication through guest Accumulate after its
    /// external consumer has durably accepted it.
    pub fn acknowledge(
        source: &mut LocalServiceV2,
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
