//! Host-owned bounded management history for image-backed Local recovery.
//!
//! These records do not authenticate themselves. Only a host which has verified
//! the signed request and the runtime transition may advance them; persistence
//! must commit the resulting history atomically with the corresponding image.

use crate::agent_sdk::authority::AuthorityReceipt;
use crate::agent_sdk::wire::CanonicalWire as _;
use crate::agent_sdk::{
    Hash, ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeTransition,
    RuntimeWork,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};

pub const MAX_LOCAL_MANAGEMENT_RECORDS: usize = 256;
pub const MAX_LOCAL_MANAGEMENT_HISTORY_BYTES: usize =
    64 + MAX_LOCAL_MANAGEMENT_RECORDS * (92 + super::wire::MAX_CLEAN_MANAGEMENT_RESULT_BYTES);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalManagementRecord {
    pub authority: Hash,
    pub request: Hash,
    pub epoch: u64,
    pub sequence: u64,
    pub observed_slot: u64,
    pub result: Result<ManagementReply, ManagementError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalReceiptHistory {
    Retained { observed_slot: u64 },
    Consumed,
    RejectedUnseen,
    Unseen,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalManagementHistory {
    acknowledged_through: u64,
    records: Vec<LocalManagementRecord>,
}

impl LocalManagementHistory {
    pub fn latest(&self) -> Option<&LocalManagementRecord> {
        self.records.last()
    }

    pub fn classify(
        &self,
        request: &ManagementRequest,
        receipt: &AuthorityReceipt,
    ) -> LocalReceiptHistory {
        if let Some(record) = self
            .records
            .iter()
            .find(|item| item.authority == receipt.commitment())
        {
            return if record.request == request.replay_commitment()
                && record.epoch == receipt.selector.epoch
                && record.sequence == receipt.selector.decision_sequence
            {
                LocalReceiptHistory::Retained {
                    observed_slot: record.observed_slot,
                }
            } else {
                LocalReceiptHistory::Consumed
            };
        }
        let high_water = self.latest().map_or(0, |record| record.sequence);
        if receipt.selector.decision_sequence <= high_water {
            return LocalReceiptHistory::Consumed;
        }
        if receipt.selector.acknowledged_through < self.acknowledged_through
            || receipt.selector.acknowledged_through > high_water
        {
            return LocalReceiptHistory::RejectedUnseen;
        }
        LocalReceiptHistory::Unseen
    }

    /// Advance only after independent request authentication and guest outcome
    /// validation. Exact retries must preserve both state and the retained result;
    /// failed admission without a state change must not consume a new receipt.
    pub fn after_validated_transition(
        &self,
        work: &RuntimeWork,
        transition: &RuntimeTransition,
    ) -> Result<Self, DecodeError> {
        self.validate()?;
        let RuntimeWork::Manage {
            state,
            request,
            authority,
            observed_slot,
            ..
        } = work
        else {
            return Err(DecodeError::NonCanonical);
        };
        let RuntimeOutcome::Management(result) = &transition.outcome else {
            return Err(DecodeError::NonCanonical);
        };
        if !request.is_valid() {
            return Err(DecodeError::NonCanonical);
        }
        let changed = *state != transition.state;
        let Some(receipt) = authority.as_ref() else {
            return if !changed
                && matches!(
                    request.as_ref(),
                    ManagementRequest::InspectActors { .. } | ManagementRequest::InspectResources
                ) {
                Ok(self.clone())
            } else {
                Err(DecodeError::NonCanonical)
            };
        };
        if receipt.validate_shape().is_err() || receipt.selector.request != request.commitment() {
            return Err(DecodeError::NonCanonical);
        }
        match self.classify(request, receipt) {
            LocalReceiptHistory::Retained { .. } => {
                let original = self
                    .records
                    .iter()
                    .find(|record| record.authority == receipt.commitment())
                    .ok_or(DecodeError::NonCanonical)?;
                return if !changed && original.result == *result {
                    Ok(self.clone())
                } else {
                    Err(DecodeError::NonCanonical)
                };
            }
            LocalReceiptHistory::Consumed | LocalReceiptHistory::RejectedUnseen => {
                return if !changed && result.is_err() {
                    Ok(self.clone())
                } else {
                    Err(DecodeError::NonCanonical)
                };
            }
            LocalReceiptHistory::Unseen => {}
        }
        if !changed && result.is_err() {
            return Ok(self.clone());
        }
        if !receipt.selector.is_live_at(*observed_slot)
            || self.latest().is_some_and(|record| {
                receipt.selector.epoch < record.epoch || *observed_slot <= record.observed_slot
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut next = self.clone();
        next.acknowledged_through = receipt.selector.acknowledged_through;
        next.records
            .retain(|record| record.sequence > next.acknowledged_through);
        next.records.push(LocalManagementRecord {
            authority: receipt.commitment(),
            request: request.replay_commitment(),
            epoch: receipt.selector.epoch,
            sequence: receipt.selector.decision_sequence,
            observed_slot: *observed_slot,
            result: result.clone(),
        });
        next.validate()?;
        Ok(next)
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.records.len() > MAX_LOCAL_MANAGEMENT_RECORDS {
            return Err(DecodeError::LimitExceeded);
        }
        if self.records.is_empty() && self.acknowledged_through != 0 {
            return Err(DecodeError::NonCanonical);
        }
        for (index, record) in self.records.iter().enumerate() {
            if record.authority == Hash::ZERO
                || record.request == Hash::ZERO
                || record.epoch == 0
                || record.sequence <= self.acknowledged_through
                || self.records[..index]
                    .iter()
                    .any(|prior| prior.authority == record.authority)
            {
                return Err(DecodeError::NonCanonical);
            }
            result_bytes(&record.result)?;
        }
        if self.records.windows(2).any(|pair| {
            pair[0].sequence >= pair[1].sequence
                || pair[0].epoch > pair[1].epoch
                || pair[0].observed_slot >= pair[1].observed_slot
        }) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

fn result_bytes(result: &Result<ManagementReply, ManagementError>) -> Result<Vec<u8>, DecodeError> {
    let bytes = RuntimeTransition {
        state: Default::default(),
        outcome: RuntimeOutcome::Management(result.clone()),
    }
    .encode()
    .map_err(|_| DecodeError::NonCanonical)?;
    if bytes.len() > super::wire::MAX_CLEAN_MANAGEMENT_RESULT_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(bytes)
}

impl ServiceWire for LocalManagementHistory {
    const MAGIC: [u8; 4] = *b"LMH1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u64(self.acknowledged_through);
        encoder.u32(self.records.len() as u32);
        for record in &self.records {
            encoder.fixed(&record.authority.0);
            encoder.fixed(&record.request.0);
            encoder.u64(record.epoch);
            encoder.u64(record.sequence);
            encoder.u64(record.observed_slot);
            // The infallible envelope encoder must not panic on a caller's
            // invalid public value. Empty result bytes fail strict decoding.
            encoder.bytes(&result_bytes(&record.result).unwrap_or_default());
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let acknowledged_through = decoder.u64()?;
        let count = decoder.u32()? as usize;
        if count > MAX_LOCAL_MANAGEMENT_RECORDS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let authority = Hash(decoder.fixed()?);
            let request = Hash(decoder.fixed()?);
            let epoch = decoder.u64()?;
            let sequence = decoder.u64()?;
            let observed_slot = decoder.u64()?;
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::wire::MAX_CLEAN_MANAGEMENT_RESULT_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            let result = super::wire::decode_clean_management_result(bytes)?;
            records.push(LocalManagementRecord {
                authority,
                request,
                epoch,
                sequence,
                observed_slot,
                result,
            });
        }
        let history = Self {
            acknowledged_through,
            records,
        };
        history.validate()?;
        Ok(history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_sdk::authority::*;
    use crate::agent_sdk::*;

    fn work(sequence: u64, acknowledged_through: u64) -> RuntimeWork {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
        let public_key = key.verifying_key().to_bytes();
        let request = ManagementRequest::RemoveLeaf {
            actor: ActorId([3; 32]),
            expected_deployment: DeploymentId([4; 32]),
        };
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash([5; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([6; 32]),
                    actor: ActorId([7; 32]),
                    deployment: DeploymentId([8; 32]),
                    program: ProgramId([9; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                space: SpaceId([1; 32]),
                agent: AgentId([2; 32]),
                operation: AuthorityOperationKind::RemoveActor,
                runtime_deployment: DeploymentId([10; 32]),
                actor: Some(ActorId([3; 32])),
                actor_deployment: Some(DeploymentId([4; 32])),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([11; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: sequence,
                acknowledged_through,
                valid_from: 1,
                expires_at: 1000,
                request: request.commitment(),
            },
            public_key,
            signature: [0; AUTHORITY_SIGNATURE_BYTES],
        };
        receipt.signature = key.sign(&receipt.signing_bytes()).to_bytes();
        RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([10; 32]),
            state: RuntimeState {
                control: vec![0xa1],
                ..Default::default()
            },
            request: Box::new(request),
            authority: Some(Box::new(receipt)),
            observed_slot: sequence,
        }
    }

    fn output(changed: bool) -> RuntimeTransition {
        RuntimeTransition {
            state: RuntimeState {
                control: vec![if changed { 0xa2 } else { 0xa1 }],
                ..Default::default()
            },
            outcome: RuntimeOutcome::Management(Err(ManagementError::NotFound)),
        }
    }

    fn classify(history: &LocalManagementHistory, work: &RuntimeWork) -> LocalReceiptHistory {
        let RuntimeWork::Manage {
            request,
            authority: Some(receipt),
            ..
        } = work
        else {
            unreachable!()
        };
        history.classify(request, receipt)
    }

    #[test]
    fn opaque_history_roundtrip_prunes_only_acknowledged_results_and_preserves_retries() {
        let empty = LocalManagementHistory::default();
        assert_eq!(
            empty.after_validated_transition(&work(1, 0), &output(false)),
            Ok(empty.clone())
        );
        let first = empty
            .after_validated_transition(&work(1, 0), &output(true))
            .unwrap();
        let second = first
            .after_validated_transition(&work(3, 0), &output(true))
            .unwrap();
        let reopened = LocalManagementHistory::decode(&second.encode()).unwrap();
        assert_eq!(reopened, second);
        assert_eq!(
            classify(&reopened, &work(1, 0)),
            LocalReceiptHistory::Retained { observed_slot: 1 }
        );
        assert_eq!(
            classify(&reopened, &work(2, 0)),
            LocalReceiptHistory::Consumed
        );
        let mut late_retry = work(1, 0);
        if let RuntimeWork::Manage { observed_slot, .. } = &mut late_retry {
            *observed_slot = 5000;
        }
        assert_eq!(
            reopened.after_validated_transition(&late_retry, &output(false)),
            Ok(reopened.clone())
        );
        assert!(
            reopened
                .after_validated_transition(&late_retry, &output(true))
                .is_err()
        );
        let mut wrong_reply = output(false);
        wrong_reply.outcome = RuntimeOutcome::Management(Err(ManagementError::ResourceLimit));
        assert!(
            reopened
                .after_validated_transition(&late_retry, &wrong_reply)
                .is_err()
        );
        let compacted = reopened
            .after_validated_transition(&work(4, 3), &output(true))
            .unwrap();
        assert_eq!(compacted.records.len(), 1);
        assert_eq!(
            classify(&compacted, &work(1, 0)),
            LocalReceiptHistory::Consumed
        );
        assert_eq!(
            classify(&compacted, &work(5, 2)),
            LocalReceiptHistory::RejectedUnseen
        );
        assert_eq!(
            classify(&compacted, &work(5, 5)),
            LocalReceiptHistory::RejectedUnseen
        );
        assert!(
            compacted
                .after_validated_transition(&work(5, 5), &output(true))
                .is_err()
        );
        assert_eq!(
            LocalManagementHistory::decode(&compacted.encode()).unwrap(),
            compacted
        );
    }

    #[test]
    fn history_bounds_and_canonical_clocks_fail_closed() {
        let first = LocalManagementHistory::default()
            .after_validated_transition(&work(1, 0), &output(true))
            .unwrap();
        let mut full = first.clone();
        for sequence in 2..=MAX_LOCAL_MANAGEMENT_RECORDS as u64 {
            full = full
                .after_validated_transition(&work(sequence, 0), &output(true))
                .unwrap();
        }
        assert!(full.encode().len() <= MAX_LOCAL_MANAGEMENT_HISTORY_BYTES);
        assert_eq!(
            full.after_validated_transition(&work(257, 0), &output(true)),
            Err(DecodeError::LimitExceeded)
        );
        assert!(
            full.after_validated_transition(&work(257, 1), &output(true))
                .is_ok()
        );
        for mutation in 0..5 {
            let mut corrupt = full.clone();
            match mutation {
                0 => corrupt.records[1].authority = corrupt.records[0].authority,
                1 => corrupt.records[1].sequence = corrupt.records[0].sequence,
                2 => corrupt.records[1].observed_slot = corrupt.records[0].observed_slot,
                3 => corrupt.records[1].epoch = 0,
                _ => corrupt.acknowledged_through = 1,
            }
            assert!(LocalManagementHistory::decode(&corrupt.encode()).is_err());
        }
        let mut oversized = Vec::new();
        let mut encoder = Encoder(&mut oversized);
        encoder.u64(0);
        encoder.u32((MAX_LOCAL_MANAGEMENT_RECORDS + 1) as u32);
        assert_eq!(
            LocalManagementHistory::decode_body(&mut Decoder::new(&oversized)),
            Err(DecodeError::LimitExceeded)
        );
    }
}
