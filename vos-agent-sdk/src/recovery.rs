//! Runtime-independent commitments to retained management decisions.
//!
//! This is a semantic projection, not a runtime storage format. Implementations
//! may derive entries from their own layout without exposing that layout. A
//! commitment authenticates nothing by itself: a host must obtain the guest's
//! value by executing the admitted runtime against the recovered state, then
//! compare it with the independently reconstructed host projection.

use alloc::collections::BTreeSet;

use crate::protocol::wire::DecodeError;
use crate::wire::CanonicalWire as _;
use crate::{Hash, ManagementError, ManagementReply, RuntimeOutcome, RuntimeTransition};

/// Bound shared by the retained Local management projection and its verifier.
pub const MAX_MANAGEMENT_HISTORY_ENTRIES: usize = 256;

/// Validate a read-only recovery query's semantic response. The caller must
/// separately execute/authenticate the admitted runtime; this predicate is not
/// a substitute for execution evidence or package admission.
pub fn management_history_reply_matches(
    state: &crate::RuntimeState,
    expected: Hash,
    reply: &RuntimeTransition,
) -> bool {
    expected != Hash::ZERO
        && reply.state == *state
        && reply.outcome
            == RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(expected)))
}

/// Borrowed semantic view of a consumed management decision. Entries are
/// ordered by increasing decision sequence and trusted observation slot.
/// `request` is the replay commitment (not necessarily the wire commitment).
#[derive(Clone, Copy)]
pub struct ManagementHistoryEntry<'a> {
    pub authority: Hash,
    pub request: Hash,
    pub epoch: u64,
    pub sequence: u64,
    pub observed_slot: u64,
    pub result: &'a Result<ManagementReply, ManagementError>,
}

/// Commit the complete retained history, including its retirement watermark.
///
/// All supplied entries are consumed decisions, including retained failures;
/// rejected/unconsumed requests and read-only replies do not belong here.
/// This validates projection shape, not signatures or transition correctness.
/// Memory is bounded by the entry ceiling plus one encoded management result;
/// neither a runtime image nor a cloned history is required.
pub fn management_history_commitment<'a>(
    acknowledged_through: u64,
    entries: impl IntoIterator<Item = ManagementHistoryEntry<'a>>,
) -> Result<Hash, DecodeError> {
    let mut chain = Hash::digest(
        b"vos/agent/management-history/seed/v1",
        &[crate::RUNTIME_ABI_ID.as_bytes()],
    );
    let mut count = 0u32;
    let mut previous: Option<(u64, u64, u64)> = None;
    let mut authorities = BTreeSet::new();
    for entry in entries {
        if count as usize == MAX_MANAGEMENT_HISTORY_ENTRIES {
            return Err(DecodeError::LimitExceeded);
        }
        if entry.authority == Hash::ZERO
            || entry.request == Hash::ZERO
            || entry.epoch == 0
            || entry.sequence <= acknowledged_through
            || !authorities.insert(entry.authority)
            || previous.is_some_and(|(epoch, sequence, slot)| {
                entry.epoch < epoch || entry.sequence <= sequence || entry.observed_slot <= slot
            })
            || matches!(
                entry.result,
                Ok(ManagementReply::Actors(_)
                    | ManagementReply::Resources(_)
                    | ManagementReply::ManagementHistory(_))
            )
        {
            return Err(DecodeError::NonCanonical);
        }
        let result = RuntimeTransition {
            state: Default::default(),
            outcome: RuntimeOutcome::Management(entry.result.clone()),
        }
        .encode()
        .map_err(|_| DecodeError::NonCanonical)?;
        chain = Hash::digest(
            b"vos/agent/management-history/entry/v1",
            &[
                chain.as_bytes(),
                entry.authority.as_bytes(),
                entry.request.as_bytes(),
                &entry.epoch.to_le_bytes(),
                &entry.sequence.to_le_bytes(),
                &entry.observed_slot.to_le_bytes(),
                &result,
            ],
        );
        previous = Some((entry.epoch, entry.sequence, entry.observed_slot));
        count += 1;
    }
    if count == 0 && acknowledged_through != 0 {
        return Err(DecodeError::NonCanonical);
    }
    Ok(Hash::digest(
        b"vos/agent/management-history/summary/v1",
        &[
            chain.as_bytes(),
            &acknowledged_through.to_le_bytes(),
            &count.to_le_bytes(),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const RESULT: Result<ManagementReply, ManagementError> = Err(ManagementError::NotFound);

    fn entry(index: u64) -> ManagementHistoryEntry<'static> {
        ManagementHistoryEntry {
            authority: Hash::digest(b"test/authority", &[&index.to_le_bytes()]),
            request: Hash::digest(b"test/request", &[&index.to_le_bytes()]),
            epoch: 2,
            sequence: index + 10,
            observed_slot: index + 20,
            result: &RESULT,
        }
    }

    #[test]
    fn recovery_reply_rejects_wrong_commitment_outcome_and_any_state_change() {
        let state = crate::RuntimeState::default();
        let expected = management_history_commitment(0, []).unwrap();
        let valid = RuntimeTransition {
            state: state.clone(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(expected))),
        };
        assert!(management_history_reply_matches(&state, expected, &valid));
        assert!(!management_history_reply_matches(
            &state,
            Hash([9; 32]),
            &valid
        ));
        assert!(!management_history_reply_matches(
            &state,
            Hash::ZERO,
            &valid
        ));
        for lane in 0..4 {
            let mut changed = valid.clone();
            match lane {
                0 => changed.state.control.push(1),
                1 => changed.state.linear.push(1),
                2 => changed.state.merge.push(1),
                _ => changed.state.local.push(1),
            }
            assert!(!management_history_reply_matches(
                &state, expected, &changed
            ));
        }
        for outcome in [
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
            RuntimeOutcome::Management(Ok(ManagementReply::Resources(Default::default()))),
            RuntimeOutcome::Completed(Err(crate::InvocationError::NotCreated)),
        ] {
            assert!(!management_history_reply_matches(
                &state,
                expected,
                &RuntimeTransition {
                    state: state.clone(),
                    outcome,
                }
            ));
        }
    }

    #[test]
    fn recovery_query_and_reply_have_exact_canonical_wire() {
        use crate::{
            AgentId, DeploymentId, ManagementRequest, RuntimeExecutionContext, RuntimeWork, SpaceId,
        };
        let work = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            state: Default::default(),
            request: alloc::boxed::Box::new(ManagementRequest::InspectManagementHistory),
            authority: None,
            observed_slot: 0,
        };
        let encoded = work.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded).unwrap(), work);
        let mut old_abi = encoded.clone();
        old_abi[4..36].copy_from_slice(b"vos-agent-runtime-abi-260915-r17");
        assert!(RuntimeWork::decode(&old_abi).is_err());
        let reply = RuntimeTransition {
            state: Default::default(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(
                management_history_commitment(0, []).unwrap(),
            ))),
        };
        assert_eq!(
            RuntimeTransition::decode(&reply.encode().unwrap()).unwrap(),
            reply
        );
        let invalid = RuntimeTransition {
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(Hash::ZERO))),
            ..reply
        };
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn every_retained_field_and_watermark_is_bound() {
        let original = entry(1);
        let expected = management_history_commitment(0, [original]).unwrap();
        let other_result = Err(ManagementError::AlreadyExists);
        for changed in [
            ManagementHistoryEntry {
                authority: Hash([9; 32]),
                ..original
            },
            ManagementHistoryEntry {
                request: Hash([9; 32]),
                ..original
            },
            ManagementHistoryEntry {
                epoch: 3,
                ..original
            },
            ManagementHistoryEntry {
                sequence: 12,
                ..original
            },
            ManagementHistoryEntry {
                observed_slot: 22,
                ..original
            },
            ManagementHistoryEntry {
                result: &other_result,
                ..original
            },
        ] {
            assert_ne!(
                management_history_commitment(0, [changed]).unwrap(),
                expected
            );
        }
        assert_ne!(
            management_history_commitment(1, [original]).unwrap(),
            expected
        );
        assert_ne!(
            management_history_commitment(0, [original, entry(2)]).unwrap(),
            expected
        );
        assert_ne!(management_history_commitment(0, []).unwrap(), expected);
    }

    #[test]
    fn malformed_or_unbounded_history_is_rejected() {
        let a = entry(1);
        let b = entry(2);
        for entries in [
            [b, a],
            [
                a,
                ManagementHistoryEntry {
                    authority: a.authority,
                    ..b
                },
            ],
            [a, ManagementHistoryEntry { epoch: 1, ..b }],
            [
                a,
                ManagementHistoryEntry {
                    observed_slot: a.observed_slot,
                    ..b
                },
            ],
            [
                a,
                ManagementHistoryEntry {
                    sequence: a.sequence,
                    ..b
                },
            ],
            [
                a,
                ManagementHistoryEntry {
                    request: Hash::ZERO,
                    ..b
                },
            ],
            [
                a,
                ManagementHistoryEntry {
                    authority: Hash::ZERO,
                    ..b
                },
            ],
        ] {
            assert_eq!(
                management_history_commitment(0, entries),
                Err(DecodeError::NonCanonical)
            );
        }
        assert_eq!(
            management_history_commitment(a.sequence, [a]),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            management_history_commitment(1, []),
            Err(DecodeError::NonCanonical)
        );
        let entries: Vec<_> = (0..MAX_MANAGEMENT_HISTORY_ENTRIES as u64)
            .map(entry)
            .collect();
        assert!(management_history_commitment(0, entries.iter().copied()).is_ok());
        assert_eq!(
            management_history_commitment(0, entries.into_iter().chain([entry(256)])),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn read_only_results_are_not_consumed_decisions() {
        let result = Ok(ManagementReply::Resources(Default::default()));
        assert_eq!(
            management_history_commitment(
                0,
                [ManagementHistoryEntry {
                    result: &result,
                    ..entry(1)
                }]
            ),
            Err(DecodeError::NonCanonical)
        );
    }
}
