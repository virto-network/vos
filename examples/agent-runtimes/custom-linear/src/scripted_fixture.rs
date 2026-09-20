//! Test-only replacement for response-table PVMs which could not retain history.
//!
//! This is deliberately NOT a deployable or authenticating runtime. The host
//! fixture supplies its deterministic transition table inside the admitted
//! program. The guest executes that table and retains the actual management
//! inputs/results needed to exercise runtime-independent recovery.

use alloc::vec::Vec;
use vos_agent_sdk::protocol::wire::{Decoder, Encoder};
use vos_agent_sdk::recovery::{ManagementHistoryEntry, management_history_commitment};
use vos_agent_sdk::wire::CanonicalWire as _;
use vos_agent_sdk::*;

pub const CONFIG_MARKER: [u8; 16] = *b"VOS-SCRIPT-R18V1";
pub const CONFIG_CAPACITY: usize = 64 * 1024;
const STATE_MAGIC: &[u8; 8] = b"VSHIST01";

const fn empty_config() -> [u8; CONFIG_CAPACITY] {
    let mut bytes = [0xd5; CONFIG_CAPACITY];
    let mut i = 0;
    while i < CONFIG_MARKER.len() {
        bytes[i] = CONFIG_MARKER[i];
        i += 1;
    }
    bytes
}

// Tests patch this fixed-size read-only region before signing/admitting the
// program, so its case table participates in the program/package identity.
// Volatile reads prevent constant folding the unconfigured placeholder.
static CONFIG: [u8; CONFIG_CAPACITY] = empty_config();

#[derive(Default)]
pub struct ScriptedRuntime;

#[derive(Clone)]
struct Retained {
    work: Vec<u8>,
    result: Vec<u8>,
}

impl Retained {
    fn decoded(&self) -> (AuthorityData, Result<ManagementReply, ManagementError>) {
        let RuntimeWork::Manage {
            request,
            authority: Some(receipt),
            observed_slot,
            ..
        } = RuntimeWork::decode(&self.work).expect("retained management input")
        else {
            panic!("retained management receipt required")
        };
        let RuntimeOutcome::Management(result) = RuntimeTransition::decode(&self.result)
            .expect("retained result")
            .outcome
        else {
            panic!("management result required")
        };
        (
            AuthorityData {
                authority: receipt.commitment(),
                request: request.replay_commitment(),
                epoch: receipt.selector.epoch,
                sequence: receipt.selector.decision_sequence,
                observed_slot,
            },
            result,
        )
    }
}

struct AuthorityData {
    authority: Hash,
    request: Hash,
    epoch: u64,
    sequence: u64,
    observed_slot: u64,
}

#[derive(Default)]
struct History {
    scope: Option<(SpaceId, AgentId, DeploymentId)>,
    acknowledged: u64,
    retained: Vec<Retained>,
}

impl History {
    fn unwrap(state: &mut RuntimeState) -> Self {
        if state.is_empty() {
            return Self::default();
        }
        let mut decoder = Decoder::new(&state.control);
        assert_eq!(decoder.take(8).unwrap(), STATE_MAGIC);
        let scope = Some((
            SpaceId(decoder.fixed().unwrap()),
            AgentId(decoder.fixed().unwrap()),
            DeploymentId(decoder.fixed().unwrap()),
        ));
        let acknowledged = decoder.u64().unwrap();
        let control = decoder.bytes_bounded(MAX_RUNTIME_STATE_BYTES).unwrap();
        let count = decoder.u32().unwrap() as usize;
        assert!(count <= vos_agent_sdk::recovery::MAX_MANAGEMENT_HISTORY_ENTRIES);
        let mut retained = Vec::new();
        for _ in 0..count {
            retained.push(Retained {
                work: decoder
                    .bytes_bounded(RuntimeWork::MAX_ENCODED_BYTES)
                    .unwrap(),
                result: decoder
                    .bytes_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                    .unwrap(),
            });
        }
        assert!(decoder.exhausted());
        state.control = control;
        Self {
            scope,
            acknowledged,
            retained,
        }
    }

    fn wrap(&self, state: &mut RuntimeState) {
        let (space, agent, deployment) = self.scope.expect("created scope");
        let mut control = Vec::new();
        control.extend_from_slice(STATE_MAGIC);
        let mut encoder = Encoder(&mut control);
        encoder.fixed(space.as_bytes());
        encoder.fixed(agent.as_bytes());
        encoder.fixed(deployment.as_bytes());
        encoder.u64(self.acknowledged);
        encoder.bytes(&state.control);
        encoder.u32(self.retained.len() as u32);
        for record in &self.retained {
            encoder.bytes(&record.work);
            encoder.bytes(&record.result);
        }
        state.control = control;
        assert!(state.validate());
    }

    fn commitment(&self) -> Hash {
        let records: Vec<_> = self.retained.iter().map(Retained::decoded).collect();
        management_history_commitment(
            self.acknowledged,
            records
                .iter()
                .map(|(record, result)| ManagementHistoryEntry {
                    authority: record.authority,
                    request: record.request,
                    epoch: record.epoch,
                    sequence: record.sequence,
                    observed_slot: record.observed_slot,
                    result,
                }),
        )
        .expect("canonical fixture history")
    }
}

fn state_mut(work: &mut RuntimeWork) -> &mut RuntimeState {
    match work {
        RuntimeWork::Manage { state, .. }
        | RuntimeWork::Invoke { state, .. }
        | RuntimeWork::Resume { state, .. }
        | RuntimeWork::Acknowledge { state, .. } => state,
    }
}

impl AgentRuntime for ScriptedRuntime {
    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::standard()
    }

    fn apply(&mut self, work: RuntimeWork) -> RuntimeTransition {
        let mut bytes = Vec::with_capacity(CONFIG_CAPACITY);
        for i in 0..CONFIG_CAPACITY {
            // SAFETY: every offset is inside the immutable CONFIG array.
            bytes.push(unsafe { core::ptr::read_volatile(CONFIG.as_ptr().add(i)) });
        }
        Self::apply_table(work, &bytes)
    }
}

impl ScriptedRuntime {
    pub fn apply_table(mut work: RuntimeWork, config: &[u8]) -> RuntimeTransition {
        assert!(work.execution_context().is_direct());
        let original_state = state_mut(&mut work).clone();
        let mut history = History::unwrap(state_mut(&mut work));
        if let RuntimeWork::Manage {
            space,
            agent,
            runtime_deployment,
            request,
            authority,
            ..
        } = &work
        {
            if request.as_ref() == &ManagementRequest::InspectManagementHistory {
                assert!(authority.is_none());
                assert_eq!(history.scope, Some((*space, *agent, *runtime_deployment)));
                return RuntimeTransition {
                    state: original_state,
                    outcome: RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(
                        history.commitment(),
                    ))),
                };
            }
        }
        let input = work.encode().expect("fixture input");
        let inner_prior = state_mut(&mut work).clone();
        let mut decoder = Decoder::new(config);
        assert_eq!(decoder.take(CONFIG_MARKER.len()).unwrap(), CONFIG_MARKER);
        let count = decoder.u32().unwrap();
        assert!(count <= 256);
        let mut selected = None;
        for _ in 0..count {
            let length = decoder.u32().unwrap() as usize;
            let discriminator = decoder
                .option(|decoder| Ok((decoder.u32()?, decoder.u8()?)))
                .unwrap();
            let mut output = decoder
                .bytes_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            let copies = decoder.u32().unwrap();
            assert!(copies <= 256);
            let matches = input.len() == length
                && discriminator
                    .is_none_or(|(offset, value)| input.get(offset as usize) == Some(&value));
            for _ in 0..copies {
                let from = decoder.u32().unwrap() as usize;
                let to = decoder.u32().unwrap() as usize;
                let len = decoder.u32().unwrap() as usize;
                if matches {
                    output[to..to + len].copy_from_slice(&input[from..from + len]);
                }
            }
            if matches {
                assert!(selected.is_none(), "ambiguous fixture case");
                selected = Some(output);
            }
        }
        let mut transition =
            RuntimeTransition::decode(&selected.expect("fixture case missing")).unwrap();
        if let RuntimeWork::Manage {
            request,
            authority: Some(receipt),
            ..
        } = &work
        {
            let RuntimeOutcome::Management(result) = &transition.outcome else {
                panic!("management outcome")
            };
            let prior = history
                .retained
                .iter()
                .find(|record| record.decoded().0.authority == receipt.commitment());
            if let Some(prior) = prior {
                let (record, expected) = prior.decoded();
                assert_eq!(record.request, request.replay_commitment());
                assert_eq!(expected, *result);
                assert_eq!(transition.state, inner_prior);
            } else if transition.state != inner_prior || result.is_ok() {
                history.acknowledged = receipt.selector.acknowledged_through;
                history
                    .retained
                    .retain(|record| record.decoded().0.sequence > history.acknowledged);
                match result {
                    Ok(
                        ManagementReply::Created(identity)
                        | ManagementReply::RuntimeUpgraded(identity),
                    ) => {
                        history.scope =
                            Some((identity.space, identity.agent, identity.runtime_deployment));
                    }
                    _ => {}
                }
                let mut retained_work = work.clone();
                *state_mut(&mut retained_work) = RuntimeState::default();
                history.retained.push(Retained {
                    work: retained_work.encode().unwrap(),
                    result: RuntimeTransition {
                        state: RuntimeState::default(),
                        outcome: transition.outcome.clone(),
                    }
                    .encode()
                    .unwrap(),
                });
                history.commitment(); // Validate bounded ordering before publication.
            }
        }
        history.wrap(&mut transition.state);
        transition
    }
}
