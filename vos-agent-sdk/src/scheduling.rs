//! Deterministic, host-independent runtime scheduling components.
//!
//! Timers are runtime-owned state. A host supplies only a durable monotonic
//! observation: a Local host persists its observation before applying work,
//! while a Shared leader commits its observation in the ordered log. Private
//! agents deliberately have no scheduling surface in this protocol release.

use alloc::vec::Vec;
use core::cmp::Ordering;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::{
    ActorId, AgentProfile, DeploymentId, Hash, InvocationId, MethodMode, ProgramId, ScheduleId,
};

pub const MAX_SCHEDULES: usize = 4_096;
pub const MAX_SCHEDULE_MESSAGE_BYTES: usize = crate::MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_SCHEDULE_STATE_BYTES: usize = crate::MAX_RUNTIME_STATE_BYTES;
pub const MAX_SCHEDULE_FIRES_PER_SLICE: usize = 256;

const SCHEDULER_STATE_MAGIC: [u8; 8] = *b"VOSSCHD1";

/// Exact timer ordering. Smaller priorities run first at the same slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScheduleKey {
    pub due_slot: u64,
    pub priority: u8,
    pub schedule: ScheduleId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleCadence {
    Once,
    Interval { slots: u64 },
}

impl ScheduleCadence {
    pub const fn validate(self) -> bool {
        matches!(self, Self::Once) || matches!(self, Self::Interval { slots } if slots != 0)
    }
}

/// One durable callback owned by a scheduling-capable runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleEntry {
    pub schedule: ScheduleId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    /// Scheduling is available only for ordered Linear callbacks in this
    /// release, for both Local and Shared agents.
    pub mode: MethodMode,
    pub message: Vec<u8>,
    pub due_slot: u64,
    pub priority: u8,
    pub cadence: ScheduleCadence,
}

impl ScheduleEntry {
    pub const fn key(&self) -> ScheduleKey {
        ScheduleKey {
            due_slot: self.due_slot,
            priority: self.priority,
            schedule: self.schedule,
        }
    }

    pub fn validate(&self) -> bool {
        self.schedule != ScheduleId::ZERO
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.mode == MethodMode::Linear
            && self.message.len() <= MAX_SCHEDULE_MESSAGE_BYTES
            && self.cadence.validate()
    }
}

/// Source of a scheduling observation. The source is part of work so a
/// runtime cannot accidentally accept a node-local clock in Shared state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ScheduleObservationSource {
    DurableLocal = 0,
    CommittedLeader = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleObservation {
    pub slot: u64,
    pub source: ScheduleObservationSource,
}

impl ScheduleObservation {
    pub const fn valid_for(self, profile: AgentProfile) -> bool {
        matches!(
            (profile, self.source),
            (AgentProfile::Local, ScheduleObservationSource::DurableLocal)
                | (
                    AgentProfile::Shared,
                    ScheduleObservationSource::CommittedLeader
                )
        )
    }
}

/// One due callback. Its invocation identity is stable for exactly one
/// `(schedule, due_slot)` occurrence, making replay an exact retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleFire {
    pub schedule: ScheduleId,
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub message: Vec<u8>,
    pub due_slot: u64,
    pub priority: u8,
    pub ready_sequence: u64,
}

impl ScheduleFire {
    fn from_entry(entry: &ScheduleEntry, ready_sequence: u64) -> Self {
        Self {
            schedule: entry.schedule,
            invocation: InvocationId::for_schedule(entry.schedule, entry.due_slot),
            actor: entry.actor,
            incarnation: entry.incarnation,
            deployment: entry.deployment,
            program: entry.program,
            mode: entry.mode,
            message: entry.message.clone(),
            due_slot: entry.due_slot,
            priority: entry.priority,
            ready_sequence,
        }
    }

    pub const fn ready(&self) -> ReadyWorkDescriptor {
        ReadyWorkDescriptor {
            ready_sequence: self.ready_sequence,
            invocation: self.invocation,
            class: ReadyWorkClass::Scheduled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ReadyWorkClass {
    Invocation = 0,
    Continuation = 1,
    Scheduled = 2,
}

/// Minimal descriptor consumed by runtime ready-work ordering components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyWorkDescriptor {
    pub ready_sequence: u64,
    pub invocation: InvocationId,
    pub class: ReadyWorkClass,
}

pub trait ReadyWorkOrdering {
    fn compare(&self, left: &ReadyWorkDescriptor, right: &ReadyWorkDescriptor) -> Ordering;
}

/// Ordering used by the embedded standard runtime. `ready_sequence` is the
/// FIFO key; the remaining fields provide a total fail-closed tie-break.
#[derive(Clone, Copy, Debug, Default)]
pub struct FifoReadyWork;

impl ReadyWorkOrdering for FifoReadyWork {
    fn compare(&self, left: &ReadyWorkDescriptor, right: &ReadyWorkDescriptor) -> Ordering {
        (left.ready_sequence, left.invocation, left.class).cmp(&(
            right.ready_sequence,
            right.invocation,
            right.class,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulingError {
    Unsupported,
    UnsupportedProfile,
    InvalidEntry,
    DuplicateSchedule,
    NotFound,
    Capacity,
    ObservationRegressed,
    InvalidObservationSource,
    ReadySequenceExhausted,
}

pub trait TimerScheduler {
    const ENABLED: bool;

    fn schedule(
        &mut self,
        profile: AgentProfile,
        entry: ScheduleEntry,
    ) -> Result<(), SchedulingError>;

    fn cancel(
        &mut self,
        profile: AgentProfile,
        schedule: ScheduleId,
    ) -> Result<ScheduleEntry, SchedulingError>;

    fn observe(
        &mut self,
        profile: AgentProfile,
        observation: ScheduleObservation,
        limit: usize,
    ) -> Result<Vec<ScheduleFire>, SchedulingError>;
}

/// Timer component used by the standard runtime: the API is absent by
/// capability declaration and fails closed if called internally.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoScheduling;

impl TimerScheduler for NoScheduling {
    const ENABLED: bool = false;

    fn schedule(
        &mut self,
        _profile: AgentProfile,
        _entry: ScheduleEntry,
    ) -> Result<(), SchedulingError> {
        Err(SchedulingError::Unsupported)
    }

    fn cancel(
        &mut self,
        _profile: AgentProfile,
        _schedule: ScheduleId,
    ) -> Result<ScheduleEntry, SchedulingError> {
        Err(SchedulingError::Unsupported)
    }

    fn observe(
        &mut self,
        _profile: AgentProfile,
        _observation: ScheduleObservation,
        _limit: usize,
    ) -> Result<Vec<ScheduleFire>, SchedulingError> {
        Err(SchedulingError::Unsupported)
    }
}

/// Canonical timer state used by the scheduling runtime example and available
/// to custom runtimes. Entries are always stored by
/// `(due_slot, priority, schedule_id)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeterministicScheduler {
    last_observation: Option<u64>,
    next_ready_sequence: u64,
    entries: Vec<ScheduleEntry>,
}

impl DeterministicScheduler {
    pub const fn last_observation(&self) -> Option<u64> {
        self.last_observation
    }

    pub const fn next_ready_sequence(&self) -> u64 {
        self.next_ready_sequence
    }

    pub fn entries(&self) -> &[ScheduleEntry] {
        &self.entries
    }

    fn encoded_len(&self) -> Option<usize> {
        // Magic, optional-observation tag/value, ready sequence, list length.
        let mut length = 8usize
            .checked_add(1)?
            .checked_add(self.last_observation.map_or(0, |_| 8))?
            .checked_add(8)?
            .checked_add(4)?;
        for entry in &self.entries {
            // Five identities, mode, length-prefixed message, due slot,
            // priority, cadence tag, and the optional interval.
            length = length
                .checked_add(5 * 32)?
                .checked_add(1)?
                .checked_add(4)?
                .checked_add(entry.message.len())?
                .checked_add(8)?
                .checked_add(1)?
                .checked_add(1)?
                .checked_add(match entry.cadence {
                    ScheduleCadence::Once => 0,
                    ScheduleCadence::Interval { .. } => 8,
                })?;
        }
        Some(length)
    }

    pub fn validate(&self) -> bool {
        self.entries.len() <= MAX_SCHEDULES
            && self.entries.iter().all(ScheduleEntry::validate)
            && self
                .entries
                .windows(2)
                .all(|pair| pair[0].key() < pair[1].key())
            && self.entries.iter().enumerate().all(|(index, entry)| {
                self.entries[index + 1..]
                    .iter()
                    .all(|other| other.schedule != entry.schedule)
            })
            && self
                .encoded_len()
                .is_some_and(|total| total <= MAX_SCHEDULE_STATE_BYTES)
    }

    fn require_profile(profile: AgentProfile) -> Result<(), SchedulingError> {
        if matches!(profile, AgentProfile::Local | AgentProfile::Shared) {
            Ok(())
        } else {
            Err(SchedulingError::UnsupportedProfile)
        }
    }

    fn insert_sorted(&mut self, entry: ScheduleEntry) -> Result<(), SchedulingError> {
        if self.entries.len() >= MAX_SCHEDULES {
            return Err(SchedulingError::Capacity);
        }
        if self
            .entries
            .iter()
            .any(|existing| existing.schedule == entry.schedule)
        {
            return Err(SchedulingError::DuplicateSchedule);
        }
        let position = self
            .entries
            .binary_search_by_key(&entry.key(), ScheduleEntry::key)
            .unwrap_or_else(|position| position);
        self.entries.insert(position, entry);
        if !self.validate() {
            self.entries.remove(position);
            return Err(SchedulingError::Capacity);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SchedulingError> {
        if !self.validate() {
            return Err(SchedulingError::InvalidEntry);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SCHEDULER_STATE_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.option(&self.last_observation, |encoder, slot| encoder.u64(*slot));
        encoder.u64(self.next_ready_sequence);
        encoder.list(&self.entries, encode_entry);
        if bytes.len() > MAX_SCHEDULE_STATE_BYTES {
            return Err(SchedulingError::Capacity);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_SCHEDULE_STATE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(SCHEDULER_STATE_MAGIC.len())? != SCHEDULER_STATE_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        let state = Self {
            last_observation: decoder.option(Decoder::u64)?,
            next_ready_sequence: decoder.u64()?,
            entries: decoder.list_bounded(MAX_SCHEDULES, decode_entry)?,
        };
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if !state.validate() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(state)
    }
}

impl TimerScheduler for DeterministicScheduler {
    const ENABLED: bool = true;

    fn schedule(
        &mut self,
        profile: AgentProfile,
        entry: ScheduleEntry,
    ) -> Result<(), SchedulingError> {
        Self::require_profile(profile)?;
        if !entry.validate() {
            return Err(SchedulingError::InvalidEntry);
        }
        self.insert_sorted(entry)
    }

    fn cancel(
        &mut self,
        profile: AgentProfile,
        schedule: ScheduleId,
    ) -> Result<ScheduleEntry, SchedulingError> {
        Self::require_profile(profile)?;
        let position = self
            .entries
            .iter()
            .position(|entry| entry.schedule == schedule)
            .ok_or(SchedulingError::NotFound)?;
        Ok(self.entries.remove(position))
    }

    fn observe(
        &mut self,
        profile: AgentProfile,
        observation: ScheduleObservation,
        limit: usize,
    ) -> Result<Vec<ScheduleFire>, SchedulingError> {
        Self::require_profile(profile)?;
        if !observation.valid_for(profile) {
            return Err(SchedulingError::InvalidObservationSource);
        }
        if self
            .last_observation
            .is_some_and(|previous| observation.slot < previous)
        {
            return Err(SchedulingError::ObservationRegressed);
        }
        let limit = limit.min(MAX_SCHEDULE_FIRES_PER_SLICE);
        let mut candidate = self.clone();
        candidate.last_observation = Some(observation.slot);
        let mut fires = Vec::new();
        while fires.len() < limit
            && candidate
                .entries
                .first()
                .is_some_and(|entry| entry.due_slot <= observation.slot)
        {
            let entry = candidate.entries.remove(0);
            let ready_sequence = candidate.next_ready_sequence;
            candidate.next_ready_sequence = candidate
                .next_ready_sequence
                .checked_add(1)
                .ok_or(SchedulingError::ReadySequenceExhausted)?;
            fires.push(ScheduleFire::from_entry(&entry, ready_sequence));

            if let ScheduleCadence::Interval { slots } = entry.cadence
                && let Some(next_due) = entry.due_slot.checked_add(slots)
            {
                let mut next = entry;
                // Advance from the previous due slot, never the observed slot,
                // so restarts, delayed leaders, and bounded catch-up do not
                // introduce drift or duplicate an occurrence.
                next.due_slot = next_due;
                candidate.insert_sorted(next)?;
            }
        }
        *self = candidate;
        Ok(fires)
    }
}

pub trait RuntimeComposition {
    type Ordering: ReadyWorkOrdering;
    type Timers: TimerScheduler;

    fn ready_ordering(&self) -> &Self::Ordering;
    fn timers(&mut self) -> &mut Self::Timers;

    fn scheduling_enabled(&self) -> bool {
        Self::Timers::ENABLED
    }
}

#[derive(Clone, Debug, Default)]
pub struct StandardRuntimeComposition {
    ordering: FifoReadyWork,
    timers: NoScheduling,
}

impl RuntimeComposition for StandardRuntimeComposition {
    type Ordering = FifoReadyWork;
    type Timers = NoScheduling;

    fn ready_ordering(&self) -> &Self::Ordering {
        &self.ordering
    }

    fn timers(&mut self) -> &mut Self::Timers {
        &mut self.timers
    }
}

#[derive(Clone, Debug, Default)]
pub struct SchedulerRuntimeComposition {
    ordering: FifoReadyWork,
    timers: DeterministicScheduler,
}

impl SchedulerRuntimeComposition {
    pub fn from_timer_state(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            ordering: FifoReadyWork,
            timers: DeterministicScheduler::decode(bytes)?,
        })
    }
}

impl RuntimeComposition for SchedulerRuntimeComposition {
    type Ordering = FifoReadyWork;
    type Timers = DeterministicScheduler;

    fn ready_ordering(&self) -> &Self::Ordering {
        &self.ordering
    }

    fn timers(&mut self) -> &mut Self::Timers {
        &mut self.timers
    }
}

fn encode_entry(encoder: &mut Encoder<'_>, entry: &ScheduleEntry) {
    encoder.fixed(entry.schedule.as_bytes());
    encoder.fixed(entry.actor.as_bytes());
    encoder.fixed(entry.incarnation.as_bytes());
    encoder.fixed(entry.deployment.as_bytes());
    encoder.fixed(entry.program.as_bytes());
    encoder.u8(entry.mode as u8);
    encoder.bytes(&entry.message);
    encoder.u64(entry.due_slot);
    encoder.u8(entry.priority);
    match entry.cadence {
        ScheduleCadence::Once => encoder.u8(0),
        ScheduleCadence::Interval { slots } => {
            encoder.u8(1);
            encoder.u64(slots);
        }
    }
}

fn decode_entry(decoder: &mut Decoder<'_>) -> Result<ScheduleEntry, DecodeError> {
    let entry = ScheduleEntry {
        schedule: ScheduleId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        mode: match decoder.u8()? {
            0 => MethodMode::Query,
            1 => MethodMode::LinearizableQuery,
            2 => MethodMode::LocalQuery,
            3 => MethodMode::Linear,
            4 => MethodMode::Merge,
            5 => MethodMode::Local,
            _ => return Err(DecodeError::InvalidTag),
        },
        message: decoder.bytes_bounded(MAX_SCHEDULE_MESSAGE_BYTES)?,
        due_slot: decoder.u64()?,
        priority: decoder.u8()?,
        cadence: match decoder.u8()? {
            0 => ScheduleCadence::Once,
            1 => ScheduleCadence::Interval {
                slots: decoder.u64()?,
            },
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    if !entry.validate() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn entry(id: u8, due_slot: u64, priority: u8, cadence: ScheduleCadence) -> ScheduleEntry {
        ScheduleEntry {
            schedule: ScheduleId([id; 32]),
            actor: ActorId([7; 32]),
            incarnation: Hash([8; 32]),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            mode: MethodMode::Linear,
            message: vec![id, 42],
            due_slot,
            priority,
            cadence,
        }
    }

    fn local(slot: u64) -> ScheduleObservation {
        ScheduleObservation {
            slot,
            source: ScheduleObservationSource::DurableLocal,
        }
    }

    #[test]
    fn timers_use_due_priority_schedule_order_and_survive_restart() {
        let mut scheduler = DeterministicScheduler::default();
        scheduler
            .schedule(AgentProfile::Local, entry(3, 9, 1, ScheduleCadence::Once))
            .unwrap();
        scheduler
            .schedule(AgentProfile::Local, entry(2, 9, 0, ScheduleCadence::Once))
            .unwrap();
        scheduler
            .schedule(AgentProfile::Local, entry(1, 8, 9, ScheduleCadence::Once))
            .unwrap();
        let encoded = scheduler.encode().unwrap();
        let mut restored = DeterministicScheduler::decode(&encoded).unwrap();
        assert_eq!(restored.encode().unwrap(), encoded);

        let fires = restored.observe(AgentProfile::Local, local(9), 10).unwrap();
        assert_eq!(
            fires.iter().map(|fire| fire.schedule).collect::<Vec<_>>(),
            vec![
                ScheduleId([1; 32]),
                ScheduleId([2; 32]),
                ScheduleId([3; 32])
            ]
        );
        assert!(restored.entries().is_empty());
    }

    #[test]
    fn intervals_advance_from_previous_due_without_drift_or_duplicates() {
        let mut scheduler = DeterministicScheduler::default();
        scheduler
            .schedule(
                AgentProfile::Shared,
                entry(1, 10, 0, ScheduleCadence::Interval { slots: 3 }),
            )
            .unwrap();
        let observation = ScheduleObservation {
            slot: 17,
            source: ScheduleObservationSource::CommittedLeader,
        };
        let fires = scheduler
            .observe(AgentProfile::Shared, observation, 2)
            .unwrap();
        assert_eq!(
            fires.iter().map(|fire| fire.due_slot).collect::<Vec<_>>(),
            vec![10, 13]
        );
        assert_eq!(scheduler.entries()[0].due_slot, 16);
        assert_ne!(fires[0].invocation, fires[1].invocation);

        // The same committed observation continues bounded catch-up from the
        // persisted prior due time; an already-fired occurrence cannot repeat.
        let catch_up = scheduler
            .observe(AgentProfile::Shared, observation, 10)
            .unwrap();
        assert_eq!(
            catch_up
                .iter()
                .map(|fire| fire.due_slot)
                .collect::<Vec<_>>(),
            vec![16]
        );
        assert_eq!(scheduler.entries()[0].due_slot, 19);
    }

    #[test]
    fn observations_are_profile_typed_monotonic_and_private_is_unsupported() {
        let mut scheduler = DeterministicScheduler::default();
        assert_eq!(
            scheduler.observe(
                AgentProfile::Shared,
                ScheduleObservation {
                    slot: 1,
                    source: ScheduleObservationSource::DurableLocal,
                },
                1,
            ),
            Err(SchedulingError::InvalidObservationSource)
        );
        scheduler.observe(AgentProfile::Local, local(5), 1).unwrap();
        assert_eq!(
            scheduler.observe(AgentProfile::Local, local(4), 1),
            Err(SchedulingError::ObservationRegressed)
        );
        assert_eq!(
            scheduler.schedule(AgentProfile::Private, entry(1, 9, 0, ScheduleCadence::Once)),
            Err(SchedulingError::UnsupportedProfile)
        );
    }

    #[test]
    fn duplicate_schedule_ids_and_non_linear_callbacks_fail_closed() {
        let mut scheduler = DeterministicScheduler::default();
        scheduler
            .schedule(AgentProfile::Local, entry(1, 1, 0, ScheduleCadence::Once))
            .unwrap();
        assert_eq!(
            scheduler.schedule(AgentProfile::Local, entry(1, 2, 0, ScheduleCadence::Once)),
            Err(SchedulingError::DuplicateSchedule)
        );
        let mut merge = entry(2, 2, 0, ScheduleCadence::Once);
        merge.mode = MethodMode::Merge;
        assert_eq!(
            scheduler.schedule(AgentProfile::Local, merge),
            Err(SchedulingError::InvalidEntry)
        );
    }

    #[test]
    fn scheduler_wire_rejects_trailing_and_noncanonical_order() {
        let mut scheduler = DeterministicScheduler::default();
        scheduler
            .schedule(AgentProfile::Local, entry(1, 1, 0, ScheduleCadence::Once))
            .unwrap();
        scheduler
            .schedule(AgentProfile::Local, entry(2, 2, 0, ScheduleCadence::Once))
            .unwrap();
        let mut encoded = scheduler.encode().unwrap();
        encoded.push(0);
        assert_eq!(
            DeterministicScheduler::decode(&encoded),
            Err(DecodeError::TrailingBytes)
        );

        let mut state = scheduler;
        state.entries.swap(0, 1);
        assert_eq!(state.encode(), Err(SchedulingError::InvalidEntry));
    }

    #[test]
    fn fifo_and_no_timer_compositions_are_explicit() {
        let early = ReadyWorkDescriptor {
            ready_sequence: 1,
            invocation: InvocationId([9; 32]),
            class: ReadyWorkClass::Continuation,
        };
        let late = ReadyWorkDescriptor {
            ready_sequence: 2,
            invocation: InvocationId([1; 32]),
            class: ReadyWorkClass::Invocation,
        };
        assert_eq!(FifoReadyWork.compare(&early, &late), Ordering::Less);

        let mut standard = StandardRuntimeComposition::default();
        assert!(!standard.scheduling_enabled());
        assert_eq!(
            standard.timers().observe(AgentProfile::Local, local(1), 1),
            Err(SchedulingError::Unsupported)
        );
        assert!(SchedulerRuntimeComposition::default().scheduling_enabled());
    }

    #[test]
    fn ready_sequence_exhaustion_is_transactional() {
        let mut scheduler = DeterministicScheduler {
            next_ready_sequence: u64::MAX,
            ..DeterministicScheduler::default()
        };
        scheduler
            .schedule(AgentProfile::Local, entry(1, 1, 0, ScheduleCadence::Once))
            .unwrap();
        let before = scheduler.clone();
        assert_eq!(
            scheduler.observe(AgentProfile::Local, local(1), 1),
            Err(SchedulingError::ReadySequenceExhausted)
        );
        assert_eq!(scheduler, before);
    }
}
