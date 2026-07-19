//! Guest-Accumulate conformance model.
//!
//! The production service PVM implements the same checks before writing JAM
//! service storage. This in-memory state is deliberately clone-and-swap: a
//! rejected transition cannot leak writes, dedup records, replies, or outbox
//! messages.

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use super::contracts::*;
use super::identity::*;
use super::wire::Encoder;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulateError {
    WrongService,
    WrongAbi,
    WrongExecutionSemantics,
    WrongProgram,
    InvalidConsistency,
    Unauthorized,
    MissingBlob(Hash),
    MissingProof,
    InvalidProof,
    StaleLinearWork {
        expected_revision: u64,
        actual_revision: u64,
    },
    StaleStateRoot,
    MissingCausalDependency(Hash),
    TransitionInputMismatch,
    TransitionBaseMismatch,
    DivergentDuplicate,
    InvalidWorkflowTransition,
    ContinuationConflict(ActorId),
    MessageCycle,
}

impl core::fmt::Display for AccumulateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "accumulate rejected transition: {self:?}")
    }
}

impl core::error::Error for AccumulateError {}

pub trait AccumulationValidator {
    fn authorize(&self, work: &WorkEnvelopeV2) -> bool;
    fn blob_available(&self, blob: &BlobRefV2) -> bool;
    fn verify_proof(
        &self,
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
        proof: &ProofCommitmentV2,
    ) -> bool;
}

/// Minimal validator useful for local conformance tests. It admits only work
/// explicitly marked public; callers with credentials/system capabilities must
/// provide a real policy verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowPublic;

impl AccumulationValidator for AllowPublic {
    fn authorize(&self, work: &WorkEnvelopeV2) -> bool {
        matches!(work.authorization, AuthorizationEvidenceV2::Public)
    }

    fn blob_available(&self, _blob: &BlobRefV2) -> bool {
        false
    }

    fn verify_proof(
        &self,
        _work: &WorkEnvelopeV2,
        _transition: &TransitionV2,
        proof: &ProofCommitmentV2,
    ) -> bool {
        proof.statement_version == super::ATTESTATION_STATEMENT_VERSION
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishedEffects {
    pub reply: Option<ReplyRecordV2>,
    pub outbox: Vec<MessageRecordV2>,
    pub exported_blobs: Vec<BlobRefV2>,
    pub proof: Option<ProofCommitmentV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulationOutcome {
    pub receipt: AccumulationReceiptV2,
    /// Effects become observable only in the successful return value, after the
    /// clone-and-swap commit completed.
    pub published: PublishedEffects,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DedupRecord {
    transition: Hash,
    receipt: AccumulationReceiptV2,
}

#[derive(Debug, Clone)]
pub struct InMemoryServiceState {
    identity: ServiceIdentityV2,
    consistency: ConsistencyModeV2,
    revision: u64,
    checkpoint: u64,
    state_root: Hash,
    crdt_heads: BTreeSet<Hash>,
    causal_nodes: BTreeSet<Hash>,
    programs: BTreeMap<ActorId, ProgramId>,
    actor_rows: BTreeMap<(ActorId, Vec<u8>), Vec<u8>>,
    continuations: BTreeMap<ActorId, BlobRefV2>,
    inbox: BTreeMap<ActorId, Vec<MessageRecordV2>>,
    outbox: Vec<MessageRecordV2>,
    blobs: BTreeSet<Hash>,
    operations: BTreeMap<OperationId, CrdtOperationV2>,
    receipts: BTreeMap<InvocationId, DedupRecord>,
}

impl InMemoryServiceState {
    pub fn new(identity: ServiceIdentityV2, consistency: ConsistencyModeV2) -> Self {
        let mut state = Self {
            identity,
            consistency,
            revision: 0,
            checkpoint: 0,
            state_root: Hash::ZERO,
            crdt_heads: BTreeSet::new(),
            causal_nodes: BTreeSet::new(),
            programs: BTreeMap::new(),
            actor_rows: BTreeMap::new(),
            continuations: BTreeMap::new(),
            inbox: BTreeMap::new(),
            outbox: Vec::new(),
            blobs: BTreeSet::new(),
            operations: BTreeMap::new(),
            receipts: BTreeMap::new(),
        };
        state.state_root = state.compute_state_root();
        state
    }

    pub fn identity(&self) -> &ServiceIdentityV2 {
        &self.identity
    }

    pub const fn consistency(&self) -> ConsistencyModeV2 {
        self.consistency
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn state_root(&self) -> Hash {
        self.state_root
    }

    pub fn crdt_heads(&self) -> &BTreeSet<Hash> {
        &self.crdt_heads
    }

    pub fn row(&self, actor: ActorId, key: &[u8]) -> Option<&[u8]> {
        self.actor_rows
            .get(&(actor, key.to_vec()))
            .map(Vec::as_slice)
    }

    pub fn continuation(&self, actor: ActorId) -> Option<&BlobRefV2> {
        self.continuations.get(&actor)
    }

    pub fn queued_messages(&self, actor: ActorId) -> &[MessageRecordV2] {
        self.inbox.get(&actor).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn install_actor(&mut self, actor: ActorId, program: ProgramId) {
        self.programs.insert(actor, program);
        self.state_root = self.compute_state_root();
    }

    pub fn make_blob_available(&mut self, hash: Hash) {
        self.blobs.insert(hash);
    }

    pub fn add_causal_node(&mut self, hash: Hash) {
        self.causal_nodes.insert(hash);
        self.crdt_heads.insert(hash);
    }

    pub fn current_base(&self) -> ConsistencyBaseV2 {
        match self.consistency {
            ConsistencyModeV2::Crdt => ConsistencyBaseV2::Crdt {
                heads: self.crdt_heads.iter().copied().collect(),
            },
            _ => ConsistencyBaseV2::Linear {
                revision: self.revision,
                state_root: self.state_root,
            },
        }
    }

    pub fn accumulate<V: AccumulationValidator>(
        &mut self,
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
        validator: &V,
    ) -> Result<AccumulationOutcome, AccumulateError> {
        let transition_hash = transition.hash();

        if let Some(existing) = self.receipts.get(&work.invocation) {
            if existing.transition != transition_hash {
                return Err(AccumulateError::DivergentDuplicate);
            }
            return Ok(AccumulationOutcome {
                receipt: existing.receipt.clone(),
                published: PublishedEffects::default(),
                duplicate: true,
            });
        }

        self.validate(work, transition, validator)?;

        // From this point all validation has succeeded. Mutate a private copy;
        // only the final assignment is the commit point.
        let mut next = self.clone();
        next.apply_transition(transition)?;
        next.checkpoint = next.checkpoint.saturating_add(1);
        if next.consistency != ConsistencyModeV2::Crdt {
            next.revision = next.revision.saturating_add(1);
        }
        next.state_root = next.compute_state_root();

        let receipt = AccumulationReceiptV2 {
            service: next.identity.clone(),
            accepted_transition: transition_hash,
            resulting_state_root: (next.consistency != ConsistencyModeV2::Crdt)
                .then_some(next.state_root),
            resulting_crdt_heads: next.crdt_heads.iter().copied().collect(),
            sequence: next.revision,
            checkpoint: next.checkpoint,
            consistency: next.consistency,
        };
        next.receipts.insert(
            work.invocation,
            DedupRecord {
                transition: transition_hash,
                receipt: receipt.clone(),
            },
        );

        let published = PublishedEffects {
            reply: transition.reply.clone(),
            outbox: transition.outbox.clone(),
            exported_blobs: transition.exported_blobs.clone(),
            proof: transition.proof.clone(),
        };

        *self = next;
        Ok(AccumulationOutcome {
            receipt,
            published,
            duplicate: false,
        })
    }

    fn validate<V: AccumulationValidator>(
        &self,
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
        validator: &V,
    ) -> Result<(), AccumulateError> {
        if work.service != self.identity || transition.service != self.identity {
            return Err(AccumulateError::WrongService);
        }
        if self.identity.service_abi != super::ABI_VERSION {
            return Err(AccumulateError::WrongAbi);
        }
        if self.identity.execution_semantics != super::EXECUTION_SEMANTICS_ID {
            return Err(AccumulateError::WrongExecutionSemantics);
        }
        if work.consistency != self.consistency
            || !work.base.mode_compatible(work.consistency)
            || !transition.base.mode_compatible(work.consistency)
        {
            return Err(AccumulateError::InvalidConsistency);
        }
        if transition.consumed_input != work.invocation {
            return Err(AccumulateError::TransitionInputMismatch);
        }
        if transition.base != work.base {
            return Err(AccumulateError::TransitionBaseMismatch);
        }
        if transition.target_program != work.target_program
            || self.programs.get(&work.target) != Some(&work.target_program)
        {
            return Err(AccumulateError::WrongProgram);
        }
        if !validator.authorize(work) {
            return Err(AccumulateError::Unauthorized);
        }

        self.validate_base(&work.base)?;

        for blob in
            work.imported_blobs
                .iter()
                .chain(work.imported_actors.iter().flat_map(|actor| {
                    core::iter::once(&actor.state).chain(actor.continuation.iter())
                }))
                .chain(transition.exported_blobs.iter())
                .chain(
                    transition
                        .continuations
                        .iter()
                        .filter_map(|change| change.replacement.as_ref()),
                )
        {
            if !self.blobs.contains(&blob.hash) && !validator.blob_available(blob) {
                return Err(AccumulateError::MissingBlob(blob.hash));
            }
        }

        match (work.proof_requested, transition.proof.as_ref()) {
            (true, None) => return Err(AccumulateError::MissingProof),
            (_, Some(proof)) => {
                if !self.blobs.contains(&proof.proof_blob.hash)
                    && !validator.blob_available(&proof.proof_blob)
                {
                    return Err(AccumulateError::MissingBlob(proof.proof_blob.hash));
                }
                if !validator.verify_proof(work, transition, proof) {
                    return Err(AccumulateError::InvalidProof);
                }
            }
            (false, None) => {}
        }

        match self.consistency {
            ConsistencyModeV2::Crdt => {
                if !transition.writes.is_empty() {
                    return Err(AccumulateError::InvalidConsistency);
                }
                for operation in &transition.crdt_operations {
                    for dependency in &operation.causal_dependencies {
                        if !self.causal_nodes.contains(dependency) {
                            return Err(AccumulateError::MissingCausalDependency(*dependency));
                        }
                    }
                    if let Some(existing) = self.operations.get(&operation.id)
                        && existing != operation
                    {
                        return Err(AccumulateError::InvalidWorkflowTransition);
                    }
                }
                let declared: BTreeSet<_> =
                    transition.resulting_crdt_heads.iter().copied().collect();
                if declared.len() != transition.resulting_crdt_heads.len()
                    || declared != self.expected_crdt_heads(transition)?
                {
                    return Err(AccumulateError::InvalidWorkflowTransition);
                }
            }
            _ if !transition.crdt_operations.is_empty()
                || !transition.resulting_crdt_heads.is_empty() =>
            {
                return Err(AccumulateError::InvalidConsistency);
            }
            _ => {}
        }

        for change in &transition.continuations {
            let actual = self.continuations.get(&change.actor).map(|blob| blob.hash);
            if actual != change.expected {
                return Err(AccumulateError::ContinuationConflict(change.actor));
            }
        }

        if contains_cycle(&transition.outbox) {
            return Err(AccumulateError::MessageCycle);
        }
        Ok(())
    }

    fn validate_base(&self, base: &ConsistencyBaseV2) -> Result<(), AccumulateError> {
        match base {
            ConsistencyBaseV2::Linear {
                revision,
                state_root,
            } => {
                if *revision != self.revision {
                    return Err(AccumulateError::StaleLinearWork {
                        expected_revision: *revision,
                        actual_revision: self.revision,
                    });
                }
                if *state_root != self.state_root {
                    return Err(AccumulateError::StaleStateRoot);
                }
            }
            ConsistencyBaseV2::Crdt { heads } => {
                for dependency in heads {
                    if !self.causal_nodes.contains(dependency) {
                        return Err(AccumulateError::MissingCausalDependency(*dependency));
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_transition(&mut self, transition: &TransitionV2) -> Result<(), AccumulateError> {
        let next_crdt_heads = (self.consistency == ConsistencyModeV2::Crdt)
            .then(|| self.expected_crdt_heads(transition))
            .transpose()?;
        for write in &transition.writes {
            let key = (write.actor, write.key.clone());
            if let Some(value) = &write.value {
                self.actor_rows.insert(key, value.clone());
            } else {
                self.actor_rows.remove(&key);
            }
        }
        for operation in &transition.crdt_operations {
            if let Some(existing) = self.operations.get(&operation.id) {
                if existing != operation {
                    return Err(AccumulateError::InvalidWorkflowTransition);
                }
            } else {
                self.operations.insert(operation.id, operation.clone());
                self.causal_nodes.insert(operation_hash(operation));
            }
        }
        if let Some(heads) = next_crdt_heads {
            self.crdt_heads = heads;
        }
        for change in &transition.continuations {
            match &change.replacement {
                Some(replacement) => {
                    self.continuations.insert(change.actor, replacement.clone());
                }
                None => {
                    self.continuations.remove(&change.actor);
                }
            }
        }
        for message in &transition.inbox {
            self.inbox
                .entry(message.to)
                .or_default()
                .push(message.clone());
        }
        for message in &transition.outbox {
            self.outbox.push(message.clone());
        }
        Ok(())
    }

    fn expected_crdt_heads(
        &self,
        transition: &TransitionV2,
    ) -> Result<BTreeSet<Hash>, AccumulateError> {
        let mut heads = self.crdt_heads.clone();
        let mut seen = BTreeSet::new();
        for operation in &transition.crdt_operations {
            if !seen.insert(operation.id) {
                return Err(AccumulateError::InvalidWorkflowTransition);
            }
            if let Some(existing) = self.operations.get(&operation.id) {
                if existing != operation {
                    return Err(AccumulateError::InvalidWorkflowTransition);
                }
                continue;
            }
            for dependency in &operation.causal_dependencies {
                heads.remove(dependency);
            }
            heads.insert(operation_hash(operation));
        }
        Ok(heads)
    }

    fn compute_state_root(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        e.u16(super::ABI_VERSION);
        e.u8(self.consistency as u8);
        e.u64(self.revision);
        e.u32(self.programs.len() as u32);
        for (actor, program) in &self.programs {
            e.fixed(&actor.0);
            e.fixed(&program.0);
        }
        e.u32(self.actor_rows.len() as u32);
        for ((actor, key), value) in &self.actor_rows {
            e.fixed(&actor.0);
            e.bytes(key);
            e.bytes(value);
        }
        e.u32(self.continuations.len() as u32);
        for (actor, continuation) in &self.continuations {
            e.fixed(&actor.0);
            e.fixed(&continuation.hash.0);
            e.u64(continuation.len);
        }
        Hash::digest(b"vos/service-state/v2", &[&bytes])
    }
}

fn encode_operation(operation: &CrdtOperationV2) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = Encoder(&mut out);
    e.fixed(&operation.actor.0);
    e.fixed(&operation.id.0);
    e.list(&operation.causal_dependencies, |e, hash| e.fixed(&hash.0));
    e.bytes(&operation.payload);
    out
}

fn operation_hash(operation: &CrdtOperationV2) -> Hash {
    Hash::digest(b"vos/crdt-operation/v2", &[&encode_operation(operation)])
}

fn contains_cycle(messages: &[MessageRecordV2]) -> bool {
    let mut edges: BTreeMap<ActorId, BTreeSet<ActorId>> = BTreeMap::new();
    for message in messages {
        if message.from == message.to {
            return true;
        }
        edges.entry(message.from).or_default().insert(message.to);
    }
    fn visit(
        actor: ActorId,
        edges: &BTreeMap<ActorId, BTreeSet<ActorId>>,
        visiting: &mut BTreeSet<ActorId>,
        visited: &mut BTreeSet<ActorId>,
    ) -> bool {
        if visited.contains(&actor) {
            return false;
        }
        if !visiting.insert(actor) {
            return true;
        }
        if edges.get(&actor).is_some_and(|targets| {
            targets
                .iter()
                .any(|target| visit(*target, edges, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(&actor);
        visited.insert(actor);
        false
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    edges
        .keys()
        .any(|actor| visit(*actor, &edges, &mut visiting, &mut visited))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: super::super::ABI_VERSION,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        }
    }

    fn fixture() -> (InMemoryServiceState, WorkEnvelopeV2, TransitionV2) {
        let actor = ActorId([4; 32]);
        let program = ProgramId([5; 32]);
        let mut state = InMemoryServiceState::new(identity(), ConsistencyModeV2::Local);
        state.install_actor(actor, program);
        let base = state.current_base();
        let work = WorkEnvelopeV2 {
            service: identity(),
            invocation: InvocationId([6; 32]),
            target: actor,
            target_program: program,
            method: "inc".into(),
            arguments: vec![],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            consistency: ConsistencyModeV2::Local,
            base: base.clone(),
            imported_actors: vec![],
            imported_blobs: vec![],
            proof_requested: false,
        };
        let transition = TransitionV2 {
            service: identity(),
            consumed_input: work.invocation,
            target_program: program,
            base,
            writes: vec![ActorWriteV2 {
                actor,
                key: b"count".to_vec(),
                value: Some(1u64.to_le_bytes().to_vec()),
            }],
            crdt_operations: vec![],
            resulting_crdt_heads: vec![],
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: Some(ReplyRecordV2 {
                call_id: work.invocation.call_id(0),
                producer: actor,
                result: b"one".to_vec(),
            }),
            exported_blobs: vec![],
            gas: GasAccountingV2::default(),
            proof: None,
        };
        (state, work, transition)
    }

    #[test]
    fn accumulate_is_atomic_and_publishes_after_commit() {
        let (mut state, work, transition) = fixture();
        let old_root = state.state_root();
        let outcome = state.accumulate(&work, &transition, &AllowPublic).unwrap();
        assert_eq!(
            state.row(work.target, b"count"),
            Some(&1u64.to_le_bytes()[..])
        );
        assert_ne!(state.state_root(), old_root);
        assert_eq!(outcome.published.reply, transition.reply);
        assert_eq!(
            outcome.receipt.resulting_state_root,
            Some(state.state_root())
        );
    }

    #[test]
    fn stale_transition_has_no_partial_effects() {
        let (mut state, work, transition) = fixture();
        let first = state.accumulate(&work, &transition, &AllowPublic).unwrap();
        let mut second_work = work.clone();
        second_work.invocation = InvocationId([8; 32]);
        let mut second = transition.clone();
        second.consumed_input = second_work.invocation;
        let root_before = state.state_root();
        assert!(matches!(
            state.accumulate(&second_work, &second, &AllowPublic),
            Err(AccumulateError::StaleLinearWork { .. })
        ));
        assert_eq!(state.state_root(), root_before);
        assert_eq!(first.published.reply, transition.reply);
    }

    #[test]
    fn retries_deduplicate_and_divergence_is_rejected() {
        let (mut state, work, transition) = fixture();
        let first = state.accumulate(&work, &transition, &AllowPublic).unwrap();
        let retry = state.accumulate(&work, &transition, &AllowPublic).unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.receipt, first.receipt);
        assert_eq!(retry.published, PublishedEffects::default());

        let mut divergent = transition;
        divergent.writes[0].value = Some(vec![2]);
        assert_eq!(
            state.accumulate(&work, &divergent, &AllowPublic),
            Err(AccumulateError::DivergentDuplicate)
        );
    }

    #[test]
    fn refine_has_no_mutable_service_state_surface() {
        struct Pure;
        impl Refine for Pure {
            type Imports = ();
            fn refine(
                work: &WorkEnvelopeV2,
                _imports: &(),
            ) -> Result<TransitionV2, RefineError> {
                Ok(TransitionV2 {
                    service: work.service.clone(),
                    consumed_input: work.invocation,
                    target_program: work.target_program,
                    base: work.base.clone(),
                    writes: vec![],
                    crdt_operations: vec![],
                    resulting_crdt_heads: vec![],
                    continuations: vec![],
                    inbox: vec![],
                    outbox: vec![],
                    reply: None,
                    exported_blobs: vec![],
                    gas: GasAccountingV2::default(),
                    proof: None,
                })
            }
        }
        let (_state, work, _) = fixture();
        assert_eq!(
            Pure::refine(&work, &()).unwrap(),
            Pure::refine(&work, &()).unwrap()
        );
    }

    #[test]
    fn crdt_heads_are_derived_and_preserve_concurrent_branches() {
        let actor = ActorId([21; 32]);
        let program = ProgramId([22; 32]);
        let left = Hash([23; 32]);
        let concurrent = Hash([24; 32]);
        let mut state = InMemoryServiceState::new(identity(), ConsistencyModeV2::Crdt);
        state.install_actor(actor, program);
        state.add_causal_node(left);
        state.add_causal_node(concurrent);
        let operation = CrdtOperationV2 {
            actor,
            id: OperationId([25; 32]),
            causal_dependencies: vec![left],
            payload: b"increment".to_vec(),
        };
        let emitted = operation_hash(&operation);
        let work = WorkEnvelopeV2 {
            service: identity(),
            invocation: InvocationId([26; 32]),
            target: actor,
            target_program: program,
            method: "inc".into(),
            arguments: vec![],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            consistency: ConsistencyModeV2::Crdt,
            base: state.current_base(),
            imported_actors: vec![],
            imported_blobs: vec![],
            proof_requested: false,
        };
        let mut transition = TransitionV2 {
            service: identity(),
            consumed_input: work.invocation,
            target_program: program,
            base: work.base.clone(),
            writes: vec![],
            crdt_operations: vec![operation],
            resulting_crdt_heads: vec![concurrent, emitted],
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![],
            gas: GasAccountingV2::default(),
            proof: None,
        };

        let invented = Hash([27; 32]);
        transition.resulting_crdt_heads = vec![invented];
        assert_eq!(
            state.accumulate(&work, &transition, &AllowPublic),
            Err(AccumulateError::InvalidWorkflowTransition)
        );
        assert_eq!(state.crdt_heads(), &BTreeSet::from([left, concurrent]));

        transition.resulting_crdt_heads = vec![concurrent, emitted];
        state.accumulate(&work, &transition, &AllowPublic).unwrap();
        assert_eq!(state.crdt_heads(), &BTreeSet::from([concurrent, emitted]));
    }
}
