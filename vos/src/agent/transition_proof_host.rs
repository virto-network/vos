//! Crash-safe proof closure for clean Agent invocation transitions.
//!
//! This module is deliberately separate from the legacy Service attestation
//! path. An attested clean invocation is first executed by an attested-only
//! tentative executor, then proved, producer-signed, independently verified,
//! and only then offered to the authoritative journal publisher. The
//! producer-private Refine witness is an atomic store sidecar and is never
//! encoded in the public host image or returned to followers.
//!
//! The current journal replay executor does not yet expose a tentative
//! publication transaction, so this module is crate-private until the clean
//! replay driver owns the verified-publication boundary. The bundled Standard
//! runtime's target-only attested ABI is driven only by the physical adapter.
//! Non-attested execution continues through the existing replay path.
//! The bounded host image retains only unfinished publication workflows.
//! Once the authoritative journal has durably published a verified tuple,
//! the local workflow is reclaimed; exact retries recover that tuple from
//! the journal and verify every binding again before returning it.

use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use super::sdk::proof::{
    MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES, MAX_TRANSITION_PROOF_RECORD_BYTES,
    PROOF_PUBLIC_KEY_BYTES, PROOF_SIGNATURE_BYTES, ProducerPrivateWitness, ProofLaneRoots,
    TRANSITION_PROOF_MATERIAL_CHUNK_BYTES, TransitionProofKey, TransitionProofMaterialManifest,
    TransitionProofRecord, TransitionProofStatement, TransitionProofSubject,
    TransitionProofVerifier,
};
use super::sdk::wire::CanonicalWire;
use super::sdk::{
    ActorEntry, AgentId, BlobRef, DeploymentId, Hash, InvocationId, ProducerId, ProgramId,
    RuntimeCapabilities, RuntimeExecutionContext, RuntimeOutcome, RuntimeRequirements,
    RuntimeTransition, RuntimeWork, SpaceId,
};
use super::sdk::{contract::ActorPackageContract, contract::RuntimePackageContract};
use crate::actors::codec::Decode as _;
use crate::actors::value::{Msg, TAG_DYNAMIC};

#[cfg(feature = "agent-transition-proof")]
pub(crate) mod physical;

const TRANSITION_PROOF_HOST_MAGIC: [u8; 4] = *b"APH5";
// A single atomic Shared replay/CAS batch may contain this many clean work
// items. The proof host must be able to retain every item in that batch; a
// smaller private capacity would make an otherwise valid Merge impossible to
// publish atomically.
const MAX_IN_FLIGHT_TRANSITION_PROOFS: usize = super::journal::MAX_REPLAY_SUFFIX_ENTRIES;

const HASH_WIRE_BYTES: usize = 32;
const U32_WIRE_BYTES: usize = 4;
const U64_WIRE_BYTES: usize = 8;
const OPTION_TAG_WIRE_BYTES: usize = 1;
const BLOB_REF_WIRE_BYTES: usize = HASH_WIRE_BYTES + U64_WIRE_BYTES;
const PROOF_LANE_ROOTS_MAX_WIRE_BYTES: usize =
    HASH_WIRE_BYTES + 3 * (OPTION_TAG_WIRE_BYTES + HASH_WIRE_BYTES);
// The largest valid retained phase is a signed record awaiting/retrying the
// replay-sealed journal CAS: witness is absent while transition, statement,
// proof, producer key, and record are present.
const RETAINED_TRANSITION_MAX_WIRE_BYTES: usize = 2 * HASH_WIRE_BYTES // TransitionProofKey
    + BLOB_REF_WIRE_BYTES // canonical work reference
    + PROOF_LANE_ROOTS_MAX_WIRE_BYTES
    + OPTION_TAG_WIRE_BYTES + BLOB_REF_WIRE_BYTES // transition
    + OPTION_TAG_WIRE_BYTES + U32_WIRE_BYTES + TransitionProofStatement::MAX_ENCODED_BYTES
    + OPTION_TAG_WIRE_BYTES // absent private witness
    + OPTION_TAG_WIRE_BYTES + BLOB_REF_WIRE_BYTES // proof manifest
    + OPTION_TAG_WIRE_BYTES + PROOF_PUBLIC_KEY_BYTES
    + OPTION_TAG_WIRE_BYTES + U32_WIRE_BYTES + MAX_TRANSITION_PROOF_RECORD_BYTES;
const TRANSITION_PROOF_HOST_FIXED_MAX_WIRE_BYTES: usize = TRANSITION_PROOF_HOST_MAGIC.len()
    + HASH_WIRE_BYTES // runtime ABI
    + 7 * HASH_WIRE_BYTES // route ids, hashes and producer
    + 2 * U64_WIRE_BYTES // package length and proof-material ceiling
    + U32_WIRE_BYTES; // records list length
const MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES: usize = TRANSITION_PROOF_HOST_FIXED_MAX_WIRE_BYTES
    + MAX_IN_FLIGHT_TRANSITION_PROOFS * RETAINED_TRANSITION_MAX_WIRE_BYTES;
const MAX_PRIVATE_WITNESS_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROOF_MATERIAL_BYTES: usize = super::sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES as usize;

/// Exact outer runtime and proof producer trusted by one host image.
///
/// Actor identity is intentionally not configurable here: it is derived from
/// each canonical Invoke or Resume slice and bound in the public statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestedTransitionRoute {
    pub(crate) space: SpaceId,
    pub(crate) agent: AgentId,
    pub(crate) runtime_deployment: DeploymentId,
    pub(crate) runtime_program: ProgramId,
    pub(crate) runtime_package: BlobRef,
    pub(crate) proof_system: Hash,
    pub(crate) max_proof_material_bytes: u64,
    producer: ProducerId,
}

impl AttestedTransitionRoute {
    /// Build the only production route shape from an authenticated portable
    /// descriptor. The transition signer is never inferred from the runtime
    /// package producer or from node-local identity.
    pub(crate) fn for_descriptor(
        descriptor: &super::sdk::AgentDescriptor,
        proof_system: Hash,
        max_proof_material_bytes: u64,
    ) -> Option<Self> {
        if descriptor.validate().is_err() {
            return None;
        }
        let route = Self {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            runtime_program: descriptor.identity.runtime_program,
            runtime_package: descriptor.runtime_package.clone(),
            proof_system,
            max_proof_material_bytes,
            producer: descriptor.identity.transition_producer,
        };
        route.is_valid().then_some(route)
    }

    pub(crate) const fn producer(&self) -> ProducerId {
        self.producer
    }

    fn is_valid(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.runtime_program != ProgramId::ZERO
            && self.runtime_package.hash != Hash::ZERO
            && self.runtime_package.len != 0
            && self.runtime_package.len <= super::MAX_CATALOG_ARTIFACT_BYTES
            && self.proof_system != Hash::ZERO
            && self.max_proof_material_bytes != 0
            && self.max_proof_material_bytes <= super::sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES
            && self.producer != ProducerId::ZERO
    }

    fn matches_work(&self, work: &RuntimeWork) -> bool {
        let context = match work {
            RuntimeWork::Invoke {
                context,
                invocation,
                ..
            } => {
                if invocation.space != self.space
                    || invocation.agent != self.agent
                    || invocation.runtime_deployment != self.runtime_deployment
                    || invocation.recovery_only
                {
                    return false;
                }
                context
            }
            RuntimeWork::Resume {
                context, resume, ..
            } => {
                if resume.invocation == InvocationId::ZERO {
                    return false;
                }
                context
            }
            RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => return false,
        };
        self.is_valid()
            && matches!(context, RuntimeExecutionContext::Attested { proof_system } if *proof_system == self.proof_system)
    }
}

/// Retry classification supplied only by pre-publication adapters.
///
/// `Terminal` means the adapter has established that repeating the exact
/// input cannot succeed and that no authoritative transition was published.
/// The host may therefore reclaim its local workflow. `Retryable` preserves
/// all durable state for an exact retry. Publisher failures deliberately do
/// not use this type because their result is always treated as ambiguous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransitionProofAdapterError<E> {
    Retryable(E),
    Terminal(E),
}

impl<E> TransitionProofAdapterError<E> {
    fn into_parts(self) -> (bool, E) {
        match self {
            Self::Retryable(error) => (false, error),
            Self::Terminal(error) => (true, error),
        }
    }

    fn into_inner(self) -> E {
        match self {
            Self::Retryable(error) | Self::Terminal(error) => error,
        }
    }
}

/// Catalog/journal facts returned by the authoritative admission adapter.
///
/// This value is untrusted until the host compares every route field and
/// constructs [`AuthenticatedAttestedTransition`]. Resume admission must
/// resolve the original accepted invocation to recover its exact method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestedTransitionAdmission {
    pub(crate) space: SpaceId,
    pub(crate) agent: AgentId,
    pub(crate) runtime_deployment: DeploymentId,
    pub(crate) runtime_program: ProgramId,
    pub(crate) runtime_package: BlobRef,
    pub(crate) max_proof_material_bytes: u64,
    pub(crate) runtime_contract: RuntimePackageContract,
    pub(crate) runtime_capabilities: RuntimeCapabilities,
    pub(crate) actor_entry: ActorEntry,
    pub(crate) actor_contract: ActorPackageContract,
    pub(crate) actor_requirements: RuntimeRequirements,
    pub(crate) method: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedAttestedExecutionBinding {
    runtime_contract: RuntimePackageContract,
    runtime_capabilities: RuntimeCapabilities,
    actor_entry: ActorEntry,
    actor_contract: ActorPackageContract,
    actor_requirements: RuntimeRequirements,
}

/// Host-validated execution identity passed to the executor and producer.
///
/// Safe code outside this module can inspect but cannot construct this
/// capability. It binds an exact Invoke/Resume slice, runtime package,
/// proof-system and method before any private witness is produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedAttestedTransition {
    route: AttestedTransitionRoute,
    key: TransitionProofKey,
    work: Hash,
    before: ProofLaneRoots,
    method: String,
    execution: Option<AuthenticatedAttestedExecutionBinding>,
}

impl AuthenticatedAttestedTransition {
    pub(crate) const fn key(&self) -> TransitionProofKey {
        self.key
    }

    pub(crate) const fn space(&self) -> SpaceId {
        self.route.space
    }

    pub(crate) const fn agent(&self) -> AgentId {
        self.route.agent
    }

    pub(crate) const fn runtime_deployment(&self) -> DeploymentId {
        self.route.runtime_deployment
    }

    pub(crate) const fn runtime_program(&self) -> ProgramId {
        self.route.runtime_program
    }

    pub(crate) fn runtime_package(&self) -> &BlobRef {
        &self.route.runtime_package
    }

    pub(crate) const fn proof_system(&self) -> Hash {
        self.route.proof_system
    }

    pub(crate) const fn max_proof_material_bytes(&self) -> u64 {
        self.route.max_proof_material_bytes
    }

    pub(crate) fn method(&self) -> &str {
        &self.method
    }

    pub(crate) fn runtime_contract(&self) -> Option<RuntimePackageContract> {
        self.execution
            .as_ref()
            .map(|binding| binding.runtime_contract)
    }

    pub(crate) fn runtime_capabilities(&self) -> Option<RuntimeCapabilities> {
        self.execution
            .as_ref()
            .map(|binding| binding.runtime_capabilities)
    }

    pub(crate) fn actor_entry(&self) -> Option<&ActorEntry> {
        self.execution.as_ref().map(|binding| &binding.actor_entry)
    }

    pub(crate) fn actor_contract(&self) -> Option<ActorPackageContract> {
        self.execution
            .as_ref()
            .map(|binding| binding.actor_contract)
    }

    pub(crate) fn actor_requirements(&self) -> Option<RuntimeRequirements> {
        self.execution
            .as_ref()
            .map(|binding| binding.actor_requirements)
    }

    /// Whether this capability authenticates this exact canonical Standard
    /// runtime work item.
    ///
    /// Keeping this check on the unforgeable capability prevents the
    /// Standard executor from accidentally growing a second, field-by-field
    /// attested admission path. The work commitment distinguishes Invoke and
    /// Resume slices which share an invocation id, while `subject_for` also
    /// revalidates the bound package, proof system and recovered method.
    pub(crate) fn authorizes_standard_work(&self, work: &RuntimeWork) -> bool {
        if self.execution.is_none() {
            return false;
        }
        let Ok(canonical_work) = work.encode() else {
            return false;
        };
        self.route.matches_work(work)
            && TransitionProofStatement::work_commitment(&canonical_work) == self.work
            && transition_key(work, &canonical_work, self.before) == Some(self.key)
            && subject_for(&self.route, work, self.method.clone()).is_some()
            && (!matches!(work, RuntimeWork::Invoke { .. })
                || method_name(work).as_deref() == Some(self.method.as_str()))
    }

    #[cfg(test)]
    pub(crate) fn authenticate_for_test(
        route: &AttestedTransitionRoute,
        work: &RuntimeWork,
        admission: AttestedTransitionAdmission,
    ) -> Option<Self> {
        let canonical_work = work.encode().ok()?;
        let state = match work {
            RuntimeWork::Invoke { state, .. } | RuntimeWork::Resume { state, .. } => state,
            RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => return None,
        };
        let root =
            |tag: &[u8], bytes: &[u8]| Hash::digest(b"vos/test/agent-proof-root", &[tag, bytes]);
        let before = ProofLaneRoots {
            control: root(b"control", &state.control),
            linear: Some(root(b"linear", &state.linear)),
            merge: Some(root(b"merge", &state.merge)),
            local: Some(root(b"local", &state.local)),
        };
        let key = transition_key(work, &canonical_work, before)?;
        authenticate_admission(route, key, before, work, &canonical_work, admission)
    }
}

/// Authoritative admission and successor validation seam.
///
/// Implementations must resolve authenticated catalog and journal state. For
/// Invoke they verify the exact method policy and runtime deployment. For
/// Resume they additionally recover the original accepted invocation and its
/// method. `validate_successor` must apply the same lane ownership, exact
/// standard-runtime successor, durable-error and state-limit checks used by
/// authoritative replay, without publishing the transition.
pub(crate) trait AttestedTransitionValidator {
    type Error;

    fn authenticate_work(
        &mut self,
        route: &AttestedTransitionRoute,
        work: &RuntimeWork,
        canonical_work: &[u8],
    ) -> Result<AttestedTransitionAdmission, TransitionProofAdapterError<Self::Error>>;

    fn validate_successor(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        work: &RuntimeWork,
        transition: &RuntimeTransition,
    ) -> Result<(), TransitionProofAdapterError<Self::Error>>;
}

/// Public artifacts made durable atomically with one image revision.
pub(crate) struct TransitionProofArtifact<'a> {
    pub(crate) reference: &'a BlobRef,
    pub(crate) bytes: &'a [u8],
}

/// Atomic producer-private sidecar mutation accompanying an image revision.
pub(crate) enum TransitionProofWitnessMutation<'a> {
    Keep,
    Put(&'a ProducerPrivateWitness),
    Remove { statement: Hash },
}

/// Bounded durable store for the proof host.
///
/// `commit` is one atomic durability boundary for the image, public CAS
/// artifacts, and private witness mutation. A returned error is ambiguous;
/// the live host poisons itself and must be reopened. Implementations must
/// reject content collisions and must never expose witness bytes through
/// `load_artifact`. Loads must enforce the bounds named by each reference (and
/// the image/witness limits in this module) before allocating their result.
pub(crate) trait TransitionProofHostStore {
    type Error;

    fn load_image(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn load_artifact(&mut self, reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error>;

    fn load_private_witness(
        &mut self,
        statement: Hash,
    ) -> Result<Option<ProducerPrivateWitness>, Self::Error>;

    fn commit(
        &mut self,
        image: &[u8],
        artifacts: &[TransitionProofArtifact<'_>],
        witness: TransitionProofWitnessMutation<'_>,
    ) -> Result<(), Self::Error>;
}

/// Trusted clean-runtime execution seam.
///
/// Implementations must canonical-decode the supplied bytes, resolve the
/// exact installed AMP2 method policy from authenticated catalog artifacts,
/// require `AttestationRequirement::Required` with the capability's proof
/// system, and execute the standard outer-runtime plus inner-actor Refine
/// invocation *without publishing its transition*. A retryable error may make
/// the host call again because no result was retained; after the transition
/// and witness commit atomically, restart never executes that slice again.
/// There is deliberately no native or legacy Service fallback. The returned
/// trace commitment is the proof-independent execution transcript for the
/// nested standard Refine run; verification recomputes it only after child
/// proof verification and deterministic native-boundary replay.
/// `private_witness` contains only producer-side material for that exact
/// execution.
pub(crate) trait AttestedTentativeExecutor {
    type Error;

    fn execute_tentative(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        canonical_work: &[u8],
    ) -> Result<TentativeAttestedExecution, TransitionProofAdapterError<Self::Error>>;
}

/// Tentative output. Its transition becomes authoritative only after the
/// verified-publication capability below is consumed.
pub(crate) struct TentativeAttestedExecution {
    transition: RuntimeTransition,
    proof_system: Hash,
    refine_trace: Hash,
    public_io: Hash,
    private_witness: Vec<u8>,
}

/// Independent lane-root derivation over the exact canonical before/after
/// states selected by journal materialization.
pub(crate) trait TransitionLaneRootResolver {
    type Error;

    fn before_roots(
        &mut self,
        work: &RuntimeWork,
    ) -> Result<ProofLaneRoots, TransitionProofAdapterError<Self::Error>>;

    fn after_roots(
        &mut self,
        work: &RuntimeWork,
        transition: &RuntimeTransition,
    ) -> Result<ProofLaneRoots, TransitionProofAdapterError<Self::Error>>;
}

/// Deterministic proof producer and distinct record signer.
///
/// Both methods must be idempotent for an exact input because a process may
/// lose their result. Once proof bytes are durable, retries never prove
/// again; once a signed record is durable, retries never sign again.
pub(crate) trait AgentTransitionProofProducer {
    type Error;

    fn public_key(&self) -> [u8; PROOF_PUBLIC_KEY_BYTES];

    fn prove_nested_refine(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        statement: &TransitionProofStatement,
        witness: &ProducerPrivateWitness,
    ) -> Result<Vec<u8>, TransitionProofAdapterError<Self::Error>>;

    fn sign_transition_record(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        message: &[u8],
    ) -> Result<[u8; PROOF_SIGNATURE_BYTES], TransitionProofAdapterError<Self::Error>>;
}

/// Exact, deterministic publication receipt returned by the authoritative
/// journal adapter. This is host-local replay state, not public proof or an
/// authorization capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransitionPublicationFact {
    key: TransitionProofKey,
    transition: Hash,
    proof_record: Hash,
    before: ProofLaneRoots,
    after: ProofLaneRoots,
    publication: Hash,
}

impl TransitionPublicationFact {
    /// Reconstruct the only valid publication fact for a retained public
    /// record. Journal adapters use this after restart rather than decoding or
    /// fabricating private fields.
    pub(crate) fn reconstruct(
        record: &TransitionProofRecord,
    ) -> Result<Self, super::sdk::wire::WireError> {
        let proof_record = record.commitment()?;
        let key = record.statement.key();
        let transition = record.statement.transition;
        let before = record.statement.before;
        let after = record.statement.after;
        let publication = record.verified_publication_commitment()?;
        Ok(Self {
            key,
            transition,
            proof_record,
            before,
            after,
            publication,
        })
    }

    pub(crate) const fn publication(self) -> Hash {
        self.publication
    }

    pub(crate) const fn key(self) -> TransitionProofKey {
        self.key
    }
}

/// Private proof that the host completed all verification before publication.
/// Safe code cannot construct this outside this module.
pub(crate) struct VerifiedTransitionPublication<'a> {
    work: &'a [u8],
    transition: &'a [u8],
    record: &'a TransitionProofRecord,
    proof_manifest: &'a [u8],
    proof_material: &'a [u8],
    expected: TransitionPublicationFact,
}

impl<'a> VerifiedTransitionPublication<'a> {
    pub(crate) const fn canonical_work(&self) -> &'a [u8] {
        self.work
    }

    pub(crate) const fn canonical_transition(&self) -> &'a [u8] {
        self.transition
    }

    pub(crate) const fn proof_record(&self) -> &'a TransitionProofRecord {
        self.record
    }

    /// Canonical signed manifest bytes retained in the public journal tuple.
    pub(crate) const fn proof_manifest_bytes(&self) -> &'a [u8] {
        self.proof_manifest
    }

    /// Exact bounded material already authenticated against the manifest and
    /// checked by the physical verifier. It is provided for an atomic
    /// publication adapter check, but is not duplicated in the journal tuple.
    pub(crate) const fn proof_material(&self) -> &'a [u8] {
        self.proof_material
    }

    pub(crate) const fn expected_fact(&self) -> TransitionPublicationFact {
        self.expected
    }
}

/// Authoritative journal lookup used before any tentative execution.
///
/// Implementations read only the currently authenticated journal/checkpoint
/// proof closure. A process-local cache is never sufficient: after a head CAS
/// succeeds but its result is lost, this lookup is what prevents a second
/// execution, proof, or signature.
pub(crate) trait VerifiedTransitionPublisher {
    type Error;

    /// Recover an already-published tuple for one exact transition key.
    /// Implementations must read the authoritative journal, not a
    /// process-local cache. The host treats the returned bytes as hostile and
    /// verifies their exact work, transition, roots, producer, proof, and
    /// publication bindings.
    fn load_published(
        &mut self,
        key: TransitionProofKey,
    ) -> Result<Option<PublishedAttestedTransition>, Self::Error>;

    /// Return checkpoint-authenticated evidence that the logical invocation
    /// was acknowledged and compacted after any public proof record ceased to
    /// be replay-reachable. This closes the crash window where the journal CAS
    /// succeeded but producer-side confirmation was lost until after Ack and
    /// checkpoint pruning. The returned key is the exact execution which made
    /// the invocation terminal; it may differ from the queried execution, but
    /// its logical invocation must match.
    fn load_retired(
        &mut self,
        _key: TransitionProofKey,
    ) -> Result<Option<AuthenticatedTransitionRetirement>, Self::Error> {
        Ok(None)
    }
}

/// Test-only compatibility seam for exercising the host state machine without
/// constructing a replay-sealed journal publication. Production callers can
/// only obtain a prepared tuple and must commit it as part of the exact replay
/// head CAS.
#[cfg(test)]
trait ImmediateVerifiedTransitionPublisher: VerifiedTransitionPublisher {
    fn publish_verified(
        &mut self,
        publication: VerifiedTransitionPublication<'_>,
    ) -> Result<TransitionPublicationFact, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublishedAttestedTransition {
    pub(crate) canonical_work: Vec<u8>,
    pub(crate) canonical_transition: Vec<u8>,
    pub(crate) proof_record: TransitionProofRecord,
    /// Canonical APM1 root. Material chunks live in the authenticated CAS.
    pub(crate) proof_manifest_bytes: Vec<u8>,
    pub(crate) publication: TransitionPublicationFact,
}

impl PublishedAttestedTransition {
    /// Rebuild one journal-returned tuple without granting it trust. This
    /// checks all content identities and the deterministic publication fact;
    /// the host still verifies route, roots, producer signature and physical
    /// proof before reuse.
    pub(crate) fn reconstruct(
        canonical_work: Vec<u8>,
        canonical_transition: Vec<u8>,
        proof_record: TransitionProofRecord,
        proof_manifest_bytes: Vec<u8>,
        publication: Hash,
    ) -> Result<Self, TransitionProofHostRejection> {
        if TransitionProofStatement::work_commitment(&canonical_work) != proof_record.statement.work
            || TransitionProofStatement::transition_commitment(&canonical_transition)
                != proof_record.statement.transition
            || !proof_record.proof.matches(&proof_manifest_bytes)
        {
            return Err(TransitionProofHostRejection::InvalidPublication);
        }
        let expected = TransitionPublicationFact::reconstruct(&proof_record)
            .map_err(|_| TransitionProofHostRejection::InvalidPublication)?;
        if expected.publication != publication {
            return Err(TransitionProofHostRejection::InvalidPublication);
        }
        Ok(Self {
            canonical_work,
            canonical_transition,
            proof_record,
            proof_manifest_bytes,
            publication: expected,
        })
    }
}

/// Durable-host output awaiting the one replay-sealed journal head CAS.
///
/// Every byte in this value has already been persisted by
/// [`TransitionProofHostStore`] and independently verified. Returning it does
/// not authorize cleanup of the host workflow; cleanup is allowed only after
/// the journal CAS succeeds or an authoritative retry lookup finds the exact
/// published tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedVerifiedTransition {
    canonical_work: Vec<u8>,
    canonical_transition: Vec<u8>,
    proof_record: TransitionProofRecord,
    proof_manifest_bytes: Vec<u8>,
    proof_material: Vec<u8>,
    actor_package: BlobRef,
    publication: TransitionPublicationFact,
}

impl PreparedVerifiedTransition {
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        canonical_work: Vec<u8>,
        canonical_transition: Vec<u8>,
        proof_record: TransitionProofRecord,
        proof_manifest_bytes: Vec<u8>,
        proof_material: Vec<u8>,
        actor_package: BlobRef,
    ) -> Self {
        let manifest = TransitionProofMaterialManifest::decode(&proof_manifest_bytes)
            .expect("test proof manifest must decode canonically");
        assert_eq!(
            manifest.encode().expect("test proof manifest must encode"),
            proof_manifest_bytes
        );
        assert!(manifest.matches_material(&proof_material));
        assert!(proof_record.validate_shape());
        assert_eq!(
            proof_record.statement.work,
            TransitionProofStatement::work_commitment(&canonical_work)
        );
        assert_eq!(
            proof_record.statement.transition,
            TransitionProofStatement::transition_commitment(&canonical_transition)
        );
        assert!(proof_record.proof.matches(&proof_manifest_bytes));
        let publication = TransitionPublicationFact::reconstruct(&proof_record)
            .expect("test proof record must define a publication");
        Self {
            canonical_work,
            canonical_transition,
            proof_record,
            proof_manifest_bytes,
            proof_material,
            actor_package,
            publication,
        }
    }

    pub(crate) fn canonical_work(&self) -> &[u8] {
        &self.canonical_work
    }

    pub(crate) fn canonical_transition(&self) -> &[u8] {
        &self.canonical_transition
    }

    pub(crate) const fn proof_record(&self) -> &TransitionProofRecord {
        &self.proof_record
    }

    pub(crate) fn proof_manifest_bytes(&self) -> &[u8] {
        &self.proof_manifest_bytes
    }

    pub(crate) fn proof_material(&self) -> &[u8] {
        &self.proof_material
    }

    pub(crate) const fn actor_package(&self) -> &BlobRef {
        &self.actor_package
    }

    pub(crate) const fn expected_fact(&self) -> TransitionPublicationFact {
        self.publication
    }

    pub(crate) const fn key(&self) -> TransitionProofKey {
        self.publication.key()
    }

    /// Fixed-size capability retained after the complete prepared tuple has
    /// been streamed into journal staging. Confirmation re-reads the exact
    /// tuple from this host's durable row, so a 1024-proof Merge publication
    /// never retains 1024 proof-material buffers until the head CAS.
    pub(crate) const fn confirmation(&self) -> TransitionProofConfirmationToken {
        TransitionProofConfirmationToken {
            expected: self.publication,
        }
    }

    fn as_publication(&self) -> VerifiedTransitionPublication<'_> {
        VerifiedTransitionPublication {
            work: &self.canonical_work,
            transition: &self.canonical_transition,
            record: &self.proof_record,
            proof_manifest: &self.proof_manifest_bytes,
            proof_material: &self.proof_material,
            expected: self.publication,
        }
    }

    fn into_published(self) -> PublishedAttestedTransition {
        PublishedAttestedTransition {
            canonical_work: self.canonical_work,
            canonical_transition: self.canonical_transition,
            proof_record: self.proof_record,
            proof_manifest_bytes: self.proof_manifest_bytes,
            publication: self.publication,
        }
    }
}

/// Host-bound proof that one exact durable prepared row may be reconciled
/// after its journal publication becomes authoritative. Safe code cannot
/// construct a token independently of [`PreparedVerifiedTransition`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransitionProofConfirmationToken {
    expected: TransitionPublicationFact,
}

impl TransitionProofConfirmationToken {
    pub(crate) const fn key(self) -> TransitionProofKey {
        self.expected.key()
    }
}

pub(crate) enum VerifiedTransitionPreparation {
    Prepared(PreparedVerifiedTransition),
    AlreadyPublished(PublishedAttestedTransition),
    AlreadyRetired(AuthenticatedTransitionRetirement),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedTransitionRetirement {
    key: TransitionProofKey,
    checkpoint: Hash,
    checkpoint_revision: u64,
}

impl AuthenticatedTransitionRetirement {
    pub(super) fn new(
        key: TransitionProofKey,
        checkpoint: Hash,
        checkpoint_revision: u64,
    ) -> Option<Self> {
        (key.validate() && checkpoint != Hash::ZERO && checkpoint_revision != 0).then_some(Self {
            key,
            checkpoint,
            checkpoint_revision,
        })
    }

    pub(crate) const fn key(self) -> TransitionProofKey {
        self.key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionProofHostRejection {
    Poisoned,
    InvalidWork,
    WrongMethod,
    InvalidTransition,
    InvalidRoots,
    InvalidTrace,
    WrongProofSystem,
    WrongProducer,
    InvalidProof,
    InvalidProducerSignature,
    InvalidPublication,
    DivergentRetry,
    Capacity,
}

#[derive(Debug)]
pub(crate) enum TransitionProofHostOpenError<StorageError> {
    Storage(StorageError),
    InvalidState,
}

#[derive(Debug)]
pub(crate) enum TransitionProofConfirmationError<StorageError, PublicationError> {
    Storage(StorageError),
    Publication(PublicationError),
    NotPublished,
    InvalidState,
}

#[derive(Debug)]
pub(crate) enum TransitionProofHostError<
    StorageError,
    ValidationError,
    ExecutionError,
    RootError,
    ProducerError,
    PublicationError,
> {
    Storage(StorageError),
    Validation(ValidationError),
    Execution(ExecutionError),
    Roots(RootError),
    Producer(ProducerError),
    Publication(PublicationError),
    InvalidState,
    Rejected(TransitionProofHostRejection),
}

impl<StorageError: fmt::Display> fmt::Display for TransitionProofHostOpenError<StorageError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "transition proof host storage: {error}"),
            Self::InvalidState => formatter.write_str("invalid transition proof host state"),
        }
    }
}

impl<StorageError, ValidationError, ExecutionError, RootError, ProducerError, PublicationError>
    fmt::Display
    for TransitionProofHostError<
        StorageError,
        ValidationError,
        ExecutionError,
        RootError,
        ProducerError,
        PublicationError,
    >
where
    StorageError: fmt::Display,
    ValidationError: fmt::Display,
    ExecutionError: fmt::Display,
    RootError: fmt::Display,
    ProducerError: fmt::Display,
    PublicationError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "transition proof host storage: {error}"),
            Self::Validation(error) => {
                write!(formatter, "transition proof validation: {error}")
            }
            Self::Execution(error) => write!(formatter, "tentative execution: {error}"),
            Self::Roots(error) => write!(formatter, "transition lane roots: {error}"),
            Self::Producer(error) => write!(formatter, "transition proof producer: {error}"),
            Self::Publication(error) => write!(formatter, "transition publication: {error}"),
            Self::InvalidState => formatter.write_str("invalid transition proof host state"),
            Self::Rejected(error) => write!(formatter, "transition proof host rejected: {error:?}"),
        }
    }
}

impl<StorageError> core::error::Error for TransitionProofHostOpenError<StorageError> where
    StorageError: core::error::Error + 'static
{
}

impl<StorageError, ValidationError, ExecutionError, RootError, ProducerError, PublicationError>
    core::error::Error
    for TransitionProofHostError<
        StorageError,
        ValidationError,
        ExecutionError,
        RootError,
        ProducerError,
        PublicationError,
    >
where
    StorageError: core::error::Error + 'static,
    ValidationError: core::error::Error + 'static,
    ExecutionError: core::error::Error + 'static,
    RootError: core::error::Error + 'static,
    ProducerError: core::error::Error + 'static,
    PublicationError: core::error::Error + 'static,
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedTransition {
    key: TransitionProofKey,
    work: BlobRef,
    before: ProofLaneRoots,
    transition: Option<BlobRef>,
    statement: Option<Vec<u8>>,
    witness: Option<Hash>,
    proof: Option<BlobRef>,
    producer_public_key: Option<[u8; PROOF_PUBLIC_KEY_BYTES]>,
    record: Option<Vec<u8>>,
}

impl RetainedTransition {
    fn has_valid_envelope(&self) -> bool {
        if !self.key.validate()
            || self.work.hash == Hash::ZERO
            || self.work.len == 0
            || self.work.len > super::sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES as u64
            || !self.before.validate()
            || self.statement.as_ref().is_some_and(|bytes| {
                bytes.is_empty() || bytes.len() > TransitionProofStatement::MAX_ENCODED_BYTES
            })
            || self.witness == Some(Hash::ZERO)
            || self.transition.as_ref().is_some_and(|reference| {
                reference.hash == Hash::ZERO
                    || reference.len == 0
                    || reference.len > super::sdk::wire::MAX_RUNTIME_TRANSITION_WIRE_BYTES as u64
            })
            || self.proof.as_ref().is_some_and(|reference| {
                reference.hash == Hash::ZERO
                    || reference.len == 0
                    || reference.len > MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES as u64
            })
            || self.producer_public_key == Some([0; PROOF_PUBLIC_KEY_BYTES])
            || self.record.as_ref().is_some_and(|bytes| {
                bytes.is_empty() || bytes.len() > MAX_TRANSITION_PROOF_RECORD_BYTES
            })
        {
            return false;
        }
        matches!(
            (
                &self.transition,
                &self.statement,
                self.witness,
                &self.proof,
                self.producer_public_key,
                &self.record,
            ),
            (None, None, None, None, None, None)
                | (Some(_), Some(_), Some(_), None, None, None)
                | (Some(_), Some(_), Some(_), Some(_), Some(_), None)
                | (Some(_), Some(_), None, Some(_), Some(_), Some(_))
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransitionProofHostImage {
    route: AttestedTransitionRoute,
    records: Vec<RetainedTransition>,
}

impl TransitionProofHostImage {
    fn empty(route: AttestedTransitionRoute) -> Self {
        Self {
            route,
            records: Vec::new(),
        }
    }

    fn has_valid_envelope(&self) -> bool {
        self.route.is_valid()
            && self.records.len() <= MAX_IN_FLIGHT_TRANSITION_PROOFS
            && self
                .records
                .iter()
                .all(RetainedTransition::has_valid_envelope)
            && self.records.iter().enumerate().all(|(index, record)| {
                self.records[..index]
                    .iter()
                    .all(|prior| prior.key != record.key)
            })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TRANSITION_PROOF_HOST_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(super::sdk::RUNTIME_ABI_ID.as_bytes());
        encode_route(&mut encoder, &self.route);
        encoder.list(&self.records, encode_retained);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(TRANSITION_PROOF_HOST_MAGIC.len())? != TRANSITION_PROOF_HOST_MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if Hash(decoder.fixed()?) != super::sdk::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let route = decode_route(&mut decoder)?;
        let count = decoder.u32()? as usize;
        if count > MAX_IN_FLIGHT_TRANSITION_PROOFS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut records = Vec::new();
        records
            .try_reserve(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            records.push(decode_retained(&mut decoder)?);
        }
        let image = Self { route, records };
        if !decoder.exhausted() || !image.has_valid_envelope() || image.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(image)
    }
}

pub(crate) struct DurableTransitionProofHost<B: TransitionProofHostStore> {
    store: B,
    image: TransitionProofHostImage,
    poisoned: bool,
}

impl<B: TransitionProofHostStore> DurableTransitionProofHost<B> {
    pub(crate) fn open<V: TransitionProofVerifier>(
        mut store: B,
        route: AttestedTransitionRoute,
        verifier: &V,
    ) -> Result<Self, TransitionProofHostOpenError<B::Error>> {
        if !route.is_valid() {
            return Err(TransitionProofHostOpenError::InvalidState);
        }
        let image = match store
            .load_image()
            .map_err(TransitionProofHostOpenError::Storage)?
        {
            None => TransitionProofHostImage::empty(route),
            Some(bytes) => {
                let image = TransitionProofHostImage::decode(&bytes)
                    .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
                if image.route != route || image.encode() != bytes {
                    return Err(TransitionProofHostOpenError::InvalidState);
                }
                validate_durable_image(&mut store, &image, verifier)?;
                image
            }
        };
        Ok(Self {
            store,
            image,
            poisoned: false,
        })
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn retained_transitions(&self) -> usize {
        self.image.records.len()
    }

    pub(crate) fn into_store(self) -> B {
        self.store
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub(crate) fn execute_prove_prepare<A, E, R, P, V, U>(
        &mut self,
        work: RuntimeWork,
        validator: &mut A,
        executor: &mut E,
        roots: &mut R,
        producer: &mut P,
        verifier: &V,
        journal: &mut U,
    ) -> Result<
        VerifiedTransitionPreparation,
        TransitionProofHostError<B::Error, A::Error, E::Error, R::Error, P::Error, U::Error>,
    >
    where
        A: AttestedTransitionValidator,
        E: AttestedTentativeExecutor,
        R: TransitionLaneRootResolver,
        P: AgentTransitionProofProducer,
        V: TransitionProofVerifier,
        U: VerifiedTransitionPublisher,
    {
        if self.poisoned {
            return Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::Poisoned,
            ));
        }
        if !self.image.route.matches_work(&work) {
            return Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::InvalidWork,
            ));
        }
        let canonical_work = work.encode().map_err(|_| {
            TransitionProofHostError::Rejected(TransitionProofHostRejection::InvalidWork)
        })?;
        if matches!(work, RuntimeWork::Invoke { .. }) && method_name(&work).is_none() {
            return Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::WrongMethod,
            ));
        }
        // Authenticate the runtime/package route before resolving state, then
        // derive the public lookup key only from that exact authenticated
        // pre-state. Caller-selected or approximate roots never reach the
        // journal lookup boundary.
        let admission = match validator.authenticate_work(&self.image.route, &work, &canonical_work)
        {
            Ok(admission) => admission,
            Err(error) => {
                let (terminal, error) = error.into_parts();
                if terminal {
                    self.reclaim_terminal_work(&work, &canonical_work)?;
                }
                return Err(TransitionProofHostError::Validation(error));
            }
        };
        let before = match roots.before_roots(&work) {
            Ok(before) => before,
            Err(error) => {
                let (terminal, error) = error.into_parts();
                if terminal {
                    self.reclaim_terminal_work(&work, &canonical_work)?;
                }
                return Err(TransitionProofHostError::Roots(error));
            }
        };
        if !before.validate() {
            self.reclaim_terminal_work(&work, &canonical_work)?;
            return Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::InvalidRoots,
            ));
        }
        let key = transition_key(&work, &canonical_work, before).ok_or(
            TransitionProofHostError::Rejected(TransitionProofHostRejection::InvalidWork),
        )?;
        let Some(authenticated) = authenticate_admission(
            &self.image.route,
            key,
            before,
            &work,
            &canonical_work,
            admission,
        ) else {
            self.reclaim_terminal_work(&work, &canonical_work)?;
            return Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::InvalidWork,
            ));
        };
        let retained_index = self
            .image
            .records
            .iter()
            .position(|record| record.key == key);

        if let Some(published) = journal
            .load_published(key)
            .map_err(TransitionProofHostError::Publication)?
        {
            if published.canonical_work != canonical_work {
                return Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::DivergentRetry,
                ));
            }
            let transition = canonical_decode::<RuntimeTransition>(&published.canonical_transition)
                .map_err(|_| {
                    TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::InvalidPublication,
                    )
                })?;
            validate_transition_for_work(&work, &transition)
                .map_err(TransitionProofHostError::Rejected)?;
            validator
                .validate_successor(&authenticated, &work, &transition)
                .map_err(|error| TransitionProofHostError::Validation(error.into_inner()))?;
            let after = roots
                .after_roots(&work, &transition)
                .map_err(|error| TransitionProofHostError::Roots(error.into_inner()))?;
            if before != published.proof_record.statement.before
                || after != published.proof_record.statement.after
                || published.proof_record.statement.key() != key
            {
                return Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::InvalidPublication,
                ));
            }
            let proof_material = self.load_proof_material(&published.proof_manifest_bytes)?;
            verify_exact_record(
                &authenticated,
                &published.proof_record,
                &published.proof_manifest_bytes,
                &proof_material,
                &work,
                &canonical_work,
                &transition,
                &published.canonical_transition,
                before,
                after,
                verifier,
            )
            .map_err(TransitionProofHostError::Rejected)?;
            let expected = TransitionPublicationFact::reconstruct(&published.proof_record)
                .map_err(|_| TransitionProofHostError::InvalidState)?;
            if published.publication != expected {
                return Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::InvalidPublication,
                ));
            }

            if let Some(index) = retained_index {
                let (retained_work_ref, witness) = self
                    .image
                    .records
                    .get(index)
                    .map(|retained| (retained.work.clone(), retained.witness))
                    .ok_or(TransitionProofHostError::InvalidState)?;
                let retained_work = self.load_artifact(retained_work_ref)?;
                if retained_work != canonical_work {
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::DivergentRetry,
                    ));
                }
                self.complete_record(index, witness)?;
            }
            return Ok(VerifiedTransitionPreparation::AlreadyPublished(published));
        }

        if let Some(retired) = journal
            .load_retired(key)
            .map_err(TransitionProofHostError::Publication)?
        {
            if retired.key().invocation != key.invocation {
                return Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::InvalidPublication,
                ));
            }
            if let Some(index) = retained_index {
                let (retained_work_ref, witness) = self
                    .image
                    .records
                    .get(index)
                    .map(|retained| (retained.work.clone(), retained.witness))
                    .ok_or(TransitionProofHostError::InvalidState)?;
                let retained_work = self.load_artifact(retained_work_ref)?;
                if retained_work != canonical_work {
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::DivergentRetry,
                    ));
                }
                self.complete_record(index, witness)?;
            }
            return Ok(VerifiedTransitionPreparation::AlreadyRetired(retired));
        }

        let index = match retained_index {
            Some(index) => {
                let retained = self.load_artifact(self.image.records[index].work.clone())?;
                if retained != canonical_work {
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::DivergentRetry,
                    ));
                }
                index
            }
            None => {
                if self.image.records.len() == MAX_IN_FLIGHT_TRANSITION_PROOFS {
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::Capacity,
                    ));
                }
                let work_ref = BlobRef::of_bytes(&canonical_work);
                let mut candidate = self.image.clone();
                candidate.records.push(RetainedTransition {
                    key,
                    work: work_ref.clone(),
                    before,
                    transition: None,
                    statement: None,
                    witness: None,
                    proof: None,
                    producer_public_key: None,
                    record: None,
                });
                self.commit(
                    candidate,
                    &[TransitionProofArtifact {
                        reference: &work_ref,
                        bytes: &canonical_work,
                    }],
                    TransitionProofWitnessMutation::Keep,
                )?;
                self.image.records.len() - 1
            }
        };

        self.resume(
            index,
            &authenticated,
            validator,
            executor,
            roots,
            producer,
            verifier,
            journal,
        )
    }

    /// Reclaim one prepared workflow only after authoritative journal lookup
    /// observes the exact tuple. Calling this after the head CAS but before
    /// returning its result makes ordinary success cheap; losing either the
    /// CAS result or this confirmation remains safe because the retained host
    /// workflow is recovered by `execute_prove_prepare` on retry.
    pub(crate) fn confirm_published<U: VerifiedTransitionPublisher>(
        &mut self,
        confirmation: TransitionProofConfirmationToken,
        journal: &mut U,
    ) -> Result<(), TransitionProofConfirmationError<B::Error, U::Error>> {
        if self.poisoned {
            return Err(TransitionProofConfirmationError::InvalidState);
        }
        let published = journal
            .load_published(confirmation.key())
            .map_err(TransitionProofConfirmationError::Publication)?
            .ok_or(TransitionProofConfirmationError::NotPublished)?;
        if published.publication != confirmation.expected {
            return Err(TransitionProofConfirmationError::InvalidState);
        }
        let index = self
            .image
            .records
            .iter()
            .position(|record| record.key == confirmation.key())
            .ok_or(TransitionProofConfirmationError::InvalidState)?;
        let retained = self
            .image
            .records
            .get(index)
            .cloned()
            .ok_or(TransitionProofConfirmationError::InvalidState)?;
        let encoded_record = published
            .proof_record
            .encode()
            .map_err(|_| TransitionProofConfirmationError::InvalidState)?;
        let encoded_statement = published
            .proof_record
            .statement
            .encode()
            .map_err(|_| TransitionProofConfirmationError::InvalidState)?;
        if retained.work != BlobRef::of_bytes(&published.canonical_work)
            || retained.transition.as_ref()
                != Some(&BlobRef::of_bytes(&published.canonical_transition))
            || retained.statement.as_deref() != Some(encoded_statement.as_slice())
            || retained.before != published.proof_record.statement.before
            || retained.proof.as_ref() != Some(&BlobRef::of_bytes(&published.proof_manifest_bytes))
            || retained.producer_public_key != Some(published.proof_record.producer_public_key)
            || retained.record.as_deref() != Some(encoded_record.as_slice())
            || retained.witness.is_some()
        {
            return Err(TransitionProofConfirmationError::InvalidState);
        }
        let retained_work = self.load_confirmation_artifact::<U::Error>(&retained.work)?;
        let retained_transition = self.load_confirmation_artifact::<U::Error>(
            retained
                .transition
                .as_ref()
                .ok_or(TransitionProofConfirmationError::InvalidState)?,
        )?;
        let retained_manifest = self.load_confirmation_artifact::<U::Error>(
            retained
                .proof
                .as_ref()
                .ok_or(TransitionProofConfirmationError::InvalidState)?,
        )?;
        if retained_work != published.canonical_work
            || retained_transition != published.canonical_transition
            || retained_manifest != published.proof_manifest_bytes
        {
            self.poisoned = true;
            return Err(TransitionProofConfirmationError::InvalidState);
        }
        let mut candidate = self.image.clone();
        candidate.records.remove(index);
        let bytes = candidate.encode();
        if !candidate.has_valid_envelope() || bytes.len() > MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES {
            return Err(TransitionProofConfirmationError::InvalidState);
        }
        if let Err(error) = self
            .store
            .commit(&bytes, &[], TransitionProofWitnessMutation::Keep)
        {
            self.poisoned = true;
            return Err(TransitionProofConfirmationError::Storage(error));
        }
        self.image = candidate;
        Ok(())
    }

    fn load_confirmation_artifact<PublicationError>(
        &mut self,
        reference: &BlobRef,
    ) -> Result<Vec<u8>, TransitionProofConfirmationError<B::Error, PublicationError>> {
        match self.store.load_artifact(reference) {
            Ok(Some(bytes)) if reference.matches(&bytes) => Ok(bytes),
            Ok(_) => {
                self.poisoned = true;
                Err(TransitionProofConfirmationError::InvalidState)
            }
            Err(error) => {
                self.poisoned = true;
                Err(TransitionProofConfirmationError::Storage(error))
            }
        }
    }

    /// Reclaim every producer-side workflow covered by an authenticated
    /// acknowledgement checkpoint. This is intentionally independent of a
    /// caller retrying the original invocation: a long-offline producer must
    /// not leak its bounded 1024 workflow slots merely because another Shared
    /// replica performed Ack and checkpoint compaction.
    pub(crate) fn reclaim_checkpoint_retired<U: VerifiedTransitionPublisher>(
        &mut self,
        journal: &mut U,
    ) -> Result<usize, TransitionProofConfirmationError<B::Error, U::Error>> {
        if self.poisoned {
            return Err(TransitionProofConfirmationError::InvalidState);
        }
        let mut removed = 0usize;
        let mut index = 0usize;
        while index < self.image.records.len() {
            let key = self.image.records[index].key;
            let Some(retired) = journal
                .load_retired(key)
                .map_err(TransitionProofConfirmationError::Publication)?
            else {
                index += 1;
                continue;
            };
            if retired.key().invocation != key.invocation {
                return Err(TransitionProofConfirmationError::InvalidState);
            }
            let witness = self.image.records[index].witness;
            let mut candidate = self.image.clone();
            candidate.records.remove(index);
            let bytes = candidate.encode();
            if !candidate.has_valid_envelope()
                || bytes.len() > MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES
            {
                return Err(TransitionProofConfirmationError::InvalidState);
            }
            let mutation = witness.map_or(TransitionProofWitnessMutation::Keep, |statement| {
                TransitionProofWitnessMutation::Remove { statement }
            });
            if let Err(error) = self.store.commit(&bytes, &[], mutation) {
                self.poisoned = true;
                return Err(TransitionProofConfirmationError::Storage(error));
            }
            self.image = candidate;
            removed = removed
                .checked_add(1)
                .ok_or(TransitionProofConfirmationError::InvalidState)?;
        }
        Ok(removed)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn execute_prove_publish<A, E, R, P, V, U>(
        &mut self,
        work: RuntimeWork,
        validator: &mut A,
        executor: &mut E,
        roots: &mut R,
        producer: &mut P,
        verifier: &V,
        publisher: &mut U,
    ) -> Result<
        PublishedAttestedTransition,
        TransitionProofHostError<B::Error, A::Error, E::Error, R::Error, P::Error, U::Error>,
    >
    where
        A: AttestedTransitionValidator,
        E: AttestedTentativeExecutor,
        R: TransitionLaneRootResolver,
        P: AgentTransitionProofProducer,
        V: TransitionProofVerifier,
        U: ImmediateVerifiedTransitionPublisher,
    {
        match self.execute_prove_prepare(
            work, validator, executor, roots, producer, verifier, publisher,
        )? {
            VerifiedTransitionPreparation::AlreadyPublished(published) => Ok(published),
            VerifiedTransitionPreparation::AlreadyRetired(_) => {
                Err(TransitionProofHostError::InvalidState)
            }
            VerifiedTransitionPreparation::Prepared(prepared) => {
                let confirmation = prepared.confirmation();
                let publication = publisher
                    .publish_verified(prepared.as_publication())
                    .map_err(TransitionProofHostError::Publication)?;
                if publication != prepared.expected_fact() {
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::InvalidPublication,
                    ));
                }
                self.confirm_published(confirmation, publisher)
                    .map_err(|error| match error {
                        TransitionProofConfirmationError::Storage(error) => {
                            TransitionProofHostError::Storage(error)
                        }
                        TransitionProofConfirmationError::Publication(error) => {
                            TransitionProofHostError::Publication(error)
                        }
                        TransitionProofConfirmationError::NotPublished
                        | TransitionProofConfirmationError::InvalidState => {
                            TransitionProofHostError::InvalidState
                        }
                    })?;
                Ok(prepared.into_published())
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn resume<A, E, R, P, V, U>(
        &mut self,
        index: usize,
        authenticated: &AuthenticatedAttestedTransition,
        validator: &mut A,
        executor: &mut E,
        roots: &mut R,
        producer: &mut P,
        verifier: &V,
        _journal: &mut U,
    ) -> Result<
        VerifiedTransitionPreparation,
        TransitionProofHostError<B::Error, A::Error, E::Error, R::Error, P::Error, U::Error>,
    >
    where
        A: AttestedTransitionValidator,
        E: AttestedTentativeExecutor,
        R: TransitionLaneRootResolver,
        P: AgentTransitionProofProducer,
        V: TransitionProofVerifier,
        U: VerifiedTransitionPublisher,
    {
        loop {
            let retained = self
                .image
                .records
                .get(index)
                .cloned()
                .ok_or(TransitionProofHostError::InvalidState)?;
            let canonical_work = self.load_artifact(retained.work.clone())?;
            let work = canonical_decode::<RuntimeWork>(&canonical_work)
                .map_err(|_| TransitionProofHostError::InvalidState)?;
            if !self.image.route.matches_work(&work)
                || transition_key(&work, &canonical_work, retained.before) != Some(retained.key)
                || retained.key != authenticated.key()
            {
                return Err(TransitionProofHostError::InvalidState);
            }
            let current_before = match roots.before_roots(&work) {
                Ok(before) => before,
                Err(error) => {
                    let (terminal, error) = error.into_parts();
                    if terminal {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                    }
                    return Err(TransitionProofHostError::Roots(error));
                }
            };
            if current_before != retained.before {
                return Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::DivergentRetry,
                ));
            }

            if retained.transition.is_none() {
                let tentative = match executor.execute_tentative(authenticated, &canonical_work) {
                    Ok(tentative) => tentative,
                    Err(error) => {
                        let (terminal, error) = error.into_parts();
                        if terminal {
                            self.reclaim_unpublished_record(index, retained.witness)?;
                        }
                        return Err(TransitionProofHostError::Execution(error));
                    }
                };
                if tentative.proof_system != self.image.route.proof_system {
                    self.reclaim_unpublished_record(index, retained.witness)?;
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::WrongProofSystem,
                    ));
                }
                if tentative.refine_trace == Hash::ZERO
                    || tentative.public_io == Hash::ZERO
                    || tentative.private_witness.is_empty()
                    || tentative.private_witness.len() > MAX_PRIVATE_WITNESS_BYTES
                {
                    self.reclaim_unpublished_record(index, retained.witness)?;
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::InvalidTrace,
                    ));
                }
                if let Err(rejection) = validate_transition_for_work(&work, &tentative.transition) {
                    self.reclaim_unpublished_record(index, retained.witness)?;
                    return Err(TransitionProofHostError::Rejected(rejection));
                }
                match validator.validate_successor(authenticated, &work, &tentative.transition) {
                    Ok(()) => {}
                    Err(error) => {
                        let (terminal, error) = error.into_parts();
                        if terminal {
                            self.reclaim_unpublished_record(index, retained.witness)?;
                        }
                        return Err(TransitionProofHostError::Validation(error));
                    }
                }
                let canonical_transition = match tentative.transition.encode() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::Rejected(
                            TransitionProofHostRejection::InvalidTransition,
                        ));
                    }
                };
                let after = match roots.after_roots(&work, &tentative.transition) {
                    Ok(after) => after,
                    Err(error) => {
                        let (terminal, error) = error.into_parts();
                        if terminal {
                            self.reclaim_unpublished_record(index, retained.witness)?;
                        }
                        return Err(TransitionProofHostError::Roots(error));
                    }
                };
                let subject = subject_for(&self.image.route, &work, authenticated.method().into())
                    .ok_or(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::InvalidWork,
                    ))?;
                let statement = TransitionProofStatement {
                    subject,
                    before: retained.before,
                    after,
                    work: TransitionProofStatement::work_commitment(&canonical_work),
                    transition: TransitionProofStatement::transition_commitment(
                        &canonical_transition,
                    ),
                    refine_trace: tentative.refine_trace,
                    public_io: tentative.public_io,
                    proof_system: tentative.proof_system,
                };
                let statement_bytes = match statement.encode() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::Rejected(
                            TransitionProofHostRejection::InvalidRoots,
                        ));
                    }
                };
                let statement_id = match statement.commitment() {
                    Ok(statement) => statement,
                    Err(_) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::InvalidState);
                    }
                };
                let witness = ProducerPrivateWitness {
                    statement: statement_id,
                    bytes: tentative.private_witness,
                };
                let transition_ref = BlobRef::of_bytes(&canonical_transition);
                let mut candidate = self.image.clone();
                let candidate_record = candidate
                    .records
                    .get_mut(index)
                    .ok_or(TransitionProofHostError::InvalidState)?;
                candidate_record.transition = Some(transition_ref.clone());
                candidate_record.statement = Some(statement_bytes);
                candidate_record.witness = Some(statement_id);
                self.commit(
                    candidate,
                    &[TransitionProofArtifact {
                        reference: &transition_ref,
                        bytes: &canonical_transition,
                    }],
                    TransitionProofWitnessMutation::Put(&witness),
                )?;
                continue;
            }

            let canonical_transition = self.load_artifact(
                retained
                    .transition
                    .clone()
                    .ok_or(TransitionProofHostError::InvalidState)?,
            )?;
            let transition = canonical_decode::<RuntimeTransition>(&canonical_transition)
                .map_err(|_| TransitionProofHostError::InvalidState)?;
            validate_transition_for_work(&work, &transition)
                .map_err(TransitionProofHostError::Rejected)?;
            let statement = canonical_decode::<TransitionProofStatement>(
                retained
                    .statement
                    .as_deref()
                    .ok_or(TransitionProofHostError::InvalidState)?,
            )
            .map_err(|_| TransitionProofHostError::InvalidState)?;
            validate_statement_binding(
                authenticated,
                &work,
                &canonical_work,
                &transition,
                &canonical_transition,
                retained.before,
                &statement,
            )
            .map_err(TransitionProofHostError::Rejected)?;
            match validator.validate_successor(authenticated, &work, &transition) {
                Ok(()) => {}
                Err(error) => {
                    let (terminal, error) = error.into_parts();
                    if terminal {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                    }
                    return Err(TransitionProofHostError::Validation(error));
                }
            }
            let current_after = match roots.after_roots(&work, &transition) {
                Ok(after) => after,
                Err(error) => {
                    let (terminal, error) = error.into_parts();
                    if terminal {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                    }
                    return Err(TransitionProofHostError::Roots(error));
                }
            };
            if current_after != statement.after {
                return Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::DivergentRetry,
                ));
            }

            if retained.proof.is_none() {
                let statement_id = statement
                    .commitment()
                    .map_err(|_| TransitionProofHostError::InvalidState)?;
                if retained.witness != Some(statement_id) {
                    return Err(TransitionProofHostError::InvalidState);
                }
                let witness = self.load_witness(statement_id)?;
                if witness.statement != statement_id
                    || witness.bytes.is_empty()
                    || witness.bytes.len() > MAX_PRIVATE_WITNESS_BYTES
                {
                    return Err(TransitionProofHostError::InvalidState);
                }
                // The atomic image/artifact/witness store is the local trust
                // boundary. The durable work/transition hashes, statement
                // commitment, and private-witness statement id authenticate
                // this prepared phase across restart, so it must not execute
                // the transition again before proving it.
                let public_key = producer.public_key();
                if public_key == [0; PROOF_PUBLIC_KEY_BYTES]
                    || ProducerId::of_public_key(&public_key) != self.image.route.producer
                {
                    self.reclaim_unpublished_record(index, retained.witness)?;
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::WrongProducer,
                    ));
                }
                let proof = producer.prove_nested_refine(authenticated, &statement, &witness);
                let proof = match proof {
                    Ok(proof) => proof,
                    Err(error) => {
                        let (terminal, error) = error.into_parts();
                        if terminal {
                            self.reclaim_unpublished_record(index, retained.witness)?;
                        }
                        return Err(TransitionProofHostError::Producer(error));
                    }
                };
                if proof.is_empty()
                    || proof.len() > MAX_PROOF_MATERIAL_BYTES
                    || proof.len() as u64 > authenticated.max_proof_material_bytes()
                {
                    self.reclaim_unpublished_record(index, retained.witness)?;
                    return Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::InvalidProof,
                    ));
                }
                let manifest = match TransitionProofMaterialManifest::for_material(&proof) {
                    Ok(manifest) => manifest,
                    Err(_) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::Rejected(
                            TransitionProofHostRejection::InvalidProof,
                        ));
                    }
                };
                let manifest_bytes = match manifest.encode() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::Rejected(
                            TransitionProofHostRejection::InvalidProof,
                        ));
                    }
                };
                let proof_ref = BlobRef::of_bytes(&manifest_bytes);
                let mut candidate = self.image.clone();
                let candidate_record = candidate
                    .records
                    .get_mut(index)
                    .ok_or(TransitionProofHostError::InvalidState)?;
                candidate_record.proof = Some(proof_ref.clone());
                candidate_record.producer_public_key = Some(public_key);
                let chunk_bytes = usize::try_from(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES)
                    .map_err(|_| TransitionProofHostError::InvalidState)?;
                let mut artifacts = Vec::with_capacity(manifest.chunks.len() + 1);
                artifacts.push(TransitionProofArtifact {
                    reference: &proof_ref,
                    bytes: &manifest_bytes,
                });
                artifacts.extend(
                    manifest
                        .chunks
                        .iter()
                        .zip(proof.chunks(chunk_bytes))
                        .map(|(reference, bytes)| TransitionProofArtifact { reference, bytes }),
                );
                self.commit(candidate, &artifacts, TransitionProofWitnessMutation::Keep)?;
                continue;
            }

            let proof_ref = retained
                .proof
                .clone()
                .ok_or(TransitionProofHostError::InvalidState)?;
            let proof_manifest = self.load_artifact(proof_ref.clone())?;
            if !proof_ref.matches(&proof_manifest) {
                return Err(TransitionProofHostError::InvalidState);
            }
            let proof_material = self.load_proof_material(&proof_manifest)?;
            let public_key = retained
                .producer_public_key
                .ok_or(TransitionProofHostError::InvalidState)?;
            if ProducerId::of_public_key(&public_key) != self.image.route.producer {
                return Err(TransitionProofHostError::InvalidState);
            }

            if retained.record.is_none() {
                let mut record = TransitionProofRecord {
                    statement: statement.clone(),
                    proof: proof_ref,
                    producer: self.image.route.producer,
                    producer_public_key: public_key,
                    producer_signature: [0; PROOF_SIGNATURE_BYTES],
                };
                let signing_bytes = record
                    .signing_bytes()
                    .map_err(|_| TransitionProofHostError::InvalidState)?;
                record.producer_signature =
                    match producer.sign_transition_record(authenticated, &signing_bytes) {
                        Ok(signature) => signature,
                        Err(error) => {
                            let (terminal, error) = error.into_parts();
                            if terminal {
                                self.reclaim_unpublished_record(index, retained.witness)?;
                            }
                            return Err(TransitionProofHostError::Producer(error));
                        }
                    };
                match verify_exact_record(
                    authenticated,
                    &record,
                    &proof_manifest,
                    &proof_material,
                    &work,
                    &canonical_work,
                    &transition,
                    &canonical_transition,
                    retained.before,
                    current_after,
                    verifier,
                ) {
                    Ok(()) => {}
                    Err(TransitionProofHostRejection::InvalidProducerSignature) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::Rejected(
                            TransitionProofHostRejection::InvalidProducerSignature,
                        ));
                    }
                    Err(_) => {
                        self.reclaim_unpublished_record(index, retained.witness)?;
                        return Err(TransitionProofHostError::Rejected(
                            TransitionProofHostRejection::InvalidProof,
                        ));
                    }
                }
                let record_bytes = record
                    .encode()
                    .map_err(|_| TransitionProofHostError::InvalidState)?;
                let statement_id = statement
                    .commitment()
                    .map_err(|_| TransitionProofHostError::InvalidState)?;
                let mut candidate = self.image.clone();
                let candidate_record = candidate
                    .records
                    .get_mut(index)
                    .ok_or(TransitionProofHostError::InvalidState)?;
                candidate_record.record = Some(record_bytes);
                candidate_record.witness = None;
                self.commit(
                    candidate,
                    &[],
                    TransitionProofWitnessMutation::Remove {
                        statement: statement_id,
                    },
                )?;
                continue;
            }

            let record = canonical_decode::<TransitionProofRecord>(
                retained
                    .record
                    .as_deref()
                    .ok_or(TransitionProofHostError::InvalidState)?,
            )
            .map_err(|_| TransitionProofHostError::InvalidState)?;
            verify_exact_record(
                authenticated,
                &record,
                &proof_manifest,
                &proof_material,
                &work,
                &canonical_work,
                &transition,
                &canonical_transition,
                retained.before,
                current_after,
                verifier,
            )
            .map_err(TransitionProofHostError::Rejected)?;
            let expected = TransitionPublicationFact::reconstruct(&record)
                .map_err(|_| TransitionProofHostError::InvalidState)?;

            let actor_package = authenticated
                .actor_entry()
                .ok_or(TransitionProofHostError::InvalidState)?
                .package
                .clone();
            return Ok(VerifiedTransitionPreparation::Prepared(
                PreparedVerifiedTransition {
                    canonical_work,
                    canonical_transition,
                    proof_record: record,
                    proof_manifest_bytes: proof_manifest,
                    proof_material,
                    actor_package,
                    publication: expected,
                },
            ));
        }
    }

    #[allow(clippy::type_complexity)]
    fn load_artifact<A, E, R, P, U>(
        &mut self,
        reference: BlobRef,
    ) -> Result<Vec<u8>, TransitionProofHostError<B::Error, A, E, R, P, U>> {
        match self.store.load_artifact(&reference) {
            Ok(Some(bytes)) if reference.matches(&bytes) => Ok(bytes),
            Ok(_) => {
                self.poisoned = true;
                Err(TransitionProofHostError::InvalidState)
            }
            Err(error) => {
                self.poisoned = true;
                Err(TransitionProofHostError::Storage(error))
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn load_proof_material<A, E, R, P, U>(
        &mut self,
        manifest_bytes: &[u8],
    ) -> Result<Vec<u8>, TransitionProofHostError<B::Error, A, E, R, P, U>> {
        let manifest = match TransitionProofMaterialManifest::decode(manifest_bytes) {
            Ok(manifest) => manifest,
            Err(_) => {
                self.poisoned = true;
                return Err(TransitionProofHostError::InvalidState);
            }
        };
        let material_len =
            match manifest.bounded_material_len(self.image.route.max_proof_material_bytes) {
                Ok(material_len) => material_len,
                Err(_) => {
                    self.poisoned = true;
                    return Err(TransitionProofHostError::InvalidState);
                }
            };
        let mut material = Vec::new();
        if material.try_reserve_exact(material_len).is_err() {
            self.poisoned = true;
            return Err(TransitionProofHostError::InvalidState);
        }
        for reference in &manifest.chunks {
            let chunk = self.load_artifact::<A, E, R, P, U>(reference.clone())?;
            material.extend_from_slice(&chunk);
        }
        if material.len() != material_len || !manifest.material.matches(&material) {
            self.poisoned = true;
            return Err(TransitionProofHostError::InvalidState);
        }
        Ok(material)
    }

    fn load_witness<A, E, R, P, U>(
        &mut self,
        statement: Hash,
    ) -> Result<ProducerPrivateWitness, TransitionProofHostError<B::Error, A, E, R, P, U>> {
        match self.store.load_private_witness(statement) {
            Ok(Some(witness)) => Ok(witness),
            Ok(None) => {
                self.poisoned = true;
                Err(TransitionProofHostError::InvalidState)
            }
            Err(error) => {
                self.poisoned = true;
                Err(TransitionProofHostError::Storage(error))
            }
        }
    }

    fn commit<A, E, R, P, U>(
        &mut self,
        candidate: TransitionProofHostImage,
        artifacts: &[TransitionProofArtifact<'_>],
        witness: TransitionProofWitnessMutation<'_>,
    ) -> Result<(), TransitionProofHostError<B::Error, A, E, R, P, U>> {
        if !candidate.has_valid_envelope() {
            return Err(TransitionProofHostError::InvalidState);
        }
        let bytes = candidate.encode();
        if bytes.len() > MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES {
            return Err(TransitionProofHostError::InvalidState);
        }
        if let Err(error) = self.store.commit(&bytes, artifacts, witness) {
            self.poisoned = true;
            return Err(TransitionProofHostError::Storage(error));
        }
        self.image = candidate;
        Ok(())
    }

    /// Remove a workflow known not to have crossed the authoritative
    /// publication seam. Public CAS objects may remain as harmless orphans;
    /// producer-private witness material is removed atomically with the image.
    fn reclaim_unpublished_record<A, E, R, P, U>(
        &mut self,
        index: usize,
        witness: Option<Hash>,
    ) -> Result<(), TransitionProofHostError<B::Error, A, E, R, P, U>> {
        self.image
            .records
            .get(index)
            .ok_or(TransitionProofHostError::InvalidState)?;
        self.remove_record(index, witness)
    }

    /// Reclaim a retry whose adapter terminally rejected authenticated work
    /// before the before-root-dependent execution key could be reconstructed.
    /// The content-addressed work body and invocation must identify exactly
    /// one retained workflow; ambiguity is rejected rather than guessed.
    #[allow(clippy::type_complexity)]
    fn reclaim_terminal_work<A, E, R, P, U>(
        &mut self,
        work: &RuntimeWork,
        canonical_work: &[u8],
    ) -> Result<(), TransitionProofHostError<B::Error, A, E, R, P, U>> {
        let invocation = invocation_id(work).ok_or(TransitionProofHostError::InvalidState)?;
        let work_ref = BlobRef::of_bytes(canonical_work);
        let mut matches =
            self.image.records.iter().enumerate().filter(|(_, record)| {
                record.key.invocation == invocation && record.work == work_ref
            });
        let Some((index, record)) = matches.next() else {
            return Ok(());
        };
        let witness = record.witness;
        if matches.next().is_some() {
            return Err(TransitionProofHostError::InvalidState);
        }
        let retained_work = self.load_artifact::<A, E, R, P, U>(work_ref)?;
        let decoded = canonical_decode::<RuntimeWork>(&retained_work)
            .map_err(|_| TransitionProofHostError::InvalidState)?;
        if retained_work != canonical_work
            || &decoded != work
            || !self.image.route.matches_work(&decoded)
        {
            return Err(TransitionProofHostError::InvalidState);
        }
        self.reclaim_unpublished_record(index, witness)
    }

    /// Remove a workflow after authoritative journal lookup confirmed the
    /// exact key and proof fact.
    fn complete_record<A, E, R, P, U>(
        &mut self,
        index: usize,
        witness: Option<Hash>,
    ) -> Result<(), TransitionProofHostError<B::Error, A, E, R, P, U>> {
        self.remove_record(index, witness)
    }

    fn remove_record<A, E, R, P, U>(
        &mut self,
        index: usize,
        witness: Option<Hash>,
    ) -> Result<(), TransitionProofHostError<B::Error, A, E, R, P, U>> {
        self.image
            .records
            .get(index)
            .ok_or(TransitionProofHostError::InvalidState)?;
        let mut candidate = self.image.clone();
        candidate.records.remove(index);
        self.commit(
            candidate,
            &[],
            witness.map_or(TransitionProofWitnessMutation::Keep, |statement| {
                TransitionProofWitnessMutation::Remove { statement }
            }),
        )
    }
}

fn canonical_decode<T: CanonicalWire + PartialEq>(bytes: &[u8]) -> Result<T, ()> {
    let value = T::decode(bytes).map_err(|_| ())?;
    (value.encode().ok().as_deref() == Some(bytes))
        .then_some(value)
        .ok_or(())
}

fn invocation_id(work: &RuntimeWork) -> Option<InvocationId> {
    match work {
        RuntimeWork::Invoke { invocation, .. } => Some(invocation.invocation),
        RuntimeWork::Resume { resume, .. } => Some(resume.invocation),
        RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => None,
    }
}

fn transition_key(
    work: &RuntimeWork,
    canonical_work: &[u8],
    before: ProofLaneRoots,
) -> Option<TransitionProofKey> {
    if !before.validate() {
        return None;
    }
    let work_commitment = TransitionProofStatement::work_commitment(canonical_work);
    let key = TransitionProofKey {
        invocation: invocation_id(work)?,
        execution: TransitionProofStatement::execution_commitment(work_commitment, before),
    };
    key.validate().then_some(key)
}

fn method_name(work: &RuntimeWork) -> Option<String> {
    let RuntimeWork::Invoke { invocation, .. } = work else {
        return None;
    };
    invocation
        .message
        .strip_prefix(&[TAG_DYNAMIC])
        .and_then(Msg::try_decode)
        .map(|message| message.name)
}

fn authenticate_admission(
    route: &AttestedTransitionRoute,
    key: TransitionProofKey,
    before: ProofLaneRoots,
    work: &RuntimeWork,
    canonical_work: &[u8],
    admission: AttestedTransitionAdmission,
) -> Option<AuthenticatedAttestedTransition> {
    let (actor, deployment, program, mode) = match work {
        RuntimeWork::Invoke { invocation, .. } => (
            invocation.actor,
            invocation.deployment,
            invocation.program,
            invocation.mode,
        ),
        RuntimeWork::Resume { resume, .. } => {
            (resume.actor, resume.deployment, resume.program, resume.mode)
        }
        RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => return None,
    };
    if admission.space != route.space
        || admission.agent != route.agent
        || admission.runtime_deployment != route.runtime_deployment
        || admission.runtime_program != route.runtime_program
        || admission.runtime_package != route.runtime_package
        || admission.max_proof_material_bytes != route.max_proof_material_bytes
        || !admission.runtime_contract.is_valid()
        || admission.runtime_capabilities.validate().is_err()
        || admission.actor_entry.validate().is_err()
        || admission.actor_entry.actor != actor
        || admission.actor_entry.deployment != deployment
        || admission.actor_entry.program != program
        || admission.actor_entry.suspended
        || admission.actor_entry.lanes != admission.actor_requirements.lanes
        || !admission
            .runtime_contract
            .supports(admission.actor_contract)
        || !admission
            .runtime_capabilities
            .satisfies(admission.actor_requirements)
        || !admission
            .runtime_capabilities
            .proof_systems
            .contains(route.proof_system)
        || !admission
            .actor_requirements
            .proof_systems
            .contains(route.proof_system)
        || mode
            .write_lane()
            .is_some_and(|lane| !admission.actor_requirements.lanes.contains(lane))
        || transition_key(work, canonical_work, before) != Some(key)
        || matches!(work, RuntimeWork::Invoke { .. })
            && method_name(work).as_deref() != Some(admission.method.as_str())
        || subject_for(route, work, admission.method.clone()).is_none()
    {
        return None;
    }
    let execution = AuthenticatedAttestedExecutionBinding {
        runtime_contract: admission.runtime_contract,
        runtime_capabilities: admission.runtime_capabilities,
        actor_entry: admission.actor_entry,
        actor_contract: admission.actor_contract,
        actor_requirements: admission.actor_requirements,
    };
    Some(AuthenticatedAttestedTransition {
        route: route.clone(),
        key,
        work: TransitionProofStatement::work_commitment(canonical_work),
        before,
        method: admission.method,
        execution: Some(execution),
    })
}

fn subject_for(
    route: &AttestedTransitionRoute,
    work: &RuntimeWork,
    method: String,
) -> Option<TransitionProofSubject> {
    let (actor, incarnation, actor_deployment, actor_program, invocation, mode) = match work {
        RuntimeWork::Invoke { invocation, .. } => (
            invocation.actor,
            invocation.incarnation,
            invocation.deployment,
            invocation.program,
            invocation.invocation,
            invocation.mode,
        ),
        RuntimeWork::Resume { resume, .. } => (
            resume.actor,
            resume.incarnation,
            resume.deployment,
            resume.program,
            resume.invocation,
            resume.mode,
        ),
        RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => return None,
    };
    let subject = TransitionProofSubject {
        space: route.space,
        agent: route.agent,
        runtime_deployment: route.runtime_deployment,
        runtime_program: route.runtime_program,
        runtime_package: route.runtime_package.clone(),
        actor,
        incarnation,
        actor_deployment,
        actor_program,
        invocation,
        method,
        mode,
    };
    subject.validate().then_some(subject)
}

fn validate_transition_for_work(
    work: &RuntimeWork,
    transition: &RuntimeTransition,
) -> Result<(), TransitionProofHostRejection> {
    let (invocation, actor, incarnation, deployment, program, mode, gas) = match work {
        RuntimeWork::Invoke { invocation, .. } => (
            invocation.invocation,
            invocation.actor,
            invocation.incarnation,
            invocation.deployment,
            invocation.program,
            invocation.mode,
            Some(invocation.gas),
        ),
        RuntimeWork::Resume { resume, .. } => (
            resume.invocation,
            resume.actor,
            resume.incarnation,
            resume.deployment,
            resume.program,
            resume.mode,
            None,
        ),
        RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => {
            return Err(TransitionProofHostRejection::InvalidWork);
        }
    };
    if !transition.validate() {
        return Err(TransitionProofHostRejection::InvalidTransition);
    }
    match &transition.outcome {
        RuntimeOutcome::Completed(Ok(reply))
            if reply.invocation == invocation
                && reply.actor == actor
                && reply.incarnation == incarnation
                && reply.deployment == deployment
                && reply.mode == mode
                && reply.lane == mode.write_lane()
                && gas.is_none_or(|budget| reply.gas_remaining <= budget) =>
        {
            Ok(())
        }
        RuntimeOutcome::Completed(Err(_)) => Ok(()),
        RuntimeOutcome::Yielded(yielded)
            if yielded.invocation == invocation
                && yielded.actor == actor
                && yielded.incarnation == incarnation
                && yielded.deployment == deployment
                && yielded.program == program
                && yielded.mode == mode =>
        {
            Ok(())
        }
        _ => Err(TransitionProofHostRejection::InvalidTransition),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_statement_binding(
    authenticated: &AuthenticatedAttestedTransition,
    work: &RuntimeWork,
    canonical_work: &[u8],
    _transition: &RuntimeTransition,
    canonical_transition: &[u8],
    before: ProofLaneRoots,
    statement: &TransitionProofStatement,
) -> Result<(), TransitionProofHostRejection> {
    validate_statement_binding_for_route(
        &authenticated.route,
        authenticated.method(),
        work,
        canonical_work,
        canonical_transition,
        before,
        statement,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_statement_binding_for_route(
    route: &AttestedTransitionRoute,
    method: &str,
    work: &RuntimeWork,
    canonical_work: &[u8],
    canonical_transition: &[u8],
    before: ProofLaneRoots,
    statement: &TransitionProofStatement,
) -> Result<(), TransitionProofHostRejection> {
    let subject =
        subject_for(route, work, method.into()).ok_or(TransitionProofHostRejection::InvalidWork)?;
    if statement.matches_execution(
        &subject,
        before,
        statement.after,
        canonical_work,
        canonical_transition,
        statement.refine_trace,
        statement.public_io,
        route.proof_system,
    ) {
        Ok(())
    } else {
        Err(TransitionProofHostRejection::InvalidTransition)
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_exact_record<V: TransitionProofVerifier>(
    authenticated: &AuthenticatedAttestedTransition,
    record: &TransitionProofRecord,
    proof_manifest: &[u8],
    proof_material: &[u8],
    work: &RuntimeWork,
    canonical_work: &[u8],
    _transition: &RuntimeTransition,
    canonical_transition: &[u8],
    expected_before: ProofLaneRoots,
    expected_after: ProofLaneRoots,
    verifier: &V,
) -> Result<(), TransitionProofHostRejection> {
    let route = &authenticated.route;
    let subject = subject_for(route, work, authenticated.method().into())
        .ok_or(TransitionProofHostRejection::InvalidWork)?;
    if record.statement.key() != authenticated.key()
        || record.producer != route.producer
        || ProducerId::of_public_key(&record.producer_public_key) != route.producer
    {
        return Err(TransitionProofHostRejection::WrongProducer);
    }
    record
        .verify_exact(
            proof_manifest,
            proof_material,
            &subject,
            expected_before,
            expected_after,
            canonical_work,
            canonical_transition,
            record.statement.refine_trace,
            record.statement.public_io,
            route.proof_system,
            route.producer,
            verifier,
        )
        .map_err(|error| match error {
            super::sdk::proof::ProofRecordError::InvalidProducerSignature => {
                TransitionProofHostRejection::InvalidProducerSignature
            }
            _ => TransitionProofHostRejection::InvalidProof,
        })
}

/// Check a retained record for corruption while opening the local sidecar.
///
/// This is deliberately not root authorization: the open path has no journal
/// materializer, so its expected roots come from the producer-signed record.
/// Before either recovering or publishing a result, `execute_prove_publish`
/// independently resolves both roots and passes them to `verify_exact_record`.
#[allow(clippy::too_many_arguments)]
fn verify_durable_record_integrity<V: TransitionProofVerifier>(
    authenticated: &AuthenticatedAttestedTransition,
    record: &TransitionProofRecord,
    proof_manifest: &[u8],
    proof_material: &[u8],
    work: &RuntimeWork,
    canonical_work: &[u8],
    transition: &RuntimeTransition,
    canonical_transition: &[u8],
    verifier: &V,
) -> Result<(), TransitionProofHostRejection> {
    verify_exact_record(
        authenticated,
        record,
        proof_manifest,
        proof_material,
        work,
        canonical_work,
        transition,
        canonical_transition,
        record.statement.before,
        record.statement.after,
        verifier,
    )
}

fn validate_durable_image<B: TransitionProofHostStore, V: TransitionProofVerifier>(
    store: &mut B,
    image: &TransitionProofHostImage,
    verifier: &V,
) -> Result<(), TransitionProofHostOpenError<B::Error>> {
    for retained in &image.records {
        let work_bytes = load_open_artifact(store, &retained.work)?;
        let work = canonical_decode::<RuntimeWork>(&work_bytes)
            .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
        if !image.route.matches_work(&work)
            || transition_key(&work, &work_bytes, retained.before) != Some(retained.key)
        {
            return Err(TransitionProofHostOpenError::InvalidState);
        }
        let Some(transition_ref) = &retained.transition else {
            continue;
        };
        let transition_bytes = load_open_artifact(store, transition_ref)?;
        let transition = canonical_decode::<RuntimeTransition>(&transition_bytes)
            .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
        validate_transition_for_work(&work, &transition)
            .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
        let statement = canonical_decode::<TransitionProofStatement>(
            retained
                .statement
                .as_deref()
                .ok_or(TransitionProofHostOpenError::InvalidState)?,
        )
        .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
        validate_statement_binding_for_route(
            &image.route,
            &statement.subject.method,
            &work,
            &work_bytes,
            &transition_bytes,
            retained.before,
            &statement,
        )
        .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
        if let Some(statement_id) = retained.witness {
            let witness = store
                .load_private_witness(statement_id)
                .map_err(TransitionProofHostOpenError::Storage)?
                .ok_or(TransitionProofHostOpenError::InvalidState)?;
            if statement.commitment().ok() != Some(statement_id)
                || witness.statement != statement_id
                || witness.bytes.is_empty()
                || witness.bytes.len() > MAX_PRIVATE_WITNESS_BYTES
            {
                return Err(TransitionProofHostOpenError::InvalidState);
            }
        }
        let Some(proof_ref) = &retained.proof else {
            continue;
        };
        let proof_manifest = load_open_artifact(store, proof_ref)?;
        let proof_material =
            load_open_proof_material(store, &proof_manifest, image.route.max_proof_material_bytes)?;
        let public_key = retained
            .producer_public_key
            .ok_or(TransitionProofHostOpenError::InvalidState)?;
        if ProducerId::of_public_key(&public_key) != image.route.producer {
            return Err(TransitionProofHostOpenError::InvalidState);
        }
        let Some(record_bytes) = &retained.record else {
            continue;
        };
        let record = canonical_decode::<TransitionProofRecord>(record_bytes)
            .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
        let authenticated = AuthenticatedAttestedTransition {
            route: image.route.clone(),
            key: retained.key,
            work: statement.work,
            before: statement.before,
            method: statement.subject.method.clone(),
            // Reopen needs only the proof subject. Execution admission is
            // re-authenticated from current catalog/journal facts before a
            // retained workflow can execute.
            execution: None,
        };
        verify_durable_record_integrity(
            &authenticated,
            &record,
            &proof_manifest,
            &proof_material,
            &work,
            &work_bytes,
            &transition,
            &transition_bytes,
            verifier,
        )
        .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
    }
    Ok(())
}

fn load_open_artifact<B: TransitionProofHostStore>(
    store: &mut B,
    reference: &BlobRef,
) -> Result<Vec<u8>, TransitionProofHostOpenError<B::Error>> {
    let bytes = store
        .load_artifact(reference)
        .map_err(TransitionProofHostOpenError::Storage)?
        .ok_or(TransitionProofHostOpenError::InvalidState)?;
    reference
        .matches(&bytes)
        .then_some(bytes)
        .ok_or(TransitionProofHostOpenError::InvalidState)
}

fn load_open_proof_material<B: TransitionProofHostStore>(
    store: &mut B,
    manifest_bytes: &[u8],
    maximum: u64,
) -> Result<Vec<u8>, TransitionProofHostOpenError<B::Error>> {
    let manifest = TransitionProofMaterialManifest::decode(manifest_bytes)
        .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
    let material_len = manifest
        .bounded_material_len(maximum)
        .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
    let mut material = Vec::new();
    material
        .try_reserve_exact(material_len)
        .map_err(|_| TransitionProofHostOpenError::InvalidState)?;
    for reference in &manifest.chunks {
        let chunk = load_open_artifact(store, reference)?;
        material.extend_from_slice(&chunk);
    }
    if material.len() != material_len || !manifest.material.matches(&material) {
        return Err(TransitionProofHostOpenError::InvalidState);
    }
    Ok(material)
}

fn encode_route(encoder: &mut Encoder<'_>, route: &AttestedTransitionRoute) {
    encoder.fixed(route.space.as_bytes());
    encoder.fixed(route.agent.as_bytes());
    encoder.fixed(route.runtime_deployment.as_bytes());
    encoder.fixed(route.runtime_program.as_bytes());
    encode_blob(encoder, &route.runtime_package);
    encoder.fixed(route.proof_system.as_bytes());
    encoder.u64(route.max_proof_material_bytes);
    encoder.fixed(route.producer.as_bytes());
}

fn decode_route(decoder: &mut Decoder<'_>) -> Result<AttestedTransitionRoute, DecodeError> {
    let route = AttestedTransitionRoute {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        runtime_deployment: DeploymentId(decoder.fixed()?),
        runtime_program: ProgramId(decoder.fixed()?),
        runtime_package: decode_blob(decoder)?,
        proof_system: Hash(decoder.fixed()?),
        max_proof_material_bytes: decoder.u64()?,
        producer: ProducerId(decoder.fixed()?),
    };
    route
        .is_valid()
        .then_some(route)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_key(encoder: &mut Encoder<'_>, key: TransitionProofKey) {
    encoder.fixed(key.invocation.as_bytes());
    encoder.fixed(key.execution.as_bytes());
}

fn decode_key(decoder: &mut Decoder<'_>) -> Result<TransitionProofKey, DecodeError> {
    let key = TransitionProofKey {
        invocation: InvocationId(decoder.fixed()?),
        execution: Hash(decoder.fixed()?),
    };
    key.validate()
        .then_some(key)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_optional_root(encoder: &mut Encoder<'_>, root: Option<Hash>) {
    encoder.option(&root, |encoder, root| encoder.fixed(root.as_bytes()));
}

fn decode_optional_root(decoder: &mut Decoder<'_>) -> Result<Option<Hash>, DecodeError> {
    let root = decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?;
    if root == Some(Hash::ZERO) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(root)
}

fn encode_roots(encoder: &mut Encoder<'_>, roots: ProofLaneRoots) {
    encoder.fixed(roots.control.as_bytes());
    encode_optional_root(encoder, roots.linear);
    encode_optional_root(encoder, roots.merge);
    encode_optional_root(encoder, roots.local);
}

fn decode_roots(decoder: &mut Decoder<'_>) -> Result<ProofLaneRoots, DecodeError> {
    let roots = ProofLaneRoots {
        control: Hash(decoder.fixed()?),
        linear: decode_optional_root(decoder)?,
        merge: decode_optional_root(decoder)?,
        local: decode_optional_root(decoder)?,
    };
    roots
        .validate()
        .then_some(roots)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_blob(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(reference.hash.as_bytes());
    encoder.u64(reference.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_retained(encoder: &mut Encoder<'_>, retained: &RetainedTransition) {
    encode_key(encoder, retained.key);
    encode_blob(encoder, &retained.work);
    encode_roots(encoder, retained.before);
    encoder.option(&retained.transition, encode_blob);
    encoder.option(&retained.statement, |encoder, bytes| encoder.bytes(bytes));
    encoder.option(&retained.witness, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&retained.proof, encode_blob);
    encoder.option(&retained.producer_public_key, |encoder, value| {
        encoder.0.extend_from_slice(value)
    });
    encoder.option(&retained.record, |encoder, bytes| encoder.bytes(bytes));
}

fn decode_retained(decoder: &mut Decoder<'_>) -> Result<RetainedTransition, DecodeError> {
    let retained = RetainedTransition {
        key: decode_key(decoder)?,
        work: decode_blob(decoder)?,
        before: decode_roots(decoder)?,
        transition: decoder.option(decode_blob)?,
        statement: decoder
            .option(|decoder| decoder.bytes_bounded(TransitionProofStatement::MAX_ENCODED_BYTES))?,
        witness: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        proof: decoder.option(decode_blob)?,
        producer_public_key: decoder.option(|decoder| {
            decoder
                .take(PROOF_PUBLIC_KEY_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)
        })?,
        record: decoder
            .option(|decoder| decoder.bytes_bounded(MAX_TRANSITION_PROOF_RECORD_BYTES))?,
    };
    retained
        .has_valid_envelope()
        .then_some(retained)
        .ok_or(DecodeError::NonCanonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "agent-transition-proof")]
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[cfg(feature = "agent-transition-proof")]
    use super::physical::{
        AttestedRuntimeProgramLoader, Ed25519PhysicalTransitionSigner, PhysicalRefineProofProducer,
        PhysicalRefineRouteComponents, PhysicalRefineRouteOpenError, STANDARD_INVOKE_GAS_OVERHEAD,
        STANDARD_RESUME_GAS_LIMIT, standard_refine_proof_system, standard_runtime_gas,
    };

    use crate::actors::codec::Encode as _;
    use crate::agent::sdk::{
        ActorId, InvocationAuthorization, InvocationOrigin, InvocationReply, InvocationRoleClaims,
        InvocationStatus, InvocationWork, MethodMode, PublicPreflight, ResumeInput, ResumeWork,
        RuntimeState,
    };

    const PRIVATE_SENTINEL: &[u8] = b"REFINE-PRIVATE-WITNESS-DO-NOT-PUBLISH-77";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StoreError {
        Injected,
        Collision,
    }

    impl fmt::Display for StoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{self:?}")
        }
    }

    impl std::error::Error for StoreError {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CommitSide {
        Before,
        After,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CommitFailure {
        number: usize,
        side: CommitSide,
    }

    #[derive(Default)]
    struct MemoryStoreState {
        image: Option<Vec<u8>>,
        artifacts: Vec<(BlobRef, Vec<u8>)>,
        artifact_loads: Vec<BlobRef>,
        witnesses: Vec<ProducerPrivateWitness>,
        commits: usize,
        fail_commit: Option<CommitFailure>,
        fail_artifact_load_once: bool,
        fail_witness_load_once: bool,
    }

    #[derive(Clone, Default)]
    struct MemoryStore(Rc<RefCell<MemoryStoreState>>);

    impl MemoryStore {
        fn fail_commit(&self, number: usize, side: CommitSide) {
            self.0.borrow_mut().fail_commit = Some(CommitFailure { number, side });
        }

        fn fail_artifact_load_once(&self) {
            self.0.borrow_mut().fail_artifact_load_once = true;
        }

        fn fail_witness_load_once(&self) {
            self.0.borrow_mut().fail_witness_load_once = true;
        }

        fn image(&self) -> Option<Vec<u8>> {
            self.0.borrow().image.clone()
        }

        fn contains_public_sentinel(&self) -> bool {
            let state = self.0.borrow();
            state
                .image
                .as_ref()
                .is_some_and(|bytes| contains(bytes, PRIVATE_SENTINEL))
                || state
                    .artifacts
                    .iter()
                    .any(|(_, bytes)| contains(bytes, PRIVATE_SENTINEL))
        }

        fn witness_count(&self) -> usize {
            self.0.borrow().witnesses.len()
        }
    }

    impl TransitionProofHostStore for MemoryStore {
        type Error = StoreError;

        fn load_image(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.borrow().image.clone())
        }

        fn load_artifact(&mut self, reference: &BlobRef) -> Result<Option<Vec<u8>>, Self::Error> {
            let mut state = self.0.borrow_mut();
            state.artifact_loads.push(reference.clone());
            if state.fail_artifact_load_once {
                state.fail_artifact_load_once = false;
                return Err(StoreError::Injected);
            }
            Ok(state
                .artifacts
                .iter()
                .find(|(stored, _)| stored == reference)
                .map(|(_, bytes)| bytes.clone()))
        }

        fn load_private_witness(
            &mut self,
            statement: Hash,
        ) -> Result<Option<ProducerPrivateWitness>, Self::Error> {
            let mut state = self.0.borrow_mut();
            if state.fail_witness_load_once {
                state.fail_witness_load_once = false;
                return Err(StoreError::Injected);
            }
            Ok(state
                .witnesses
                .iter()
                .find(|witness| witness.statement == statement)
                .map(|witness| ProducerPrivateWitness {
                    statement: witness.statement,
                    bytes: witness.bytes.clone(),
                }))
        }

        fn commit(
            &mut self,
            image: &[u8],
            artifacts: &[TransitionProofArtifact<'_>],
            witness: TransitionProofWitnessMutation<'_>,
        ) -> Result<(), Self::Error> {
            let mut state = self.0.borrow_mut();
            state.commits += 1;
            let failure = state
                .fail_commit
                .filter(|failure| failure.number == state.commits);
            if failure.is_some_and(|failure| failure.side == CommitSide::Before) {
                state.fail_commit = None;
                return Err(StoreError::Injected);
            }

            let mut next_artifacts = state.artifacts.clone();
            for artifact in artifacts {
                if !artifact.reference.matches(artifact.bytes) {
                    return Err(StoreError::Collision);
                }
                if let Some((_, bytes)) = next_artifacts
                    .iter()
                    .find(|(stored, _)| stored == artifact.reference)
                {
                    if bytes.as_slice() != artifact.bytes {
                        return Err(StoreError::Collision);
                    }
                } else {
                    next_artifacts.push((artifact.reference.clone(), artifact.bytes.to_vec()));
                }
            }
            let mut next_witnesses: Vec<ProducerPrivateWitness> = state
                .witnesses
                .iter()
                .map(|witness| ProducerPrivateWitness {
                    statement: witness.statement,
                    bytes: witness.bytes.clone(),
                })
                .collect();
            match witness {
                TransitionProofWitnessMutation::Keep => {}
                TransitionProofWitnessMutation::Put(witness) => {
                    if let Some(stored) = next_witnesses
                        .iter()
                        .find(|stored| stored.statement == witness.statement)
                    {
                        if stored.bytes != witness.bytes {
                            return Err(StoreError::Collision);
                        }
                    } else {
                        next_witnesses.push(ProducerPrivateWitness {
                            statement: witness.statement,
                            bytes: witness.bytes.clone(),
                        });
                    }
                }
                TransitionProofWitnessMutation::Remove { statement } => {
                    next_witnesses.retain(|witness| witness.statement != statement);
                }
            }
            state.image = Some(image.to_vec());
            state.artifacts = next_artifacts;
            state.witnesses = next_witnesses;
            if failure.is_some_and(|failure| failure.side == CommitSide::After) {
                state.fail_commit = None;
                return Err(StoreError::Injected);
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeValidator {
        route: AttestedTransitionRoute,
        auth_calls: usize,
        successor_calls: usize,
        terminal_auth: bool,
        terminal_successor: bool,
        wrong_deployment: bool,
        wrong_program: bool,
        wrong_package: bool,
        wrong_proof_ceiling: bool,
        accepted_invokes: Vec<(InvocationId, Hash)>,
    }

    impl FakeValidator {
        fn new(route: AttestedTransitionRoute) -> Self {
            Self {
                route,
                auth_calls: 0,
                successor_calls: 0,
                terminal_auth: false,
                terminal_successor: false,
                wrong_deployment: false,
                wrong_program: false,
                wrong_package: false,
                wrong_proof_ceiling: false,
                accepted_invokes: Vec::new(),
            }
        }
    }

    impl AttestedTransitionValidator for FakeValidator {
        type Error = AdapterError;

        fn authenticate_work(
            &mut self,
            route: &AttestedTransitionRoute,
            work: &RuntimeWork,
            canonical_work: &[u8],
        ) -> Result<AttestedTransitionAdmission, TransitionProofAdapterError<Self::Error>> {
            self.auth_calls += 1;
            assert_eq!(route, &self.route);
            assert_eq!(work.encode().unwrap(), canonical_work);
            if self.terminal_auth {
                return Err(TransitionProofAdapterError::Terminal(
                    AdapterError::Rejected,
                ));
            }
            let method = match work {
                RuntimeWork::Invoke { invocation, .. } => {
                    let commitment = TransitionProofStatement::work_commitment(canonical_work);
                    if let Some((_, accepted)) = self
                        .accepted_invokes
                        .iter()
                        .find(|(accepted, _)| *accepted == invocation.invocation)
                    {
                        if *accepted != commitment {
                            return Err(TransitionProofAdapterError::Terminal(
                                AdapterError::Rejected,
                            ));
                        }
                    } else {
                        self.accepted_invokes
                            .push((invocation.invocation, commitment));
                    }
                    method_name(work).ok_or(TransitionProofAdapterError::Terminal(
                        AdapterError::Rejected,
                    ))?
                }
                RuntimeWork::Resume { .. } => "increment".into(),
                RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => {
                    return Err(TransitionProofAdapterError::Terminal(
                        AdapterError::Rejected,
                    ));
                }
            };
            let (actor, deployment, program) = match work {
                RuntimeWork::Invoke { invocation, .. } => {
                    (invocation.actor, invocation.deployment, invocation.program)
                }
                RuntimeWork::Resume { resume, .. } => {
                    (resume.actor, resume.deployment, resume.program)
                }
                RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => unreachable!(),
            };
            let proof_systems =
                crate::agent::sdk::ProofSystemSet::from_sorted(&[route.proof_system]).unwrap();
            Ok(AttestedTransitionAdmission {
                space: route.space,
                agent: route.agent,
                runtime_deployment: if self.wrong_deployment {
                    DeploymentId([0xd1; 32])
                } else {
                    route.runtime_deployment
                },
                runtime_program: if self.wrong_program {
                    ProgramId([0xd2; 32])
                } else {
                    route.runtime_program
                },
                runtime_package: if self.wrong_package {
                    BlobRef::of_bytes(b"substituted-runtime-package")
                } else {
                    route.runtime_package.clone()
                },
                max_proof_material_bytes: if self.wrong_proof_ceiling {
                    route.max_proof_material_bytes - 1
                } else {
                    route.max_proof_material_bytes
                },
                runtime_contract: RuntimePackageContract::canonical(),
                runtime_capabilities: RuntimeCapabilities {
                    proof_systems,
                    ..RuntimeCapabilities::standard()
                },
                actor_entry: ActorEntry {
                    actor,
                    name: "actor".into(),
                    parent: None,
                    deployment,
                    program,
                    package: BlobRef::of_bytes(b"actor-package"),
                    agent_schema: BlobRef::of_bytes(b"actor-schema"),
                    method_policy: BlobRef::of_bytes(b"actor-method-policy"),
                    constructor_abi: Hash([0x61; 32]),
                    installation_data: None,
                    state_layout: Hash([0x62; 32]),
                    lanes: crate::agent::sdk::LaneSet::of(crate::agent::sdk::StateLane::Linear),
                    suspended: false,
                },
                actor_contract: ActorPackageContract::canonical(),
                actor_requirements: RuntimeRequirements {
                    lanes: crate::agent::sdk::LaneSet::of(crate::agent::sdk::StateLane::Linear),
                    scheduling: false,
                    proof_systems,
                },
                method,
            })
        }

        fn validate_successor(
            &mut self,
            authenticated: &AuthenticatedAttestedTransition,
            work: &RuntimeWork,
            transition: &RuntimeTransition,
        ) -> Result<(), TransitionProofAdapterError<Self::Error>> {
            self.successor_calls += 1;
            assert_eq!(authenticated.runtime_package(), &self.route.runtime_package);
            if self.terminal_successor {
                return Err(TransitionProofAdapterError::Terminal(
                    AdapterError::Rejected,
                ));
            }
            let before = match work {
                RuntimeWork::Invoke { state, .. } | RuntimeWork::Resume { state, .. } => state,
                RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => {
                    return Err(TransitionProofAdapterError::Terminal(
                        AdapterError::Rejected,
                    ));
                }
            };
            if transition.state.control != before.control
                || transition.state.merge != before.merge
                || transition.state.local != before.local
            {
                return Err(TransitionProofAdapterError::Terminal(
                    AdapterError::Rejected,
                ));
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeRoots {
        wrong_before: bool,
        invalid_before: bool,
        wrong_after: bool,
        terminal_after: bool,
    }

    impl Default for FakeRoots {
        fn default() -> Self {
            Self {
                wrong_before: false,
                invalid_before: false,
                wrong_after: false,
                terminal_after: false,
            }
        }
    }

    impl TransitionLaneRootResolver for FakeRoots {
        type Error = ();

        fn before_roots(
            &mut self,
            work: &RuntimeWork,
        ) -> Result<ProofLaneRoots, TransitionProofAdapterError<Self::Error>> {
            let state = match work {
                RuntimeWork::Invoke { state, .. } | RuntimeWork::Resume { state, .. } => state,
                RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => {
                    return Err(TransitionProofAdapterError::Terminal(()));
                }
            };
            let mut roots = state_roots(state);
            if self.wrong_before {
                roots.control = Hash([0x91; 32]);
            }
            if self.invalid_before {
                roots.control = Hash::ZERO;
            }
            Ok(roots)
        }

        fn after_roots(
            &mut self,
            _work: &RuntimeWork,
            transition: &RuntimeTransition,
        ) -> Result<ProofLaneRoots, TransitionProofAdapterError<Self::Error>> {
            if self.terminal_after {
                return Err(TransitionProofAdapterError::Terminal(()));
            }
            let mut roots = state_roots(&transition.state);
            if self.wrong_after {
                roots.merge = Some(Hash([0x92; 32]));
            }
            Ok(roots)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AdapterError {
        Lost,
        Rejected,
    }

    impl fmt::Display for AdapterError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{self:?}")
        }
    }

    impl std::error::Error for AdapterError {}

    struct FakeExecutor {
        calls: usize,
        fail_next: bool,
        fail_terminal: bool,
        proof_system: Hash,
        refine_trace: Hash,
        public_io: Hash,
        wrong_reply: bool,
        mutate_forbidden_lane: bool,
        witness: Vec<u8>,
        order: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeExecutor {
        fn new(route: AttestedTransitionRoute, order: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                calls: 0,
                fail_next: false,
                fail_terminal: false,
                proof_system: route.proof_system,
                refine_trace: Hash([0x51; 32]),
                public_io: Hash([0x52; 32]),
                wrong_reply: false,
                mutate_forbidden_lane: false,
                witness: PRIVATE_SENTINEL.to_vec(),
                order,
            }
        }
    }

    impl AttestedTentativeExecutor for FakeExecutor {
        type Error = AdapterError;

        fn execute_tentative(
            &mut self,
            authenticated: &AuthenticatedAttestedTransition,
            canonical_work: &[u8],
        ) -> Result<TentativeAttestedExecution, TransitionProofAdapterError<Self::Error>> {
            self.calls += 1;
            self.order.borrow_mut().push("execute");
            assert_eq!(authenticated.proof_system(), route().proof_system);
            assert_eq!(
                authenticated.runtime_deployment(),
                route().runtime_deployment
            );
            assert_eq!(authenticated.runtime_program(), route().runtime_program);
            assert_eq!(authenticated.runtime_package(), &route().runtime_package);
            let work = RuntimeWork::decode(canonical_work).unwrap();
            assert_eq!(
                authenticated.key(),
                transition_key(&work, canonical_work, authenticated.before).unwrap()
            );
            let (state, invocation, actor, incarnation, deployment, mode, gas_remaining) =
                match work {
                    RuntimeWork::Invoke {
                        state, invocation, ..
                    } => (
                        state,
                        invocation.invocation,
                        invocation.actor,
                        invocation.incarnation,
                        invocation.deployment,
                        invocation.mode,
                        invocation.gas - 1,
                    ),
                    RuntimeWork::Resume { state, resume, .. } => (
                        state,
                        resume.invocation,
                        resume.actor,
                        resume.incarnation,
                        resume.deployment,
                        resume.mode,
                        0,
                    ),
                    RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => unreachable!(),
                };
            if self.fail_terminal {
                return Err(TransitionProofAdapterError::Terminal(
                    AdapterError::Rejected,
                ));
            };
            let mut after = state;
            after.linear = b"proved-linear-successor".to_vec();
            if self.mutate_forbidden_lane {
                after.merge = b"hostile-merge-successor".to_vec();
            }
            let transition = RuntimeTransition {
                state: after,
                outcome: RuntimeOutcome::Completed(Ok(InvocationReply {
                    invocation: if self.wrong_reply {
                        InvocationId([0xee; 32])
                    } else {
                        invocation
                    },
                    actor,
                    incarnation,
                    deployment,
                    mode,
                    lane: mode.write_lane(),
                    status: InvocationStatus::Done,
                    reply: b"ok".to_vec(),
                    gas_remaining,
                    observation: Default::default(),
                })),
            };
            let result = TentativeAttestedExecution {
                transition,
                proof_system: self.proof_system,
                refine_trace: self.refine_trace,
                public_io: self.public_io,
                private_witness: self.witness.clone(),
            };
            if self.fail_next {
                self.fail_next = false;
                return Err(TransitionProofAdapterError::Retryable(AdapterError::Lost));
            }
            Ok(result)
        }
    }

    struct FakeProducer {
        key: [u8; PROOF_PUBLIC_KEY_BYTES],
        prove_calls: usize,
        sign_calls: usize,
        fail_prove: bool,
        fail_sign: bool,
        fail_prove_terminal: bool,
        fail_sign_terminal: bool,
        invalid_proof: bool,
        invalid_signature: bool,
        proof_material_bytes: Option<usize>,
        lost_proof: Option<(Hash, Vec<u8>)>,
        lost_signature: Option<(Hash, [u8; PROOF_SIGNATURE_BYTES])>,
        order: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeProducer {
        fn new(key: [u8; 32], order: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                key,
                prove_calls: 0,
                sign_calls: 0,
                fail_prove: false,
                fail_sign: false,
                fail_prove_terminal: false,
                fail_sign_terminal: false,
                invalid_proof: false,
                invalid_signature: false,
                proof_material_bytes: None,
                lost_proof: None,
                lost_signature: None,
                order,
            }
        }
    }

    impl AgentTransitionProofProducer for FakeProducer {
        type Error = AdapterError;

        fn public_key(&self) -> [u8; PROOF_PUBLIC_KEY_BYTES] {
            self.key
        }

        fn prove_nested_refine(
            &mut self,
            authenticated: &AuthenticatedAttestedTransition,
            statement: &TransitionProofStatement,
            witness: &ProducerPrivateWitness,
        ) -> Result<Vec<u8>, TransitionProofAdapterError<Self::Error>> {
            self.prove_calls += 1;
            self.order.borrow_mut().push("prove");
            assert_eq!(authenticated.key(), statement.key());
            assert_eq!(
                authenticated.runtime_package(),
                &statement.subject.runtime_package
            );
            assert_eq!(statement.commitment().unwrap(), witness.statement);
            assert_eq!(witness.bytes, PRIVATE_SENTINEL);
            let mut output = if self.invalid_proof {
                b"hostile-proof".to_vec()
            } else {
                proof_for(statement)
            };
            if let Some(len) = self.proof_material_bytes {
                assert!(len >= output.len());
                output.resize(len, 0xa7);
            }
            let statement_id = statement.commitment().unwrap();
            if let Some((lost_statement, lost_output)) = self.lost_proof.take() {
                assert_eq!(lost_statement, statement_id);
                assert_eq!(lost_output, output);
            }
            if self.fail_prove_terminal {
                self.fail_prove_terminal = false;
                return Err(TransitionProofAdapterError::Terminal(
                    AdapterError::Rejected,
                ));
            }
            if self.fail_prove {
                self.fail_prove = false;
                self.lost_proof = Some((statement_id, output));
                return Err(TransitionProofAdapterError::Retryable(AdapterError::Lost));
            }
            Ok(output)
        }

        fn sign_transition_record(
            &mut self,
            authenticated: &AuthenticatedAttestedTransition,
            message: &[u8],
        ) -> Result<[u8; PROOF_SIGNATURE_BYTES], TransitionProofAdapterError<Self::Error>> {
            self.sign_calls += 1;
            self.order.borrow_mut().push("sign");
            assert_ne!(authenticated.runtime_package().hash, Hash::ZERO);
            let mut signature = signature_for(&self.key, message);
            if self.invalid_signature {
                signature[0] ^= 1;
            }
            let message_id = Hash::digest(b"vos/test/lost-proof-signature", &[message]);
            if let Some((lost_message, lost_signature)) = self.lost_signature.take() {
                assert_eq!(lost_message, message_id);
                assert_eq!(lost_signature, signature);
            }
            if self.fail_sign_terminal {
                self.fail_sign_terminal = false;
                return Err(TransitionProofAdapterError::Terminal(
                    AdapterError::Rejected,
                ));
            }
            if self.fail_sign {
                self.fail_sign = false;
                self.lost_signature = Some((message_id, signature));
                return Err(TransitionProofAdapterError::Retryable(AdapterError::Lost));
            }
            Ok(signature)
        }
    }

    struct FakeVerifier;

    impl TransitionProofVerifier for FakeVerifier {
        fn verify_producer(
            &self,
            public_key: &[u8; PROOF_PUBLIC_KEY_BYTES],
            message: &[u8],
            signature: &[u8; PROOF_SIGNATURE_BYTES],
        ) -> bool {
            *signature == signature_for(public_key, message)
        }

        fn verify_transition(
            &self,
            statement: &TransitionProofStatement,
            proof_bytes: &[u8],
        ) -> bool {
            let expected = proof_for(statement);
            proof_bytes.starts_with(&expected)
                && proof_bytes[expected.len()..]
                    .iter()
                    .all(|byte| *byte == 0xa7)
        }
    }

    #[derive(Default)]
    struct PublisherState {
        published: Vec<PublishedAttestedTransition>,
        retired: Option<AuthenticatedTransitionRetirement>,
        calls: usize,
        fail_after_commit: bool,
        wrong_fact: bool,
    }

    #[derive(Clone)]
    struct FakePublisher {
        state: Rc<RefCell<PublisherState>>,
        order: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakePublisher {
        fn new(order: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                state: Rc::new(RefCell::new(PublisherState::default())),
                order,
            }
        }

        fn effective_publications(&self) -> usize {
            self.state.borrow().published.len()
        }
    }

    impl VerifiedTransitionPublisher for FakePublisher {
        type Error = AdapterError;

        fn load_published(
            &mut self,
            key: TransitionProofKey,
        ) -> Result<Option<PublishedAttestedTransition>, Self::Error> {
            self.state
                .borrow()
                .published
                .iter()
                .find(|published| published.proof_record.statement.key() == key)
                .map(|published| {
                    PublishedAttestedTransition::reconstruct(
                        published.canonical_work.clone(),
                        published.canonical_transition.clone(),
                        published.proof_record.clone(),
                        published.proof_manifest_bytes.clone(),
                        published.publication.publication(),
                    )
                    .map_err(|_| AdapterError::Rejected)
                })
                .transpose()
        }

        fn load_retired(
            &mut self,
            key: TransitionProofKey,
        ) -> Result<Option<AuthenticatedTransitionRetirement>, Self::Error> {
            Ok(self
                .state
                .borrow()
                .retired
                .filter(|retired| retired.key().invocation == key.invocation))
        }
    }

    impl ImmediateVerifiedTransitionPublisher for FakePublisher {
        fn publish_verified(
            &mut self,
            publication: VerifiedTransitionPublication<'_>,
        ) -> Result<TransitionPublicationFact, Self::Error> {
            self.order.borrow_mut().push("publish");
            assert!(
                publication
                    .proof_record()
                    .verify(
                        publication.proof_manifest_bytes(),
                        publication.proof_material(),
                        &FakeVerifier,
                    )
                    .is_ok()
            );
            assert_eq!(
                TransitionProofStatement::work_commitment(publication.canonical_work()),
                publication.proof_record().statement.work
            );
            assert_eq!(
                TransitionProofStatement::transition_commitment(publication.canonical_transition()),
                publication.proof_record().statement.transition
            );
            let expected = publication.expected_fact();
            let key = publication.proof_record().statement.key();
            let retained = PublishedAttestedTransition::reconstruct(
                publication.canonical_work().to_vec(),
                publication.canonical_transition().to_vec(),
                publication.proof_record().clone(),
                publication.proof_manifest_bytes().to_vec(),
                expected.publication(),
            )
            .unwrap();
            let mut state = self.state.borrow_mut();
            state.calls += 1;
            if let Some(stored) = state
                .published
                .iter()
                .find(|stored| stored.proof_record.statement.key() == key)
            {
                if *stored != retained {
                    return Err(AdapterError::Lost);
                }
            } else {
                state.published.push(retained);
            }
            if state.fail_after_commit {
                state.fail_after_commit = false;
                return Err(AdapterError::Lost);
            }
            if state.wrong_fact {
                let mut wrong = expected;
                wrong.publication = Hash([0xfd; 32]);
                return Ok(wrong);
            }
            Ok(expected)
        }
    }

    fn route() -> AttestedTransitionRoute {
        let key = [0x41; 32];
        AttestedTransitionRoute {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            runtime_program: ProgramId([4; 32]),
            runtime_package: BlobRef::of_bytes(b"signed-runtime-package"),
            proof_system: Hash([5; 32]),
            max_proof_material_bytes: crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES,
            producer: ProducerId::of_public_key(&key),
        }
    }

    fn invocation_id(value: u64) -> InvocationId {
        if let Ok(byte) = u8::try_from(value) {
            return InvocationId([byte; 32]);
        }
        let mut bytes = [0xa5; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        InvocationId(bytes)
    }

    fn work(invocation: u64) -> RuntimeWork {
        let route = route();
        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("increment").encode());
        let invocation = InvocationWork {
            space: route.space,
            agent: route.agent,
            runtime_deployment: route.runtime_deployment,
            invocation: invocation_id(invocation),
            actor: ActorId([7; 32]),
            incarnation: Hash([8; 32]),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            message,
            installation_data: None,
            availability: Vec::new(),
            gas: 1_000,
            recovery_only: false,
        };
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 11));
        RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Attested {
                proof_system: route.proof_system,
            },
            state: RuntimeState {
                control: b"control".to_vec(),
                linear: b"linear".to_vec(),
                merge: b"merge".to_vec(),
                local: b"local".to_vec(),
            },
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot: 11,
        }
    }

    fn resume_work(invocation: u64, ready_sequence: u64) -> RuntimeWork {
        let route = route();
        RuntimeWork::Resume {
            context: RuntimeExecutionContext::Attested {
                proof_system: route.proof_system,
            },
            state: RuntimeState {
                control: b"control".to_vec(),
                linear: b"linear".to_vec(),
                merge: b"merge".to_vec(),
                local: b"local".to_vec(),
            },
            resume: Box::new(ResumeWork {
                invocation: invocation_id(invocation),
                actor: ActorId([7; 32]),
                incarnation: Hash([8; 32]),
                deployment: DeploymentId([9; 32]),
                program: ProgramId([10; 32]),
                mode: MethodMode::Linear,
                continuation: BlobRef::of_bytes(b"retained-continuation"),
                ready_sequence,
                installation_data: None,
                availability: Vec::new(),
                input: Some(ResumeInput::Ready(vec![ready_sequence as u8])),
            }),
        }
    }

    fn state_roots(state: &RuntimeState) -> ProofLaneRoots {
        fn root(tag: &[u8], bytes: &[u8]) -> Hash {
            Hash::digest(b"vos/test/agent-proof-root", &[tag, bytes])
        }
        ProofLaneRoots {
            control: root(b"control", &state.control),
            linear: Some(root(b"linear", &state.linear)),
            merge: Some(root(b"merge", &state.merge)),
            local: Some(root(b"local", &state.local)),
        }
    }

    fn proof_for(statement: &TransitionProofStatement) -> Vec<u8> {
        let mut proof = b"PVM-REFINE-PROOF-V3\0".to_vec();
        proof.extend_from_slice(&statement.encode().unwrap());
        proof
    }

    fn signature_for(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(b"vos/test/proof-signature/first", &[public_key, message]);
        let second = Hash::digest(b"vos/test/proof-signature/second", &[public_key, message]);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn components(
        order: Rc<RefCell<Vec<&'static str>>>,
    ) -> (
        FakeValidator,
        FakeExecutor,
        FakeRoots,
        FakeProducer,
        FakePublisher,
    ) {
        components_for(route(), order)
    }

    fn components_for(
        route: AttestedTransitionRoute,
        order: Rc<RefCell<Vec<&'static str>>>,
    ) -> (
        FakeValidator,
        FakeExecutor,
        FakeRoots,
        FakeProducer,
        FakePublisher,
    ) {
        (
            FakeValidator::new(route.clone()),
            FakeExecutor::new(route, order.clone()),
            FakeRoots::default(),
            FakeProducer::new([0x41; 32], order.clone()),
            FakePublisher::new(order),
        )
    }

    #[test]
    fn exact_retry_and_restart_reuse_public_proof_without_witness_or_resigning() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order.clone());
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
        let first = host
            .execute_prove_publish(
                work(12),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        assert_eq!(
            executor.calls, 1,
            "a durable prepared phase is not replayed"
        );
        assert_eq!(producer.prove_calls, 1);
        assert_eq!(producer.sign_calls, 1);
        assert_eq!(publisher.effective_publications(), 1);
        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
        assert!(!store.contains_public_sentinel());
        assert_eq!(
            order.borrow().as_slice(),
            ["execute", "prove", "sign", "publish"]
        );

        let before_counts = (
            executor.calls,
            producer.prove_calls,
            producer.sign_calls,
            publisher.state.borrow().calls,
        );
        let exact = host
            .execute_prove_publish(
                work(12),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        assert_eq!(exact, first);
        assert_eq!(
            (
                executor.calls,
                producer.prove_calls,
                producer.sign_calls,
                publisher.state.borrow().calls,
            ),
            before_counts
        );

        let store = host.into_store();
        let mut reopened = DurableTransitionProofHost::open(store, route(), &FakeVerifier).unwrap();
        let after_restart = reopened
            .execute_prove_publish(
                work(12),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        assert_eq!(after_restart, first);
        assert_eq!(
            after_restart.publication.publication(),
            first.publication.publication()
        );

        let RuntimeWork::Invoke { invocation, .. } = work(12) else {
            unreachable!()
        };
        let subject = subject_for(&route(), &work(12), "increment".into()).unwrap();
        assert!(
            first
                .proof_record
                .verify_exact(
                    &first.proof_manifest_bytes,
                    &proof_for(&first.proof_record.statement),
                    &subject,
                    state_roots(match &work(12) {
                        RuntimeWork::Invoke { state, .. } => state,
                        _ => unreachable!(),
                    }),
                    first.proof_record.statement.after,
                    &first.canonical_work,
                    &first.canonical_transition,
                    first.proof_record.statement.refine_trace,
                    first.proof_record.statement.public_io,
                    route().proof_system,
                    route().producer,
                    &FakeVerifier,
                )
                .is_ok()
        );
        assert_eq!(first.proof_record.statement.subject.actor, invocation.actor);
    }

    #[test]
    fn proof_material_is_manifest_rooted_chunked_and_fails_closed_on_cas_corruption() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let chunk_bytes = usize::try_from(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES).unwrap();
        producer.proof_material_bytes = Some(chunk_bytes + 1);
        publisher.state.borrow_mut().fail_after_commit = true;
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
        assert!(matches!(
            host.execute_prove_publish(
                work(64),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Publication(AdapterError::Lost))
        ));

        let image_bytes = store.image().unwrap();
        let image = TransitionProofHostImage::decode(&image_bytes).unwrap();
        let retained = image.records.first().unwrap();
        let proof_ref = retained.proof.as_ref().unwrap();
        let (manifest_bytes, artifact_snapshot) = {
            let state = store.0.borrow();
            let manifest_bytes = state
                .artifacts
                .iter()
                .find(|(reference, _)| reference == proof_ref)
                .map(|(_, bytes)| bytes.clone())
                .unwrap();
            (manifest_bytes, state.artifacts.clone())
        };
        assert!(manifest_bytes.starts_with(b"APM1"));
        let manifest = TransitionProofMaterialManifest::decode(&manifest_bytes).unwrap();
        assert_eq!(manifest.material.len, (chunk_bytes + 1) as u64);
        assert_eq!(manifest.chunks.len(), 2);
        let material_chunks: Vec<Vec<u8>> = manifest
            .chunks
            .iter()
            .map(|reference| {
                artifact_snapshot
                    .iter()
                    .find(|(stored, _)| stored == reference)
                    .map(|(_, bytes)| bytes.clone())
                    .unwrap()
            })
            .collect();
        let material = manifest
            .assemble_bounded(
                material_chunks.iter().map(Vec::as_slice),
                route().max_proof_material_bytes,
            )
            .unwrap();
        let record =
            canonical_decode::<TransitionProofRecord>(retained.record.as_deref().unwrap()).unwrap();
        assert_eq!(record.proof, *proof_ref);
        assert!(
            record
                .verify(&manifest_bytes, &material, &FakeVerifier)
                .is_ok()
        );
        assert!(DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier,).is_ok());

        let snapshot = || {
            MemoryStore(Rc::new(RefCell::new(MemoryStoreState {
                image: Some(image_bytes.clone()),
                artifacts: artifact_snapshot.clone(),
                ..MemoryStoreState::default()
            })))
        };

        let missing = snapshot();
        missing
            .0
            .borrow_mut()
            .artifacts
            .retain(|(reference, _)| reference != &manifest.chunks[0]);
        assert!(matches!(
            DurableTransitionProofHost::open(missing, route(), &FakeVerifier),
            Err(TransitionProofHostOpenError::InvalidState)
        ));

        let substituted = snapshot();
        substituted
            .0
            .borrow_mut()
            .artifacts
            .iter_mut()
            .find(|(reference, _)| reference == &manifest.chunks[0])
            .unwrap()
            .1[0] ^= 1;
        assert!(matches!(
            DurableTransitionProofHost::open(substituted, route(), &FakeVerifier),
            Err(TransitionProofHostOpenError::InvalidState)
        ));

        let narrowed = snapshot();
        let mut narrowed_image = image.clone();
        narrowed_image.route.max_proof_material_bytes = 1;
        narrowed.0.borrow_mut().image = Some(narrowed_image.encode());
        let mut narrowed_route = route();
        narrowed_route.max_proof_material_bytes = 1;
        assert!(matches!(
            DurableTransitionProofHost::open(
                narrowed.clone(),
                narrowed_route.clone(),
                &FakeVerifier,
            ),
            Err(TransitionProofHostOpenError::InvalidState)
        ));
        let narrowed_state = narrowed.0.borrow();
        let narrowed_loads = &narrowed_state.artifact_loads;
        assert!(narrowed_loads.contains(proof_ref));
        assert!(
            manifest
                .chunks
                .iter()
                .all(|reference| !narrowed_loads.contains(reference))
        );

        let narrowed_retry = snapshot();
        {
            let mut state = narrowed_retry.0.borrow_mut();
            state.image = None;
            state.artifact_loads.clear();
        }
        let retry_order = Rc::new(RefCell::new(Vec::new()));
        let (mut retry_validator, mut retry_executor, mut retry_roots, mut retry_producer, _) =
            components_for(narrowed_route.clone(), retry_order);
        let mut retry_host =
            DurableTransitionProofHost::open(narrowed_retry.clone(), narrowed_route, &FakeVerifier)
                .unwrap();
        assert!(matches!(
            retry_host.execute_prove_publish(
                work(64),
                &mut retry_validator,
                &mut retry_executor,
                &mut retry_roots,
                &mut retry_producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::InvalidState)
        ));
        assert!(retry_host.is_poisoned());
        assert_eq!(retry_executor.calls, 0);
        let retry_state = narrowed_retry.0.borrow();
        let retry_loads = &retry_state.artifact_loads;
        assert!(
            manifest
                .chunks
                .iter()
                .all(|reference| !retry_loads.contains(reference))
        );

        let reordered = snapshot();
        let mut reordered_manifest = manifest;
        reordered_manifest.chunks.swap(0, 1);
        let mut reordered_manifest_bytes = b"APM1".to_vec();
        let mut encoder = Encoder(&mut reordered_manifest_bytes);
        encode_blob(&mut encoder, &reordered_manifest.material);
        encoder.list(&reordered_manifest.chunks, encode_blob);
        let reordered_ref = BlobRef::of_bytes(&reordered_manifest_bytes);
        let mut reordered_image = image;
        reordered_image.records[0].proof = Some(reordered_ref.clone());
        {
            let mut state = reordered.0.borrow_mut();
            state.image = Some(reordered_image.encode());
            state
                .artifacts
                .push((reordered_ref, reordered_manifest_bytes));
        }
        assert!(matches!(
            DurableTransitionProofHost::open(reordered, route(), &FakeVerifier),
            Err(TransitionProofHostOpenError::InvalidState)
        ));
    }

    #[test]
    fn authenticated_runtime_proof_ceiling_rejects_before_manifest_publication() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let mut bounded_route = route();
        bounded_route.max_proof_material_bytes = 1;
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components_for(bounded_route.clone(), order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), bounded_route, &FakeVerifier).unwrap();
        assert!(matches!(
            host.execute_prove_publish(
                work(65),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::InvalidProof
            ))
        ));
        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
        assert_eq!(publisher.effective_publications(), 0);
        assert!(
            !store
                .0
                .borrow()
                .artifacts
                .iter()
                .any(|(_, bytes)| bytes.starts_with(b"APM1"))
        );
    }

    #[test]
    fn every_atomic_commit_failure_poisons_and_reopens_to_one_verified_publication() {
        for number in 1..=5 {
            for side in [CommitSide::Before, CommitSide::After] {
                let store = MemoryStore::default();
                store.fail_commit(number, side);
                let order = Rc::new(RefCell::new(Vec::new()));
                let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                    components(order.clone());
                let mut host =
                    DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier)
                        .unwrap();
                let error = host
                    .execute_prove_publish(
                        work(13),
                        &mut validator,
                        &mut executor,
                        &mut roots,
                        &mut producer,
                        &FakeVerifier,
                        &mut publisher,
                    )
                    .unwrap_err();
                assert!(matches!(error, TransitionProofHostError::Storage(_)));
                assert!(host.is_poisoned());
                assert!(!store.contains_public_sentinel());
                assert!(matches!(
                    host.execute_prove_publish(
                        work(13),
                        &mut validator,
                        &mut executor,
                        &mut roots,
                        &mut producer,
                        &FakeVerifier,
                        &mut publisher,
                    ),
                    Err(TransitionProofHostError::Rejected(
                        TransitionProofHostRejection::Poisoned
                    ))
                ));

                let mut reopened =
                    DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier)
                        .unwrap();
                let completed = reopened
                    .execute_prove_publish(
                        work(13),
                        &mut validator,
                        &mut executor,
                        &mut roots,
                        &mut producer,
                        &FakeVerifier,
                        &mut publisher,
                    )
                    .unwrap();
                assert!(
                    completed
                        .proof_record
                        .verify(
                            &completed.proof_manifest_bytes,
                            &proof_for(&completed.proof_record.statement),
                            &FakeVerifier,
                        )
                        .is_ok()
                );
                assert_eq!(publisher.effective_publications(), 1);
                let publish_at = order
                    .borrow()
                    .iter()
                    .position(|event| *event == "publish")
                    .unwrap();
                let sign_at = order
                    .borrow()
                    .iter()
                    .position(|event| *event == "sign")
                    .unwrap();
                assert!(sign_at < publish_at);
                assert!(!store.contains_public_sentinel());
                assert_eq!(store.witness_count(), 0);
            }
        }
    }

    #[test]
    fn result_loss_at_execution_proving_signing_and_publication_resumes_exactly() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();

        executor.fail_next = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(14),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Lost))
        ));
        assert_eq!(publisher.effective_publications(), 0);

        producer.fail_prove = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(14),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Producer(AdapterError::Lost))
        ));
        assert_eq!(publisher.effective_publications(), 0);

        producer.fail_sign = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(14),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Producer(AdapterError::Lost))
        ));
        assert_eq!(publisher.effective_publications(), 0);
        assert_eq!(
            producer.prove_calls, 2,
            "durable proof is reused before signing"
        );

        publisher.state.borrow_mut().fail_after_commit = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(14),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Publication(AdapterError::Lost))
        ));
        assert_eq!(publisher.effective_publications(), 1);
        let signed = producer.sign_calls;
        let proved = producer.prove_calls;

        let store = host.into_store();
        let mut reopened = DurableTransitionProofHost::open(store, route(), &FakeVerifier).unwrap();
        let completed = reopened
            .execute_prove_publish(
                work(14),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        assert!(
            completed
                .proof_record
                .verify(
                    &completed.proof_manifest_bytes,
                    &proof_for(&completed.proof_record.statement),
                    &FakeVerifier,
                )
                .is_ok()
        );
        assert_eq!(producer.prove_calls, proved);
        assert_eq!(producer.sign_calls, signed);
        assert_eq!(publisher.effective_publications(), 1);
    }

    #[test]
    fn route_work_transition_trace_root_proof_signature_and_publication_substitutions_fail_closed()
    {
        let verifier = FakeVerifier;

        for mutate in 0..6 {
            let store = MemoryStore::default();
            let order = Rc::new(RefCell::new(Vec::new()));
            let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                components(order);
            let mut host = DurableTransitionProofHost::open(store, route(), &verifier).unwrap();
            let mut hostile = work(15);
            let RuntimeWork::Invoke {
                context,
                invocation,
                ..
            } = &mut hostile
            else {
                unreachable!()
            };
            match mutate {
                0 => invocation.space = SpaceId([0xa1; 32]),
                1 => invocation.agent = AgentId([0xa2; 32]),
                2 => invocation.runtime_deployment = DeploymentId([0xa3; 32]),
                3 => invocation.recovery_only = true,
                4 => *context = RuntimeExecutionContext::Direct,
                5 => {
                    *context = RuntimeExecutionContext::Attested {
                        proof_system: Hash([0xa4; 32]),
                    }
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                host.execute_prove_publish(
                    hostile,
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &verifier,
                    &mut publisher,
                ),
                Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::InvalidWork
                ))
            ));
            assert_eq!(executor.calls, 0);
            assert_eq!(publisher.effective_publications(), 0);
        }

        let hostile_cases = 8;
        for case in 0..hostile_cases {
            let store = MemoryStore::default();
            let order = Rc::new(RefCell::new(Vec::new()));
            let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                components(order);
            match case {
                0 => executor.proof_system = Hash([0xb1; 32]),
                1 => executor.refine_trace = Hash::ZERO,
                2 => executor.wrong_reply = true,
                3 => roots.wrong_after = true,
                4 => producer.invalid_proof = true,
                5 => producer.invalid_signature = true,
                6 => publisher.state.borrow_mut().wrong_fact = true,
                7 => producer.key = [0xb2; 32],
                _ => unreachable!(),
            }
            let mut host =
                DurableTransitionProofHost::open(store.clone(), route(), &verifier).unwrap();
            assert!(
                host.execute_prove_publish(
                    work(16 + case as u64),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &verifier,
                    &mut publisher,
                )
                .is_err()
            );
            assert_eq!(publisher.effective_publications(), usize::from(case == 6));
            if case == 6 {
                // The hostile adapter durably published the exact verified
                // capability but lied in its echo; no unproved transition
                // crossed the seam, and completion was not recorded.
                assert_eq!(store.witness_count(), 0);
            }
        }
    }

    #[test]
    fn thin_confirmation_reloads_the_durable_host_tuple_after_publication() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
        let VerifiedTransitionPreparation::Prepared(prepared) = host
            .execute_prove_prepare(
                work(13),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap()
        else {
            panic!("fresh work must produce one durable preparation")
        };
        let confirmation = prepared.confirmation();
        assert!(
            core::mem::size_of::<TransitionProofConfirmationToken>() < 512,
            "confirmation remains fixed-size rather than retaining proof material"
        );
        publisher
            .publish_verified(prepared.as_publication())
            .unwrap();
        drop(prepared);

        host.confirm_published(confirmation, &mut publisher)
            .unwrap();
        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
        assert!(!host.is_poisoned());
    }

    #[test]
    fn authoritative_retry_tuple_is_fully_reverified_before_reuse() {
        for case in 0..6 {
            let store = MemoryStore::default();
            let order = Rc::new(RefCell::new(Vec::new()));
            let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                components(order);
            let mut host = DurableTransitionProofHost::open(store, route(), &FakeVerifier).unwrap();
            host.execute_prove_publish(
                work(29),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
            let before = (executor.calls, producer.prove_calls, producer.sign_calls);
            {
                let mut state = publisher.state.borrow_mut();
                let published = state.published.first_mut().unwrap();
                match case {
                    0 => published.canonical_work.push(0),
                    1 => published.canonical_transition.push(0),
                    2 => published.proof_manifest_bytes[0] ^= 1,
                    3 => published.proof_record.producer_signature[0] ^= 1,
                    4 => published.publication.publication = Hash([0xe4; 32]),
                    5 => published.proof_record.statement.subject.actor = ActorId([0xe5; 32]),
                    _ => unreachable!(),
                }
            }
            assert!(
                host.execute_prove_publish(
                    work(29),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                )
                .is_err()
            );
            assert_eq!(
                (executor.calls, producer.prove_calls, producer.sign_calls),
                before,
                "a hostile journal retry must fail before execution or proof production"
            );
        }
    }

    #[test]
    fn divergent_retry_noncanonical_method_corruption_and_storage_error_fail_closed() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        executor.fail_next = true;
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
        assert!(
            host.execute_prove_publish(
                work(30),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .is_err()
        );
        let mut divergent = work(30);
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = &mut divergent
        else {
            unreachable!()
        };
        invocation.actor = ActorId([0xc1; 32]);
        *authorization = Box::new(InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(invocation, 11),
        ));
        assert!(matches!(
            host.execute_prove_publish(
                divergent,
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Validation(AdapterError::Rejected))
        ));

        let mut invalid_method = work(31);
        let RuntimeWork::Invoke { invocation, .. } = &mut invalid_method else {
            unreachable!()
        };
        invocation.message = vec![TAG_DYNAMIC, 0xff];
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = &mut invalid_method
        else {
            unreachable!()
        };
        *authorization = Box::new(InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(invocation, 11),
        ));
        assert!(matches!(
            host.execute_prove_publish(
                invalid_method,
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::WrongMethod
            ))
        ));
        assert_eq!(publisher.effective_publications(), 0);

        let corrupt_store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut complete =
            DurableTransitionProofHost::open(corrupt_store.clone(), route(), &FakeVerifier)
                .unwrap();
        complete
            .execute_prove_publish(
                work(32),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        let mut image = corrupt_store.image().unwrap();
        image[0] = b'X';
        corrupt_store.0.borrow_mut().image = Some(image);
        assert!(matches!(
            DurableTransitionProofHost::open(corrupt_store, route(), &FakeVerifier),
            Err(TransitionProofHostOpenError::InvalidState)
        ));

        let poison_store = MemoryStore::default();
        let mut poison =
            DurableTransitionProofHost::open(poison_store.clone(), route(), &FakeVerifier).unwrap();
        poison_store.fail_artifact_load_once();
        assert!(matches!(
            poison.execute_prove_publish(
                work(33),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Storage(StoreError::Injected))
        ));
        assert!(poison.is_poisoned());

        let witness_store = MemoryStore::default();
        witness_store.fail_commit(3, CommitSide::Before);
        let mut witness_host =
            DurableTransitionProofHost::open(witness_store.clone(), route(), &FakeVerifier)
                .unwrap();
        assert!(matches!(
            witness_host.execute_prove_publish(
                work(34),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Storage(StoreError::Injected))
        ));
        let mut witness_host =
            DurableTransitionProofHost::open(witness_store.clone(), route(), &FakeVerifier)
                .unwrap();
        witness_store.fail_witness_load_once();
        assert!(matches!(
            witness_host.execute_prove_publish(
                work(34),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Storage(StoreError::Injected))
        ));
        assert!(witness_host.is_poisoned());
    }

    #[test]
    fn durable_execute_prove_and_sign_phases_are_not_repeated_after_restart() {
        for commit_after_phase in 2..=5 {
            let store = MemoryStore::default();
            store.fail_commit(commit_after_phase, CommitSide::After);
            let order = Rc::new(RefCell::new(Vec::new()));
            let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                components(order);
            let mut host =
                DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
            assert!(matches!(
                host.execute_prove_publish(
                    work(40 + commit_after_phase as u64),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                ),
                Err(TransitionProofHostError::Storage(StoreError::Injected))
            ));
            assert!(host.is_poisoned());

            let durable_counts = (executor.calls, producer.prove_calls, producer.sign_calls);
            let mut reopened =
                DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
            reopened
                .execute_prove_publish(
                    work(40 + commit_after_phase as u64),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                )
                .unwrap();

            assert_eq!(executor.calls, 1, "durable execution phase was repeated");
            assert_eq!(producer.prove_calls, 1, "durable proof phase was repeated");
            assert_eq!(producer.sign_calls, 1, "durable signing phase was repeated");
            match commit_after_phase {
                2 => assert_eq!(durable_counts, (1, 0, 0)),
                3 => assert_eq!(durable_counts, (1, 1, 0)),
                4 | 5 => assert_eq!(durable_counts, (1, 1, 1)),
                _ => unreachable!(),
            }
            assert_eq!(publisher.effective_publications(), 1);
            assert_eq!(reopened.retained_transitions(), 0);
            assert_eq!(store.witness_count(), 0);
        }
    }

    #[test]
    fn terminal_prepublication_failures_reclaim_capacity_and_private_witnesses() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();

        validator.terminal_auth = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(50),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Validation(AdapterError::Rejected))
        ));
        validator.terminal_auth = false;

        executor.fail_terminal = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(51),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Rejected))
        ));
        executor.fail_terminal = false;

        executor.mutate_forbidden_lane = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(52),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Validation(AdapterError::Rejected))
        ));
        executor.mutate_forbidden_lane = false;

        roots.terminal_after = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(53),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Roots(()))
        ));
        roots.terminal_after = false;

        producer.fail_prove_terminal = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(54),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Producer(AdapterError::Rejected))
        ));

        producer.fail_sign_terminal = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(55),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Producer(AdapterError::Rejected))
        ));

        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
        assert!(!store.contains_public_sentinel());
        assert_eq!(publisher.effective_publications(), 0);

        executor.fail_terminal = true;
        for invocation in 64..=64 + MAX_IN_FLIGHT_TRANSITION_PROOFS as u64 {
            assert!(matches!(
                host.execute_prove_publish(
                    work(invocation),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                ),
                Err(TransitionProofHostError::Execution(AdapterError::Rejected))
            ));
            assert_eq!(host.retained_transitions(), 0);
        }
        assert_eq!(store.witness_count(), 0);
        assert_eq!(publisher.effective_publications(), 0);
    }

    #[test]
    fn terminal_authentication_retry_reclaims_the_exact_retained_workflow() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
        let exact_work = work(63);

        executor.fail_next = true;
        assert!(matches!(
            host.execute_prove_publish(
                exact_work.clone(),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Lost))
        ));
        assert_eq!(host.retained_transitions(), 1);

        validator.terminal_auth = true;
        assert!(matches!(
            host.execute_prove_publish(
                exact_work,
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Validation(AdapterError::Rejected))
        ));
        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
        assert_eq!(publisher.effective_publications(), 0);

        validator.terminal_auth = false;
        let invalid_roots_work = work(64);
        executor.fail_next = true;
        assert!(matches!(
            host.execute_prove_publish(
                invalid_roots_work.clone(),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Lost))
        ));
        roots.invalid_before = true;
        assert!(matches!(
            host.execute_prove_publish(
                invalid_roots_work,
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::InvalidRoots
            ))
        ));
        roots.invalid_before = false;
        assert_eq!(host.retained_transitions(), 0);

        let invalid_admission_work = work(65);
        executor.fail_next = true;
        assert!(matches!(
            host.execute_prove_publish(
                invalid_admission_work.clone(),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Lost))
        ));
        validator.wrong_deployment = true;
        assert!(matches!(
            host.execute_prove_publish(
                invalid_admission_work,
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::InvalidWork
            ))
        ));
        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
    }

    #[test]
    fn ambiguous_terminal_cleanup_commit_poisons_but_does_not_leak_capacity() {
        for side in [CommitSide::Before, CommitSide::After] {
            let store = MemoryStore::default();
            store.fail_commit(2, side);
            let order = Rc::new(RefCell::new(Vec::new()));
            let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                components(order);
            executor.fail_terminal = true;
            let mut host =
                DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
            assert!(matches!(
                host.execute_prove_publish(
                    work(61),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                ),
                Err(TransitionProofHostError::Storage(StoreError::Injected))
            ));
            assert!(host.is_poisoned());

            let mut reopened =
                DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
            assert!(matches!(
                reopened.execute_prove_publish(
                    work(61),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                ),
                Err(TransitionProofHostError::Execution(AdapterError::Rejected))
            ));
            assert_eq!(reopened.retained_transitions(), 0);
            assert_eq!(store.witness_count(), 0);
            assert_eq!(publisher.effective_publications(), 0);
        }
    }

    #[test]
    fn invoke_and_resume_slices_with_one_invocation_have_distinct_exact_keys() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();

        executor.fail_next = true;
        assert!(
            host.execute_prove_publish(
                work(62),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .is_err()
        );
        executor.fail_next = true;
        assert!(
            host.execute_prove_publish(
                resume_work(62, 1),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .is_err()
        );
        assert_eq!(host.retained_transitions(), 2);
        assert_eq!(host.image.records[0].key.invocation, InvocationId([62; 32]));
        assert_eq!(host.image.records[1].key.invocation, InvocationId([62; 32]));
        assert_ne!(host.image.records[0].key, host.image.records[1].key);

        let invoked = host
            .execute_prove_publish(
                work(62),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        let resumed = host
            .execute_prove_publish(
                resume_work(62, 1),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        assert_ne!(
            invoked.proof_record.statement.key(),
            resumed.proof_record.statement.key()
        );
        assert_eq!(invoked.proof_record.statement.subject.method, "increment");
        assert_eq!(resumed.proof_record.statement.subject.method, "increment");
        assert_eq!(publisher.effective_publications(), 2);
        assert_eq!(host.retained_transitions(), 0);

        let counts = (
            executor.calls,
            producer.prove_calls,
            producer.sign_calls,
            publisher.state.borrow().calls,
        );
        assert_eq!(
            host.execute_prove_publish(
                work(62),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap(),
            invoked
        );
        assert_eq!(
            host.execute_prove_publish(
                resume_work(62, 1),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap(),
            resumed
        );
        assert_eq!(
            (
                executor.calls,
                producer.prove_calls,
                producer.sign_calls,
                publisher.state.borrow().calls,
            ),
            counts
        );
    }

    #[test]
    fn logical_retirement_prevents_new_execution_and_reclaims_all_superseded_records() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host =
            DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();

        executor.fail_next = true;
        assert!(matches!(
            host.execute_prove_publish(
                work(62),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Lost))
        ));
        executor.fail_next = true;
        assert!(matches!(
            host.execute_prove_publish(
                resume_work(62, 1),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Execution(AdapterError::Lost))
        ));
        assert_eq!(host.retained_transitions(), 2);
        let final_key = host.image.records[0].key;
        assert_eq!(host.image.records[1].key.invocation, final_key.invocation);
        assert_ne!(host.image.records[1].key, final_key);
        publisher.state.borrow_mut().retired =
            Some(AuthenticatedTransitionRetirement::new(final_key, Hash([0xe1; 32]), 7).unwrap());

        let executions_before = executor.calls;
        let preparation = host
            .execute_prove_prepare(
                resume_work(62, 2),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        let VerifiedTransitionPreparation::AlreadyRetired(retired) = preparation else {
            panic!("logical retirement must preempt a new execution");
        };
        assert_eq!(retired.key(), final_key);
        assert_eq!(executor.calls, executions_before);
        assert_eq!(host.retained_transitions(), 2);

        assert_eq!(host.reclaim_checkpoint_retired(&mut publisher).unwrap(), 2);
        assert_eq!(host.retained_transitions(), 0);
        assert_eq!(store.witness_count(), 0);
    }

    #[test]
    fn runtime_deployment_program_package_and_proof_ceiling_substitution_fail_before_execution() {
        for case in 0..4 {
            let store = MemoryStore::default();
            let order = Rc::new(RefCell::new(Vec::new()));
            let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
                components(order);
            match case {
                0 => validator.wrong_deployment = true,
                1 => validator.wrong_program = true,
                2 => validator.wrong_package = true,
                3 => validator.wrong_proof_ceiling = true,
                _ => unreachable!(),
            }
            let mut host =
                DurableTransitionProofHost::open(store.clone(), route(), &FakeVerifier).unwrap();
            assert!(matches!(
                host.execute_prove_publish(
                    work(63),
                    &mut validator,
                    &mut executor,
                    &mut roots,
                    &mut producer,
                    &FakeVerifier,
                    &mut publisher,
                ),
                Err(TransitionProofHostError::Rejected(
                    TransitionProofHostRejection::InvalidWork
                ))
            ));
            assert_eq!(executor.calls, 0);
            assert_eq!(producer.prove_calls, 0);
            assert_eq!(host.retained_transitions(), 0);
            assert_eq!(store.witness_count(), 0);
            assert_eq!(publisher.effective_publications(), 0);
        }
    }

    #[test]
    fn published_tuple_reconstruction_rejects_a_substituted_fact() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host = DurableTransitionProofHost::open(store, route(), &FakeVerifier).unwrap();
        let published = host
            .execute_prove_publish(
                work(60),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
        assert_eq!(
            PublishedAttestedTransition::reconstruct(
                published.canonical_work.clone(),
                published.canonical_transition.clone(),
                published.proof_record.clone(),
                published.proof_manifest_bytes.clone(),
                published.publication.publication(),
            )
            .unwrap(),
            published
        );
        assert!(matches!(
            PublishedAttestedTransition::reconstruct(
                published.canonical_work,
                published.canonical_transition,
                published.proof_record,
                published.proof_manifest_bytes,
                Hash([0xfa; 32]),
            ),
            Err(TransitionProofHostRejection::InvalidPublication)
        ));
    }

    #[test]
    fn completed_workflows_are_reclaimed_without_a_lifetime_invocation_limit() {
        let store = MemoryStore::default();
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host = DurableTransitionProofHost::open(store, route(), &FakeVerifier).unwrap();

        for value in 1..=MAX_IN_FLIGHT_TRANSITION_PROOFS + 1 {
            host.execute_prove_publish(
                work(value as u64),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            )
            .unwrap();
            assert_eq!(host.retained_transitions(), 0);
        }
        assert_eq!(
            publisher.effective_publications(),
            MAX_IN_FLIGHT_TRANSITION_PROOFS + 1
        );
    }

    #[test]
    fn image_ceiling_covers_one_maximum_atomic_replay_batch() {
        assert_eq!(
            MAX_IN_FLIGHT_TRANSITION_PROOFS,
            super::super::journal::MAX_REPLAY_SUFFIX_ENTRIES
        );
        let roots = ProofLaneRoots {
            control: Hash([0x11; 32]),
            linear: Some(Hash([0x12; 32])),
            merge: Some(Hash([0x13; 32])),
            local: Some(Hash([0x14; 32])),
        };
        let mut image = TransitionProofHostImage::empty(route());
        for index in 1..=MAX_IN_FLIGHT_TRANSITION_PROOFS {
            let ordinal = (index as u64).to_le_bytes();
            let key = TransitionProofKey {
                invocation: invocation_id(index as u64 + u8::MAX as u64),
                execution: Hash::digest(b"vos/test/max-proof-host-execution", &[&ordinal]),
            };
            let transition = Hash::digest(b"vos/test/max-proof-host-transition", &[&ordinal]);
            image.records.push(RetainedTransition {
                key,
                work: BlobRef {
                    hash: key.execution,
                    len: 1,
                },
                before: roots,
                transition: Some(BlobRef {
                    hash: transition,
                    len: 1,
                }),
                statement: Some(vec![0xa1; TransitionProofStatement::MAX_ENCODED_BYTES]),
                witness: None,
                proof: Some(BlobRef {
                    hash: Hash::digest(b"vos/test/max-proof-host-proof", &[&ordinal]),
                    len: 1,
                }),
                producer_public_key: Some([0xa2; PROOF_PUBLIC_KEY_BYTES]),
                record: Some(vec![0xa3; MAX_TRANSITION_PROOF_RECORD_BYTES]),
            });
        }

        assert!(image.has_valid_envelope());
        let encoded = image.encode();
        assert_eq!(encoded.len(), MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES);
        assert!(MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES <= vos_protocol::wire::MAX_WIRE_BYTES);
        assert_eq!(TransitionProofHostImage::decode(&encoded).unwrap(), image);
    }

    #[test]
    fn image_bounds_unfinished_workflows_and_has_no_legacy_decoder() {
        let route = route();
        for invalid_ceiling in [0, crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1] {
            let mut invalid_route = route.clone();
            invalid_route.max_proof_material_bytes = invalid_ceiling;
            assert!(matches!(
                DurableTransitionProofHost::open(
                    MemoryStore::default(),
                    invalid_route,
                    &FakeVerifier,
                ),
                Err(TransitionProofHostOpenError::InvalidState)
            ));
        }
        let mut image = TransitionProofHostImage::empty(route.clone());
        let mut artifacts = Vec::new();
        for value in 1..=MAX_IN_FLIGHT_TRANSITION_PROOFS {
            let runtime_work = work(value as u64);
            let canonical_work = runtime_work.encode().unwrap();
            let work_ref = BlobRef::of_bytes(&canonical_work);
            let before = state_roots(match &runtime_work {
                RuntimeWork::Invoke { state, .. } => state,
                _ => unreachable!(),
            });
            image.records.push(RetainedTransition {
                key: transition_key(&runtime_work, &canonical_work, before).unwrap(),
                work: work_ref.clone(),
                before,
                transition: None,
                statement: None,
                witness: None,
                proof: None,
                producer_public_key: None,
                record: None,
            });
            artifacts.push((work_ref, canonical_work));
        }
        assert!(image.has_valid_envelope());
        let encoded = image.encode();
        assert!(encoded.len() <= MAX_TRANSITION_PROOF_HOST_IMAGE_BYTES);
        assert_eq!(TransitionProofHostImage::decode(&encoded).unwrap(), image);

        for magic in [b"APH1", b"APH2", b"APH3", b"APH4"] {
            let mut legacy = encoded.clone();
            legacy[..4].copy_from_slice(magic);
            assert!(matches!(
                TransitionProofHostImage::decode(&legacy),
                Err(DecodeError::InvalidTag)
            ));
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(TransitionProofHostImage::decode(&trailing).is_err());

        let mut over_capacity = image.clone();
        let runtime_work = work((MAX_IN_FLIGHT_TRANSITION_PROOFS + 1) as u64);
        let canonical_work = runtime_work.encode().unwrap();
        let before = state_roots(match &runtime_work {
            RuntimeWork::Invoke { state, .. } => state,
            _ => unreachable!(),
        });
        over_capacity.records.push(RetainedTransition {
            key: transition_key(&runtime_work, &canonical_work, before).unwrap(),
            work: BlobRef::of_bytes(&canonical_work),
            before,
            transition: None,
            statement: None,
            witness: None,
            proof: None,
            producer_public_key: None,
            record: None,
        });
        assert!(!over_capacity.has_valid_envelope());

        let mut oversized_transition = image.clone();
        let record = &mut oversized_transition.records[0];
        record.transition = Some(BlobRef {
            hash: Hash([0xd1; 32]),
            len: super::super::sdk::wire::MAX_RUNTIME_TRANSITION_WIRE_BYTES as u64 + 1,
        });
        record.statement = Some(vec![1]);
        record.witness = Some(Hash([0xd2; 32]));
        assert!(!oversized_transition.has_valid_envelope());

        let mut oversized_proof = image.clone();
        let record = &mut oversized_proof.records[0];
        record.transition = Some(BlobRef {
            hash: Hash([0xd3; 32]),
            len: 1,
        });
        record.statement = Some(vec![1]);
        record.witness = Some(Hash([0xd4; 32]));
        record.proof = Some(BlobRef {
            hash: Hash([0xd5; 32]),
            len: MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES as u64 + 1,
        });
        record.producer_public_key = Some([0xd6; PROOF_PUBLIC_KEY_BYTES]);
        assert!(!oversized_proof.has_valid_envelope());

        let store = MemoryStore::default();
        {
            let mut state = store.0.borrow_mut();
            state.image = Some(image.encode());
            state.artifacts = artifacts;
        }
        let mut wrong_route = route.clone();
        wrong_route.runtime_program = ProgramId([0xee; 32]);
        assert!(matches!(
            DurableTransitionProofHost::open(store.clone(), wrong_route, &FakeVerifier),
            Err(TransitionProofHostOpenError::InvalidState)
        ));
        let order = Rc::new(RefCell::new(Vec::new()));
        let (mut validator, mut executor, mut roots, mut producer, mut publisher) =
            components(order);
        let mut host = DurableTransitionProofHost::open(store, route, &FakeVerifier).unwrap();
        assert_eq!(host.retained_transitions(), MAX_IN_FLIGHT_TRANSITION_PROOFS);
        assert!(matches!(
            host.execute_prove_publish(
                work((MAX_IN_FLIGHT_TRANSITION_PROOFS + 1) as u64),
                &mut validator,
                &mut executor,
                &mut roots,
                &mut producer,
                &FakeVerifier,
                &mut publisher,
            ),
            Err(TransitionProofHostError::Rejected(
                TransitionProofHostRejection::Capacity
            ))
        ));
        assert_eq!(executor.calls, 0);
        assert_eq!(publisher.effective_publications(), 0);
    }

    #[cfg(feature = "agent-transition-proof")]
    #[test]
    fn physical_refine_path_binds_same_run_output_and_replays_exact_proof() {
        use core::convert::Infallible;

        use vos_pvm_compiler::assembler::{Assembler, Reg};
        use vos_pvm_proof::{
            decode_refine_proof_bundle, encode_refine_proof_bundle, refine_bundle_commitment,
        };

        struct ProgramSource {
            program: ProgramId,
            bytes: Vec<u8>,
            loads: Rc<Cell<usize>>,
        }

        impl AttestedRuntimeProgramLoader for ProgramSource {
            type Error = Infallible;

            fn load_attested_runtime_program(
                &self,
                program: ProgramId,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                self.loads.set(self.loads.get() + 1);
                Ok((program == self.program).then(|| self.bytes.clone()))
            }
        }

        let proof_system = standard_refine_proof_system();
        let mut runtime_work = work(0x71);
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            ..
        } = &mut runtime_work
        else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested { proof_system };
        let mut successor = state.clone();
        successor.linear = b"physically-proved-linear-successor".to_vec();
        let transition = RuntimeTransition {
            state: successor,
            outcome: RuntimeOutcome::Completed(Ok(InvocationReply {
                invocation: invocation.invocation,
                actor: invocation.actor,
                incarnation: invocation.incarnation,
                deployment: invocation.deployment,
                mode: invocation.mode,
                lane: invocation.mode.write_lane(),
                status: InvocationStatus::Done,
                reply: b"proved".to_vec(),
                gas_remaining: invocation.gas - 1,
                observation: Default::default(),
            })),
        };
        let invocation_gas = invocation.gas;
        let canonical_work = runtime_work.encode().unwrap();
        assert_eq!(
            standard_runtime_gas(&runtime_work),
            Some(STANDARD_INVOKE_GAS_OVERHEAD + invocation_gas)
        );
        assert_eq!(
            standard_runtime_gas(&resume_work(0x71, 1)),
            Some(STANDARD_RESUME_GAS_LIMIT)
        );
        let canonical_transition = transition.encode().unwrap();
        let public_io =
            crate::agent_sdk::runtime_transition_public_io(&canonical_work, &canonical_transition);
        let words = public_io
            .as_bytes()
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let mut assembler = Assembler::new();
        assembler
            .set_rw_data(canonical_transition.clone())
            .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
            .load_imm_64(Reg::A1, canonical_transition.len() as u64)
            .load_imm_64(Reg::A2, words[0])
            .load_imm_64(Reg::A3, words[1])
            .load_imm_64(Reg::A4, words[2])
            .load_imm_64(Reg::A5, words[3])
            .jump_ind(Reg::RA, 0);
        let runtime = assembler.build_standard();

        let mut physical_route = route();
        physical_route.runtime_program = ProgramId::of_pvm(&runtime);
        physical_route.proof_system = proof_system;
        let signer_seed = [0x71; 32];
        let signer_public_key = ed25519_dalek::SigningKey::from_bytes(&signer_seed)
            .verifying_key()
            .to_bytes();
        physical_route.producer = ProducerId::of_public_key(&signer_public_key);
        let mut validator = FakeValidator::new(physical_route.clone());
        let admission = validator
            .authenticate_work(&physical_route, &runtime_work, &canonical_work)
            .unwrap();
        let authenticated = AuthenticatedAttestedTransition::authenticate_for_test(
            &physical_route,
            &runtime_work,
            admission,
        )
        .unwrap();
        let missing_loads = Rc::new(Cell::new(0));
        assert!(matches!(
            PhysicalRefineRouteComponents::open(
                physical_route.clone(),
                ProgramSource {
                    program: ProgramId([0xfe; 32]),
                    bytes: runtime.clone(),
                    loads: missing_loads.clone(),
                },
                Ed25519PhysicalTransitionSigner::from_seed(signer_seed),
            ),
            Err(PhysicalRefineRouteOpenError::MissingProgram)
        ));
        assert_eq!(missing_loads.get(), 1);

        let substituted_loads = Rc::new(Cell::new(0));
        assert!(matches!(
            PhysicalRefineRouteComponents::open(
                physical_route.clone(),
                ProgramSource {
                    program: physical_route.runtime_program,
                    bytes: vec![0xff],
                    loads: substituted_loads.clone(),
                },
                Ed25519PhysicalTransitionSigner::from_seed(signer_seed),
            ),
            Err(PhysicalRefineRouteOpenError::InvalidRoute)
        ));
        assert_eq!(substituted_loads.get(), 1);

        let mut wrong_producer_route = physical_route.clone();
        wrong_producer_route.producer = ProducerId([0xfd; 32]);
        let wrong_producer_loads = Rc::new(Cell::new(0));
        assert!(matches!(
            PhysicalRefineRouteComponents::open(
                wrong_producer_route,
                ProgramSource {
                    program: physical_route.runtime_program,
                    bytes: runtime.clone(),
                    loads: wrong_producer_loads.clone(),
                },
                Ed25519PhysicalTransitionSigner::from_seed(signer_seed),
            ),
            Err(PhysicalRefineRouteOpenError::WrongProducer)
        ));
        assert_eq!(wrong_producer_loads.get(), 0);

        let loads = Rc::new(Cell::new(0));
        let source = ProgramSource {
            program: physical_route.runtime_program,
            bytes: runtime.clone(),
            loads: loads.clone(),
        };
        let components = PhysicalRefineRouteComponents::open(
            physical_route.clone(),
            source,
            Ed25519PhysicalTransitionSigner::from_seed(signer_seed),
        )
        .unwrap();
        assert_eq!(loads.get(), 1);
        let (mut executor, mut producer, verifier) = components.into_parts();
        let tentative = executor
            .execute_tentative(&authenticated, &canonical_work)
            .unwrap();
        assert_eq!(tentative.transition, transition);
        assert_eq!(tentative.public_io, public_io);
        assert_eq!(loads.get(), 2);

        let subject = subject_for(
            &physical_route,
            &runtime_work,
            authenticated.method().into(),
        )
        .unwrap();
        let before = state_roots(match &runtime_work {
            RuntimeWork::Invoke { state, .. } => state,
            _ => unreachable!(),
        });
        let after = state_roots(&transition.state);
        let statement = TransitionProofStatement {
            subject,
            before,
            after,
            work: TransitionProofStatement::work_commitment(&canonical_work),
            transition: TransitionProofStatement::transition_commitment(&canonical_transition),
            refine_trace: tentative.refine_trace,
            public_io: tentative.public_io,
            proof_system,
        };
        let witness = ProducerPrivateWitness {
            statement: statement.commitment().unwrap(),
            bytes: tentative.private_witness,
        };
        let material = producer
            .prove_nested_refine(&authenticated, &statement, &witness)
            .unwrap();
        assert_eq!(material, witness.bytes);
        let mut restarted_producer = PhysicalRefineProofProducer::new(
            Ed25519PhysicalTransitionSigner::from_seed(signer_seed),
        );
        assert_eq!(
            restarted_producer
                .prove_nested_refine(&authenticated, &statement, &witness)
                .unwrap(),
            material,
            "restart must reuse the exact durably prepared proof without execution"
        );

        let signed_message = b"physical-transition-record";
        let signature = producer
            .sign_transition_record(&authenticated, signed_message)
            .unwrap();
        assert!(verifier.verify_producer(&producer.public_key(), signed_message, &signature));

        assert!(verifier.verify_transition_exact(
            &statement,
            &canonical_work,
            &canonical_transition,
            &material,
        ));
        assert!(!verifier.verify_transition(&statement, &material));

        let mut substituted_transition = transition.clone();
        substituted_transition.state.linear.push(0xff);
        assert!(!verifier.verify_transition_exact(
            &statement,
            &canonical_work,
            &substituted_transition.encode().unwrap(),
            &material,
        ));
        let mut substituted_statement = statement.clone();
        substituted_statement.public_io.0[0] ^= 1;
        assert!(!verifier.verify_transition_exact(
            &substituted_statement,
            &canonical_work,
            &canonical_transition,
            &material,
        ));

        let mut substituted_bundle = decode_refine_proof_bundle(
            &material,
            crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        )
        .unwrap();
        substituted_bundle
            .slices
            .last_mut()
            .unwrap()
            .proof
            .final_state
            .registers[9] ^= 1;
        substituted_bundle.transcript_commitment = refine_bundle_commitment(&substituted_bundle);
        let substituted_material = encode_refine_proof_bundle(&substituted_bundle).unwrap();
        assert!(!verifier.verify_transition_exact(
            &statement,
            &canonical_work,
            &canonical_transition,
            &substituted_material,
        ));
    }
}
