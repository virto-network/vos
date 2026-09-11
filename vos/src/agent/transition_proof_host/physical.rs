//! Production physical execution and verification for attested Standard work.
//!
//! The host-authenticated capability is the trust boundary above this module.
//! A runtime program is loaded by its exact admitted `ProgramId`, then one
//! `trace_refine_observed` call supplies the transition bytes, transcript and
//! terminal a2..a5 values. The observed trace is consumed directly by
//! `prove_refine`; no executor-provided trace or public-I/O value enters the
//! durable statement. The canonical proof bundle is retained as the private
//! witness so a crash after preparation never executes the work again.
//!
//! Acceptance uses the inverse path: bounded canonical decode, exact
//! work/transition/gas/program binding, terminal public-I/O comparison, and
//! full child-proof verification plus deterministic native-boundary replay.

use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use vos_pvm_proof::{
    RefineProofCodecError, RefineTraceError, decode_refine_proof_bundle,
    encode_refine_proof_bundle, prove_refine, refine_arguments_commitment,
    refine_bundle_execution_commitment, refine_bundle_terminal_public_io, refine_program_id,
    refine_trace_execution_commitment, trace_refine_observed, verify_refine_bundle_replayed,
};

use super::{
    AgentTransitionProofProducer, AttestedTentativeExecutor, AttestedTransitionRoute,
    AuthenticatedAttestedTransition, PROOF_PUBLIC_KEY_BYTES, PROOF_SIGNATURE_BYTES,
    ProducerPrivateWitness, TentativeAttestedExecution, TransitionProofAdapterError,
    TransitionProofStatement, TransitionProofVerifier, canonical_decode, subject_for,
    validate_transition_for_work,
};
use crate::agent::driver::{AgentImageStore, AgentStoreError, DEFAULT_MANAGEMENT_GAS};
use crate::agent::execution::{MAX_EXECUTION_GAS, MAX_EXECUTION_PROGRAM_BYTES};
use crate::agent::sdk::wire::MAX_RUNTIME_TRANSITION_WIRE_BYTES;
use crate::agent::sdk::{Hash, ProducerId, ProgramId, RuntimeTransition, RuntimeWork};

/// Fixed outer-runtime overhead applied to every Standard Invoke.
///
/// The complete Invoke limit is this overhead plus the exact admitted inner
/// invocation gas. Overflow is rejected before the PVM is started.
pub(crate) const STANDARD_INVOKE_GAS_OVERHEAD: u64 = DEFAULT_MANAGEMENT_GAS;

/// Fixed outer-runtime gas used for Resume.
///
/// Resume carries no fresh caller gas field, so the clean runtime contract
/// reserves the maximum inner execution budget in addition to management
/// overhead. The current host allowance is `6_000_000_000`; the inner actor
/// execution cap remains `1_000_000_000`.
pub(crate) const STANDARD_RESUME_GAS_LIMIT: u64 =
    DEFAULT_MANAGEMENT_GAS.saturating_add(MAX_EXECUTION_GAS);

/// Domain identity of the exact Refine proof stack used by this adapter.
///
/// Package capabilities and AMP2 policies name this value. Including all
/// format generations prevents a verifier for one codec/AIR generation from
/// accepting a differently interpreted proof under the same policy label.
pub(crate) fn standard_refine_proof_system() -> Hash {
    Hash::digest(
        b"vos/agent/standard-refine-proof-system/v1",
        &[
            crate::agent_sdk::RUNTIME_ABI_ID.as_bytes(),
            &vos_pvm_proof::PROOF_FORMAT_VERSION.to_le_bytes(),
            &vos_pvm_proof::REFINE_BUNDLE_FORMAT_VERSION.to_le_bytes(),
            &vos_pvm_proof::REFINE_PROOF_BUNDLE_CODEC_VERSION.to_le_bytes(),
        ],
    )
}

/// Exact physical lookup of an admitted runtime PVM.
///
/// Implementations must bound reads before allocation. The executor repeats
/// the byte length and `ProgramId` checks before any interpreter work.
pub(crate) trait AttestedRuntimeProgramLoader {
    type Error;

    fn load_attested_runtime_program(
        &self,
        program: ProgramId,
    ) -> Result<Option<Vec<u8>>, Self::Error>;
}

impl<T: AgentImageStore> AttestedRuntimeProgramLoader for T {
    type Error = AgentStoreError;

    fn load_attested_runtime_program(
        &self,
        program: ProgramId,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        self.load_program(crate::service::ProgramId(program.0))
    }
}

/// Failure from exact physical preparation.
#[derive(Debug)]
pub(crate) enum PhysicalRefineExecutionError<E> {
    ProgramStore(E),
    MissingProgram,
    InvalidProgram,
    InvalidWork,
    InvalidTransition,
    PublicIoMismatch,
    ProofTooLarge,
    Trace(RefineTraceError),
    Codec(RefineProofCodecError),
}

impl<E: fmt::Display> fmt::Display for PhysicalRefineExecutionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgramStore(error) => write!(formatter, "runtime program store: {error}"),
            Self::MissingProgram => formatter.write_str("admitted runtime program is unavailable"),
            Self::InvalidProgram => {
                formatter.write_str("runtime program bytes do not match admission")
            }
            Self::InvalidWork => formatter.write_str("work does not match attested admission"),
            Self::InvalidTransition => {
                formatter.write_str("runtime returned an invalid canonical transition")
            }
            Self::PublicIoMismatch => {
                formatter.write_str("runtime terminal public I/O does not bind its exact output")
            }
            Self::ProofTooLarge => {
                formatter.write_str("Refine proof exceeds the authenticated runtime ceiling")
            }
            Self::Trace(error) => write!(formatter, "Refine execution/proof: {error}"),
            Self::Codec(error) => write!(formatter, "Refine proof codec: {error}"),
        }
    }
}

impl<E> core::error::Error for PhysicalRefineExecutionError<E> where E: core::error::Error + 'static {}

/// The sole constructor of physically derived tentative execution results.
pub(crate) struct PhysicalAttestedTentativeExecutor<L> {
    programs: L,
}

impl<L> PhysicalAttestedTentativeExecutor<L> {
    pub(crate) const fn new(programs: L) -> Self {
        Self { programs }
    }

    pub(crate) fn into_inner(self) -> L {
        self.programs
    }
}

impl<L: AttestedRuntimeProgramLoader> AttestedTentativeExecutor
    for PhysicalAttestedTentativeExecutor<L>
{
    type Error = PhysicalRefineExecutionError<L::Error>;

    fn execute_tentative(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        canonical_work: &[u8],
    ) -> Result<TentativeAttestedExecution, TransitionProofAdapterError<Self::Error>> {
        let work = canonical_decode::<RuntimeWork>(canonical_work).map_err(|()| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::InvalidWork)
        })?;
        if !authenticated.authorizes_standard_work(&work)
            || authenticated.proof_system() != standard_refine_proof_system()
        {
            return Err(TransitionProofAdapterError::Terminal(
                PhysicalRefineExecutionError::InvalidWork,
            ));
        }
        let runtime = self
            .programs
            .load_attested_runtime_program(authenticated.runtime_program())
            .map_err(|error| {
                TransitionProofAdapterError::Retryable(PhysicalRefineExecutionError::ProgramStore(
                    error,
                ))
            })?
            .ok_or_else(|| {
                TransitionProofAdapterError::Retryable(PhysicalRefineExecutionError::MissingProgram)
            })?;
        if runtime.is_empty()
            || runtime.len() > MAX_EXECUTION_PROGRAM_BYTES
            || ProgramId::of_pvm(&runtime) != authenticated.runtime_program()
        {
            return Err(TransitionProofAdapterError::Terminal(
                PhysicalRefineExecutionError::InvalidProgram,
            ));
        }
        let gas = standard_runtime_gas(&work).ok_or_else(|| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::InvalidWork)
        })?;
        let observed = trace_refine_observed(
            &runtime,
            canonical_work,
            gas,
            MAX_RUNTIME_TRANSITION_WIRE_BYTES,
        )
        .map_err(|error| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::Trace(error))
        })?;
        let transition = canonical_decode::<RuntimeTransition>(&observed.output).map_err(|()| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::InvalidTransition)
        })?;
        validate_transition_for_work(&work, &transition).map_err(|_| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::InvalidTransition)
        })?;
        let expected_public_io =
            crate::agent_sdk::runtime_transition_public_io(canonical_work, &observed.output);
        if observed.public_io != expected_public_io.0 {
            return Err(TransitionProofAdapterError::Terminal(
                PhysicalRefineExecutionError::PublicIoMismatch,
            ));
        }
        let refine_trace = Hash(refine_trace_execution_commitment(&observed.trace));
        let bundle = prove_refine(observed.trace).map_err(|error| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::Trace(error))
        })?;
        let material = encode_refine_proof_bundle(&bundle).map_err(|error| {
            TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::Codec(error))
        })?;
        if material.is_empty() || material.len() as u64 > authenticated.max_proof_material_bytes() {
            return Err(TransitionProofAdapterError::Terminal(
                PhysicalRefineExecutionError::ProofTooLarge,
            ));
        }
        let decoded =
            decode_refine_proof_bundle(&material, authenticated.max_proof_material_bytes())
                .map_err(|error| {
                    TransitionProofAdapterError::Terminal(PhysicalRefineExecutionError::Codec(
                        error,
                    ))
                })?;
        if encode_refine_proof_bundle(&decoded).ok().as_deref() != Some(material.as_slice())
            || refine_bundle_execution_commitment(&decoded) != refine_trace.0
            || refine_bundle_terminal_public_io(&decoded) != Some(expected_public_io.0)
        {
            return Err(TransitionProofAdapterError::Terminal(
                PhysicalRefineExecutionError::PublicIoMismatch,
            ));
        }
        Ok(TentativeAttestedExecution {
            transition,
            proof_system: authenticated.proof_system(),
            refine_trace,
            public_io: expected_public_io,
            private_witness: material,
        })
    }
}

pub(crate) fn standard_runtime_gas(work: &RuntimeWork) -> Option<u64> {
    match work {
        RuntimeWork::Invoke { invocation, .. } => {
            STANDARD_INVOKE_GAS_OVERHEAD.checked_add(invocation.gas)
        }
        RuntimeWork::Resume { .. } => Some(STANDARD_RESUME_GAS_LIMIT),
        RuntimeWork::Manage { .. } | RuntimeWork::Acknowledge { .. } => None,
    }
}

/// Signing key seam kept separate from physical proof creation.
pub(crate) trait PhysicalTransitionRecordSigner {
    type Error;

    fn public_key(&self) -> [u8; PROOF_PUBLIC_KEY_BYTES];

    fn sign(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        message: &[u8],
    ) -> Result<[u8; PROOF_SIGNATURE_BYTES], TransitionProofAdapterError<Self::Error>>;
}

/// Node-owned Ed25519 producer key used by the production Refine route.
///
/// The route constructor below refuses a key whose derived `ProducerId` is
/// not the exact producer admitted in the route. `SigningKey` zeroizes its
/// secret material on drop through the crate's enabled `zeroize` feature.
pub(crate) struct Ed25519PhysicalTransitionSigner {
    signing_key: SigningKey,
}

impl Ed25519PhysicalTransitionSigner {
    pub(crate) const fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self::new(SigningKey::from_bytes(&seed))
    }
}

impl PhysicalTransitionRecordSigner for Ed25519PhysicalTransitionSigner {
    type Error = core::convert::Infallible;

    fn public_key(&self) -> [u8; PROOF_PUBLIC_KEY_BYTES] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign(
        &mut self,
        _authenticated: &AuthenticatedAttestedTransition,
        message: &[u8],
    ) -> Result<[u8; PROOF_SIGNATURE_BYTES], TransitionProofAdapterError<Self::Error>> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

/// Construction failure for the production physical execution route.
#[derive(Debug)]
pub(crate) enum PhysicalRefineRouteOpenError<E> {
    ProgramStore(E),
    MissingProgram,
    InvalidRoute,
    WrongProducer,
}

impl<E: fmt::Display> fmt::Display for PhysicalRefineRouteOpenError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgramStore(error) => write!(formatter, "runtime program store: {error}"),
            Self::MissingProgram => formatter.write_str("admitted runtime program is unavailable"),
            Self::InvalidRoute => formatter.write_str("invalid physical Refine route"),
            Self::WrongProducer => {
                formatter.write_str("producer key does not match the admitted route")
            }
        }
    }
}

impl<E> core::error::Error for PhysicalRefineRouteOpenError<E> where E: core::error::Error + 'static {}

/// Fully bound production adapters for one attested Standard runtime route.
///
/// Opening performs a physical read and exact `ProgramId` check for the
/// verifier snapshot, while the returned executor retains the loader and
/// repeats that read for every tentative execution. The producer key is bound
/// to the route before any component is made available. This is the intended
/// construction seam for `DurableTransitionProofHost`; journal publication
/// remains an independently owned adapter.
pub(crate) struct PhysicalRefineRouteComponents<L, S> {
    executor: PhysicalAttestedTentativeExecutor<L>,
    producer: PhysicalRefineProofProducer<S>,
    verifier: PhysicalRefineTransitionVerifier,
}

impl<L, S> PhysicalRefineRouteComponents<L, S>
where
    L: AttestedRuntimeProgramLoader,
    S: PhysicalTransitionRecordSigner,
{
    pub(crate) fn open(
        route: AttestedTransitionRoute,
        programs: L,
        signer: S,
    ) -> Result<Self, PhysicalRefineRouteOpenError<L::Error>> {
        if !route.is_valid() || route.proof_system != standard_refine_proof_system() {
            return Err(PhysicalRefineRouteOpenError::InvalidRoute);
        }
        if ProducerId::of_public_key(&signer.public_key()) != route.producer {
            return Err(PhysicalRefineRouteOpenError::WrongProducer);
        }
        let runtime = programs
            .load_attested_runtime_program(route.runtime_program)
            .map_err(PhysicalRefineRouteOpenError::ProgramStore)?
            .ok_or(PhysicalRefineRouteOpenError::MissingProgram)?;
        let verifier = PhysicalRefineTransitionVerifier::new(route, runtime)
            .map_err(|_| PhysicalRefineRouteOpenError::InvalidRoute)?;
        Ok(Self {
            executor: PhysicalAttestedTentativeExecutor::new(programs),
            producer: PhysicalRefineProofProducer::new(signer),
            verifier,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PhysicalAttestedTentativeExecutor<L>,
        PhysicalRefineProofProducer<S>,
        PhysicalRefineTransitionVerifier,
    ) {
        (self.executor, self.producer, self.verifier)
    }
}

#[derive(Debug)]
pub(crate) enum PhysicalRefineProofProducerError<E> {
    InvalidPreparedProof,
    Signer(E),
}

impl<E: fmt::Display> fmt::Display for PhysicalRefineProofProducerError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPreparedProof => formatter.write_str("invalid prepared Refine proof"),
            Self::Signer(error) => write!(formatter, "transition record signer: {error}"),
        }
    }
}

impl<E> core::error::Error for PhysicalRefineProofProducerError<E> where
    E: core::error::Error + 'static
{
}

/// Producer which consumes the proof bundle durably prepared by the executor.
///
/// `prove_refine` already consumed the exact observed trace before the host's
/// atomic prepared-state commit. This adapter validates and returns those
/// exact canonical bytes after restart; it never reruns the transition.
pub(crate) struct PhysicalRefineProofProducer<S> {
    signer: S,
}

impl<S> PhysicalRefineProofProducer<S> {
    pub(crate) const fn new(signer: S) -> Self {
        Self { signer }
    }

    pub(crate) fn into_inner(self) -> S {
        self.signer
    }
}

impl<S: PhysicalTransitionRecordSigner> AgentTransitionProofProducer
    for PhysicalRefineProofProducer<S>
{
    type Error = PhysicalRefineProofProducerError<S::Error>;

    fn public_key(&self) -> [u8; PROOF_PUBLIC_KEY_BYTES] {
        self.signer.public_key()
    }

    fn prove_nested_refine(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        statement: &TransitionProofStatement,
        witness: &ProducerPrivateWitness,
    ) -> Result<Vec<u8>, TransitionProofAdapterError<Self::Error>> {
        let reject = || {
            TransitionProofAdapterError::Terminal(
                PhysicalRefineProofProducerError::InvalidPreparedProof,
            )
        };
        if statement.commitment().ok() != Some(witness.statement)
            || statement.key() != authenticated.key()
            || statement.proof_system != authenticated.proof_system()
            || statement.proof_system != standard_refine_proof_system()
            || witness.bytes.is_empty()
            || witness.bytes.len() as u64 > authenticated.max_proof_material_bytes()
        {
            return Err(reject());
        }
        let bundle =
            decode_refine_proof_bundle(&witness.bytes, authenticated.max_proof_material_bytes())
                .map_err(|_| reject())?;
        if encode_refine_proof_bundle(&bundle).ok().as_deref() != Some(witness.bytes.as_slice())
            || Hash(refine_bundle_execution_commitment(&bundle)) != statement.refine_trace
            || refine_bundle_terminal_public_io(&bundle) != Some(statement.public_io.0)
        {
            return Err(reject());
        }
        Ok(witness.bytes.clone())
    }

    fn sign_transition_record(
        &mut self,
        authenticated: &AuthenticatedAttestedTransition,
        message: &[u8],
    ) -> Result<[u8; PROOF_SIGNATURE_BYTES], TransitionProofAdapterError<Self::Error>> {
        self.signer
            .sign(authenticated, message)
            .map_err(|error| match error {
                TransitionProofAdapterError::Retryable(error) => {
                    TransitionProofAdapterError::Retryable(
                        PhysicalRefineProofProducerError::Signer(error),
                    )
                }
                TransitionProofAdapterError::Terminal(error) => {
                    TransitionProofAdapterError::Terminal(PhysicalRefineProofProducerError::Signer(
                        error,
                    ))
                }
            })
    }
}

/// Exact replaying verifier for one authenticated runtime route.
pub(crate) struct PhysicalRefineTransitionVerifier {
    route: AttestedTransitionRoute,
    runtime: Vec<u8>,
}

impl PhysicalRefineTransitionVerifier {
    pub(crate) fn new(
        route: AttestedTransitionRoute,
        runtime: Vec<u8>,
    ) -> Result<Self, PhysicalRefineExecutionError<core::convert::Infallible>> {
        if !route.is_valid()
            || route.proof_system != standard_refine_proof_system()
            || runtime.is_empty()
            || runtime.len() > MAX_EXECUTION_PROGRAM_BYTES
            || ProgramId::of_pvm(&runtime) != route.runtime_program
        {
            return Err(PhysicalRefineExecutionError::InvalidProgram);
        }
        Ok(Self { route, runtime })
    }

    pub(crate) fn route(&self) -> &AttestedTransitionRoute {
        &self.route
    }
}

impl TransitionProofVerifier for PhysicalRefineTransitionVerifier {
    fn verify_producer(
        &self,
        public_key: &[u8; PROOF_PUBLIC_KEY_BYTES],
        message: &[u8],
        signature: &[u8; PROOF_SIGNATURE_BYTES],
    ) -> bool {
        VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
            key.verify_strict(message, &Signature::from_bytes(signature))
                .is_ok()
        })
    }

    fn verify_transition(
        &self,
        _statement: &TransitionProofStatement,
        _proof_material: &[u8],
    ) -> bool {
        // A statement carries only commitments. This backend requires exact
        // work and transition bytes so it cannot be used through the weaker
        // compatibility entry.
        false
    }

    fn verify_transition_exact(
        &self,
        statement: &TransitionProofStatement,
        canonical_work: &[u8],
        canonical_transition: &[u8],
        proof_material: &[u8],
    ) -> bool {
        // This verifies the physical work/output execution only. The host's
        // exact-record caller must independently materialize and compare both
        // before/after roots before it can construct a publication capability.
        let Ok(work) = canonical_decode::<RuntimeWork>(canonical_work) else {
            return false;
        };
        let Ok(transition) = canonical_decode::<RuntimeTransition>(canonical_transition) else {
            return false;
        };
        if !self.route.matches_work(&work)
            || validate_transition_for_work(&work, &transition).is_err()
            || proof_material.is_empty()
            || proof_material.len() as u64 > self.route.max_proof_material_bytes
        {
            return false;
        }
        let Some(subject) = subject_for(&self.route, &work, statement.subject.method.clone())
        else {
            return false;
        };
        if !statement.matches_execution(
            &subject,
            statement.before,
            statement.after,
            canonical_work,
            canonical_transition,
            statement.refine_trace,
            statement.public_io,
            self.route.proof_system,
        ) {
            return false;
        }
        let Some(gas) = standard_runtime_gas(&work) else {
            return false;
        };
        let Ok(bundle) =
            decode_refine_proof_bundle(proof_material, self.route.max_proof_material_bytes)
        else {
            return false;
        };
        let expected_public_io =
            crate::agent_sdk::runtime_transition_public_io(canonical_work, canonical_transition);
        if encode_refine_proof_bundle(&bundle).ok().as_deref() != Some(proof_material)
            || bundle.outer_program != refine_program_id(&self.runtime)
            || bundle.arguments_commitment != refine_arguments_commitment(canonical_work)
            || bundle.gas_limit != gas
            || Hash(refine_bundle_execution_commitment(&bundle)) != statement.refine_trace
            || refine_bundle_terminal_public_io(&bundle) != Some(statement.public_io.0)
            || statement.public_io != expected_public_io
        {
            return false;
        }
        verify_refine_bundle_replayed(&bundle, &self.runtime, canonical_work, gas).is_ok()
    }
}
