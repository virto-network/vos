//! The credential prover and verifier over a [`Call`]: the statement's
//! public words computed from the secret, the witness and the call; the
//! witness checked before any proving; the proof under the registry's
//! credential format, its masks the operating system's.

use std::sync::OnceLock;

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm_final_verifier::credential::{self as verifier, CREDENTIAL};
use vos_pvm_proof::format::CREDENTIAL_PROOF;
use vos_pvm_recair::context::Witness;
use vos_pvm_recair::credential::{self as circuits, AuthPublic, OwnerPublic, Statement};
use vos_pvm_recair::prove::ProveError;
use vos_pvm_recair_air::credential::CredentialKind;
use zeroize::Zeroize;

use crate::secret::{self, DeviceSecret};
use crate::{AuthWitness, Call, DeviceError, Digest, FORMAT, scope};

use vos_pvm_recair::masked::MaskRng;

/// The most memory a credential proof takes, in bytes: its peak resident
/// size measured on the gate phone and on x86, rounded up. A configuration
/// allowing less is refused.
pub const PEAK_BYTES: u64 = 192 << 20;

/// The kind byte the joint statement's binding hashes: it has no
/// `CredentialPublic` index, and no ingress admits it.
const JOINT_KIND: u8 = 0xff;

/// How a [`Prover`]'s pool spreads its work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Threads {
    /// One thread a core the system reports, the work split evenly over
    /// them.
    Auto,
    /// This many threads, unpinned.
    Count(usize),
    /// One thread a named core, each pinned to its core.
    Cores(Vec<usize>),
}

/// A prover's threads and its memory allowance. Its masks are the
/// operating system's.
#[derive(Clone, Debug)]
pub struct ProverConfig {
    pub threads: Threads,
    /// The memory a proof may take, in bytes: at least [`PEAK_BYTES`].
    pub max_memory: u64,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            threads: Threads::Auto,
            max_memory: PEAK_BYTES,
        }
    }
}

/// A statement's public digests, after its kind; the enum's index is the
/// statement's `kind` (`proving.md` §8), as the node API's
/// `CredentialPublic` encodes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialPublic {
    Auth {
        map_root: Digest,
        scope: Digest,
        nullifier: Digest,
        binding: Digest,
    },
    Owner {
        owner: Digest,
        binding: Digest,
    },
}

impl CredentialPublic {
    /// The statement's kind.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            CredentialPublic::Auth { .. } => CredentialKind::Auth,
            CredentialPublic::Owner { .. } => CredentialKind::Owner,
        }
    }

    /// Its `binding`.
    pub const fn binding(&self) -> &Digest {
        match self {
            CredentialPublic::Auth { binding, .. } | CredentialPublic::Owner { binding, .. } => {
                binding
            }
        }
    }

    /// Its public words: the kind, then each digest's eight.
    pub fn words(&self) -> Vec<u32> {
        let digests: &[&Digest] = match self {
            CredentialPublic::Auth {
                map_root,
                scope,
                nullifier,
                binding,
            } => &[map_root, scope, nullifier, binding],
            CredentialPublic::Owner { owner, binding } => &[owner, binding],
        };
        core::iter::once(u32::from(self.kind() as u8))
            .chain(digests.iter().flat_map(|digest| digest.0))
            .collect()
    }
}

/// A credential proof: its format, its statement's public digests and the
/// proof's bytes, what a `Credentialed` request carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialProof {
    pub format: u32,
    pub public: CredentialPublic,
    pub proof: Vec<u8>,
}

/// Membership and payment together's public digests: auth's, and the
/// owner digest of the same secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointPublic {
    pub map_root: Digest,
    pub scope: Digest,
    pub nullifier: Digest,
    pub owner: Digest,
    pub binding: Digest,
}

impl JointPublic {
    /// Its public words, in the circuit's order; no kind.
    pub fn words(&self) -> Vec<u32> {
        [
            self.map_root,
            self.scope,
            self.nullifier,
            self.owner,
            self.binding,
        ]
        .iter()
        .flat_map(|digest| digest.0)
        .collect()
    }
}

/// A proof of membership and payment together: measured, admitted by no
/// ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointProof {
    pub format: u32,
    pub public: JointPublic,
    pub proof: Vec<u8>,
}

/// The prover: its thread pool.
pub struct Prover {
    pool: rayon::ThreadPool,
    masks: MaskRng,
}

impl Prover {
    /// A prover as `config` says: its pool built, its memory allowance at
    /// least [`PEAK_BYTES`].
    pub fn new(config: ProverConfig) -> Result<Self, DeviceError> {
        if config.max_memory < PEAK_BYTES {
            return Err(DeviceError::Memory);
        }
        let builder = rayon::ThreadPoolBuilder::new();
        let builder = match config.threads {
            Threads::Auto => builder.num_threads(
                std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1),
            ),
            Threads::Count(0) => return Err(DeviceError::Config),
            Threads::Count(count) => builder.num_threads(count),
            Threads::Cores(cores) => {
                if cores.is_empty() || !cores.iter().all(|&core| pinnable(core)) {
                    return Err(DeviceError::Config);
                }
                builder
                    .num_threads(cores.len())
                    .start_handler(move |index| pin(cores[index]))
            }
        };
        let pool = builder.build().map_err(|_| DeviceError::Config)?;
        Ok(Self {
            pool,
            masks: MaskRng::Os,
        })
    }

    /// This prover with every proof's masks from `seed`, so a proof's
    /// bytes are any machine's: the phone bench's seeded build. A test seam
    /// (`seeded-masks`), refused in every production build by `just
    /// check-no-seeded-masks`.
    #[cfg(feature = "seeded-masks")]
    #[doc(hidden)]
    pub fn seeded(self, seed: u64) -> Self {
        Self {
            masks: MaskRng::Seeded(seed),
            ..self
        }
    }

    /// The pool's threads.
    pub fn threads(&self) -> usize {
        self.pool.current_num_threads()
    }

    /// Proves that `secret`'s member holds the leaf `witness` places under
    /// its root, and its nullifier in the scope of the guard named `name`,
    /// for `call`. The witness is checked first: a path that does not place
    /// the member's leaf under its root is [`DeviceError::Witness`], before
    /// any proving.
    pub fn prove_auth(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        name: &[u8],
        call: &Call,
    ) -> Result<CredentialProof, DeviceError> {
        let public = auth_public(
            secret,
            witness,
            name,
            call,
            verifier::program(CredentialKind::Auth),
            CredentialKind::Auth as u8,
        )?;
        let statement = Held(Statement::Auth(
            public.circuit(),
            circuit_witness(secret, witness),
        ));
        let proof = self.prove(&statement.0);
        drop(statement);
        Ok(CredentialProof {
            format: FORMAT,
            public: CredentialPublic::Auth {
                map_root: public.map_root,
                scope: public.scope,
                nullifier: public.nullifier,
                binding: public.binding,
            },
            proof: proof?,
        })
    }

    /// Proves that `secret` is behind `owner(secret)`, for `call`.
    pub fn prove_owner(
        &self,
        secret: &DeviceSecret,
        call: &Call,
    ) -> Result<CredentialProof, DeviceError> {
        call.check()?;
        let owner = secret::owner(secret);
        let binding = call.binding(
            verifier::program(CredentialKind::Owner),
            CredentialKind::Owner as u8,
        );
        let statement = Held(Statement::Owner(
            OwnerPublic {
                owner: owner.0,
                binding: binding.0,
            },
            secret.0,
        ));
        let proof = self.prove(&statement.0);
        drop(statement);
        Ok(CredentialProof {
            format: FORMAT,
            public: CredentialPublic::Owner { owner, binding },
            proof: proof?,
        })
    }

    /// Proves auth's statement and owner's digest from one secret: the
    /// joint circuit, timed against auth's budget so a later private
    /// payment's statement is known to fit. No ingress admits it.
    pub fn prove_membership_and_payment(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        name: &[u8],
        call: &Call,
    ) -> Result<JointProof, DeviceError> {
        let joint = joint();
        let auth = auth_public(secret, witness, name, call, &joint.program, JOINT_KIND)?;
        let public = JointPublic {
            map_root: auth.map_root,
            scope: auth.scope,
            nullifier: auth.nullifier,
            owner: secret::owner(secret),
            binding: auth.binding,
        };
        let statement = Held(Statement::Joint(
            auth.circuit(),
            public.owner.0,
            circuit_witness(secret, witness),
        ));
        let proof = self.prove(&statement.0);
        drop(statement);
        Ok(JointProof {
            format: FORMAT,
            public,
            proof: proof?,
        })
    }

    /// `statement`'s proof's bytes, proved in this prover's pool.
    fn prove(&self, statement: &Statement) -> Result<Vec<u8>, DeviceError> {
        self.pool.install(|| {
            let mut finalized = circuits::witness(statement).map_err(prove_error)?;
            let proved = circuits::prove_on::<Blake2sM31MerkleChannel>(
                &CREDENTIAL_PROOF,
                &finalized.circuit,
                &finalized.witness,
                self.masks,
            );
            wipe_values(&mut finalized.witness);
            let (proof, _) = proved.map_err(prove_error)?;
            let proof = verifier::CredentialProof {
                format_version: FORMAT,
                interaction_pow: proof.interaction_pow,
                claimed_sums: proof
                    .claimed_sums
                    .try_into()
                    .map_err(|_| DeviceError::Prove)?,
                stark_proof: proof.stark_proof,
            };
            verifier::encode(&proof).ok_or(DeviceError::Prove)
        })
    }
}

/// Verifies `proof` against `call` as ingress does: its format the
/// registry's, its binding `call`'s under its kind's program, for auth its
/// scope the one the guard named `name` gives, then the proof under the
/// program its kind picks.
pub fn verify(
    proof: &CredentialProof,
    call: &Call,
    name: Option<&[u8]>,
) -> Result<(), DeviceError> {
    if proof.format != FORMAT {
        return Err(DeviceError::Verify);
    }
    let kind = proof.public.kind();
    if *proof.public.binding() != call.binding(verifier::program(kind), kind as u8) {
        return Err(DeviceError::Verify);
    }
    if let CredentialPublic::Auth { scope: proved, .. } = proof.public {
        let name = name.ok_or(DeviceError::Verify)?;
        if scope(&call.space, call.agent, call.instance, name) != Some(proved) {
            return Err(DeviceError::Verify);
        }
    }
    verifier::verify_bytes(kind, &proof.public.words(), &proof.proof)
        .map_err(|_| DeviceError::Verify)
}

/// Verifies a joint proof against `call` and the guard name `name`: its
/// binding and scope, then the proof under the joint circuit's root.
pub fn verify_joint(proof: &JointProof, call: &Call, name: &[u8]) -> Result<(), DeviceError> {
    let joint = joint();
    if proof.format != FORMAT
        || call.check().is_err()
        || proof.public.binding != call.binding(&joint.program, JOINT_KIND)
        || scope(&call.space, call.agent, call.instance, name) != Some(proof.public.scope)
    {
        return Err(DeviceError::Verify);
    }
    let decoded = verifier::decode(&proof.proof).map_err(|_| DeviceError::Verify)?;
    verifier::verify_with(&CREDENTIAL, &joint.root, &proof.public.words(), decoded)
        .map_err(|_| DeviceError::Verify)
}

/// Auth's public digests.
struct AuthDigests {
    map_root: Digest,
    scope: Digest,
    nullifier: Digest,
    binding: Digest,
}

impl AuthDigests {
    fn circuit(&self) -> AuthPublic {
        AuthPublic {
            map_root: self.map_root.0,
            scope: self.scope.0,
            nullifier: self.nullifier.0,
            binding: self.binding.0,
        }
    }
}

/// Auth's public digests for `secret` at `witness`, the guard `name` and
/// `call`, the binding under `program` and `kind`; the witness checked.
fn auth_public(
    secret: &DeviceSecret,
    witness: &AuthWitness,
    name: &[u8],
    call: &Call,
    program: &[u8; 32],
    kind: u8,
) -> Result<AuthDigests, DeviceError> {
    call.check()?;
    let scope = scope(&call.space, call.agent, call.instance, name).ok_or(DeviceError::Config)?;
    if !witness.proves(&secret::member(secret)) {
        return Err(DeviceError::Witness);
    }
    Ok(AuthDigests {
        map_root: witness.root,
        scope,
        nullifier: secret::nullifier(secret, &scope),
        binding: call.binding(program, kind),
    })
}

/// The circuit's witness: the secret's words, the slot, the siblings.
fn circuit_witness(secret: &DeviceSecret, witness: &AuthWitness) -> circuits::AuthWitness {
    circuits::AuthWitness {
        secret: secret.0,
        slot: witness.slot,
        siblings: witness.siblings.map(|sibling| sibling.0),
    }
}

/// A statement whose secret words are zeroized when it is dropped, a
/// prover's panic unwinding included.
struct Held(Statement);

impl Drop for Held {
    fn drop(&mut self) {
        match &mut self.0 {
            Statement::Auth(_, witness) | Statement::Joint(_, _, witness) => {
                witness.secret.zeroize()
            }
            Statement::Owner(_, secret) => secret.zeroize(),
        }
    }
}

/// Overwrites the circuit's private values: every row's but the outputs',
/// which are public.
fn wipe_values(witness: &mut Witness<SecureField>) {
    let zero = SecureField::zero();
    for row in &mut witness.p2 {
        row.input = [zero; 4];
        row.m = [zero; 2];
        row.b = zero;
    }
    for row in &mut witness.qm31 {
        *row = [zero; 4];
    }
    for row in &mut witness.h8 {
        row.acc = zero;
        row.step = zero;
        row.mu = zero;
        row.v = [zero; 2];
        row.out = zero;
    }
    std::hint::black_box(witness);
}

fn prove_error(error: ProveError) -> DeviceError {
    match error {
        ProveError::Witness(_) => DeviceError::Witness,
        _ => DeviceError::Prove,
    }
}

/// The joint circuit's preprocessed root and program id under the
/// registry's format, computed once.
struct Joint {
    root: [u8; 32],
    program: [u8; 32],
}

fn joint() -> &'static Joint {
    static JOINT: OnceLock<Joint> = OnceLock::new();
    JOINT.get_or_init(|| {
        let Blake2sHash(root) = circuits::preprocessed_root::<Blake2sM31MerkleChannel>(
            &CREDENTIAL_PROOF,
            &circuits::circuit(None),
        )
        .expect("the joint circuit's wiring checks");
        let program = vos_pvm_recair_air::credential::program_id(
            FORMAT,
            verifier::PARAMS,
            &verifier::LOG_SIZES,
            &root,
        )
        .expect("a Blake2s-M31 root's words are below p");
        Joint { root, program }
    })
}

/// Whether `core` is one a thread can be pinned to.
fn pinnable(core: usize) -> bool {
    core < libc::CPU_SETSIZE as usize
}

/// Pins the calling thread to `core`, as far as the system allows.
fn pin(core: usize) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `set` is a zeroed `cpu_set_t` the calls below only write
    // within, and `core` is below `CPU_SETSIZE` (`pinnable`).
    unsafe {
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = core;
}
