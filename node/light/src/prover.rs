//! The prover of proven calls over a [`Call`]: a stock kernel's claim
//! computed from the secret, the witness and the call; the witness checked
//! before any proving; the kernel's run proved under the device format
//! against the program its release artifact names, its masks the operating
//! system's.

use scale::Encode;
use vos_wire::abi::cap;
use vos_wire::credentials::{AuthClaim, OwnerClaim, claim_binding};
use zeroize::Zeroize;

use crate::kernel::{DEVICE_FORMAT, DeviceProgram, claim_io};
use crate::secret::{self, DeviceSecret};
use crate::threads::thread_pool;
use crate::{AuthWitness, Call, DeviceError, scope};

use vos_pvm_recair::masked::MaskRng;

/// The most memory a device kernel's proof takes, in bytes: the device
/// budget, above the stock auth kernel's peak resident size measured on
/// the gate phone (0.70 GiB). A configuration allowing less is refused.
pub const PEAK_BYTES: u64 = 1 << 30;

/// A pool thread's stack, in bytes: the prover's nested joins overflowed
/// rayon's default 2 MiB on a device kernel's proof at blowup 8 on 8
/// threads, about once in 18 proofs, and never in 24 at this size.
pub const STACK_BYTES: usize = 16 << 20;

/// How a [`Prover`]'s pool spreads its work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Threads {
    /// By core class: the cores this thread may run on, grouped by the
    /// rate the system states for each (its capacity, else its highest
    /// clock), each class's rate measured on one of its cores. An even
    /// split over cores runs at its slowest core's rate times their number,
    /// so the work goes to the fastest classes whose count times the
    /// slowest kept rate is greatest: every class, one unpinned thread a
    /// core, when that is all of them; else one thread pinned to each core
    /// of the classes kept. One thread a core where the system states no
    /// classes. On x86's four performance and four efficient cores the even
    /// split over both is about 1.3 times the performance cores alone; on
    /// the Fairphone 6 the A720s alone were about 1.2 times the split over
    /// them and the A520s (measured).
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

/// A proven call's proof: its device format, the kernel's claim (its
/// public arguments, the call's binding last) and the proof's bytes, what a
/// `Credentialed` request carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proven {
    pub format: u32,
    pub claim: Vec<u8>,
    pub proof: Vec<u8>,
}

/// The prover: its thread pool, its masks' source and its memory
/// allowance.
pub struct Prover {
    pub(crate) pool: rayon::ThreadPool,
    pub(crate) masks: MaskRng,
}

impl Prover {
    /// A prover as `config` says: its pool built, its memory allowance at
    /// least [`PEAK_BYTES`].
    pub fn new(config: ProverConfig) -> Result<Self, DeviceError> {
        if config.max_memory < PEAK_BYTES {
            return Err(DeviceError::Memory);
        }
        Ok(Self {
            pool: thread_pool(&config.threads)?,
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

    /// Proves with the stock `auth` kernel `program` that `secret`'s member
    /// holds the leaf `witness` places under its root, and its nullifier in
    /// the scope of the guard named `name`, for `call`, the binding naming
    /// the program. The witness is checked first: a path that does not
    /// place the member's leaf under its root is [`DeviceError::Witness`],
    /// before any proving.
    pub fn prove_auth(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        name: &[u8],
        call: &Call,
        program: &DeviceProgram,
    ) -> Result<Proven, DeviceError> {
        call.check()?;
        let scope =
            scope(&call.space, call.agent, call.instance, name).ok_or(DeviceError::Config)?;
        if !witness.proves(&secret::member(secret)) {
            return Err(DeviceError::Witness);
        }
        let claim = AuthClaim {
            map_root: witness.root.to_bytes(),
            scope: scope.to_bytes(),
            nullifier: secret::nullifier(secret, &scope).to_bytes(),
            binding: call.binding(program.id()).to_bytes(),
        }
        .encode();
        // The arguments as the kernel reads them in place: the path's 32
        // siblings and its slot's eight bytes, the secret, the claim.
        let mut arguments = Vec::with_capacity(1032 + 32 + claim.len());
        for sibling in &witness.siblings {
            arguments.extend_from_slice(&sibling.to_bytes());
        }
        arguments.extend_from_slice(&u64::from(witness.slot).to_le_bytes());
        self.prove_stock(program, secret, claim, arguments)
    }

    /// Proves with the stock `owner` kernel `program` that `secret` is
    /// behind `owner(secret)`, for `call`.
    pub fn prove_owner(
        &self,
        secret: &DeviceSecret,
        call: &Call,
        program: &DeviceProgram,
    ) -> Result<Proven, DeviceError> {
        call.check()?;
        let claim = OwnerClaim {
            owner: secret::owner(secret).to_bytes(),
            binding: call.binding(program.id()).to_bytes(),
        }
        .encode();
        self.prove_stock(program, secret, claim, Vec::new())
    }

    /// A stock kernel's proof: `program` run on `arguments`, then the
    /// secret, then `claim`, the arguments zeroized once proved, the run's
    /// io-hash checked to be the claim's. Their room is reserved before the
    /// secret is written, so no reallocation frees a block holding it.
    fn prove_stock(
        &self,
        program: &DeviceProgram,
        secret: &DeviceSecret,
        claim: Vec<u8>,
        mut arguments: Vec<u8>,
    ) -> Result<Proven, DeviceError> {
        arguments.reserve_exact(32 + claim.len());
        secret.append_to(&mut arguments);
        arguments.extend_from_slice(&claim);
        let proved = self.prove_kernel(program, &arguments);
        arguments.zeroize();
        let proof = proved?;
        if Some(proof.io) != claim_io(&claim) {
            return Err(DeviceError::Prove);
        }
        Ok(Proven {
            format: DEVICE_FORMAT,
            claim,
            proof: proof.proof,
        })
    }
}

/// Verifies `proof` against `call` under the kernel `program` as ingress
/// does: its format the device format, its claim within its cap, `call`'s
/// arguments within their
/// cap, the claim's binding `call`'s under the program's id, for a stock
/// auth claim (`name` given) its scope the one the guard named `name`
/// gives, then the proof under the program against the claim's io-hash.
pub fn verify(
    proof: &Proven,
    call: &Call,
    program: &DeviceProgram,
    name: Option<&[u8]>,
) -> Result<(), DeviceError> {
    if proof.format != DEVICE_FORMAT || proof.claim.len() > cap::CLAIM || call.check().is_err() {
        return Err(DeviceError::Verify);
    }
    let binding = claim_binding(&proof.claim).ok_or(DeviceError::Verify)?;
    if *binding != call.binding(program.id()).to_bytes() {
        return Err(DeviceError::Verify);
    }
    if let Some(name) = name {
        let claim =
            <AuthClaim as scale::Decode>::decode_exact(&proof.claim).ok_or(DeviceError::Verify)?;
        let scope =
            scope(&call.space, call.agent, call.instance, name).ok_or(DeviceError::Verify)?;
        if claim.scope != scope.to_bytes() {
            return Err(DeviceError::Verify);
        }
    }
    let io = claim_io(&proof.claim).ok_or(DeviceError::Verify)?;
    program.verify_io(&io, &proof.proof)
}
