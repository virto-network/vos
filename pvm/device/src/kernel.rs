//! Device kernels proved under the device profile (`proving.md` §8,
//! `slice-7-mobile.md` pins J and L): a kernel's program, computed from the
//! kernel as a space's ingress computes it, a run of it proved against
//! that program, and auth's statement proved by a device kernel, which
//! ingress takes as it takes auth's credential proof.

use vos_pvm_recair::device::{self as profile, Program};
use vos_wire::credentials::Words;
use zeroize::Zeroize;

use crate::prover::auth_public;
use crate::secret::DeviceSecret;
use crate::{AuthWitness, Call, CredentialProof, CredentialPublic, DeviceError, Prover, scope};

/// The device format's number, the registry's: format 46.
pub const DEVICE_FORMAT: u32 = profile::FORMAT.number;

/// The most memory a device kernel's proof takes, in bytes: PG2's budget,
/// above the auth kernel's peak resident size measured on the gate phone
/// (0.70 GiB). A prover allowing less refuses to prove one.
pub const DEVICE_PEAK_BYTES: u64 = 1 << 30;

/// A device kernel's program under the device format: the chips its code
/// reaches, a log size each and the preprocessed root they commit, all
/// computed from the kernel, never taken from a proof. A branch-free kernel
/// proves every witness under its one program.
pub struct DeviceProgram(Program);

impl DeviceProgram {
    /// Kernel `kernel`'s program, its log sizes those its run on
    /// `reference` needs: [`DeviceError::Prove`] when the kernel does not
    /// run to its halt on it, or needs more than the format's shape.
    pub fn install(kernel: &[u8], reference: &[u8]) -> Result<Self, DeviceError> {
        Program::install(kernel, reference)
            .map(Self)
            .map_err(|_| DeviceError::Prove)
    }

    /// The program of a device kernel of auth's statement, as a space's
    /// ingress computes it from the installed kernel: its reference run on
    /// auth's public reference statement.
    pub fn auth(kernel: &[u8]) -> Result<Self, DeviceError> {
        Program::auth(kernel)
            .map(Self)
            .map_err(|_| DeviceError::Prove)
    }

    /// Its id, which a binding names.
    pub fn id(&self) -> &[u8; 32] {
        self.0.id()
    }

    /// Each chip's log size, in the device order.
    pub fn log_sizes(&self) -> &[u32] {
        self.0.log_sizes()
    }

    /// The chips, a device mask.
    pub fn chips(&self) -> u32 {
        self.0.program().active
    }

    /// Verifies `proof`'s bytes under this program against its io-hash,
    /// which a caller holding the statement's words computes itself.
    pub fn verify(&self, proof: &DeviceProof) -> Result<(), DeviceError> {
        if proof.format != DEVICE_FORMAT {
            return Err(DeviceError::Verify);
        }
        self.0
            .verify(&proof.io, &proof.proof)
            .map_err(|_| DeviceError::Verify)
    }
}

/// The io-hash a device kernel of auth's statement states for its public
/// arguments `public` (the SCALE encoding of auth's `CredentialPublic`):
/// `H_io` of them, no output, no root; `None` past `H_io`'s bound.
pub fn auth_io(public: &[u8]) -> Option<[u8; 32]> {
    profile::auth_io(public)
}

/// A device kernel's proof: the io-hash its run states and the proof's
/// bytes, which hold no io-hash (a verifier takes it from the words it
/// holds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceProof {
    pub format: u32,
    pub io: [u8; 32],
    pub proof: Vec<u8>,
}

impl Prover {
    /// `program`'s kernel run on `arguments`, through its witness input,
    /// proved under the device format in this prover's pool. A run that
    /// does not halt, or needs more rows than the program's shape, is
    /// [`DeviceError::Prove`]; an allowance below [`DEVICE_PEAK_BYTES`] is
    /// [`DeviceError::Memory`].
    pub fn prove_kernel(
        &self,
        program: &DeviceProgram,
        arguments: &[u8],
    ) -> Result<DeviceProof, DeviceError> {
        if self.max_memory < DEVICE_PEAK_BYTES {
            return Err(DeviceError::Memory);
        }
        self.pool.install(|| {
            let (proof, _) = program
                .0
                .prove(arguments, self.masks)
                .map_err(|_| DeviceError::Prove)?;
            Ok(DeviceProof {
                format: DEVICE_FORMAT,
                io: proof.io,
                proof: profile::encode(&proof.proof).ok_or(DeviceError::Prove)?,
            })
        })
    }

    /// Proves auth's statement with device kernel `program`: `secret`'s
    /// member holds the leaf `witness` places under its root, and its
    /// nullifier in the scope of the guard named `name`, for `call`, the
    /// binding naming the program. The witness is checked first, as
    /// [`Prover::prove_auth`] checks it. The proof is what a `Credentialed`
    /// request carries under the device format.
    pub fn prove_device_auth(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        name: &[u8],
        call: &Call,
        program: &DeviceProgram,
    ) -> Result<CredentialProof, DeviceError> {
        let public = auth_public(secret, witness, name, call, program.id(), 0)?;
        let bytes = profile::auth_public(
            &public.map_root.to_bytes(),
            &public.scope.to_bytes(),
            &public.nullifier.to_bytes(),
            &public.binding.to_bytes(),
        );
        let siblings: [Words; vos_wire::credentials::DEPTH] =
            witness.siblings.map(|sibling| sibling.0);
        let mut arguments = profile::auth_arguments(&siblings, &secret.0, witness.slot, &bytes);
        let proved = self.prove_kernel(program, &arguments);
        arguments.zeroize();
        let proof = proved?;
        if Some(proof.io) != profile::auth_io(&bytes) {
            return Err(DeviceError::Prove);
        }
        Ok(CredentialProof {
            format: DEVICE_FORMAT,
            public: CredentialPublic::Auth {
                map_root: public.map_root,
                scope: public.scope,
                nullifier: public.nullifier,
                binding: public.binding,
            },
            proof: proof.proof,
        })
    }
}

/// Verifies a device proof of auth's statement against `call` as ingress
/// does: its format the device format, its binding `call`'s under
/// `program`'s id, its scope the one the guard named `name` gives, then the
/// proof under `program` against the io-hash of its words.
pub fn verify_device(
    proof: &CredentialProof,
    call: &Call,
    name: &[u8],
    program: &DeviceProgram,
) -> Result<(), DeviceError> {
    let CredentialPublic::Auth {
        map_root,
        scope: proved,
        nullifier,
        binding,
    } = proof.public
    else {
        return Err(DeviceError::Verify);
    };
    if proof.format != DEVICE_FORMAT
        || call.check().is_err()
        || binding != call.binding(program.id(), 0)
        || scope(&call.space, call.agent, call.instance, name) != Some(proved)
    {
        return Err(DeviceError::Verify);
    }
    let bytes = profile::auth_public(
        &map_root.to_bytes(),
        &proved.to_bytes(),
        &nullifier.to_bytes(),
        &binding.to_bytes(),
    );
    let io = profile::auth_io(&bytes).ok_or(DeviceError::Verify)?;
    program
        .0
        .verify(&io, &proof.proof)
        .map_err(|_| DeviceError::Verify)
}
