//! A device program's verifier: its id, a proof's bytes and their check.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm_final_verifier::masking::MaskedFormat;
use vos_pvm_final_verifier::masking::MaskedProof;
use vos_pvm_proof::format::Format;

use super::{DeviceProgramId, Hasher, MAX_PROOF_BYTES, Refusal};

use crate::masked::{DeviceProgram, DeviceProof, device_format, verify_device_in};

/// The domain a program id hashes first.
const PROGRAM_DOMAIN: &[u8] = b"vos/device/program/v1";

/// A program's masked format, its log sizes and words left out: computed
/// once, at its install ([`masked`]).
pub(super) type Masked = MaskedFormat<'static>;

/// `program`'s masked format under `format`, its log sizes and words left
/// for each verification to fill in from the program.
pub(super) fn masked(format: &Format, program: &DeviceProgram<Hasher>) -> Option<Masked> {
    let header = program.header();
    let (masked, _) = device_format(format, program, &header)?;
    Some(MaskedFormat {
        log_sizes: &[],
        program: &[],
        ..masked
    })
}

/// A device program as its verifier keeps it: the program, its masked
/// format and the id.
#[derive(Clone, Debug)]
pub struct Verifier {
    pub(super) format: Format,
    pub(super) program: DeviceProgram<Hasher>,
    pub(super) id: DeviceProgramId,
    pub(super) masked: Masked,
}

impl Verifier {
    /// The verifier of the program `release` names, from its CPU's column
    /// words `cpu` and its preprocessed root `circuit` as a build with the
    /// prover computed them ([`Verifier::cpu`], [`Verifier::circuit`]): no
    /// prover, no transpiler and no tree committed, each part held to the
    /// release's id, which hashes them all. What a build without the
    /// `prover` feature, ingress's, verifies with. Refused when this build
    /// verifies no such format, the kernel's layout is not a device's, the
    /// chips are not a device mask or the CPU's words name no column, a log
    /// size is under its floor or past the format's ceiling, or the id is
    /// not the release's.
    pub fn of_release(
        release: &super::Release,
        cpu: [u64; vos_pvm_proof::chips::CPU_COLUMN_WORDS],
        circuit: [u8; 32],
    ) -> Result<Self, super::Error> {
        use super::Error;
        let format = *crate::format(release.format).ok_or(Error::Format(release.format))?;
        let layout = vos_pvm_proof::device::DeviceLayout::of_program(&release.kernel)
            .filter(|layout| layout.is_disjoint())
            .ok_or(Error::Layout)?;
        if !vos_pvm_proof::device::is_device_mask(release.chips) {
            return Err(Error::Chips);
        }
        let program = DeviceProgram {
            active: release.chips,
            cpu: vos_pvm_proof::chips::CpuColumns::from_words(cpu).ok_or(Error::Chips)?,
            log_sizes: release.log_sizes.clone(),
            layout,
            circuit: Blake2sHash(circuit),
        };
        let masked = masked(&format, &program).ok_or(Error::Sizes)?;
        let id = DeviceProgramId::of(&format, &program);
        if id.0 != release.id {
            return Err(Error::IdMismatch);
        }
        Ok(Self {
            format,
            program,
            id,
            masked,
        })
    }

    /// Its CPU's column words, which [`Verifier::of_release`] takes.
    pub fn cpu(&self) -> [u64; vos_pvm_proof::chips::CPU_COLUMN_WORDS] {
        self.program.cpu.words()
    }

    /// Its preprocessed root, which [`Verifier::of_release`] takes.
    pub fn circuit(&self) -> [u8; 32] {
        self.program.circuit.0
    }

    /// Its id, which a binding names.
    pub fn id(&self) -> &DeviceProgramId {
        &self.id
    }

    /// The device format it verifies under.
    pub fn format(&self) -> &Format {
        &self.format
    }

    /// Verifies the proof in `bytes` ([`decode`]) of this program's kernel
    /// stating the io-hash `io`.
    ///
    /// The crate runs with std and is not linted panic-free: a panic in the
    /// verification is caught and refused as [`Refusal::Panic`], in a build
    /// that unwinds (the workspace's profiles do; one built with
    /// `panic = "abort"` aborts). The fuzz targets `device_verify_bytes` and
    /// `device_verify_mutate` hold it to no panic.
    pub fn verify(&self, io: &[u8; 32], bytes: &[u8]) -> Result<(), Refusal> {
        verify(&self.format, &self.program, &self.masked, io, bytes)
    }
}

pub(super) fn verify(
    format: &Format,
    program: &DeviceProgram<Hasher>,
    masked: &Masked,
    io: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Refusal> {
    // Nothing the verification holds outlives it: a panic leaves no state
    // half-changed behind.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_unguarded(format, program, masked, io, bytes)
    }))
    .unwrap_or(Err(Refusal::Panic))
}

fn verify_unguarded(
    format: &Format,
    program: &DeviceProgram<Hasher>,
    masked: &Masked,
    io: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Refusal> {
    let header = program.header();
    let masked = MaskedFormat {
        log_sizes: &program.log_sizes,
        program: &header,
        ..*masked
    };
    precheck(format, &masked, io, bytes)?;
    let proof = DeviceProof {
        io: *io,
        proof: decode(format, bytes)?,
    };
    verify_device_in::<Blake2sM31MerkleChannel>(&masked, program, proof).map_err(Refusal::of)
}

/// A proof's encoding's leading fields, as [`Wire`] and its STARK proof
/// start: what the interaction PoW is checked over.
#[derive(serde::Deserialize)]
struct Head {
    format_version: u32,
    interaction_pow: u64,
    #[allow(dead_code, reason = "read past, to reach the commitments")]
    claimed_sums: Vec<stwo::core::fields::qm31::SecureField>,
    #[allow(dead_code, reason = "read past, to reach the commitments")]
    config: stwo::core::pcs::PcsConfig,
    commitments: Vec<Blake2sHash>,
}

/// The device verifier's pre-check, before the proof is decoded whole: its
/// length within [`MAX_PROOF_BYTES`], its leading fields read, its format
/// `format`, and its interaction PoW holding over the program `masked`
/// names, its roots and `io` as the verifier's transcript mixes them. A proof it refuses,
/// the verifier refuses; well-formed junk that has not ground the
/// interaction PoW is refused here, at a small fraction of a decode.
fn precheck(
    format: &Format,
    masked: &MaskedFormat<'_>,
    io: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Refusal> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Refusal::Length);
    }
    let (head, _): (Head, &[u8]) = postcard::take_from_bytes(bytes).map_err(|_| Refusal::Decode)?;
    if head.format_version != format.number {
        return Err(Refusal::Format);
    }
    let public = vos_pvm_proof::masked::device_public_values(io);
    let holds = vos_pvm_final_verifier::masking::interaction_pow_holds::<Blake2sM31MerkleChannel>(
        masked,
        &public,
        &head.commitments,
        head.interaction_pow,
    );
    holds.then_some(()).ok_or(Refusal::InteractionPow)
}

impl DeviceProgramId {
    /// The id of `program` under `format`: BLAKE2b-256 of the domain, the
    /// format's number, its parameters (log blowup, queries, PoW, fold
    /// step, log last layer, interaction PoW, `log h`), the chips, the count
    /// of log sizes and each, when the CPU is cut its column words (eight
    /// little-endian bytes each), the word ledger's tag (eight
    /// little-endian bytes, `DEVICE_WORD_MEMORY_TAG`), and the preprocessed
    /// root, every other integer four little-endian bytes.
    pub fn of(format: &Format, program: &DeviceProgram<Hasher>) -> Self {
        let params = &format.params;
        let log_mask_rows = format.masking.map_or(0, |masking| masking.log_mask_rows);
        let mut hash = Blake2b::<U32>::new();
        hash.update(PROGRAM_DOMAIN);
        for word in [
            format.number,
            params.log_blowup,
            params.n_queries as u32,
            params.pow_bits,
            params.fold_step,
            params.log_last_layer,
            params.interaction_pow_bits,
            log_mask_rows,
            program.active,
            program.log_sizes.len() as u32,
        ]
        .into_iter()
        .chain(program.log_sizes.iter().copied())
        {
            hash.update(word.to_le_bytes());
        }
        if program.cpu != vos_pvm_proof::chips::CpuColumns::ALL {
            for word in program.cpu.words() {
                hash.update(word.to_le_bytes());
            }
        }
        hash.update(crate::masked::DEVICE_WORD_MEMORY_TAG.to_le_bytes());
        let Blake2sHash(root) = program.circuit;
        hash.update(root);
        Self(hash.finalize().into())
    }
}

/// The canonical encoding of a device proof's masked part.
#[derive(serde::Deserialize)]
struct Wire {
    format_version: u32,
    interaction_pow: u64,
    claimed_sums: Vec<stwo::core::fields::qm31::SecureField>,
    stark_proof: stwo::core::proof::StarkProof<Hasher>,
}

/// [`Wire`] borrowed from a proof, for its encoding: the same bytes, no
/// copy of the proof.
#[derive(serde::Serialize)]
struct WireRef<'a> {
    format_version: u32,
    interaction_pow: u64,
    claimed_sums: &'a [stwo::core::fields::qm31::SecureField],
    stark_proof: &'a stwo::core::proof::StarkProof<Hasher>,
}

impl<'a> WireRef<'a> {
    fn of(format: &Format, proof: &'a MaskedProof<Hasher>) -> Self {
        Self {
            format_version: format.number,
            interaction_pow: proof.interaction_pow,
            claimed_sums: &proof.claimed_sums,
            stark_proof: &proof.stark_proof,
        }
    }
}

/// A postcard flavor that compares each byte written with `expected`'s at
/// its place, and stops at the first that differs: whether an encoding is
/// `expected`, with nothing allocated.
struct Matches<'a> {
    expected: &'a [u8],
    at: usize,
}

impl postcard::ser_flavors::Flavor for Matches<'_> {
    type Output = bool;

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        if self.expected.get(self.at) != Some(&byte) {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.at += 1;
        Ok(())
    }

    fn finalize(self) -> postcard::Result<bool> {
        Ok(self.at == self.expected.len())
    }
}

/// `proof`'s bytes under the device format `format`, the one encoding
/// [`decode`] reads; `None` when it cannot be encoded.
pub fn encode(format: &Format, proof: &MaskedProof<Hasher>) -> Option<Vec<u8>> {
    postcard::to_allocvec(&WireRef::of(format, proof)).ok()
}

/// The most a proof's decode holds in memory, a multiple of its bytes:
/// [`Scan`] counts it before the decode. An honest device proof's values
/// take about as much memory as their encoding (a field element's 16 bytes
/// from its limbs' varints), its vectors' headers a few percent more; junk
/// of nested empty vectors would take 24 bytes a byte.
const DECODE_MEMORY: usize = 3;

/// A sequence of `T` read past, its elements decoded one at a time and
/// dropped: the memory its decode would hold, the elements' and each
/// one's own, counted with nothing kept.
struct Seq<T>(usize, core::marker::PhantomData<T>);

/// The memory a value's decode holds beyond itself: its sequences'.
trait Held {
    fn held(&self) -> usize;
}

macro_rules! held_by_value {
    ($($type:ty),*) => {$(
        impl Held for $type {
            fn held(&self) -> usize {
                0
            }
        }
    )*};
}
held_by_value!(
    u32,
    u64,
    stwo::core::fields::qm31::SecureField,
    stwo::core::fields::m31::BaseField,
    Blake2sHash,
    stwo::core::pcs::PcsConfig
);

impl<T> Held for Seq<T> {
    fn held(&self) -> usize {
        self.0
    }
}

impl<'de, T: serde::Deserialize<'de> + Held> serde::Deserialize<'de> for Seq<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit<T>(core::marker::PhantomData<T>);
        impl<'de, T: serde::Deserialize<'de> + Held> serde::de::Visitor<'de> for Visit<T> {
            type Value = Seq<T>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a sequence")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Seq<T>, A::Error> {
                let mut held = core::mem::size_of::<Vec<T>>();
                while let Some(element) = seq.next_element::<T>()? {
                    held = held
                        .saturating_add(core::mem::size_of::<T>())
                        .saturating_add(element.held());
                }
                Ok(Seq(held, core::marker::PhantomData))
            }
        }
        deserializer.deserialize_seq(Visit(core::marker::PhantomData))
    }
}

/// A FRI layer's proof, as [`Wire`]'s read past.
#[derive(serde::Deserialize)]
struct LayerScan {
    fri_witness: Seq<stwo::core::fields::qm31::SecureField>,
    decommitment: Seq<Blake2sHash>,
    #[allow(dead_code, reason = "read past")]
    commitment: Blake2sHash,
}

impl Held for LayerScan {
    fn held(&self) -> usize {
        self.fri_witness.0.saturating_add(self.decommitment.0)
    }
}

/// [`Wire`], read past: its fields in its order, every sequence a [`Seq`].
#[derive(serde::Deserialize)]
struct Scan {
    #[allow(dead_code, reason = "read past")]
    format_version: u32,
    #[allow(dead_code, reason = "read past")]
    interaction_pow: u64,
    claimed_sums: Seq<stwo::core::fields::qm31::SecureField>,
    #[allow(dead_code, reason = "read past")]
    config: stwo::core::pcs::PcsConfig,
    commitments: Seq<Blake2sHash>,
    sampled_values: Seq<Seq<Seq<stwo::core::fields::qm31::SecureField>>>,
    decommitments: Seq<Seq<Blake2sHash>>,
    queried_values: Seq<Seq<Seq<stwo::core::fields::m31::BaseField>>>,
    #[allow(dead_code, reason = "read past")]
    proof_of_work: u64,
    first_layer: LayerScan,
    inner_layers: Seq<LayerScan>,
    last_layer: Seq<stwo::core::fields::qm31::SecureField>,
    #[allow(dead_code, reason = "read past")]
    log_size: u32,
}

impl Scan {
    /// The memory the decode of the proof it read would hold.
    fn held(&self) -> usize {
        [
            self.claimed_sums.0,
            self.commitments.0,
            self.sampled_values.0,
            self.decommitments.0,
            self.queried_values.0,
            self.first_layer.held(),
            self.inner_layers.0,
            self.last_layer.0,
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }
}

/// The proof in `bytes` under the device format `format`: at most
/// [`MAX_PROOF_BYTES`], read whole and canonical (re-encoded, the same
/// bytes, compared as they are written). Read past first, nothing kept, and
/// refused when its decode would hold more than [`DECODE_MEMORY`] times its
/// bytes.
pub fn decode(format: &Format, bytes: &[u8]) -> Result<MaskedProof<Hasher>, Refusal> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Refusal::Length);
    }
    let (scan, _): (Scan, &[u8]) = postcard::take_from_bytes(bytes).map_err(|_| Refusal::Decode)?;
    if scan.held() > DECODE_MEMORY.saturating_mul(bytes.len()) {
        return Err(Refusal::Decode);
    }
    let (wire, rest): (Wire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| Refusal::Decode)?;
    if wire.format_version != format.number {
        return Err(Refusal::Format);
    }
    let proof = MaskedProof {
        interaction_pow: wire.interaction_pow,
        claimed_sums: wire.claimed_sums,
        stark_proof: wire.stark_proof,
    };
    let canonical = rest.is_empty()
        && postcard::serialize_with_flavor(
            &WireRef::of(format, &proof),
            Matches {
                expected: bytes,
                at: 0,
            },
        )
        .unwrap_or(false);
    if !canonical {
        return Err(Refusal::Decode);
    }
    Ok(proof)
}

/// The io-hash a device kernel states for its claim `claim`, its public
/// arguments' encoding: `H_io` of `claim`, no output and no root. `None`
/// past `H_io`'s bound.
pub fn claim_io(claim: &[u8]) -> Option<[u8; 32]> {
    vos_pvm_precompiles::compute_device_io_hash(claim, &[], &[])
}

#[cfg(test)]
mod tests {
    use super::super::FORMAT;
    use super::*;

    /// A well-formed proof of `n` empty sampled columns and nothing else: a
    /// byte each, 24 bytes each once decoded.
    fn hollow(n: usize) -> Vec<u8> {
        let mut bytes = postcard::to_allocvec(&(FORMAT.number, 0u64, 0u8)).unwrap();
        bytes.extend(postcard::to_allocvec(&FORMAT.pcs_config()).unwrap());
        bytes.push(0);
        bytes.extend(postcard::to_allocvec(&n).unwrap());
        bytes.extend(core::iter::repeat_n(0, n));
        bytes.extend([0, 0, 0, 0, 0]);
        bytes.extend([0; 32]);
        bytes.extend([0, 0, 0]);
        bytes
    }

    /// Junk whose decode would hold far more than its bytes, nested empty
    /// vectors, is refused before it is decoded: it decodes whole as a
    /// proof's wire, at 24 bytes a byte, where the read past it holds none.
    #[test]
    fn a_decode_holds_at_most_a_few_times_its_bytes() {
        let bytes = hollow(1 << 20);
        let (wire, rest): (Wire, &[u8]) = postcard::take_from_bytes(&bytes).expect("a wire");
        assert!(rest.is_empty());
        assert_eq!(wire.stark_proof.0.sampled_values.len(), 1 << 20);
        drop(wire);
        assert!(matches!(decode(&FORMAT, &bytes), Err(Refusal::Decode)));
        let (scan, _): (Scan, &[u8]) = postcard::take_from_bytes(&bytes).expect("a scan");
        assert!(scan.held() > 24 * bytes.len());
    }

    /// A decode refuses bytes past the cap, of another format, cut or with
    /// a byte more.
    #[test]
    fn a_decode_refuses_what_is_not_one_proof() {
        assert!(matches!(
            decode(&FORMAT, &vec![0; MAX_PROOF_BYTES + 1]),
            Err(Refusal::Length)
        ));
        assert!(decode(&FORMAT, &[]).is_err());
        let mut other = Vec::new();
        other.extend_from_slice(&postcard::to_allocvec(&44u32).unwrap());
        assert!(decode(&FORMAT, &other).is_err());
    }
}
