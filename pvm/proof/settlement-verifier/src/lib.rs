//! Verify-only Poseidon2-over-M31 stwo verifier — the on-chain settlement
//! verifier for native recursion.
//!
//! The native-recursion settlement verifier — stwo's `verify()` driven by a
//! custom Poseidon2-M31 Merkle channel, plus the in-AIR constraint evaluation
//! the verifier re-runs at the OODS point — built for `wasm32-unknown-unknown`
//! AND the JAM PVM (`riscv64em-vos`) target with NO blst and NO rayon. It
//! executes and ACCEPTS real proofs on the PVM (see `pvm/proof/tests/settle_run.rs`).
//!
//! It carries only the VERIFY side of the recursion stack (promoted from the
//! prover-side `pvm/proof/tests/recursion_common/mod.rs`):
//!   * the `MerkleHasherLifted` (`P2MerkleHasher`) the inner proofs are
//!     committed under,
//!   * the Poseidon2-M31 Fiat-Shamir `Channel` (`Poseidon2M31Channel`) + its
//!     `MerkleChannel` (`P2MerkleChannel`).
//!
//! It DROPS everything prover-side: the `BackendForChannel`/`CpuBackend`
//! commitment ops, the SIMD→CPU transplant, the host trace recorder, and any
//! `std`/`rayon`/`blst` dependency (the latter only ever entered transitively
//! via `vos_pvm`, which this crate does not depend on).
//!
//! The permutation and its modes come from `vos-poseidon2`, as the prover's
//! do; this crate adapts them to Stwo's hasher and channel traits.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use num_traits::One;
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{verify, VerificationError};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};
use vos_poseidon2::{LeafSponge, Transcript, M31};

fn word(value: BaseField) -> M31 {
    M31::from(value.0)
}

fn base(value: M31) -> BaseField {
    BaseField::from_u32_unchecked(value.value())
}

// ── The Merkle hasher and the channel ─────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct P2Hash(pub [BaseField; 8]);

impl core::fmt::Display for P2Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P2Hash({:?})", self.0.map(|m| m.0))
    }
}
impl Hash for P2Hash {}

/// The leaf sponge and the node compression, as Stwo's Merkle hasher.
#[derive(Clone, Debug, Default)]
pub struct P2MerkleHasher {
    sponge: LeafSponge,
}

// `StarkProof<H>`'s derive bounds require `H: Serialize + Deserialize`, but the
// hasher VALUE is never serialized — only `H::Hash` (the committed roots) is. So
// these are dummy round-trippable impls (serialize 0 fields, deserialize to
// `default()`), byte-identical to the prover's `vos_pvm_proof::poseidon2::P2MerkleHasher`
// so a `StarkProof` produced there decodes here.
impl serde::Serialize for P2MerkleHasher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::ser::SerializeStruct::end(serializer.serialize_struct("P2MerkleHasher", 0)?)
    }
}
impl<'de> serde::Deserialize<'de> for P2MerkleHasher {
    fn deserialize<D: serde::Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::default())
    }
}
impl MerkleHasherLifted for P2MerkleHasher {
    type Hash = P2Hash;
    fn hash_children((left, right): (P2Hash, P2Hash)) -> P2Hash {
        P2Hash(vos_poseidon2::compress(&left.0.map(word), &right.0.map(word)).map(base))
    }
    fn update_leaf(&mut self, column_values: &[BaseField]) {
        self.sponge
            .absorb(column_values.iter().map(|&value| word(value)));
    }
    fn finalize(self) -> P2Hash {
        P2Hash(self.sponge.finalize().map(base))
    }
}

/// `vos_poseidon2`'s transcript as Stwo's channel. Verify-side only — no
/// recorder (that is prover/test instrumentation).
#[derive(Clone, Debug, Default)]
pub struct Poseidon2M31Channel {
    transcript: Transcript,
}

impl Poseidon2M31Channel {
    fn absorb(&mut self, values: &[M31]) {
        self.transcript.absorb(values, &mut ());
    }

    fn squeeze8(&mut self) -> [BaseField; 8] {
        self.transcript.squeeze(&mut ()).map(base)
    }
}

impl Channel for Poseidon2M31Channel {
    const BYTES_PER_HASH: usize = 32;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        self.transcript.verify_pow_nonce(n_bits, nonce, &mut ())
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let words: Vec<M31> = data
            .iter()
            .flat_map(|&value| vos_poseidon2::u32_limbs(value))
            .collect();
        self.absorb(&words);
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let words: Vec<M31> = felts
            .iter()
            .flat_map(|felt| felt.to_m31_array().map(word))
            .collect();
        self.absorb(&words);
    }

    fn mix_u64(&mut self, value: u64) {
        self.absorb(&vos_poseidon2::u64_limbs(value));
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let f = self.squeeze8();
        SecureField::from_m31_array([f[0], f[1], f[2], f[3]])
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut out = Vec::with_capacity(n_felts);
        while out.len() < n_felts {
            let f = self.squeeze8();
            out.push(SecureField::from_m31_array([f[0], f[1], f[2], f[3]]));
            if out.len() < n_felts {
                out.push(SecureField::from_m31_array([f[4], f[5], f[6], f[7]]));
            }
        }
        out
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        self.squeeze8().iter().map(|m| m.0).collect()
    }
}

#[derive(Default)]
pub struct P2MerkleChannel;
impl MerkleChannel for P2MerkleChannel {
    type C = Poseidon2M31Channel;
    type H = P2MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        channel.absorb(&root.0.map(word));
    }
}

// ── Configs + the verify entry (forces monomorphization of the verify path) ─

/// MOBILE: blowup 4 (log_blowup_factor=2), 38 queries, 20-bit PoW.
pub fn mobile_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    }
}

/// The settlement verify entry: run stwo's `verify()` driven by the custom
/// Poseidon2-M31 Merkle channel.  Concrete in `P2MerkleChannel`, so building
/// this crate for a target MONOMORPHIZES the entire verify path (FRI + Merkle
/// decommit + OODS composition re-eval) for the custom M31-algebraic stack.
pub fn verify_segment(
    components: &[&dyn Component],
    channel: &mut Poseidon2M31Channel,
    commitment_scheme: &mut CommitmentSchemeVerifier<P2MerkleChannel>,
    proof: StarkProof<P2MerkleHasher>,
) -> Result<(), VerificationError> {
    verify::<P2MerkleChannel>(components, channel, commitment_scheme, proof)
}

// ── A concrete end-to-end settlement verify (proof bytes → accept/reject) ──
//
// The trivial settlement AIR `x·(x−1)=0`: a single boolean main column. Its
// constraint count is irrelevant to verify COST (FRI verify + Poseidon2 Merkle
// decommit + OODS dominate, independent of the AIR), so it is a representative
// stand-in for measuring on-chain settlement-verify cycles without carrying the
// full canonical segment AIR. MUST stay identical to the prover-side `BoolEval`
// in `pvm/proof/tests/settle_fixture.rs` (same `FIXTURE_LOG`, same constraint), or
// the verifier replays a different AIR and rejects the honest proof.

/// Trace log-size of the embedded settlement-proof fixture.
pub const FIXTURE_LOG: u32 = 5;

struct BoolEval;
impl FrameworkEval for BoolEval {
    fn log_size(&self) -> u32 {
        FIXTURE_LOG
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        FIXTURE_LOG + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let x = eval.next_trace_mask();
        eval.add_constraint(x.clone() * (x - E::F::one()));
        eval
    }
}

/// Why a settlement proof was not accepted.
#[derive(Debug)]
pub enum SettlementError {
    /// The bytes are not a postcard-encoded proof.
    Decode(postcard::Error),
    /// The proof does not verify.
    Rejected(VerificationError),
}

impl core::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SettlementError::Decode(error) => write!(f, "not a settlement proof: {error}"),
            SettlementError::Rejected(error) => write!(f, "the proof does not verify: {error}"),
        }
    }
}

impl core::error::Error for SettlementError {}

/// Deserialize a postcard-encoded settlement proof and verify it against the
/// embedded AIR + MOBILE config: `Ok(())` iff it is valid (the settlement bin
/// maps the outcome to its halt code). This is the full M31-algebraic verify
/// the PVM run measures.
pub fn verify_settlement_proof(bytes: &[u8]) -> Result<(), SettlementError> {
    let proof: StarkProof<P2MerkleHasher> =
        postcard::from_bytes(bytes).map_err(SettlementError::Decode)?;
    if proof.commitments.len() < 2 {
        return Err(SettlementError::Rejected(
            VerificationError::InvalidStructure("fewer than two commitments".into()),
        ));
    }
    let config = mobile_config();
    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        BoolEval,
        SecureField::default(),
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    // Replay the prover's 2-tree commitment transcript (preprocessed + main);
    // `verify` handles the interaction (logup) tree internally.
    let sizes = component.trace_log_degree_bounds();
    cs.commit(proof.commitments[0], &sizes[0], channel);
    cs.commit(proof.commitments[1], &sizes[1], channel);
    verify_segment(&[&component as &dyn Component], channel, &mut cs, proof)
        .map_err(SettlementError::Rejected)
}

// ── Single-core atomic libcall shims for the JAM PVM (riscv64em-vos) ──────
//
// The PVM target is RV64EM with NO `a` (atomic) extension — JAVM does not decode
// `lr`/`sc`/`amo*`. We therefore set `max-atomic-width: 64` WITHOUT `+a`, so the
// few `core::sync::atomic` loads stwo's verify graph pulls in (via `foldhash`'s
// global seed and `tracing-core`'s callsite registration) lower to `__atomic_*`
// LIBCALLS instead of atomic instructions. JAVM is single-threaded, so an
// "atomic" load is just a plain load — these provide that. (Only the load widths
// the verify build actually references are defined; add others if a future link
// reports them undefined.) Scoped to the bare-metal PVM target so a host/wasm
// build never shadows the real `__atomic_*`.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
mod pvm_atomic_shim {
    // Single-core ⇒ every "atomic" op is its plain non-atomic counterpart;
    // there is no other hart to race with. Signatures follow the GCC/LLVM
    // sized atomic-libcall ABI. Only the widths the verify build references
    // are defined (load/store/compare_exchange at 1 and 8 bytes); add more if
    // a future link reports them undefined.

    /// `T __atomic_load_N(const T* ptr, int memorder)`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_load_1(ptr: *const u8, _memorder: i32) -> u8 {
        core::ptr::read(ptr)
    }
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_load_8(ptr: *const u64, _memorder: i32) -> u64 {
        core::ptr::read(ptr)
    }

    /// `void __atomic_store_N(T* ptr, T val, int memorder)`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_store_1(ptr: *mut u8, val: u8, _memorder: i32) {
        core::ptr::write(ptr, val)
    }
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_store_8(ptr: *mut u64, val: u64, _memorder: i32) {
        core::ptr::write(ptr, val)
    }

    /// `bool __atomic_compare_exchange_N(T* ptr, T* expected, T desired,
    ///  int success_memorder, int failure_memorder)` — on single-core the
    /// load-compare-store cannot be interrupted by another hart, so the plain
    /// sequence IS the atomic CAS.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_compare_exchange_1(
        ptr: *mut u8,
        expected: *mut u8,
        desired: u8,
        _success: i32,
        _failure: i32,
    ) -> bool {
        let cur = core::ptr::read(ptr);
        if cur == core::ptr::read(expected) {
            core::ptr::write(ptr, desired);
            true
        } else {
            core::ptr::write(expected, cur);
            false
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_compare_exchange_8(
        ptr: *mut u64,
        expected: *mut u64,
        desired: u64,
        _success: i32,
        _failure: i32,
    ) -> bool {
        let cur = core::ptr::read(ptr);
        if cur == core::ptr::read(expected) {
            core::ptr::write(ptr, desired);
            true
        } else {
            core::ptr::write(expected, cur);
            false
        }
    }

    /// `T __atomic_exchange_N(T* ptr, T val, int memorder) -> old` (the spin
    /// lock's lock/unlock primitive).
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_exchange_1(ptr: *mut u8, val: u8, _memorder: i32) -> u8 {
        let old = core::ptr::read(ptr);
        core::ptr::write(ptr, val);
        old
    }

    /// `T __atomic_fetch_or_N(T* ptr, T val, int memorder) -> old`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_fetch_or_1(ptr: *mut u8, val: u8, _memorder: i32) -> u8 {
        let old = core::ptr::read(ptr);
        core::ptr::write(ptr, old | val);
        old
    }

    /// `T __atomic_fetch_and_N(T* ptr, T val, int memorder) -> old`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_fetch_and_1(ptr: *mut u8, val: u8, _memorder: i32) -> u8 {
        let old = core::ptr::read(ptr);
        core::ptr::write(ptr, old & val);
        old
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The channel copy draws what the prover's channel draws, after the same
    /// u64s, u32s, felts, roots and PoW nonces: values that collide under a
    /// reduction mod p, and nonces whose limbs exceed 16 bits' worth of one
    /// word.
    #[test]
    fn the_channel_copy_draws_as_the_provers() {
        use vos_pvm_proof::poseidon2 as prover;
        let p = u64::from(stwo::core::fields::m31::P);
        let mut copy = Poseidon2M31Channel::default();
        let mut theirs = prover::Poseidon2M31Channel::default();
        macro_rules! both {
            ($method:ident($($argument:expr),*)) => {
                copy.$method($($argument),*);
                theirs.$method($($argument),*);
                assert_eq!(copy.clone().draw_secure_felt(), theirs.clone().draw_secure_felt());
            };
        }
        for value in [
            0,
            1,
            0xffff,
            0x1_0000,
            p,
            p + 5,
            5 << 32,
            (5 + p) << 32,
            u64::MAX,
        ] {
            both!(mix_u64(value));
        }
        both!(mix_u32s(&[0, 1, 0xffff, 0x1_0000, p as u32, u32::MAX]));
        both!(mix_u32s(&[]));
        both!(mix_felts(&[
            SecureField::from_u32_unchecked(1, 2, 3, 4),
            SecureField::from_u32_unchecked(p as u32 - 1, 0, 7, 9),
        ]));
        let limbs: [BaseField; 8] =
            core::array::from_fn(|i| BaseField::from_u32_unchecked(i as u32 * 77));
        P2MerkleChannel::mix_root(&mut copy, P2Hash(limbs));
        prover::P2MerkleChannel::mix_root(&mut theirs, prover::P2Hash(limbs));

        for nonce in [0, 1, 0xffff, 0x1_0000, 0xdead_beef_cafe_f00d, u64::MAX] {
            for bits in [0, 1, 4, 8, 20] {
                assert_eq!(
                    copy.verify_pow_nonce(bits, nonce),
                    theirs.verify_pow_nonce(bits, nonce),
                    "{bits} bits, nonce {nonce:#x}"
                );
            }
        }
        let nonce = (1u64 << 40..)
            .find(|&nonce| copy.verify_pow_nonce(8, nonce))
            .unwrap();
        assert!(theirs.verify_pow_nonce(8, nonce));
        copy.mix_u64(nonce);
        theirs.mix_u64(nonce);

        assert_eq!(copy.draw_secure_felts(3), theirs.draw_secure_felts(3));
        assert_eq!(copy.draw_u32s(), theirs.draw_u32s());
        assert_eq!(copy.draw_secure_felt(), theirs.draw_secure_felt());
    }
}
