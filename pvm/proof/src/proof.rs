//! Proof and segment-state data types — shared between prover and verifier.
//!
//! Pure data: no execution semantics live here, so the no_std verifier build
//! can reach them without pulling in the prover stack.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use stwo::core::{
    channel::Channel, fields::qm31::SecureField, pcs::PcsConfig, poly::line::LinePoly,
    proof::StarkProof,
};

use crate::recursion_pcs::ProverMerkleHasher;

/// Current proof format version.  Bumped whenever the AIR shape (number
/// of components, column counts, lookup-tuple shapes, flag layouts) or
/// the proof struct layout changes in a way that would make an older
/// verifier silently accept the wrong thing.
///
/// Verifiers MUST reject proofs whose `format_version` does not match
/// the constant they were compiled against — see the bounds check in
/// `vos_pvm_proof::verify` and `vos_pvm_proof_verifier::verify_standalone`.
///
/// History:
///   1 — Rotate / BitManip / 32-bit-shift / Sbrk all bound;
///       PROG_MEMORY_N_FLAGS = 48; 14 components.
///   2 — `RegisterMemoryClosingChip` added at index 6,
///       shifting every higher chip index by +1; closes the register-
///       memory ledger by consuming a synthetic per-register read at
///       `closing_ts = last_step.timestamp + 1`, pinning the final
///       register COLUMN to the trace's true final register values.
///       The FS-transcript also mixes `final_state.registers`, making
///       a finished proof tamper-evident. (See the SCOPE note in
///       `chips/register_memory_closing.rs`: the mix does NOT bind the
///       separate metadata FIELD against a from-scratch prover.) Older
///       proofs reject at the `format_version` gate.
///   3 — FS-transcript also mixes
///       `proof.initial_state.registers` (before the existing
///       `final_state.registers` mix) — same tamper-evidence on the
///       initial side; the boundary chip already commits `initial_regs`
///       in its trace.
///   4 — Boundary pc + timestamp join the FS mix (after the register
///       mixes; order: initial regs, final regs, initial pc, initial
///       ts, final pc, final ts). Their in-circuit commitments already
///       existed — ProgramBoundaryChip commits (InitialPc,
///       InitialTimestamp) and (FinalNextPc, FinalNextTimestamp),
///       telescoped through CpuChip's program-execution relation. So
///       the mix extends the SAME tamper-evidence the registers have to
///       pc and timestamp; `verify_chain`'s whole-struct boundary
///       equality stops comparing pure metadata for those fields.
///       LIMITATION (shared with the register mix since v2): the mix is
///       tamper-evidence, NOT a binding constraint — a from-scratch
///       prover can still ship self-consistent boundary metadata that
///       differs from the committed columns. True binding needs a
///       boundary public-input constraint (the conservation-of-value
///       chain-verification project). `memory_commitment` is weaker
///       still — computed outside the circuit, not even mixed.
///   5 — Boundary public-input binding (metadata→column): closes the
///       v2–v4 metadata-vs-column gap. Verifiers recompute each boundary
///       chip's logup claimed sum from `proof.{initial,final}_state`
///       (registers, pc, timestamp) with the FS-drawn lookup elements
///       and require equality with `proof.claimed_sums` — binding the
///       metadata fields to the committed boundary COLUMNS. A
///       from-scratch prover that commits honest columns and ships lying
///       metadata is now rejected (gate: `tests/boundary_binding.rs`).
///       pc/timestamp become genuine bound public inputs (their columns
///       are pinned to the trace by CpuChip program-execution chaining).
///       REGISTERS are bound metadata→column only: their column→trace
///       link is `RegisterMemoryChip` read-consistency, which is NOT
///       enforced cross-row (a separate, pre-existing gap — a malicious
///       prover can still forge the closing read's value and hence the
///       io-hash; see `chips/register_memory_closing.rs` and
///       `docs/plans/roadmap.md`). No AIR change — the
///       proof bytes an honest prover produces are unchanged apart from
///       this version field; the bump exists because older verifiers
///       ACCEPT metadata forgeries that v5 verifiers reject, and proofs
///       over EMPTY traces (which bind nothing) now reject. The
///       standalone verifier additionally requires `component_mask` to
///       contain the three binding chips and to popcount-match
///       `num_components`. `memory_commitment` remains outside the
///       binding (no committed column; see `segment.rs`).
///   6 — Register/RAM ledger read-consistency bound (closes the v5
///       register column→trace gap). `RegisterMemoryChip` and `MemoryChip`
///       gain a cross-row `prev_value` binding (`#[mask_next_row]`) and a
///       `(key, ts)` sortedness range-check (self-contained 24-bit
///       decomposition), and the register ledger tuple gains an `is_write`
///       limb (17→18; CpuChip / boundary / closing producers + the verifier
///       boundary-binding recompute updated). The B5 register read-run merge
///       is disabled (one entry per row). So a from-scratch prover can no
///       longer forge a register/RAM read — in particular the closing read
///       that pins `final_state.registers` / the actor io-hash is now
///       sound. AIR change: new columns + the wider register relation, so
///       the proof bytes differ (gate: `tests/ledger_readconsistency_gate.rs`).
///       `memory_commitment` is still outside the binding.
///   7 — In-circuit RAM-image binding (closes the memory-continuity
///       gap `memory_commitment` left open). RAM is committed as a page-keyed
///       blake2b Merkle tree; per segment the prover proves a boundary
///       multiproof binding the entering page images to `initial_state
///       .memory_root` and the exit images to `final_state.memory_root`
///       (`Memory{Page,Merkle,RootBoundary}Chip` + `Blake2bBoundaryChip`), and
///       the RAM ledger forces every accessed address into a listed page
///       (per-page ts=0 boundary write + closing read, group-start/end
///       constraints). The roots join the FS mix and `MemoryRootBoundaryChip`'s
///       claimed sum is bound to them closed-form (`boundary_binding`). So
///       `verify_chain_standalone(proofs, commitment, expected_initial_root)`
///       becomes sound for memory continuity, not only tamper-evident. New
///       components (`COUNT` 28 → 31, `MemoryBoundaryChip` deleted), a wider
///       `MemoryAccess` tuple (`is_closing`), and a new `MerkleNode` relation,
///       so the proof bytes differ.
///   8 — Ristretto memory-op `ts` binding (closes the
///       money-path ts-forgery gap where the three ristretto memory producers
///       set `ts` as a free witness). CpuChip gains five `Is{110..114}Ecall`
///       gates that emit a `RistrettoCall` (RELATION A) producer + register
///       reads (φ[7,8,9]) per ristretto ECALL step; RistrettoEcallChip moves
///       to a uniform 96-row preprocessed period that consumes RELATION A at a
///       preprocessed-pinned `InitGate` (so its block `ts` == the chained CpuChip
///       step ts ∈ [initial_ts, final_ts), excluding 0 and `closing_ts`) and
///       re-emits the anchored ts to the two comb chips via `RistrettoFixedScalarTs`
///       / `RistrettoFixedOutTs` (Tier-2); the comb chips consume those and add
///       intra-call ts/ptr equality + per-byte authenticated `Addr`. Three new
///       relations, a wider CpuChip, and restructured ristretto chips — no new
///       CHIPS (`COUNT` unchanged at 31) — so the proof bytes differ and older
///       verifiers must reject.
///   10 — Register/RAM ledger ordering deltas widen from 24 to 28 bits. The
///        former hidden `2^24` timestamp ceiling made long software-arithmetic
///        actor traces unprovable at their terminal segment. Twenty-eight bits
///        cover the canonical 100M-gas actor-proof budget while remaining well
///        below the M31 modulus, preserving the wrapped-negative rejection the
///        sortedness proof relies on. AIR column counts change, so older
///        verifiers must reject. Version 9 was already assigned to the
///        Poseidon2-M31 PCS variant of format 8.
///   12 — Gray Paper v0.8.0 unary-opcode table: removes the retired `sbrk`
///        opcode and renumbers CountSetBits64 through ReverseBytes from
///        102..=111 to 101..=110. Program identities and opcode-bound CPU
///        traces change, so v10 native-channel proofs must be rejected.
///        Version 11 was the Poseidon2-M31 PCS variant of format 10.
///   13 — Poseidon2-M31 PCS variant of format 12.
///   14 — ISA-profile-bound program memory. Every authenticated instruction
///        tuple now carries the container-derived profile (standard v0.8 or
///        frozen capability manifest), and opcode decoding uses that profile.
///        This prevents valid service Tasks from being reinterpreted under
///        the shifted v0.8 unary table during proof tracing. CpuChip and
///        ProgramMemoryChip each gain one column/lookup limb.
///   15 — Poseidon2-M31 PCS variant of format 14.
///   16 — Standard host-call continuation and scalar-memory address binding.
///        CpuChip commits whether a policy-supported ECALLI was acknowledged,
///        constrains handled/cause PCs across segment boundaries, and binds the
///        supported-call policy through ProgramMemory. ProgramMemory also
///        authenticates the exact cryptographic precompile dispatch ID; every
///        continued precompile row must select exactly that handler-call
///        relation, while lifecycle/VOS stubs select none. This widens the
///        program-memory tuple from 33 to 34 limbs. Standard load/store rows
///        also prove that their full scalar range stays outside the protected
///        low 64 KiB and does not wrap through 2^32. CPU/ProgramMemory columns
///        and the program-memory lookup tuple change, so older proofs reject.
///   17 — Poseidon2-M31 PCS variant of format 16.
///   18 — Standard Refine proof-closure generation. Individual STARKs remain
///        single-program machine-slice proofs; the new boundary bundle binds
///        their exact outer/inner program identities, proof shapes, order,
///        sparse memory states, and calls 9..=14 before/after transcript.
///        Sparse entering images also replace the dense nearly-4-GiB Refine
///        witness representation. Older proof/bundle combinations reject.
///   19 — Poseidon2-M31 PCS variant of format 18.
///   20 — Full PCS configuration is Fiat–Shamir-bound, including the lifting
///        `Option` discriminant; proof-side verification also uses the exact
///        AIR-derived lifted shape.
///   21 — Poseidon2-M31 PCS variant of format 20.
#[cfg(not(feature = "poseidon2-channel"))]
pub const PROOF_FORMAT_VERSION: u32 = 20;
/// Native recursion: the PCS commit hash + Fiat-Shamir
/// transcript move from Blake2s to Poseidon2-M31, so `stark_proof.commitments`
/// become `P2Hash` digests — a different wire format. A Blake2s verifier
/// (v20) and a Poseidon2-M31 verifier (v21) therefore reject each other's proofs.
#[cfg(feature = "poseidon2-channel")]
pub const PROOF_FORMAT_VERSION: u32 = 21;

/// Exact number of commitment trees in this generation of the Stwo proof:
/// preprocessed, main, interaction, and split composition.
pub const PROOF_COMMITMENT_TREE_COUNT: usize = 4;
/// The component mask is a `u32`; accepting more components would make its
/// shape ambiguous before any cryptographic check.
pub const MAX_PROOF_COMPONENTS: usize = u32::BITS as usize;
/// SIMD trace builders use 16 lanes and index rows with
/// `log_size - LOG_N_LANES`; smaller claimed components are structurally
/// impossible and can otherwise reach an unchecked subtraction.
pub const MIN_PROOF_LOG_SIZE: u32 = 4;
/// Hard transport-independent cap for every proof-owned column vector. The
/// complete v20/v21 AIR currently commits 7,912 columns in its widest tree;
/// the next power of two leaves narrowly audited generation-local headroom.
pub const MAX_PROOF_COLUMNS_PER_TREE: usize = 1 << 13;
/// Hard cap for OODS samples attached to one committed column.
pub const MAX_PROOF_SAMPLES_PER_COLUMN: usize = 64;
/// Stwo's current query protocol has no useful production shape above this.
pub const MAX_FRI_QUERIES: usize = 256;
/// M31's canonical circle coset supports log sizes only through 30.
pub const MAX_EXTENDED_LOG_SIZE: u32 = 30;
/// Proof-side verification regenerates the preprocessed tree from a trusted
/// SideNote. Larger blowups turn a small hostile proof into exponential local
/// recommitment work; production STANDARD uses 4 and MOBILE uses 2.
pub const MAX_RECOMMIT_LOG_BLOWUP: u32 = 4;
/// Network/refine protocol cap for a child component's unextended trace.
pub const MAX_PROOF_LOG_SIZE: u32 = 24;
/// Bound proof-owned Merkle witnesses before hashing or allocation-heavy work.
pub const MAX_MERKLE_WITNESS_HASHES: usize = MAX_FRI_QUERIES * MAX_EXTENDED_LOG_SIZE as usize;
/// Maximum aggregate heap payload cloned from one hostile proof after decode.
/// This covers every nested sampled/query/witness/FRI vector, not only each
/// vector in isolation.
pub const MAX_PROOF_OWNED_BYTES: usize = 16 * 1024 * 1024;

// Two fixed little-endian words spelling "VOS/PVM/" and "STARK/FS". The
// format version follows as its own word. This is deliberately mixed before
// log sizes or roots on every proving and verifying path: changing a wire
// version can never merely relabel an old proof under the same transcript.
const PROOF_FS_DOMAIN_WORD_0: u64 = u64::from_le_bytes(*b"VOS/PVM/");
const PROOF_FS_DOMAIN_WORD_1: u64 = u64::from_le_bytes(*b"STARK/FS");

#[cfg(all(feature = "prover", not(feature = "poseidon2-channel")))]
const PRE_CONFIG_FS_FORMAT_VERSION: u32 = 18;
#[cfg(all(feature = "prover", feature = "poseidon2-channel"))]
const PRE_CONFIG_FS_FORMAT_VERSION: u32 = 19;

/// Bind the proof protocol domain and exact format generation into a Fiat–
/// Shamir channel. This prefix authenticates the STARK statement transcript;
/// Refine's outer bundle transcript additionally authenticates machine
/// identities, native boundary witnesses, and ordered child identities.
pub fn mix_proof_fs_domain(channel: &mut impl Channel, format_version: u32, config: &PcsConfig) {
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_0);
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_1);
    channel.mix_u64(u64::from(format_version));
    channel.mix_u64(u64::from(config.pow_bits));
    channel.mix_u64(config.fri_config.n_queries as u64);
    channel.mix_u64(u64::from(config.fri_config.log_blowup_factor));
    channel.mix_u64(u64::from(config.fri_config.log_last_layer_degree_bound));
    channel.mix_u64(u64::from(config.fri_config.fold_step));
    match config.lifting_log_size {
        None => channel.mix_u64(0),
        Some(lifting) => {
            channel.mix_u64(1);
            channel.mix_u64(u64::from(lifting));
        }
    }
}

/// Adversarial-test seam for constructing a proof under the immediately
/// preceding transcript, which bound the format but omitted `PcsConfig`.
/// The returned proof is deliberately invalid under the current generation.
#[cfg(feature = "prover")]
pub(crate) fn mix_pre_config_proof_fs_domain(channel: &mut impl Channel) {
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_0);
    channel.mix_u64(PROOF_FS_DOMAIN_WORD_1);
    channel.mix_u64(u64::from(PRE_CONFIG_FS_FORMAT_VERSION));
}

/// Execution state at a segment boundary (initial or final).
/// Maps to VOS's ContinuationHeader for checkpoint integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentState {
    pub pc: u32,
    pub timestamp: u64,
    pub registers: [u64; 13],
    pub memory_commitment: [u8; 32], // blake3(flat_mem); computed outside the circuit, unbound
    /// Page-Merkle root of the RAM image AT THIS boundary (format v7):
    /// bound in-circuit by the boundary multiproof + `MemoryRootBoundaryChip`,
    /// so cross-segment continuity (`final_state == next.initial_state`)
    /// genuinely forces memory continuity.  A segment binds `initial_state
    /// .memory_root` (entering image) and `final_state.memory_root` (exit
    /// image); the two are equal across a chain boundary by struct-eq.
    #[serde(default)]
    pub memory_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Format-shape version — must equal `PROOF_FORMAT_VERSION` of the
    /// verifier crate this proof is presented to.  Mismatches are
    /// rejected with `VerificationError::InvalidStructure` before any
    /// cryptographic work happens.
    #[serde(default = "proof_format_version_default")]
    pub format_version: u32,
    pub stark_proof: StarkProof<ProverMerkleHasher>,
    pub claimed_sums: Vec<SecureField>,
    pub log_sizes: Vec<u32>,
    pub num_components: usize,
    /// Bit i set ⇔ chip i in BASE_COMPONENTS was active for
    /// this proof.  Allows the standalone verifier (no SideNote) to
    /// reconstruct the exact active-chip selection the prover used.
    /// Defaults to `0` for back-compat with older proofs (the verifier
    /// then falls back to count-based inference: full set if count =
    /// BASE_COMPONENTS.len(), Blake2b-skipped if count = len-1).
    #[serde(default)]
    pub component_mask: u32,
    pub pcs_config: PcsConfig,
    /// State at segment start. pc/timestamp, registers, and `memory_root`
    /// are bound to the committed boundary columns (boundary-binding check):
    /// pc/ts pinned to the trace via CpuChip chaining, registers via
    /// register-ledger read-consistency, `memory_root` via the in-AIR
    /// page-Merkle trie. `memory_commitment` is unbound/vestigial metadata
    /// (see `SegmentState`).
    pub initial_state: SegmentState,
    /// State at segment end. Same binding scope as `initial_state`.
    pub final_state: SegmentState,
}

/// Serde default for `format_version` so older serialized proofs (which
/// pre-date the field) deserialize as version 0 → guaranteed reject.
fn proof_format_version_default() -> u32 {
    0
}

impl Proof {
    /// Reconstruct the 32-byte actor-IO binding hash from
    /// the final-state register window φ[9..13].
    ///
    /// A binding actor places `H = compute_io_hash(public, return)` (see
    /// `vos::zk`) into φ[9..12] as part of its Gray Paper halt jump — the four
    /// hash words are passed as inline-asm `in` operands (`a2..a5`), so
    /// the compiler materialises them via real instructions immediately
    /// before halt. No host/tracer cooperation is involved: the binding
    /// is just ordinary register state at halt.  The verifier's
    /// boundary-binding check (`boundary_binding`) equates this field to
    /// the closing chip's committed RegVal column, which is pinned to the
    /// trace's true final registers by `RegisterMemoryChip` read-consistency
    /// (masked `prev_value` + `(reg, ts)` sortedness + the `is_write` limb).
    /// So this hash is bound to the genuine halting register state, sound
    /// against a from-scratch prover. The host verifier (the `prover`
    /// extension's `verify`) additionally checks it against a locally
    /// recomputed `vos::zk::compute_io_hash`, composed with the STARK-validity
    /// check against the trusted program commitment — so the io-binding can't
    /// be checked without validity.
    ///
    /// Decoding is the exact inverse of the guest-side encoding: word
    /// φ[9] → bytes 0..8, φ[10] → 8..16, φ[11] → 16..24, φ[12] → 24..32,
    /// each little-endian.  `registers[9..13]` is statically in bounds
    /// (registers is `[u64; 13]`).
    ///
    /// Proofs from non-binding actors leave φ[9..13] at their cold-start
    /// zero, so this returns `[0u8; 32]` — which fails any real
    /// `compute_io_hash` equality check, the intended "unbound proof"
    /// rejection.
    pub fn public_io_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in self.final_state.registers[9..13].iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// Transport-independent hostile-proof preflight shared by the prover-enabled
/// and standalone no_std verifiers.
///
/// This must run before either verifier indexes a Stwo `TreeVec`, constructs a
/// commitment verifier, or hashes proof-owned vectors. It validates the parts
/// that are independent of the selected AIR components; callers additionally
/// validate exact per-tree column/sample/query dimensions once they derive the
/// component layout. Its mutable wrapper reconstructs the last-layer
/// polynomial from visible coefficients so a serde-forged private cached
/// `log_size` cannot reach Stwo's shifting code.
pub fn preflight_proof_structure_readonly(
    proof: &Proof,
    max_log_size: u32,
) -> Result<usize, alloc::string::String> {
    use alloc::{format, string::ToString};

    if proof.format_version != PROOF_FORMAT_VERSION {
        return Err(format!(
            "proof format version mismatch: verifier expects {PROOF_FORMAT_VERSION}, proof has {}",
            proof.format_version
        ));
    }
    if proof.num_components == 0 || proof.num_components > MAX_PROOF_COMPONENTS {
        return Err("proof component cardinality is outside protocol bounds".into());
    }
    if proof.log_sizes.len() != proof.num_components
        || proof.claimed_sums.len() != proof.num_components
    {
        return Err("proof component/log-size/claimed-sum lengths differ".into());
    }
    if let Some(&offending) = proof
        .log_sizes
        .iter()
        .find(|&&log_size| log_size < MIN_PROOF_LOG_SIZE || log_size > max_log_size)
    {
        return Err(format!(
            "proof log_size {offending} is outside {MIN_PROOF_LOG_SIZE}..={max_log_size}"
        ));
    }

    let config = proof.pcs_config;
    if proof.stark_proof.config != config {
        return Err("outer and embedded pcs_config differ".into());
    }
    let fri = config.fri_config;
    if !(1..=16).contains(&fri.log_blowup_factor) {
        return Err("FRI log blowup is outside Stwo's 1..=16 bound".into());
    }
    if fri.log_last_layer_degree_bound > 10 {
        return Err("FRI last-layer degree bound exceeds 10".into());
    }
    // Stwo 2.x exposes a configurable field but implements one-fold layers;
    // admitting another value reaches assumptions and shifts not audited here.
    if fri.fold_step != 1 {
        return Err("FRI fold_step must equal the protocol value 1".into());
    }
    if !(1..=MAX_FRI_QUERIES).contains(&fri.n_queries) {
        return Err(format!("FRI query count is outside 1..={MAX_FRI_QUERIES}"));
    }
    if config.pow_bits > 31 {
        return Err("PCS proof-of-work bits exceed the supported bound 31".into());
    }

    let max_trace_log = proof.log_sizes.iter().copied().max().unwrap_or(0);
    let max_extended_log = max_trace_log
        .checked_add(fri.log_blowup_factor)
        .ok_or_else(|| "trace log size plus FRI blowup overflows".to_string())?;
    if max_extended_log > MAX_EXTENDED_LOG_SIZE {
        return Err(format!(
            "extended trace log size {max_extended_log} exceeds {MAX_EXTENDED_LOG_SIZE}"
        ));
    }
    if let Some(lifting) = config.lifting_log_size {
        if lifting < max_extended_log || lifting > MAX_EXTENDED_LOG_SIZE {
            return Err(format!(
                "PCS lifting log size {lifting} does not cover {max_extended_log} within the protocol bound"
            ));
        }
    }

    let stark = &proof.stark_proof;
    if stark.commitments.len() != PROOF_COMMITMENT_TREE_COUNT
        || stark.sampled_values.len() != PROOF_COMMITMENT_TREE_COUNT
        || stark.decommitments.len() != PROOF_COMMITMENT_TREE_COUNT
        || stark.queried_values.len() != PROOF_COMMITMENT_TREE_COUNT
    {
        return Err(format!(
            "Stwo proof must contain exactly {PROOF_COMMITMENT_TREE_COUNT} commitment trees"
        ));
    }

    for columns in stark.sampled_values.iter() {
        if columns.len() > MAX_PROOF_COLUMNS_PER_TREE {
            return Err(format!(
                "sampled-value column count {} exceeds protocol bound {MAX_PROOF_COLUMNS_PER_TREE}",
                columns.len()
            ));
        }
        if columns
            .iter()
            .any(|samples| samples.len() > MAX_PROOF_SAMPLES_PER_COLUMN)
        {
            return Err("sample count per column exceeds protocol bound".into());
        }
    }
    for columns in stark.queried_values.iter() {
        if columns.len() > MAX_PROOF_COLUMNS_PER_TREE {
            return Err(format!(
                "queried-value column count {} exceeds protocol bound {MAX_PROOF_COLUMNS_PER_TREE}",
                columns.len()
            ));
        }
        if columns.iter().any(|values| values.len() > fri.n_queries) {
            return Err("queried-value count exceeds configured FRI queries".into());
        }
    }
    if stark
        .decommitments
        .iter()
        .any(|decommitment| decommitment.hash_witness.len() > MAX_MERKLE_WITNESS_HASHES)
    {
        return Err("trace Merkle witness exceeds protocol bound".into());
    }

    let fri_proof = &stark.fri_proof;
    if fri_proof.inner_layers.len() > MAX_EXTENDED_LOG_SIZE as usize {
        return Err("FRI inner-layer count exceeds protocol bound".into());
    }
    let layer_is_bounded = |layer: &stwo::core::fri::FriLayerProof<ProverMerkleHasher>| {
        layer.fri_witness.len() <= MAX_FRI_QUERIES
            && layer.decommitment.hash_witness.len() <= MAX_MERKLE_WITNESS_HASHES
    };
    if !layer_is_bounded(&fri_proof.first_layer)
        || fri_proof
            .inner_layers
            .iter()
            .any(|layer| !layer_is_bounded(layer))
    {
        return Err("FRI layer witness exceeds protocol bound".into());
    }
    let owned_bytes = proof_owned_bytes(proof).ok_or_else(|| {
        alloc::format!("proof nested payload exceeds {MAX_PROOF_OWNED_BYTES} bytes")
    })?;

    let expected_last_len = 1usize
        .checked_shl(fri.log_last_layer_degree_bound)
        .ok_or_else(|| "FRI last-layer length shift overflows".to_string())?;
    let coefficients_len = fri_proof.last_layer_poly.iter().count();
    if coefficients_len != expected_last_len {
        return Err(format!(
            "FRI last-layer polynomial has {} coefficients, expected {expected_last_len}",
            coefficients_len
        ));
    }
    if !proof_fields_are_canonical(proof) {
        return Err("proof contains a noncanonical M31 field limb".into());
    }
    Ok(owned_bytes)
}

fn base_field_is_canonical(value: &stwo::core::fields::m31::BaseField) -> bool {
    value.0 < stwo::core::fields::m31::P
}

fn secure_field_is_canonical(value: &SecureField) -> bool {
    value.to_m31_array().iter().all(base_field_is_canonical)
}

#[cfg(not(feature = "poseidon2-channel"))]
fn merkle_hash_is_canonical(_: &crate::recursion_pcs::ProverMerkleHash) -> bool {
    true
}

#[cfg(feature = "poseidon2-channel")]
fn merkle_hash_is_canonical(hash: &crate::recursion_pcs::ProverMerkleHash) -> bool {
    hash.0.iter().all(base_field_is_canonical)
}

fn proof_fields_are_canonical(proof: &Proof) -> bool {
    let stark = &proof.stark_proof;
    proof.claimed_sums.iter().all(secure_field_is_canonical)
        && stark.commitments.iter().all(merkle_hash_is_canonical)
        && stark
            .sampled_values
            .iter()
            .flatten()
            .flatten()
            .all(secure_field_is_canonical)
        && stark
            .queried_values
            .iter()
            .flatten()
            .flatten()
            .all(base_field_is_canonical)
        && stark
            .decommitments
            .iter()
            .flat_map(|decommitment| &decommitment.hash_witness)
            .all(merkle_hash_is_canonical)
        && core::iter::once(&stark.fri_proof.first_layer)
            .chain(&stark.fri_proof.inner_layers)
            .all(|layer| {
                merkle_hash_is_canonical(&layer.commitment)
                    && layer.fri_witness.iter().all(secure_field_is_canonical)
                    && layer
                        .decommitment
                        .hash_witness
                        .iter()
                        .all(merkle_hash_is_canonical)
            })
        && stark
            .fri_proof
            .last_layer_poly
            .iter()
            .all(secure_field_is_canonical)
}

/// Checked aggregate size of all proof-owned nested vector elements.
///
/// This is a post-decode heap-payload bound (transport must still cap bytes
/// before Serde). Returning `None` means arithmetic overflow or a payload over
/// [`MAX_PROOF_OWNED_BYTES`]. Vec headers are included so thousands of empty
/// attacker-controlled columns are not free in the accounting.
pub fn proof_owned_bytes(proof: &Proof) -> Option<usize> {
    use core::mem::size_of;

    fn add<T>(total: &mut usize, len: usize) -> Option<()> {
        *total = total.checked_add(len.checked_mul(size_of::<T>())?)?;
        (*total <= MAX_PROOF_OWNED_BYTES).then_some(())
    }

    let mut total = size_of::<Proof>();
    add::<SecureField>(&mut total, proof.claimed_sums.len())?;
    add::<u32>(&mut total, proof.log_sizes.len())?;
    add::<crate::recursion_pcs::ProverMerkleHash>(&mut total, proof.stark_proof.commitments.len())?;
    add::<Vec<Vec<SecureField>>>(&mut total, proof.stark_proof.sampled_values.len())?;
    for tree in proof.stark_proof.sampled_values.iter() {
        add::<Vec<SecureField>>(&mut total, tree.len())?;
        for column in tree {
            add::<SecureField>(&mut total, column.len())?;
        }
    }
    add::<Vec<Vec<stwo::core::fields::m31::BaseField>>>(
        &mut total,
        proof.stark_proof.queried_values.len(),
    )?;
    for tree in proof.stark_proof.queried_values.iter() {
        add::<Vec<stwo::core::fields::m31::BaseField>>(&mut total, tree.len())?;
        for column in tree {
            add::<stwo::core::fields::m31::BaseField>(&mut total, column.len())?;
        }
    }
    add::<stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted<ProverMerkleHasher>>(
        &mut total,
        proof.stark_proof.decommitments.len(),
    )?;
    for decommitment in proof.stark_proof.decommitments.iter() {
        add::<crate::recursion_pcs::ProverMerkleHash>(&mut total, decommitment.hash_witness.len())?;
    }
    let fri = &proof.stark_proof.fri_proof;
    add::<SecureField>(&mut total, fri.last_layer_poly.iter().count())?;
    add::<stwo::core::fri::FriLayerProof<ProverMerkleHasher>>(&mut total, fri.inner_layers.len())?;
    for layer in core::iter::once(&fri.first_layer).chain(&fri.inner_layers) {
        add::<SecureField>(&mut total, layer.fri_witness.len())?;
        add::<crate::recursion_pcs::ProverMerkleHash>(
            &mut total,
            layer.decommitment.hash_witness.len(),
        )?;
    }
    Some(total)
}

/// Mutable wrapper around [`preflight_proof_structure_readonly`] that also
/// normalizes Stwo's private cached last-layer `log_size` from the already
/// bounded visible coefficient vector. This must happen before handing a
/// serde-created proof to Stwo.
pub fn preflight_proof_structure(
    proof: &mut Proof,
    max_log_size: u32,
) -> Result<(), alloc::string::String> {
    use alloc::vec::Vec;

    let _bounded_bytes = preflight_proof_structure_readonly(proof, max_log_size)?;
    let coefficients: Vec<SecureField> = proof
        .stark_proof
        .fri_proof
        .last_layer_poly
        .iter()
        .copied()
        .collect();
    proof.stark_proof.0.fri_proof.last_layer_poly = LinePoly::new(coefficients);
    Ok(())
}

/// Derived safe dimensions of a structurally valid Stwo statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofProtocolShape {
    pub lifting_log_size: u32,
    pub max_log_degree_bound: u32,
    /// Number of sorted/deduplicated query positions represented by every
    /// non-empty queried-value column. Callers compare this with a safe replay
    /// of Fiat–Shamir query sampling before entering Stwo.
    pub query_count: usize,
}

/// Derive Stwo's lifted/composition degree pair with checked arithmetic and
/// the M31 canonical-coset bound enforced before either value reaches a shift
/// or domain constructor.
pub fn derive_protocol_degree_shape(
    config: &PcsConfig,
    composition_log_degree_bound: u32,
) -> Result<(u32, u32), alloc::string::String> {
    use alloc::string::ToString;

    let split_composition_log = composition_log_degree_bound
        .checked_sub(1)
        .ok_or_else(|| "composition log degree cannot be split".to_string())?;
    let required_lifting = split_composition_log
        .checked_add(config.fri_config.log_blowup_factor)
        .ok_or_else(|| "composition log degree plus blowup overflows".to_string())?;
    if config
        .lifting_log_size
        .is_some_and(|explicit| explicit != required_lifting)
    {
        return Err(alloc::format!(
            "explicit lifting log size must equal the AIR-derived value {required_lifting}"
        ));
    }
    let lifting_log_size = required_lifting;
    if lifting_log_size > MAX_EXTENDED_LOG_SIZE {
        return Err(alloc::format!(
            "lifting log size {lifting_log_size} does not cover composition domain {required_lifting}"
        ));
    }
    let max_log_degree_bound = lifting_log_size
        .checked_sub(config.fri_config.log_blowup_factor)
        .ok_or_else(|| "lifting log size is below FRI blowup".to_string())?;
    if max_log_degree_bound < MIN_PROOF_LOG_SIZE {
        return Err(alloc::format!(
            "maximum polynomial log degree {max_log_degree_bound} is below {MIN_PROOF_LOG_SIZE}"
        ));
    }
    Ok((lifting_log_size, max_log_degree_bound))
}

/// Validate all nested Stwo vector dimensions against the exact AIR-derived
/// tree layout. `expected_log_sizes` and `expected_sample_counts` include all
/// four trees, including the eight split-composition columns.
pub fn preflight_proof_dimensions(
    proof: &Proof,
    expected_log_sizes: &[alloc::vec::Vec<u32>],
    expected_sample_counts: &[alloc::vec::Vec<usize>],
    composition_log_degree_bound: u32,
) -> Result<ProofProtocolShape, alloc::string::String> {
    use alloc::{format, string::ToString};

    if expected_log_sizes.len() != PROOF_COMMITMENT_TREE_COUNT
        || expected_sample_counts.len() != PROOF_COMMITMENT_TREE_COUNT
    {
        return Err("AIR-derived proof layout must contain exactly four trees".into());
    }
    let fri = proof.pcs_config.fri_config;
    let (lifting_log_size, max_log_degree_bound) =
        derive_protocol_degree_shape(&proof.pcs_config, composition_log_degree_bound)?;

    for (tree_index, logs) in expected_log_sizes.iter().enumerate() {
        if logs.len() > MAX_PROOF_COLUMNS_PER_TREE {
            return Err(format!(
                "AIR-derived tree {tree_index} column count exceeds protocol bound"
            ));
        }
        for &log_size in logs {
            if log_size < MIN_PROOF_LOG_SIZE {
                return Err(format!(
                    "tree {tree_index} column log size {log_size} is below {MIN_PROOF_LOG_SIZE}"
                ));
            }
            let extended = log_size
                .checked_add(fri.log_blowup_factor)
                .ok_or_else(|| "column log size plus blowup overflows".to_string())?;
            if extended > lifting_log_size || extended > MAX_EXTENDED_LOG_SIZE {
                return Err(format!(
                    "tree {tree_index} column log size {log_size} is incompatible with lifting {lifting_log_size}"
                ));
            }
        }
    }

    let expected_composition_logs = alloc::vec![max_log_degree_bound; 8];
    if expected_log_sizes[PROOF_COMMITMENT_TREE_COUNT - 1] != expected_composition_logs {
        return Err("composition tree must contain eight exact split columns".into());
    }
    if expected_sample_counts[PROOF_COMMITMENT_TREE_COUNT - 1] != alloc::vec![1; 8] {
        return Err("composition tree must contain one OODS sample per split column".into());
    }

    let mut common_query_count = None;
    for tree_index in 0..PROOF_COMMITMENT_TREE_COUNT {
        let logs = &expected_log_sizes[tree_index];
        let samples = &expected_sample_counts[tree_index];
        if samples.len() != logs.len()
            || proof.stark_proof.sampled_values[tree_index].len() != logs.len()
            || proof.stark_proof.queried_values[tree_index].len() != logs.len()
        {
            return Err(format!(
                "tree {tree_index} column dimensions differ from the AIR-derived layout"
            ));
        }
        for (column, &expected_samples) in proof.stark_proof.sampled_values[tree_index]
            .iter()
            .zip(samples)
        {
            if column.len() != expected_samples {
                return Err(format!(
                    "tree {tree_index} OODS sample dimensions differ from the AIR mask"
                ));
            }
        }
        for column in &proof.stark_proof.queried_values[tree_index] {
            let query_count = column.len();
            if let Some(expected) = common_query_count {
                if query_count != expected {
                    return Err("queried-value columns have inconsistent row counts".into());
                }
            } else {
                common_query_count = Some(query_count);
            }
        }
    }
    let query_count =
        common_query_count.ok_or_else(|| "proof contains no queried-value columns".to_string())?;
    if query_count == 0 || query_count > fri.n_queries {
        return Err("deduplicated FRI query count is outside configured bounds".into());
    }

    let expected_inner_layers = max_log_degree_bound
        .checked_sub(1)
        .and_then(|after_circle_fold| {
            after_circle_fold.checked_sub(fri.log_last_layer_degree_bound)
        })
        .ok_or_else(|| "FRI last layer exceeds the folded composition bound".to_string())?
        as usize;
    if proof.stark_proof.fri_proof.inner_layers.len() != expected_inner_layers {
        return Err(format!(
            "FRI inner-layer count {}, expected {expected_inner_layers}",
            proof.stark_proof.fri_proof.inner_layers.len()
        ));
    }

    Ok(ProofProtocolShape {
        lifting_log_size,
        max_log_degree_bound,
        query_count,
    })
}

/// Safely replay the Stwo verifier transcript from the point immediately
/// after the interaction-tree commitment and return the exact number of
/// sorted/deduplicated FRI queries. All proof-owned vector dimensions must
/// first pass [`preflight_proof_structure`] and
/// [`preflight_proof_dimensions`]. This closes the remaining upstream
/// `MerkleVerifierLifted` assumption that every queried-value column has
/// exactly one value per deduplicated query.
pub fn expected_fiat_shamir_query_count(
    transcript_after_interaction: &crate::recursion_pcs::ProverChannel,
    stark_proof: &StarkProof<ProverMerkleHasher>,
    config: &PcsConfig,
    shape: ProofProtocolShape,
    expected_log_sizes: &[alloc::vec::Vec<u32>],
) -> Result<usize, alloc::string::String> {
    use stwo::core::{
        channel::MerkleChannel, circle::CirclePoint,
        pcs::utils::prepare_preprocessed_query_positions, queries::draw_queries,
    };

    let mut channel = transcript_after_interaction.clone();
    // Stwo verifier head: composition coefficient/root, then OODS point.
    let _ = channel.draw_secure_felt();
    let composition = stark_proof
        .commitments
        .get(PROOF_COMMITMENT_TREE_COUNT - 1)
        .copied()
        .ok_or_else(|| alloc::string::String::from("missing composition commitment"))?;
    <crate::recursion_pcs::ProverMerkleChannel as MerkleChannel>::mix_root(
        &mut channel,
        composition,
    );
    let _ = CirclePoint::<SecureField>::get_random_point(&mut channel);

    // CommitmentSchemeVerifier::verify_values prefix.
    for tree in stark_proof.sampled_values.iter() {
        for column in tree {
            channel.mix_felts(column);
        }
    }
    let _ = channel.draw_secure_felt();

    let fri = &stark_proof.fri_proof;
    <crate::recursion_pcs::ProverMerkleChannel as MerkleChannel>::mix_root(
        &mut channel,
        fri.first_layer.commitment,
    );
    let _ = channel.draw_secure_felt();
    for layer in &fri.inner_layers {
        <crate::recursion_pcs::ProverMerkleChannel as MerkleChannel>::mix_root(
            &mut channel,
            layer.commitment,
        );
        let _ = channel.draw_secure_felt();
    }
    channel.mix_felts(&fri.last_layer_poly);
    channel.mix_u64(stark_proof.proof_of_work);
    let mut positions = draw_queries(
        &mut channel,
        shape.lifting_log_size,
        config.fri_config.n_queries,
    );
    positions.sort_unstable();
    positions.dedup();
    if positions.len() != shape.query_count {
        return Err(alloc::string::String::from(
            "queried-value rows differ from Fiat-Shamir query positions",
        ));
    }

    let preprocessed_logs = expected_log_sizes
        .first()
        .ok_or_else(|| alloc::string::String::from("missing preprocessed tree shape"))?;
    let preprocessed_max_extended = match preprocessed_logs.iter().copied().max() {
        Some(log_size) => log_size
            .checked_add(config.fri_config.log_blowup_factor)
            .ok_or_else(|| {
                alloc::string::String::from("preprocessed tree height arithmetic overflow")
            })?,
        None => 0,
    };
    let preprocessed_height = config.lifting_log_size.unwrap_or(preprocessed_max_extended);
    let remapped = prepare_preprocessed_query_positions(
        &positions,
        shape.lifting_log_size,
        preprocessed_height,
    );
    validate_preprocessed_query_values(&remapped, &stark_proof.queried_values[0])?;
    Ok(positions.len())
}

fn validate_preprocessed_query_values(
    remapped_positions: &[usize],
    columns: &[alloc::vec::Vec<stwo::core::fields::m31::BaseField>],
) -> Result<(), alloc::string::String> {
    for (index, mapped) in remapped_positions.windows(2).enumerate() {
        if mapped[0] == mapped[1]
            && columns.iter().any(|column| {
                column
                    .get(index)
                    .zip(column.get(index + 1))
                    .is_none_or(|(left, right)| left != right)
            })
        {
            return Err(alloc::string::String::from(
                "duplicate preprocessed query positions carry different values",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod hostile_query_tests {
    use super::validate_preprocessed_query_values;
    use stwo::core::fields::m31::BaseField;

    #[test]
    fn duplicate_preprocessed_queries_are_checked_without_panicking() {
        let hostile = std::panic::catch_unwind(|| {
            validate_preprocessed_query_values(
                &[2, 2],
                &[alloc::vec![
                    BaseField::from_u32_unchecked(1),
                    BaseField::from_u32_unchecked(2),
                ]],
            )
        });
        assert!(hostile.is_ok());
        assert!(hostile.unwrap().is_err());

        validate_preprocessed_query_values(
            &[2, 2],
            &[alloc::vec![
                BaseField::from_u32_unchecked(1),
                BaseField::from_u32_unchecked(1),
            ]],
        )
        .unwrap();
    }
}

/// Minimum FRI proof-of-work bits the production verifier requires.
///
/// `production_pcs_config()` sets `pow_bits = 20`; this constant is
/// the policy floor used by `verify_*_with_min_pow_bits` and the
/// default `verify_*` (≈96-bit conjectured security).  A deployer
/// who needs more (e.g. to defend against a stronger adversary)
/// can raise the bar; a deployer who needs less for testing can
/// reach for the explicit `*_with_min_pow_bits` variants with a
/// lower floor.  See SECURITY.md "Proof shape" for the rationale.
pub const STANDARD_MIN_POW_BITS: u32 = 20;

/// Minimum FRI query count the production verifier requires.
/// Production config uses 19; lower counts trade soundness for
/// proof size.
pub const STANDARD_MIN_FRI_QUERIES: usize = 19;

/// Minimum FRI log-blowup-factor the production verifier requires.
/// Production config uses 4 (= blowup 16).  Higher means more
/// security per query at the cost of larger committed traces.
pub const STANDARD_MIN_FRI_LOG_BLOWUP: u32 = 4;

// ── Mobile / low-latency policy ────────────────────────────────────
// Track B: trades proof size for prove speed.
// Target: low-power devices where the prove-time-vs-proof-size
// curve favours faster prove.  ~2.5× faster than STANDARD on the
// reference bench at log14, ~1.4× larger proof.

/// PoW bits floor for the mobile policy (same as STANDARD —
/// PoW-grind cost is fixed per prove and doesn't help mobile when
/// raised, so we keep it at the standard 20).
pub const MOBILE_MIN_POW_BITS: u32 = 20;

/// FRI queries floor for the mobile policy.  At log_blowup=2 we
/// need 2× the queries of STANDARD (which uses log_blowup=4) to
/// hit the same security: 20 + 38·2 = 96.
pub const MOBILE_MIN_FRI_QUERIES: usize = 38;

/// FRI log-blowup floor for the mobile policy.  Halves the
/// FRI-prove-domain size vs STANDARD (blowup 4 vs 16) at the cost
/// of 2× more queries.  Net: ~2.5× faster prove on the bench.
pub const MOBILE_MIN_FRI_LOG_BLOWUP: u32 = 2;

/// PCS-config policy: a deployer-friendly bundle of the three
/// security knobs the verifier checks against `proof.pcs_config`.
///
/// `STANDARD` matches what `production_pcs_config()` sets, so the
/// default `verify` and `verify_standalone` paths use it
/// transparently.  Build a custom policy with `PcsPolicy { ... }`
/// and pass to the `*_with_pcs_policy` variants for stricter or
/// looser deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcsPolicy {
    /// Minimum acceptable `proof.pcs_config.pow_bits`.
    pub min_pow_bits: u32,
    /// Minimum acceptable `proof.pcs_config.fri_config.n_queries`.
    pub min_fri_queries: usize,
    /// Minimum acceptable `proof.pcs_config.fri_config.log_blowup_factor`.
    pub min_fri_log_blowup: u32,
}

impl PcsPolicy {
    /// Production policy — the floor `verify` / `verify_standalone`
    /// enforce by default.  Mirrors the values that
    /// `production_pcs_config()` produces.
    pub const STANDARD: Self = Self {
        min_pow_bits: STANDARD_MIN_POW_BITS,
        min_fri_queries: STANDARD_MIN_FRI_QUERIES,
        min_fri_log_blowup: STANDARD_MIN_FRI_LOG_BLOWUP,
    };

    /// Mobile / low-latency policy.  Mirrors
    /// `production_pcs_config_mobile()` — same 96-bit security as
    /// STANDARD, but at a different point on the prove-time vs
    /// proof-size curve (~2.5× faster, ~1.4× larger).  Verifiers
    /// that accept mobile-shape proofs should pass this policy
    /// (or a stricter custom one) to the `*_with_pcs_policy`
    /// variants.
    pub const MOBILE: Self = Self {
        min_pow_bits: MOBILE_MIN_POW_BITS,
        min_fri_queries: MOBILE_MIN_FRI_QUERIES,
        min_fri_log_blowup: MOBILE_MIN_FRI_LOG_BLOWUP,
    };
}

/// Validate `proof.pcs_config` against a policy.  Used by both
/// `vos_pvm_proof::verify` and `vos_pvm_proof_verifier::verify_standalone` so the
/// prover-side and verifier-only paths reject at the same threshold.
///
/// Returns a string description of the first failure for the caller
/// to wrap into `VerificationError::InvalidStructure`.
pub fn check_pcs_policy(
    config: &stwo::core::pcs::PcsConfig,
    policy: &PcsPolicy,
) -> Result<(), alloc::string::String> {
    use alloc::format;
    if config.pow_bits < policy.min_pow_bits {
        return Err(format!(
            "pcs_config.pow_bits {} < policy minimum {}",
            config.pow_bits, policy.min_pow_bits
        ));
    }
    if config.fri_config.n_queries < policy.min_fri_queries {
        return Err(format!(
            "pcs_config.fri_config.n_queries {} < policy minimum {}",
            config.fri_config.n_queries, policy.min_fri_queries
        ));
    }
    if config.fri_config.log_blowup_factor < policy.min_fri_log_blowup {
        return Err(format!(
            "pcs_config.fri_config.log_blowup_factor {} < policy minimum {}",
            config.fri_config.log_blowup_factor, policy.min_fri_log_blowup
        ));
    }
    Ok(())
}

/// Minimum conjectured FRI security (bits) the DEFAULT verify paths require.
///
/// Both named policies hit exactly this floor — STANDARD (20 + 19·4 = 96) and
/// MOBILE (20 + 38·2 = 96) — so the default `verify` / `verify_standalone`
/// accept EITHER shape without the caller naming a policy. The two policies
/// are incomparable per-field (STANDARD high-blowup/low-queries, MOBILE
/// low-blowup/high-queries), so a per-field policy floor can only ever accept
/// one of them; this single conjectured-security floor accepts both while
/// still rejecting degenerate FRI shapes. See SECURITY.md "Proof shape".
pub const MIN_CONJECTURED_SECURITY_BITS: u32 = 96;

/// Conjectured FRI soundness (bits) of a `PcsConfig`: `pow_bits +
/// n_queries · log_blowup_factor`. This is the standard heuristic the named
/// policies are tuned to (STANDARD and MOBILE both yield 96) — NOT a proven
/// bound; it exists so the default verify paths can gate on a single number
/// that both shapes satisfy.
pub fn conjectured_security_bits(config: &stwo::core::pcs::PcsConfig) -> u32 {
    checked_conjectured_security_bits(config).unwrap_or(u32::MAX)
}

/// Checked form of [`conjectured_security_bits`]. Wire-facing validation uses
/// this form so a hostile `usize` query count can never truncate to `u32` or
/// wrap the multiplication/addition into a passing security estimate.
pub fn checked_conjectured_security_bits(config: &stwo::core::pcs::PcsConfig) -> Option<u32> {
    let queries = u32::try_from(config.fri_config.n_queries).ok()?;
    let fri_bits = queries.checked_mul(config.fri_config.log_blowup_factor)?;
    config.pow_bits.checked_add(fri_bits)
}

/// Validate `proof.pcs_config` against the conjectured-security floor the
/// DEFAULT `verify` / `verify_standalone` paths enforce. Unlike
/// [`check_pcs_policy`] (an exact per-field pin), this accepts ANY shape
/// meeting the floor — so both STANDARD and MOBILE proofs verify by default —
/// while still rejecting degenerate FRI shapes. Returns `Err` (mirroring
/// `check_pcs_policy`'s style) if ANY of:
///   - `pow_bits < MOBILE_MIN_POW_BITS` (the shared PoW floor),
///   - `log_blowup_factor < MOBILE_MIN_FRI_LOG_BLOWUP` (rejects the
///     degenerate rate-1 / blowup-1 shapes, whose per-query soundness is nil),
///   - [`conjectured_security_bits`] `< MIN_CONJECTURED_SECURITY_BITS`.
///
/// STANDARD (20, 19, 4) and MOBILE (20, 38, 2) both pass (each is 96 bits);
/// a blowup-1 or a 95-bit config fails.
pub fn check_min_security(
    config: &stwo::core::pcs::PcsConfig,
) -> Result<(), alloc::string::String> {
    use alloc::format;
    if config.pow_bits < MOBILE_MIN_POW_BITS {
        return Err(format!(
            "pcs_config.pow_bits {} < security-floor minimum {}",
            config.pow_bits, MOBILE_MIN_POW_BITS
        ));
    }
    if config.fri_config.log_blowup_factor < MOBILE_MIN_FRI_LOG_BLOWUP {
        return Err(format!(
            "pcs_config.fri_config.log_blowup_factor {} < security-floor minimum {} \
             (degenerate FRI rate)",
            config.fri_config.log_blowup_factor, MOBILE_MIN_FRI_LOG_BLOWUP
        ));
    }
    let bits = checked_conjectured_security_bits(config).ok_or_else(|| {
        alloc::string::String::from("pcs_config conjectured-security arithmetic overflows")
    })?;
    if bits < MIN_CONJECTURED_SECURITY_BITS {
        return Err(format!(
            "pcs_config conjectured security {bits} bits < minimum {MIN_CONJECTURED_SECURITY_BITS}"
        ));
    }
    Ok(())
}
