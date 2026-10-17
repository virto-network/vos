#![cfg(feature = "prover")]

//! Negative AIR gates for the multiplication and division chips.
//!
//! Each gate is a whole proof: an execution whose destination register
//! holds a forged value, carried through every later step so the register
//! ledger agrees with it, proved by a prover that witnesses MulChip,
//! DivRemChip and the CpuChip's division columns as an adversary would.
//! The forged witness is written into the component traces between their
//! generation and their commitment, and the proof goes to the verifier with
//! the real chips. A gate passes when the forgery is refused, by the prover
//! or by the verifier.

mod common;
use common::*;

use stwo::core::ColumnVec;
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::prover::ComponentProver;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_constraint_framework::TraceLocationAllocator;

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm_proof::chips::cpu::Column as Cpu;
use vos_pvm_proof::chips::divrem::{self, Column as Div};
use vos_pvm_proof::chips::mul::{self, Column as Mul};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::pcs::ChannelRef;
use vos_pvm_proof::trace::component::ComponentTrace;
use vos_pvm_proof::{AirColumn, PcsPolicy, SideNote, chips};

// ── A chip whose trace the adversary rewrites ────────────────────────────

type ProducerPatch = Box<dyn Fn(&mut ComponentTrace, &mut SideNote) + Send + Sync>;
type ConsumerPatch = Box<dyn Fn(&mut ComponentTrace, &SideNote) + Send + Sync>;

enum Patch {
    /// For a chip that writes the side note (the CpuChip): may rewrite the
    /// entries and lookup multiplicities the chips after it read.
    Producer(ProducerPatch),
    Consumer(ConsumerPatch),
}

/// `inner`, with its main trace rewritten by `patch` after generation.
struct Forged {
    inner: &'static dyn MachineProverComponent,
    patch: Patch,
}

impl Forged {
    fn apply(&self, mut trace: ComponentTrace, side_note: &mut SideNote) -> ComponentTrace {
        match &self.patch {
            Patch::Producer(patch) => patch(&mut trace, side_note),
            Patch::Consumer(patch) => patch(&mut trace, side_note),
        }
        trace
    }

    fn apply_immut(&self, mut trace: ComponentTrace, side_note: &SideNote) -> ComponentTrace {
        match &self.patch {
            Patch::Producer(_) => panic!("a producer's trace is generated with the side note"),
            Patch::Consumer(patch) => patch(&mut trace, side_note),
        }
        trace
    }
}

impl MachineComponent for Forged {
    fn max_constraint_log_degree_bound(&self, log_size: u32) -> u32 {
        self.inner.max_constraint_log_degree_bound(log_size)
    }
    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
        self.inner.trace_sizes(log_size)
    }
    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32> {
        self.inner.preprocessed_trace_sizes(log_size)
    }
    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: ChannelRef<'_>,
    ) {
        self.inner.draw_lookup_elements(lookup_elements, channel)
    }
    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a> {
        self.inner
            .to_component(tree_span_provider, lookup_elements, log_size, claimed_sum)
    }
}

impl MachineProverComponent for Forged {
    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        self.inner.generate_preprocessed_trace(log_size, side_note)
    }
    fn is_producer(&self) -> bool {
        self.inner.is_producer()
    }
    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace {
        let trace = self.inner.generate_component_trace(side_note);
        self.apply(trace, side_note)
    }
    fn generate_component_trace_immut(&self, side_note: &SideNote) -> ComponentTrace {
        self.apply_immut(
            self.inner.generate_component_trace_immut(side_note),
            side_note,
        )
    }
    fn generate_component_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> ComponentTrace {
        let trace = self
            .inner
            .generate_component_trace_min(side_note, min_log_size);
        self.apply(trace, side_note)
    }
    fn generate_component_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> ComponentTrace {
        let trace = self
            .inner
            .generate_component_trace_immut_min(side_note, min_log_size);
        self.apply_immut(trace, side_note)
    }
    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        self.inner
            .generate_interaction_trace(component_trace, side_note, lookup_elements)
    }
    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a> {
        self.inner
            .to_component_prover(tree_span_provider, lookup_elements, log_size, claimed_sum)
    }
    #[cfg(feature = "debug-internals")]
    fn debug_assert_constraints(
        &self,
        component_trace: &ComponentTrace,
        interaction_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
        lookup_elements: &AllLookupElements,
        claimed_sum: SecureField,
    ) {
        self.inner.debug_assert_constraints(
            component_trace,
            interaction_trace,
            lookup_elements,
            claimed_sum,
        )
    }
}

/// The AIR's chips in their canonical order.
fn real_chips() -> Vec<&'static dyn MachineProverComponent> {
    vec![
        &chips::CpuChip,
        &chips::Blake2bChip,
        &chips::Blake2bBoundaryChip,
        &chips::MemoryChip,
        &chips::MemoryPageChip,
        &chips::MemoryMerkleChip,
        &chips::MemoryRootBoundaryChip,
        &chips::RegisterMemoryChip,
        &chips::RegisterMemoryBoundaryChip,
        &chips::RegisterMemoryClosingChip,
        &chips::ProgramBoundaryChip,
        &chips::ProgramMemoryChip,
        &chips::JumpTableChip,
        &chips::WitnessInputChip,
        &chips::RangeMultiplicity256,
        &chips::BitwiseLookupChip,
        &chips::PowerOfTwoChip,
        &chips::PopcountChip,
        &chips::BitcountChip,
        &chips::ByteToBitsChip,
        &chips::MulChip,
        &chips::BitwiseChip,
        &chips::CompareChip,
        &chips::DivRemChip,
        &chips::BitwiseAndByteChip,
    ]
}

const CPU: usize = 0;
const MUL: usize = 20;
const DIVREM: usize = 23;

/// Prove `steps` with the chips at the given indices replaced by forged
/// ones, and verify the proof with the real chips. `Ok` means the forgery
/// was accepted.
fn prove_forged(
    steps: Vec<vos_pvm_proof::core::step::PvmStep>,
    code: &[u8],
    bitmask: &[u8],
    forged: Vec<(usize, Patch)>,
) -> Result<(), String> {
    let mut side_note = SideNote::new(steps, code.to_vec(), bitmask.to_vec());
    vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
    let real = real_chips();
    let mut provers = real.clone();
    for (index, patch) in forged {
        let chip: &'static Forged = Box::leak(Box::new(Forged {
            inner: real[index],
            patch,
        }));
        provers[index] = chip;
    }
    let provers: &'static [&'static dyn MachineProverComponent] = Box::leak(provers.into());
    let proved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vos_pvm_proof::prove_with_explicit_components(
            &mut side_note,
            vos_pvm_proof::production_pcs_config(),
            provers,
        )
    }));
    let proof = match proved {
        Ok(Ok(proof)) => proof,
        Ok(Err(e)) => return Err(format!("prover refused: {e:?}")),
        Err(_) => return Err("prover panicked".into()),
    };
    let verifiers: Vec<&dyn MachineComponent> =
        real.iter().map(|c| *c as &dyn MachineComponent).collect();
    vos_pvm_proof::verify_with_explicit_components(
        proof,
        &side_note,
        &verifiers,
        &real,
        &PcsPolicy::STANDARD,
    )
    .map_err(|e| format!("verifier refused: {e:?}"))
}

fn assert_refused(result: Result<(), String>) {
    match result {
        Ok(()) => panic!("SOUNDNESS GAP: the forged execution proved and verified"),
        Err(why) => eprintln!("refused: {why}"),
    }
}

/// The register a ThreeReg gate program writes.
const RD: usize = 2;

/// A ThreeReg program `op rd, ra, rb; trap` with `ra = a`, `rb = b`,
/// traced.
fn traced_steps(
    op: Opcode,
    a: u64,
    b: u64,
) -> (Vec<vos_pvm_proof::core::step::PvmStep>, Vec<u8>, Vec<u8>) {
    let (ra, rb) = (0u8, 1u8);
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[ra as usize] = a;
    regs[rb as usize] = b;
    let (code, bitmask) = three_reg_program(op, RD as u8, ra, rb);
    let steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    assert_eq!(steps[0].opcode, op);
    (steps, code, bitmask)
}

/// [`traced_steps`] with `rd`'s value after the operation replaced by
/// `forged` in every step from it on.
fn forged_steps(
    op: Opcode,
    a: u64,
    b: u64,
    forged: u64,
) -> (Vec<vos_pvm_proof::core::step::PvmStep>, Vec<u8>, Vec<u8>) {
    let rd = RD;
    let (mut steps, code, bitmask) = traced_steps(op, a, b);
    assert_ne!(steps[0].regs_after[rd], forged, "the forgery must differ");
    steps[0].regs_after[rd] = forged;
    for step in steps.iter_mut().skip(1) {
        step.regs_before[rd] = forged;
        step.regs_after[rd] = forged;
    }
    (steps, code, bitmask)
}

// ── Trace cells ──────────────────────────────────────────────────────────

/// Where a trace of `log_size` keeps its logical row `row`: the builder
/// stores rows in the circle domain's bit-reversed order.
fn stored(log_size: u32, row: usize) -> usize {
    let rows: Vec<BaseField> = (0..1u32 << log_size).map(BaseField::from).collect();
    let order = vos_pvm_proof::trace::utils::finalize_columns(vec![rows]);
    order[0]
        .as_slice()
        .iter()
        .position(|&at| at == BaseField::from(row as u32))
        .expect("a row of the trace")
}

fn get(trace: &ComponentTrace, column: impl AirColumn, i: usize) -> BaseField {
    trace.original_trace[column.offset() + i].as_slice()[stored(trace.log_size, 0)]
}

fn set(trace: &mut ComponentTrace, column: impl AirColumn, i: usize, value: BaseField) {
    let at = stored(trace.log_size, 0);
    trace.original_trace[column.offset() + i].as_mut_slice()[at] = value;
}

fn set_bytes(trace: &mut ComponentTrace, column: impl AirColumn, bytes: &[u8]) {
    for (i, &byte) in bytes.iter().enumerate() {
        set(trace, column, i, f(byte as u32));
    }
}

fn bytes(trace: &ComponentTrace, column: impl AirColumn, n: usize) -> Vec<u32> {
    (0..n).map(|i| get(trace, column, i).0).collect()
}

fn f(x: u32) -> BaseField {
    BaseField::from(x)
}

fn inv256() -> BaseField {
    f(256).inverse()
}

// ── The adversary's division witness ─────────────────────────────────────

/// Rewrite the first CpuChip row's quotient and remainder, with every
/// column derived from them: the remainder's zero test, and the sign pins
/// with their nibble lookups' multiplicities.
fn forge_cpu_quotient(trace: &mut ComponentTrace, side_note: &mut SideNote, q: u64, r: u64) {
    let is_32bit = get(trace, Cpu::Is32Bit, 0).0 == 1;
    let src = if is_32bit { 3 } else { 7 };
    let (q, r) = (q.to_le_bytes(), r.to_le_bytes());
    let old_q = bytes(trace, Cpu::DivQuotient, 8);
    let old_r = bytes(trace, Cpu::DivRemainder, 8);
    for (old, new) in [(old_q[src] as u8, q[src]), (old_r[src] as u8, r[src])] {
        for (hi_lo, delta) in [(old, -1i64), (new, 1)] {
            for key in [(hi_lo >> 4, 8u8), (hi_lo & 0xF, 0xF)] {
                let count = side_note.bitwise_and_counts.entry(key).or_insert(0);
                *count = (*count as i64 + delta) as u32;
            }
        }
    }
    set_bytes(trace, Cpu::DivQuotient, &q);
    set_bytes(trace, Cpu::DivRemainder, &r);
    for (byte, sign_src, hi_nib, sign_bit) in [
        (q[src], Cpu::SignSrcQ, Cpu::SignQHiNib, Cpu::SignBitQ),
        (r[src], Cpu::SignSrcR, Cpu::SignRHiNib, Cpu::SignBitR),
    ] {
        set(trace, sign_src, 0, f(byte as u32));
        set(trace, hi_nib, 0, f((byte >> 4) as u32));
        set(trace, sign_bit, 0, f((byte >> 7) as u32));
    }
    let mut partial_nz = 0u32;
    for (i, &byte) in r.iter().enumerate() {
        let indicator = (byte != 0) as u32;
        let inverse = if byte != 0 {
            f(byte as u32).inverse()
        } else {
            f(0)
        };
        set(trace, Cpu::ValRByteInv, i, inverse);
        set(trace, Cpu::ValRByteIndicatorH, i, f(indicator));
        if i > 0 {
            set(
                trace,
                Cpu::ValRPartNZTimesIndH,
                i,
                f(partial_nz * indicator),
            );
        }
        partial_nz |= indicator;
        set(trace, Cpu::ValRPartialNZ, i, f(partial_nz));
    }
    let gate = get(trace, Cpu::IsDivSNotDbzH, 0);
    set(trace, Cpu::DivSActivePartialH, 0, gate * f(partial_nz));
}

/// `x + ~y` over 8 bytes: its bytes and carries; the top carry is `x > y`.
fn compare_chain(x: [u8; 8], y: [u8; 8]) -> ([u8; 8], [u8; 8]) {
    let (mut diff, mut carries) = ([0u8; 8], [0u8; 8]);
    let mut c = 0u16;
    for i in 0..8 {
        let s = x[i] as u16 + 255 - y[i] as u16 + c;
        diff[i] = s as u8;
        c = s >> 8;
        carries[i] = c as u8;
    }
    (diff, carries)
}

/// The DivRem entry for the quotient `q` and remainder `r`: its internal
/// witness — the chains' bytes and carries over the integers, as the honest
/// filler computes them — optionally with another high half or remainder
/// magnitude, the Range256 multiplicities moved with the values the chip
/// emits, so every byte-valued emission balances.
fn rewitness_entry(
    side_note: &mut SideNote,
    (q, r): (u64, u64),
    high: Option<[u8; 8]>,
    abs_r: Option<[u8; 8]>,
) {
    let e = &side_note.divrem_entries[0];
    let before: Vec<u8> = divrem::range_checked_bytes(e).collect();
    let mut e = divrem::witness(
        e.val_b,
        e.val_d,
        q,
        r,
        e.div_overflow,
        e.is_32bit,
        e.is_div_s,
        e.is_shar_r,
    );
    if let Some(high) = high {
        e.div_corr_hi = high;
    }
    if let Some(abs_r) = abs_r {
        e.abs_r = abs_r;
        (e.abs_cmp_diff, e.abs_cmp_carry) = compare_chain(e.abs_d, e.abs_r);
    }
    for b in before {
        side_note.range256_counts[b as usize] -= 1;
    }
    for b in divrem::range_checked_bytes(&e) {
        side_note.range256_counts[b as usize] += 1;
    }
    side_note.divrem_entries[0] = e;
}

/// The MulChip entry's low product taken from the forged result, with the
/// Range256 multiplicities moved to match.
fn forge_mul_entry(_: &mut ComponentTrace, side_note: &mut SideNote) {
    let e = &mut side_note.mul_entries[0];
    let before: Vec<u8> = mul::range_checked_bytes(e).collect();
    e.unsigned_product_low = e.result;
    let after: Vec<u8> = mul::range_checked_bytes(e).collect();
    for b in before {
        side_note.range256_counts[b as usize] -= 1;
    }
    for b in after {
        side_note.range256_counts[b as usize] += 1;
    }
}

/// Solve DivRemChip's 64-bit schoolbook carries in M31 for the row's
/// quotient, remainder and high half, whatever they are.
fn solve_schoolbook_in_m31(trace: &mut ComponentTrace) {
    let q = bytes(trace, Div::DivQuotient, 8);
    let d = bytes(trace, Div::ValD, 8);
    let r = bytes(trace, Div::DivRemainder, 8);
    let b = bytes(trace, Div::ValB, 8);
    let high = bytes(trace, Div::DivCorrHi, 8);
    let mut carry = f(0);
    for k in 0..16usize {
        let mut psum = f(0);
        for i in 0..8 {
            if let Some(j) = k.checked_sub(i).filter(|&j| j < 8) {
                psum += f(q[i] * d[j]);
            }
        }
        let rem = if k < 8 { f(r[k]) } else { f(0) };
        let expected = if k < 8 { f(b[k]) } else { f(high[k - 8]) };
        carry = (psum + rem + carry - expected) * inv256();
        set(trace, Div::DivMulCarry, k, carry);
        set(trace, Div::DivMulCarryHi, k, f(0));
    }
}

/// Solve the signed correction chain's carries in M31:
/// `H[i] + 256·c[i] = sq·d[i] + sd·is_div_s·q[i] + 255·sb + c[i−1]`,
/// `c[−1] = sr + overflow`.
fn solve_signed_chain_in_m31(trace: &mut ComponentTrace) {
    let q = bytes(trace, Div::DivQuotient, 8);
    let d = bytes(trace, Div::ValD, 8);
    let high = bytes(trace, Div::DivCorrHi, 8);
    let bit = |c: Div| get(trace, c, 0);
    let (sb, sd, sq) = (bit(Div::SignBitB), bit(Div::SignBitD), bit(Div::SignBitQ));
    let sd = sd * bit(Div::IsDivS);
    let mut carry = bit(Div::SignBitR) + bit(Div::DivOverflow);
    for i in 0..8 {
        carry = (sq * f(d[i]) + sd * f(q[i]) + f(255) * sb + carry - f(high[i])) * inv256();
        set(trace, Div::DivCorrCarry, i, carry);
    }
}

/// Solve the remainder-magnitude chain's carries in M31 for the row's AbsR.
fn solve_abs_r_in_m31(trace: &mut ComponentTrace) {
    let r = bytes(trace, Div::DivRemainder, 8);
    let abs_r = bytes(trace, Div::AbsR, 8);
    let mut carry = f(1);
    for i in 0..8 {
        carry = (f(255) - f(r[i]) + carry - f(abs_r[i])) * inv256();
        set(trace, Div::AbsRCarry, i, carry);
    }
}

fn producer(patch: impl Fn(&mut ComponentTrace, &mut SideNote) + Send + Sync + 'static) -> Patch {
    Patch::Producer(Box::new(patch))
}

fn consumer(patch: impl Fn(&mut ComponentTrace, &SideNote) + Send + Sync + 'static) -> Patch {
    Patch::Consumer(Box::new(patch))
}

// ── MulChip ──────────────────────────────────────────────────────────────

/// Take the forged result as the low product and solve the 64-bit
/// schoolbook carries in M31.
fn forge_mul_low_product(trace: &mut ComponentTrace, _: &SideNote) {
    let result = bytes(trace, Mul::Result, 8);
    let high = bytes(trace, Mul::MulHigh, 8);
    let psum: Vec<BaseField> = (0..16).map(|k| get(trace, Mul::PartialSum64, k)).collect();
    for (i, &byte) in result.iter().enumerate() {
        set(trace, Mul::UnsignedProductLow, i, f(byte));
    }
    let mut carry = f(0);
    for k in 0..16 {
        let out = if k < 8 { result[k] } else { high[k - 8] };
        carry = (psum[k] + carry - f(out)) * inv256();
        set(trace, Mul::MulCarry, k, carry);
        set(trace, Mul::MulCarryHi, k, f(0));
    }
}

/// G3-1: 6·7 proven as 41.
#[test]
fn mul64_carries_solved_in_m31_refused() {
    let (steps, code, bitmask) = forged_steps(Opcode::Mul64, 6, 7, 41);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![
            (CPU, producer(forge_mul_entry)),
            (MUL, consumer(forge_mul_low_product)),
        ],
    ));
}

/// G3-1: 1 << 3 proven as 0xDEAD_BEEF.
#[test]
fn shlo_l64_carries_solved_in_m31_refused() {
    let (steps, code, bitmask) = forged_steps(Opcode::ShloL64, 1, 3, 0xDEAD_BEEF);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![
            (CPU, producer(forge_mul_entry)),
            (MUL, consumer(forge_mul_low_product)),
        ],
    ));
}

// ── DivRemChip ───────────────────────────────────────────────────────────

/// G3-2: 100 / 7 proven as 13, the remainder honest (2), the schoolbook's
/// carries solved in M31 against a zero high half.
#[test]
fn divu64_carries_solved_in_m31_refused() {
    let (steps, code, bitmask) = forged_steps(Opcode::DivU64, 100, 7, 13);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![
            (
                CPU,
                producer(|trace, side_note| {
                    forge_cpu_quotient(trace, side_note, 13, 2);
                    rewitness_entry(side_note, (13, 2), Some([0; 8]), None);
                }),
            ),
            (DIVREM, consumer(|trace, _| solve_schoolbook_in_m31(trace))),
        ],
    ));
}

/// X-DIVHI / G3-4: `0x1000 >> 12` proven as `1 + 2^52`. The quotient times
/// 2^12 wraps to the dividend; every carry is a byte and the high half is
/// the product's own (1), so only a pinned high half refuses it.
#[test]
fn shlo_r64_quotient_top_bits_refused() {
    let forged = 1 + (1u64 << 52);
    let (steps, code, bitmask) = forged_steps(Opcode::ShloR64, 0x1000, 12, forged);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                forge_cpu_quotient(trace, side_note, forged, 0);
                rewitness_entry(side_note, (forged, 0), None, None);
            }),
        )],
    ));
}

/// G3-4: `-1024 >> 3` (arithmetic, -128) proven as the logical shift
/// `2^61 - 128`, a witness of byte carries and a zero high half: only a
/// tuple flag telling SharR from ShloR refuses it.
#[test]
fn shar_r64_sign_dropped_refused() {
    let logical = (-1024i64 as u64) >> 3;
    let (steps, code, bitmask) = forged_steps(Opcode::SharR64, -1024i64 as u64, 3, logical);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                forge_cpu_quotient(trace, side_note, logical, 0);
                rewitness_entry(side_note, (logical, 0), None, None);
            }),
        )],
    ));
}

/// G3-3: `-100 rem 7` (-2) proven as -9 with quotient -13: an exact
/// integer identity, `|r| = 9 > 7` hidden by a remainder magnitude of 0
/// whose negation-chain carries are solved in M31.
#[test]
fn rems64_magnitude_carries_solved_in_m31_refused() {
    let (q, r) = (-13i64 as u64, -9i64 as u64);
    let (steps, code, bitmask) = forged_steps(Opcode::RemS64, -100i64 as u64, 7, r);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![
            (
                CPU,
                producer(move |trace, side_note| {
                    forge_cpu_quotient(trace, side_note, q, r);
                    rewitness_entry(side_note, (q, r), None, Some([0; 8]));
                }),
            ),
            (DIVREM, consumer(|trace, _| solve_abs_r_in_m31(trace))),
        ],
    ));
}

/// G3-3: `-100 / 7` (-14) proven as the quotient `0xDB6D…DB60` with
/// remainder -4: `q·7 + r ≡ -100 (mod 2^64)` only, the high half the
/// product's own, the signed correction chain's carries solved in M31.
#[test]
fn divs64_correction_carries_solved_in_m31_refused() {
    let (q, r) = (0xDB6D_B6DB_6DB6_DB60u64, -4i64 as u64);
    let (steps, code, bitmask) = forged_steps(Opcode::DivS64, -100i64 as u64, 7, q);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![
            (
                CPU,
                producer(move |trace, side_note| {
                    forge_cpu_quotient(trace, side_note, q, r);
                    rewitness_entry(side_note, (q, r), None, None);
                }),
            ),
            (
                DIVREM,
                consumer(|trace, _| solve_signed_chain_in_m31(trace)),
            ),
        ],
    ));
}

/// 32-bit signed division by a negative divisor: `100 / -7` (-14 rem 2)
/// proven as -13 rem 9. Every chain holds over the integers; the divisor's
/// magnitude, taken over the 8 bytes of a zero-extended 32-bit value, is
/// about 2^64 and admits `|r| = 9`.
#[test]
fn divs32_negative_divisor_magnitude_refused() {
    let (q, r) = (-13i64 as u64, 9u64);
    let (steps, code, bitmask) = forged_steps(Opcode::DivS32, 100, -7i64 as u64, q);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                forge_cpu_quotient(trace, side_note, q, r);
                rewitness_entry(side_note, (q, r), None, None);
            }),
        )],
    ));
}

/// `100 / 7` proven as 13 rem 9: `13·7 + 9 = 100` exactly, every chain
/// over the integers, but `r ≥ d`: the `r < d` chain refuses it.
#[test]
fn divu64_remainder_not_below_divisor_refused() {
    let (steps, code, bitmask) = forged_steps(Opcode::DivU64, 100, 7, 13);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(|trace, side_note| {
                forge_cpu_quotient(trace, side_note, 13, 9);
                rewitness_entry(side_note, (13, 9), None, None);
            }),
        )],
    ));
}

// ── 32-bit chains and the flag byte ──────────────────────────────────────

/// `-100 / 7` in 32 bits (-14 rem -2) with the remainder's low word honest
/// and its high word zeroed: the 32-bit schoolbook and sign chain read the
/// low word alone, so the remainder must be read as a sign-extended word
/// somewhere else, or a register of the run could hold either word.
#[test]
fn divs32_remainder_high_word_zeroed_refused() {
    let (steps, code, bitmask) = traced_steps(Opcode::DivS32, (-100i32) as u32 as u64, 7);
    let q = steps[0].regs_after[RD];
    assert_eq!(q, -14i64 as u64);
    let r = 0x0000_0000_FFFF_FFFEu64;
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                forge_cpu_quotient(trace, side_note, q, r);
                rewitness_entry(side_note, (q, r), None, None);
            }),
        )],
    ));
}

/// `-1024 >> 3` in 32 bits (arithmetic, -128) proven as the logical shift
/// `0x1FFF_FF80`: `q·8 = b` modulo 2^32 with `r = 0`, every chain over the
/// integers, so only the 32-bit sign chain's high half refuses it.
#[test]
fn shar_r32_sign_dropped_refused() {
    let logical = u64::from((-1024i32) as u32 >> 3);
    assert_eq!(logical, 0x1FFF_FF80);
    let (steps, code, bitmask) =
        forged_steps(Opcode::SharR32, (-1024i32) as u32 as u64, 3, logical);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                forge_cpu_quotient(trace, side_note, logical, 0);
                rewitness_entry(side_note, (logical, 0), None, None);
            }),
        )],
    ));
}

/// `-1024 >> 3` (arithmetic) proven as the logical shift with `is_shar_r`
/// cleared on the CpuChip row and in DivRemChip's: both chips then agree
/// on a logical shift, and only the flag's place in the instruction's
/// committed flag byte (byte 0, bit 3, through the byte-to-bits table)
/// refuses it.
#[test]
fn shar_r64_flag_cleared_refused() {
    let logical = (-1024i64 as u64) >> 3;
    let (steps, code, bitmask) = forged_steps(Opcode::SharR64, -1024i64 as u64, 3, logical);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                assert_eq!(get(trace, Cpu::IsSharR, 0), f(1));
                set(trace, Cpu::IsSharR, 0, f(0));
                forge_cpu_quotient(trace, side_note, logical, 0);
                let e = &side_note.divrem_entries[0];
                let before: Vec<u8> = divrem::range_checked_bytes(e).collect();
                let e = divrem::witness(e.val_b, e.val_d, logical, 0, false, false, false, false);
                for b in before {
                    side_note.range256_counts[b as usize] -= 1;
                }
                for b in divrem::range_checked_bytes(&e) {
                    side_note.range256_counts[b as usize] += 1;
                }
                side_note.divrem_entries[0] = e;
            }),
        )],
    ));
}

// ── Controls: the same forgeries with honest witnesses ───────────────────

/// 6·7 as 41 with the low product and carries the honest filler writes.
#[test]
fn mul64_honest_carries_refused() {
    let (steps, code, bitmask) = forged_steps(Opcode::Mul64, 6, 7, 41);
    assert_refused(prove_forged(steps, &code, &bitmask, vec![]));
}

/// `0x1000 >> 12` with the quotient's bits below 2^52 forged: the
/// schoolbook itself refuses it.
#[test]
fn shlo_r64_quotient_low_bits_refused() {
    let (steps, code, bitmask) = forged_steps(Opcode::ShloR64, 0x1000, 12, 2);
    assert_refused(prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(|trace, side_note| {
                forge_cpu_quotient(trace, side_note, 2, 0);
                rewitness_entry(side_note, (2, 0), None, None);
            }),
        )],
    ));
}

/// `-100 / 7` in 32 bits with the honest, sign-extended remainder
/// rewitnessed through the harness proves.
#[test]
fn divs32_honest_remainder_through_the_harness_proves() {
    let (steps, code, bitmask) = traced_steps(Opcode::DivS32, (-100i32) as u32 as u64, 7);
    let q = steps[0].regs_after[RD];
    let r = -2i64 as u64;
    prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(
            CPU,
            producer(move |trace, side_note| {
                forge_cpu_quotient(trace, side_note, q, r);
                rewitness_entry(side_note, (q, r), None, None);
            }),
        )],
    )
    .expect("the honest remainder proves");
}

/// The harness itself: an honest execution through the forging chips
/// with no rewrite proves and verifies.
#[test]
fn honest_execution_through_the_harness_proves() {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = -100i64 as u64;
    regs[1] = 7;
    let (code, bitmask) = three_reg_program(Opcode::RemS64, 2, 0, 1);
    let steps = trace_until_opcode_zero(code.clone(), bitmask.clone(), regs);
    prove_forged(
        steps,
        &code,
        &bitmask,
        vec![(CPU, producer(|_, _| {})), (DIVREM, consumer(|_, _| {}))],
    )
    .expect("an honest execution proves through the harness");
}
