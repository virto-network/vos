//! Blake2b compression precompile — 96 rows per hash (one per G-function call).
//!
//! G(a, b, c, d, mx, my):
//!   a1 = a + b + mx;  xor1 = d ^ a1;  d1 = xor1 >>> 32  (byte permutation)
//!   c1 = c + d1;      xor2 = b ^ c1;  b1 = xor2 >>> 24  (byte permutation)
//!   a' = a1 + b1 + my; xor3 = d1 ^ a'; d' = xor3 >>> 16  (byte permutation)
//!   c' = c1 + d';     xor4 = b1 ^ c'; b' = xor4 >>> 63  (1-bit carry)
//!
//! Each G-row emits 48 byte-wide AND lookups (six a byte, over eight bytes:
//! the four XORs' ANDs and two for the rotation's split) to the bitwise AND
//! table (`BitwiseAndByteLookupElements`), constraining the AND witnesses
//! the XORs derive from.

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::trace::eval::TraceEval;

use crate::{
    framework::BuiltInComponent,
    lookups::{
        BitwiseAndByteLookupElements, Blake2bCallLookupElements, MemoryAccessLookupElements,
        Range256LookupElements,
    },
};

mod address;
mod boundary;
mod call;
mod columns;
mod compression;
mod consts;
mod sw;
#[cfg(feature = "prover")]
mod trace;

pub use boundary::{Blake2bBoundaryChip, BoundaryColumn};
pub use call::Blake2bCall;
pub use sw::blake2b_compress;

use columns::{CompressionColumns, PreprocessedColumn};
// Re-exported (gate tests reach `Column::IsReal`/`Output` offsets to tamper).
pub use columns::Column;
use compression::{add_compression_core, read_schedule};

#[derive(Clone, Copy)]
pub struct Blake2bChip;

impl BuiltInComponent for Blake2bChip {
    // The carries' bounds, `is_real · c · (c-1) · (c-2)` and its kin, are
    // flattened to degree 2 by helper columns (`compression::constraints`'s
    // `carry_bounds`), within the bound CpuChip uses.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        Range256LookupElements,
        BitwiseAndByteLookupElements,
        MemoryAccessLookupElements,
        Blake2bCallLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            Range256LookupElements,
            BitwiseAndByteLookupElements,
            MemoryAccessLookupElements,
            Blake2bCallLookupElements,
        ),
    ) {
        let (range256_lookup, bitwise_lookup, mem_lookup, blake2b_call_lookup) = lookup_elements;
        let one = E::F::one();

        // ── IsReal anchor ──────────────────────────────────────────────
        // A compression's first row consumes the CPU's call and reads `h`
        // and `m`; its last row writes the digest. Nothing outside this
        // chip relates the two rows, so IsReal is boolean, constant across
        // the 96 rows (ContinuityGate is 0 at the row-95 block boundary and
        // on the last trace row, whose next row wraps to row 0), and 0 in
        // the trailing partial block, which has no row 95. A real first row
        // therefore implies a real last row, chained to it by GateH.
        //
        // These and the address relations are emitted before the first
        // lookup, so a violation unwinds before the evaluator holds pending
        // logup state.
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let is_real_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsReal);
        let continuity_gate =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ContinuityGate);
        let is_tail =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsTail);
        eval.add_constraint(is_real[0].clone() * (is_real[0].clone() - one.clone()));
        eval.add_constraint(
            continuity_gate[0].clone() * (is_real_next[0].clone() - is_real[0].clone()),
        );
        eval.add_constraint(is_tail[0].clone() * is_real[0].clone());

        // ── Addresses: `h_ptr + i`, `m_ptr + k` as u32 byte limbs ─────
        let h_addr = address::Addresses::<E, 64>::read(&trace_eval, address::H);
        let m_addr = address::Addresses::<E, 128>::read(&trace_eval, address::M);
        h_addr.constrain(eval, &is_real[0]);
        m_addr.constrain(eval, &is_real[0]);

        // T[8..16] = 0 — the ECALL handler only uses the low 8 bytes of t,
        // so the upper half must be zero for the binding to CpuChip TLow
        // to be unambiguous.  Gated by is_real so padding rows are inert.
        let t_e = crate::trace::trace_eval!(trace_eval, Column::T);
        for i in 8..16 {
            eval.add_constraint(is_real[0].clone() * t_e[i].clone());
        }

        // Arithmetic compression core (G-function, V-chain, output
        // derivation, BitwiseAnd / Range256 lookups, the GateH / InitGateH /
        // OutputGateH helper definitions) — shared with Blake2bBoundaryChip.
        let sched = read_schedule(&trace_eval);
        add_compression_core(eval, &trace_eval, &sched, range256_lookup, bitwise_lookup);

        let init_gate = crate::trace::trace_eval!(trace_eval, Column::InitGateH)[0].clone();
        let output_gate = crate::trace::trace_eval!(trace_eval, Column::OutputGateH)[0].clone();
        let gate = crate::trace::trace_eval!(trace_eval, Column::GateH)[0].clone();
        let output_e = crate::trace::trace_eval!(trace_eval, Column::Output);
        let h_cols: [_; 8] = Column::H.map(|col| trace_eval.column_eval::<8>(col));
        let m_cols: [_; 16] = Column::M.map(|col| trace_eval.column_eval::<8>(col));

        // ── ECALL memory binding ──────────────────────
        // HPtr / MPtr / CallTs are witnessed per row and constant within a
        // compression.
        let h_ptr_e = crate::trace::trace_eval!(trace_eval, Column::HPtr);
        let m_ptr_e = crate::trace::trace_eval!(trace_eval, Column::MPtr);
        let call_ts_e = crate::trace::trace_eval!(trace_eval, Column::CallTs);
        let h_ptr_next = crate::trace::trace_eval_next_row!(trace_eval, Column::HPtr);
        let m_ptr_next = crate::trace::trace_eval_next_row!(trace_eval, Column::MPtr);
        let call_ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::CallTs);
        for i in 0..4 {
            eval.add_constraint(gate.clone() * (h_ptr_next[i].clone() - h_ptr_e[i].clone()));
            eval.add_constraint(gate.clone() * (m_ptr_next[i].clone() - m_ptr_e[i].clone()));
        }
        for i in 0..8 {
            eval.add_constraint(gate.clone() * (call_ts_next[i].clone() - call_ts_e[i].clone()));
        }

        // Limb 0 of every address and the increments are bytes on the rows
        // that emit them: `h` on the first and last rows, `m` on the first.
        h_addr.add_range_lookups(
            eval,
            range256_lookup,
            &(init_gate.clone() + output_gate.clone()),
        );
        m_addr.add_range_lookups(eval, range256_lookup, &init_gate);

        // ── Memory-access tuples (addr[4], value, ts[8], is_write, is_closing) ──
        // Their address limbs are bytes by the addresses' carry identity and
        // range checks above, which the word ledger's group test by 16-bit
        // halves rests on (`word_memory`).
        let f_zero = E::F::zero();
        let mut access = |addr: [E::F; 4], value: E::F, is_write: E::F, mult: &E::F| {
            let mut tuple: Vec<E::F> = Vec::with_capacity(15);
            tuple.extend(addr);
            tuple.push(value);
            tuple.extend(call_ts_e.iter().cloned());
            tuple.push(is_write);
            tuple.push(f_zero.clone()); // is_closing = 0
            eval.add_to_relation(RelationEntry::new(mem_lookup, mult.clone().into(), &tuple));
        };
        // 64 h reads and 128 m reads on the first row.
        for i in 0..64usize {
            access(
                h_addr.address(i),
                h_cols[i / 8][i % 8].clone(),
                f_zero.clone(),
                &init_gate,
            );
        }
        for k in 0..128usize {
            access(
                m_addr.address(k),
                m_cols[k / 8][k % 8].clone(),
                f_zero.clone(),
                &init_gate,
            );
        }
        // 64 digest writes on the last row, at that row's `h` addresses
        // (Output is populated on the last row only).
        for i in 0..64usize {
            access(
                h_addr.address(i),
                output_e[i].clone(),
                one.clone(),
                &output_gate,
            );
        }

        // ── Consumer linking to CpuChip ECALL step ──
        // Tuple (h_ptr[0..4], m_ptr[0..4], T[0..8], F, CallTs[0..8]) = 25 limbs,
        // multiplicity −InitGateH so CpuChip's producer (+is_blake_ecall)
        // balances.
        let f_col_e = crate::trace::trace_eval!(trace_eval, Column::F);
        let mut tuple: Vec<E::F> = Vec::with_capacity(25);
        tuple.extend(h_ptr_e.iter().cloned());
        tuple.extend(m_ptr_e.iter().cloned());
        tuple.extend(t_e[..8].iter().cloned());
        tuple.push(f_col_e[0].clone());
        tuple.extend(call_ts_e.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            blake2b_call_lookup,
            (-init_gate).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::consts::IV;
    use super::sw::g_func;
    use super::trace::g_traced;
    use super::*;

    #[test]
    fn test_blake2b_compress() {
        let h = IV;
        let m = [0u64; 16];
        let result = blake2b_compress(&h, &m, 0, true);
        assert_ne!(result, [0u64; 8]);
        let result2 = blake2b_compress(&h, &m, 0, true);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_g_traced_consistency() {
        // Verify g_traced produces the same outputs as g_func
        let mut v1 = [0u64; 16];
        v1[0] = 0x6A09E667F3BCC908;
        v1[4] = 0xBB67AE8584CAA73B;
        v1[8] = 0x3C6EF372FE94F82B;
        v1[12] = 0xA54FF53A5F1D36F1;
        let mx = 0x0123456789ABCDEF;
        let my = 0xFEDCBA9876543210;

        let mut v2 = v1;
        g_func(&mut v2, 0, 4, 8, 12, mx, my);

        let m_full = [0u64; 16];
        let h_full = [0u64; 8];
        let row = g_traced(
            &v1, &m_full, &h_full, 0u128, false, v1[0], v1[4], v1[8], v1[12], mx, my,
        );
        assert_eq!(u64::from_le_bytes(row.a_out), v2[0]);
        assert_eq!(u64::from_le_bytes(row.b_out), v2[4]);
        assert_eq!(u64::from_le_bytes(row.c_out), v2[8]);
        assert_eq!(u64::from_le_bytes(row.d_out), v2[12]);
        // State snapshot captured before the G-call should match v1.
        for k in 0..16 {
            assert_eq!(u64::from_le_bytes(row.v[k]), v1[k]);
        }
    }
}
