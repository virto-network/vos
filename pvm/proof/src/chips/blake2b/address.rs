//! The guest addresses `Blake2bChip` reads and writes: byte `i` of `h` at
//! `h_ptr + i` (read on a compression's first row, its digest written back on
//! the last), byte `k` of `m` at `m_ptr + k` (read on the first row), each as
//! four u32 byte limbs.
//!
//! Limb 0 of `ptr + i` is the expression `ptr0 + i − 256·c_i`, with `c_i` the
//! boolean carry out of the low byte, range-checked to a byte. Limbs 1..3 are
//! columns equal to the pointer's own limbs when `c_i = 0` and to the limbs of
//! `(ptr >> 8) + 1` when `c_i = 1`; that increment is a per-row decomposition
//! with boolean carries and range-checked limbs and no carry out of limb 3.
//! Every identity is over small integers, so each address is `ptr + i`
//! exactly, never a value congruent to it modulo p, and a pointer whose
//! increment would wrap 2^32 has no satisfying row (the runtime refuses a
//! range that wraps as well). The limb relations hold on every row, so the
//! writing row's addresses are pinned on that row, not only on the first.

#[allow(unused_imports)]
use alloc::{vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::prover::backend::simd::{m31::PackedBaseField, qm31::PackedSecureField};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::columns::{Column, PreprocessedColumn};
use crate::lookups::Range256LookupElements;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::{
    lookups::LogupTraceBuilder,
    side_note::SideNote,
    trace::{
        builder::TraceBuilder,
        component::{ComponentTrace, FinalizedColumn},
    },
};

/// One pointer's address columns.
#[derive(Clone, Copy)]
pub(super) struct AddressColumns {
    /// The pointer's four limbs, constant across the compression.
    pub ptr: Column,
    /// `c_i`, the carry out of limb 0 of `ptr + i`.
    pub carry: Column,
    /// Limbs 1, 2 and 3 of `ptr + i`.
    pub limbs: [Column; 3],
    /// Limbs 0..3 of `(ptr >> 8) + 1`.
    pub inc: Column,
    /// The carries out of the increment's limbs 0 and 1.
    pub inc_carry: Column,
}

pub(super) const H: AddressColumns = AddressColumns {
    ptr: Column::HPtr,
    carry: Column::HAddrCarry,
    limbs: [Column::HAddrB1, Column::HAddrB2, Column::HAddrB3],
    inc: Column::HPtrInc,
    inc_carry: Column::HPtrIncCarry,
};

pub(super) const M: AddressColumns = AddressColumns {
    ptr: Column::MPtr,
    carry: Column::MAddrCarry,
    limbs: [Column::MAddrB1, Column::MAddrB2, Column::MAddrB3],
    inc: Column::MPtrInc,
    inc_carry: Column::MPtrIncCarry,
};

/// `ptr + i` for `i < N`, at one row, as AIR expressions.
pub(super) struct Addresses<E: EvalAtRow, const N: usize> {
    ptr: [E::F; 4],
    carry: [E::F; N],
    limbs: [[E::F; N]; 3],
    inc: [E::F; 3],
    inc_carry: [E::F; 2],
}

impl<E: EvalAtRow, const N: usize> Addresses<E, N> {
    pub fn read(
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        cols: AddressColumns,
    ) -> Self {
        Self {
            ptr: trace_eval.column_eval::<4>(cols.ptr),
            carry: trace_eval.column_eval::<N>(cols.carry),
            limbs: cols.limbs.map(|col| trace_eval.column_eval::<N>(col)),
            inc: trace_eval.column_eval::<3>(cols.inc),
            inc_carry: trace_eval.column_eval::<2>(cols.inc_carry),
        }
    }

    /// Booleanity of every carry, the increment on real rows, and limbs 1..3
    /// of every address on every row (zero on padding, where `c_i = 0`).
    pub fn constrain(&self, eval: &mut E, is_real: &E::F) {
        let one = E::F::from(BaseField::from(1u32));
        let b256 = E::F::from(BaseField::from(256u32));
        for c in self.carry.iter().chain(&self.inc_carry) {
            eval.add_constraint(c.clone() * (c.clone() - one.clone()));
        }
        let [inc0, inc1, inc2] = self.inc.clone();
        let [e0, e1] = self.inc_carry.clone();
        let [_, p1, p2, p3] = self.ptr.clone();
        eval.add_constraint(is_real.clone() * (inc0 + b256.clone() * e0.clone() - p1 - one));
        eval.add_constraint(is_real.clone() * (inc1 + b256 * e1.clone() - p2 - e0));
        eval.add_constraint(is_real.clone() * (inc2 - p3 - e1));
        for k in 0..3 {
            let p = self.ptr[k + 1].clone();
            let step = self.inc[k].clone() - p.clone();
            for i in 0..N {
                eval.add_constraint(
                    self.limbs[k][i].clone() - p.clone() - self.carry[i].clone() * step.clone(),
                );
            }
        }
    }

    /// The four limbs of `ptr + i`.
    pub fn address(&self, i: usize) -> [E::F; 4] {
        let b256 = E::F::from(BaseField::from(256u32));
        let offset = E::F::from(BaseField::from(i as u32));
        [
            self.ptr[0].clone() + offset - b256 * self.carry[i].clone(),
            self.limbs[0][i].clone(),
            self.limbs[1][i].clone(),
            self.limbs[2][i].clone(),
        ]
    }

    /// Range256 lookups of every limb 0 and of the increment's limbs, with
    /// multiplicity `mult` (the rows whose tuples carry these addresses).
    pub fn add_range_lookups(&self, eval: &mut E, range256: &Range256LookupElements, mult: &E::F) {
        let limbs0 = (0..N).map(|i| self.address(i)[0].clone());
        for value in limbs0.chain(self.inc.iter().cloned()) {
            eval.add_to_relation(RelationEntry::new(range256, mult.clone().into(), &[value]));
        }
    }
}

/// `ptr + i` for `i < N` in a component trace.
#[cfg(feature = "prover")]
pub(super) struct AddressTrace<'a, const N: usize> {
    ptr0: FinalizedColumn<'a>,
    carry: [FinalizedColumn<'a>; N],
    limbs: [[FinalizedColumn<'a>; N]; 3],
    inc: [FinalizedColumn<'a>; 3],
}

#[cfg(feature = "prover")]
impl<'a, const N: usize> AddressTrace<'a, N> {
    pub fn read(trace: &'a ComponentTrace, cols: AddressColumns) -> Self {
        let [ptr0, ..] = trace.original_base_column::<4, _>(cols.ptr);
        Self {
            ptr0,
            carry: trace.original_base_column::<N, _>(cols.carry),
            limbs: cols
                .limbs
                .map(|col| trace.original_base_column::<N, _>(col)),
            inc: trace.original_base_column::<3, _>(cols.inc),
        }
    }

    /// The four limbs of `ptr + i`, at packed row `v`, as columns the
    /// tuple closures evaluate.
    pub fn address(&self, i: usize) -> impl Fn(usize) -> [PackedBaseField; 4] {
        let (ptr0, carry) = (self.ptr0.clone(), self.carry[i].clone());
        let limbs = [
            self.limbs[0][i].clone(),
            self.limbs[1][i].clone(),
            self.limbs[2][i].clone(),
        ];
        let offset = PackedBaseField::broadcast(BaseField::from(i as u32));
        let b256 = PackedBaseField::broadcast(BaseField::from(256u32));
        move |v| {
            [
                ptr0.at(v) + offset - b256 * carry.at(v),
                limbs[0].at(v),
                limbs[1].at(v),
                limbs[2].at(v),
            ]
        }
    }

    /// Mirror of [`Addresses::add_range_lookups`], the multiplicity the sum
    /// of `mult`.
    pub fn add_range_lookups<const K: usize>(
        &self,
        logup: &mut LogupTraceBuilder,
        range256: &Range256LookupElements,
        mult: [FinalizedColumn<'a>; K],
    ) {
        let sum = |m: [PackedBaseField; K]| -> PackedSecureField {
            m.into_iter()
                .fold(PackedBaseField::broadcast(BaseField::from(0u32)), |a, b| {
                    a + b
                })
                .into()
        };
        for i in 0..N {
            let address = self.address(i);
            logup.add_to_relation_computed(range256, mult.clone(), sum, 1, move |v| {
                vec![address(v)[0]]
            });
        }
        for inc in &self.inc {
            let inc = inc.clone();
            logup
                .add_to_relation_computed(range256, mult.clone(), sum, 1, move |v| vec![inc.at(v)]);
        }
    }
}

/// The limbs of `ptr + i` for `i < N`: limb 0 and its carry out, limbs 1..3.
#[cfg(feature = "prover")]
fn limbs<const N: usize>(ptr: u32) -> ([u8; N], [u8; N], [[u8; N]; 3]) {
    let p = ptr.to_le_bytes();
    let inc = increment(ptr);
    let mut limbs0 = [0u8; N];
    let mut carry = [0u8; N];
    let mut upper = [[0u8; N]; 3];
    for i in 0..N {
        let sum = p[0] as usize + i;
        let c = sum >= 256;
        limbs0[i] = sum as u8;
        carry[i] = c as u8;
        for k in 0..3 {
            upper[k][i] = if c { inc[k] } else { p[k + 1] };
        }
    }
    (limbs0, carry, upper)
}

/// Limbs 0..3 of `(ptr >> 8) + 1`. A pointer whose increment overflows 24
/// bits gets limbs 0 with both carries set, which the AIR refuses: no
/// address of its range is provable.
#[cfg(feature = "prover")]
fn increment(ptr: u32) -> [u8; 3] {
    let inc = ((ptr >> 8) + 1).to_le_bytes();
    [inc[0], inc[1], inc[2]]
}

/// Fill `ptr + i` for `i < N` on one row.
#[cfg(feature = "prover")]
pub(super) fn fill<const N: usize>(
    trace: &mut TraceBuilder<Column>,
    row: usize,
    ptr: u32,
    cols: AddressColumns,
) {
    let p = ptr.to_le_bytes();
    let (_, carry, upper) = limbs::<N>(ptr);
    trace.fill_columns_bytes(row, &carry, cols.carry);
    for k in 0..3 {
        trace.fill_columns_bytes(row, &upper[k], cols.limbs[k]);
    }
    let e0 = p[1] == 0xff;
    let e1 = e0 && p[2] == 0xff;
    trace.fill_columns_bytes(row, &increment(ptr), cols.inc);
    trace.fill_columns_bytes(row, &[e0 as u8, e1 as u8], cols.inc_carry);
}

/// Count the Range256 lookups of `ptr + i` for `i < N`, `uses` times (the
/// rows of a compression that emit them).
#[cfg(feature = "prover")]
pub(super) fn count_range_lookups<const N: usize>(side_note: &mut SideNote, ptr: u32, uses: usize) {
    let (limbs0, _, _) = limbs::<N>(ptr);
    for _ in 0..uses {
        for &limb in limbs0.iter().chain(&increment(ptr)) {
            side_note.add_range256(limb);
        }
    }
}
