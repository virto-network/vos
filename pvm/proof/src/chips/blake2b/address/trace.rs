//! The address limbs' trace generation, the prover's half.

use super::*;
use crate::prelude::*;
use crate::{
    lookups::LogupTraceBuilder,
    side_note::SideNote,
    trace::{
        builder::TraceBuilder,
        component::{ComponentTrace, FinalizedColumn},
    },
};
use stwo::prover::backend::simd::{m31::PackedBaseField, qm31::PackedSecureField};

/// `ptr + i` for `i < N` in a component trace.
pub(in crate::chips::blake2b) struct AddressTrace<'a, const N: usize> {
    ptr0: FinalizedColumn<'a>,
    carry: [FinalizedColumn<'a>; N],
    limbs: [[FinalizedColumn<'a>; N]; 3],
    inc: [FinalizedColumn<'a>; 3],
}

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
fn increment(ptr: u32) -> [u8; 3] {
    let inc = ((ptr >> 8) + 1).to_le_bytes();
    [inc[0], inc[1], inc[2]]
}

/// Fill `ptr + i` for `i < N` on one row.
pub(in crate::chips::blake2b) fn fill<const N: usize>(
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
pub(in crate::chips::blake2b) fn count_range_lookups<const N: usize>(
    side_note: &mut SideNote,
    ptr: u32,
    uses: usize,
) {
    let (limbs0, _, _) = limbs::<N>(ptr);
    for _ in 0..uses {
        for &limb in limbs0.iter().chain(&increment(ptr)) {
            side_note.add_range256(limb);
        }
    }
}
