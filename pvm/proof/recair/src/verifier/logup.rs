//! The logup sums (`recursion-air.md` §4.5), as the segment verifier
//! checks them: the components' claimed sums add to zero, and each
//! boundary chip's is the public term recomputed from the boundary states
//! (`vos_pvm_proof::boundary_binding`), so the other chips' sums and the
//! public terms add to zero.
//!
//! The boundary states are the 296 bytes the channel absorbed, one M31 a
//! byte, packed four a wire: a tuple's limb is a lane of its wire. A tuple
//! combines as `Σ α^i·t_i − z`, Horner from its last limb, one row a limb.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use vos_pvm_proof::boundary_binding::BoundaryChipPositions;

use crate::circuit::Qm31Op;
use crate::context::{Context, Var};
use crate::value::Value;

/// A relation's drawn challenges: `z` and `α`.
#[derive(Clone, Copy, Debug)]
pub struct Challenges {
    pub z: Var,
    pub alpha: Var,
}

/// The three relations the boundary chips emit into.
#[derive(Clone, Copy, Debug)]
pub struct BoundaryRelations {
    pub register_memory: Challenges,
    pub program_execution: Challenges,
    pub merkle_node: Challenges,
}

/// A tuple's limb: a constant, or byte `index` of the boundary states.
#[derive(Clone, Copy, Debug)]
enum Limb {
    Constant(u32),
    Byte(usize),
}

/// The boundary states' byte offsets (`boundary_state_bytes`' order).
const REGISTERS_IN: usize = 0;
const REGISTERS_OUT: usize = 13 * 8;
const PC_IN: usize = 2 * 13 * 8;
const TS_IN: usize = PC_IN + 4;
const PC_OUT: usize = TS_IN + 8;
const TS_OUT: usize = PC_OUT + 4;
const ROOT_IN: usize = TS_OUT + 8;
const ROOT_OUT: usize = ROOT_IN + 32;

fn bytes(start: usize, n: usize) -> impl Iterator<Item = Limb> {
    (start..start + n).map(Limb::Byte)
}

/// `1 / (Σ α^i·t_i − z)` over `tuple`.
fn inverse_combined<V: Value>(
    context: &mut Context<V>,
    challenges: Challenges,
    boundary: &[Var],
    tuple: &[Limb],
) -> Var {
    let one = context.one();
    let mut acc: Option<Var> = None;
    for &limb in tuple.iter().rev() {
        let (lanes, k_c, c) = match limb {
            Limb::Constant(value) => ([BaseField::zero(); 4], BaseField::from(value), one),
            Limb::Byte(index) => {
                let mut lanes = [BaseField::zero(); 4];
                lanes[index % 4] = BaseField::one();
                (lanes, BaseField::zero(), boundary[index / 4])
            }
        };
        acc = Some(match acc {
            None => context.qm31(
                Qm31Op {
                    k_c,
                    lanes,
                    ..Default::default()
                },
                None,
                None,
                Some(c),
            ),
            Some(acc) => context.qm31(
                Qm31Op {
                    k_m: BaseField::one(),
                    k_c,
                    lanes,
                    ..Default::default()
                },
                Some(acc),
                Some(challenges.alpha),
                Some(c),
            ),
        });
    }
    let combined = context.sub(acc.expect("a limb"), challenges.z);
    context.inverse(combined)
}

/// The thirteen register tuples `(r, value, ts, is_write)`.
fn register_file<V: Value>(
    context: &mut Context<V>,
    challenges: Challenges,
    boundary: &[Var],
    registers: usize,
    ts: Option<usize>,
    is_write: u32,
) -> Var {
    let mut sum: Option<Var> = None;
    for r in 0..13 {
        let mut tuple = vec![Limb::Constant(r as u32)];
        tuple.extend(bytes(registers + 8 * r, 8));
        match ts {
            Some(ts) => tuple.extend(bytes(ts, 8)),
            None => tuple.extend([Limb::Constant(0); 8]),
        }
        tuple.push(Limb::Constant(is_write));
        let term = inverse_combined(context, challenges, boundary, &tuple);
        sum = Some(match sum {
            None => term,
            Some(sum) => context.add(sum, term),
        });
    }
    sum.expect("thirteen registers")
}

/// The components' `claimed_sums` add to zero.
pub fn check_total<V: Value>(context: &mut Context<V>, claimed_sums: &[Var]) {
    let zero = context.zero();
    let terms: Vec<(BaseField, Var)> = claimed_sums
        .iter()
        .map(|&sum| (BaseField::one(), sum))
        .collect();
    super::bits::linear(context, &terms, Some(zero));
}

/// The logup check over the components' `claimed_sums` (active order), and
/// the boundary chips' at `positions` against the public terms over the
/// boundary bytes' wires.
pub fn check<V: Value>(
    context: &mut Context<V>,
    claimed_sums: &[Var],
    positions: &BoundaryChipPositions,
    boundary: &[Var],
    relations: &BoundaryRelations,
) {
    check_total(context, claimed_sums);

    // Register file in: (r, value, 0, 1); out: (r, value, ts_out, 0).
    let expected = register_file(
        context,
        relations.register_memory,
        boundary,
        REGISTERS_IN,
        None,
        1,
    );
    context.assert_eq(expected, claimed_sums[positions.register_boundary]);
    let expected = register_file(
        context,
        relations.register_memory,
        boundary,
        REGISTERS_OUT,
        Some(TS_OUT),
        0,
    );
    context.assert_eq(expected, claimed_sums[positions.register_closing]);

    // Program boundary: (ts, pc) produced in, consumed out.
    let produced: Vec<Limb> = bytes(TS_IN, 8).chain(bytes(PC_IN, 4)).collect();
    let consumed: Vec<Limb> = bytes(TS_OUT, 8).chain(bytes(PC_OUT, 4)).collect();
    let produced = inverse_combined(context, relations.program_execution, boundary, &produced);
    let consumed = inverse_combined(context, relations.program_execution, boundary, &consumed);
    context.qm31_into(
        Qm31Op {
            k_a: BaseField::one(),
            k_b: -BaseField::one(),
            ..Default::default()
        },
        Some(produced),
        Some(consumed),
        None,
        claimed_sums[positions.program_boundary],
    );

    // Memory roots: (0, 0, root_in, root_out) consumed.
    let tuple: Vec<Limb> = [Limb::Constant(0), Limb::Constant(0)]
        .into_iter()
        .chain(bytes(ROOT_IN, 32))
        .chain(bytes(ROOT_OUT, 32))
        .collect();
    let consumed = inverse_combined(context, relations.merkle_node, boundary, &tuple);
    context.qm31_into(
        Qm31Op {
            k_a: -BaseField::one(),
            ..Default::default()
        },
        Some(consumed),
        None,
        None,
        claimed_sums[positions.memory_root_boundary],
    );
}
