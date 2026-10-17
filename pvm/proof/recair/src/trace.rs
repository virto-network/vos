//! The components' traces from a circuit and its witness: the preprocessed
//! columns from the wiring alone, the main columns from the witness, and the
//! interaction columns, each component's fractions in pairs.
//!
//! Columns are built row by row in the coset's order, where a row's
//! predecessor is the row before it, and stored in Stwo's bit-reversed
//! circle-domain order.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_constraint_framework::LogupTraceGenerator;
use vos_recair_air::gate::GateRelation;
use vos_recair_air::p2::{self, P2Mode};
use vos_recair_air::{h8, qm31};

use crate::circuit::{Circuit, Entry, signed};
use crate::context::Witness;
use crate::value::words_of;

/// A component's columns, as Stwo commits them.
pub type Evaluations = Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

/// Columns in the coset's order, `columns[c][row]`.
pub type CosetColumns = Vec<Vec<BaseField>>;

/// The storage position of each coset row.
fn storage_positions(log_size: u32) -> Vec<usize> {
    (0..1usize << log_size)
        .map(|row| bit_reverse_index(coset_index_to_circle_domain_index(row, log_size), log_size))
        .collect()
}

/// Columns in the coset's order as Stwo's evaluations.
pub fn evaluations(columns: &CosetColumns, log_size: u32) -> Evaluations {
    let positions = storage_positions(log_size);
    let domain = CanonicCoset::new(log_size).circle_domain();
    columns
        .iter()
        .map(|column| {
            let mut stored = vec![BaseField::zero(); column.len()];
            for (row, &value) in column.iter().enumerate() {
                stored[positions[row]] = value;
            }
            CircleEvaluation::new(domain, BaseColumn::from_iter(stored))
        })
        .collect()
}

fn columns(n_columns: usize, n_rows: usize) -> CosetColumns {
    vec![vec![BaseField::zero(); n_rows]; n_columns]
}

fn limbs(value: SecureField) -> [BaseField; 4] {
    value.to_m31_array()
}

/// The preprocessed columns of each component, in the coset's order.
pub fn preprocessed_columns(circuit: &Circuit) -> [CosetColumns; 3] {
    let mut p2_columns = columns(p2::PREPROCESSED.len(), circuit.p2.len());
    for (row, wiring) in circuit.p2.iter().enumerate() {
        let mut set = |column: usize, value: BaseField| p2_columns[column][row] = value;
        if let Some(mode) = wiring.mode {
            set(p2::pre::SELECTORS + mode as usize, BaseField::one());
        }
        for w in 0..2 {
            set(p2::pre::ADDR_M[w], BaseField::from(wiring.m[w].address));
            set(p2::pre::MULT_M[w], signed(wiring.m[w].multiplicity));
            set(p2::pre::MULT_OUT[w], signed(wiring.out_multiplicity[w]));
        }
        set(p2::pre::ADDR_OUT, BaseField::from(wiring.out_address));
        set(p2::pre::ADDR_BIT, BaseField::from(wiring.bit_address));
        for j in 0..8 {
            set(p2::pre::ACT + j, wiring.act[j]);
        }
        for j in 0..10 {
            set(p2::pre::C + j, wiring.c[j]);
        }
    }

    let mut qm31_columns = columns(qm31::PREPROCESSED.len(), circuit.qm31.len());
    for (row, wiring) in circuit.qm31.iter().enumerate() {
        let mut set = |column: usize, value: BaseField| qm31_columns[column][row] = value;
        let op = wiring.op;
        set(qm31::pre::K_M, op.k_m);
        set(qm31::pre::K_P, op.k_p);
        set(qm31::pre::K_A, op.k_a);
        set(qm31::pre::K_B, op.k_b);
        set(qm31::pre::K_C, op.k_c);
        for j in 0..4 {
            set(qm31::pre::LANES + j, op.lanes[j]);
        }
        for (i, operand) in wiring.operands.iter().enumerate() {
            set(qm31::pre::ADDR + i, BaseField::from(operand.address));
            set(qm31::pre::MULT + i, signed(operand.multiplicity));
        }
    }

    let mut h8_columns = columns(h8::PREPROCESSED.len(), circuit.h8.len());
    for (row, wiring) in circuit.h8.iter().enumerate() {
        let addresses = [
            h8::pre::ADDR_ACC,
            h8::pre::ADDR_STEP,
            h8::pre::ADDR_MU,
            h8::pre::ADDR_V[0],
            h8::pre::ADDR_V[1],
        ];
        for (column, address) in addresses.into_iter().zip(wiring.inputs) {
            h8_columns[column][row] = BaseField::from(address);
        }
        h8_columns[h8::pre::ADDR_OUT][row] = BaseField::from(wiring.out.address);
        h8_columns[h8::pre::MULT_OUT][row] = signed(wiring.out.multiplicity);
    }
    [p2_columns, qm31_columns, h8_columns]
}

/// One fraction of the `Gate` relation: its multiplicity and its tuple.
#[derive(Clone, Copy)]
struct Fraction {
    multiplicity: BaseField,
    address: BaseField,
    limbs: [BaseField; 4],
}

fn fraction(entry: Entry, limbs: [BaseField; 4]) -> Fraction {
    Fraction {
        multiplicity: signed(entry.multiplicity),
        address: BaseField::from(entry.address),
        limbs,
    }
}

/// The main columns of each component, in the coset's order.
pub struct MainTrace {
    pub columns: [CosetColumns; 3],
}

fn words(value: [vos_pvm_poseidon2::M31; 16]) -> [BaseField; 16] {
    value.map(|word| BaseField::from_u32_unchecked(word.value()))
}

fn limbs_at(columns: &CosetColumns, at: usize, row: usize) -> [BaseField; 4] {
    core::array::from_fn(|j| columns[at + j][row])
}

/// The main trace of `witness` over `circuit`.
pub fn main_trace(circuit: &Circuit, witness: &Witness<SecureField>) -> MainTrace {
    let mut p2_columns = columns(p2::N_MAIN, circuit.p2.len());
    let mut permutation = vec![vos_pvm_poseidon2::M31::ZERO; p2::main::M];
    for (row, values) in witness.p2.iter().enumerate() {
        p2::permutation_columns(words_of(values.input), &mut permutation);
        for (column, word) in permutation.iter().enumerate() {
            p2_columns[column][row] = BaseField::from_u32_unchecked(word.value());
        }
        for j in 0..8 {
            p2_columns[p2::main::M + j][row] = limbs(values.m[j / 4])[j % 4];
        }
        p2_columns[p2::main::B][row] = limbs(values.b)[0];
    }

    let mut qm31_columns = columns(qm31::N_MAIN, circuit.qm31.len());
    for (row, values) in witness.qm31.iter().enumerate() {
        for (i, &value) in values.iter().enumerate() {
            for (j, limb) in limbs(value).into_iter().enumerate() {
                qm31_columns[4 * i + j][row] = limb;
            }
        }
    }

    let mut h8_columns = columns(h8::N_MAIN, circuit.h8.len());
    for (row, values) in witness.h8.iter().enumerate() {
        let samples: [BaseField; 8] = core::array::from_fn(|j| limbs(values.v[j / 4])[j % 4]);
        let step = values.step;
        let horner = |h: SecureField, x: BaseField, y: BaseField| {
            (h * step + SecureField::from(x)) * step + SecureField::from(y)
        };
        let q0 = horner(SecureField::from(samples[7]), samples[6], samples[5]);
        let q1 = horner(q0, samples[4], samples[3]);
        let q2 = horner(q1, samples[2], samples[1]);
        let mut put = |at: usize, value: SecureField| {
            for (j, limb) in limbs(value).into_iter().enumerate() {
                h8_columns[at + j][row] = limb;
            }
        };
        put(h8::main::ACC, values.acc);
        put(h8::main::STEP, values.step);
        put(h8::main::MU, values.mu);
        for (w, wire) in values.v.into_iter().enumerate() {
            put(h8::main::V + 4 * w, wire);
        }
        for (i, q) in [q0, q1, q2].into_iter().enumerate() {
            put(h8::main::Q + 4 * i, q);
        }
        put(h8::main::OUT, values.out);
    }

    MainTrace {
        columns: [p2_columns, qm31_columns, h8_columns],
    }
}

impl MainTrace {
    /// Each row's fractions, read from the main columns and the wiring, in
    /// the order the components' bodies add them.
    fn fractions(&self, circuit: &Circuit) -> [Vec<Vec<Fraction>>; 3] {
        let [p2_columns, qm31_columns, h8_columns] = &self.columns;
        let mut permutation = vec![vos_pvm_poseidon2::M31::ZERO; p2::main::M];
        let p2_fractions = circuit
            .p2
            .iter()
            .enumerate()
            .map(|(row, wiring)| {
                for (column, word) in permutation.iter_mut().enumerate() {
                    *word = vos_pvm_poseidon2::M31::new(p2_columns[column][row].0);
                }
                let output = words(p2::output_of_columns(&permutation));
                let b = p2_columns[p2::main::B][row];
                let out = |w: usize| core::array::from_fn(|i| output[4 * w + i]);
                vec![
                    fraction(wiring.m[0], limbs_at(p2_columns, p2::main::M, row)),
                    fraction(wiring.m[1], limbs_at(p2_columns, p2::main::M + 4, row)),
                    fraction(
                        Entry {
                            address: wiring.out_address,
                            multiplicity: wiring.out_multiplicity[0],
                        },
                        out(0),
                    ),
                    fraction(
                        Entry {
                            address: wiring.out_address + 1,
                            multiplicity: wiring.out_multiplicity[1],
                        },
                        out(1),
                    ),
                    fraction(
                        Entry {
                            address: wiring.bit_address,
                            multiplicity: i64::from(wiring.mode == Some(P2Mode::Node)),
                        },
                        [b, BaseField::zero(), BaseField::zero(), BaseField::zero()],
                    ),
                ]
            })
            .collect();
        let qm31_fractions = circuit
            .qm31
            .iter()
            .enumerate()
            .map(|(row, wiring)| {
                (0..4)
                    .map(|i| fraction(wiring.operands[i], limbs_at(qm31_columns, 4 * i, row)))
                    .collect()
            })
            .collect();
        let h8_fractions = circuit
            .h8
            .iter()
            .enumerate()
            .map(|(row, wiring)| {
                let use_ = |address: u32| Entry {
                    address,
                    multiplicity: 1,
                };
                let at = [
                    h8::main::ACC,
                    h8::main::STEP,
                    h8::main::MU,
                    h8::main::V,
                    h8::main::V + 4,
                ];
                let mut row_fractions: Vec<Fraction> = wiring
                    .inputs
                    .iter()
                    .zip(at)
                    .map(|(&address, at)| fraction(use_(address), limbs_at(h8_columns, at, row)))
                    .collect();
                row_fractions.push(fraction(
                    wiring.out,
                    limbs_at(h8_columns, h8::main::OUT, row),
                ));
                row_fractions
            })
            .collect();
        [p2_fractions, qm31_fractions, h8_fractions]
    }

    /// Each component's interaction columns and claimed sum: its fractions
    /// in pairs, as `finalize_logup_in_pairs` batches them.
    pub fn interaction(
        &self,
        circuit: &Circuit,
        relation: &GateRelation,
    ) -> [(Evaluations, SecureField); 3] {
        let log_sizes = circuit.log_sizes();
        let fractions = self.fractions(circuit);
        core::array::from_fn(|component| {
            let log_size = log_sizes[component];
            let rows = &fractions[component];
            let positions = storage_positions(log_size);
            let n_fractions = rows[0].len();
            let term = |f: &Fraction| {
                let [l0, l1, l2, l3] = f.limbs;
                let denominator: SecureField = relation.0.combine(&[f.address, l0, l1, l2, l3]);
                (SecureField::from(f.multiplicity), denominator)
            };
            let mut generator = LogupTraceGenerator::new(log_size);
            for pair in (0..n_fractions).step_by(2) {
                let mut stored = vec![(SecureField::zero(), SecureField::one()); rows.len()];
                for (row, fractions) in rows.iter().enumerate() {
                    let (n0, d0) = term(&fractions[pair]);
                    stored[positions[row]] = match fractions.get(pair + 1) {
                        Some(second) => {
                            let (n1, d1) = term(second);
                            (n0 * d1 + n1 * d0, d0 * d1)
                        }
                        None => (n0, d0),
                    };
                }
                let mut column = generator.new_col();
                for (vec_row, chunk) in stored.chunks(N_LANES).enumerate() {
                    column.write_frac(
                        vec_row,
                        PackedSecureField::from_array(core::array::from_fn(|i| chunk[i].0)),
                        PackedSecureField::from_array(core::array::from_fn(|i| chunk[i].1)),
                    );
                }
                column.finalize_col();
            }
            generator.finalize_last()
        })
    }
}
