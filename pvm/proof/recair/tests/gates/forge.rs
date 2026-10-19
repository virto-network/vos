//! The malicious prover the gates share.
//!
//! It proves any main trace over any wiring: it skips the wiring's static
//! check (`Circuit::check_wiring`), which `prove` runs first, and Stwo's
//! closing check that the trace meets the constraints (`prove_ex`'s
//! comparison of the composition with the trace at the OODS point), and it
//! states whatever outputs and claimed sums it likes. So every refusal a gate
//! asserts is the verifier's, named by its message:
//! - [`LOGUP`]: the components' claimed sums and the outputs' public terms do
//!   not add to zero, a `Gate` relation that does not balance;
//! - [`DEEP_ALI`]: Stwo's OODS comparison, a trace that breaks a constraint;
//! - [`ANOTHER_CIRCUIT`]: the proof's preprocessed tree is not the pinned
//!   circuit's.

use std::collections::{HashMap, HashSet};

use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::proof_of_work::GrindOps;
use stwo::core::verifier::PREPROCESSED_TRACE_IDX;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, ComponentProver, ComponentProvers};
use vos_pvm_poseidon2::{Digest, M31, N_STATE, apply_external_round_matrix};
use vos_pvm_proof::poseidon2::{P2MerkleChannel, P2MerkleHasher};
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair::circuit::{Circuit, Entry};
use vos_pvm_recair::prove::FORMAT;
use vos_pvm_recair::trace::{self, MainTrace};
use vos_pvm_recair::{Finalized, RecairProof, circuit_commitment, circuit_hash_of, verify};
use vos_pvm_recair_air::gate::GateRelation;
use vos_pvm_recair_air::{Components, LOG_CONSTRAINT_EXPANSION, h8, p2};

/// The refusal of a `Gate` relation that does not balance.
pub const LOGUP: &str = "the claimed sums and the public terms do not add to zero";
/// The refusal of a trace that breaks a constraint: Stwo's OODS comparison.
pub const DEEP_ALI: &str = "DEEP-ALI failure";
/// The refusal of a proof of another circuit than the pinned one.
pub const ANOTHER_CIRCUIT: &str = "the proof is of another circuit";

/// What a forger proves: a wiring, a main trace over it and the outputs it
/// states.
pub struct Forgery {
    pub circuit: Circuit,
    pub trace: MainTrace,
    pub outputs: Vec<SecureField>,
}

/// A value's four limbs.
fn limbs(value: SecureField) -> [BaseField; 4] {
    value.to_m31_array()
}

fn qm31_of(limbs: [BaseField; 4]) -> SecureField {
    SecureField::from_m31_array(limbs)
}

fn word(value: BaseField) -> M31 {
    M31::new(value.0)
}

fn base(word: M31) -> BaseField {
    BaseField::from(word.value())
}

/// Where an `h8` row's inputs (`acc`, `σ`, `μ`, the two sample wires) and
/// its output start in its main columns.
const H8_STARTS: [usize; 6] = [
    h8::main::ACC,
    h8::main::STEP,
    h8::main::MU,
    h8::main::V,
    h8::main::V + 4,
    h8::main::OUT,
];

/// Where an entry's value sits in the main trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    /// A `p2` row's message wire `w`.
    P2Message { row: usize, w: usize },
    /// A `p2` row's output wire `w`: computed by the permutation.
    P2Output { row: usize, w: usize },
    /// A node row's bit, a wire of one limb.
    P2Bit { row: usize },
    /// A `qm31` row's operand `i`: `a`, `b`, `c`, `out`.
    Qm31 { row: usize, i: usize },
    /// An `h8` row's input `i`, or its output (`i == 5`).
    H8 { row: usize, i: usize },
}

impl Forgery {
    /// The honest prover's trace and outputs of `finalized`.
    pub fn honest(finalized: &Finalized<SecureField>) -> Self {
        Self {
            circuit: finalized.circuit.clone(),
            trace: trace::main_trace(&finalized.circuit, &finalized.witness),
            outputs: finalized.witness.outputs.clone(),
        }
    }

    /// Every entry of the relation with its slot in the trace, the public
    /// terms aside.
    fn slots(&self) -> Vec<(Entry, Slot)> {
        let mut slots = Vec::new();
        for (row, wiring) in self.circuit.p2.iter().enumerate() {
            for w in 0..2 {
                slots.push((wiring.m[w], Slot::P2Message { row, w }));
                slots.push((
                    Entry {
                        address: wiring.out_address + w as u32,
                        multiplicity: wiring.out_multiplicity[w],
                    },
                    Slot::P2Output { row, w },
                ));
            }
            if wiring.mode == Some(vos_pvm_recair::P2Mode::Node) {
                slots.push((
                    Entry {
                        address: wiring.bit_address,
                        multiplicity: 1,
                    },
                    Slot::P2Bit { row },
                ));
            }
        }
        for (row, wiring) in self.circuit.qm31.iter().enumerate() {
            for (i, &entry) in wiring.operands.iter().enumerate() {
                slots.push((entry, Slot::Qm31 { row, i }));
            }
        }
        for (row, wiring) in self.circuit.h8.iter().enumerate() {
            for (i, &address) in wiring.inputs.iter().enumerate() {
                let entry = Entry {
                    address,
                    multiplicity: 1,
                };
                slots.push((entry, Slot::H8 { row, i }));
            }
            slots.push((wiring.out, Slot::H8 { row, i: 5 }));
        }
        slots.retain(|(entry, _)| entry.multiplicity != 0);
        slots
    }

    /// The value the trace holds at `slot`.
    fn get(&self, slot: Slot) -> SecureField {
        let [p2_columns, qm31_columns, h8_columns] = &self.trace.columns;
        let at = |columns: &Vec<Vec<BaseField>>, start: usize, row: usize| {
            qm31_of(core::array::from_fn(|j| columns[start + j][row]))
        };
        match slot {
            Slot::P2Message { row, w } => at(p2_columns, p2::main::M + 4 * w, row),
            Slot::P2Output { row, w } => {
                let output = self.p2_output(row);
                qm31_of(core::array::from_fn(|j| base(output[4 * w + j])))
            }
            Slot::P2Bit { row } => SecureField::from(p2_columns[p2::main::B][row]),
            Slot::Qm31 { row, i } => at(qm31_columns, 4 * i, row),
            Slot::H8 { row, i } => at(h8_columns, H8_STARTS[i], row),
        }
    }

    /// Writes `value` at `slot`; a `p2` output is the permutation's and is
    /// not written.
    fn set(&mut self, slot: Slot, value: SecureField) {
        let [p2_columns, qm31_columns, h8_columns] = &mut self.trace.columns;
        let put = |columns: &mut Vec<Vec<BaseField>>, start: usize, row: usize| {
            for (j, limb) in limbs(value).into_iter().enumerate() {
                columns[start + j][row] = limb;
            }
        };
        match slot {
            Slot::P2Message { row, w } => put(p2_columns, p2::main::M + 4 * w, row),
            Slot::P2Output { .. } => {}
            Slot::P2Bit { row } => p2_columns[p2::main::B][row] = limbs(value)[0],
            Slot::Qm31 { row, i } => put(qm31_columns, 4 * i, row),
            Slot::H8 { row, i } => put(h8_columns, H8_STARTS[i], row),
        }
    }

    /// The entries whose value differs from their address's yield's, and
    /// the outputs stated otherwise: where the relation does not balance.
    pub fn unbalanced(&self) -> Vec<String> {
        let yields = self.yields();
        let mut unbalanced: Vec<String> = self
            .slots()
            .into_iter()
            .filter(|(entry, slot)| {
                entry.multiplicity > 0
                    && yields
                        .get(&entry.address)
                        .is_some_and(|&value| value != self.get(*slot))
            })
            .map(|(entry, slot)| format!("{slot:?} at {}", entry.address))
            .collect();
        let layout = self.circuit.layout;
        for (i, &output) in self.outputs.iter().enumerate() {
            let address = layout.output(i as u32);
            if yields.get(&address).is_some_and(|&value| value != output) {
                unbalanced.push(format!("output {i}"));
            }
        }
        unbalanced
    }

    /// `qm31` row `row`'s operand `i` (`a`, `b`, `c`, `out`).
    pub fn qm31(&self, row: usize, i: usize) -> SecureField {
        self.get(Slot::Qm31 { row, i })
    }

    /// Sets `qm31` row `row`'s operand `i` to `value`.
    pub fn set_qm31(&mut self, row: usize, i: usize, value: SecureField) {
        self.set(Slot::Qm31 { row, i }, value);
    }

    /// Sets lane `lane` (0–7) of `p2` row `row`'s message to `value`.
    pub fn set_message_lane(&mut self, row: usize, lane: usize, value: BaseField) {
        self.trace.columns[0][p2::main::M + lane][row] = value;
    }

    /// Each yielded address's value, as the trace holds it at its yield.
    pub fn yields(&self) -> HashMap<u32, SecureField> {
        self.slots()
            .into_iter()
            .filter(|(entry, _)| entry.multiplicity < 0)
            .map(|(entry, slot)| (entry.address, self.get(slot)))
            .collect()
    }

    /// The forger's balancing, so the `Gate` relation balances: a wire that
    /// a `p2` row's output must equal (a Merkle root, say) takes the first
    /// such output's value at its yield, unless a `p2` row's output yields
    /// it, and every other such row is made to state the wire's value
    /// ([`Forgery::force_output`]); then every use the trace can carry, and
    /// every output stated, takes its yield's value. The gates whose
    /// operands moved, and the forced rows' last rounds, no longer hold.
    pub fn balance(&mut self) {
        self.balance_except(&[]);
    }

    fn balance_except(&mut self, forged: &[(usize, usize)]) {
        let slots = self.slots();
        let yield_slots: HashMap<u32, Slot> = slots
            .iter()
            .filter(|(entry, _)| entry.multiplicity < 0)
            .map(|&(entry, slot)| (entry.address, slot))
            .collect();
        let mut taken: HashSet<u32> = HashSet::new();
        for &(entry, slot) in &slots {
            let Slot::P2Output { row, w } = slot else {
                continue;
            };
            if entry.multiplicity <= 0 {
                continue;
            }
            let Some(&at) = yield_slots.get(&entry.address) else {
                continue;
            };
            let value = self.get(slot);
            if !matches!(at, Slot::P2Output { .. }) && taken.insert(entry.address) {
                self.set(at, value);
            } else if self.get(at) != value {
                let wanted = self.get(at);
                self.force_output(row, w, wanted);
            }
        }
        let yields = self.yields();
        for (entry, slot) in slots {
            if let Slot::Qm31 { row, i } = slot
                && forged.contains(&(row, i))
            {
                continue;
            }
            if entry.multiplicity > 0
                && let Some(&value) = yields.get(&entry.address)
            {
                self.set(slot, value);
            }
        }
        let layout = self.circuit.layout;
        for (i, output) in self.outputs.iter_mut().enumerate() {
            if let Some(&value) = yields.get(&layout.output(i as u32)) {
                *output = value;
            }
        }
    }

    /// [`Forgery::balance`], then every `qm31` row whose output it yields
    /// recomputed from its operands, until nothing moves: a forged value
    /// carried through the gates below it to the outputs, every gate there
    /// holding. `h8` rows are not recomputed: a forgery carried through one
    /// would leave it stale, and its refusal would be that row's.
    pub fn settle(&mut self) {
        self.settle_except(&[]);
    }

    /// [`Forgery::settle`], the `qm31` operands `forged` (row, operand)
    /// left as the forger set them.
    pub fn settle_except(&mut self, forged: &[(usize, usize)]) {
        loop {
            self.balance_except(forged);
            let mut moved = false;
            for row in 0..self.circuit.qm31.len() {
                let wiring = self.circuit.qm31[row];
                if wiring.operands[3].multiplicity >= 0 {
                    continue;
                }
                let [a, b, c, out] = core::array::from_fn(|i| self.qm31(row, i));
                let computed = wiring.op.apply(a, b, c);
                if computed != out {
                    self.set(Slot::Qm31 { row, i: 3 }, computed);
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        }
    }

    /// Row `row`'s output wire `w` made `value`, its other words kept: the
    /// last round's S-box outputs rewritten through the external matrix's
    /// inverse, so those S-boxes no longer hold.
    pub fn force_output(&mut self, row: usize, w: usize, value: SecureField) {
        let mut output = self.p2_output(row).map(base);
        for (j, limb) in limbs(value).into_iter().enumerate() {
            output[4 * w + j] = limb;
        }
        let sboxes = external_matrix_inverse().map(|line| {
            line.iter()
                .zip(&output)
                .map(|(&a, &b)| a * b)
                .sum::<BaseField>()
        });
        let last_round = p2::N_SBOXES - N_STATE;
        for (j, value) in sboxes.into_iter().enumerate() {
            self.trace.columns[0][p2::main::SBOXES + 2 * (last_round + j) + 1][row] = value;
        }
        debug_assert_eq!(self.p2_output(row).map(base), output);
    }

    /// Row `row`'s permutation input, read from its columns.
    pub fn p2_input(&self, row: usize) -> [M31; N_STATE] {
        core::array::from_fn(|j| word(self.trace.columns[0][p2::main::INPUT + j][row]))
    }

    /// Row `row`'s permutation output, from its last round's columns.
    pub fn p2_output(&self, row: usize) -> [M31; N_STATE] {
        let columns: Vec<M31> = (0..p2::main::M)
            .map(|column| word(self.trace.columns[0][column][row]))
            .collect();
        p2::output_of_columns(&columns)
    }

    /// Row `row`'s message limbs and bit.
    pub fn p2_message(&self, row: usize) -> ([BaseField; 8], BaseField) {
        let columns = &self.trace.columns[0];
        (
            core::array::from_fn(|j| columns[p2::main::M + j][row]),
            columns[p2::main::B][row],
        )
    }

    /// Row `row`'s permutation over `input`: its columns recomputed.
    pub fn rewrite_input(&mut self, row: usize, input: [M31; N_STATE]) {
        let mut permutation = vec![M31::ZERO; p2::main::M];
        p2::permutation_columns(input, &mut permutation);
        for (column, word) in permutation.into_iter().enumerate() {
            self.trace.columns[0][column][row] = base(word);
        }
    }

    /// The forgery proved, its claimed sums the trace's.
    pub fn prove(&self) -> RecairProof {
        self.prove_with_sums(|_, _, _| {})
    }

    /// The forgery proved, its claimed sums the trace's passed through
    /// `forge_sums` with the drawn relation and the outputs.
    pub fn prove_with_sums(
        &self,
        forge_sums: impl FnOnce(&GateRelation, &[SecureField], &mut [SecureField; 3]),
    ) -> RecairProof {
        let circuit = &self.circuit;
        let log_sizes = circuit.log_sizes();
        let config = FORMAT.pcs_config();
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(
                log_sizes.iter().max().copied().unwrap_or(0)
                    + LOG_CONSTRAINT_EXPANSION
                    + config.fri_config.log_blowup_factor,
            )
            .circle_domain()
            .half_coset,
        );
        let channel = &mut <P2MerkleChannel as MerkleChannel>::C::default();
        mix_statement_header(channel, FORMAT.number, &config, &log_sizes);
        let mut scheme =
            CommitmentSchemeProver::<SimdBackend, P2MerkleChannel>::new(config, &twiddles);
        scheme.set_store_polynomials_coefficients();

        let mut builder = scheme.tree_builder();
        for (columns, &log_size) in trace::preprocessed_columns(circuit).iter().zip(&log_sizes) {
            builder.extend_evals(trace::evaluations(columns, log_size));
        }
        builder.commit(channel);
        let mut builder = scheme.tree_builder();
        for (columns, &log_size) in self.trace.columns.iter().zip(&log_sizes) {
            builder.extend_evals(trace::evaluations(columns, log_size));
        }
        builder.commit(channel);

        channel.mix_felts(&self.outputs);
        let interaction_pow =
            <SimdBackend as GrindOps<_>>::grind(channel, FORMAT.interaction_pow_bits());
        channel.mix_u64(interaction_pow);
        let relation = GateRelation::draw(channel);
        let interaction = self.trace.interaction(circuit, &relation);
        let mut claimed_sums = [0, 1, 2].map(|i| interaction[i].1);
        forge_sums(&relation, &self.outputs, &mut claimed_sums);
        let mut builder = scheme.tree_builder();
        for (evaluations, _) in interaction {
            builder.extend_evals(evaluations);
        }
        channel.mix_felts(&claimed_sums);
        builder.commit(channel);

        let components = Components::new(&relation, &log_sizes, &claimed_sums);
        let provers: [&dyn ComponentProver<SimdBackend>; 3] =
            [&components.p2, &components.qm31, &components.h8];
        let stark_proof = prove_unchecked(&provers, channel, scheme);
        RecairProof {
            format_version: FORMAT.number,
            log_sizes,
            outputs: self.outputs.clone(),
            interaction_pow,
            claimed_sums,
            stark_proof,
        }
    }
}

/// The inverse of the permutation's external matrix, by Gauss–Jordan over
/// its columns.
fn external_matrix_inverse() -> [[BaseField; N_STATE]; N_STATE] {
    let mut matrix = [[BaseField::from(0); N_STATE]; N_STATE];
    for column in 0..N_STATE {
        let mut unit = [BaseField::from(0); N_STATE];
        unit[column] = BaseField::from(1);
        apply_external_round_matrix(&mut unit);
        for (line, value) in matrix.iter_mut().zip(unit) {
            line[column] = value;
        }
    }
    let mut inverse = [[BaseField::from(0); N_STATE]; N_STATE];
    for (i, line) in inverse.iter_mut().enumerate() {
        line[i] = BaseField::from(1);
    }
    for column in 0..N_STATE {
        let pivot = (column..N_STATE)
            .find(|&line| matrix[line][column] != BaseField::from(0))
            .expect("the external matrix is invertible");
        matrix.swap(column, pivot);
        inverse.swap(column, pivot);
        let scale = matrix[column][column].inverse();
        for j in 0..N_STATE {
            matrix[column][j] *= scale;
            inverse[column][j] *= scale;
        }
        for line in 0..N_STATE {
            let factor = matrix[line][column];
            if line == column || factor == BaseField::from(0) {
                continue;
            }
            for j in 0..N_STATE {
                let (a, b) = (matrix[column][j], inverse[column][j]);
                matrix[line][j] -= factor * a;
                inverse[line][j] -= factor * b;
            }
        }
    }
    inverse
}

/// Stwo's `prove_ex` at the pin without its closing check that the trace
/// meets the constraints: the composition committed and the values opened
/// whatever the trace. It mirrors the pinned fork's `prove_ex` line for line
/// and is to be compared with it again whenever the pin moves.
fn prove_unchecked(
    components: &[&dyn ComponentProver<SimdBackend>],
    channel: &mut <P2MerkleChannel as MerkleChannel>::C,
    mut scheme: CommitmentSchemeProver<'_, SimdBackend, P2MerkleChannel>,
) -> StarkProof<P2MerkleHasher> {
    let provers = ComponentProvers {
        components: components.to_vec(),
        n_preprocessed_columns: scheme.trees[PREPROCESSED_TRACE_IDX].polynomials.len(),
    };
    let trace = scheme.trace();
    let random_coeff = channel.draw_secure_felt();
    let composition = provers.compute_composition_polynomial(
        random_coeff,
        &trace,
        scheme.twiddles,
        scheme.config.fri_config.log_blowup_factor,
    );
    let mut builder = scheme.tree_builder();
    let (left, right) = composition.split_at_mid();
    builder.extend_polys(left.into_coordinate_polys());
    builder.extend_polys(right.into_coordinate_polys());
    builder.commit(channel);

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let split_log_size = scheme
        .trees
        .last()
        .expect("the composition tree")
        .commitment
        .layers
        .len() as u32
        - 1;
    let lifting_log_size =
        try_get_lifting_log_size(&scheme.config, split_log_size).expect("a lifting log size");
    let max_log_degree_bound = lifting_log_size - scheme.config.fri_config.log_blowup_factor;
    let mut points = provers
        .components()
        .mask_points(oods_point, max_log_degree_bound, false);
    points.push(vec![vec![oods_point]; 2 * SECURE_EXTENSION_DEGREE]);
    StarkProof(scheme.prove_values(points, channel).proof)
}

/// The pinned hash of `circuit`, whose wiring checks.
pub fn hash_of(circuit: &Circuit) -> Digest {
    circuit_commitment(circuit).expect("the wiring checks").1
}

/// The hash a proof's own preprocessed tree states, checked or not.
pub fn own_hash(proof: &RecairProof) -> Digest {
    circuit_hash_of(&proof.log_sizes, &proof.stark_proof.commitments[0])
}

/// Asserts that `proof` is refused against `hash` with `reason`.
#[track_caller]
pub fn assert_refused(proof: RecairProof, hash: &Digest, reason: &str, forgery: &str) {
    match verify(proof, hash) {
        Ok(()) => panic!("SOUNDNESS GAP: the forgery {forgery} was accepted"),
        Err(error) => assert!(
            error.0.contains(reason),
            "{forgery}: refused for another reason than {reason:?}: {error}"
        ),
    }
}

/// Asserts that `proof` verifies against `hash`.
#[track_caller]
pub fn assert_accepted(proof: RecairProof, hash: &Digest, what: &str) {
    if let Err(error) = verify(proof, hash) {
        panic!("{what}: refused: {error}");
    }
}
