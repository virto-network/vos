//! The gate compiler (`recursion-air.md` §3): a component's constraints,
//! as constraint-framework's recording evaluator states them, compiled to
//! rows of the recursion AIR's `qm31` gate that evaluate them at the OODS
//! point as the native verifier does (§4.5).
//!
//! 1. [`Recording`] drives a component's own `evaluate` through
//!    `ExprEvaluator` (its constraints) and `InfoEvaluator` (the columns and
//!    offsets it reads). For the segment AIR's chips it goes through
//!    `drive_chip_oods`.
//! 2. [`compile`] lowers every recording into one hash-consed DAG of QM31
//!    operations, resolving each name the recording uses: columns are the
//!    component's samples, preprocessed columns the shape's, relation
//!    challenges the shape's, intermediates the component's own.
//! 3. The DAG becomes rows ([`Row`]): one an operation, a single-use
//!    product, negation or M31 scaling taken in by the add or sub that
//!    consumes it. A relation's `α` powers are rows of their own, before the
//!    rest.
//!
//! What each recorded construct becomes:
//! - **a base or an extension expression**: the same rows, as every sample
//!   at the OODS point is a QM31; an interaction column (`SecureCol`) is
//!   `s0 + s1·i + s2·u + s3·iu`, three rows;
//! - **a next-row mask**: one input a sampled offset ([`Input::Sample`]);
//! - **a relation's challenges**: its `z` and `α` are inputs, `α^0 = 1`,
//!   and `α^i` for `i ≥ 2` rows from `α`;
//! - **logup, paired or not**: the recorded batch constraints themselves,
//!   with `column_size` the constant `2^log_size` and `claimed_sum` the
//!   component's input;
//! - **intermediates**: lowered once, shared through the DAG;
//! - **an inverse**: of a constant, folded; of anything else, one row;
//! - **preprocessed columns**: the shape's inputs, by id.
//!
//! The compiled circuit's output is each constraint's value. [`compose`]
//! folds them as the verifier's `PointEvaluationAccumulator` does, a
//! component's numerator, or the whole composition in the components'
//! order; the composition is that times the vanishing polynomial's inverse
//! at the OODS point. A component's logup contribution is its claimed sum.

mod dag;
mod program;
mod record;

use std::collections::{BTreeSet, HashMap};

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use vos_pvm_proof::framework_access::RelationChallenges;

pub use program::{Operand, Row};
pub use record::Recording;

use crate::context::{Context, Var};
use crate::value::Value;

/// A value the verifier holds at the OODS point, which the compiled circuit
/// reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Input {
    /// Component `chip`'s column `column` of `tree` (0, main; 1,
    /// interaction), sampled at `offset` rows from the OODS point.
    Sample {
        chip: usize,
        tree: usize,
        column: usize,
        offset: isize,
    },
    /// A preprocessed column's sample, by its index in
    /// [`Compiled::preprocessed`].
    Preprocessed(usize),
    /// Component `chip`'s claimed logup sum.
    ClaimedSum(usize),
    /// A relation's `z`, by its index in [`Compiled::relations`].
    Z(usize),
    /// A relation's `α`.
    Alpha(usize),
}

/// A component as compiled.
#[derive(Clone, Debug)]
pub struct Component {
    pub name: String,
    pub log_size: u32,
    /// Its main and interaction columns' mask offsets.
    pub offsets: [Vec<Vec<isize>>; 2],
    /// The preprocessed columns it reads, in its order, as indices into
    /// [`Compiled::preprocessed`].
    pub preprocessed: Vec<usize>,
    /// Each constraint's value, in the recorded order.
    pub constraints: Vec<Operand>,
}

/// A shape's constraints, compiled.
#[derive(Clone, Debug)]
pub struct Compiled {
    pub components: Vec<Component>,
    /// The relations, name and tuple size, in the order given.
    pub relations: Vec<(String, usize)>,
    /// The preprocessed columns the components read, each once.
    pub preprocessed: Vec<PreProcessedColumnId>,
    pub inputs: Vec<Input>,
    pub rows: Vec<Row>,
    /// The first rows, which compute the relations' `α` powers.
    pub power_rows: usize,
}

/// The values of [`Compiled::inputs`] the verifier holds.
pub struct OodsValues<'a> {
    /// Per component, its main and interaction samples,
    /// `[tree][column][k]` at its column's `k`-th offset.
    pub samples: Vec<[&'a [Vec<SecureField>]; 2]>,
    /// The preprocessed samples, by [`Compiled::preprocessed`].
    pub preprocessed: Vec<SecureField>,
    pub claimed_sums: Vec<SecureField>,
    /// Each relation's challenges, any order: they are matched by name.
    pub relations: &'a [RelationChallenges],
}

/// Compiles `recordings`, components of one shape over `relations` (name,
/// tuple size).
///
/// # Panics
/// When a recording reads a name it does not define, a column outside its
/// mask or a power of `α` past its relation's size, leaves an interaction
/// column unread, or inverts zero.
pub fn compile(recordings: &[Recording], relations: &[(String, usize)]) -> Compiled {
    let mut dag = dag::Dag::default();
    let mut preprocessed: Vec<PreProcessedColumnId> = Vec::new();
    let mut components = Vec::new();
    let mut roots = Vec::new();
    for (chip, recording) in recordings.iter().enumerate() {
        let indices: Vec<usize> = recording
            .preprocessed
            .iter()
            .map(
                |id| match preprocessed.iter().position(|known| known == id) {
                    Some(index) => index,
                    None => {
                        preprocessed.push(id.clone());
                        preprocessed.len() - 1
                    }
                },
            )
            .collect();
        let constraints = recording.lower(chip, relations, &indices, &mut dag);
        roots.push(constraints);
        components.push(Component {
            name: recording.name.clone(),
            log_size: recording.log_size,
            offsets: recording.offsets.clone(),
            preprocessed: indices,
            constraints: Vec::new(),
        });
    }

    // The inputs in a fixed order: by kind, then component, tree, column
    // and offset. A relation whose powers are computed has its `α` among
    // them.
    let mut inputs: BTreeSet<Input> = BTreeSet::new();
    for op in &dag.nodes {
        match *op {
            dag::Op::Input(input) => inputs.insert(input),
            dag::Op::Power { relation, .. } => inputs.insert(Input::Alpha(relation)),
            _ => continue,
        };
    }
    let inputs: Vec<Input> = inputs.into_iter().collect();
    let index: HashMap<Input, usize> = inputs
        .iter()
        .enumerate()
        .map(|(i, &input)| (input, i))
        .collect();
    let all: Vec<dag::Node> = roots.iter().flatten().copied().collect();
    let lowered = program::lower(&dag, &all, &|input| index[input], &|relation| {
        Operand::Input(index[&Input::Alpha(relation)])
    });
    let mut values = lowered.roots.into_iter();
    for (component, roots) in components.iter_mut().zip(&roots) {
        component.constraints = values.by_ref().take(roots.len()).collect();
    }
    Compiled {
        components,
        relations: relations.to_vec(),
        preprocessed,
        inputs,
        rows: lowered.rows,
        power_rows: lowered.power_rows,
    }
}

/// The relations of `challenges`, name and tuple size, for [`compile`].
pub fn relations_of(challenges: &[RelationChallenges]) -> Vec<(String, usize)> {
    challenges
        .iter()
        .map(|relation| (relation.name.clone(), relation.alpha_powers.len()))
        .collect()
}

/// The verifier's random linear combination of `constraints` under `coeff`,
/// continuing `acc`: `acc ← acc·coeff + c` for each constraint `c`, as
/// `PointEvaluationAccumulator::accumulate`. One `mul_add` row a constraint,
/// none for the first when `acc` is `None`.
pub fn compose<V: Value>(
    context: &mut Context<V>,
    acc: Option<Var>,
    coeff: Var,
    constraints: &[Var],
) -> Option<Var> {
    constraints.iter().fold(acc, |acc, &c| {
        Some(match acc {
            None => c,
            Some(acc) => context.mul_add(acc, coeff, c),
        })
    })
}

/// [`compose`] over values.
pub fn compose_values(
    acc: Option<SecureField>,
    coeff: SecureField,
    constraints: &[SecureField],
) -> Option<SecureField> {
    constraints.iter().fold(acc, |acc, &c| {
        Some(match acc {
            None => c,
            Some(acc) => acc * coeff + c,
        })
    })
}

impl Compiled {
    /// The rows that evaluate the constraints, past the `α` powers.
    pub fn gate_rows(&self) -> usize {
        self.rows.len() - self.power_rows
    }

    /// The input values `values` gives, in [`Compiled::inputs`]' order.
    ///
    /// # Panics
    /// When a relation is missing, or a sample's offset is not in its
    /// column's mask.
    pub fn input_values(&self, values: &OodsValues<'_>) -> Vec<SecureField> {
        let relation = |r: usize| {
            values
                .relations
                .iter()
                .find(|c| c.name == self.relations[r].0)
                .unwrap_or_else(|| panic!("no challenges for {}", self.relations[r].0))
        };
        self.inputs
            .iter()
            .map(|input| match *input {
                Input::Sample {
                    chip,
                    tree,
                    column,
                    offset,
                } => {
                    let offsets = &self.components[chip].offsets[tree][column];
                    let k = offsets
                        .iter()
                        .position(|&o| o == offset)
                        .expect("an offset of the column's mask");
                    values.samples[chip][tree][column][k]
                }
                Input::Preprocessed(index) => values.preprocessed[index],
                Input::ClaimedSum(chip) => values.claimed_sums[chip],
                Input::Z(r) => relation(r).z,
                Input::Alpha(r) => relation(r).alpha_powers[1],
            })
            .collect()
    }

    /// Each row's value, over the input values `inputs`.
    pub fn evaluate_rows(&self, inputs: &[SecureField]) -> Vec<SecureField> {
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let value = row.evaluate(inputs, &rows);
            rows.push(value);
        }
        rows
    }

    /// Each component's constraint values, over the input values `inputs`.
    pub fn evaluate(&self, inputs: &[SecureField]) -> Vec<Vec<SecureField>> {
        let rows = self.evaluate_rows(inputs);
        self.values(inputs, &rows)
    }

    /// Each component's constraint values, given every row's value.
    pub fn values(&self, inputs: &[SecureField], rows: &[SecureField]) -> Vec<Vec<SecureField>> {
        self.components
            .iter()
            .map(|component| {
                component
                    .constraints
                    .iter()
                    .map(|operand| match *operand {
                        Operand::Input(i) => inputs[i],
                        Operand::Row(r) => rows[r],
                        Operand::One => SecureField::from(1),
                        Operand::Constant(value) => value,
                    })
                    .collect()
            })
            .collect()
    }

    /// The rows in `context`, over the input wires `inputs`; each
    /// component's constraint values as wires.
    pub fn emit<V: Value>(&self, context: &mut Context<V>, inputs: &[Var]) -> Vec<Vec<Var>> {
        assert_eq!(inputs.len(), self.inputs.len(), "one wire an input");
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let var = row.emit(context, inputs, &rows);
            rows.push(var);
        }
        self.components
            .iter()
            .map(|component| {
                component
                    .constraints
                    .iter()
                    .map(|operand| match *operand {
                        Operand::Input(i) => inputs[i],
                        Operand::Row(r) => rows[r],
                        Operand::One => context.one(),
                        Operand::Constant(value) => context.constant(value),
                    })
                    .collect()
            })
            .collect()
    }

    /// The composition polynomial's value at the OODS point from the
    /// constraint values, as `Components::eval_composition_polynomial_at_point`:
    /// every component's constraints in one random linear combination under
    /// `coeff`, times the vanishing polynomial's inverse `denom_inverse`.
    pub fn composition_value(
        constraints: &[Vec<SecureField>],
        coeff: SecureField,
        denom_inverse: SecureField,
    ) -> SecureField {
        let acc = constraints
            .iter()
            .fold(None, |acc, values| compose_values(acc, coeff, values));
        acc.unwrap_or_else(SecureField::zero) * denom_inverse
    }

    /// The rows each component reaches, past the `α` powers: its own cost,
    /// counting rows it shares with others.
    pub fn component_rows(&self, chip: usize) -> usize {
        let mut reached = vec![false; self.rows.len()];
        let mut stack: Vec<usize> = self.components[chip]
            .constraints
            .iter()
            .filter_map(|operand| match operand {
                Operand::Row(r) => Some(*r),
                _ => None,
            })
            .collect();
        while let Some(r) = stack.pop() {
            if std::mem::replace(&mut reached[r], true) {
                continue;
            }
            let operands = match &self.rows[r] {
                Row::Inverse(a) => vec![*a],
                Row::Gate { operands, .. } => operands.iter().flatten().copied().collect(),
            };
            stack.extend(operands.into_iter().filter_map(|operand| match operand {
                Operand::Row(r) => Some(r),
                _ => None,
            }));
        }
        reached[self.power_rows..].iter().filter(|&&r| r).count()
    }
}
