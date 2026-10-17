//! A component's constraints as constraint-framework's recording evaluator
//! (`ExprEvaluator`) states them, and their lowering into the DAG
//! (`recursion-air.md` §3, steps 1–2).
//!
//! The recording names everything the verifier supplies: columns by
//! `(tree, index, offset)`, preprocessed columns by their id, each relation's
//! challenges as `<Relation>_z` and `<Relation>_alpha<i>`, and the logup's
//! `claimed_sum` and `column_size`. Lowering resolves every name to an input,
//! a constant or an intermediate of the same component, so components share
//! only challenges, preprocessed columns and constants. A name it cannot
//! resolve is refused: nothing becomes a free input silently.

use std::collections::{HashMap, HashSet};

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::expr::{BaseExpr, ColumnExpr, ExprEvaluator, ExtExpr};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    FrameworkEval, INTERACTION_TRACE_IDX, InfoEvaluator, ORIGINAL_TRACE_IDX,
};
use vos_pvm_proof::framework_access::{AllLookupElements, drive_chip_oods};

use super::Input;
use super::dag::{Dag, Node};

/// A component's recorded constraints and the layout of what it reads.
pub struct Recording {
    pub name: String,
    pub log_size: u32,
    /// Each main column's mask offsets, in the order the component reads
    /// them; then each interaction column's.
    pub offsets: [Vec<Vec<isize>>; 2],
    /// The preprocessed columns it reads, in the order it reads them.
    pub preprocessed: Vec<PreProcessedColumnId>,
    expr: ExprEvaluator,
}

impl Recording {
    /// The constraints of `component`.
    pub fn of<C: FrameworkEval>(name: &str, component: &C) -> Self {
        Self::new(
            name,
            component.log_size(),
            component.evaluate(InfoEvaluator::empty()),
            component.evaluate(ExprEvaluator::new()),
        )
    }

    /// The constraints of the segment AIR's chip `chip_idx` at `log_size`
    /// rows. The recording names each relation's challenges, so `lookup`'s
    /// values do not matter; it must hold every relation the chip uses.
    pub fn chip(chip_idx: usize, log_size: u32, lookup: &AllLookupElements) -> Self {
        Self::new(
            super::CHIP_NAMES[chip_idx],
            log_size,
            drive_chip_oods(chip_idx, log_size, lookup, InfoEvaluator::empty()),
            drive_chip_oods(chip_idx, log_size, lookup, ExprEvaluator::new()),
        )
    }

    /// A recording from a component's two evaluations: `info`, what it
    /// reads, and `expr`, its constraints.
    pub fn new(name: &str, log_size: u32, info: InfoEvaluator, expr: ExprEvaluator) -> Self {
        let tree = |index: usize| info.mask_offsets.get(index).cloned().unwrap_or_default();
        Self {
            name: name.into(),
            log_size,
            offsets: [tree(ORIGINAL_TRACE_IDX), tree(INTERACTION_TRACE_IDX)],
            preprocessed: info.preprocessed_columns,
            expr,
        }
    }

    /// The recording itself.
    pub fn expr(&self) -> &ExprEvaluator {
        &self.expr
    }

    /// The recording's key `(interaction, index, offset)` for column
    /// `column` of `tree` (0, main; 1, interaction) at `offset`.
    ///
    /// The recording numbers every column the component reads in one
    /// sequence, so this numbering holds if the component reads its main
    /// columns first. Lowering checks it: it refuses a recorded column
    /// outside this numbering, and a component whose constraints leave an
    /// interaction column unread. With every interaction column read, the
    /// first one's key is in the numbering only if every main column was
    /// read before it, and then every key names its column.
    pub fn column_key(&self, tree: usize, column: usize, offset: isize) -> (usize, usize, isize) {
        match tree {
            0 => (ORIGINAL_TRACE_IDX, column, offset),
            1 => (
                INTERACTION_TRACE_IDX,
                self.offsets[0].len() + column,
                offset,
            ),
            _ => panic!("tree {tree} holds no sampled column"),
        }
    }

    /// The component's constraints lowered into `dag`, as component `chip`
    /// of the shape, with the shape's `relations` (name, tuple size) and
    /// preprocessed columns (`preprocessed[k]` the shape's index of the
    /// recording's `k`-th).
    pub(crate) fn lower(
        &self,
        chip: usize,
        relations: &[(String, usize)],
        preprocessed: &[usize],
        dag: &mut Dag,
    ) -> Vec<Node> {
        let mut columns = HashMap::new();
        for tree in 0..2 {
            for (column, offsets) in self.offsets[tree].iter().enumerate() {
                for &offset in offsets {
                    let input = Input::Sample {
                        chip,
                        tree,
                        column,
                        offset,
                    };
                    columns.insert(
                        ColumnExpr::from(self.column_key(tree, column, offset)),
                        input,
                    );
                }
            }
        }
        let mut lowering = Lowering {
            recording: self,
            chip,
            relations,
            preprocessed,
            columns,
            names: HashMap::new(),
            read: HashSet::new(),
        };
        let constraints = self
            .expr
            .constraints
            .iter()
            .map(|constraint| lowering.ext(constraint, dag))
            .collect();
        for column in 0..self.offsets[1].len() {
            assert!(
                lowering.read.contains(&(1, column)),
                "{}: no constraint reads interaction column {column}",
                self.name
            );
        }
        constraints
    }
}

/// What a recorded name stands for.
enum Name<'a> {
    Base(&'a BaseExpr),
    Ext(&'a ExtExpr),
    Power { relation: usize, power: usize },
    Input(Input),
    Const(SecureField),
}

struct Lowering<'a> {
    recording: &'a Recording,
    chip: usize,
    relations: &'a [(String, usize)],
    preprocessed: &'a [usize],
    columns: HashMap<ColumnExpr, Input>,
    /// The names already lowered, intermediates among them.
    names: HashMap<String, Node>,
    /// The columns read, `(tree, column)`.
    read: HashSet<(usize, usize)>,
}

impl Lowering<'_> {
    /// What `name` stands for, refused if it is none or more than one of the
    /// recording's names.
    fn resolve(&self, name: &str) -> Name<'_> {
        let expr = &self.recording.expr;
        let mut found = Vec::new();
        if let Some(e) = expr.intermediates.get(name) {
            found.push(Name::Base(e));
        }
        if let Some(e) = expr.ext_intermediates.get(name) {
            found.push(Name::Ext(e));
        }
        if name == "claimed_sum" {
            found.push(Name::Input(Input::ClaimedSum(self.chip)));
        }
        if name == "column_size" {
            let size = BaseField::from(1u32 << self.recording.log_size);
            found.push(Name::Const(size.into()));
        }
        if let Some(k) = self
            .recording
            .preprocessed
            .iter()
            .position(|id| id.id == name)
        {
            found.push(Name::Input(Input::Preprocessed(self.preprocessed[k])));
        }
        for (relation, (relation_name, size)) in self.relations.iter().enumerate() {
            let Some(rest) = name.strip_prefix(relation_name.as_str()) else {
                continue;
            };
            if rest == "_z" {
                found.push(Name::Input(Input::Z(relation)));
            } else if let Some(digits) = rest.strip_prefix("_alpha") {
                let power = match digits.parse::<usize>() {
                    Ok(power) if power < *size && power.to_string() == digits => power,
                    _ => panic!("{name}: no power of {relation_name}'s α"),
                };
                found.push(match power {
                    0 => Name::Const(SecureField::one()),
                    1 => Name::Input(Input::Alpha(relation)),
                    _ => Name::Power { relation, power },
                });
            }
        }
        match found.len() {
            1 => found.pop().unwrap(),
            0 => panic!(
                "{}: the recording names {name}, which is no input",
                self.recording.name
            ),
            _ => panic!("{}: the name {name} is ambiguous", self.recording.name),
        }
    }

    fn param(&mut self, name: &str, dag: &mut Dag) -> Node {
        if let Some(&node) = self.names.get(name) {
            return node;
        }
        let node = match self.resolve(name) {
            Name::Base(e) => {
                let e = e.clone();
                self.base(&e, dag)
            }
            Name::Ext(e) => {
                let e = e.clone();
                self.ext(&e, dag)
            }
            Name::Input(input) => dag.input(input),
            Name::Const(value) => dag.constant(value),
            Name::Power { relation, power } => dag.power(relation, power),
        };
        self.names.insert(name.to_owned(), node);
        node
    }

    fn base(&mut self, e: &BaseExpr, dag: &mut Dag) -> Node {
        match e {
            BaseExpr::Col(column) => {
                let input = *self.columns.get(column).unwrap_or_else(|| {
                    panic!(
                        "{}: {column:?} is outside the component's mask",
                        self.recording.name
                    )
                });
                if let Input::Sample { tree, column, .. } = input {
                    self.read.insert((tree, column));
                }
                dag.input(input)
            }
            BaseExpr::Const(value) => dag.constant((*value).into()),
            BaseExpr::Param(name) => self.param(name, dag),
            BaseExpr::Add(a, b) => {
                let (a, b) = (self.base(a, dag), self.base(b, dag));
                dag.add(a, b)
            }
            BaseExpr::Sub(a, b) => {
                let (a, b) = (self.base(a, dag), self.base(b, dag));
                dag.sub(a, b)
            }
            BaseExpr::Mul(a, b) => {
                let (a, b) = (self.base(a, dag), self.base(b, dag));
                dag.mul(a, b)
            }
            BaseExpr::Neg(a) => {
                let a = self.base(a, dag);
                dag.neg(a)
            }
            BaseExpr::Inv(a) => {
                let a = self.base(a, dag);
                dag.inv(a)
            }
        }
    }

    fn ext(&mut self, e: &ExtExpr, dag: &mut Dag) -> Node {
        match e {
            // `a + b·i + c·u + d·iu`, as `SecureField::from_partial_evals`.
            ExtExpr::SecureCol(parts) => {
                let mut sum = dag.constant(SecureField::from(0));
                for (k, part) in parts.iter().enumerate() {
                    let part = self.base(part, dag);
                    let mut unit = [BaseField::from(0); 4];
                    unit[k] = BaseField::one();
                    let unit = dag.constant(SecureField::from_m31_array(unit));
                    let term = dag.mul(part, unit);
                    sum = dag.add(sum, term);
                }
                sum
            }
            ExtExpr::Const(value) => dag.constant(*value),
            ExtExpr::Param(name) => self.param(name, dag),
            ExtExpr::Add(a, b) => {
                let (a, b) = (self.ext(a, dag), self.ext(b, dag));
                dag.add(a, b)
            }
            ExtExpr::Sub(a, b) => {
                let (a, b) = (self.ext(a, dag), self.ext(b, dag));
                dag.sub(a, b)
            }
            ExtExpr::Mul(a, b) => {
                let (a, b) = (self.ext(a, dag), self.ext(b, dag));
                dag.mul(a, b)
            }
            ExtExpr::Neg(a) => {
                let a = self.ext(a, dag);
                dag.neg(a)
            }
        }
    }
}
