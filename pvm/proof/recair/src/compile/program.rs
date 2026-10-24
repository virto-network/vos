//! The DAG as rows of the `qm31` gate (`recursion-air.md` §3, step 4).
//!
//! Every reachable operation is one row, except a child its only consumer
//! takes in: a linear row (an add or a sub) takes in, within the gate's three
//! operands, a single-use product (one at most), negation or scaling by an
//! M31 constant. An M31 constant is a coefficient on the `one` wire; any
//! other constant is a wire the `Context` fixes. A constraint's value is a
//! row, an input or a constant, never taken in.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::dag::{Dag, Node, Op};
use crate::circuit::Qm31Op;
use crate::context::{Context, Var};
use crate::value::Value;

/// A gate's operand.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operand {
    /// The compiled circuit's input, by its index.
    Input(usize),
    /// An earlier row's output.
    Row(usize),
    /// The wire `one`.
    One,
    /// A constant's wire.
    Constant(SecureField),
}

/// A row of the compiled circuit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Row {
    /// The `qm31` gate over `a`, `b` and `c`.
    Gate {
        op: Qm31Op,
        operands: [Option<Operand>; 3],
    },
    /// `a⁻¹`, one row of the gate: `a·b = 1`.
    Inverse(Operand),
}

/// A linear form: at most one product, and M31 multiples of wires.
#[derive(Default)]
struct Form {
    product: Option<(BaseField, Operand, Operand)>,
    terms: Vec<(BaseField, Operand)>,
}

impl Form {
    fn term(&mut self, k: BaseField, operand: Operand) {
        match self.terms.iter_mut().find(|(_, o)| *o == operand) {
            Some((sum, _)) => *sum += k,
            None => self.terms.push((k, operand)),
        }
    }

    /// The form as one row.
    fn row(self) -> Row {
        let mut op = Qm31Op::default();
        let mut operands = [None; 3];
        let mut free = 0;
        if let Some((k, a, b)) = self.product {
            op.k_m = k;
            operands[0] = Some(a);
            operands[1] = Some(b);
            free = 2;
        }
        for (k, operand) in self.terms {
            let slot = match operands.iter().position(|o| *o == Some(operand)) {
                Some(slot) => slot,
                None => {
                    assert!(free < 3, "a form of more than three operands");
                    operands[free] = Some(operand);
                    free += 1;
                    free - 1
                }
            };
            match slot {
                0 => op.k_a += k,
                1 => op.k_b += k,
                _ => op.k_c += k,
            }
        }
        Row::Gate { op, operands }
    }
}

/// The rows reaching `roots`, and each root as an operand.
pub(crate) struct Lowered {
    pub rows: Vec<Row>,
    pub roots: Vec<Operand>,
    /// The rows that compute a relation's `α` powers, first.
    pub power_rows: usize,
}

/// `dag`'s nodes reaching `roots`, as rows. `input_index` numbers the
/// inputs; `alpha` gives a relation's `α` input.
pub(crate) fn lower(
    dag: &Dag,
    roots: &[Node],
    input_index: &dyn Fn(&super::Input) -> usize,
    alpha: &dyn Fn(usize) -> Operand,
) -> Lowered {
    let n = dag.nodes.len();
    let (reached, uses, is_root) = reach(dag, roots);
    let mut rows = Vec::new();
    let power_row = power_rows(dag, &reached, alpha, &mut rows);
    let power_rows = rows.len();
    let absorbed = absorbed(dag, &reached, &uses, &is_root);

    let mut operands = Operands {
        dag,
        of: vec![None; n],
    };
    for node in (0..n).filter(|&node| reached[node]) {
        let operand = match dag.nodes[node] {
            Op::Input(input) => Operand::Input(input_index(&input)),
            Op::Power { relation, power } => power_row[&(relation, power)],
            Op::Const(_) => continue,
            _ if absorbed[node] => continue,
            Op::Inv(a) => {
                let (k, a) = operands.wire(a);
                assert_eq!(k, BaseField::one(), "an inverse of a constant is folded");
                rows.push(Row::Inverse(a));
                Operand::Row(rows.len() - 1)
            }
            Op::Neg(a) => {
                let mut form = Form::default();
                let (k, a) = operands.wire(a);
                form.term(-k, a);
                rows.push(form.row());
                Operand::Row(rows.len() - 1)
            }
            Op::Mul(x, y) => {
                rows.push(operands.product(x, y, BaseField::one()).row());
                Operand::Row(rows.len() - 1)
            }
            Op::Add(a, b) | Op::Sub(a, b) => {
                let sign = if matches!(dag.nodes[node], Op::Sub(..)) {
                    -BaseField::one()
                } else {
                    BaseField::one()
                };
                let mut form = Form::default();
                for (child, k) in [(a, BaseField::one()), (b, sign)] {
                    match dag.nodes[child] {
                        _ if !absorbed[child] => {
                            let (scale, operand) = operands.wire(child);
                            form.term(k * scale, operand);
                        }
                        Op::Mul(x, y) => {
                            let inner = operands.product(x, y, k);
                            if inner.product.is_some() {
                                form.product = inner.product;
                            }
                            for (k, operand) in inner.terms {
                                form.term(k, operand);
                            }
                        }
                        Op::Neg(z) => {
                            let (scale, operand) = operands.wire(z);
                            form.term(-k * scale, operand);
                        }
                        _ => unreachable!("only products and negations are taken in"),
                    }
                }
                rows.push(form.row());
                Operand::Row(rows.len() - 1)
            }
        };
        operands.of[node] = Some(operand);
    }
    let roots = roots
        .iter()
        .map(|&root| match dag.value(root) {
            Some(value) => Operand::Constant(value),
            None => operands.of[root].expect("a root is reached"),
        })
        .collect();
    Lowered {
        rows,
        roots,
        power_rows,
    }
}

/// The nodes reaching `roots`, each node's uses by the reached nodes and
/// the roots, and whether it is a root.
fn reach(dag: &Dag, roots: &[Node]) -> (Vec<bool>, Vec<usize>, Vec<bool>) {
    let n = dag.nodes.len();
    let mut reached = vec![false; n];
    let mut stack = roots.to_vec();
    while let Some(node) = stack.pop() {
        if !std::mem::replace(&mut reached[node], true) {
            stack.extend(dag.operands(node));
        }
    }
    let mut uses = vec![0usize; n];
    let mut is_root = vec![false; n];
    for &root in roots {
        uses[root] += 1;
        is_root[root] = true;
    }
    for node in (0..n).filter(|&node| reached[node]) {
        for operand in dag.operands(node) {
            uses[operand] += 1;
        }
    }
    (reached, uses, is_root)
}

/// A relation's powers: `α^i = α^(i−1)·α`, one row each pushed to `rows`,
/// up to the highest power reached; the row of each.
fn power_rows(
    dag: &Dag,
    reached: &[bool],
    alpha: &dyn Fn(usize) -> Operand,
    rows: &mut Vec<Row>,
) -> std::collections::BTreeMap<(usize, usize), Operand> {
    let mut powers: Vec<(usize, usize)> = (0..dag.nodes.len())
        .filter(|&node| reached[node])
        .filter_map(|node| match dag.nodes[node] {
            Op::Power { relation, power } => Some((relation, power)),
            _ => None,
        })
        .collect();
    powers.sort();
    let mut power_row = std::collections::BTreeMap::new();
    for relation in powers.iter().map(|&(relation, _)| relation) {
        if power_row.contains_key(&(relation, 2)) {
            continue;
        }
        let highest = powers
            .iter()
            .filter(|&&(r, _)| r == relation)
            .map(|&(_, power)| power)
            .max()
            .unwrap();
        let mut previous = alpha(relation);
        for power in 2..=highest {
            rows.push(
                Form {
                    product: Some((BaseField::one(), previous, alpha(relation))),
                    terms: vec![],
                }
                .row(),
            );
            previous = Operand::Row(rows.len() - 1);
            power_row.insert((relation, power), previous);
        }
    }
    power_row
}

/// The nodes their consumer takes in: a sum's or a difference's operands
/// that only it uses, each a negation or a product, at most one of them a
/// product of two wires.
fn absorbed(dag: &Dag, reached: &[bool], uses: &[usize], is_root: &[bool]) -> Vec<bool> {
    let n = dag.nodes.len();
    let single = |node: Node| uses[node] == 1 && !is_root[node];
    let mut absorbed = vec![false; n];
    for node in (0..n).filter(|&node| reached[node]) {
        if let Op::Add(a, b) | Op::Sub(a, b) = dag.nodes[node] {
            let mut product = false;
            for child in [a, b] {
                match dag.nodes[child] {
                    Op::Mul(x, y) if single(child) && !product => {
                        absorbed[child] = true;
                        if dag.m31(x).is_none() && dag.m31(y).is_none() {
                            product = true;
                        }
                    }
                    Op::Neg(_) if single(child) => absorbed[child] = true,
                    _ => {}
                }
            }
        }
    }
    absorbed
}

/// The operand each lowered node is.
struct Operands<'a> {
    dag: &'a Dag,
    of: Vec<Option<Operand>>,
}

impl Operands<'_> {
    /// The operand a consumer reads for `node`, and the factor it scales it
    /// by: an M31 constant is its value times `one`.
    fn wire(&self, node: Node) -> (BaseField, Operand) {
        if let Some(k) = self.dag.m31(node) {
            return (k, Operand::One);
        }
        if let Some(value) = self.dag.value(node) {
            return (BaseField::one(), Operand::Constant(value));
        }
        let operand = self.of[node].expect("an operand precedes its consumer");
        (BaseField::one(), operand)
    }

    /// `k·x·y` as a form: a scaling when a factor is an M31 constant, a
    /// product otherwise.
    fn product(&self, x: Node, y: Node, k: BaseField) -> Form {
        let mut form = Form::default();
        match (self.dag.m31(x), self.dag.m31(y)) {
            (Some(scale), _) => {
                let (s, operand) = self.wire(y);
                form.term(k * scale * s, operand);
            }
            (_, Some(scale)) => {
                let (s, operand) = self.wire(x);
                form.term(k * scale * s, operand);
            }
            (None, None) => form.product = Some((k, self.wire(x).1, self.wire(y).1)),
        }
        form
    }
}

impl Row {
    /// The row's value over `values` (the inputs) and `rows` (earlier rows).
    pub fn evaluate(&self, inputs: &[SecureField], rows: &[SecureField]) -> SecureField {
        let value = |operand: &Operand| match *operand {
            Operand::Input(i) => inputs[i],
            Operand::Row(r) => rows[r],
            Operand::One => SecureField::one(),
            Operand::Constant(value) => value,
        };
        match self {
            Row::Inverse(a) => Value::inverse(value(a)),
            Row::Gate { op, operands } => {
                let [a, b, c] = operands.map(|o| o.as_ref().map_or(SecureField::zero(), value));
                op.apply(a, b, c)
            }
        }
    }

    /// The row in `context`, over the wires `inputs` and `rows`.
    pub fn emit<V: Value>(&self, context: &mut Context<V>, inputs: &[Var], rows: &[Var]) -> Var {
        let mut wire = |operand: &Operand| match *operand {
            Operand::Input(i) => inputs[i],
            Operand::Row(r) => rows[r],
            Operand::One => context.one(),
            Operand::Constant(value) => context.constant(value),
        };
        match self {
            Row::Inverse(a) => {
                let a = wire(a);
                context.inverse(a)
            }
            Row::Gate { op, operands } => {
                let [a, b, c] = operands.map(|o| o.as_ref().map(&mut wire));
                context.qm31(*op, a, b, c)
            }
        }
    }
}
