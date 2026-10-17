//! The hash-consed DAG of QM31 operations that every recorded constraint
//! compiles into (`recursion-air.md` §3, step 3).
//!
//! At the OODS point every value is a QM31: a base column's sample at an
//! extension point is one. So a base and an extension expression make the
//! same nodes. Interning shares every repeated subexpression, within a chip
//! and across chips (their challenges and constants), and the constructors
//! simplify `x + 0`, `x − 0`, `x − x`, `x·1`, `x·0`, a double negation and
//! every operation on constants.

use std::collections::HashMap;

use num_traits::{One, Zero};
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::Input;

/// A node of the DAG, by its index.
pub(crate) type Node = usize;

/// What a node computes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Input(Input),
    /// A relation's `α^power`, `power ≥ 2`, which the circuit computes from
    /// `α`.
    Power {
        relation: usize,
        power: usize,
    },
    /// A constant, by its four limbs.
    Const([u32; 4]),
    Add(Node, Node),
    Sub(Node, Node),
    Mul(Node, Node),
    Neg(Node),
    Inv(Node),
}

/// The DAG: its nodes in creation order, so every operand precedes its
/// consumers.
#[derive(Clone, Debug, Default)]
pub(crate) struct Dag {
    pub nodes: Vec<Op>,
    interned: HashMap<Op, Node>,
}

fn limbs(value: SecureField) -> [u32; 4] {
    value.to_m31_array().map(|limb| limb.0)
}

pub(crate) fn value_of(limbs: [u32; 4]) -> SecureField {
    SecureField::from_m31_array(limbs.map(BaseField::from_u32_unchecked))
}

impl Dag {
    fn intern(&mut self, op: Op) -> Node {
        if let Some(&node) = self.interned.get(&op) {
            return node;
        }
        let node = self.nodes.len();
        self.nodes.push(op.clone());
        self.interned.insert(op, node);
        node
    }

    pub fn input(&mut self, input: Input) -> Node {
        self.intern(Op::Input(input))
    }

    pub fn power(&mut self, relation: usize, power: usize) -> Node {
        self.intern(Op::Power { relation, power })
    }

    pub fn constant(&mut self, value: SecureField) -> Node {
        self.intern(Op::Const(limbs(value)))
    }

    /// The node's value, if it is a constant.
    pub fn value(&self, node: Node) -> Option<SecureField> {
        match self.nodes[node] {
            Op::Const(limbs) => Some(value_of(limbs)),
            _ => None,
        }
    }

    /// The node's value, if it is an M31 constant: a gate takes it as a
    /// coefficient.
    pub fn m31(&self, node: Node) -> Option<BaseField> {
        match self.nodes[node] {
            Op::Const([limb, 0, 0, 0]) => Some(BaseField::from_u32_unchecked(limb)),
            _ => None,
        }
    }

    fn is(&self, node: Node, value: SecureField) -> bool {
        self.value(node) == Some(value)
    }

    pub fn add(&mut self, a: Node, b: Node) -> Node {
        if self.is(a, SecureField::zero()) {
            return b;
        }
        if self.is(b, SecureField::zero()) {
            return a;
        }
        if let (Some(x), Some(y)) = (self.value(a), self.value(b)) {
            return self.constant(x + y);
        }
        self.intern(Op::Add(a.min(b), a.max(b)))
    }

    pub fn sub(&mut self, a: Node, b: Node) -> Node {
        if self.is(b, SecureField::zero()) {
            return a;
        }
        if a == b {
            return self.constant(SecureField::zero());
        }
        if let (Some(x), Some(y)) = (self.value(a), self.value(b)) {
            return self.constant(x - y);
        }
        if self.is(a, SecureField::zero()) {
            return self.neg(b);
        }
        self.intern(Op::Sub(a, b))
    }

    pub fn mul(&mut self, a: Node, b: Node) -> Node {
        if self.is(a, SecureField::zero()) || self.is(b, SecureField::zero()) {
            return self.constant(SecureField::zero());
        }
        if self.is(a, SecureField::one()) {
            return b;
        }
        if self.is(b, SecureField::one()) {
            return a;
        }
        if let (Some(x), Some(y)) = (self.value(a), self.value(b)) {
            return self.constant(x * y);
        }
        self.intern(Op::Mul(a.min(b), a.max(b)))
    }

    pub fn neg(&mut self, a: Node) -> Node {
        if let Some(x) = self.value(a) {
            return self.constant(-x);
        }
        if let Op::Neg(inner) = self.nodes[a] {
            return inner;
        }
        self.intern(Op::Neg(a))
    }

    /// `a⁻¹`. The inverse of the constant zero is refused: the verifier
    /// would divide by zero.
    pub fn inv(&mut self, a: Node) -> Node {
        if let Some(x) = self.value(a) {
            assert_ne!(x, SecureField::zero(), "a recorded inverse of zero");
            return self.constant(x.inverse());
        }
        self.intern(Op::Inv(a))
    }

    /// The operands of `node`.
    pub fn operands(&self, node: Node) -> impl Iterator<Item = Node> {
        let (a, b) = match self.nodes[node] {
            Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) => (Some(a), Some(b)),
            Op::Neg(a) | Op::Inv(a) => (Some(a), None),
            Op::Input(_) | Op::Power { .. } | Op::Const(_) => (None, None),
        };
        a.into_iter().chain(b)
    }
}
