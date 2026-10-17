//! The QM31 gate's idioms, each one row.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;

use super::{Context, Var};
use crate::circuit::Qm31Op;
use crate::value::Value;

impl<V: Value> Context<V> {
    /// `a + b`.
    pub fn add(&mut self, a: Var, b: Var) -> Var {
        self.qm31(
            Qm31Op {
                k_a: BaseField::one(),
                k_b: BaseField::one(),
                ..Default::default()
            },
            Some(a),
            Some(b),
            None,
        )
    }

    /// `a − b`.
    pub fn sub(&mut self, a: Var, b: Var) -> Var {
        self.qm31(
            Qm31Op {
                k_a: BaseField::one(),
                k_b: -BaseField::one(),
                ..Default::default()
            },
            Some(a),
            Some(b),
            None,
        )
    }

    /// `a·b`.
    pub fn mul(&mut self, a: Var, b: Var) -> Var {
        self.qm31(
            Qm31Op {
                k_m: BaseField::one(),
                ..Default::default()
            },
            Some(a),
            Some(b),
            None,
        )
    }

    /// `a⊙b`, limb by limb.
    pub fn pointwise_mul(&mut self, a: Var, b: Var) -> Var {
        self.qm31(
            Qm31Op {
                k_p: BaseField::one(),
                ..Default::default()
            },
            Some(a),
            Some(b),
            None,
        )
    }

    /// `a·b + c`, one row.
    pub fn mul_add(&mut self, a: Var, b: Var, c: Var) -> Var {
        self.qm31(
            Qm31Op {
                k_m: BaseField::one(),
                k_c: BaseField::one(),
                ..Default::default()
            },
            Some(a),
            Some(b),
            Some(c),
        )
    }

    /// `k·a`.
    pub fn scale(&mut self, a: Var, k: BaseField) -> Var {
        self.qm31(
            Qm31Op {
                k_a: k,
                ..Default::default()
            },
            Some(a),
            None,
            None,
        )
    }

    /// Limb `j` of the packed wire `c`, as a QM31.
    pub fn limb(&mut self, c: Var, j: usize) -> Var {
        let mut lanes = [BaseField::zero(); 4];
        lanes[j] = BaseField::one();
        self.qm31(
            Qm31Op {
                lanes,
                ..Default::default()
            },
            None,
            None,
            Some(c),
        )
    }

    /// `a⁻¹`, one row: `a·b = 1`, with `b` guessed and yielded by the row,
    /// whose output uses `one`. `a` must not be zero.
    pub fn inverse(&mut self, a: Var) -> Var {
        let value = self.value(a).inverse();
        let b = self.guess(value);
        let one = self.one();
        self.qm31_into(
            Qm31Op {
                k_m: BaseField::one(),
                ..Default::default()
            },
            Some(a),
            Some(b),
            None,
            one,
        );
        b
    }

    /// Constrains `b` to a bit: `b·b = b`, one row.
    pub fn assert_bit(&mut self, b: Var) {
        self.qm31_into(
            Qm31Op {
                k_m: BaseField::one(),
                ..Default::default()
            },
            Some(b),
            Some(b),
            None,
            b,
        );
    }

    /// Constrains `a` to equal `b`: `1·a` written to `b`'s address.
    pub fn assert_eq(&mut self, a: Var, b: Var) {
        self.qm31_into(
            Qm31Op {
                k_a: BaseField::one(),
                ..Default::default()
            },
            Some(a),
            None,
            None,
            b,
        );
    }
}
