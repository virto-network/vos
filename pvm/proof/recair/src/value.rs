//! The values a [`Context`](crate::Context) carries: the witness's QM31s, or
//! nothing, for a circuit's wiring alone.
//!
//! Adapted from starkware-libs/proving, crates/circuits/src/ivalue.rs, at
//! 916aefb5 (Apache-2.0), modified: our gate set's operations, and the
//! Poseidon2-M31 permutation over four packed wires.

use core::fmt::Debug;
use core::ops::{Add, Mul, Sub};

use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

/// A wire's value. One code path builds a circuit's wiring and its witness:
/// with [`NoValue`] it builds the wiring, with [`SecureField`] the same wiring
/// filled.
pub trait Value:
    Copy + Debug + PartialEq + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self>
{
    fn from_qm31(value: SecureField) -> Self;

    /// The product limb by limb.
    fn pointwise_mul(self, other: Self) -> Self;

    /// `Σ_j lanes_j·self_j`, an M31 as a QM31.
    fn lane_sum(self, lanes: [BaseField; 4]) -> Self;

    /// Limb `j`, an M31 as a QM31.
    fn limb(self, j: usize) -> Self;

    /// The inverse; zero's is zero.
    fn inverse(self) -> Self;

    /// The Poseidon2-M31 permutation of the sixteen limbs of four wires.
    fn permute(state: [Self; 4]) -> [Self; 4];

    /// The value, when there is one.
    fn to_qm31(self) -> Option<SecureField>;
}

/// No value: the circuit's wiring alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NoValue;

impl Add for NoValue {
    type Output = Self;
    fn add(self, _: Self) -> Self {
        NoValue
    }
}

impl Sub for NoValue {
    type Output = Self;
    fn sub(self, _: Self) -> Self {
        NoValue
    }
}

impl Mul for NoValue {
    type Output = Self;
    fn mul(self, _: Self) -> Self {
        NoValue
    }
}

impl Value for NoValue {
    fn from_qm31(_: SecureField) -> Self {
        NoValue
    }
    fn pointwise_mul(self, _: Self) -> Self {
        NoValue
    }
    fn lane_sum(self, _: [BaseField; 4]) -> Self {
        NoValue
    }
    fn limb(self, _: usize) -> Self {
        NoValue
    }
    fn inverse(self) -> Self {
        NoValue
    }
    fn permute(_: [Self; 4]) -> [Self; 4] {
        [NoValue; 4]
    }
    fn to_qm31(self) -> Option<SecureField> {
        None
    }
}

/// An M31 as a QM31.
pub fn embed(value: BaseField) -> SecureField {
    SecureField::from_m31_array([
        value,
        BaseField::from(0),
        BaseField::from(0),
        BaseField::from(0),
    ])
}

impl Value for SecureField {
    fn from_qm31(value: SecureField) -> Self {
        value
    }

    fn pointwise_mul(self, other: Self) -> Self {
        let [a, b] = [self.to_m31_array(), other.to_m31_array()];
        SecureField::from_m31_array(core::array::from_fn(|i| a[i] * b[i]))
    }

    fn lane_sum(self, lanes: [BaseField; 4]) -> Self {
        let limbs = self.to_m31_array();
        embed((0..4).map(|j| lanes[j] * limbs[j]).sum())
    }

    fn limb(self, j: usize) -> Self {
        embed(self.to_m31_array()[j])
    }

    fn inverse(self) -> Self {
        if self == SecureField::from(0) {
            self
        } else {
            FieldExpOps::inverse(&self)
        }
    }

    fn permute(state: [Self; 4]) -> [Self; 4] {
        let mut words = words_of(state);
        vos_pvm_poseidon2::permute(&mut words);
        wires_of(words)
    }

    fn to_qm31(self) -> Option<SecureField> {
        Some(self)
    }
}

/// The sixteen words of four wires.
pub fn words_of(wires: [SecureField; 4]) -> [vos_pvm_poseidon2::M31; 16] {
    core::array::from_fn(|i| vos_pvm_poseidon2::M31::new(wires[i / 4].to_m31_array()[i % 4].0))
}

/// Four wires of sixteen words.
pub fn wires_of(words: [vos_pvm_poseidon2::M31; 16]) -> [SecureField; 4] {
    core::array::from_fn(|w| {
        SecureField::from_m31_array(core::array::from_fn(|i| {
            BaseField::from_u32_unchecked(words[4 * w + i].value())
        }))
    })
}
