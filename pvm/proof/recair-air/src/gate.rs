//! The `Gate` relation: the one relation that wires the recursion AIR's
//! components (`recursion-air.md` §1.1).
//!
//! # The wiring
//!
//! A **wire** is a tuple `(address, l0, l1, l2, l3)`: a QM31, or four M31
//! limbs packed (a Merkle digest is two wires, a block of eight values two).
//! Every operand of every gate is an entry of this relation whose address and
//! multiplicity are preprocessed columns, so a circuit fixes both. The
//! multiplicity is signed:
//! - **+1, a use** of a wire yielded elsewhere;
//! - **−k, a yield**: the operand introduces the wire, a computed output or a
//!   guessed value consumed here first, and `k` operands elsewhere use it;
//! - **0, free**: a witness no other operand reads (a Merkle sibling).
//!
//! A circuit's **outputs** are public: each output's yield counts one use
//! more, and the verifier adds that use as a public term, the tuple of the
//! output's address and its claimed value ([`public_logup_sum`]). The wire `u`
//! at [`U_ADDRESS`] is such an output, with the fixed value [`U_VALUE`]: the
//! constants are made from it and from `one`.
//!
//! **The circuit's builder checks two things statically,** on the
//! preprocessed columns alone (`vos-recair`'s wiring check):
//! 1. every address that any operand or public term uses is yielded exactly
//!    once, with the multiplicity `−k` of its `k` uses;
//! 2. the sum of the absolute multiplicities, the public uses among them, is
//!    below `p`.
//!
//! # Why it is sound
//!
//! Fix the circuit, so its addresses and multiplicities, and let the prover
//! choose every other column. The relation's challenges `(z, α)` are drawn
//! after the main trace is committed, and the verifier checks that the
//! components' claimed sums and the public terms add to zero.
//!
//! - **The logup lemma.** The sum is `Σ_t m_t / (combine(t) − z)` over the
//!   distinct tuples `t`, with `m_t` the total multiplicity of `t` in `F_p`.
//!   As a rational function of `z` (at the drawn `α`) it vanishes only if
//!   every `m_t` is zero in `F_p`; otherwise it vanishes at a random `z` with
//!   probability at most (the number of fractions) / |QM31|, and `combine`
//!   separates distinct tuples except with probability at most 4/|QM31| over
//!   `α`. Both are the Schwartz–Zippel error.
//! - **From `F_p` to the integers.** Each `m_t` is a sum of preprocessed
//!   multiplicities, each a small signed integer. Their absolute values sum
//!   below `p` (check 2), so `m_t ≡ 0 (mod p)` forces `m_t = 0` as an integer.
//! - **One value an address.** The address is the tuple's first limb, so
//!   tuples at different addresses never cancel. At one address, the only
//!   negative multiplicity is the yield's `−k` (check 1), and the `k` uses are
//!   `+1` each. A use whose four limbs differ from the yield's is a tuple of
//!   its own, whose total is positive: nothing can cancel it. So every use
//!   carries the yielded value, which is the wiring: each gate's input is the
//!   value its producer computed, or the value the prover guessed once.
//! - **Outputs.** An output's yield counts `k + 1`, and the verifier's public
//!   term supplies the last `+1` at the claimed value. The same argument makes
//!   the yielded value the claimed one. So `u` is [`U_VALUE`], and each output
//!   is the value the verifier was given.
//! - **Constants** are then fixed by gates: zero by `x + x = x`, one by
//!   `u·x = u`, and every other constant by a gate from `one`, `u` and the
//!   basis they make.
//! - **What it does not need.** The yield count is static: it lives in the
//!   preprocessed columns, which the circuit hash pins, so no in-AIR check of
//!   a dynamic component size is needed, as StarkWare's verifier has for its
//!   (`stark_verifier/src/verify.rs:238-311` of `starkware-libs/proving`).
//!   Equality needs no component either: a value that must equal another is
//!   produced by a gate whose operand uses the other's address.
//!
//! The argument holds for any circuit that passes the checks; the checks are
//! the builder's, and a verifier trusts the circuit by its hash.

use stwo::core::channel::Channel;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::logup::LookupElements;
use stwo_constraint_framework::{Relation, RelationEFTraitBound};

/// A wire's width: its address and four limbs.
pub const GATE_WIDTH: usize = 5;

/// The address of the zero wire.
pub const ZERO_ADDRESS: u32 = 0;
/// The address of the one wire.
pub const ONE_ADDRESS: u32 = 1;
/// The address of `u`.
pub const U_ADDRESS: u32 = 2;
/// The address of a node's first output wire; its others follow.
pub const FIRST_OUTPUT_ADDRESS: u32 = 3;

/// `u`, the QM31 generator over CM31: `(0, 0, 1, 0)`.
pub const U_VALUE: SecureField = SecureField::from_u32_unchecked(0, 0, 1, 0);

/// The `Gate` relation's challenges.
#[derive(Clone, Debug, PartialEq)]
pub struct GateRelation(pub LookupElements<GATE_WIDTH>);

impl GateRelation {
    /// The relation's challenge pair, drawn from `channel`.
    pub fn draw(channel: &mut impl Channel) -> Self {
        Self(LookupElements::draw(channel))
    }

    /// Fixed challenges, for evaluations that do not prove.
    pub fn dummy() -> Self {
        Self(LookupElements::dummy())
    }

    /// The denominator of the wire `(address, limbs)`.
    pub fn denominator(&self, address: u32, limbs: [BaseField; 4]) -> SecureField {
        let [l0, l1, l2, l3] = limbs;
        self.0
            .combine(&[BaseField::from_u32_unchecked(address), l0, l1, l2, l3])
    }
}

impl<F: Clone, EF: RelationEFTraitBound<F>> Relation<F, EF> for GateRelation {
    fn combine(&self, values: &[F]) -> EF {
        self.0.combine(values)
    }

    fn get_name(&self) -> &str {
        "Gate"
    }

    fn get_size(&self) -> usize {
        GATE_WIDTH
    }
}

/// A public use: an output's address and its claimed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicTerm {
    pub address: u32,
    pub value: SecureField,
}

/// The public terms a verifier adds, one use each: `u`, then the outputs at
/// their addresses.
pub fn public_terms(
    outputs: impl IntoIterator<Item = (u32, SecureField)>,
) -> impl Iterator<Item = PublicTerm> {
    core::iter::once(PublicTerm {
        address: U_ADDRESS,
        value: U_VALUE,
    })
    .chain(
        outputs
            .into_iter()
            .map(|(address, value)| PublicTerm { address, value }),
    )
}

/// The sum of the public terms' fractions, each a use (`+1`). The components'
/// claimed sums and this sum add to zero for an honest proof.
pub fn public_logup_sum(
    relation: &GateRelation,
    terms: impl IntoIterator<Item = PublicTerm>,
) -> SecureField {
    terms
        .into_iter()
        .map(|term| {
            relation
                .denominator(term.address, term.value.to_m31_array())
                .inverse()
        })
        .sum()
}
