//! `p2`: one Poseidon2-M31 permutation a row (`recursion-air.md` §1.3).
//!
//! **The permutation** is `vos_pvm_poseidon2`'s: the external matrix, four
//! full rounds, fourteen partial rounds, four full rounds. Its S-box `y⁵` is
//! two columns, `a = y²` and `out = a²·y`, so every constraint is of degree 3;
//! with the 16 input words that is 300 columns, the floor at degree 3. The
//! words between S-boxes are linear in the columns.
//!
//! **The modes chain rows.** The last round's S-box outputs are also read at
//! offset −1, so a row's input can take the previous row's output `prev`. One
//! preprocessed selector a row picks the input, from eight message limbs `m`
//! (two wires), a direction bit `b` and per-row constants `act` and `c`, with
//! `a_j = act_j·m_j + c_j` and `h_j = act_j·m_j`:
//!
//! | mode | input `[0, 8)` | input `[8, 16)` | used for |
//! |---|---|---|---|
//! | leaf start | `a` | 0 | a Merkle leaf's first block |
//! | leaf continue | `prev[0, 8) + a` | `prev[8, 16)` | its next blocks |
//! | node | `b ? m : prev[0, 8)` | `b ? prev[0, 8) : m` | a path step over the child below |
//! | channel start | 0 | `h` | the transcript's first absorption |
//! | channel first | `prev[0, 8)` | `h` | an absorption over the last digest; the PoW's second permutation |
//! | channel continue | `prev[0, 8)` | `prev[8, 16) + h` | an absorption's next chunks |
//! | wired | `a` | `(c_8, c_9, 0, …)` | a draw, the PoW's first permutation |
//! | tagged | `c[0, 8)` | `m` | a tag's block and a wire pair: the credential AIR's `C(T(name), x)` |
//!
//! **The tagged row has no selector of its own:** it sets leaf start's and
//! node's selectors to 1 and channel first's to −1, with `act` zero and its
//! bit the zero wire's (a use, so `b = 0` by the relation). The constraint is
//! linear in the selectors, so its input is the sum of the three modes':
//! `[c + prev + 0·(m − prev) − prev, m + 0·(prev − m) − 0]`, which is
//! `[c, m]` as polynomials, `prev` cancelled whatever the row before it holds.
//! A constant block on the left of a wire pair is a compression no single
//! mode forms ([`P2Mode::Tagged`]).
//!
//! A padding row has no selector, so its input is zero and the row holds the
//! permutation of zero. Row order is part of the circuit: a chained row
//! follows its predecessor, and row 0, whose offset −1 is the last row, is
//! never chained.
//!
//! **The lookups** (`Gate`, see [`crate::gate`]): the message as two wires and
//! the output's first eight words as two wires at consecutive addresses, each
//! with a preprocessed multiplicity, and in node rows the bit as a use. Five
//! fractions in three pairs.

use core::array::from_fn;

use alloc::string::ToString;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX, RelationEntry};
use vos_pvm_poseidon2::{
    EXTERNAL_ROUND_CONSTS, FULL_ROUNDS, INTERNAL_ROUND_CONSTS, M31, N_HALF_FULL_ROUNDS, N_STATE,
    apply_external_round_matrix, apply_internal_round_matrix,
};

use crate::gate::GateRelation;
use crate::{Body, LOG_CONSTRAINT_EXPANSION};

/// How a row's input is formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum P2Mode {
    LeafStart,
    LeafContinue,
    Node,
    ChannelStart,
    ChannelFirst,
    ChannelContinue,
    Wired,
    /// `[c[0, 8), m]`: three modes' selectors at once, none of its own (the
    /// module's notes).
    Tagged,
}

impl P2Mode {
    /// The modes with a selector column each, in the columns' order:
    /// every mode but [`P2Mode::Tagged`].
    pub const ALL: [P2Mode; 7] = [
        P2Mode::LeafStart,
        P2Mode::LeafContinue,
        P2Mode::Node,
        P2Mode::ChannelStart,
        P2Mode::ChannelFirst,
        P2Mode::ChannelContinue,
        P2Mode::Wired,
    ];

    /// Whether the row's input reads the previous row's output. A tagged
    /// row's terms in it cancel, so it is not chained.
    pub const fn is_chained(self) -> bool {
        matches!(
            self,
            P2Mode::LeafContinue | P2Mode::Node | P2Mode::ChannelFirst | P2Mode::ChannelContinue
        )
    }

    /// The selectors a row of this mode sets, in [`P2Mode::ALL`]'s order:
    /// its own at 1; a tagged row's leaf start and node at 1 and channel
    /// first at −1.
    pub const fn selectors(self) -> [i8; 7] {
        let mut selectors = [0; 7];
        match self {
            P2Mode::Tagged => {
                selectors[P2Mode::LeafStart as usize] = 1;
                selectors[P2Mode::Node as usize] = 1;
                selectors[P2Mode::ChannelFirst as usize] = -1;
            }
            mode => selectors[mode as usize] = 1,
        }
        selectors
    }

    /// Whether the row's bit is a use: node's selector is set. A tagged
    /// row's is the zero wire's.
    pub const fn reads_bit(self) -> bool {
        matches!(self, P2Mode::Node | P2Mode::Tagged)
    }

    /// Whether the row reads every lane of its message, whatever its `act`:
    /// a node's and a tagged row's.
    pub const fn reads_whole_message(self) -> bool {
        matches!(self, P2Mode::Node | P2Mode::Tagged)
    }
}

/// The S-boxes a permutation applies: 16 in each full round, one in each
/// partial round.
pub const N_SBOXES: usize = FULL_ROUNDS * N_STATE + vos_pvm_poseidon2::N_PARTIAL_ROUNDS;

/// The preprocessed columns, in commitment order: the mode selectors in
/// [`P2Mode::ALL`]'s order, the message wires', the output's and the bit's
/// addresses, the four multiplicities, `act` and `c`.
pub const PREPROCESSED: [&str; 33] = [
    "recair_p2_leaf_start",
    "recair_p2_leaf_continue",
    "recair_p2_node",
    "recair_p2_channel_start",
    "recair_p2_channel_first",
    "recair_p2_channel_continue",
    "recair_p2_wired",
    "recair_p2_addr_m0",
    "recair_p2_addr_m1",
    "recair_p2_addr_out",
    "recair_p2_addr_bit",
    "recair_p2_mult_m0",
    "recair_p2_mult_m1",
    "recair_p2_mult_out0",
    "recair_p2_mult_out1",
    "recair_p2_act_0",
    "recair_p2_act_1",
    "recair_p2_act_2",
    "recair_p2_act_3",
    "recair_p2_act_4",
    "recair_p2_act_5",
    "recair_p2_act_6",
    "recair_p2_act_7",
    "recair_p2_c_0",
    "recair_p2_c_1",
    "recair_p2_c_2",
    "recair_p2_c_3",
    "recair_p2_c_4",
    "recair_p2_c_5",
    "recair_p2_c_6",
    "recair_p2_c_7",
    "recair_p2_c_8",
    "recair_p2_c_9",
];

/// Positions in [`PREPROCESSED`].
pub mod pre {
    /// The first selector; the others follow in [`super::P2Mode::ALL`]'s order.
    pub const SELECTORS: usize = 0;
    pub const ADDR_M: [usize; 2] = [7, 8];
    pub const ADDR_OUT: usize = 9;
    pub const ADDR_BIT: usize = 10;
    pub const MULT_M: [usize; 2] = [11, 12];
    pub const MULT_OUT: [usize; 2] = [13, 14];
    pub const ACT: usize = 15;
    pub const C: usize = 23;
}

/// Positions in the main trace: the input, then each S-box's `a` and `out`
/// in the permutation's order, then the message and the bit.
pub mod main {
    pub const INPUT: usize = 0;
    pub const SBOXES: usize = 16;
    pub const M: usize = SBOXES + 2 * super::N_SBOXES;
    pub const B: usize = M + 8;
}

/// The main trace's columns.
pub const N_MAIN: usize = main::B + 1;
/// The interaction trace's columns: three pairs of fractions.
pub const N_INTERACTION: usize = 12;
/// The constraints: two an S-box, sixteen for the input, three for the
/// fraction pairs.
pub const N_CONSTRAINTS: usize = 2 * N_SBOXES + 16 + 3;

/// The first S-box of the last full round, whose outputs a chained row
/// reads at offset −1.
const LAST_ROUND_SBOXES: usize = N_SBOXES - N_STATE;

fn base(value: M31) -> BaseField {
    BaseField::from_u32_unchecked(value.value())
}

/// The component, at `log_size` rows.
#[derive(Clone)]
pub struct P2Eval {
    pub log_size: u32,
    pub relation: GateRelation,
}

/// The S-box over `y`, as two columns: `a = y²`, `out = a²·y`. In the last
/// round `out` is also read at offset −1, returned second.
fn sbox<E: EvalAtRow>(eval: &mut E, y: E::F, last_round: bool) -> (E::F, Option<E::F>) {
    let a = eval.next_trace_mask();
    let (out, prev) = if last_round {
        let [prev, out] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0]);
        (out, Some(prev))
    } else {
        (eval.next_trace_mask(), None)
    };
    eval.add_constraint(a.clone() - y.clone() * y.clone());
    eval.add_constraint(out.clone() - a.clone() * a * y);
    (out, prev)
}

/// A full round over `state`: its constants, the S-boxes, the external
/// matrix. The last round's S-box outputs at offset −1 go to `prev`.
fn full_round<E: EvalAtRow>(
    eval: &mut E,
    state: &mut [E::F; N_STATE],
    round: usize,
    prev: &mut [E::F; N_STATE],
) {
    let last_round = round == FULL_ROUNDS - 1;
    for j in 0..N_STATE {
        let y = eval
            .add_intermediate(state[j].clone() + E::F::from(base(EXTERNAL_ROUND_CONSTS[round][j])));
        let (out, at_prev) = sbox(eval, y, last_round);
        state[j] = out;
        if let Some(at_prev) = at_prev {
            prev[j] = at_prev;
        }
    }
    apply_external_round_matrix(state);
}

impl FrameworkEval for P2Eval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + LOG_CONSTRAINT_EXPANSION
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        self.body(&mut eval);
        eval.finalize_logup_in_pairs();
        eval
    }
}

impl Body for P2Eval {
    fn body<E: EvalAtRow>(&self, eval: &mut E) {
        let pre: [E::F; 33] = from_fn(|i| {
            eval.get_preprocessed_column(PreProcessedColumnId {
                id: PREPROCESSED[i].to_string(),
            })
        });
        // A selector mode's column; the tagged row has none.
        let selector = |mode: P2Mode| {
            debug_assert!(mode != P2Mode::Tagged, "the tagged row has no selector");
            pre[pre::SELECTORS + mode as usize].clone()
        };
        let act: [E::F; 8] = from_fn(|j| pre[pre::ACT + j].clone());
        let c: [E::F; 10] = from_fn(|j| pre[pre::C + j].clone());

        // The permutation, in `vos_pvm_poseidon2::permute_with`'s order.
        let input: [E::F; N_STATE] = from_fn(|_| eval.next_trace_mask());
        let mut state = input.clone();
        let mut prev_sboxes: [E::F; N_STATE] = from_fn(|_| E::F::zero());
        apply_external_round_matrix(&mut state);
        for round in 0..N_HALF_FULL_ROUNDS {
            full_round(eval, &mut state, round, &mut prev_sboxes);
        }
        for &constant in &INTERNAL_ROUND_CONSTS {
            let y = eval.add_intermediate(state[0].clone() + E::F::from(base(constant)));
            state[0] = sbox(eval, y, false).0;
            apply_internal_round_matrix::<_, BaseField>(&mut state);
            for word in state.iter_mut() {
                *word = eval.add_intermediate(word.clone());
            }
        }
        for round in N_HALF_FULL_ROUNDS..FULL_ROUNDS {
            full_round(eval, &mut state, round, &mut prev_sboxes);
        }
        let output = state;
        // The previous row's output: the same external matrix over its last
        // round's S-boxes.
        apply_external_round_matrix(&mut prev_sboxes);
        let prev: [E::F; N_STATE] = prev_sboxes.map(|word| eval.add_intermediate(word));

        let m: [E::F; 8] = from_fn(|_| eval.next_trace_mask());
        let b = eval.next_trace_mask();

        for j in 0..8 {
            let h = act[j].clone() * m[j].clone();
            let a = h.clone() + c[j].clone();
            let low = selector(P2Mode::LeafStart) * a.clone()
                + selector(P2Mode::LeafContinue) * (prev[j].clone() + a.clone())
                + selector(P2Mode::Node)
                    * (prev[j].clone() + b.clone() * (m[j].clone() - prev[j].clone()))
                + selector(P2Mode::ChannelFirst) * prev[j].clone()
                + selector(P2Mode::ChannelContinue) * prev[j].clone()
                + selector(P2Mode::Wired) * a;
            eval.add_constraint(input[j].clone() - low);

            let mut high = selector(P2Mode::LeafContinue) * prev[8 + j].clone()
                + selector(P2Mode::Node)
                    * (m[j].clone() + b.clone() * (prev[j].clone() - m[j].clone()))
                + selector(P2Mode::ChannelStart) * h.clone()
                + selector(P2Mode::ChannelFirst) * h.clone()
                + selector(P2Mode::ChannelContinue) * (prev[8 + j].clone() + h);
            if j < 2 {
                high += selector(P2Mode::Wired) * c[8 + j].clone();
            }
            eval.add_constraint(input[8 + j].clone() - high);
        }

        let address = |i: usize| pre[i].clone();
        let multiplicity = |i: usize| E::EF::from(pre[i].clone());
        let zero = E::F::zero();
        let entries: [(E::EF, [E::F; 5]); 5] = [
            (
                multiplicity(pre::MULT_M[0]),
                [
                    address(pre::ADDR_M[0]),
                    m[0].clone(),
                    m[1].clone(),
                    m[2].clone(),
                    m[3].clone(),
                ],
            ),
            (
                multiplicity(pre::MULT_M[1]),
                [
                    address(pre::ADDR_M[1]),
                    m[4].clone(),
                    m[5].clone(),
                    m[6].clone(),
                    m[7].clone(),
                ],
            ),
            (
                multiplicity(pre::MULT_OUT[0]),
                [
                    address(pre::ADDR_OUT),
                    output[0].clone(),
                    output[1].clone(),
                    output[2].clone(),
                    output[3].clone(),
                ],
            ),
            (
                multiplicity(pre::MULT_OUT[1]),
                [
                    address(pre::ADDR_OUT) + E::F::from(BaseField::one()),
                    output[4].clone(),
                    output[5].clone(),
                    output[6].clone(),
                    output[7].clone(),
                ],
            ),
            (
                E::EF::from(selector(P2Mode::Node)),
                [address(pre::ADDR_BIT), b, zero.clone(), zero.clone(), zero],
            ),
        ];
        for (multiplicity, values) in &entries {
            eval.add_to_relation(RelationEntry::new(
                &self.relation,
                multiplicity.clone(),
                values,
            ));
        }
    }
}

/// The permutation's columns for `input`: the input, then each S-box's `a`
/// and `out` in [`main`]'s order; and the permutation's output.
pub fn permutation_columns(input: [M31; N_STATE], columns: &mut [M31]) -> [M31; N_STATE] {
    debug_assert_eq!(columns.len(), main::M);
    columns[..N_STATE].copy_from_slice(&input);
    let mut at = main::SBOXES;
    let mut sbox = |y: M31| {
        let a = y * y;
        let out = a * a * y;
        columns[at] = a;
        columns[at + 1] = out;
        at += 2;
        out
    };
    let mut state = input;
    apply_external_round_matrix(&mut state);
    fn full_round(state: &mut [M31; N_STATE], round: usize, sbox: &mut dyn FnMut(M31) -> M31) {
        for j in 0..N_STATE {
            state[j] = sbox(state[j] + EXTERNAL_ROUND_CONSTS[round][j]);
        }
        apply_external_round_matrix(state);
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        full_round(&mut state, round, &mut sbox);
    }
    for &constant in &INTERNAL_ROUND_CONSTS {
        state[0] = sbox(state[0] + constant);
        apply_internal_round_matrix::<_, M31>(&mut state);
    }
    for round in N_HALF_FULL_ROUNDS..FULL_ROUNDS {
        full_round(&mut state, round, &mut sbox);
    }
    debug_assert_eq!(at, main::M);
    state
}

/// The words a chained row reads from its predecessor: the external matrix
/// over the last round's S-box outputs, read from `columns`.
pub fn output_of_columns(columns: &[M31]) -> [M31; N_STATE] {
    let mut state: [M31; N_STATE] =
        from_fn(|j| columns[main::SBOXES + 2 * (LAST_ROUND_SBOXES + j) + 1]);
    apply_external_round_matrix(&mut state);
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The columns' output is the reference permutation's, and the output a
    /// successor reads from the columns is the same.
    #[test]
    fn the_columns_compute_the_reference_permutation() {
        let input: [M31; N_STATE] = from_fn(|i| M31::new(i as u32 * 104_729 + 7));
        let mut columns = [M31::ZERO; main::M];
        let output = permutation_columns(input, &mut columns);
        let mut expected = input;
        vos_pvm_poseidon2::permute(&mut expected);
        assert_eq!(output, expected);
        assert_eq!(output_of_columns(&columns), expected);
    }
}
