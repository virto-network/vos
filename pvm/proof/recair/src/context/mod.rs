//! The `Context` that builds circuits (`recursion-air.md` §2).
//!
//! Adapted from starkware-libs/proving, crates/circuits/src/context.rs and
//! crates/circuits/src/ops.rs, at 916aefb5 (Apache-2.0), modified: our gate
//! set, signed multiplicities with a guess yielded by its first consumer, the
//! reserved wires fixed by two rows, and chained Poseidon2 rows.
//!
//! - **Witness values flow through yields.** A gate's computed output is
//!   yielded by that gate. A guessed value ([`Context::guess`]) is yielded by
//!   the first operand that consumes it and can yield (an `h8` input and a
//!   `p2` bit cannot), or, if none can, by an identity row at
//!   [`Context::finalize`]. Every other consumer uses the address.
//! - **Equality is a use:** a gate whose output must equal a wire writes its
//!   output to that wire's address ([`Context::qm31_into`]).
//! - **Constants are fixed by gates** at [`Context::finalize`]: zero by
//!   `x + x = x`, one and `u` by `u·x = u`, an M31 constant by `k·one`, any
//!   other by at most two rows from `one`, `i = u² − 2`, `u` and `iu`. A
//!   constant is never yielded by a consumer.
//! - **Outputs** sit at the reserved addresses from 3, copied there by
//!   [`Context::set_outputs`]; with `u` they are the circuit's public uses.
//! - **`p2` rows chain:** a chained row names its predecessor, which may have
//!   one successor. Rows are laid out chain by chain, each chain contiguous,
//!   in the order the chains were started.
//!
//! [`Context::finalize`] pads every component to its size, computes the
//! multiplicities, and runs the static wiring check
//! ([`Circuit::check_wiring`]).

mod arith;
mod finalize;

use std::collections::HashMap;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_recair_air::gate::{FIRST_OUTPUT_ADDRESS, ONE_ADDRESS, U_ADDRESS, U_VALUE, ZERO_ADDRESS};
use vos_recair_air::p2::P2Mode;

use crate::circuit::{Circuit, Qm31Op};
use crate::value::{Value, embed};

/// A wire, by its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Var(u32);

impl Var {
    pub const fn address(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// A guessed value, not yet yielded.
    Guess,
    /// A constant, yielded only by the gate that fixes it.
    Constant,
    /// An output's address, before its value is set.
    Reserved,
    Yielded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Use,
    Yield,
    Free,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    address: u32,
    role: Role,
}

impl Slot {
    const FREE: Self = Self {
        address: 0,
        role: Role::Free,
    };
}

/// A `p2` row's message wire: a wire of the circuit, or a free value that no
/// other operand reads (a Merkle sibling).
#[derive(Clone, Copy, Debug)]
pub enum Message<V> {
    Wire(Var),
    Free(V),
}

/// A `p2` row as the builder states it.
#[derive(Clone, Copy, Debug)]
pub struct P2Row<'a, V> {
    pub mode: P2Mode,
    /// The predecessor, for a chained mode.
    pub prev: Option<&'a P2Handle<V>>,
    pub m: [Message<V>; 2],
    pub act: [BaseField; 8],
    pub c: [BaseField; 10],
    /// The direction bit, for a node: a use.
    pub bit: Option<Var>,
    /// Wires at consecutive addresses the output must equal; new wires
    /// otherwise.
    pub out: Option<[Var; 2]>,
}

impl<V: Value> P2Row<'_, V> {
    /// A row of `mode` with no message, no constants and new output wires.
    pub fn new(mode: P2Mode) -> Self {
        Self {
            mode,
            prev: None,
            m: [Message::Free(V::from_qm31(SecureField::zero())); 2],
            act: [BaseField::zero(); 8],
            c: [BaseField::zero(); 10],
            bit: None,
            out: None,
        }
    }
}

/// A built `p2` row: its output's first eight words as two wires, and its
/// whole output state, which a chained successor reads.
#[derive(Clone, Copy, Debug)]
pub struct P2Handle<V> {
    gate: usize,
    pub digest: [Var; 2],
    pub state: [V; 4],
}

#[derive(Clone, Debug)]
struct P2Gate<V> {
    mode: Option<P2Mode>,
    prev: Option<usize>,
    next: Option<usize>,
    act: [BaseField; 8],
    c: [BaseField; 10],
    m: [Slot; 2],
    out: [Slot; 2],
    bit: Option<u32>,
    input: [V; 4],
    m_values: [V; 2],
    b: V,
}

#[derive(Clone, Debug)]
struct Qm31Gate<V> {
    op: Qm31Op,
    slots: [Slot; 4],
    values: [V; 4],
}

#[derive(Clone, Debug)]
struct H8Gate<V> {
    inputs: [u32; 5],
    out: Slot,
    values: H8Values<V>,
}

/// A `p2` row's values: its input as four wires, its message and its bit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct P2Values<V> {
    pub input: [V; 4],
    pub m: [V; 2],
    pub b: V,
}

/// An `h8` row's values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct H8Values<V> {
    pub acc: V,
    pub step: V,
    pub mu: V,
    pub v: [V; 2],
    pub out: V,
}

/// A circuit's values, row by row as its wiring lays them out.
#[derive(Clone, Debug, PartialEq)]
pub struct Witness<V> {
    pub p2: Vec<P2Values<V>>,
    /// Each row's `a`, `b`, `c` and `out`.
    pub qm31: Vec<[V; 4]>,
    pub h8: Vec<H8Values<V>>,
    /// The outputs' values, from [`FIRST_OUTPUT_ADDRESS`].
    pub outputs: Vec<V>,
}

/// A finalized circuit: its wiring and its witness.
#[derive(Clone, Debug)]
pub struct Finalized<V> {
    pub circuit: Circuit,
    pub witness: Witness<V>,
}

/// Builds a circuit and, with [`SecureField`] values, its witness.
#[derive(Clone, Debug)]
pub struct Context<V: Value> {
    values: Vec<V>,
    states: Vec<State>,
    p2: Vec<P2Gate<V>>,
    qm31: Vec<Qm31Gate<V>>,
    h8: Vec<H8Gate<V>>,
    /// The constants by value, in the order they were asked for.
    constants: Vec<(SecureField, Var)>,
    constant_vars: HashMap<[u32; 4], Var>,
    n_outputs: u32,
    outputs_set: bool,
}

impl<V: Value> Default for Context<V> {
    fn default() -> Self {
        Self::new()
    }
}

fn key(value: SecureField) -> [u32; 4] {
    value.to_m31_array().map(|limb| limb.0)
}

impl<V: Value> Context<V> {
    /// A context with no outputs.
    pub fn new() -> Self {
        Self::with_outputs(0)
    }

    /// A context whose circuit outputs `n_outputs` wires, at the addresses
    /// from [`FIRST_OUTPUT_ADDRESS`], set by [`Context::set_outputs`].
    pub fn with_outputs(n_outputs: u32) -> Self {
        let mut context = Self {
            values: Vec::new(),
            states: Vec::new(),
            p2: Vec::new(),
            qm31: Vec::new(),
            h8: Vec::new(),
            constants: Vec::new(),
            constant_vars: HashMap::new(),
            n_outputs,
            outputs_set: n_outputs == 0,
        };
        for (address, value) in [
            (ZERO_ADDRESS, SecureField::zero()),
            (ONE_ADDRESS, SecureField::one()),
            (U_ADDRESS, U_VALUE),
        ] {
            let var = context.new_var(V::from_qm31(value), State::Yielded);
            assert_eq!(var.address(), address);
            context.constant_vars.insert(key(value), var);
        }
        for i in 0..n_outputs {
            let var = context.new_var(V::from_qm31(SecureField::zero()), State::Reserved);
            assert_eq!(var.address(), FIRST_OUTPUT_ADDRESS + i);
        }
        let [zero, one, u] = [context.zero(), context.one(), context.u()];
        let yields = |var: Var| Slot {
            address: var.0,
            role: Role::Yield,
        };
        let uses = |var: Var| Slot {
            address: var.0,
            role: Role::Use,
        };
        // Zero: `x + x = x`.
        context.push_qm31(
            Qm31Op {
                k_a: BaseField::one(),
                k_b: BaseField::one(),
                ..Qm31Op::default()
            },
            [yields(zero), uses(zero), Slot::FREE, uses(zero)],
        );
        // One and u: `u·x = u`. The verifier's public term fixes u.
        context.push_qm31(
            Qm31Op {
                k_m: BaseField::one(),
                ..Qm31Op::default()
            },
            [yields(u), yields(one), Slot::FREE, uses(u)],
        );
        context
    }

    pub fn zero(&self) -> Var {
        Var(ZERO_ADDRESS)
    }

    pub fn one(&self) -> Var {
        Var(ONE_ADDRESS)
    }

    pub fn u(&self) -> Var {
        Var(U_ADDRESS)
    }

    /// A wire's value.
    pub fn value(&self, var: Var) -> V {
        assert_ne!(
            self.states[var.0 as usize],
            State::Reserved,
            "an output is read before it is set"
        );
        self.values[var.0 as usize]
    }

    fn new_var(&mut self, value: V, state: State) -> Var {
        let address = u32::try_from(self.values.len()).expect("addresses fit in u32");
        self.values.push(value);
        self.states.push(state);
        Var(address)
    }

    /// A guessed value: the first operand that consumes it yields it.
    pub fn guess(&mut self, value: V) -> Var {
        self.new_var(value, State::Guess)
    }

    /// Two guessed wires at consecutive addresses: a digest, or eight
    /// values.
    pub fn guess_pair(&mut self, values: [V; 2]) -> [Var; 2] {
        values.map(|value| self.guess(value))
    }

    /// The constant `value`, fixed by a gate at [`Context::finalize`].
    pub fn constant(&mut self, value: SecureField) -> Var {
        if let Some(&var) = self.constant_vars.get(&key(value)) {
            return var;
        }
        let var = self.new_var(V::from_qm31(value), State::Constant);
        self.constant_vars.insert(key(value), var);
        self.constants.push((value, var));
        var
    }

    /// The constant M31 `value`.
    pub fn constant_m31(&mut self, value: u32) -> Var {
        self.constant(embed(BaseField::from(value)))
    }

    /// The operand slot of `var`: its yield, if it is a guess not yet
    /// yielded and the slot can yield; a use otherwise.
    fn slot(&mut self, var: Var, can_yield: bool) -> Slot {
        let state = &mut self.states[var.0 as usize];
        let role = match *state {
            State::Reserved => panic!("an output is read before it is set"),
            State::Guess if can_yield => {
                *state = State::Yielded;
                Role::Yield
            }
            _ => Role::Use,
        };
        Slot {
            address: var.0,
            role,
        }
    }

    /// A gate's output slot for `out`, a new wire if `None`, with the value
    /// the gate computes. An existing wire's value must be the computed one.
    fn out_slot(&mut self, out: Option<Var>, value: V) -> (Var, Slot) {
        match out {
            None => {
                let var = self.new_var(value, State::Yielded);
                (
                    var,
                    Slot {
                        address: var.0,
                        role: Role::Yield,
                    },
                )
            }
            Some(var) => {
                if let (Some(expected), Some(computed)) =
                    (self.values[var.0 as usize].to_qm31(), value.to_qm31())
                {
                    assert_eq!(
                        expected, computed,
                        "a gate's output differs from the wire it must equal"
                    );
                }
                (var, self.slot(var, true))
            }
        }
    }

    fn push_qm31(&mut self, op: Qm31Op, slots: [Slot; 4]) {
        let values = slots.map(|slot| match slot.role {
            Role::Free => V::from_qm31(SecureField::zero()),
            _ => self.values[slot.address as usize],
        });
        self.qm31.push(Qm31Gate { op, slots, values });
    }

    /// The QM31 gate over `a`, `b` and `c` (`None` for an operand no term
    /// reads), its output a new wire.
    pub fn qm31(&mut self, op: Qm31Op, a: Option<Var>, b: Option<Var>, c: Option<Var>) -> Var {
        self.qm31_gate(op, [a, b, c], None)
    }

    /// The QM31 gate, its output the wire `out`: a use of it, or its yield if
    /// it is a guess.
    pub fn qm31_into(
        &mut self,
        op: Qm31Op,
        a: Option<Var>,
        b: Option<Var>,
        c: Option<Var>,
        out: Var,
    ) {
        self.qm31_gate(op, [a, b, c], Some(out));
    }

    fn qm31_gate(&mut self, op: Qm31Op, operands: [Option<Var>; 3], out: Option<Var>) -> Var {
        let zero = BaseField::zero();
        let [a, b, c] = operands;
        assert!(
            a.is_some() || (op.k_m == zero && op.k_p == zero && op.k_a == zero),
            "a term reads the absent operand a"
        );
        assert!(
            b.is_some() || (op.k_m == zero && op.k_p == zero && op.k_b == zero),
            "a term reads the absent operand b"
        );
        assert!(
            c.is_some() || (op.k_c == zero && op.lanes == [zero; 4]),
            "a term reads the absent operand c"
        );
        let value = |var: Option<Var>| match var {
            Some(var) => self.value(var),
            None => V::from_qm31(SecureField::zero()),
        };
        let [va, vb, vc] = [value(a), value(b), value(c)];
        let k = |k: BaseField| V::from_qm31(embed(k));
        let computed = k(op.k_m) * va * vb
            + k(op.k_p) * va.pointwise_mul(vb)
            + k(op.k_a) * va
            + k(op.k_b) * vb
            + k(op.k_c) * vc
            + vc.lane_sum(op.lanes);
        let mut slots = [Slot::FREE; 4];
        for (slot, operand) in slots.iter_mut().zip(operands) {
            if let Some(var) = operand {
                *slot = self.slot(var, true);
            }
        }
        let (var, out_slot) = self.out_slot(out, computed);
        slots[3] = out_slot;
        self.qm31.push(Qm31Gate {
            op,
            slots,
            values: [va, vb, vc, computed],
        });
        var
    }

    /// The DEEP accumulator `acc·μ + Σ_j σ^j·v_j` over the eight limbs of the
    /// wires `v`, its output a new wire.
    pub fn h8(&mut self, acc: Var, step: Var, mu: Var, v: [Var; 2]) -> Var {
        self.h8_gate([acc, step, mu, v[0], v[1]], None)
    }

    /// The DEEP accumulator, its output the wire `out`.
    pub fn h8_into(&mut self, acc: Var, step: Var, mu: Var, v: [Var; 2], out: Var) {
        self.h8_gate([acc, step, mu, v[0], v[1]], Some(out));
    }

    fn h8_gate(&mut self, inputs: [Var; 5], out: Option<Var>) -> Var {
        let [acc, step, mu, v0, v1] = inputs.map(|var| self.value(var));
        // Each input is a use, so none yields: a guess stays pending.
        for var in inputs {
            self.slot(var, false);
        }
        let samples = [v0, v1];
        let mut horner = V::from_qm31(SecureField::zero());
        for j in (0..8).rev() {
            horner = horner * step + samples[j / 4].limb(j % 4);
        }
        let computed = acc * mu + horner;
        let (var, out_slot) = self.out_slot(out, computed);
        self.h8.push(H8Gate {
            inputs: inputs.map(Var::address),
            out: out_slot,
            values: H8Values {
                acc,
                step,
                mu,
                v: samples,
                out: computed,
            },
        });
        var
    }

    /// A `p2` row.
    ///
    /// # Panics
    /// When a chained mode has no predecessor, or its predecessor already has
    /// a successor; when a node has no bit; when `out` is not two consecutive
    /// addresses.
    pub fn p2(&mut self, row: P2Row<'_, V>) -> P2Handle<V> {
        let P2Row {
            mode,
            prev,
            m,
            act,
            c,
            bit,
            out,
        } = row;
        let zero = V::from_qm31(SecureField::zero());
        let prev_state = match (mode.is_chained(), prev) {
            (true, Some(prev)) => {
                assert!(
                    self.p2[prev.gate].next.is_none(),
                    "a p2 row has one chained successor"
                );
                Some(prev.state)
            }
            (true, None) => panic!("a chained p2 row names its predecessor"),
            (false, _) => None,
        };
        let m_values = m.map(|message| match message {
            Message::Wire(var) => self.value(var),
            Message::Free(value) => value,
        });
        let b = match (mode, bit) {
            (P2Mode::Node, Some(bit)) => self.value(bit),
            (P2Mode::Node, None) => panic!("a node row needs its bit"),
            _ => zero,
        };
        let wire = |limbs: &[BaseField]| {
            V::from_qm31(SecureField::from_m31_array(core::array::from_fn(|i| {
                limbs[i]
            })))
        };
        let act_wires = [wire(&act[..4]), wire(&act[4..])];
        let c_wires = [wire(&c[..4]), wire(&c[4..8])];
        let h = [0, 1].map(|w| m_values[w].pointwise_mul(act_wires[w]));
        let a = [0, 1].map(|w| h[w] + c_wires[w]);
        let p = prev_state.unwrap_or([zero; 4]);
        let input = match mode {
            P2Mode::LeafStart => [a[0], a[1], zero, zero],
            P2Mode::LeafContinue => [p[0] + a[0], p[1] + a[1], p[2], p[3]],
            P2Mode::Node => {
                let low = [0, 1].map(|w| p[w] + b * (m_values[w] - p[w]));
                let high = [0, 1].map(|w| m_values[w] + b * (p[w] - m_values[w]));
                [low[0], low[1], high[0], high[1]]
            }
            P2Mode::ChannelStart => [zero, zero, h[0], h[1]],
            P2Mode::ChannelFirst => [p[0], p[1], h[0], h[1]],
            P2Mode::ChannelContinue => [p[0], p[1], p[2] + h[0], p[3] + h[1]],
            P2Mode::Wired => [
                a[0],
                a[1],
                wire(&[c[8], c[9], BaseField::zero(), BaseField::zero()]),
                zero,
            ],
        };
        let state = V::permute(input);

        let m_slots = [0, 1].map(|w| match m[w] {
            Message::Wire(var) => self.slot(var, true),
            Message::Free(_) => Slot::FREE,
        });
        let bit = bit
            .filter(|_| mode == P2Mode::Node)
            .map(|bit| self.slot(bit, false).address);
        let (digest, out_slots) = match out {
            None => {
                let digest = [0, 1].map(|w| self.new_var(state[w], State::Yielded));
                let slots = digest.map(|var| Slot {
                    address: var.0,
                    role: Role::Yield,
                });
                (digest, slots)
            }
            Some(digest) => {
                assert_eq!(
                    digest[1].0,
                    digest[0].0 + 1,
                    "a p2 output's wires are at consecutive addresses"
                );
                let slots = [0, 1].map(|w| self.out_slot(Some(digest[w]), state[w]).1);
                (digest, slots)
            }
        };
        let gate = self.p2.len();
        if let Some(prev) = prev.filter(|_| mode.is_chained()) {
            self.p2[prev.gate].next = Some(gate);
        }
        self.p2.push(P2Gate {
            mode: Some(mode),
            prev: prev.filter(|_| mode.is_chained()).map(|prev| prev.gate),
            next: None,
            act,
            c,
            m: m_slots,
            out: out_slots,
            bit,
            input,
            m_values,
            b,
        });
        P2Handle {
            gate,
            digest,
            state,
        }
    }

    /// Copies `vars` to the reserved output addresses; with `u` they are the
    /// circuit's public uses.
    pub fn set_outputs(&mut self, vars: &[Var]) {
        assert!(!self.outputs_set, "the outputs are set once");
        assert_eq!(vars.len(), self.n_outputs as usize, "one wire an output");
        for (i, &var) in vars.iter().enumerate() {
            let reserved = Var(FIRST_OUTPUT_ADDRESS + i as u32);
            self.values[reserved.0 as usize] = self.value(var);
            self.states[reserved.0 as usize] = State::Guess;
            self.assert_eq(var, reserved);
        }
        self.outputs_set = true;
    }

    /// The rows each component has so far: `p2`, `qm31`, `h8`.
    pub fn rows(&self) -> [usize; 3] {
        [self.p2.len(), self.qm31.len(), self.h8.len()]
    }
}
