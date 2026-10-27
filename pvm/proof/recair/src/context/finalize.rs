//! Finalizing a circuit: its constants fixed, its pending guesses yielded,
//! its components padded, its multiplicities counted and its wiring checked.
//!
//! Adapted from starkware-libs/proving, crates/circuits/src/context.rs,
//! crates/circuits/src/finalize_constants.rs and
//! crates/circuit_common/src/finalize.rs, at 916aefb5 (Apache-2.0),
//! modified: M31 coefficients that make an M31 constant one row, a guess
//! yielded by an identity row, padding rows that touch no wire, the
//! multiplicities counted per address, and the static wiring check.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::{
    Context, Finalized, H8Gate, H8Values, P2Gate, P2Values, Qm31Gate, Role, Slot, State, Var,
    Witness,
};
use crate::circuit::{
    Circuit, Entry, H8Wiring, MIN_ROWS, P2Wiring, Qm31Op, Qm31Wiring, WiringError,
};
use crate::value::Value;

impl<V: Value> Context<V> {
    /// Fixes the constants, yields the guesses no operand yielded, pads each
    /// component to the next power of two (at least [`MIN_ROWS`]), and checks
    /// the wiring.
    pub fn finalize(self) -> Result<Finalized<V>, WiringError> {
        self.finalize_to(None)
    }

    /// [`Context::finalize`], padding to `sizes` (`p2`, `qm31`, `h8`) rows.
    pub fn finalize_to(mut self, sizes: Option<[usize; 3]>) -> Result<Finalized<V>, WiringError> {
        self.close();
        let rows = self.rows();
        let sizes = sizes.unwrap_or(rows.map(|rows| rows.next_power_of_two().max(MIN_ROWS)));
        Self::check_sizes(&["p2", "qm31", "h8"], &rows, &sizes)?;
        self.pad(sizes);
        let finalized = self.wire();
        finalized.circuit.check_wiring()?;
        Ok(finalized)
    }

    /// [`Context::finalize`] for a circuit of `p2` and `qm31` alone (the
    /// credential AIR's set), padded to `sizes` rows: it has no `h8` row,
    /// and `h8`'s padding, whose inputs use the zero wire, is not added.
    pub fn finalize_without_h8(mut self, sizes: [usize; 2]) -> Result<Finalized<V>, WiringError> {
        self.close();
        let [p2, qm31, h8] = self.rows();
        if h8 != 0 {
            return Err(WiringError::Size {
                component: "h8",
                rows: h8,
            });
        }
        Self::check_sizes(&["p2", "qm31"], &[p2, qm31], &sizes)?;
        self.pad([sizes[0], sizes[1], 0]);
        let finalized = self.wire();
        finalized.circuit.check_wiring_without_h8()?;
        Ok(finalized)
    }

    /// The constants fixed and the pending guesses yielded: the rows a
    /// circuit has before its padding.
    fn close(&mut self) {
        assert!(self.outputs_set, "the outputs are set before finalizing");
        self.piece("finalize");
        self.fix_constants();
        self.yield_guesses();
    }

    /// Each component's `rows` within its size, a power of two of at least
    /// [`MIN_ROWS`].
    fn check_sizes(
        components: &[&'static str],
        rows: &[usize],
        sizes: &[usize],
    ) -> Result<(), WiringError> {
        for ((&component, &rows), &size) in components.iter().zip(rows).zip(sizes) {
            if rows > size || size < MIN_ROWS || !size.is_power_of_two() {
                return Err(WiringError::Size {
                    component,
                    rows: size,
                });
            }
        }
        Ok(())
    }

    /// The rows the circuit has once finalized, before its padding: its
    /// constants fixed and its pending guesses yielded.
    pub fn finalized_rows(&self) -> [usize; 3] {
        let mut context = self.clone();
        context.fix_constants();
        context.yield_guesses();
        context.rows()
    }

    /// The uses of each address: operands, `h8` inputs, node bits and the
    /// public terms.
    fn uses(&self) -> Vec<i64> {
        let mut uses = vec![0i64; self.values.len()];
        let mut count = |slot: &Slot| {
            if slot.role == Role::Use {
                uses[slot.address as usize] += 1;
            }
        };
        for gate in &self.p2 {
            gate.m.iter().chain(&gate.out).for_each(&mut count);
        }
        for gate in &self.qm31 {
            gate.slots.iter().for_each(&mut count);
        }
        for gate in &self.h8 {
            count(&gate.out);
        }
        for gate in &self.h8 {
            for &address in &gate.inputs {
                uses[address as usize] += 1;
            }
        }
        for gate in &self.p2 {
            if let Some(address) = gate.bit {
                uses[address as usize] += 1;
            }
        }
        uses[self.layout.u() as usize] += 1;
        for i in 0..self.layout.n_outputs {
            uses[self.layout.output(i) as usize] += 1;
        }
        uses
    }

    /// Fixes every constant some operand reads, by gates from `one`, `u` and
    /// the basis `i = u² − 2`, `iu`.
    fn fix_constants(&mut self) {
        let uses = self.uses();
        let needed: Vec<(SecureField, Var)> = self
            .constants
            .iter()
            .copied()
            .filter(|&(_, var)| uses[var.0 as usize] > 0)
            .collect();
        let extension = needed
            .iter()
            .any(|(value, _)| value.to_m31_array()[1..] != [BaseField::zero(); 3]);
        let (one, u) = (self.one(), self.u());
        let mut basis = None;
        if extension {
            let two = BaseField::from(2);
            let i = self.constant(SecureField::from_m31_array(
                [0, 1, 0, 0].map(BaseField::from),
            ));
            self.fix(
                Qm31Op {
                    k_m: BaseField::one(),
                    k_c: -two,
                    ..Default::default()
                },
                [Some(u), Some(u), Some(one)],
                i,
            );
            let iu = self.constant(SecureField::from_m31_array(
                [0, 0, 0, 1].map(BaseField::from),
            ));
            self.fix(
                Qm31Op {
                    k_m: BaseField::one(),
                    ..Default::default()
                },
                [Some(i), Some(u), None],
                iu,
            );
            basis = Some((i, iu));
        }
        for (value, var) in needed {
            if self.states[var.0 as usize] != State::Constant {
                continue;
            }
            let [x0, x1, x2, x3] = value.to_m31_array();
            if [x1, x2, x3] == [BaseField::zero(); 3] {
                self.fix(
                    Qm31Op {
                        k_a: x0,
                        ..Default::default()
                    },
                    [Some(one), None, None],
                    var,
                );
                continue;
            }
            let (i, iu) = basis.expect("the basis is built for an extension constant");
            let some_if =
                |coefficient: BaseField, var: Var| (!coefficient.is_zero()).then_some(var);
            let low = Qm31Op {
                k_a: x0,
                k_b: x1,
                k_c: x2,
                ..Default::default()
            };
            let operands = [some_if(x0, one), some_if(x1, i), some_if(x2, u)];
            if x3.is_zero() {
                self.fix(low, operands, var);
            } else {
                let partial = SecureField::from_m31_array([x0, x1, x2, BaseField::zero()]);
                let partial = self.new_var(V::from_qm31(partial), State::Constant);
                self.fix(low, operands, partial);
                self.fix(
                    Qm31Op {
                        k_a: BaseField::one(),
                        k_b: x3,
                        ..Default::default()
                    },
                    [Some(partial), Some(iu), None],
                    var,
                );
            }
        }
    }

    /// The gate that fixes the constant `var`, yielding it.
    fn fix(&mut self, op: Qm31Op, operands: [Option<Var>; 3], var: Var) {
        if self.states[var.0 as usize] != State::Constant {
            return;
        }
        self.states[var.0 as usize] = State::Guess;
        self.qm31_gate(op, operands, Some(var));
        debug_assert_eq!(self.states[var.0 as usize], State::Yielded);
    }

    /// Yields, by an identity row each, the guesses an operand uses but none
    /// yielded.
    fn yield_guesses(&mut self) {
        let pending: Vec<Var> = self
            .uses()
            .into_iter()
            .zip(&self.states)
            .enumerate()
            .filter(|&(_, (uses, &state))| state == State::Guess && uses > 0)
            .map(|(address, _)| Var(address as u32))
            .collect();
        for var in pending {
            self.assert_eq(var, var);
        }
    }

    fn pad(&mut self, sizes: [usize; 3]) {
        let zero = V::from_qm31(SecureField::zero());
        let padding = P2Gate {
            mode: None,
            prev: None,
            next: None,
            act: [BaseField::zero(); 8],
            c: [BaseField::zero(); 10],
            m: [Slot::FREE; 2],
            out: [Slot::FREE; 2],
            bit: None,
            input: [zero; 4],
            m_values: [zero; 2],
            b: zero,
        };
        self.p2.resize(sizes[0], padding);
        self.qm31.resize(
            sizes[1],
            Qm31Gate {
                op: Qm31Op::default(),
                slots: [Slot::FREE; 4],
                values: [zero; 4],
            },
        );
        self.h8.resize(
            sizes[2],
            H8Gate {
                inputs: [self.layout.zero; 5],
                out: Slot::FREE,
                values: H8Values {
                    acc: zero,
                    step: zero,
                    mu: zero,
                    v: [zero; 2],
                    out: zero,
                },
            },
        );
    }

    /// The `p2` gates in row order: chain by chain, each from its head, the
    /// chains in the order they were started.
    fn p2_row_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.p2.len());
        for head in (0..self.p2.len()).filter(|&gate| self.p2[gate].prev.is_none()) {
            let mut gate = Some(head);
            while let Some(index) = gate {
                order.push(index);
                gate = self.p2[index].next;
            }
        }
        debug_assert_eq!(order.len(), self.p2.len());
        order
    }

    /// The wiring and the witness, with each yield's multiplicity the count
    /// of its address's uses.
    fn wire(self) -> Finalized<V> {
        let uses = self.uses();
        let entry = |slot: &Slot| Entry {
            address: slot.address,
            multiplicity: match slot.role {
                Role::Use => 1,
                Role::Yield => -uses[slot.address as usize],
                Role::Free => 0,
            },
        };
        let order = self.p2_row_order();
        let p2 = order
            .iter()
            .map(|&index| {
                let gate = &self.p2[index];
                let out = gate.out.map(|slot| entry(&slot));
                P2Wiring {
                    mode: gate.mode,
                    act: gate.act,
                    c: gate.c,
                    m: gate.m.map(|slot| entry(&slot)),
                    out_address: if out[0].multiplicity != 0 || out[1].multiplicity != 0 {
                        gate.out[0].address
                    } else {
                        0
                    },
                    out_multiplicity: out.map(|entry| entry.multiplicity),
                    bit_address: gate.bit.unwrap_or(0),
                }
            })
            .collect();
        let p2_values = order
            .iter()
            .map(|&index| {
                let gate = &self.p2[index];
                P2Values {
                    input: gate.input,
                    m: gate.m_values,
                    b: gate.b,
                }
            })
            .collect();
        let qm31 = self
            .qm31
            .iter()
            .map(|gate| Qm31Wiring {
                op: gate.op,
                operands: gate.slots.map(|slot| entry(&slot)),
            })
            .collect();
        let h8 = self
            .h8
            .iter()
            .map(|gate| H8Wiring {
                inputs: gate.inputs,
                out: entry(&gate.out),
            })
            .collect();
        let outputs = (0..self.layout.n_outputs)
            .map(|i| self.values[self.layout.output(i) as usize])
            .collect();
        Finalized {
            circuit: Circuit {
                p2,
                qm31,
                h8,
                layout: self.layout,
            },
            witness: Witness {
                p2: p2_values,
                qm31: self.qm31.iter().map(|gate| gate.values).collect(),
                h8: self.h8.iter().map(|gate| gate.values).collect(),
                outputs,
            },
        }
    }
}
