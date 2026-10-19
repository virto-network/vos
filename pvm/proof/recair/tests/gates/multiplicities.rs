//! The `Gate` relation's signed multiplicities (`recursion-air.md` §1.1,
//! §11's R12; `vos_pvm_recair_air::gate`): every use carries its address's
//! one yielded value, and a circuit's outputs are the values its proof
//! states.
//!
//! On a small circuit, `y = x·x`, `z = y + x`, its outputs `y` and `z`:
//! - **a use carrying another value** than its yield, on the honest wiring:
//!   the relation does not balance; with the claimed sums forged to make the
//!   public check balance, the interaction trace refuses them;
//! - **a public use added or dropped:** an output stated that the circuit
//!   does not yield, or one it yields left unstated;
//! - **a yield consumed once more than it counts:** a wiring the static
//!   check refuses, proved by a prover that skips it, is another circuit's;
//!   pinned by its own hash, the relation still does not balance, whatever
//!   the values;
//! - **a negative multiplicity,** a use turned into a yield: the
//!   multiplicities are preprocessed, so a forger's only form of it is a
//!   wiring with a second yield, balanced in the relation with two values at
//!   one address. The static check refuses it and no pinned hash is of an
//!   unchecked wiring, so the verifier refuses it as another circuit; the
//!   relation alone would not, which is why the check is static and the
//!   circuit hash pins it.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair::circuit::{Circuit, Entry, WiringError};
use vos_pvm_recair::{Context, Finalized, ProveError, Var, circuit_commitment, prove};
use vos_pvm_recair_air::gate::{Layout, public_logup_sum};

use crate::common::Rng;
use crate::forge::{
    ANOTHER_CIRCUIT, DEEP_ALI, Forgery, LOGUP, assert_accepted, assert_refused, hash_of, own_hash,
};

/// `y = x·x`, `z = y + x`; outputs `y` and `z`. With `x`'s address.
fn small() -> (Finalized<SecureField>, Var) {
    let mut rng = Rng::new(53);
    let mut context = Context::<SecureField>::with_outputs(2);
    let x = context.guess(rng.qm31());
    let y = context.mul(x, x);
    let z = context.add(y, x);
    context.set_outputs(&[y, z]);
    (context.finalize().expect("the wiring checks"), x)
}

/// The `qm31` row whose operands are at `addresses` (`None` for a free
/// one), `a`, `b` and `c`.
fn row_of(circuit: &Circuit, addresses: [Option<u32>; 3]) -> usize {
    circuit
        .qm31
        .iter()
        .position(|wiring| {
            wiring.operands[..3]
                .iter()
                .zip(addresses)
                .all(|(entry, address)| match address {
                    Some(address) => entry.multiplicity != 0 && entry.address == address,
                    None => entry.multiplicity == 0,
                })
        })
        .expect("the row")
}

/// The addition `z = y + x`'s row.
fn addition(finalized: &Finalized<SecureField>, x: Var) -> usize {
    let circuit = &finalized.circuit;
    let mul = row_of(circuit, [Some(x.address()), Some(x.address()), None]);
    let y = circuit.qm31[mul].operands[3].address;
    row_of(circuit, [Some(y), Some(x.address()), None])
}

/// The sum the verifier checks: the claimed sums and the public terms
/// at `layout`'s addresses.
fn total(
    relation: &vos_pvm_recair_air::GateRelation,
    layout: Layout,
    outputs: &[SecureField],
    sums: &[SecureField; 3],
) -> SecureField {
    sums.iter().copied().sum::<SecureField>()
        + public_logup_sum(relation, layout.public_terms(outputs.iter().copied()))
}

/// The addition's `b` (and `c`, when `on_c`) set to `x_value`, its output
/// `y + x_value`, carried to the outputs; its `b` and `c`, and the operands
/// `forged` besides, left as set. The forged sum.
fn add_another_x(
    forgery: &mut Forgery,
    row: usize,
    x_value: SecureField,
    on_c: bool,
    forged: &[(usize, usize)],
) -> SecureField {
    forgery.set_qm31(row, 1, x_value);
    if on_c {
        forgery.set_qm31(row, 2, x_value);
    }
    let z = forgery.qm31(row, 0) + x_value;
    forgery.set_qm31(row, 3, z);
    let mut frozen = vec![(row, 1), (row, 2)];
    frozen.extend_from_slice(forged);
    forgery.settle_except(&frozen);
    z
}

/// A forger's value other than `x`'s.
fn other_value() -> SecureField {
    SecureField::from_m31_array([7, 11, 13, 17].map(BaseField::from))
}

/// The addition's use of `x` carries another value, and the sum and the
/// output follow it, every gate holding: the relation does not balance.
/// With a claimed sum moved so that the public check balances, the
/// interaction trace's last row refuses it.
#[test]
fn a_use_carrying_another_value_is_refused() {
    let (finalized, x) = small();
    let hash = hash_of(&finalized.circuit);
    assert_accepted(
        Forgery::honest(&finalized).prove(),
        &hash,
        "the honest trace",
    );
    let row = addition(&finalized, x);
    let mut forgery = Forgery::honest(&finalized);
    let z = add_another_x(&mut forgery, row, other_value(), false, &[]);
    assert_eq!(forgery.outputs[1], z, "the forged sum is stated");
    assert_refused(
        forgery.prove(),
        &hash,
        LOGUP,
        "a use carrying another value",
    );

    let layout = forgery.circuit.layout;
    let proof = forgery.prove_with_sums(|relation, outputs, sums| {
        let off = total(relation, layout, outputs, sums);
        sums[1] -= off;
        assert!(total(relation, layout, outputs, sums).is_zero());
    });
    assert_refused(proof, &hash, DEEP_ALI, "the same, its claimed sum balanced");
}

/// An output stated that the circuit does not yield, and one it yields
/// left unstated: the public terms do not balance the relation.
#[test]
fn a_public_use_added_or_dropped_is_refused() {
    let (finalized, _) = small();
    let hash = hash_of(&finalized.circuit);
    let mut added = Forgery::honest(&finalized);
    added.outputs.push(SecureField::one());
    assert_refused(added.prove(), &hash, LOGUP, "an output added");
    // The added output's value the wire's at its address, a third output's.
    let mut added = Forgery::honest(&finalized);
    let next = Layout::node(3).output(2);
    let value = added.yields()[&next];
    added.outputs.push(value);
    assert_refused(
        added.prove(),
        &hash,
        LOGUP,
        "an output added, the wire's value",
    );
    let mut dropped = Forgery::honest(&finalized);
    dropped.outputs.pop();
    assert_refused(dropped.prove(), &hash, LOGUP, "an output dropped");
}

/// One more use of `x` than its yield counts, on the addition's free `c`
/// operand (no coefficient reads it): the static check refuses the wiring,
/// so it is neither committed nor proved. A prover that skips the check
/// proves it; the verifier refuses it as another circuit, and, pinned by
/// its own hash, by the relation, whether the use carries `x`'s value or
/// another.
#[test]
fn a_yield_consumed_once_more_is_refused() {
    let (finalized, x) = small();
    let hash = hash_of(&finalized.circuit);
    let row = addition(&finalized, x);
    let mut forged = finalized.clone();
    forged.circuit.qm31[row].operands[2] = Entry {
        address: x.address(),
        multiplicity: 1,
    };
    assert_eq!(
        forged.circuit.check_wiring(),
        Err(WiringError::Unbalanced {
            address: x.address(),
            total: 1
        })
    );
    assert!(
        circuit_commitment(&forged.circuit).is_err(),
        "not committed"
    );
    assert!(
        matches!(
            prove(&forged.circuit, &forged.witness),
            Err(ProveError::Wiring(_))
        ),
        "not proved"
    );
    for value in [finalized.witness.qm31[row][1], other_value()] {
        let mut forgery = Forgery::honest(&forged);
        forgery.set_qm31(row, 2, value);
        let proof = forgery.prove();
        assert_refused(
            proof.clone(),
            &hash,
            ANOTHER_CIRCUIT,
            "a third use of a yield of two",
        );
        let own = own_hash(&proof);
        assert_refused(proof, &own, LOGUP, "the same, pinned by its own hash");
    }
}

/// A second yield of `x`, balanced: the addition's use becomes a yield of
/// another value, which a use on its free `c` operand consumes, and the
/// first yield counts one use fewer. The static check refuses it, so no
/// hash of it is pinned, and the verifier refuses it as another circuit.
/// The relation alone balances it, two values at one address: the static
/// check, and the circuit hash pinning only checked wirings, are what
/// refuse it.
#[test]
fn a_second_yield_is_refused_by_the_pin() {
    let (finalized, x) = small();
    let hash = hash_of(&finalized.circuit);
    let row = addition(&finalized, x);
    let circuit = &finalized.circuit;
    let mul = row_of(circuit, [Some(x.address()), Some(x.address()), None]);
    let mut forged = finalized.clone();
    let wiring = &mut forged.circuit.qm31;
    assert_eq!(
        wiring[mul].operands[0].multiplicity, -2,
        "x's yield, two uses"
    );
    wiring[mul].operands[0].multiplicity = -1;
    wiring[row].operands[1].multiplicity = -1;
    wiring[row].operands[2] = Entry {
        address: x.address(),
        multiplicity: 1,
    };
    assert_eq!(
        forged.circuit.check_wiring(),
        Err(WiringError::YieldedTwice {
            address: x.address()
        })
    );
    assert!(
        circuit_commitment(&forged.circuit).is_err(),
        "not committed"
    );

    let mut forgery = Forgery::honest(&forged);
    let z = add_another_x(&mut forgery, row, other_value(), true, &[(mul, 1)]);
    assert_eq!(forgery.outputs[1], z, "y plus another x is stated");
    let proof = forgery.prove();
    assert_refused(proof.clone(), &hash, ANOTHER_CIRCUIT, "a second yield");
    let own = own_hash(&proof);
    assert_accepted(proof, &own, "the relation alone balances a second yield");
}
