//! The gate VM: random circuits prove and verify, their wiring is the same
//! built with or without values, and the static check refuses what the
//! `Gate` relation's soundness forbids.

use crate::common;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair::circuit::{Entry, WiringError, signed};
use vos_pvm_recair::{Context, NoValue, P2Mode, ProveError, circuit_commitment, prove, verify};

use common::random_circuit;

/// Random circuits over every gate and mode prove and verify; each verifies
/// against its own hash only.
#[test]
fn random_circuits_prove_and_verify() {
    let mut hashes = Vec::new();
    for seed in 0..6 {
        let finalized = random_circuit::<SecureField>(seed, 300 + 150 * seed as usize)
            .finalize()
            .expect("the wiring checks");
        let modes: std::collections::HashSet<_> = finalized
            .circuit
            .p2
            .iter()
            .filter_map(|row| row.mode)
            .collect();
        assert!(seed < 2 || modes.len() >= 5, "seed {seed}: modes {modes:?}");
        let (_, hash) = circuit_commitment(&finalized.circuit).expect("the wiring checks");
        let proof = prove(&finalized.circuit, &finalized.witness).expect("proves");
        if let Some(other) = hashes.last() {
            assert!(
                verify(proof.clone(), other).is_err(),
                "seed {seed}: another circuit's hash"
            );
        }
        verify(proof, &hash).unwrap_or_else(|error| panic!("seed {seed}: {error}"));
        hashes.push(hash);
    }
}

/// One code path builds the wiring and the witness: without values it is
/// the same wiring.
#[test]
fn the_wiring_alone_is_the_filled_wiring() {
    for seed in 0..8 {
        let filled = random_circuit::<SecureField>(seed, 400).finalize().unwrap();
        let alone = random_circuit::<NoValue>(seed, 400).finalize().unwrap();
        assert_eq!(filled.circuit, alone.circuit, "seed {seed}");
    }
}

fn honest() -> vos_pvm_recair::Circuit {
    random_circuit::<NoValue>(3, 500)
        .finalize()
        .unwrap()
        .circuit
}

/// The entry of `circuit`'s `qm31` rows that is a use of an address yielded
/// with at least `uses` uses: its row, operand and address.
fn a_use(circuit: &vos_pvm_recair::Circuit, uses: i64) -> (usize, usize, u32) {
    let yielded: std::collections::HashMap<u32, i64> = circuit
        .entries()
        .filter(|entry| entry.multiplicity < 0)
        .map(|entry| (entry.address, -entry.multiplicity))
        .collect();
    circuit
        .qm31
        .iter()
        .enumerate()
        .find_map(|(row, wiring)| {
            wiring.operands.iter().enumerate().find_map(|(i, entry)| {
                (entry.multiplicity == 1 && yielded.get(&entry.address).is_some_and(|&k| k >= uses))
                    .then_some((row, i, entry.address))
            })
        })
        .expect("a use")
}

/// Each used address is yielded exactly once: a second yield, a yield
/// removed, and a yield that miscounts its uses are each refused; so is a
/// multiplicity total of `p` or more, and a chained first row.
#[test]
fn each_address_is_yielded_exactly_once() {
    let circuit = honest();
    let stats = circuit
        .check_wiring()
        .expect("an honest circuit's wiring checks");
    assert!(stats.addresses > 100 && stats.total_multiplicity > 0);

    // A use turned into a second yield: the uses split between two yields,
    // which could carry two values.
    let (row, operand, address) = a_use(&circuit, 3);
    let mut twice = circuit.clone();
    twice.qm31[row].operands[operand].multiplicity = -1;
    assert_eq!(
        twice.check_wiring(),
        Err(WiringError::YieldedTwice { address })
    );
    // ... even when the yields count the uses between them.
    let yield_entry = twice
        .qm31
        .iter_mut()
        .flat_map(|wiring| wiring.operands.iter_mut())
        .chain(twice.h8.iter_mut().map(|wiring| &mut wiring.out))
        .find(|entry| entry.address == address && entry.multiplicity < -1);
    if let Some(entry) = yield_entry {
        entry.multiplicity += 2;
        assert_eq!(
            twice.check_wiring(),
            Err(WiringError::YieldedTwice { address })
        );
    }

    // The yield removed.
    let mut unyielded = circuit.clone();
    for entry in unyielded
        .qm31
        .iter_mut()
        .flat_map(|wiring| wiring.operands.iter_mut())
        .chain(unyielded.h8.iter_mut().map(|wiring| &mut wiring.out))
        .chain(
            unyielded
                .p2
                .iter_mut()
                .flat_map(|wiring| wiring.m.iter_mut()),
        )
        .filter(|entry| entry.address == address && entry.multiplicity < 0)
    {
        *entry = Entry::FREE;
    }
    for wiring in unyielded.p2.iter_mut() {
        for w in 0..2 {
            if wiring.out_address + w as u32 == address && wiring.out_multiplicity[w] < 0 {
                wiring.out_multiplicity[w] = 0;
            }
        }
    }
    assert_eq!(
        unyielded.check_wiring(),
        Err(WiringError::NotYielded { address })
    );

    // A use dropped: the yield counts one use too many.
    let mut miscounted = circuit.clone();
    miscounted.qm31[row].operands[operand] = Entry::FREE;
    assert_eq!(
        miscounted.check_wiring(),
        Err(WiringError::Unbalanced { address, total: -1 })
    );

    // Multiplicities whose absolute values reach p.
    let mut heavy = circuit.clone();
    let half = i64::from(P / 2) + 1;
    heavy.qm31[row].operands[operand].multiplicity = half;
    for entry in heavy
        .qm31
        .iter_mut()
        .flat_map(|wiring| wiring.operands.iter_mut())
        .chain(heavy.h8.iter_mut().map(|wiring| &mut wiring.out))
        .filter(|entry| entry.address == address && entry.multiplicity < 0)
    {
        entry.multiplicity -= half - 1;
    }
    for wiring in heavy.p2.iter_mut() {
        for w in 0..2 {
            if wiring.out_address + w as u32 == address && wiring.out_multiplicity[w] < 0 {
                wiring.out_multiplicity[w] -= half - 1;
            }
        }
    }
    assert!(matches!(
        heavy.check_wiring(),
        Err(WiringError::TotalMultiplicity(_))
    ));

    // A chained row first, whose predecessor would be the last row.
    let mut chained = circuit.clone();
    chained.p2[0].mode = Some(P2Mode::LeafContinue);
    assert_eq!(chained.check_wiring(), Err(WiringError::ChainedFirstRow));
}

/// A circuit whose operands read a wire nothing yields is refused when the
/// context finalizes it.
#[test]
fn the_context_runs_the_check() {
    let mut context = Context::<SecureField>::new();
    let a = context.guess(SecureField::from_u32_unchecked(1, 2, 3, 4));
    let b = context.mul(a, a);
    context.h8(a, b, a, [b, b]);
    let finalized = context
        .finalize()
        .expect("guesses read only by h8 are yielded");
    finalized.circuit.check_wiring().unwrap();
    // Every component is padded to a power of two of at least 16 rows.
    assert_eq!(finalized.circuit.log_sizes(), [4, 4, 4]);
    // A padding p2 row holds the permutation of zero.
    let last = finalized.witness.p2.last().unwrap();
    assert_eq!(last.input, [SecureField::from(0); 4]);
    assert!(finalized.circuit.p2.last().unwrap().mode.is_none());
}

/// No path commits a circuit whose wiring fails the check: its commitment
/// and its proof are refused.
#[test]
fn an_unchecked_circuit_is_neither_committed_nor_proved() {
    let finalized = random_circuit::<SecureField>(3, 300).finalize().unwrap();
    let mut circuit = finalized.circuit.clone();
    let (row, operand, address) = a_use(&circuit, 2);
    circuit.qm31[row].operands[operand] = Entry::FREE;
    let refusal = WiringError::Unbalanced { address, total: -1 };
    assert_eq!(circuit_commitment(&circuit).err(), Some(refusal.clone()));
    match prove(&circuit, &finalized.witness) {
        Err(ProveError::Wiring(error)) => assert_eq!(error, refusal),
        other => panic!("proved an unchecked circuit: {:?}", other.map(|_| ())),
    }
}

/// A multiplicity's magnitude below `p` is a field element; at `p` it is
/// refused.
#[test]
fn a_multiplicity_is_below_p() {
    let below = i64::from(P) - 1;
    assert_eq!(signed(below), -signed(-below));
    for multiplicity in [i64::from(P), -i64::from(P), i64::from(u32::MAX)] {
        assert!(
            std::panic::catch_unwind(|| signed(multiplicity)).is_err(),
            "{multiplicity}"
        );
    }
}

/// The static check refuses a read of a value that is no wire: a `qm31`
/// row's free operand under a coefficient or a lane, and a free message
/// absorbed by a `p2` row other than a node. A node's free message, a
/// Merkle sibling, is admitted.
#[test]
fn a_read_of_no_wire_is_refused() {
    let circuit = honest();
    let free = |entry: &Entry| entry.multiplicity == 0 && entry.address == 0;
    let (row, operand) = circuit
        .qm31
        .iter()
        .enumerate()
        .find_map(|(row, wiring)| {
            (0..3)
                .find(|&i| free(&wiring.operands[i]))
                .map(|i| (row, i))
        })
        .expect("a row with a free operand");
    let mut read = circuit.clone();
    match operand {
        0 => read.qm31[row].op.k_a = BaseField::from(1),
        1 => read.qm31[row].op.k_b = BaseField::from(1),
        _ => read.qm31[row].op.k_c = BaseField::from(1),
    }
    assert_eq!(
        read.check_wiring(),
        Err(WiringError::FreeOperandRead { row, operand })
    );
    let row = circuit
        .qm31
        .iter()
        .position(|wiring| free(&wiring.operands[2]))
        .expect("a row with a free c");
    let mut lane = circuit.clone();
    lane.qm31[row].op.lanes[1] = BaseField::from(1);
    assert_eq!(
        lane.check_wiring(),
        Err(WiringError::FreeOperandRead { row, operand: 2 })
    );

    assert!(
        circuit
            .p2
            .iter()
            .any(|wiring| wiring.mode == Some(P2Mode::Node)
                && (free(&wiring.m[0]) || free(&wiring.m[1]))),
        "a node with a free sibling, admitted"
    );
    let (row, lane) = circuit
        .p2
        .iter()
        .enumerate()
        .find_map(|(row, wiring)| {
            let absorbing = wiring.mode.is_some() && wiring.mode != Some(P2Mode::Node);
            (0..8)
                .find(|&j| absorbing && free(&wiring.m[j / 4]))
                .map(|j| (row, j))
        })
        .expect("a row with a free message");
    let mut absorbed = circuit.clone();
    absorbed.p2[row].act[lane] = BaseField::from(1);
    assert_eq!(
        absorbed.check_wiring(),
        Err(WiringError::FreeMessageAbsorbed { row })
    );
}

/// A read with no multiplicity at an address another entry holds, a free
/// value in a wire's guise, is refused: a `qm31` operand under a
/// coefficient, and a message absorbed outside a node.
#[test]
fn a_disguised_free_read_is_refused() {
    let circuit = honest();
    let held = circuit
        .entries()
        .find(|entry| entry.multiplicity > 0 && entry.address > 2)
        .expect("a used wire")
        .address;
    let row = circuit
        .qm31
        .iter()
        .position(|wiring| wiring.operands[2].multiplicity == 0)
        .expect("a row with a free c");
    let mut read = circuit.clone();
    read.qm31[row].operands[2] = Entry {
        address: held,
        multiplicity: 0,
    };
    read.qm31[row].op.k_c = BaseField::from(1);
    assert_eq!(
        read.check_wiring(),
        Err(WiringError::FreeOperandRead { row, operand: 2 })
    );
    let (row, lane) = circuit
        .p2
        .iter()
        .enumerate()
        .find_map(|(row, wiring)| {
            let absorbing = wiring.mode.is_some() && wiring.mode != Some(P2Mode::Node);
            (0..8)
                .find(|&j| {
                    absorbing
                        && wiring.m[j / 4].multiplicity == 0
                        && wiring.act[j] == BaseField::from(0)
                })
                .map(|j| (row, j))
        })
        .expect("a row with a free message");
    let mut absorbed = circuit.clone();
    absorbed.p2[row].m[lane / 4] = Entry {
        address: held,
        multiplicity: 0,
    };
    absorbed.p2[row].act[lane] = BaseField::from(1);
    assert_eq!(
        absorbed.check_wiring(),
        Err(WiringError::FreeMessageAbsorbed { row })
    );
}
