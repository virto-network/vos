//! A target's limits: an instance installed for JAM runs within JAM's on
//! every host, as the model does, and an install whose statics pass them is
//! refused.

use vos_testkit::programs::{actor, derivation, derived, method, package};
use vos_testkit::{InstallError, Testkit};
use vos_wire::abi::Failure;
use vos_wire::abi::cap::{JAM, Target, VOS};
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::{InstanceId, MethodId, ProgramHash};
use vos_wire::records::Derivation;
use vos_wire::result::Outcome;
use vos_wire::{Encode, keys};

use crate::common::{AGENT, ALICE, COUNTER, MINTER, Node, Sessions, ran};

/// The hosts a test runs on: a VOS node's, and the JAM-only host serving
/// applied state as a package's witness does.
fn hosts() -> [Node; 2] {
    [Node::new(), Node::jam(true)]
}

/// An install of `derivation` at `instance` for `target`.
fn install(instance: InstanceId, derivation: Derivation, target: Target) -> Input {
    Input::Admin(Admin::Install {
        instance,
        derivation,
        roles: vec![(b"minter".to_vec(), MINTER)],
        target,
    })
}

/// An install of a program with no attestable.
fn bare(instance: InstanceId, program: ProgramHash, target: Target) -> Input {
    install(instance, vos_testkit::programs::bare(program), target)
}

/// A step's effects at the edge of JAM's limits run for both targets, and
/// one past an edge fails `Cap` for JAM alone: on every host, as in the
/// model.
#[test]
fn an_instance_installed_for_jam_runs_within_its_limits() {
    let counter = actor("counter");
    let spam = method(&counter, "spam");
    let fill = method(&counter, "fill");
    // A row of the counter's table: its key's bytes beside the value's.
    let value = JAM.step_writes - 64;
    let calls: [(MethodId, Vec<u8>, bool); 6] = [
        (spam, (JAM.messages as u32).encode(), false),
        (spam, (JAM.messages as u32 + 1).encode(), true),
        (fill, (JAM.step_rows as u32, 8u32).encode(), false),
        (fill, (JAM.step_rows as u32 + 1, 8u32).encode(), true),
        (fill, (1u32, value as u32).encode(), false),
        (fill, (1u32, JAM.step_writes as u32).encode(), true),
    ];
    for target in [Target::Vos, Target::Jam] {
        for mut node in hosts() {
            let program = node.add(&counter);
            ran(&node.batch(0, vec![bare(COUNTER, program, target)]).steps[0]);
            let mut kit = Testkit::new(AGENT);
            kit.install_for(target, COUNTER, &counter, &[], &[])
                .unwrap();
            let mut sessions = Sessions::new();
            let inputs = calls
                .iter()
                .map(|(method, arguments, _)| {
                    sessions.request_bytes(ALICE, COUNTER, *method, arguments.clone())
                })
                .collect();
            let result = node.batch(1, inputs);
            kit.batch(1, [0; 32]);
            for (step, (method, arguments, past)) in result.steps.iter().zip(&calls) {
                let expected = kit.command(ALICE, COUNTER, *method, arguments);
                let run = ran(step);
                assert_eq!(run.outcome, expected.outcome);
                assert_eq!(run.messages, expected.messages);
                let capped = matches!(
                    run.outcome,
                    Outcome::Failed {
                        code: Failure::Cap,
                        ..
                    }
                );
                assert_eq!(capped, *past && target == Target::Jam, "{target:?}");
            }
        }
    }
}

/// An install whose program writes more pages than JAM's limit, or whose
/// attestable method's gas limit pays for more compressions than a JAM
/// kernel may make, is refused for JAM, `Cap`, and installs for VOS: in
/// the agent on every host, as in the model. Its record is not written.
#[test]
fn an_install_past_the_jam_limits_is_refused() {
    let (shop, lean) = (actor("shop"), actor("lean"));
    let ledger = derived("ledger");
    let ledger_kernels: Vec<(MethodId, &[u8])> = ledger
        .kernels
        .iter()
        .map(|(method, kernel)| (MethodId(*method), kernel.as_slice()))
        .collect();
    let instance = InstanceId(9);
    for target in [Target::Vos, Target::Jam] {
        for mut node in hosts() {
            let (shop_hash, lean_hash) = (node.add(&shop), node.add(&lean));
            node.add(&ledger.actor);
            for (_, kernel) in &ledger_kernels {
                node.add(kernel);
            }
            let inputs = vec![
                bare(instance, shop_hash, target),
                install(
                    InstanceId(10),
                    derivation(&package("ledger"), &ledger),
                    target,
                ),
                bare(InstanceId(11), lean_hash, target),
            ];
            let result = node.batch(0, inputs);
            let outcomes: Vec<&Outcome> =
                result.steps.iter().map(|step| &ran(step).outcome).collect();
            let mut kit = Testkit::new(AGENT);
            let model = [
                kit.install_for(target, instance, &shop, &[], &[]),
                kit.install_for(
                    target,
                    InstanceId(10),
                    &ledger.actor,
                    &ledger_kernels,
                    &[("minter", MINTER)],
                ),
                kit.install_for(target, InstanceId(11), &lean, &[], &[]),
            ];
            let refused = target == Target::Jam;
            for (index, (outcome, model)) in outcomes.iter().zip(&model).enumerate() {
                let past = refused && index < 2;
                assert_eq!(
                    matches!(
                        outcome,
                        Outcome::Failed {
                            code: Failure::Cap,
                            ..
                        }
                    ),
                    past,
                    "{target:?} {index}: {outcome:?}"
                );
                assert_eq!(model.clone().err(), past.then_some(InstallError::Cap));
            }
            assert_eq!(
                node.get(&keys::installed(instance)).is_some(),
                !refused,
                "a refused install writes no record"
            );
        }
    }
}

/// JAM's limits are within VOS's, which size every step's result and
/// every batch's floor.
#[test]
fn the_jam_limits_are_within_vos_limits() {
    assert!(JAM.within(&VOS));
    assert_eq!(Target::default().limits(), &VOS);
    assert_eq!(Target::Jam.limits(), &JAM);
}
