//! A target's limits: an agent runs on one target, its instances within
//! its limits on every host, as the model runs them; an install whose
//! statics pass them, or which names another target than its agent's, is
//! refused.

use vos_testkit::programs::{actor, derivation, derived, method, package};
use vos_testkit::{InstallError, Testkit};
use vos_wire::abi::cap::{JAM, Refused, Target, VOS};
use vos_wire::abi::{Failure, INVOCATION_HEAP};
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::{InstanceId, MethodId, ProgramHash, WorkflowId};
use vos_wire::records::{Derivation, Workflow, WorkflowState};
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

/// Test actor `name` derived, its programs added to `node`, installed at
/// `instance` for `target`: the install, and the model's.
fn derived_install(
    node: &mut Node,
    kit: &mut Testkit,
    name: &str,
    instance: InstanceId,
    target: Target,
) -> (Input, Result<(), InstallError>) {
    let derived = derived(name);
    node.add(&derived.actor);
    for (_, kernel) in &derived.kernels {
        node.add(kernel);
    }
    let input = install(instance, derivation(&package(name), &derived), target);
    let model = kit.install_derived(target, instance, &derived, &[("minter", MINTER)]);
    (input, model)
}

/// An install refused: `refused`'s failure, its detail the refusal.
fn refusal(refused: Refused) -> Outcome {
    Outcome::Failed {
        code: refused.failure(),
        detail: refused.encode(),
    }
}

/// A step's effects at the edge of JAM's limits run for both targets, and
/// one past an edge fails `Cap` for JAM alone: messages, rows and bytes
/// written, attests and their arguments and output. On every host, as in
/// the model.
#[test]
fn an_agent_on_jam_runs_within_its_limits() {
    const BOUNDS: InstanceId = InstanceId(2);
    let counter = actor("counter");
    let (spam, fill) = (method(&counter, "spam"), method(&counter, "fill"));
    let attest = method(&derived("bounds").actor, "attest");
    // A row of the counter's table: its key's bytes beside the value's.
    let value = JAM.step_writes - 64;
    // An echo's arguments: its padding's four-byte length, the padding,
    // the output's length; its output: four bytes of length, then bytes.
    let padding = JAM.attest as u32 - 8;
    let output = JAM.attest as u32 - 4;
    let attests = JAM.attests as u32;
    let calls: [(InstanceId, MethodId, Vec<u8>, bool); 12] = [
        (COUNTER, spam, (JAM.messages as u32).encode(), false),
        (COUNTER, spam, (JAM.messages as u32 + 1).encode(), true),
        (COUNTER, fill, (JAM.step_rows as u32, 8u32).encode(), false),
        (
            COUNTER,
            fill,
            (JAM.step_rows as u32 + 1, 8u32).encode(),
            true,
        ),
        (COUNTER, fill, (1u32, value as u32).encode(), false),
        (COUNTER, fill, (1u32, JAM.step_writes as u32).encode(), true),
        (BOUNDS, attest, (attests, 0u32, 8u32).encode(), false),
        (BOUNDS, attest, (attests + 1, 0u32, 8u32).encode(), true),
        (BOUNDS, attest, (1u32, padding, 8u32).encode(), false),
        (BOUNDS, attest, (1u32, padding + 1, 8u32).encode(), true),
        (BOUNDS, attest, (1u32, 0u32, output).encode(), false),
        (BOUNDS, attest, (1u32, 0u32, output + 1).encode(), true),
    ];
    for target in [Target::Vos, Target::Jam] {
        for mut node in hosts() {
            let mut kit = Testkit::new(AGENT);
            let program = node.add(&counter);
            let (bounds, model) = derived_install(&mut node, &mut kit, "bounds", BOUNDS, target);
            model.unwrap();
            let installs = vec![bare(COUNTER, program, target), bounds];
            for step in &node.batch(0, installs).steps {
                assert!(matches!(ran(step).outcome, Outcome::Done(_)));
            }
            kit.install_for(target, COUNTER, &counter, &[], &[])
                .unwrap();
            let mut sessions = Sessions::new();
            let inputs = calls
                .iter()
                .map(|(instance, method, arguments, _)| {
                    sessions.request_bytes(ALICE, *instance, *method, arguments.clone())
                })
                .collect();
            let result = node.batch(1, inputs);
            kit.batch(1, [0; 32]);
            for (step, (instance, method, arguments, past)) in result.steps.iter().zip(&calls) {
                let expected = kit.command(ALICE, *instance, *method, arguments);
                let run = ran(step);
                assert_eq!(run.outcome, expected.outcome);
                assert_eq!(run.messages, expected.messages);
                assert_eq!(run.attests, expected.attests);
                let capped = matches!(
                    run.outcome,
                    Outcome::Failed {
                        code: Failure::Cap,
                        ..
                    }
                );
                assert_eq!(
                    capped,
                    *past && target == Target::Jam,
                    "{target:?} {arguments:?}"
                );
            }
        }
    }
}

/// A kernel runs within the gas its method declares on JAM, and within the
/// calling handler's on VOS: one past its declared gas fails the step on
/// JAM alone, `OutOfGas`. An attestable that declares none takes JAM's
/// most, what 4,096 compressions pay for, and one declaring more runs
/// within that.
#[test]
fn a_kernel_runs_within_its_declared_gas_on_jam() {
    const BOUNDS: InstanceId = InstanceId(2);
    let spun = method(&derived("bounds").actor, "spun");
    let rounds = [100u32, 20_000];
    for target in [Target::Vos, Target::Jam] {
        for mut node in hosts() {
            let mut kit = Testkit::new(AGENT);
            let (bounds, model) = derived_install(&mut node, &mut kit, "bounds", BOUNDS, target);
            model.unwrap();
            ran(&node.batch(0, vec![bounds]).steps[0]);
            let mut sessions = Sessions::new();
            let inputs = rounds
                .iter()
                .map(|rounds| sessions.request(ALICE, BOUNDS, spun, *rounds))
                .collect();
            let result = node.batch(1, inputs);
            kit.batch(1, [0; 32]);
            for (step, rounds) in result.steps.iter().zip(rounds) {
                let expected = kit.command(ALICE, BOUNDS, spun, &rounds.encode());
                let run = ran(step);
                assert_eq!(run.outcome, expected.outcome);
                assert_eq!(run.gas_used, expected.gas_used);
                let out_of_gas = run.outcome == Outcome::failed(Failure::OutOfGas);
                let past = rounds > 100 && target == Target::Jam;
                assert_eq!(out_of_gas, past, "{target:?} {rounds}: {:?}", run.outcome);
            }
        }
    }
    let most = 4_096 * 600;
    assert_eq!(JAM.kernel_gas(), Some(most));
    assert_eq!(JAM.kernel_limit(None), Some(most));
    assert_eq!(JAM.kernel_limit(Some(50_000)), Some(50_000));
    assert_eq!(JAM.kernel_limit(Some(most + 1)), Some(most));
    assert_eq!(VOS.kernel_limit(Some(50_000)), None);
}

/// An install past a JAM limit on its statics is refused for JAM, `Cap`,
/// its detail naming the limit, and installs for VOS: a program writing
/// more pages (the shop's 4 MiB heap), binding more kernels (33), of more
/// bytes (640 KiB of data), or an attestable declaring more gas than a
/// kernel runs with. An attestable declaring none, and the default-heap
/// shop, install. In the agent on every host, as in the model; a refused
/// install writes no record.
#[test]
fn an_install_past_the_jam_limits_is_refused() {
    let shop = actor("shop");
    // The pages the shop's program may write, as the model counts them.
    let pages = match Testkit::new(AGENT).install_for(Target::Jam, InstanceId(1), &shop, &[], &[]) {
        Err(InstallError::Refused(Refused::Pages { pages, .. })) => pages,
        other => panic!("{other:?}"),
    };
    let kernels = derived("wide").kernels.len() as u64;
    let bytes = derived("bulky").actor.len() as u64;
    let greedy = derived("greedy");
    let hash = method(&greedy.actor, "hash");
    let most = JAM.kernel_gas().unwrap();
    let expected = [
        Some(Refused::Pages {
            pages,
            most: JAM.program_pages.unwrap() as u64,
        }),
        Some(Refused::Kernels {
            kernels,
            most: JAM.kernels as u64,
        }),
        Some(Refused::Program {
            bytes,
            most: JAM.program as u64,
        }),
        Some(Refused::KernelGas {
            method: hash,
            gas: 3_000_000,
            most,
        }),
        None,
        None,
    ];
    assert_eq!(kernels, 33);
    // A JAM builder's derivation names the method.
    let Err(vos_jam::Error::Package(why)) = vos_jam::programs::derive(&package("greedy")) else {
        panic!("derived for JAM");
    };
    assert!(why.contains("`hash`") && why.contains("3000000"), "{why}");
    for target in [Target::Vos, Target::Jam] {
        for mut node in hosts() {
            let mut kit = Testkit::new(AGENT);
            let shop_hash = node.add(&shop);
            let lean_hash = node.add(&actor("lean"));
            let mut inputs = vec![bare(InstanceId(1), shop_hash, target)];
            let mut models = vec![kit.install_for(target, InstanceId(1), &shop, &[], &[])];
            for (instance, name) in [(2, "wide"), (3, "bulky"), (4, "greedy"), (5, "ledger")] {
                let (input, model) =
                    derived_install(&mut node, &mut kit, name, InstanceId(instance), target);
                inputs.push(input);
                models.push(model);
            }
            inputs.push(bare(InstanceId(6), lean_hash, target));
            models.push(kit.install_for(target, InstanceId(6), &actor("lean"), &[], &[]));
            let result = node.batch(0, inputs);
            for (index, ((step, model), expected)) in
                result.steps.iter().zip(&models).zip(&expected).enumerate()
            {
                let refused = expected.filter(|_| target == Target::Jam);
                let outcome = &ran(step).outcome;
                match refused {
                    Some(refused) => {
                        assert_eq!(outcome, &refusal(refused), "{target:?} {index}");
                        assert_eq!(model, &Err(InstallError::Refused(refused)));
                        let instance = InstanceId(index as u32 + 1);
                        assert!(node.get(&keys::installed(instance)).is_none());
                    }
                    None => {
                        assert!(
                            matches!(outcome, Outcome::Done(_)),
                            "{target:?} {index}: {outcome:?}"
                        );
                        assert_eq!(model, &Ok(()));
                    }
                }
            }
        }
    }
}

/// An agent runs on one target, which its first install names: an install
/// for another is refused, `Target`, its detail the agent's, and writes no
/// record, on every host as in the model. A refused first install names
/// none.
#[test]
fn an_install_for_another_target_than_its_agents_is_refused() {
    let (counter, shop) = (actor("counter"), actor("shop"));
    for (first, other) in [(Target::Vos, Target::Jam), (Target::Jam, Target::Vos)] {
        for mut node in hosts() {
            let mut kit = Testkit::new(AGENT);
            let (counter_hash, shop_hash) = (node.add(&counter), node.add(&shop));
            // The shop's heap is past JAM's pages: refused there, it names
            // no target.
            let inputs = vec![
                bare(InstanceId(5), shop_hash, Target::Jam),
                bare(COUNTER, counter_hash, first),
                bare(InstanceId(2), counter_hash, other),
                bare(InstanceId(3), counter_hash, first),
            ];
            let models = [
                kit.install_for(Target::Jam, InstanceId(5), &shop, &[], &[]),
                kit.install_for(first, COUNTER, &counter, &[], &[]),
                kit.install_for(other, InstanceId(2), &counter, &[], &[]),
                kit.install_for(first, InstanceId(3), &counter, &[], &[]),
            ];
            let result = node.batch(0, inputs);
            let outcomes: Vec<&Outcome> =
                result.steps.iter().map(|step| &ran(step).outcome).collect();
            assert!(matches!(
                outcomes[0],
                Outcome::Failed {
                    code: Failure::Cap,
                    ..
                }
            ));
            assert!(models[0].is_err());
            assert!(matches!(outcomes[1], Outcome::Done(_)), "{first:?}");
            assert_eq!(models[1], Ok(()));
            let mixed = Refused::Target { agent: first };
            assert_eq!(outcomes[2], &refusal(mixed), "{first:?}");
            assert_eq!(models[2], Err(InstallError::Refused(mixed)));
            assert!(node.get(&keys::installed(InstanceId(2))).is_none());
            assert!(matches!(outcomes[3], Outcome::Done(_)));
            assert_eq!(models[3], Ok(()));
            let recorded: Target = node.value(&keys::target()).expect("the agent's target");
            assert_eq!(recorded, first);
        }
    }
}

/// A handler is given its actor's heap up to [`INVOCATION_HEAP`]: an
/// allocation past it fails, and the step traps, though the actor's heap
/// is larger and the memory never touched; one within it runs. A workflow
/// allocates from the whole heap. On every host, as in the model.
#[test]
fn a_handler_allocates_within_the_invocation_heap() {
    const BOUNDS: InstanceId = InstanceId(2);
    let ample = derived("ample");
    let (reserve, reserved) = (
        method(&ample.actor, "reserve"),
        method(&ample.actor, "reserved"),
    );
    let within = (INVOCATION_HEAP / 2) as u32;
    let past = INVOCATION_HEAP as u32 * 2;
    for mut node in hosts() {
        let mut kit = Testkit::new(AGENT);
        let (install, model) = derived_install(&mut node, &mut kit, "ample", BOUNDS, Target::Vos);
        model.unwrap();
        ran(&node.batch(0, vec![install]).steps[0]);
        let mut sessions = Sessions::new();
        let calls = [within, past];
        let mut inputs: Vec<Input> = calls
            .iter()
            .map(|bytes| sessions.request(ALICE, BOUNDS, reserve, *bytes))
            .collect();
        inputs.push(sessions.request(ALICE, BOUNDS, reserved, past));
        let result = node.batch(1, inputs);
        kit.batch(1, [0; 32]);
        for (step, bytes) in result.steps.iter().zip(calls) {
            let expected = kit.command(ALICE, BOUNDS, reserve, &bytes.encode());
            assert_eq!(ran(step).outcome, expected.outcome);
        }
        assert_eq!(
            ran(&result.steps[0]).outcome,
            Outcome::Done(within.encode())
        );
        assert_eq!(
            ran(&result.steps[1]).outcome,
            Outcome::failed(Failure::Trapped)
        );
        let workflow: Workflow = node.value(&keys::workflow(WorkflowId(0))).unwrap();
        assert_eq!(
            workflow.state,
            WorkflowState::Ended(Outcome::Done(past.encode()))
        );
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
