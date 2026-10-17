//! Kernels: an attestable method's, bound at install, derived from an
//! actor's ELF, and run on the arguments their witness input reads.

use super::*;
use vos_wire::abi::cap::Target;
use vos_wire::records::Kernel;

/// A kernel's machine maps no arguments: they reach it through its
/// witness input. A store at the standard argument window, which φ7 names,
/// traps, in the agent as in the model.
#[test]
fn a_kernels_argument_window_is_unmapped() {
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    // store_ind_u8 [φ7] = φ0, then return to the halt address.
    let scribble = build_standard_program(&StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 0,
        stack_size: 4096,
        code: CodeBlob {
            jump_table: vec![],
            code: vec![120, 0x70, 50, 0],
            bitmask: vec![1, 0, 1, 0],
        },
    })
    .unwrap();
    let actors = Actors::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    let program = node.add(&scribble);
    let Input::Admin(Admin::Install {
        instance,
        mut derivation,
        roles,
        target,
    }) = actors.install_ledger(&mut node)
    else {
        unreachable!("an install")
    };
    derivation.kernels[0].program = program;
    node.batch(
        0,
        vec![Input::Admin(Admin::Install {
            instance,
            derivation,
            roles,
            target,
        })],
    );
    let checksum = method(&actors.ledger, "checksum");
    kit.install(
        LEDGER,
        &actors.ledger,
        &[(checksum, &scribble)],
        &[("minter", MINTER)],
    )
    .unwrap();
    let audit = actors.method(LEDGER, "audit");
    let mut sessions = Sessions::new();
    let result = node.batch(1, vec![sessions.request(ALICE, LEDGER, audit, vec![1u64])]);
    assert_eq!(failed(&result.steps[0]), Failure::Trapped);
    kit.batch(1, [0; 32]);
    let expected = kit.command(ALICE, LEDGER, audit, &vec![1u64].encode());
    assert_eq!(ran(&result.steps[0]).outcome, expected.outcome);
}

/// An install binds each kernel to an attestable method: exactly one for
/// each, and none that names another method; a workflow needs none, as it
/// runs in the actor's program. Its record keeps the derivation, which the
/// install answers.
#[test]
fn an_install_binds_each_kernel_to_an_attestable_method() {
    let actors = Actors::load();
    let mut node = Node::new();
    let Input::Admin(Admin::Install {
        instance,
        derivation,
        roles,
        target,
    }) = actors.install_ledger(&mut node)
    else {
        unreachable!("an install")
    };
    let with = |kernels: Vec<Kernel>| {
        Input::Admin(Admin::Install {
            instance,
            derivation: vos_wire::records::Derivation {
                kernels,
                ..derivation.clone()
            },
            roles: roles.clone(),
            target,
        })
    };
    let checksum = derivation.kernels[0].clone();
    let (mint, tally) = (
        actors.method(LEDGER, "mint"),
        actors.method(LEDGER, "tally"),
    );
    let result = node.batch(
        0,
        vec![
            with(vec![]),
            with(vec![
                checksum.clone(),
                Kernel {
                    method: mint,
                    ..checksum.clone()
                },
            ]),
            with(vec![
                checksum.clone(),
                Kernel {
                    method: tally,
                    ..checksum.clone()
                },
            ]),
            with(vec![checksum.clone(), checksum]),
            with(derivation.kernels.clone()),
        ],
    );
    for (index, step) in result.steps[..4].iter().enumerate() {
        assert_eq!(failed(step), Failure::Unknown, "install {index}");
    }
    assert_eq!(
        ran(&result.steps[4]).outcome,
        Outcome::Done(derivation.encode())
    );
    let installed: vos_wire::records::Installed =
        node.value(&keys::installed(LEDGER)).expect("installed");
    assert_eq!(installed.derivation, derivation);
}

/// Kernels derived from an actor's ELF run in the agent as in the model,
/// on every host and for every target: a precompile and its fallback's
/// constants, a switch table and calls through a vtable, each its own
/// kernel, within its method's gas limit for JAM.
#[test]
fn derived_kernels_run_in_the_agent() {
    use vos_testkit::programs::{derivation, derived, package};
    let derived = derived("kernels");
    let instance = InstanceId(9);
    let kernels: Vec<(MethodId, &[u8])> = derived
        .kernels
        .iter()
        .map(|(method, kernel)| (MethodId(*method), kernel.as_slice()))
        .collect();
    let check = method(&derived.actor, "check");
    let hosts = || [Node::new(), Node::jam(true)];
    for (target, mut node) in hosts()
        .map(|node| (Target::Vos, node))
        .into_iter()
        .chain(hosts().map(|node| (Target::Jam, node)))
    {
        let install = Input::Admin(Admin::Install {
            instance,
            derivation: derivation(&package("kernels"), &derived),
            roles: vec![],
            target,
        });
        node.add(&derived.actor);
        for (_, kernel) in &kernels {
            node.add(kernel);
        }
        ran_done(&node.batch(0, vec![install]).steps[0]);
        let mut kit = Testkit::new(AGENT);
        kit.install_for(target, instance, &derived.actor, &kernels, &[])
            .unwrap();
        let mut sessions = Sessions::new();
        let values = vec![1u64, 2, 3, 40];
        let result = node.batch(
            1,
            vec![sessions.request(ALICE, instance, check, values.clone())],
        );
        kit.batch(1, [0; 32]);
        let expected = kit.command(ALICE, instance, check, &values.encode());
        let run = ran(&result.steps[0]);
        assert!(matches!(run.outcome, Outcome::Done(_)), "{:?}", run.outcome);
        assert_eq!(run.outcome, expected.outcome);
        assert_eq!(run.attests, expected.attests);
        assert_eq!(run.gas_used, expected.gas_used);
    }
}
