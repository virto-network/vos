//! The SDK's test actors (`agent/test-actors`, built by `just
//! build-test-actors`) running on the testkit. The tests fail, not skip,
//! when the programs are missing.

use vos_testkit::programs::{actor, kernel, method, schema};
use vos_testkit::{InstallError, Testkit, decode, program_hash};
use vos_wire::abi::{Failure, Kind};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
const LEDGER: InstanceId = InstanceId(2);
const CALLER: InstanceId = InstanceId(3);
const ALICE: Principal = Principal::Client([1; 32]);

fn reply<T: Decode>(outcome: Outcome) -> T {
    match outcome {
        Outcome::Done(bytes) => decode(&bytes).expect("decodes"),
        other => panic!("not done: {other:?}"),
    }
}

/// The ledger's kernels: its attestable's, derived from its ELF. Its
/// workflow runs in its own program.
fn kernels<'a>(ledger: &[u8]) -> Vec<(MethodId, &'a [u8])> {
    static CHECKSUM: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let checksum = CHECKSUM.get_or_init(|| kernel("ledger", "checksum"));
    vec![(method(ledger, "checksum"), checksum)]
}

fn kit() -> Testkit {
    let mut kit = Testkit::new(AgentId(7));
    kit.install(COUNTER, &actor("counter"), &[], &[]).unwrap();
    let ledger = actor("ledger");
    kit.install(LEDGER, &ledger, &kernels(&ledger), &[("minter", 1)])
        .unwrap();
    kit.install(CALLER, &actor("caller"), &[], &[]).unwrap();
    kit
}

fn call<A: Encode>(
    kit: &mut Testkit,
    instance: InstanceId,
    name: &str,
    arguments: A,
) -> vos_testkit::Step {
    let method = kit.method(instance, name).expect("a method");
    kit.command(ALICE, instance, method, &arguments.encode())
}

fn query<A: Encode, R: Decode>(kit: &Testkit, instance: InstanceId, name: &str, arguments: A) -> R {
    let method = kit.method(instance, name).expect("a method");
    reply(kit.query(ALICE, instance, method, &arguments.encode()))
}

#[test]
fn programs_carry_their_schema_first_in_read_only_data() {
    let counter = schema(&actor("counter"));
    let linearizable: Vec<_> = counter
        .methods
        .iter()
        .filter(|method| method.linearizable)
        .map(|method| method.name.as_slice())
        .collect();
    assert_eq!(linearizable, [b"latest"]);
    let names: Vec<_> = counter
        .methods
        .iter()
        .map(|method| String::from_utf8(method.name.clone()).unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "increment",
            "value",
            "latest",
            "forward",
            "put_and_scan",
            "store",
            "scan_rows",
            "blob_keys",
            "set_entries",
            "entry",
            "entries",
            "echo",
            "large",
            "sneaky",
            "unserved",
            "fill",
            "spam",
            "ops",
            "hash",
            "stamp"
        ]
    );

    let ledger = actor("ledger");
    let schema = schema(&ledger);
    let mint = schema.method(method(&ledger, "mint")).unwrap();
    assert_eq!(mint.role.as_deref(), Some(&b"minter"[..]));
    let transfer = schema.method(method(&ledger, "transfer")).unwrap();
    assert_eq!(transfer.gas, Some(2_000_000));
    let kinds = |name| schema.method(method(&ledger, name)).unwrap().kind;
    assert_eq!(kinds("checksum"), Kind::Attestable);
    assert_eq!(kinds("tally"), Kind::Workflow);
}

#[test]
fn a_counter_keeps_its_state_and_fails_without_effects() {
    let mut kit = kit();
    let step = call(&mut kit, COUNTER, "increment", 5u64);
    assert_eq!(reply::<u64>(step.outcome), 5);
    assert_eq!(
        reply::<u64>(call(&mut kit, COUNTER, "increment", 3u64).outcome),
        8
    );
    assert_eq!(query::<_, u64>(&kit, COUNTER, "value", ()), 8);

    let overflow = call(&mut kit, COUNTER, "increment", u64::MAX);
    assert_eq!(
        overflow.outcome,
        Outcome::Failed {
            code: Failure::Handler,
            detail: vec![0],
        },
        "the handler's own error, encoded"
    );
    assert!(overflow.writes.is_empty());
    assert_eq!(query::<_, u64>(&kit, COUNTER, "value", ()), 8);
}

#[test]
fn time_and_randomness_come_from_the_batch() {
    let mut kit = kit();
    kit.time = 1_700_000_000_000;
    kit.seed = [9; 32];
    let first: [u8; 32] = reply(call(&mut kit, COUNTER, "stamp", ()).outcome);
    assert_eq!(
        query::<_, u64>(&kit, COUNTER, "value", ()),
        1_700_000_000_000
    );
    let second: [u8; 32] = reply(call(&mut kit, COUNTER, "stamp", ()).outcome);
    assert_ne!(first, second, "each step draws differently");
}

#[test]
fn roles_gate_handlers() {
    let mut kit = kit();
    let denied = call(&mut kit, LEDGER, "mint", (1u64, 100u64));
    assert_eq!(
        denied.outcome,
        Outcome::Failed {
            code: Failure::Forbidden,
            detail: vec![],
        }
    );
    kit.set_role(ALICE, Some(1));
    assert_eq!(
        reply::<u64>(call(&mut kit, LEDGER, "mint", (1u64, 100u64)).outcome),
        100
    );
    assert_eq!(query::<_, u64>(&kit, LEDGER, "total", ()), 100);
}

#[test]
fn a_ledger_moves_balances_in_a_table() {
    let mut kit = kit();
    kit.set_role(ALICE, Some(1));
    call(&mut kit, LEDGER, "mint", (1u64, 100u64));
    call(&mut kit, LEDGER, "mint", (3u64, 5u64));
    let step = call(&mut kit, LEDGER, "transfer", (1u64, 2u64, 30u64));
    assert_eq!(step.outcome, Outcome::Done(vec![]));
    assert_eq!(step.writes.len(), 2, "two rows, no struct change");
    assert_eq!(query::<_, u64>(&kit, LEDGER, "balance", 1u64), 70);
    assert_eq!(query::<_, u64>(&kit, LEDGER, "balance", 2u64), 30);
    assert_eq!(
        query::<_, Vec<(u64, u64)>>(&kit, LEDGER, "holders", ()),
        [(1, 70), (2, 30), (3, 5)]
    );

    let short = call(&mut kit, LEDGER, "transfer", (2u64, 1u64, 31u64));
    assert_eq!(
        short.outcome,
        Outcome::Failed {
            code: Failure::Handler,
            detail: vec![0],
        }
    );
    assert_eq!(query::<_, u64>(&kit, LEDGER, "balance", 2u64), 30);
}

#[test]
fn an_attestable_method_runs_as_its_own_kernel() {
    let mut kit = kit();
    let values = vec![1u64, 2, 3];
    let expected = values.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, value| {
        (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
    });
    let step = call(&mut kit, LEDGER, "audit", values.clone());
    assert_eq!(reply::<u64>(step.outcome), expected);
    assert_eq!(step.attests.len(), 1);
    assert_eq!(
        step.attests[0].program,
        program_hash(&kernel("ledger", "checksum"))
    );
    assert_eq!(step.attests[0].arguments, values.encode());
    assert_eq!(step.attests[0].output, expected.encode());
}

#[test]
fn installing_needs_every_attestable_kernel_and_role() {
    let mut kit = Testkit::new(AgentId(7));
    let ledger = actor("ledger");
    let all = kernels(&ledger);
    assert_eq!(
        kit.install(LEDGER, &ledger, &[], &[("minter", 1)]),
        Err(InstallError::Unbound(method(&ledger, "checksum")))
    );
    // A kernel runs an attestable method, never a workflow, which runs in
    // the actor's program.
    let checksum = all[0];
    let tally = (method(&ledger, "tally"), checksum.1);
    assert_eq!(
        kit.install(LEDGER, &ledger, &[checksum, tally], &[("minter", 1)]),
        Err(InstallError::Unmatched(tally.0))
    );
    let mut twice = all.clone();
    twice.push(checksum);
    assert_eq!(
        kit.install(LEDGER, &ledger, &twice, &[("minter", 1)]),
        Err(InstallError::Duplicate(checksum.0))
    );
    let mut stray = all.clone();
    stray.push((method(&ledger, "mint"), checksum.1));
    assert_eq!(
        kit.install(LEDGER, &ledger, &stray, &[("minter", 1)]),
        Err(InstallError::Unmatched(method(&ledger, "mint")))
    );
    assert_eq!(
        kit.install(LEDGER, &ledger, &all, &[]),
        Err(InstallError::UnmappedRole(b"minter".to_vec()))
    );
    assert_eq!(kit.install(LEDGER, &ledger, &all, &[("minter", 1)]), Ok(()));
}

#[test]
fn nested_calls_commit_with_their_caller_and_see_it_as_their_principal() {
    let mut kit = kit();
    kit.set_role(ALICE, Some(1));
    call(&mut kit, LEDGER, "mint", (1u64, 100u64));

    let step = call(&mut kit, CALLER, "pay", ((LEDGER.0, 1u64), (2u64, 40u64)));
    assert_eq!(reply::<u64>(step.outcome), 40);
    let instances: Vec<_> = step.instances.iter().map(|entry| entry.instance).collect();
    assert_eq!(instances, [CALLER, LEDGER], "in the order they first ran");
    assert_eq!(
        step.instances.iter().map(|entry| entry.gas).sum::<u64>(),
        step.gas_used,
        "each instance's own gas, callees excluded"
    );
    assert_eq!(query::<_, u64>(&kit, LEDGER, "balance", 1u64), 60);

    // The ledger's error returns to the caller, which fails the step: the
    // whole step's writes are discarded, the caller's count with them.
    let refused = call(&mut kit, CALLER, "pay", ((LEDGER.0, 2u64), (1u64, 41u64)));
    assert_eq!(
        refused.outcome,
        Outcome::Failed {
            code: Failure::Handler,
            detail: vec![0],
        }
    );
    assert!(refused.writes.is_empty());

    let principal: Option<Principal> = query(&kit, CALLER, "ask", LEDGER.0);
    assert_eq!(principal, Some(Principal::Instance(CALLER)));
}

#[test]
fn a_call_cycle_fails_the_step() {
    let mut kit = kit();
    let step = call(&mut kit, CALLER, "recurse", ());
    assert_eq!(
        step.outcome,
        Outcome::Failed {
            code: Failure::Cycle,
            detail: vec![],
        }
    );
    assert!(step.writes.is_empty());
}

#[test]
fn a_failed_callee_leaves_no_messages() {
    let mut kit = kit();
    let step = call(&mut kit, CALLER, "relay", LEDGER.0);
    assert!(reply::<bool>(step.outcome), "the callee failed");
    assert!(step.messages.is_empty(), "its send went with it");
    assert_eq!(step.writes.len(), 1, "the caller's own count survives");
}

#[test]
fn a_kernel_may_not_make_host_calls() {
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    // ecalli 9 (`machine`), then return to the halt address.
    let bad = build_standard_program(&StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 0,
        stack_size: 4096,
        code: CodeBlob {
            jump_table: vec![],
            code: vec![10, 9, 50, 0],
            bitmask: vec![1, 0, 1, 0],
        },
    })
    .unwrap();
    let ledger = actor("ledger");
    let mut kit = Testkit::new(AgentId(7));
    let mut programs = kernels(&ledger);
    programs[0].1 = &bad;
    kit.install(LEDGER, &ledger, &programs, &[("minter", 1)])
        .unwrap();
    let step = call(&mut kit, LEDGER, "audit", vec![1u64]);
    assert_eq!(
        step.outcome,
        Outcome::Failed {
            code: Failure::Trapped,
            detail: vec![],
        }
    );
}
