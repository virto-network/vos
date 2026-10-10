//! The SDK's test actors (`agent/test-actors`, built by `just
//! build-test-actors`) running on the testkit. The tests fail, not skip,
//! when the programs are missing.

use vos_testkit::{InstallError, Testkit, decode, program_hash};
use vos_wire::abi::failure;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
const LEDGER: InstanceId = InstanceId(2);
const CALLER: InstanceId = InstanceId(3);
const ALICE: Principal = Principal::Client([1; 32]);

fn program(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../test-actors/target/riscv64em-vos/release/{name}.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let elf = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("{path}: {error}; run `just build-test-actors`"));
    vos_pvm_compiler::link_elf_spi(&elf).expect("links")
}

fn reply<T: Decode>(outcome: Outcome) -> T {
    match outcome {
        Outcome::Done(bytes) => decode(&bytes).expect("decodes"),
        Outcome::Failed { code, detail } => panic!("failed with {code}: {detail:?}"),
    }
}

fn kit() -> Testkit {
    let mut kit = Testkit::new(AgentId(7));
    kit.install(COUNTER, &program("counter"), &[], &[]).unwrap();
    let ledger = program("ledger");
    let checksum = program("checksum");
    let checksum_method = method_of(&ledger, "checksum");
    kit.install(
        LEDGER,
        &ledger,
        &[(checksum_method, &checksum)],
        &[("minter", 1)],
    )
    .unwrap();
    kit.install(CALLER, &program("caller"), &[], &[]).unwrap();
    kit
}

/// A method's id, from the program's own schema.
fn method_of(program: &[u8], name: &str) -> MethodId {
    let parsed = vos_pvm::spi::parse_standard_program(program).unwrap();
    let schema = Schema::read(&parsed.ro_data).unwrap();
    schema
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap()
        .id
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
    let counter = program("counter");
    let parsed = vos_pvm::spi::parse_standard_program(&counter).unwrap();
    let schema = Schema::read(&parsed.ro_data).expect("a schema");
    let names: Vec<_> = schema
        .methods
        .iter()
        .map(|method| String::from_utf8(method.name.clone()).unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "increment",
            "value",
            "forward",
            "put_and_scan",
            "echo",
            "large",
            "sneaky",
            "unserved",
            "fill",
            "spam",
            "ops",
            "stamp"
        ]
    );

    let ledger = program("ledger");
    let parsed = vos_pvm::spi::parse_standard_program(&ledger).unwrap();
    let schema = Schema::read(&parsed.ro_data).unwrap();
    let mint = schema.method(method_of(&ledger, "mint")).unwrap();
    assert_eq!(mint.role.as_deref(), Some(&b"minter"[..]));
    let transfer = schema.method(method_of(&ledger, "transfer")).unwrap();
    assert_eq!(transfer.gas, Some(2_000_000));
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
            code: failure::HANDLER,
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
            code: failure::FORBIDDEN,
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
            code: failure::HANDLER,
            detail: vec![0],
        }
    );
    assert_eq!(query::<_, u64>(&kit, LEDGER, "balance", 2u64), 30);
}

#[test]
fn an_attestable_method_runs_as_its_own_program() {
    let mut kit = kit();
    let values = vec![1u64, 2, 3];
    let expected = values.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, value| {
        (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
    });
    let step = call(&mut kit, LEDGER, "audit", values.clone());
    assert_eq!(reply::<u64>(step.outcome), expected);
    assert_eq!(step.attests.len(), 1);
    assert_eq!(step.attests[0].program, program_hash(&program("checksum")));
    assert_eq!(step.attests[0].arguments, values.encode());
    assert_eq!(step.attests[0].output, expected.encode());
}

#[test]
fn installing_needs_every_attestable_program_and_role() {
    let mut kit = Testkit::new(AgentId(7));
    let ledger = program("ledger");
    assert_eq!(
        kit.install(LEDGER, &ledger, &[], &[("minter", 1)]),
        Err(InstallError::Unbound(method_of(&ledger, "checksum")))
    );
    let checksum = program("checksum");
    assert_eq!(
        kit.install(
            LEDGER,
            &ledger,
            &[(method_of(&ledger, "checksum"), &checksum)],
            &[]
        ),
        Err(InstallError::UnmappedRole(b"minter".to_vec()))
    );
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
            code: failure::HANDLER,
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
            code: failure::CYCLE,
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
fn an_attestable_program_may_not_make_host_calls() {
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
    let ledger = program("ledger");
    let mut kit = Testkit::new(AgentId(7));
    kit.install(
        LEDGER,
        &ledger,
        &[(method_of(&ledger, "checksum"), &bad)],
        &[("minter", 1)],
    )
    .unwrap();
    let step = call(&mut kit, LEDGER, "audit", vec![1u64]);
    assert_eq!(
        step.outcome,
        Outcome::Failed {
            code: failure::TRAPPED,
            detail: vec![],
        }
    );
}
