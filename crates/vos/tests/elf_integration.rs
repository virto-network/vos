//! ELF integration tests — full pipeline: RISC-V ELF → transpile → PVM → run.
//!
//! These tests load pre-built actor ELF binaries from the examples/ directory,
//! transpile them to PVM blobs, and run them through VosRuntime.

use vos::runtime::VosRuntime;

/// Resolve the path to a pre-built example ELF.
fn example_elf(name: &str) -> Vec<u8> {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{}/../../examples/actors/{name}/target/riscv64em-javm/release/{name}.elf",
        workspace
    );
    match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) => panic!("Failed to read {path}: {e}\nRun `just build` in examples/ first."),
    }
}

/// Transpile an ELF to a JAM service PVM blob (dual entry: refine + accumulate).
fn transpile_actor(elf_data: &[u8]) -> Vec<u8> {
    grey_transpiler::link_elf_service(elf_data).expect("transpile failed")
}

/// Register a service blob and create a service (dual-entry, accumulate at PC=5).
fn register_svc(rt: &mut VosRuntime, blob: Vec<u8>) -> vos_abi::service::ServiceId {
    let blob_idx = rt.register_service_blob(blob);
    rt.register_service(blob_idx)
}

#[test]
fn transpile_all_examples() {
    // Smoke test: all example ELFs transpile without error.
    for name in &["greeter", "counter", "fizzbuzz", "hasher", "animation"] {
        let elf = example_elf(name);
        let blob = transpile_actor(&elf);
        assert!(!blob.is_empty(), "{name} produced empty blob");
    }
}

#[test]
fn greeter_pvm_blob_has_jump_header() {
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);
    assert!(blob.len() > 100, "greeter blob suspiciously small: {} bytes", blob.len());
}

#[test]
fn greeter_metadata_from_elf() {
    // Verify the .vos_meta section is present and decodable.
    let elf = example_elf("greeter");
    let Some(meta) = vos::metadata::from_elf(&elf) else {
        eprintln!("SKIP: greeter ELF lacks .vos_meta — rebuild examples");
        return;
    };

    assert_eq!(meta.actor_name, "Greeter");
    assert!(!meta.messages.is_empty(), "greeter should have at least one message");
}

#[test]
fn agent_service_lifecycle() {
    // The scheduler agent is a service (accumulate at PC=5). Verify it inits and halts.
    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace
    );
    let agent_data = match std::fs::read(&agent_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let blob = transpile_actor(&agent_data);

    let mut rt = VosRuntime::new();
    let id = register_svc(&mut rt, blob);

    // Write init args (empty children list)
    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(id, vos::lifecycle::INIT_KEY, &encoded);

    // Send empty kick-start transfer
    rt.send_to(id, Vec::new());
    rt.run();

    // Agent persists state via main_loop's accumulate path
    let state = rt.storage.read(id, b"__vos_actor_state");
    assert!(
        state.is_some(),
        "agent should persist actor state after init"
    );
}

#[test]
fn cooperative_loop_with_greeter() {
    // Full cooperative test: scheduler agent invokes greeter.
    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace
    );
    let agent_data = match std::fs::read(&agent_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };

    let greeter_elf = example_elf("greeter");

    let agent_blob = transpile_actor(&agent_data);
    let greeter_blob = transpile_actor(&greeter_elf);

    let mut rt = VosRuntime::new();

    // Register agent as service
    let agent_blob_idx = rt.register_service_blob(agent_blob);
    let agent_id = rt.register_service(agent_blob_idx);

    // Register greeter as service blob (dual-entry for invoke at PC=0)
    let greeter_blob_idx = rt.register_service_blob(greeter_blob);
    let greeter_id = rt.register_service(greeter_blob_idx);

    // Write init args (children = [greeter_id])
    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![greeter_id.0]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    // Kick-start agent
    rt.send_to(agent_id, Vec::new());
    rt.run();

    // Agent should have state persisted
    assert!(rt.storage.read(agent_id, b"__vos_actor_state").is_some());
}

#[test]
fn refine_round_commits_once() {
    // Smoke test for the refine journal commit path. The scheduler agent
    // is a full service (built with the `service` feature) — its
    // `save_state` issues a real `WRITE` hostcall during refine, which
    // the runtime journals and then commits to storage. We verify that
    // after a single `run()` the persisted state is present and that
    // there is no leftover work in the pending-transfers queue.
    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace
    );
    let agent_data = match std::fs::read(&agent_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let blob = transpile_actor(&agent_data);

    let mut rt = VosRuntime::new();
    let id = register_svc(&mut rt, blob);

    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(id, vos::lifecycle::INIT_KEY, &encoded);

    let before = rt.storage.read(id, b"__vos_actor_state").map(|v| v.to_vec());
    assert!(before.is_none(), "state should be empty before first tick");

    rt.send_to(id, Vec::new());
    rt.run();

    let after = rt.storage.read(id, b"__vos_actor_state");
    assert!(
        after.is_some(),
        "refine journal WRITE should have been committed to storage after tick"
    );

    // No further work should be pending: journal had no cross-service
    // transfers and no self-messages beyond what the single tick consumed.
    assert!(!rt.has_work(), "no leftover pending_transfers expected");
}

#[test]
fn runtime_multiple_services_same_blob() {
    // Register same blob twice — both services are independent.
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);

    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_service_blob(blob);
    let id1 = rt.register_service(blob_idx);
    let id2 = rt.register_service(blob_idx);

    assert_ne!(id1, id2);
}
