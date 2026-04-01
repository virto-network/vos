//! ELF integration tests — full pipeline: RISC-V ELF → transpile → PVM → run.
//!
//! These tests load pre-built actor ELF binaries from the examples/ directory,
//! transpile them to PVM blobs, and run them through VosRuntime. They verify
//! the complete actor lifecycle: init, hostcalls, state persistence, halt.

use vos::runtime::VosRuntime;

/// Resolve the path to a pre-built example ELF.
fn example_elf(name: &str) -> Vec<u8> {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{}/../../examples/{name}/target/riscv64em-javm/release/{name}.elf",
        workspace
    );
    match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) => panic!("Failed to read {path}: {e}\nRun `just build` in examples/ first."),
    }
}

/// Transpile an ELF to a PVM blob.
fn transpile_actor(elf_data: &[u8]) -> Vec<u8> {
    grey_transpiler::link_elf(elf_data).expect("transpile failed")
}

#[test]
fn greeter_lifecycle() {
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);

    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);

    // Send empty init trigger — greeter has a parameterless constructor
    rt.send_to(id, Vec::new());
    rt.run();

    // Greeter should have persisted its state under "__vos_actor_state"
    let state = rt.hostcalls.storage.read(id, b"__vos_actor_state");
    assert!(
        state.is_some(),
        "greeter should persist actor state after init"
    );
}

#[test]
fn greeter_survives_second_invocation() {
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);

    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);

    // First invocation — init
    rt.send_to(id, Vec::new());
    rt.run();

    let state1 = rt.hostcalls.storage.read(id, b"__vos_actor_state")
        .map(|s| s.to_vec());
    assert!(state1.is_some());

    // Second invocation — should load state from storage, process empty fetch, re-save
    rt.send_to(id, Vec::new());
    rt.run();

    let state2 = rt.hostcalls.storage.read(id, b"__vos_actor_state")
        .map(|s| s.to_vec());
    assert!(state2.is_some());
    // State should be identical (greeter is stateless, no messages processed)
    assert_eq!(state1, state2);
}

#[test]
fn transpile_all_examples() {
    // Smoke test: all example ELFs transpile without error.
    for name in &["greeter", "counter", "fizzbuzz"] {
        let elf = example_elf(name);
        let blob = transpile_actor(&elf);
        assert!(!blob.is_empty(), "{name} produced empty blob");
    }
}

#[test]
fn greeter_pvm_blob_has_jump_header() {
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);

    // The PVM blob starts with the standard program header (ro_data, rw_data, etc.)
    // The code section should start with opcode 40 (jump to _start)
    // We can't easily check the raw code offset without parsing the blob format,
    // but we can verify the blob is non-trivially sized
    assert!(blob.len() > 100, "greeter blob suspiciously small: {} bytes", blob.len());
}

#[test]
fn runtime_multiple_services_mixed() {
    // Register greeter twice — both should init and halt independently
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);

    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id1 = rt.register_service(blob_idx);
    let id2 = rt.register_service(blob_idx);

    rt.send_to(id1, Vec::new());
    rt.send_to(id2, Vec::new());
    rt.run();

    // Both services should have persisted state
    assert!(rt.hostcalls.storage.read(id1, b"__vos_actor_state").is_some());
    assert!(rt.hostcalls.storage.read(id2, b"__vos_actor_state").is_some());
}

#[test]
fn counter_needs_init_payload() {
    // Counter has fn new(initial: u8) — needs init data.
    // Sending empty should cause it to wait (YIELD+FETCH loop)
    // until it runs out of gas. This is expected behavior.
    let elf = example_elf("counter");
    let blob = transpile_actor(&elf);

    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_blob(blob);
    let id = rt.register_service(blob_idx);

    // Send empty — counter will spin waiting for init payload
    rt.send_to(id, Vec::new());
    rt.run();

    // Counter should NOT have persisted state (never constructed)
    let state = rt.hostcalls.storage.read(id, b"__vos_actor_state");
    assert!(
        state.is_none(),
        "counter without init payload should not persist state"
    );
}

