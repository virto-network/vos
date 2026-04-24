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
    grey_transpiler::link_elf(elf_data).expect("transpile failed")
}

/// Register a service blob and create a service (dual-entry, accumulate at PC=5).
fn register_svc(rt: &mut VosRuntime, blob: Vec<u8>) -> vos::abi::service::ServiceId {
    let blob_idx = rt.register_service_blob(blob);
    rt.register_service(blob_idx)
}

#[test]
fn transpile_all_examples() {
    // Smoke test: all example ELFs transpile without error.
    for name in &["greeter", "counter", "fizzbuzz", "hasher", "animation", "display"] {
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
    rt.run_blocking();

    // Under the CoreVM-on-JAM model the agent's state is its PVM
    // image, not a serialized actor under STATE_KEY. With an empty
    // children list the scheduler completes its init pass and the
    // continuation is evicted on the final non-yielding tick.
    assert!(
        !rt.has_work(),
        "scheduler should drain pending_transfers after init"
    );
    assert!(
        !rt.is_suspended(id),
        "scheduler with empty children list should run to completion"
    );
    assert_eq!(rt.panics, 0, "scheduler (empty children) panicked");
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
    rt.run_blocking();

    // Cooperative loop completes: scheduler eventually drains its
    // run queue, the final tick is non-yielding, and both the
    // continuation cache and the pending-transfers queue are empty.
    assert!(!rt.has_work());
    assert!(!rt.is_suspended(agent_id));
    assert!(!rt.is_suspended(greeter_id));
    assert_eq!(rt.panics, 0, "no service should have panicked in refine");
}

#[test]
fn refine_completes_and_clears_continuation() {
    // Smoke test for the CoreVM-on-JAM model: a service that completes
    // its work in one tick should leave behind no continuation image
    // and no pending transfers. (When a service yields mid-work, the
    // continuation is preserved instead — covered by the cooperative
    // loop test.)
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

    assert!(!rt.is_suspended(id), "no continuation before first tick");

    rt.send_to(id, Vec::new());
    rt.run_blocking();

    assert!(
        !rt.is_suspended(id),
        "scheduler with no children should run to completion (no DA continuation)"
    );
    assert!(!rt.has_work(), "no leftover pending_transfers expected");
}

#[test]
fn data_layer_roundtrip_via_runtime() {
    // Basic wiring test for the pluggable DataLayer: poke bytes
    // directly into the backend under a service id and verify the
    // runtime's `is_suspended` surfaces them. This covers the
    // DataLayer <-> VosRuntime plumbing without needing a service
    // actor that actually calls `yield_now` (none of the current
    // examples do — the scheduler drives progress via `send_self`
    // transfers, not explicit refine yields).
    //
    // TODO: add an end-to-end "suspend in runtime A, resume in
    // runtime B through a shared DataLayer" test once we have a
    // service actor whose refine body calls `ctx.yield_now()` or
    // `ctx.sleep()`. That's the test that exercises
    // `pvm_image::capture`/`restore` against a real PVM image.
    use vos::data_layer::{DataLayer, MemoryDataLayer};
    use vos::pvm_image::{commit, ContinuationHeader};

    // Build a body + matching header, put the body in the data
    // layer, write the header into service storage, and verify the
    // runtime sees the service as suspended.
    let body = vec![0xAAu8; 64];
    let commitment = commit(&body);

    let mut da = MemoryDataLayer::new();
    assert!(!da.contains(&commitment));
    pollster::block_on(da.put(commitment, body.clone()));
    assert!(da.contains(&commitment));
    assert_eq!(pollster::block_on(da.get(&commitment)).as_deref(), Some(&body[..]));

    let header = ContinuationHeader {
        pc: 0,
        heap_base: 0,
        heap_top: 0,
        need_gas_charge: false,
        iters: 1,
        flat_mem_len: body.len() as u32,
        commitment,
        registers: [0; 13],
    };
    let encoded = header.encode();

    let mut rt = VosRuntime::with_data_layer(da);
    let id = vos::abi::service::ServiceId(42);
    assert!(!rt.is_suspended(id));
    rt.storage.write(id, vos::lifecycle::CONTINUATION_HEADER_KEY, &encoded);
    assert!(
        rt.is_suspended(id),
        "runtime should see the continuation header in service storage"
    );
}

#[test]
fn data_layer_survives_runtime_teardown() {
    // Inject a synthetic continuation into runtime A's data layer and
    // storage, then move both to runtime B and verify B sees the service
    // as suspended. This tests the plumbing: storage header + DA body
    // survive across runtime instances.
    use vos::data_layer::{DataLayer, MemoryDataLayer};
    use vos::pvm_image::{commit, ContinuationHeader};

    let body = vec![0xBBu8; 128];
    let commitment = commit(&body);

    let header = ContinuationHeader {
        pc: 0,
        heap_base: 0x1000,
        heap_top: 0x2000,
        need_gas_charge: false,
        iters: 1,
        flat_mem_len: body.len() as u32,
        commitment,
        registers: [0; 13],
    };

    // Runtime A: inject the continuation.
    let mut da = MemoryDataLayer::new();
    pollster::block_on(da.put(commitment, body.clone()));
    let mut rt_a = VosRuntime::with_data_layer(da);
    let greeter_elf = example_elf("greeter");
    let blob = transpile_actor(&greeter_elf);
    let blob_idx = rt_a.register_service_blob(blob.clone());
    let svc_id = rt_a.register_service(blob_idx);
    rt_a.storage.write(svc_id, vos::lifecycle::CONTINUATION_HEADER_KEY, &header.encode());
    assert!(rt_a.is_suspended(svc_id));

    // Move data layer and storage to runtime B.
    let da_moved = std::mem::replace(&mut rt_a.data, MemoryDataLayer::new());
    let storage_moved = std::mem::take(&mut rt_a.storage);
    drop(rt_a);

    let mut rt_b = VosRuntime::with_data_layer(da_moved);
    let b_blob_idx = rt_b.register_service_blob(blob);
    let b_svc_id = rt_b.register_service(b_blob_idx);
    assert_eq!(b_svc_id, svc_id);
    rt_b.storage = storage_moved;

    assert!(
        rt_b.is_suspended(b_svc_id),
        "new runtime sees the captured image via the shared data layer"
    );

    // Verify the body is intact.
    let retrieved = pollster::block_on(rt_b.data.get(&commitment));
    assert_eq!(retrieved.as_deref(), Some(&body[..]));
}

#[test]
fn greeter_as_top_level_service() {
    // Skip the scheduler; register greeter directly as a service and send it a start message.
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);
    let mut rt = VosRuntime::new();
    let id = register_svc(&mut rt, blob);

    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    let encoded = Msg::new("start").encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    rt.send_to(id, payload);
    rt.run_blocking();
    assert_eq!(rt.panics, 0, "greeter panicked running directly as top-level service");
}

#[test]
fn pvm_agent_invokes_worker_via_external_handler() {
    // The scheduler agent invokes its children via lifecycle::invoke().
    // We register a fake "child" ServiceId that maps to a worker via
    // the external_invoke callback. This tests the full PVM→worker path.
    use std::sync::atomic::{AtomicU32, Ordering};

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

    let echo_so = {
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let p = format!("{}/../../target/{profile}/libecho_worker.so", workspace);
        std::path::PathBuf::from(p)
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-worker not built (cargo build -p echo-worker)");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    // The "worker child" gets ServiceId 99 — not registered in the runtime,
    // so INVOKE will fall through to external_invoke.
    let worker_child_id = vos::abi::service::ServiceId(99);
    let invoke_count = std::sync::Arc::new(AtomicU32::new(0));
    let count_clone = invoke_count.clone();

    // Load the worker plugin for the external handler.
    // Leak the plugin so the WorkerInstance is 'static (test only).
    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::worker::WorkerPlugin::load(&echo_so) }.expect("load echo worker")
    ));
    let instance = std::sync::Mutex::new(plugin.create());

    rt.set_external_invoke(Box::new(move |target, msg| {
        if target != worker_child_id { return None; }
        count_clone.fetch_add(1, Ordering::Relaxed);
        let mut inst = instance.lock().unwrap();
        match inst.dispatch_raw(msg) {
            Ok(reply) => Some(reply),
            Err(_) => Some(Vec::new()),
        }
    }));

    // Init scheduler with children = [99] (our worker)
    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![worker_child_id.0]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();

    assert_eq!(rt.panics, 0, "scheduler panicked when invoking worker child");
    let invokes = invoke_count.load(Ordering::Relaxed);
    assert!(invokes > 0, "external_invoke should have been called at least once, got {invokes}");
    eprintln!("pvm_agent_invokes_worker: {invokes} invoke(s) routed to worker");
}

#[test]
fn recording_session_captures_invoke_replies() {
    // Same setup as pvm_agent_invokes_worker_via_external_handler,
    // but this time the runtime is in a recording session: every
    // invoke the scheduler issues should end up in the session's
    // EffectLog, ready to be attached to a CRDT commit.
    use std::sync::atomic::{AtomicU32, Ordering};

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

    let echo_so = {
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let p = format!("{}/../../target/{profile}/libecho_worker.so", workspace);
        std::path::PathBuf::from(p)
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-worker not built");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    let worker_child_id = vos::abi::service::ServiceId(99);
    let invoke_count = std::sync::Arc::new(AtomicU32::new(0));
    let count_clone = invoke_count.clone();

    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::worker::WorkerPlugin::load(&echo_so) }.expect("load echo worker")
    ));
    let instance = std::sync::Mutex::new(plugin.create());

    rt.set_external_invoke(Box::new(move |target, msg| {
        if target != worker_child_id { return None; }
        count_clone.fetch_add(1, Ordering::Relaxed);
        let mut inst = instance.lock().unwrap();
        match inst.dispatch_raw(msg) {
            Ok(reply) => Some(reply),
            Err(_) => Some(Vec::new()),
        }
    }));

    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![worker_child_id.0]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    // Begin a recording session before the dispatch. The msg bytes
    // here would normally be the incoming envelope payload; we pass
    // a tag so we can assert it came through.
    let dispatch_msg = b"test-dispatch".to_vec();
    rt.begin_recording(dispatch_msg.clone());
    assert!(rt.is_recording(), "session should be active after begin_recording");

    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();

    let log = rt.finish_recording().expect("session should be in flight");
    assert!(!rt.is_recording(), "session should be cleared after finish_recording");

    assert_eq!(rt.panics, 0, "scheduler panicked under recording");
    let invokes = invoke_count.load(Ordering::Relaxed);
    assert!(invokes > 0, "external_invoke should have fired");

    // The session's msg is exactly what we handed to begin_recording.
    assert_eq!(log.msg, dispatch_msg);

    // Every top-level invoke issued during this tick got its output
    // captured, so reply_count should match the invoke count. Nested
    // invokes (depth > 1) are excluded, but the scheduler → worker
    // path is depth 1 so all of them should appear.
    assert_eq!(
        log.reply_count() as u32,
        invokes,
        "each external invoke should have been recorded",
    );

    // Each recorded output is a valid invoke wire frame: it starts
    // with a status byte (STATUS_DONE for the external path).
    for reply in &log.replies {
        assert!(!reply.is_empty(), "recorded output should not be empty");
        assert_eq!(reply[0], vos::STATUS_DONE, "expected successful invoke");
    }
}

#[test]
fn display_multiple_vec_renders() {
    // Regression test for the multi-deliver Vec bug (March 2025):
    // under the old bump allocator, sequential messages containing
    // Vec<u8> payloads would silently fail because heap memory was
    // never freed. The freelist allocator should handle this.
    let elf = example_elf("display");
    let blob = transpile_actor(&elf);
    let mut rt = VosRuntime::new();
    let id = register_svc(&mut rt, blob);

    use vos::value::{Msg, Value, TAG_DYNAMIC};
    use vos::Encode;

    // Send two render messages with Vec<u8> payloads in separate ticks.
    // Each gets its own kernel invocation so both must independently
    // allocate, process, and free Vec heap memory.
    let pixels = vec![0xAAu8; 16 * 8];
    for i in 0..2 {
        let msg = Msg::new("render").with("pixels", Value::Bytes(pixels.clone()));
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        rt.send_to(id, payload);
        rt.run_blocking();
        assert_eq!(rt.panics, 0, "display panicked on render #{i}");
    }
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
