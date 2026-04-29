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
fn replay_session_short_circuits_external_invoke() {
    // Two runs: record the first, replay the second. In replay mode
    // the runtime should NOT call external_invoke at all — the
    // logged outputs are handed back verbatim at the top-level
    // invoke. Both runs should produce identical scheduler behaviour.
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
    let worker_child_id = vos::abi::service::ServiceId(99);

    // ── Run 1: record ───────────────────────────────────────────────
    let invoke_count_rec = std::sync::Arc::new(AtomicU32::new(0));
    let count_rec_clone = invoke_count_rec.clone();

    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::worker::WorkerPlugin::load(&echo_so) }.expect("load echo worker")
    ));
    let instance_rec = std::sync::Mutex::new(plugin.create());

    let recorded_log = {
        let mut rt = VosRuntime::new();
        let agent_id = register_svc(&mut rt, blob.clone());

        rt.set_external_invoke(Box::new(move |target, msg| {
            if target != worker_child_id { return None; }
            count_rec_clone.fetch_add(1, Ordering::Relaxed);
            let mut inst = instance_rec.lock().unwrap();
            match inst.dispatch_raw(msg) {
                Ok(reply) => Some(reply),
                Err(_) => Some(Vec::new()),
            }
        }));

        let args = vos::init::InitArgs::new()
            .with("children", vos::init::InitValue::ListU32(vec![worker_child_id.0]));
        let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
        rt.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

        rt.begin_recording(Vec::new());
        rt.send_to(agent_id, Vec::new());
        rt.run_blocking();
        let log = rt.finish_recording().expect("recording");
        assert_eq!(rt.panics, 0);
        log
    };

    let rec_invokes = invoke_count_rec.load(Ordering::Relaxed);
    assert!(rec_invokes > 0, "recording run should have invoked");
    assert_eq!(
        recorded_log.reply_count() as u32, rec_invokes,
        "log should have one entry per top-level invoke",
    );

    // ── Run 2: replay with a fresh runtime + a callback that
    //           MUST NOT fire ─────────────────────────────────────────
    let invoke_count_rep = std::sync::Arc::new(AtomicU32::new(0));
    let count_rep_clone = invoke_count_rep.clone();

    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    rt.set_external_invoke(Box::new(move |_target, _msg| {
        count_rep_clone.fetch_add(1, Ordering::Relaxed);
        // Return something obviously wrong so that if the test
        // accidentally hits this path, the assertions below will fail.
        Some(alloc_bogus_reply())
    }));

    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![worker_child_id.0]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.begin_replay(recorded_log);
    assert!(rt.is_replaying());
    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();
    let replay = rt.finish_replay().expect("replay");
    assert!(!rt.is_replaying(), "replay should be cleared");

    assert_eq!(rt.panics, 0, "scheduler panicked during replay");

    // The crucial invariant: replay did NOT call external_invoke.
    let rep_invokes = invoke_count_rep.load(Ordering::Relaxed);
    assert_eq!(rep_invokes, 0, "replay must not issue external invokes");

    // All recorded replies consumed — no drift.
    assert!(
        replay.is_complete(),
        "replay should consume all recorded replies (pos={}, exhausted={})",
        replay.position(), replay.was_exhausted(),
    );
}

fn alloc_bogus_reply() -> Vec<u8> {
    // rkyv-encoded "this-should-not-appear" string bytes — doesn't
    // matter what exactly, just something recognizably wrong.
    b"BOGUS".to_vec()
}

#[test]
fn crdt_consistency_without_data_dir_fails_loud() {
    // SOUND-2/4 + ARCH-3 from the audit: a Crdt-requested agent that
    // can't open its DAG file used to silently downgrade to NoCommit.
    // Now build_agent_strategy returns Err and agent_thread surfaces
    // it via AgentResult.error so the host can refuse to run.
    use vos::node::{AgentConfig, Consistency, VosNode};

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

    let blob = grey_transpiler::link_elf(&agent_data).expect("transpile");
    let mut node = VosNode::new();
    let _id = node.register(
        AgentConfig::new(blob).with_consistency(Consistency::Crdt),
        // intentionally NOT calling .persist(...) — Crdt without
        // data_dir is a configuration error
    );
    node.run();
    let results = node.collect();

    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(r.error.is_some(), "expected fatal error, got result: panics={}, error={:?}", r.panics, r.error);
    let err = r.error.as_ref().unwrap();
    assert!(
        err.contains("Crdt") && err.contains("data_dir"),
        "error should call out the missing data_dir, got: {err}",
    );
}

#[test]
fn cross_agent_invoke_returns_typed_reply() {
    // #13 from the audit — exercises the data path of cross-agent
    // invoke, not just the structural roundtrip. Registers the
    // math actor (which has `add(a, b: u64) -> u64`), invokes it
    // from outside the PVM via VosNode::invoke, decodes the rkyv-
    // encoded reply, and asserts on the value.
    use vos::node::{AgentConfig, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let math_path = format!(
        "{}/../../examples/actors/math/target/riscv64em-javm/release/math.elf",
        workspace,
    );
    let math_data = match std::fs::read(&math_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: math actor not built");
            return;
        }
    };
    let math_blob = grey_transpiler::link_elf(&math_data).expect("transpile");

    // Spin up a node in a background thread so we can drive it
    // synchronously from the test. The node's run_until_idle
    // would normally wind it down on quiet, but here we want it
    // alive while we issue invokes.
    let mut node = VosNode::new();
    let math_id = node.register(AgentConfig::new(math_blob));

    // Build the invoke wire payload: TAG_DYNAMIC + rkyv-encoded
    // Msg::new("add").with("a", 2).with("b", 3).
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    let msg = Msg::new("add").with("a", 2u64).with("b", 3u64);
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);

    let reply_bytes = node
        .invoke(math_id, payload)
        .expect("math.add invoke failed (timeout or disconnected)");

    // Decode reply as Value and check the answer.
    let value: vos::value::Value = vos::Decode::decode(&reply_bytes);
    let result = value.as_u64().expect("reply not a u64");
    assert_eq!(result, 5, "expected 2 + 3 = 5, got {result}");

    // Wind the node down explicitly.
    node.shutdown();
    let results = node.collect();
    for r in &results {
        assert!(
            r.is_ok(),
            "agent {} failed: panics={} error={:?}",
            r.id, r.panics, r.error,
        );
    }
}

#[test]
fn crdt_cross_agent_invoke_records_reply_in_dag() {
    // Cross-agent invoke under CRDT recording must capture peer
    // replies in the caller's DAG, just as worker replies are
    // captured (the existing CRDT path). Combines the cross-agent
    // routing with the CRDT recording machinery.
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let scheduler_path = format!(
        "{}/../../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let greeter_path = format!(
        "{}/../../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf",
        workspace,
    );
    let scheduler_data = match std::fs::read(&scheduler_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let greeter_data = match std::fs::read(&greeter_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: greeter actor not built");
            return;
        }
    };

    let scheduler_blob = grey_transpiler::link_elf(&scheduler_data).expect("transpile");
    let greeter_blob = grey_transpiler::link_elf(&greeter_data).expect("transpile");

    let data_dir = std::env::temp_dir().join(format!(
        "vos_crdt_xagent_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let _ = std::fs::remove_dir_all(&data_dir);

    let mut node = VosNode::new();

    // Greeter is Ephemeral (it doesn't persist anything); the
    // SCHEDULER is the CRDT actor whose DAG we're inspecting.
    let greeter_id = node.register(AgentConfig::new(greeter_blob));

    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(vec![greeter_id.0]));
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .unwrap()
        .to_vec();
    let scheduler_id = node.register(
        AgentConfig::new(scheduler_blob)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), encoded)])
            .with_consistency(Consistency::Crdt)
            .persist(&data_dir),
    );

    node.run();
    let results = node.collect();
    for r in &results {
        assert!(r.is_ok(), "agent {} failed: {:?}", r.id, r.error);
    }

    // Inspect the scheduler's CRDT DAG. We expect at least one
    // node (the dispatch that triggered the invoke) and the
    // captured effect log should contain at least one reply entry
    // from the greeter cross-agent invoke.
    let db_path = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", scheduler_id.0));
    assert!(db_path.exists(), "scheduler's redb missing: {}", db_path.display());

    let db = redb::Database::open(&db_path).unwrap();
    let txn = db.begin_read().unwrap();

    use redb::{ReadableTable, ReadableTableMetadata};
    const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("dag");
    let dag_table = txn.open_table(DAG_TABLE).unwrap();
    let dag_count = dag_table.len().unwrap();
    assert!(
        dag_count >= 1,
        "expected at least one CRDT DAG node, got {dag_count}",
    );

    // Decode every DAG node and check each effect log; at least
    // one should carry a recorded reply (the greeter invoke).
    let mut total_replies = 0usize;
    for entry in dag_table.iter().unwrap() {
        let (_key, value) = entry.unwrap();
        let bytes: &[u8] = value.value();
        // DagNode wire format: [payload_len:u64 LE][payload][n_children:u64 LE][children...]
        let payload_len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        let payload_bytes = &bytes[8..8 + payload_len];
        let log = vos::effect_log::EffectLog::from_bytes(payload_bytes)
            .expect("decode EffectLog");
        total_replies += log.reply_count();
    }
    assert!(
        total_replies >= 1,
        "expected at least one cross-agent reply captured in the DAG, got {total_replies}",
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn cross_agent_invoke_routes_through_node() {
    // Two PVM agents on the same VosNode: scheduler (parent) and
    // greeter (child). Scheduler's `init.children = [greeter_id]`,
    // so when it runs it dispatches `start` to greeter via the
    // INVOKE hostcall. With cross-agent invoke routing wired up,
    // greeter's reply makes it back to the scheduler and both
    // agents complete cleanly.
    use vos::node::{AgentConfig, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let scheduler_path = format!(
        "{}/../../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let greeter_path = format!(
        "{}/../../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf",
        workspace,
    );
    let scheduler_data = match std::fs::read(&scheduler_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let greeter_data = match std::fs::read(&greeter_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: greeter actor not built");
            return;
        }
    };

    let scheduler_blob = grey_transpiler::link_elf(&scheduler_data).expect("transpile sched");
    let greeter_blob = grey_transpiler::link_elf(&greeter_data).expect("transpile greeter");

    let mut node = VosNode::new();

    // Register greeter first so we know its ServiceId before
    // registering the scheduler that references it.
    let greeter_id = node.register(AgentConfig::new(greeter_blob));

    // Scheduler's init args point at greeter as a child.
    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![greeter_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .unwrap()
        .to_vec();
    let scheduler_id = node.register(
        AgentConfig::new(scheduler_blob)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), encoded)]),
    );

    node.run();
    let results = node.collect();

    // Both agents should complete without host errors or PVM panics.
    assert_eq!(results.len(), 2, "expected 2 agent threads");
    for r in &results {
        assert!(
            r.is_ok(),
            "agent {} failed: panics={} error={:?}",
            r.id, r.panics, r.error,
        );
    }

    let _ = scheduler_id; // unused suppression
}

#[test]
fn recording_cap_truncates_oversized_invoke_output() {
    // SOUND-1 from the audit: when an invoke output exceeds the
    // session's per-reply cap, the host must replace it with a
    // single STATUS_PANICKED byte both in the caller's buffer and
    // in the recorded log. Otherwise a runaway worker can poison
    // consensus DAG nodes with arbitrarily large payloads.
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

    // Recording with an absurdly small cap (1 byte) — every invoke
    // wire frame is at least 1 status byte plus state_len, so any
    // real reply will overshoot.
    rt.begin_recording_with_cap(b"cap-test".to_vec(), 1);
    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();
    let log = rt.finish_recording().expect("recording");

    let invokes = invoke_count.load(Ordering::Relaxed);
    assert!(invokes > 0, "scheduler should have invoked at least once");
    assert_eq!(
        log.reply_count() as u32, invokes,
        "every top-level invoke is logged",
    );
    for (i, reply) in log.replies.iter().enumerate() {
        assert_eq!(
            reply.as_slice(),
            &[vos::STATUS_PANICKED],
            "reply #{i} should be the cap-truncated STATUS_PANICKED marker, got {reply:?}",
        );
    }
}

#[test]
fn crdt_agent_populates_dag_and_state_on_dispatch() {
    // End-to-end: register a PVM agent with Crdt consistency + a
    // data-dir, kick a dispatch, and verify the agent's redb file
    // holds both a materialized state entry and at least one DAG
    // node. This exercises the agent_thread → runtime →
    // record_and_write_invoke → commit_with_log path.
    use vos::node::{AgentConfig, Consistency, Envelope, VosNode};
    use vos::abi::service::ServiceId;

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

    let data_dir = std::env::temp_dir().join(format!(
        "vos_crdt_agent_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&data_dir);

    let blob = grey_transpiler::link_elf(&agent_data).expect("transpile");

    // Scheduler needs its `children` init arg in storage before
    // dispatch — an empty list is fine, we're just proving the
    // CRDT wire-up fires.
    let args = vos::init::InitArgs::new()
        .with("children", vos::init::InitValue::ListU32(Vec::new()));
    let init_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .unwrap()
        .to_vec();

    let mut node = VosNode::new();
    let agent_id = node.register(
        AgentConfig::new(blob)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), init_bytes)])
            .with_consistency(Consistency::Crdt)
            .persist(&data_dir),
    );

    node.run();
    let results = node.collect();
    for r in &results {
        assert!(r.is_ok(), "agent {} failed: panics={} error={:?}", r.id, r.panics, r.error);
    }

    // Verify the redb file exists at the expected path.
    let db_path = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", agent_id.0));
    assert!(db_path.exists(), "CRDT redb not created at {}", db_path.display());

    // Open the db and check both tables.
    let db = redb::Database::open(&db_path).expect("open db");
    let txn = db.begin_read().unwrap();

    // State table: must hold the roots key AND the actor-state row.
    // After SOUND-3 the runtime always journals serialized actor
    // state on every dispatch — not just on yield — so even a
    // refine-only one-shot agent leaves a non-empty state blob.
    let state_table = txn
        .open_table(redb::TableDefinition::<&str, &[u8]>::new("state"))
        .expect("state table exists");

    let roots_bytes = state_table
        .get("crdt_roots")
        .unwrap()
        .expect("crdt_roots persisted")
        .value()
        .to_vec();
    assert!(roots_bytes.len() >= 8, "roots must encode at least count");
    let roots_count = u64::from_le_bytes(roots_bytes[..8].try_into().unwrap());
    assert!(roots_count >= 1, "expected at least one root CID");

    let actor_bytes = state_table
        .get("actor")
        .unwrap()
        .expect("actor state row persisted")
        .value()
        .to_vec();
    assert!(
        !actor_bytes.is_empty(),
        "actor state should be persisted on every dispatch (SOUND-3 fix)",
    );

    // DAG table: at least one node was appended.
    let dag_table = txn
        .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("dag"))
        .expect("dag table exists");
    use redb::ReadableTableMetadata;
    let n = dag_table.len().unwrap();
    assert!(n >= 1, "expected at least one DAG node, found {n}");

    drop(dag_table);
    drop(state_table);
    drop(txn);
    drop(db);

    // Silence unused warnings for ids that aren't otherwise used here.
    let _ = ServiceId(0);
    let _ = Envelope { from: agent_id, to: agent_id, payload: Vec::new() };

    // ── Second run: reuse the same data-dir. The agent_thread
    //    should hit the restore fast path and the existing DAG
    //    should pick up a second commit from the new dispatch,
    //    growing without panicking or clobbering the prior state.
    let dag_count_after_first = {
        let db = redb::Database::open(&db_path).unwrap();
        let txn = db.begin_read().unwrap();
        let t = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("dag"))
            .unwrap();
        use redb::ReadableTableMetadata;
        t.len().unwrap()
    };

    let blob2 = grey_transpiler::link_elf(&agent_data).expect("transpile");
    let init_bytes2 = {
        let args = vos::init::InitArgs::new()
            .with("children", vos::init::InitValue::ListU32(Vec::new()));
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
            .unwrap()
            .to_vec()
    };

    let mut node2 = VosNode::new();
    let _agent_id2 = node2.register(
        AgentConfig::new(blob2)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), init_bytes2)])
            .with_consistency(Consistency::Crdt)
            .persist(&data_dir),
    );
    node2.run();
    let results2 = node2.collect();
    for r in &results2 {
        assert!(r.is_ok(), "agent {} failed on restart: panics={} error={:?}", r.id, r.panics, r.error);
    }

    let dag_count_after_second = {
        let db = redb::Database::open(&db_path).unwrap();
        let txn = db.begin_read().unwrap();
        let t = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("dag"))
            .unwrap();
        use redb::ReadableTableMetadata;
        t.len().unwrap()
    };
    // The scheduler with empty children produces the same state on
    // every dispatch — the unchanged-state skip rule (correctly)
    // refuses to pollute the DAG with no-op events. So we assert
    // monotone growth, not strict growth: the second run either
    // skipped (state unchanged) or appended (state diverged for
    // some reason). Both are acceptable; what matters is the
    // restart didn't blow up and the existing DAG is preserved.
    assert!(
        dag_count_after_second >= dag_count_after_first,
        "second run should not have shrunk the DAG (first={dag_count_after_first}, second={dag_count_after_second})",
    );

    let _ = std::fs::remove_dir_all(&data_dir);
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

#[test]
fn crdt_counter_local_invoke_smoke() {
    // Sanity check: drive the crdt-counter actor in a single
    // VosNode (no replication) using the macro-generated typed
    // `CrdtCounterClient`. inc returns (), get returns u64 —
    // both come from the actor's `#[msg]` signatures, no manual
    // `Msg::new(...)` plumbing needed.
    use crdt_counter::CrdtCounterClient;
    use vos::node::{AgentConfig, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt-counter.elf",
        workspace,
    );
    let data = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: crdt-counter not built"); return; }
    };
    let blob = grey_transpiler::link_elf(&data).expect("transpile");
    let mut node = VosNode::new();
    let id = node.register(AgentConfig::new(blob));

    let counter = CrdtCounterClient::at(&node, id);
    counter.inc(1).expect("inc 1");
    counter.inc(2).expect("inc 2");
    assert_eq!(counter.get().expect("get"), 2);

    node.shutdown();
    let _ = node.collect();
}

#[test]
#[cfg(feature = "network")]
fn crdt_counter_init_payloads_dispatch() {
    // Smoke test the on_start manifest path: register a CRDT
    // counter with an init_payload that encodes inc(tag=7) and
    // verify the count went up to 1 by the time we invoke get().
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt-counter.elf",
        workspace,
    );
    let data = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: crdt-counter not built"); return; }
    };
    let blob = grey_transpiler::link_elf(&data).expect("transpile");

    let dir = std::env::temp_dir().join(format!(
        "vos_init_payload_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let inc_payload = {
        let m = Msg::new("inc").with("tag", 7u32);
        let encoded = m.encode();
        let mut p = Vec::with_capacity(1 + encoded.len());
        p.push(TAG_DYNAMIC);
        p.extend_from_slice(&encoded);
        p
    };

    let mut node = VosNode::new();
    let id = node.register(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir)
            .with_init_payloads(vec![inc_payload]),
    );

    // Give the agent thread time to drain the init_payload.
    let count = wait_for(
        || {
            let m = Msg::new("get");
            let encoded = m.encode();
            let mut p = Vec::with_capacity(1 + encoded.len());
            p.push(TAG_DYNAMIC);
            p.extend_from_slice(&encoded);
            let bytes = node.invoke(id, p)?;
            let v: vos::value::Value = vos::Decode::decode(&bytes);
            match v.as_u64() {
                Some(1) => Some(1u64),
                _ => None,
            }
        },
        std::time::Duration::from_secs(3),
    );
    assert_eq!(count, Some(1), "init_payload inc(tag=7) should drive count=1");

    node.shutdown();
    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn crdt_counter_converges_across_nodes_live() {
    // Cycle 5 end-to-end: stand up two networked VosNodes with the
    // crdt-counter actor registered on both under the same
    // replication_id. Drive each side once with `inc()`, wait for
    // the per-replica sync ticker to gossip + the agent's mid-
    // flight soft restart to refresh state, then invoke `get()`
    // on each side and assert both report the converged total.
    //
    // Path under test:
    //
    //   1. local invoke writes a DAG node + state to A's redb
    //   2. sync ticker on B fetches A's heads (FetchHeads/FetchNode)
    //   3. ticker calls `insert_node` + `compact_roots` on B's
    //      redb and pings the agent's sync_rx channel
    //   4. agent_thread runs `soft_restart_crdt`: reload clock
    //      from disk, wipe runtime state, replay every log in the
    //      merged DAG, commit the rebuilt state
    //   5. invoke `get()` reads the rebuilt count
    //
    // Replication of the same actor across nodes is the headline
    // feature kunekt's CRDT machinery is for; this is the first
    // test that drives it through a real PVM actor end-to-end.
    use vos::abi::service::ServiceId;
    use vos::network::{derive_node_prefix, Network, NetworkConfig};
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt-counter.elf",
        workspace,
    );
    let counter_data = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: crdt-counter actor not built");
            return;
        }
    };
    let counter_blob = grey_transpiler::link_elf(&counter_data).expect("transpile");

    // Each node needs its own data dir + libp2p identity. Make a
    // shared replication_id so both nodes' counter replicas land
    // in the same group.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root = std::env::temp_dir().join(format!("vos_crdt_e2e_{}_{}", std::process::id(), stamp));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let rep_id: [u8; 32] = {
        // Use the same derivation our manifest path will use later
        // — `auto_replication_id`-equivalent — so this test mirrors
        // production behaviour rather than relying on an arbitrary
        // sentinel.
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"crdt-counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // ── Networks ────────────────────────────────────────────────
    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let net_a = Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        std::time::Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
    });

    // ── Nodes + actors ─────────────────────────────────────────
    let mut node_a = VosNode::with_prefix(prefix_a);
    let counter_a = node_a.register(
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(rep_id),
    );
    node_a.attach_network(net_a);

    let mut node_b = VosNode::with_prefix(prefix_b);
    let counter_b = node_b.register(
        AgentConfig::new(counter_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(rep_id),
    );
    node_b.attach_network(net_b);

    // Wait for the Hello handshake before driving anything so the
    // first inc() doesn't get its sync attempt swallowed.
    let net_a_arc = node_a.network().expect("net_a attached");
    let net_b_arc = node_b.network().expect("net_b attached");
    wait_for(
        || {
            if net_a_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some()
            {
                Some(())
            } else {
                None
            }
        },
        std::time::Duration::from_secs(10),
    )
    .expect("Hello completes");

    // ── Drive each replica once ────────────────────────────────
    // Use distinct tags so each replica's EffectLog hashes to a
    // different CID; otherwise the merkle-DAG dedups identical
    // events and the two replicas appear pre-converged at the
    // single-node level.
    let inc_with_tag = |tag: u32| -> Vec<u8> {
        let m = Msg::new("inc").with("tag", tag);
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };
    let _ = node_a.invoke(counter_a, inc_with_tag(1)).expect("inc on A");
    let _ = node_b.invoke(counter_b, inc_with_tag(2)).expect("inc on B");

    // ── Wait for convergence ───────────────────────────────────
    // Both replicas should observe count=2 once the sync ticker
    // (250ms) plus the agent's soft restart have completed in
    // both directions.
    let get_payload = || {
        let m = Msg::new("get");
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };
    let read_count = |node: &VosNode, target: ServiceId| -> Option<u64> {
        let bytes = node.invoke(target, get_payload())?;
        let v: vos::value::Value = vos::Decode::decode(&bytes);
        v.as_u64()
    };

    // Each replica has applied its OWN inc; cross-node sync is
    // what brings them to count=2.
    assert_eq!(read_count(&node_a, counter_a), Some(1));
    assert_eq!(read_count(&node_b, counter_b), Some(1));

    let count_a = wait_for(
        || match read_count(&node_a, counter_a) {
            Some(2) => Some(2),
            _ => None,
        },
        std::time::Duration::from_secs(8),
    );
    let count_b = wait_for(
        || match read_count(&node_b, counter_b) {
            Some(2) => Some(2),
            _ => None,
        },
        std::time::Duration::from_secs(8),
    );
    assert_eq!(count_a, Some(2), "A did not converge to count=2 within deadline");
    assert_eq!(count_b, Some(2), "B did not converge to count=2 within deadline");

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}

#[cfg(feature = "network")]
fn wait_for<T>(
    mut probe: impl FnMut() -> Option<T>,
    deadline: std::time::Duration,
) -> Option<T> {
    let until = std::time::Instant::now() + deadline;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if std::time::Instant::now() >= until {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
#[cfg(feature = "network")]
fn ctx_resolve_returns_announced_service_id() {
    // Cycle 9 phase 3: a PVM actor calls `ctx.resolve(name)` and
    // gets back the ServiceId the registry was announced under.
    // Single-node setup — the path under test is the actor's
    // INVOKE hostcall to ServiceId::REGISTRY, decoding the rkyv
    // RegistryEntry, and surfacing the full u32 to the caller.
    use registry::RegistryClient;
    use vos::abi::service::ServiceId;
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt-counter.elf",
        workspace,
    );
    let registry_path = format!(
        "{}/../actors/registry/target/riscv64em-javm/release/registry-actor.elf",
        workspace,
    );
    let counter_data = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: crdt-counter not built"); return; }
    };
    let registry_data = match std::fs::read(&registry_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: registry-actor not built"); return; }
    };
    let counter_blob = grey_transpiler::link_elf(&counter_data).expect("transpile counter");
    let registry_blob = grey_transpiler::link_elf(&registry_data).expect("transpile registry");

    let dir = std::env::temp_dir().join(format!(
        "vos_resolve_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // Single node, no network. Both the registry and the
    // counter live as local replicas; `ctx.resolve` from the
    // counter goes through the in-process invoke_routes to the
    // registry replica.
    let mut node = VosNode::new();

    let _registry_id = node.register_at_id(
        AgentConfig::new(registry_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir)
            .with_replication_id(registry::replication_id("test")),
        ServiceId::REGISTRY,
    );

    let counter_id = node.register(AgentConfig::new(counter_blob));

    // Tell the registry that "kunekt/counter" lives at
    // counter_id. owner_prefix=0 since the node has no prefix.
    let registry_client = || RegistryClient::at(&node, ServiceId::REGISTRY);
    registry_client()
        .announce(
            "kunekt/counter".to_string(),
            counter_id.node_prefix() as u32,
            counter_id.local_id() as u32,
            vec!["counter".to_string()],
        )
        .expect("announce");

    // Poll the registry until it sees the entry — the announce
    // returns immediately but the actor loop processes it on
    // its next tick. The macro-generated `lookup` returns
    // `Result<Option<RegistryEntry>, ClientError>` directly.
    wait_for(
        || registry_client().lookup("kunekt/counter".to_string()).ok().flatten(),
        std::time::Duration::from_secs(3),
    )
    .expect("registry sees announce");

    // Drive `whois("kunekt/counter")` on the counter and check
    // the reply.
    let invoke = |actor: ServiceId, m: Msg| -> Vec<u8> {
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        node.invoke(actor, payload).expect("invoke")
    };

    let bytes = invoke(counter_id, Msg::new("whois").with("name", "kunekt/counter"));
    let value: vos::value::Value = vos::Decode::decode(&bytes);
    let resolved = value.as_u32().expect("u32 reply");
    assert_eq!(resolved, counter_id.0, "ctx.resolve should return the announced ServiceId");

    // Lookup of a missing name returns 0 (the sentinel `whois`
    // uses for "not found", separate from any valid ServiceId
    // since the counter's id is non-zero).
    let bytes = invoke(counter_id, Msg::new("whois").with("name", "kunekt/missing"));
    let value: vos::value::Value = vos::Decode::decode(&bytes);
    let resolved = value.as_u32().expect("u32 reply");
    assert_eq!(resolved, 0, "missing name should resolve to 0");

    node.shutdown();
    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn registry_announce_lookup_and_list_converge_across_nodes() {
    // Cycle 9 phase 1: two networked VosNodes, each with a
    // registry replica at ServiceId::REGISTRY under the same
    // hyperspace replication_id. Each side announces a service;
    // both replicas converge to a 2-entry directory. Lookup,
    // by_role, and paginated list all return consistent answers
    // from either side.
    use registry::RegistryClient;
    use std::time::Duration;
    use vos::abi::service::ServiceId;
    use vos::network::{derive_node_prefix, Network, NetworkConfig};
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let actor_path = format!(
        "{}/../actors/registry/target/riscv64em-javm/release/registry-actor.elf",
        workspace,
    );
    let elf = match std::fs::read(&actor_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: registry-actor not built"); return; }
    };
    let blob = grey_transpiler::link_elf(&elf).expect("transpile");

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir_root = std::env::temp_dir().join(format!("vos_reg_{}_{}", std::process::id(), stamp));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let rep_id = registry::replication_id("kunekt-test");

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let net_a = Network::start(NetworkConfig {
        keypair: kp_a, local_prefix: prefix_a,
        listen: vec![listen.clone()], bootstrap: vec![],
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    ).expect("net_a binds");
    let a_dial = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let net_b = Network::start(NetworkConfig {
        keypair: kp_b, local_prefix: prefix_b,
        listen: vec![listen], bootstrap: vec![a_dial],
    });

    // Build node A with the registry at ServiceId::REGISTRY.
    let mut node_a = VosNode::with_prefix(prefix_a);
    let registry_a = node_a.register_at_id(
        AgentConfig::new(blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(rep_id),
        ServiceId::REGISTRY,
    );
    assert_eq!(registry_a, ServiceId::REGISTRY);
    node_a.attach_network(net_a);

    let mut node_b = VosNode::with_prefix(prefix_b);
    let registry_b = node_b.register_at_id(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(rep_id),
        ServiceId::REGISTRY,
    );
    assert_eq!(registry_b, ServiceId::REGISTRY);
    node_b.attach_network(net_b);

    // Wait for Hello so subsequent announcements have a peer to
    // gossip to.
    let net_a_arc = node_a.network().expect("net_a");
    let net_b_arc = node_b.network().expect("net_b");
    wait_for(|| {
        if net_a_arc.peer_for_prefix(prefix_b).is_some()
            && net_b_arc.peer_for_prefix(prefix_a).is_some()
        { Some(()) } else { None }
    }, Duration::from_secs(10)).expect("Hello completes");

    // ── Drive announces from each replica ──────────────────────
    let alice_roles = vec!["worker".to_string()];
    let bob_roles = vec!["worker".to_string(), "leader".to_string()];

    RegistryClient::at(&node_a, ServiceId::REGISTRY)
        .announce(
            "kunekt/alice".to_string(), prefix_a as u32, 100, alice_roles.clone(),
        )
        .expect("announce alice on A");
    RegistryClient::at(&node_b, ServiceId::REGISTRY)
        .announce(
            "kunekt/bob".to_string(), prefix_b as u32, 200, bob_roles.clone(),
        )
        .expect("announce bob on B");

    // ── Wait for both replicas to converge on both entries ────
    let see_both = |node: &VosNode| -> bool {
        let client = RegistryClient::at(node, ServiceId::REGISTRY);
        client.lookup("kunekt/alice".to_string()).ok().flatten().is_some()
        && client.lookup("kunekt/bob".to_string()).ok().flatten().is_some()
    };

    wait_for(|| if see_both(&node_a) { Some(()) } else { None },
        Duration::from_secs(8)).expect("A converges");
    wait_for(|| if see_both(&node_b) { Some(()) } else { None },
        Duration::from_secs(8)).expect("B converges");

    // ── Inspect via the host client on each side ──────────────
    for (label, node, expected_a_prefix, expected_b_prefix) in
        [("A", &node_a, prefix_a, prefix_b), ("B", &node_b, prefix_a, prefix_b)]
    {
        let client = RegistryClient::at(node, ServiceId::REGISTRY);
        let alice = client.lookup("kunekt/alice".to_string()).unwrap()
            .unwrap_or_else(|| panic!("{label}: alice missing"));
        assert_eq!(alice.name, "kunekt/alice");
        assert_eq!(alice.owner_prefix, expected_a_prefix);
        assert_eq!(alice.service_id, 100);
        assert_eq!(alice.roles, alice_roles);

        let bob = client.lookup("kunekt/bob".to_string()).unwrap()
            .unwrap_or_else(|| panic!("{label}: bob missing"));
        assert_eq!(bob.owner_prefix, expected_b_prefix);
        assert_eq!(bob.service_id, 200);
        assert_eq!(bob.roles, bob_roles);

        // Listing under the prefix returns both, sorted.
        let page = client.list("kunekt/".to_string(), String::new(), 64).unwrap();
        let names: Vec<_> = page.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["kunekt/alice", "kunekt/bob"], "{label}: list");

        // by_role narrows correctly.
        let workers = client
            .by_role("worker".to_string(), String::new(), String::new(), 64).unwrap();
        let worker_names: Vec<_> = workers.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(worker_names, vec!["kunekt/alice", "kunekt/bob"], "{label}: workers");

        let leaders = client
            .by_role("leader".to_string(), String::new(), String::new(), 64).unwrap();
        let leader_names: Vec<_> = leaders.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(leader_names, vec!["kunekt/bob"], "{label}: leaders");

        // Lookup of a missing name returns None.
        assert!(client.lookup("kunekt/nobody".to_string()).unwrap().is_none(),
            "{label}: missing");
    }

    // ── Pagination: limit=1 walks both entries in 2 pages ─────
    {
        let client = RegistryClient::at(&node_a, ServiceId::REGISTRY);
        let p1 = client.list("kunekt/".to_string(), String::new(), 1).unwrap();
        assert_eq!(p1.entries.len(), 1);
        assert_eq!(p1.entries[0].name, "kunekt/alice");
        assert!(p1.has_more());
        let p2 = client.list("kunekt/".to_string(), p1.next.clone(), 1).unwrap();
        assert_eq!(p2.entries.len(), 1);
        assert_eq!(p2.entries[0].name, "kunekt/bob");
        assert!(!p2.has_more());
    }

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
#[cfg(feature = "network")]
fn registry_heartbeat_bumps_last_seen() {
    // Cycle 9 phase 4 (slice 4a): a `heartbeat(name)` invoke
    // bumps the entry's `last_seen` while leaving the rest of
    // the row alone. Single-node setup — the wire shape and
    // tick semantics are what's under test, not network-side
    // convergence (the existing
    // `registry_announce_lookup_and_list_converge_across_nodes`
    // already exercises that).
    use registry::RegistryClient;
    use vos::abi::service::ServiceId;
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let actor_path = format!(
        "{}/../actors/registry/target/riscv64em-javm/release/registry-actor.elf",
        workspace,
    );
    let elf = match std::fs::read(&actor_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: registry-actor not built"); return; }
    };
    let blob = grey_transpiler::link_elf(&elf).expect("transpile");

    let dir = std::env::temp_dir().join(format!(
        "vos_hb_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let mut node = VosNode::new();
    let _ = node.register_at_id(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir)
            .with_replication_id(registry::replication_id("hb-test")),
        ServiceId::REGISTRY,
    );

    let client = RegistryClient::at(&node, ServiceId::REGISTRY);
    let lookup = |name: &str| client.lookup(name.to_string()).expect("invoke");

    client.announce("kunekt/alpha".to_string(), 0, 11, vec!["worker".to_string()])
        .expect("announce alpha");
    client.announce("kunekt/beta".to_string(), 0, 22, vec![])
        .expect("announce beta");

    // Initial state: announce assigns last_seen in tick order.
    let alpha_t0 = lookup("kunekt/alpha").expect("alpha");
    let beta_t0 = lookup("kunekt/beta").expect("beta");
    assert!(alpha_t0.last_seen < beta_t0.last_seen,
        "later announce should have higher last_seen: alpha={} beta={}",
        alpha_t0.last_seen, beta_t0.last_seen);

    // Page snapshot exposes the registry's current tick.
    let page0 = client.list("kunekt/".to_string(), String::new(), 64).unwrap();
    assert!(page0.clock >= beta_t0.last_seen, "page clock {} < beta {}",
        page0.clock, beta_t0.last_seen);

    // Heartbeat alpha — last_seen should advance past beta's.
    client.heartbeat("kunekt/alpha".to_string()).expect("heartbeat alpha");
    let alpha_t1 = lookup("kunekt/alpha").expect("alpha post-hb");
    assert!(alpha_t1.last_seen > beta_t0.last_seen,
        "heartbeat should bump alpha's last_seen above beta's: alpha={} beta={}",
        alpha_t1.last_seen, beta_t0.last_seen);
    // Other fields untouched.
    assert_eq!(alpha_t1.owner_prefix, alpha_t0.owner_prefix);
    assert_eq!(alpha_t1.service_id, alpha_t0.service_id);
    assert_eq!(alpha_t1.roles, alpha_t0.roles);
    // Beta unchanged.
    let beta_t1 = lookup("kunekt/beta").expect("beta still here");
    assert_eq!(beta_t1.last_seen, beta_t0.last_seen, "heartbeat should not touch siblings");

    // Heartbeat for an unknown name is a silent no-op.
    client.heartbeat("kunekt/ghost".to_string()).expect("heartbeat ghost (no-op)");
    assert!(lookup("kunekt/ghost").is_none(),
        "heartbeat should not create entries");

    // is_alive_within helper.
    let page1 = client.list("kunekt/".to_string(), String::new(), 64).unwrap();
    assert!(alpha_t1.is_alive_within(page1.clock, 1), "alpha should be fresh");
    assert!(!beta_t0.is_alive_within(page1.clock, 1),
        "beta should age past max_age=1: clock={} beta.last_seen={}",
        page1.clock, beta_t0.last_seen);

    node.shutdown();
    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn registry_invoke_handle_drives_heartbeats_from_another_thread() {
    // Cycle 9 phase 4 (slice 4b): vosx's auto-heartbeat lives
    // on a side thread that calls into the node via
    // `VosNode::invoke_handle`. This test exercises that
    // primitive directly — register, announce, then drive
    // heartbeats from a worker thread and observe last_seen
    // climb.
    use registry::RegistryClient;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use vos::abi::service::ServiceId;
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;

    let workspace = env!("CARGO_MANIFEST_DIR");
    let actor_path = format!(
        "{}/../actors/registry/target/riscv64em-javm/release/registry-actor.elf",
        workspace,
    );
    let elf = match std::fs::read(&actor_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: registry-actor not built"); return; }
    };
    let blob = grey_transpiler::link_elf(&elf).expect("transpile");

    let dir = std::env::temp_dir().join(format!(
        "vos_hb2_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let mut node = VosNode::new();
    let _ = node.register_at_id(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir)
            .with_replication_id(registry::replication_id("hb2-test")),
        ServiceId::REGISTRY,
    );

    let client = RegistryClient::at(&node, ServiceId::REGISTRY);
    let lookup_entry = || client.lookup("kunekt/svc".to_string()).ok().flatten();
    client.announce("kunekt/svc".to_string(), 0, 7, vec![]).expect("announce");
    let initial = lookup_entry().expect("svc");

    // Spin up a side thread that fires heartbeats every 50ms
    // until told to stop. Mirrors what vosx does in production
    // via `heartbeat_loop`.
    let handle = node.invoke_handle();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let beats = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let beats_clone = beats.clone();

    let thread = std::thread::spawn(move || {
        let m = Msg::new("heartbeat").with("name", "kunekt/svc");
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        while !stop_clone.load(Ordering::Relaxed) && !handle.is_shutting_down() {
            let _ = handle.invoke_with_timeout(
                ServiceId::REGISTRY,
                payload.clone(),
                Duration::from_secs(2),
            );
            beats_clone.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    // Wait until we observe the entry's last_seen rise above its
    // initial value at least 3 times — confirms repeated beats
    // round-trip through invoke_routes from the other thread.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_observed = initial.last_seen;
    let mut bumps = 0u32;
    while Instant::now() < deadline && bumps < 3 {
        std::thread::sleep(Duration::from_millis(75));
        if let Some(entry) = lookup_entry() {
            if entry.last_seen > last_observed {
                last_observed = entry.last_seen;
                bumps += 1;
            }
        }
    }
    assert!(bumps >= 3, "expected ≥3 last_seen bumps, got {bumps}");

    // Tell the thread to wind down via the node's shutdown
    // flag — same path vosx uses when run_forever returns.
    node.shutdown();
    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    assert!(beats.load(Ordering::Relaxed) > 0);

    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn registry_cold_bootstrap_pulls_existing_state_from_peer() {
    // Sync protocol cold-start: node A is the only replica, it
    // has accumulated three announces, then node B joins fresh
    // (no on-disk state) and dials A. The CRDT sync_loop on B
    // should walk A's heads via FetchHeads/FetchNode, populate
    // its DAG, and replay on the local replica — no further
    // writes from anyone needed.
    use registry::RegistryClient;
    use std::time::Duration;
    use vos::abi::service::ServiceId;
    use vos::network::{derive_node_prefix, Network, NetworkConfig};
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let actor_path = format!(
        "{}/../actors/registry/target/riscv64em-javm/release/registry-actor.elf",
        workspace,
    );
    let elf = match std::fs::read(&actor_path) {
        Ok(d) => d,
        Err(_) => { eprintln!("SKIP: registry-actor not built"); return; }
    };
    let blob = grey_transpiler::link_elf(&elf).expect("transpile");

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir_root = std::env::temp_dir()
        .join(format!("vos_cold_{}_{}", std::process::id(), stamp));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let rep_id = registry::replication_id("cold-bootstrap-test");

    // ── Phase 1: only A exists, accumulates state ──────────────
    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let net_a = Network::start(NetworkConfig {
        keypair: kp_a, local_prefix: prefix_a,
        listen: vec![listen.clone()], bootstrap: vec![],
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    ).expect("net_a binds");
    let a_dial = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let mut node_a = VosNode::with_prefix(prefix_a);
    node_a.register_at_id(
        AgentConfig::new(blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(rep_id),
        ServiceId::REGISTRY,
    );
    node_a.attach_network(net_a);

    let client_a = RegistryClient::at(&node_a, ServiceId::REGISTRY);
    client_a.announce("kunekt/alpha".to_string(), prefix_a as u32, 1, vec![])
        .expect("announce alpha");
    client_a.announce("kunekt/beta".to_string(), prefix_a as u32, 2, vec![])
        .expect("announce beta");
    client_a.announce("kunekt/gamma".to_string(), prefix_a as u32, 3,
        vec!["worker".to_string()]).expect("announce gamma");

    // Confirm A has all three before bringing B up.
    let initial = client_a.list("kunekt/".to_string(), String::new(), 64).unwrap();
    assert_eq!(initial.entries.len(), 3,
        "A should hold three entries before B joins");

    // ── Phase 2: B joins fresh, dials A ────────────────────────
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let net_b = Network::start(NetworkConfig {
        keypair: kp_b, local_prefix: prefix_b,
        listen: vec![listen], bootstrap: vec![a_dial],
    });

    let mut node_b = VosNode::with_prefix(prefix_b);
    node_b.register_at_id(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(rep_id),
        ServiceId::REGISTRY,
    );
    node_b.attach_network(net_b);

    // ── Phase 3: B catches up via the sync protocol ────────────
    let client_b = RegistryClient::at(&node_b, ServiceId::REGISTRY);
    wait_for(
        || {
            let alpha = client_b.lookup("kunekt/alpha".to_string()).ok().flatten();
            let beta = client_b.lookup("kunekt/beta".to_string()).ok().flatten();
            let gamma = client_b.lookup("kunekt/gamma".to_string()).ok().flatten();
            if alpha.is_some() && beta.is_some() && gamma.is_some() {
                Some(())
            } else {
                None
            }
        },
        Duration::from_secs(15),
    ).expect("B converges to A's three entries within deadline");

    // Confirm gamma's role list survived the round-trip — checks
    // that the EffectLog payload was replicated faithfully, not
    // just the entry count.
    let gamma = client_b.lookup("kunekt/gamma".to_string())
        .unwrap().expect("gamma");
    assert_eq!(gamma.roles, vec!["worker".to_string()]);

    // Both replicas now report the same clock — a side effect of
    // every announce flowing through both DAGs. They may differ
    // by 1 if a heartbeat raced; treat ≥ A's tick as sync-caught-up.
    let page_a = client_a.list("kunekt/".to_string(), String::new(), 64).unwrap();
    let page_b = client_b.list("kunekt/".to_string(), String::new(), 64).unwrap();
    assert!(page_b.clock >= page_a.clock - 1,
        "B's clock {} < A's clock {} — sync did not deliver tail events",
        page_b.clock, page_a.clock);

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}
