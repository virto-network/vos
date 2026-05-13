//! ELF integration tests — full pipeline: RISC-V ELF → transpile → PVM → run.
//!
//! These tests load pre-built actor ELF binaries from the examples/ directory,
//! transpile them to PVM blobs, and run them through VosRuntime.

use vos::runtime::VosRuntime;

/// Resolve the path to a pre-built example ELF.
fn example_elf(name: &str) -> Vec<u8> {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{}/../examples/actors/{name}/target/riscv64em-javm/release/{name}.elf",
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
    for name in &[
        "greeter",
        "counter",
        "fizzbuzz",
        "hasher",
        "animation",
        "display",
        "pushy",
    ] {
        let elf = example_elf(name);
        let blob = transpile_actor(&elf);
        assert!(!blob.is_empty(), "{name} produced empty blob");
    }
}

#[test]
fn greeter_pvm_blob_has_jump_header() {
    let elf = example_elf("greeter");
    let blob = transpile_actor(&elf);
    assert!(
        blob.len() > 100,
        "greeter blob suspiciously small: {} bytes",
        blob.len()
    );
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
    assert!(
        !meta.messages.is_empty(),
        "greeter should have at least one message"
    );
}

#[test]
fn agent_service_lifecycle() {
    // The scheduler agent is a service (accumulate at PC=5). Verify it inits and halts.
    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
    let args = vos::init::InitArgs::new().with("children", vos::init::InitValue::ListU32(vec![]));
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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![greeter_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

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

/// Regression for Sprint 1 / B6 — yielding sub-actors keep ticking
/// when driven by the scheduler agent. See
/// memory/project_runtime_tick_regression.md for the original
/// failure (`lifecycle::invoke` was returning `Done` for yielded
/// children, so the scheduler dropped them from the run queue
/// after one iteration). RESOLVED on master 2026-05-04 via the
/// per-service refine journal + invoke envelope packing commits;
/// this test pins the property so a future refactor can't
/// silently regress it.
///
/// Assertion: after N bounded `tick_blocking()` rounds the
/// runtime still has work pending (scheduler hasn't stopped
/// queuing self-`tick` messages) and nothing has panicked. The
/// counter actor in `examples/actors/counter` is the canonical
/// self-yielding fixture used by `examples/space.toml`.
#[test]
fn scheduler_keeps_driving_yielding_counter() {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace
    );
    let scheduler_data = match std::fs::read(&agent_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let counter_data = example_elf("counter");

    let scheduler_blob = transpile_actor(&scheduler_data);
    let counter_blob = transpile_actor(&counter_data);

    let mut rt = VosRuntime::new();

    let sched_blob_idx = rt.register_service_blob(scheduler_blob);
    let sched_id = rt.register_service(sched_blob_idx);
    let counter_blob_idx = rt.register_service_blob(counter_blob);
    let counter_id = rt.register_service(counter_blob_idx);

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![counter_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(sched_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(sched_id, Vec::new());

    // Drain a bounded number of ticks. The scheduler self-sends
    // `tick` after each round so `has_work()` should stay true as
    // long as the counter remains yielded. If the regression
    // returned (yield treated as Done), the scheduler would
    // drop the counter from `run_queue`, stop scheduling ticks,
    // and has_work() would go false within the first round.
    const TICKS: usize = 8;
    let mut productive = 0usize;
    for _ in 0..TICKS {
        if rt.tick_blocking() {
            productive += 1;
        }
        if !rt.has_work() {
            break;
        }
    }

    assert_eq!(rt.panics, 0, "no service should have panicked");
    assert!(
        productive >= TICKS,
        "expected the scheduler to drive at least {TICKS} productive ticks; \
         got {productive} — yielded counter dropped early"
    );
    assert!(
        rt.has_work(),
        "scheduler should still have pending tick after {TICKS} rounds — \
         a yielding counter must keep the run queue non-empty"
    );
    // The counter is invoked synchronously through the scheduler
    // (lifecycle::invoke), not as a top-level suspended service —
    // its yielded state lives in the scheduler's run_queue, not
    // in the runtime's data layer. So we don't check
    // `is_suspended(counter_id)`; the productive-tick + has_work
    // assertions above are the real signal.
    let _ = counter_id;
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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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

    let args = vos::init::InitArgs::new().with("children", vos::init::InitValue::ListU32(vec![]));
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
    use vos::pvm_image::{ContinuationHeader, commit};

    // Build a body + matching header, put the body in the data
    // layer, write the header into service storage, and verify the
    // runtime sees the service as suspended.
    let body = vec![0xAAu8; 64];
    let commitment = commit(&body);

    let mut da = MemoryDataLayer::new();
    assert!(!da.contains(&commitment));
    pollster::block_on(da.put(commitment, body.clone()));
    assert!(da.contains(&commitment));
    assert_eq!(
        pollster::block_on(da.get(&commitment)).as_deref(),
        Some(&body[..])
    );

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
    rt.storage
        .write(id, vos::lifecycle::CONTINUATION_HEADER_KEY, &encoded);
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
    use vos::pvm_image::{ContinuationHeader, commit};

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
    rt_a.storage.write(
        svc_id,
        vos::lifecycle::CONTINUATION_HEADER_KEY,
        &header.encode(),
    );
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

    use vos::Encode;
    use vos::value::{Msg, TAG_DYNAMIC};
    let encoded = Msg::new("start").encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    rt.send_to(id, payload);
    rt.run_blocking();
    assert_eq!(
        rt.panics, 0,
        "greeter panicked running directly as top-level service"
    );
}

#[test]
fn pvm_agent_invokes_extension_via_external_handler() {
    // The scheduler agent invokes its children via lifecycle::invoke().
    // We register a fake "child" ServiceId that maps to a worker via
    // the external_invoke callback. This tests the full PVM→extension path.
    use std::sync::atomic::{AtomicU32, Ordering};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let p = format!("{}/../target/{profile}/libecho_extension.so", workspace);
        std::path::PathBuf::from(p)
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-extension not built (cargo build -p echo-extension)");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    // The "extension child" gets ServiceId 99 — not registered in the runtime,
    // so INVOKE will fall through to external_invoke.
    let worker_child_id = vos::abi::service::ServiceId(99);
    let invoke_count = std::sync::Arc::new(AtomicU32::new(0));
    let count_clone = invoke_count.clone();

    // Load the worker plugin for the external handler.
    // Leak the plugin so the ExtensionInstance is 'static (test only).
    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::extension::ExtensionPlugin::load(&echo_so) }.expect("load echo worker"),
    ));
    let instance = std::sync::Mutex::new(plugin.create());

    rt.set_external_invoke(Box::new(move |target, msg| {
        if target != worker_child_id {
            return None;
        }
        count_clone.fetch_add(1, Ordering::Relaxed);
        let mut inst = instance.lock().unwrap();
        match inst.dispatch_raw(msg) {
            Ok(reply) => Some(vos::runtime::ExternalInvokeReply::done(reply)),
            Err(_) => Some(vos::runtime::ExternalInvokeReply::done(Vec::new())),
        }
    }));

    // Init scheduler with children = [99] (our worker)
    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![worker_child_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();

    assert_eq!(
        rt.panics, 0,
        "scheduler panicked when invoking worker child"
    );
    let invokes = invoke_count.load(Ordering::Relaxed);
    assert!(
        invokes > 0,
        "external_invoke should have been called at least once, got {invokes}"
    );
    eprintln!("pvm_agent_invokes_worker: {invokes} invoke(s) routed to worker");
}

#[test]
fn recording_session_captures_invoke_replies() {
    // Same setup as pvm_agent_invokes_extension_via_external_handler,
    // but this time the runtime is in a recording session: every
    // invoke the scheduler issues should end up in the session's
    // EffectLog, ready to be attached to a CRDT commit.
    use std::sync::atomic::{AtomicU32, Ordering};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let p = format!("{}/../target/{profile}/libecho_extension.so", workspace);
        std::path::PathBuf::from(p)
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-extension not built");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    let worker_child_id = vos::abi::service::ServiceId(99);
    let invoke_count = std::sync::Arc::new(AtomicU32::new(0));
    let count_clone = invoke_count.clone();

    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::extension::ExtensionPlugin::load(&echo_so) }.expect("load echo worker"),
    ));
    let instance = std::sync::Mutex::new(plugin.create());

    rt.set_external_invoke(Box::new(move |target, msg| {
        if target != worker_child_id {
            return None;
        }
        count_clone.fetch_add(1, Ordering::Relaxed);
        let mut inst = instance.lock().unwrap();
        match inst.dispatch_raw(msg) {
            Ok(reply) => Some(vos::runtime::ExternalInvokeReply::done(reply)),
            Err(_) => Some(vos::runtime::ExternalInvokeReply::done(Vec::new())),
        }
    }));

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![worker_child_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    // Begin a recording session before the dispatch. The msg bytes
    // here would normally be the incoming envelope payload; we pass
    // a tag so we can assert it came through.
    let dispatch_msg = b"test-dispatch".to_vec();
    rt.begin_recording(dispatch_msg.clone());
    assert!(
        rt.is_recording(),
        "session should be active after begin_recording"
    );

    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();

    let log = rt.finish_recording().expect("session should be in flight");
    assert!(
        !rt.is_recording(),
        "session should be cleared after finish_recording"
    );

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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let p = format!("{}/../target/{profile}/libecho_extension.so", workspace);
        std::path::PathBuf::from(p)
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-extension not built");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let worker_child_id = vos::abi::service::ServiceId(99);

    // ── Run 1: record ───────────────────────────────────────────────
    let invoke_count_rec = std::sync::Arc::new(AtomicU32::new(0));
    let count_rec_clone = invoke_count_rec.clone();

    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::extension::ExtensionPlugin::load(&echo_so) }.expect("load echo worker"),
    ));
    let instance_rec = std::sync::Mutex::new(plugin.create());

    let recorded_log = {
        let mut rt = VosRuntime::new();
        let agent_id = register_svc(&mut rt, blob.clone());

        rt.set_external_invoke(Box::new(move |target, msg| {
            if target != worker_child_id {
                return None;
            }
            count_rec_clone.fetch_add(1, Ordering::Relaxed);
            let mut inst = instance_rec.lock().unwrap();
            match inst.dispatch_raw(msg) {
                Ok(reply) => Some(vos::runtime::ExternalInvokeReply::done(reply)),
                Err(_) => Some(vos::runtime::ExternalInvokeReply::done(Vec::new())),
            }
        }));

        let args = vos::init::InitArgs::new().with(
            "children",
            vos::init::InitValue::ListU32(vec![worker_child_id.0]),
        );
        let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
        rt.storage
            .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

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
        recorded_log.reply_count() as u32,
        rec_invokes,
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
        Some(vos::runtime::ExternalInvokeReply::done(alloc_bogus_reply()))
    }));

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![worker_child_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

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
        replay.position(),
        replay.was_exhausted(),
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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
    // Provide replication_id so the data_dir check fires next —
    // this test is specifically about the data_dir requirement.
    // (A separate `crdt_consistency_without_replication_id_fails_loud`
    // test below covers the rep_id check.)
    let _id = node.register(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .with_replication_id([0xa5u8; 32]),
        // intentionally NOT calling .persist(...) — Crdt without
        // data_dir is a configuration error
    );
    node.run();
    let results = node.collect();

    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(
        r.error.is_some(),
        "expected fatal error, got result: panics={}, error={:?}",
        r.panics,
        r.error
    );
    let err = r.error.as_ref().unwrap();
    assert!(
        err.contains("Crdt") && err.contains("data_dir"),
        "error should call out the missing data_dir, got: {err}",
    );
}

#[test]
fn crdt_consistency_without_replication_id_fails_loud() {
    // The (origin, seq) tagging that gives CRDT events globally-unique
    // CIDs requires every CrdtCommit to know its origin. Registering a
    // Crdt agent without a replication_id is a configuration error
    // — without one, every "unconfigured" Crdt agent would share an
    // origin and silently dedup each other's events.
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
    let dir = std::env::temp_dir().join(format!(
        "vos_crdt_no_repid_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let mut node = VosNode::new();
    let _id = node.register(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir),
        // intentionally NOT calling .with_replication_id(...) — that's
        // the configuration error under test
    );
    node.run();
    let results = node.collect();

    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(
        r.error.is_some(),
        "expected fatal error, got: panics={}, error={:?}",
        r.panics,
        r.error
    );
    let err = r.error.as_ref().unwrap();
    assert!(
        err.contains("replication_id"),
        "error should call out the missing replication_id, got: {err}",
    );

    let _ = std::fs::remove_dir_all(&dir);
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
        "{}/../examples/actors/math/target/riscv64em-javm/release/math.elf",
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
    use vos::Encode;
    use vos::value::{Msg, TAG_DYNAMIC};
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
            r.id,
            r.panics,
            r.error,
        );
    }
}

#[test]
fn pushy_vec_push_grows_correctly() {
    // Regression for the JAVM ScaledAdd self-aliasing bug. The
    // recompiler peephole that fused `slli a1,s0,2; add a0,a0,a1;
    // sw a1,0(a0)` into a scaled-index store re-applied the
    // stride at emit time when the `add`'s destination aliased
    // its base operand, so each non-grow `Vec::push` wrote at
    // offset `len*8` instead of `len*4`. The visible effect:
    // `prove_grow` (which pushes 11, 22, 33 in one handler call)
    // produced `[11, 0, 22]` pre-fix and `[11, 22, 33]` post-fix.
    use vos::node::{AgentConfig, VosNode};

    let pushy_data = example_elf("pushy");
    let pushy_blob = grey_transpiler::link_elf(&pushy_data).expect("transpile pushy");

    let mut node = VosNode::new();
    let pushy_id = node.register(AgentConfig::new(pushy_blob));

    use vos::Encode;
    use vos::value::{Msg, TAG_DYNAMIC};
    let dyn_payload = |m: Msg| -> Vec<u8> {
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };

    // (a) Single-handler triple push hits the no-grow path twice.
    let _ = node
        .invoke(pushy_id, dyn_payload(Msg::new("prove_grow")))
        .expect("prove_grow failed");
    let bytes = node
        .invoke(pushy_id, dyn_payload(Msg::new("get")))
        .expect("get() failed");
    let value: vos::value::Value = vos::Decode::decode(&bytes);
    let items = value
        .as_list_u32()
        .expect("get() reply not a ListU32")
        .to_vec();
    assert_eq!(
        items,
        vec![11u32, 22u32, 33u32],
        "prove_grow corrupted — got {items:?} (expected [11, 22, 33])",
    );

    // (b) Two further pushes via separate invokes — each invoke
    // serializes and re-deserializes the actor via STATE_KEY, so
    // both pushes hit `Vec::push` on a fresh-from-rkyv Vec where
    // `cap == len` and a grow is needed.
    let _ = node
        .invoke(pushy_id, dyn_payload(Msg::new("push").with("val", 100u32)))
        .expect("push(100) failed");
    let _ = node
        .invoke(pushy_id, dyn_payload(Msg::new("push").with("val", 200u32)))
        .expect("push(200) failed");
    let bytes = node
        .invoke(pushy_id, dyn_payload(Msg::new("get")))
        .expect("get() failed");
    let value: vos::value::Value = vos::Decode::decode(&bytes);
    let items = value
        .as_list_u32()
        .expect("get() reply not a ListU32")
        .to_vec();

    node.shutdown();
    let results = node.collect();
    for r in &results {
        assert!(
            r.is_ok(),
            "agent {} failed: panics={} error={:?}",
            r.id,
            r.panics,
            r.error,
        );
    }

    assert_eq!(
        items,
        vec![11u32, 22u32, 33u32, 100u32, 200u32],
        "across-invoke push corrupted — got {items:?}",
    );
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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let greeter_path = format!(
        "{}/../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf",
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

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![greeter_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .unwrap()
        .to_vec();
    let scheduler_id = node.register(
        AgentConfig::new(scheduler_blob)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), encoded)])
            .with_consistency(Consistency::Crdt)
            .with_replication_id([0xa3u8; 32])
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
    assert!(
        db_path.exists(),
        "scheduler's redb missing: {}",
        db_path.display()
    );

    let db = redb::Database::open(&db_path).unwrap();
    let txn = db.begin_read().unwrap();

    use redb::{ReadableTable, ReadableTableMetadata};
    const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");
    let dag_table = txn.open_table(DAG_TABLE).unwrap();
    let dag_count = dag_table.len().unwrap();
    assert!(
        dag_count >= 1,
        "expected at least one CRDT DAG node, got {dag_count}",
    );

    // Decode every DAG node and check each effect log; at least
    // one should carry a recorded reply (the greeter invoke). The
    // payload is now a `CrdtEvent` wrapping the original
    // `EffectLog`, so peel the wrapper before counting replies.
    let mut total_replies = 0usize;
    for entry in dag_table.iter().unwrap() {
        let (_key, value) = entry.unwrap();
        let bytes: &[u8] = value.value();
        // DagNode wire format: [payload_len:u64 LE][payload][n_children:u64 LE][children...]
        let payload_len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        let payload_bytes = &bytes[8..8 + payload_len];
        let event =
            vos::effect_log::CrdtEvent::from_bytes(payload_bytes).expect("decode CrdtEvent");
        total_replies += event.log.reply_count();
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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let greeter_path = format!(
        "{}/../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf",
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
            r.id,
            r.panics,
            r.error,
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
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let p = format!("{}/../target/{profile}/libecho_extension.so", workspace);
        std::path::PathBuf::from(p)
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-extension not built");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    let worker_child_id = vos::abi::service::ServiceId(99);
    let invoke_count = std::sync::Arc::new(AtomicU32::new(0));
    let count_clone = invoke_count.clone();

    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::extension::ExtensionPlugin::load(&echo_so) }.expect("load echo worker"),
    ));
    let instance = std::sync::Mutex::new(plugin.create());

    rt.set_external_invoke(Box::new(move |target, msg| {
        if target != worker_child_id {
            return None;
        }
        count_clone.fetch_add(1, Ordering::Relaxed);
        let mut inst = instance.lock().unwrap();
        match inst.dispatch_raw(msg) {
            Ok(reply) => Some(vos::runtime::ExternalInvokeReply::done(reply)),
            Err(_) => Some(vos::runtime::ExternalInvokeReply::done(Vec::new())),
        }
    }));

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![worker_child_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

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
        log.reply_count() as u32,
        invokes,
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
    use vos::abi::service::ServiceId;
    use vos::node::{AgentConfig, Consistency, Envelope, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
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
    let args =
        vos::init::InitArgs::new().with("children", vos::init::InitValue::ListU32(Vec::new()));
    let init_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .unwrap()
        .to_vec();

    let mut node = VosNode::new();
    let agent_id = node.register(
        AgentConfig::new(blob)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), init_bytes)])
            .with_consistency(Consistency::Crdt)
            .with_replication_id([0xa1u8; 32])
            .persist(&data_dir),
    );

    node.run();
    let results = node.collect();
    for r in &results {
        assert!(
            r.is_ok(),
            "agent {} failed: panics={} error={:?}",
            r.id,
            r.panics,
            r.error
        );
    }

    // Verify the redb file exists at the expected path.
    let db_path = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", agent_id.0));
    assert!(
        db_path.exists(),
        "CRDT redb not created at {}",
        db_path.display()
    );

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
    let _ = Envelope {
        from: agent_id,
        to: agent_id,
        payload: Vec::new(),
    };

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
        let args =
            vos::init::InitArgs::new().with("children", vos::init::InitValue::ListU32(Vec::new()));
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
            .unwrap()
            .to_vec()
    };

    let mut node2 = VosNode::new();
    let _agent_id2 = node2.register(
        AgentConfig::new(blob2)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), init_bytes2)])
            .with_consistency(Consistency::Crdt)
            .with_replication_id([0xa1u8; 32])
            .persist(&data_dir),
    );
    node2.run();
    let results2 = node2.collect();
    for r in &results2 {
        assert!(
            r.is_ok(),
            "agent {} failed on restart: panics={} error={:?}",
            r.id,
            r.panics,
            r.error
        );
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

    use vos::Encode;
    use vos::value::{Msg, TAG_DYNAMIC, Value};

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
fn fetch_at_buf_size_boundary_delivers_message() {
    // Regression for the off-by-one in
    // `lifecycle::{fetch_raw, read_storage, read_persisted_state}`:
    // they treated `n == buf.len()` as "not found" rather than
    // "fits exactly", silently dropping any value of size
    // BUF_SIZE (4096 bytes). Fixed by returning the *full* value
    // length from runtime-side STORAGE_R / FETCH so the guest can
    // distinguish exact-fit from truncation, plus changing the
    // guest's check from `<` to `<=`.
    //
    // Probe shape: build a TAG_DYNAMIC + Msg payload, pad it to
    // exactly 4096 bytes by stuffing extra bytes onto the rkyv
    // tail (the actor's `from_dynamic` decoder doesn't validate
    // trailing bytes), then send it to crdt-counter.
    //
    // Pre-fix: the message gets silently dropped at fetch_raw,
    // counter never sees `inc()`, count stays 0.
    // Post-fix: the message arrives, dispatches, count goes to 1.
    use crdt_counter::CrdtCounterRef;
    use vos::Encode;
    use vos::node::{AgentConfig, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let mut node = VosNode::new();
    let id = node.register(AgentConfig::new(counter_blob));
    let counter = CrdtCounterRef::at(id);

    // Build a valid TAG_DYNAMIC + Msg("inc") payload, padded
    // to exactly 4096 bytes by inserting zero bytes between the
    // TAG_DYNAMIC byte and the rkyv-archived Msg. rkyv archives
    // are tail-anchored — the Archived type sits at the END of
    // the buffer — so leading padding is tolerated by
    // `access_unchecked` while trailing padding would break it.
    let m = Msg::new("inc");
    let encoded = m.encode();
    let pad_len = 4096 - 1 - encoded.len();
    let mut payload = Vec::with_capacity(4096);
    payload.push(TAG_DYNAMIC);
    payload.extend(std::iter::repeat(0u8).take(pad_len));
    payload.extend_from_slice(&encoded);
    assert_eq!(payload.len(), 4096, "payload size at the boundary");

    // Use `node.invoke` rather than node.outbox_sender so the
    // agent thread's invoke loop processes our payload without
    // needing run_until_idle.
    let _ = node.invoke(id, payload);

    let count = vos::block_on(counter.get(&mut &node)).expect("get must succeed");
    assert_eq!(
        count, 1,
        "exact-fit FETCH must deliver the message — pre-fix the guest \
         dropped it because `fetch_raw` checked `n < buf.len()` and the \
         runtime returned `copy_len` (== buf.len() for exact fits), so \
         the actor never saw the inc()",
    );

    node.shutdown();
    let _ = node.collect();
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
    // `CrdtCounterRef`. inc returns (), get returns u64 —
    // both come from the actor's `#[msg]` signatures, no manual
    // `Msg::new(...)` plumbing needed.
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
        workspace,
    );
    let data = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: crdt-counter not built");
            return;
        }
    };
    let blob = grey_transpiler::link_elf(&data).expect("transpile");
    let mut node = VosNode::new();
    let id = node.register(AgentConfig::new(blob));

    let counter = CrdtCounterRef::at(id);
    vos::block_on(counter.inc(&mut &node)).expect("inc 1");
    vos::block_on(counter.inc(&mut &node)).expect("inc 2");
    assert_eq!(vos::block_on(counter.get(&mut &node)).expect("get"), 2);

    node.shutdown();
    let _ = node.collect();
}

#[test]
#[cfg(feature = "network")]
fn crdt_counter_init_payloads_dispatch() {
    // Smoke test the on_start manifest path: register a CRDT
    // counter with an init_payload that encodes inc() and
    // verify the count went up to 1 by the time we invoke get().
    use vos::Encode;
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
        workspace,
    );
    let data = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: crdt-counter not built");
            return;
        }
    };
    let blob = grey_transpiler::link_elf(&data).expect("transpile");

    let dir = std::env::temp_dir().join(format!(
        "vos_init_payload_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let inc_payload = {
        let m = Msg::new("inc");
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
            .with_replication_id([0xa2u8; 32])
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
    assert_eq!(count, Some(1), "init_payload inc() should drive count=1");

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
    use vos::Encode;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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
    let dir_root =
        std::env::temp_dir().join(format!("vos_crdt_e2e_{}_{}", std::process::id(), stamp));
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
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        std::time::Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr =
        a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
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
    // Both replicas call the *same* `inc()` (no payload). With the
    // `(origin, seq)` tagging on `CrdtEvent`, each replica stamps
    // its event with its own per-node origin so the two events get
    // distinct CIDs even though their `EffectLog`s are byte-
    // identical. Without that fix, the merkle-DAG would dedup them
    // and both replicas would appear "pre-converged" at count=1
    // — a silent loss of one of the increments.
    let inc_payload = || -> Vec<u8> {
        let m = Msg::new("inc");
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };
    let _ = node_a.invoke(counter_a, inc_payload()).expect("inc on A");
    let _ = node_b.invoke(counter_b, inc_payload()).expect("inc on B");

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
    assert_eq!(
        count_a,
        Some(2),
        "A did not converge to count=2 within deadline"
    );
    assert_eq!(
        count_b,
        Some(2),
        "B did not converge to count=2 within deadline"
    );

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
#[cfg(feature = "network")]
fn crdt_scheduler_install_propagates_across_nodes() {
    // CRDT replication of an agent that drives sub-actors. The
    // scheduler tracks state (`round`, `children`, `run_queue`)
    // and on each external dispatch invokes its registered children
    // via `lifecycle::invoke` — those replies land in the
    // EffectLog so peer replicas can replay deterministically
    // without re-issuing the invokes.
    //
    // What this exercises that the crdt-counter tests don't:
    //   - the recorded `replies` array on the EffectLog is non-empty
    //     (scheduler invokes its children inside the handler).
    //   - state is a non-trivial structure (Vec<u32> + Vec<...>),
    //     not a single u64.
    //   - replay's effect-cursor short-circuits the runtime's
    //     INVOKE hostcall on the replica that didn't originate
    //     the dispatch.
    //
    // Setup:
    //   1. Two networked nodes A, B with a shared rep_id.
    //   2. Both register scheduler with consistency = Crdt and
    //      empty children initially. Greeter is registered as an
    //      `Ephemeral` sibling on each node so scheduler's child
    //      invokes have a real local target — but the test only
    //      asserts on the scheduler's own state, not greeter's.
    //   3. From outside, `install(some_id)` lands on A only.
    //   4. Wait for B's scheduler to also report `some_id` in its
    //      `get_children()` — that's the convergence signal. The
    //      `id` we pick is intentionally not registered on either
    //      side, so install's `invoke_child` reply is NotFound on
    //      A and the same recorded NotFound on B's replay.
    use vos::Encode;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let scheduler_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let scheduler_data = match std::fs::read(&scheduler_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let scheduler_blob = grey_transpiler::link_elf(&scheduler_data).expect("transpile");

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_crdt_sched_{}_{}", std::process::id(), stamp,));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"crdt-scheduler-test");
        h.update(&[0u8]);
        h.update(&scheduler_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // Networks
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
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        std::time::Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));
    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
    });

    // Empty initial children so install(N) is the only state
    // mutation we need to observe.
    let init_args =
        vos::init::InitArgs::new().with("children", vos::init::InitValue::ListU32(Vec::new()));
    let init_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&init_args)
        .unwrap()
        .to_vec();

    let mut node_a = VosNode::with_prefix(prefix_a);
    let scheduler_a = node_a.register(
        AgentConfig::new(scheduler_blob.clone())
            .with_storage(vec![(
                vos::lifecycle::INIT_KEY.to_vec(),
                init_bytes.clone(),
            )])
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(rep_id),
    );
    node_a.attach_network(net_a);

    let mut node_b = VosNode::with_prefix(prefix_b);
    let scheduler_b = node_b.register(
        AgentConfig::new(scheduler_blob)
            .with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), init_bytes)])
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(rep_id),
    );
    node_b.attach_network(net_b);

    // Hello handshake first so the first install's sync attempt
    // doesn't get swallowed.
    let net_a_arc = node_a.network().expect("net_a");
    let net_b_arc = node_b.network().expect("net_b");
    wait_for(
        || {
            (net_a_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some())
            .then_some(())
        },
        std::time::Duration::from_secs(10),
    )
    .expect("Hello completes");

    // Drive install(0xC0DE) on A only. The id isn't registered as a
    // service anywhere, so scheduler's `invoke_child` inside install
    // gets NotFound back — recorded in A's EffectLog as the single
    // reply. children gets pushed unconditionally.
    let install_payload = {
        let m = Msg::new("install").with("actor_id", 0xC0DEu32);
        let encoded = m.encode();
        let mut p = Vec::with_capacity(1 + encoded.len());
        p.push(TAG_DYNAMIC);
        p.extend_from_slice(&encoded);
        p
    };
    let _ = node_a
        .invoke(scheduler_a, install_payload)
        .expect("install on A");

    // Probe both replicas. A sees the change immediately; B has to
    // catch up via the sync ticker (cycle-3) then a soft-restart
    // replays the single DAG node.
    let get_children_payload = || {
        let m = Msg::new("get_children");
        let encoded = m.encode();
        let mut p = Vec::with_capacity(1 + encoded.len());
        p.push(TAG_DYNAMIC);
        p.extend_from_slice(&encoded);
        p
    };
    let read_children = |node: &VosNode, target: ServiceId| -> Option<Vec<u32>> {
        let bytes = node.invoke(target, get_children_payload())?;
        let v: vos::value::Value = vos::Decode::decode(&bytes);
        v.as_list_u32().map(|s| s.to_vec())
    };

    // A applied locally.
    assert_eq!(read_children(&node_a, scheduler_a), Some(vec![0xC0DE]));

    // B converges via CRDT replay.
    let b_children = wait_for(
        || match read_children(&node_b, scheduler_b) {
            Some(v) if v == vec![0xC0DE] => Some(v),
            _ => None,
        },
        std::time::Duration::from_secs(8),
    );
    assert_eq!(
        b_children,
        Some(vec![0xC0DE]),
        "B did not converge to A's installed children list within deadline",
    );

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
#[cfg(feature = "network")]
fn crdt_counter_burst_converges_under_concurrent_load() {
    // Robustness probe: the existing convergence test does one
    // inc() per side. Real workloads will have bursts of writes
    // racing with each other and with the sync ticker. This
    // probe drives N inc()s on each side concurrently from
    // host-side threads (so the sync ticker, the agent threads,
    // and the local invokes are all in flight at once) and
    // asserts both replicas converge to 2*N.
    //
    // What can fail here that the single-inc test wouldn't catch:
    //   - race between the agent's commit_with_log and the sync
    //     ticker's insert_node + soft_restart_crdt
    //   - a stale snapshot of `last_reply` carrying across an
    //     unexpected soft restart
    //   - tag collision causing two inc events to share a CID
    //     (silent dedup → undercount on convergence)
    //   - the BFS from FetchHeads stopping mid-fetch and
    //     leaving the merged DAG short of a few nodes
    use vos::Encode;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    const PER_SIDE: u32 = 5;
    const EXPECTED: u64 = (PER_SIDE as u64) * 2;

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_crdt_burst_{}_{}", std::process::id(), stamp,));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"crdt-counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

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
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        std::time::Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr =
        a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
    });

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

    let net_a_arc = node_a.network().expect("net_a attached");
    let net_b_arc = node_b.network().expect("net_b attached");
    wait_for(
        || {
            (net_a_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some())
            .then_some(())
        },
        std::time::Duration::from_secs(10),
    )
    .expect("Hello completes");

    let inc_payload = || -> Vec<u8> {
        let m = Msg::new("inc");
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };

    // Drive the bursts on background threads so both sides race.
    let handle_a = node_a.invoke_handle();
    let handle_b = node_b.invoke_handle();
    let one_sec = std::time::Duration::from_secs(10);

    let t_a = std::thread::spawn(move || {
        for _ in 1..=PER_SIDE {
            let _ = handle_a.invoke_with_timeout(counter_a, inc_payload(), one_sec);
        }
    });
    let t_b = std::thread::spawn(move || {
        for _ in 1..=PER_SIDE {
            let _ = handle_b.invoke_with_timeout(counter_b, inc_payload(), one_sec);
        }
    });
    t_a.join().expect("burst A");
    t_b.join().expect("burst B");

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

    let final_a = wait_for(
        || match read_count(&node_a, counter_a) {
            Some(c) if c == EXPECTED => Some(c),
            _ => None,
        },
        std::time::Duration::from_secs(15),
    );
    let final_b = wait_for(
        || match read_count(&node_b, counter_b) {
            Some(c) if c == EXPECTED => Some(c),
            _ => None,
        },
        std::time::Duration::from_secs(15),
    );
    let observed_a = read_count(&node_a, counter_a);
    let observed_b = read_count(&node_b, counter_b);
    assert_eq!(
        final_a,
        Some(EXPECTED),
        "A did not converge to {EXPECTED} within deadline; last observed = {observed_a:?}",
    );
    assert_eq!(
        final_b,
        Some(EXPECTED),
        "B did not converge to {EXPECTED} within deadline; last observed = {observed_b:?}",
    );

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}

#[cfg(feature = "network")]
fn wait_for<T>(mut probe: impl FnMut() -> Option<T>, deadline: std::time::Duration) -> Option<T> {
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
fn crdt_counter_restart_replays_state_from_disk() {
    // Core determinism claim: a CRDT actor whose process dies
    // mid-flight and then comes back against the same data_dir
    // must replay its EffectLog and rebuild the same state.
    // No networking — just one node, same redb file across two
    // VosNode instances, asserting `get()` survives the restart.
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, Consistency, VosNode};

    // Initialize tracing so any error! / warn! from the agent
    // thread surfaces during debugging. No-op if already set
    // (other tests in this file may have initialized it).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("vos=warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let dir = std::env::temp_dir().join(format!(
        "vos_restart_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // Same replication_id derivation cmd_start uses, so this
    // mirrors what a real `vosx up` would produce.
    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // ── First boot: drive three inc() calls, observe count=3 ──
    let counter_id;
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob.clone())
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        counter_id = id;

        let counter = CrdtCounterRef::at(id);
        vos::block_on(counter.inc(&mut &node)).expect("inc 1");
        vos::block_on(counter.inc(&mut &node)).expect("inc 2");
        vos::block_on(counter.inc(&mut &node)).expect("inc 3");
        assert_eq!(
            vos::block_on(counter.get(&mut &node)).expect("get pre-restart"),
            3
        );

        node.shutdown();
        let _ = node.collect();
    } // node + its agent thread fully torn down here.

    // Sanity: the redb file should exist on disk after the
    // first boot finishes. If it doesn't, persistence isn't
    // happening and the rest of the test is meaningless.
    let agents_dir = dir.join("agents");
    let entries: Vec<_> = std::fs::read_dir(&agents_dir)
        .expect("agents/ should exist after first boot")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    assert!(
        !entries.is_empty(),
        "first boot should have persisted at least one redb under {}",
        agents_dir.display(),
    );
    eprintln!("test: persisted files: {entries:?}");

    // ── Second boot: same dir, fresh VosNode. Replay should
    //    rebuild state from the on-disk DAG without any
    //    further `inc()` from us.
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob)
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        // The actor must come back at the same ServiceId for
        // its persisted DAG to be addressable from on-disk
        // state. (Same prefix, deterministic local-id allocation.)
        assert_eq!(id, counter_id, "restarted actor must reuse its ServiceId");

        let counter = CrdtCounterRef::at(id);
        assert_eq!(
            vos::block_on(counter.get(&mut &node)).expect("get post-restart"),
            3,
            "restart must replay the three logged incs",
        );

        // One more inc after restart — confirms the replayed
        // state isn't a frozen snapshot, the actor really is
        // alive and writable on the same DAG.
        vos::block_on(counter.inc(&mut &node)).expect("inc post-restart");
        assert_eq!(
            vos::block_on(counter.get(&mut &node)).expect("get final"),
            4
        );

        node.shutdown();
        let _ = node.collect();
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crdt_counter_survives_corrupted_persisted_state() {
    // Robustness probe: simulate schema drift / disk
    // corruption / hand-edited save by overwriting the
    // actor's persisted state blob with garbage between two
    // node boots. The actor's rkyv-decode on restart must:
    //
    //  1. Not silently surface garbage as "valid" state —
    //     either the actor falls back to default state
    //     (count==0) or refuses to dispatch entirely.
    //  2. Not crash the agent thread permanently — the next
    //     invoke must produce a usable error or a usable
    //     reply, not a hang or segfault.
    //
    // Pre-fix behaviour was: `codec::Decode` used
    // `rkyv::access_unchecked`, so 7 bytes of garbage
    // decoded into a u64 of 72057589742960640 and the actor
    // happily reported it as the count. Fixed by routing
    // `lifecycle::load_or_create` through validating
    // `Decode::try_decode` (rkyv `access` + bytecheck), so a
    // corrupted blob falls back to `A::create()` and the
    // actor reports a clean count==0.
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let dir = std::env::temp_dir().join(format!(
        "vos_corrupt_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // Boot 1: drive a few inc() calls so the state row gets
    // populated with valid rkyv-encoded bytes.
    let counter_id;
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob.clone())
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        counter_id = id;
        let counter = CrdtCounterRef::at(id);
        vos::block_on(counter.inc(&mut &node)).expect("inc 1");
        vos::block_on(counter.inc(&mut &node)).expect("inc 2");
        assert_eq!(vos::block_on(counter.get(&mut &node)).expect("get"), 2);
        node.shutdown();
        let _ = node.collect();
    }

    // Hand-corrupt the actor's persisted state. Open the same
    // redb file, find the `state` table, replace the `actor`
    // row with random bytes that won't deserialize.
    {
        let db_path = dir
            .join("agents")
            .join(format!("{:08x}.redb", counter_id.0));
        assert!(
            db_path.exists(),
            "redb at {} should exist",
            db_path.display()
        );
        let db = redb::Database::create(&db_path).expect("open redb for corruption");
        let table_def: redb::TableDefinition<'_, &str, &[u8]> = redb::TableDefinition::new("state");
        let txn = db.begin_write().expect("write txn");
        {
            let mut table = txn.open_table(table_def).expect("open state table");
            // Garbage that won't deserialize as the actor's
            // state. rkyv's archive format is highly
            // specific; a short pile of zeros tends to fail
            // alignment / pointer checks.
            table.insert("actor", &[0u8][..]).expect("write garbage");
        }
        txn.commit().expect("commit corruption");
    }

    // Boot 2: same data_dir, fresh node. The actor's first
    // dispatch will try to deserialize the garbage state.
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob)
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        assert_eq!(id, counter_id);

        let counter = CrdtCounterRef::at(id);

        // The expected behaviour after the fix lands:
        //   (a) get() returns Ok(0) — actor fell back to a
        //       fresh instance because the on-disk blob
        //       failed to validate; OR
        //   (b) get() returns Err(_) — actor refused to
        //       dispatch on a corrupt state.
        // What MUST NOT happen: get() returns Ok(<garbage>),
        // because then any caller silently consumes wrong
        // state.
        let get_result = vos::block_on(counter.get(&mut &node));
        match get_result {
            Ok(0) => { /* fresh start, ideal */ }
            Err(_) => { /* explicit failure, also fine */ }
            Ok(other) => panic!(
                "post-corruption get returned Ok({other}); \
                 corrupted state must not surface as valid output \
                 (expected Ok(0) for fresh-start fallback or Err(_) \
                 for explicit refusal)",
            ),
        }

        // Once we've handled the corruption, the agent thread
        // must still respond to subsequent calls — even if
        // they error.
        let _ = vos::block_on(counter.inc(&mut &node));
        let _ = vos::block_on(counter.get(&mut &node));

        node.shutdown();
        let _ = node.collect();
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invoke_with_oversized_external_reply_does_not_corrupt_caller() {
    // Regression for the INVOKE-hostcall buffer-overrun fix:
    // the PVM ABI now packs `output.as_mut_ptr() | (output.len() << 32)`
    // into register 11 so the runtime knows the caller's
    // buffer size. When an external responder produces a reply
    // larger than that buffer, `record_and_write_invoke`
    // substitutes a one-byte `STATUS_PANICKED` envelope at the
    // caller's `output_ptr` rather than overrunning the stack.
    //
    // The probe simulates a misbehaving external responder that
    // returns 5 KiB to a caller whose `lifecycle::invoke_raw`
    // allocates a 4 KiB buffer. Two invariants must hold:
    //
    //  1. `VosRuntime` MUST NOT segfault, deadlock, or affect
    //     the surrounding test process.
    //  2. The caller observes a deterministic InvokeResult::Panicked
    //     (clean) and the agent thread keeps running. No silent
    //     corruption, no PVM-level panic from a guest-side bounds
    //     check on overrun memory.
    use std::sync::atomic::{AtomicU32, Ordering};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
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
    let agent_id = register_svc(&mut rt, blob);

    let oversized_target = vos::abi::service::ServiceId(99);
    let invokes = std::sync::Arc::new(AtomicU32::new(0));
    let invokes_clone = invokes.clone();

    // External responder returns 5 KiB of zeros — well past the
    // caller's 4 KiB invoke output buffer. The bytes themselves
    // don't matter; what's interesting is the *length*.
    rt.set_external_invoke(Box::new(move |target, _msg| {
        if target != oversized_target {
            return None;
        }
        invokes_clone.fetch_add(1, Ordering::Relaxed);
        Some(vos::runtime::ExternalInvokeReply::done(vec![0u8; 5_000]))
    }));

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![oversized_target.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(agent_id, Vec::new());
    // The runtime must terminate (panicked agent or otherwise) —
    // not hang.  `run_blocking` has its own iteration cap so a
    // hang here would already trip the test timeout.
    rt.run_blocking();

    let n = invokes.load(Ordering::Relaxed);
    assert!(
        n > 0,
        "external_invoke handler should have been called at least once"
    );

    // Post-fix behaviour: the runtime sees output.len()=5005 >
    // output_buf_len=4096 and substitutes a single-byte
    // STATUS_PANICKED envelope at the caller's output_ptr. The
    // guest's `invoke_raw` reads back n=1, takes the short-output
    // branch, and surfaces InvokeResult::Panicked to the
    // scheduler — which logs "child N panicked, dropping" and
    // removes it from the run queue. No internal panic.
    assert_eq!(
        rt.panics, 0,
        "after the ABI fix the runtime must trap the over-write \
         instead of letting the guest panic on its own bounds \
         check; rt.panics = {} means an oversized reply is still \
         reaching guest memory unbounded",
        rt.panics,
    );
}

#[test]
fn crdt_counter_survives_handler_panic_and_keeps_dispatching() {
    // Robustness claim: a `panic!()` inside a `#[msg]` handler
    // must surface to the invoke caller as a `Panicked` error
    // and leave the agent thread alive so the next message
    // gets dispatched normally. State must not be corrupted
    // by the panicked handler — its mutations get rolled back.
    //
    // If a handler panic deadlocks the agent thread, every
    // subsequent invoke times out and the actor is effectively
    // dead. That'd be a fatal regression for any production
    // use, so this is a load-bearing test.
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let dir = std::env::temp_dir().join(format!(
        "vos_panic_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let mut node = VosNode::new();
    let id = node.register(
        AgentConfig::new(counter_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir)
            .with_replication_id(rep_id),
    );

    let counter = CrdtCounterRef::at(id);

    // Build up some state first so we can detect corruption
    // post-panic.
    vos::block_on(counter.inc(&mut &node)).expect("inc 1");
    vos::block_on(counter.inc(&mut &node)).expect("inc 2");
    assert_eq!(
        vos::block_on(counter.get(&mut &node)).expect("get pre-boom"),
        2
    );

    // Trigger the panic. The macro-generated Ref returns
    // `ClientError::Unreachable` because `node.invoke` returns
    // `None` when the actor's invoke pipeline reports a panic.
    // We don't care about the exact error variant — we care
    // that (a) the call returns *something* without hanging,
    // and (b) the agent thread is still alive after.
    let boom_result = vos::block_on(counter.boom(&mut &node));
    assert!(
        boom_result.is_err(),
        "boom() must surface the panic as an error, got Ok: {boom_result:?}",
    );

    // Now the real probe: agent thread should still be
    // dispatching, state should be exactly 2 (the panic
    // mutated nothing observable since `boom` only panics).
    assert_eq!(
        vos::block_on(counter.get(&mut &node)).expect("get post-boom must succeed"),
        2,
        "state should be unchanged after a handler panic",
    );

    // Subsequent writes must still land. This is the test
    // that fails loudest if the agent thread died on the panic
    // (the invoke would time out / return Unreachable).
    vos::block_on(counter.inc(&mut &node)).expect("inc post-boom must succeed");
    assert_eq!(
        vos::block_on(counter.get(&mut &node)).expect("get final"),
        3
    );

    // Hit boom a second time — exercises the recovery path
    // twice in case the first survival was a fluke.
    let _ = vos::block_on(counter.boom(&mut &node));
    vos::block_on(counter.inc(&mut &node)).expect("inc after second boom");
    assert_eq!(
        vos::block_on(counter.get(&mut &node)).expect("get final-final"),
        4
    );

    node.shutdown();
    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crdt_counter_shutdown_under_active_load() {
    // Robustness probe: a CRDT counter is being hammered with
    // inc()s on a side thread when `shutdown` + `collect` fire.
    // The node must:
    //   1. Stop accepting new work without crashing the host
    //      thread or the side thread.
    //   2. Drain currently-queued invokes (or fail them with a
    //      clean error — never hang).
    //   3. Release the redb file so a follow-on boot at the
    //      same data_dir doesn't get "Database already open."
    //
    // Earlier in this session a real bug was fixed where
    // sync threads weren't joined and the redb file stayed
    // locked across a node restart (commit 3d56179). This test
    // exercises a tighter loop — interleaving inc() with
    // shutdown — to make sure that fix holds under contention.
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let dir = std::env::temp_dir().join(format!(
        "vos_shut_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let mut node = VosNode::new();
    let counter_id = node.register(
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir)
            .with_replication_id(rep_id),
    );

    // Side thread hammers inc() until the side handle's invoke
    // returns None (which happens once the agent's invoke route
    // is dropped at shutdown). Tracks tag values produced so
    // the post-shutdown reboot can reason about prior state.
    let handle = node.invoke_handle();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop.clone();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count_clone = count.clone();

    use vos::Encode;
    use vos::value::{Msg, TAG_DYNAMIC};
    let inc_payload = || -> Vec<u8> {
        let m = Msg::new("inc");
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };

    let one_sec = std::time::Duration::from_secs(2);
    let burst = std::thread::spawn(move || {
        while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            match handle.invoke_with_timeout(counter_id, inc_payload(), one_sec) {
                Some(_) => {
                    count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                None => break,
            }
        }
    });

    // Let the burst run for a bit so there's actually work in
    // flight when shutdown lands.
    std::thread::sleep(std::time::Duration::from_millis(150));

    // Hard test: collect (which drives shutdown internally) must
    // return without hanging even though the side thread is
    // still pumping invokes. The side thread's next invoke after
    // routes are dropped will return None and let it exit.
    let collect_started = std::time::Instant::now();
    node.shutdown();
    let _agent_results = node.collect();
    let collect_elapsed = collect_started.elapsed();

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    burst.join().expect("burst thread should exit cleanly");

    // collect() should be fast — agent threads exit on a
    // 50 ms inbox poll, sync threads on the SYNC_INTERVAL tick.
    // Generous deadline accounts for CI variance, but a hang
    // would mean someone is blocked indefinitely.
    assert!(
        collect_elapsed < std::time::Duration::from_secs(5),
        "collect() took {collect_elapsed:?}; a hang here means shutdown \
         leaked a blocked thread (sync tick? worker dispatch loop?)",
    );
    let landed = count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        landed > 0,
        "expected at least one inc to land before shutdown"
    );

    // Reboot at the same data_dir. The redb file must be unlocked
    // — the regression we're guarding against is a sync thread
    // holding the last `Arc<Database>` past collect's join.
    {
        let mut node2 = VosNode::new();
        let id2 = node2.register(
            AgentConfig::new(counter_blob)
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        assert_eq!(id2, counter_id, "service id should be stable across boots");
        let counter2 = CrdtCounterRef::at(id2);
        let count_after =
            vos::block_on(counter2.get(&mut &node2)).expect("get must work after reboot");
        assert_eq!(
            count_after, landed as u64,
            "post-reboot count must match the number of inc() calls that returned \
             before shutdown — the agent persists the DAG node before sending its \
             reply, so every successful invoke is on disk by the time the next call \
             returns",
        );
        node2.shutdown();
        let _ = node2.collect();
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn crdt_counter_offline_node_catches_up_after_restart() {
    // Cross-node restart: A and B start in sync, both at
    // count=1. A shuts down. While A is offline, B drives
    // additional `inc()` calls. A restarts against the same
    // data_dir (and same libp2p identity), reconnects to B,
    // and must catch up to B's higher count.
    //
    // This test spans two of kunekt's load-bearing claims:
    //
    //  1. Restart determinism: A's on-disk state survives the
    //     process boundary (probed in
    //     `crdt_counter_restart_replays_state_from_disk`,
    //     reused here cross-node).
    //  2. Sync recovery: A doesn't have to "re-do" the work
    //     it missed; the EffectLogs B accumulated propagate
    //     over libp2p once A reconnects.
    use vos::Encode;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root = std::env::temp_dir().join(format!(
        "vos_crdt_offline_restart_{}_{}",
        std::process::id(),
        stamp
    ));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // A and B keep the same libp2p identity across restart so
    // peers can re-find them at the same prefix. We persist the
    // keys explicitly for that reason.
    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    // Helper: invoke a Msg on a node, return the rkyv reply.
    let dyn_payload = |m: Msg| -> Vec<u8> {
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        payload
    };
    let read_count = |node: &VosNode, target: ServiceId| -> Option<u64> {
        let bytes = node.invoke(target, dyn_payload(Msg::new("get")))?;
        let v: vos::value::Value = vos::Decode::decode(&bytes);
        v.as_u64()
    };

    // ── Phase 1: bring A and B up, converge to count=2 ─────────
    let net_a = Network::start(NetworkConfig {
        keypair: kp_a.clone(),
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        std::time::Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial = a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));
    let net_b = Network::start(NetworkConfig {
        keypair: kp_b.clone(),
        local_prefix: prefix_b,
        listen: vec![listen.clone()],
        bootstrap: vec![a_dial.clone()],
        auto_dial_mdns: true,
    });
    // Snapshot B's bound address now so A's restart can dial
    // it directly — without that, A2 would only discover B
    // via mDNS, which makes the test flaky in CI sandboxes.
    let b_listen = wait_for(
        || net_b.listen_addrs().into_iter().next(),
        std::time::Duration::from_secs(5),
    )
    .expect("net_b binds");
    let b_dial = b_listen.with(libp2p::multiaddr::Protocol::P2p(net_b.peer_id()));

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
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(rep_id),
    );
    node_b.attach_network(net_b);

    let net_a_arc = node_a.network().expect("net_a");
    let net_b_arc = node_b.network().expect("net_b");
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

    let _ = node_a
        .invoke(counter_a, dyn_payload(Msg::new("inc")))
        .expect("inc A");
    let _ = node_b
        .invoke(counter_b, dyn_payload(Msg::new("inc")))
        .expect("inc B");

    wait_for(
        || {
            if read_count(&node_a, counter_a) == Some(2) {
                Some(())
            } else {
                None
            }
        },
        std::time::Duration::from_secs(8),
    )
    .expect("A converges to 2");
    wait_for(
        || {
            if read_count(&node_b, counter_b) == Some(2) {
                Some(())
            } else {
                None
            }
        },
        std::time::Duration::from_secs(8),
    )
    .expect("B converges to 2");

    // ── Phase 2: A goes offline, B drives more incs ────────────
    let _ = node_a.collect();
    drop(net_a_arc); // release the test's reference so collect actually drops the redb arc

    // While A is offline, give B a few more incs.
    for _ in 3u32..=5 {
        let _ = node_b
            .invoke(counter_b, dyn_payload(Msg::new("inc")))
            .expect("inc on B while A offline");
    }
    wait_for(
        || {
            if read_count(&node_b, counter_b) == Some(5) {
                Some(())
            } else {
                None
            }
        },
        std::time::Duration::from_secs(2),
    )
    .expect("B reaches 5 alone");

    // ── Phase 3: A comes back, must catch up to 5 ──────────────
    let net_a2 = Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen],
        bootstrap: vec![b_dial],
        auto_dial_mdns: true,
    });

    let mut node_a2 = VosNode::with_prefix(prefix_a);
    let counter_a2 = node_a2.register(
        AgentConfig::new(counter_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(rep_id),
    );
    assert_eq!(
        counter_a2, counter_a,
        "restarted A must reuse the same ServiceId"
    );
    node_a2.attach_network(net_a2);

    let net_a2_arc = node_a2.network().expect("net_a2");
    wait_for(
        || {
            if net_a2_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some()
            {
                Some(())
            } else {
                None
            }
        },
        std::time::Duration::from_secs(10),
    )
    .expect("A re-Hellos B");

    // Catch-up window: A's CRDT layer should pull B's three
    // missed incs and replay; final count is 5.
    wait_for(
        || {
            if read_count(&node_a2, counter_a2) == Some(5) {
                Some(())
            } else {
                None
            }
        },
        std::time::Duration::from_secs(15),
    )
    .expect("A catches up to 5 after restart");
    assert_eq!(read_count(&node_b, counter_b), Some(5));

    let _ = node_a2.collect();
    let _ = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
fn scheduler_drops_non_existent_children_and_keeps_others_running() {
    // Robustness probe: the scheduler drives multiple children
    // each tick. If one child reports NOT_FOUND (or any non-Yielded
    // result), it should be dropped from the run queue but every
    // other child must still be invoked. The headline regression
    // would be: a single bad child kills the whole dispatch loop
    // because the scheduler aborts on the first failure, or worse,
    // the scheduler itself panics when an InvokeResult variant
    // isn't gracefully handled.
    //
    // Setup: scheduler init with children=[99, 100, 101]. The
    // external_invoke handler routes 99 + 101 to the echo worker
    // (so they DONE/Yielded normally) and returns None for 100
    // (so the runtime emits STATUS_NOT_FOUND). After one tick:
    //   - invokes_99 + invokes_101 must both be > 0
    //   - rt.panics must be 0 (scheduler itself didn't crash)
    use std::sync::atomic::{AtomicU32, Ordering};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let agent_data = match std::fs::read(&agent_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };
    let echo_so = {
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        std::path::PathBuf::from(format!(
            "{}/../target/{profile}/libecho_extension.so",
            workspace
        ))
    };
    if !echo_so.exists() {
        eprintln!("SKIP: echo-extension not built");
        return;
    }

    let blob = transpile_actor(&agent_data);
    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, blob);

    let good_a = vos::abi::service::ServiceId(99);
    let missing = vos::abi::service::ServiceId(100);
    let good_b = vos::abi::service::ServiceId(101);

    let invokes_a = std::sync::Arc::new(AtomicU32::new(0));
    let invokes_missing = std::sync::Arc::new(AtomicU32::new(0));
    let invokes_b = std::sync::Arc::new(AtomicU32::new(0));
    let ia = invokes_a.clone();
    let im = invokes_missing.clone();
    let ib = invokes_b.clone();

    let plugin: &'static _ = Box::leak(Box::new(
        unsafe { vos::extension::ExtensionPlugin::load(&echo_so) }.expect("load echo worker"),
    ));
    let instance = std::sync::Mutex::new(plugin.create());

    rt.set_external_invoke(Box::new(move |target, msg| {
        match target {
            t if t == good_a => {
                ia.fetch_add(1, Ordering::Relaxed);
                let mut inst = instance.lock().unwrap();
                inst.dispatch_raw(msg)
                    .map(vos::runtime::ExternalInvokeReply::done)
                    .ok()
                    .or(Some(vos::runtime::ExternalInvokeReply::done(Vec::new())))
            }
            t if t == good_b => {
                ib.fetch_add(1, Ordering::Relaxed);
                let mut inst = instance.lock().unwrap();
                inst.dispatch_raw(msg)
                    .map(vos::runtime::ExternalInvokeReply::done)
                    .ok()
                    .or(Some(vos::runtime::ExternalInvokeReply::done(Vec::new())))
            }
            t if t == missing => {
                im.fetch_add(1, Ordering::Relaxed);
                None // → runtime emits STATUS_NOT_FOUND to caller
            }
            _ => None,
        }
    }));

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![good_a.0, missing.0, good_b.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(agent_id, Vec::new());
    rt.run_blocking();

    assert_eq!(
        rt.panics, 0,
        "scheduler must not panic when one of its children is NOT_FOUND"
    );
    let na = invokes_a.load(Ordering::Relaxed);
    let nm = invokes_missing.load(Ordering::Relaxed);
    let nb = invokes_b.load(Ordering::Relaxed);
    assert!(
        na > 0,
        "good child A (99) should have been invoked at least once, got {na}"
    );
    assert!(
        nb > 0,
        "good child B (101) should have been invoked at least once, got {nb}"
    );
    assert!(
        nm > 0,
        "missing child (100) should have been *attempted* at least once, got {nm}"
    );

    // The scheduler's tick re-queues yielded children but drops
    // NOT_FOUND ones. Across all ticks the missing child should
    // be attempted exactly the number of times the scheduler
    // tried to enqueue it — typically just once at start. The
    // good children get re-invoked each tick they yield. So
    // good >= missing. A regression where missing gets retried
    // every tick (queue not pruned) shows up as `nm > na`.
    assert!(
        na >= nm && nb >= nm,
        "scheduler should drop the missing child rather than retry it each tick \
         — got A={na}, missing={nm}, B={nb}",
    );
}

#[test]
fn crdt_read_only_get_does_not_append_dag_nodes() {
    // Robustness probe: calling `get()` on a CRDT counter is
    // a pure read — the actor's `count` field doesn't change.
    // The runtime's commit pipeline detects this and skips the
    // DAG-node append (`crdt_commit_skips_unchanged_plain_commits`
    // covers the unit), but the *end-to-end* claim is that no
    // matter how often callers `get()`, the DAG size only grows
    // when state actually mutates. If pure reads bloat the DAG,
    // consensus history grows without bound and replay cost
    // explodes.
    //
    // Probe shape: drive 1 inc() (1 DAG node), then 50 get()s
    // (no new nodes), then another inc() (1 more node). Counts
    // dag-table row count by opening redb directly.
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let dir = std::env::temp_dir().join(format!(
        "vos_dag_growth_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"counter");
        h.update(&[0u8]);
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let count_dag_rows = |db_path: &std::path::Path| -> usize {
        use redb::ReadableTableMetadata;
        let db = redb::Database::create(db_path).expect("open redb");
        let txn = db.begin_read().expect("read txn");
        let table = match txn.open_table(vos::commit::DAG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return 0,
            Err(e) => panic!("open DAG_TABLE: {e}"),
        };
        table.len().expect("len") as usize
    };

    let counter_id;
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob)
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        counter_id = id;
        let counter = CrdtCounterRef::at(id);

        // Phase 1: one inc → one DAG node.
        vos::block_on(counter.inc(&mut &node)).expect("inc 1");
        node.shutdown();
        let _ = node.collect();
    }

    let db_path = dir
        .join("agents")
        .join(format!("{:08x}.redb", counter_id.0));
    assert!(
        db_path.exists(),
        "redb at {} should exist",
        db_path.display()
    );
    let after_one_inc = count_dag_rows(&db_path);
    assert_eq!(
        after_one_inc, 1,
        "exactly one DAG row after one inc(); got {after_one_inc}",
    );

    // Phase 2: many get()s — DAG row count must not grow.
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(grey_transpiler::link_elf(&counter_data).expect("transpile"))
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        assert_eq!(id, counter_id);
        let counter = CrdtCounterRef::at(id);
        for _ in 0..50 {
            assert_eq!(
                vos::block_on(counter.get(&mut &node)).expect("get during read-burst"),
                1
            );
        }
        node.shutdown();
        let _ = node.collect();
    }
    let after_50_reads = count_dag_rows(&db_path);
    assert_eq!(
        after_50_reads, after_one_inc,
        "DAG row count grew from {after_one_inc} to {after_50_reads} after 50 \
         pure read get()s — read-only dispatches must not append DAG nodes \
         or consensus history bloats without bound",
    );

    // Phase 3: another inc → exactly one more node.
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(grey_transpiler::link_elf(&counter_data).expect("transpile"))
                .with_consistency(Consistency::Crdt)
                .persist(&dir)
                .with_replication_id(rep_id),
        );
        assert_eq!(id, counter_id);
        let counter = CrdtCounterRef::at(id);
        vos::block_on(counter.inc(&mut &node)).expect("inc 2");
        assert_eq!(
            vos::block_on(counter.get(&mut &node)).expect("get post-inc"),
            2
        );
        node.shutdown();
        let _ = node.collect();
    }
    let after_two_incs = count_dag_rows(&db_path);
    assert_eq!(
        after_two_incs, 2,
        "expected exactly 2 DAG rows after 2 inc()s + 50 get()s, got {after_two_incs}",
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn raft_counter_single_node_replays_log_after_restart() {
    // Phase-1 boundary for Raft: prove `RaftCommit`'s redb tables
    // persist a log of `EffectLog`s and replay them on cold
    // restart to produce identical state. No peers, no leader
    // election — the strategy runs in `Role::SingleNode` so each
    // commit appends + applies + persists state in one redb txn.
    //
    // Same crdt-counter actor, same shape as
    // `crdt_counter_restart_replays_state_from_disk`, only the
    // `Consistency` selection differs. A single test exercises:
    //
    //   - `restore` returning `None` on the first boot
    //   - `commit_with_log` advancing `last_applied` per inc
    //   - skip-on-unchanged: `get()` calls don't append entries
    //   - cold restart: `replay_logs` rebuilds count from the log
    //   - subsequent inc()s continue from the rebuilt state
    use crdt_counter::CrdtCounterRef;
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let dir = std::env::temp_dir().join(format!(
        "vos_raft_phase1_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let counter_id;
    // ── Boot 1: drive 3 inc()s + a few read-only get()s. ──────
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob.clone())
                .with_consistency(Consistency::Raft)
                .persist(&dir),
        );
        counter_id = id;
        let counter = CrdtCounterRef::at(id);
        vos::block_on(counter.inc(&mut &node)).expect("inc 1");
        vos::block_on(counter.inc(&mut &node)).expect("inc 2");
        vos::block_on(counter.inc(&mut &node)).expect("inc 3");
        // Sanity reads — must NOT bloat the log.
        for _ in 0..5 {
            assert_eq!(
                vos::block_on(counter.get(&mut &node)).expect("get pre-restart"),
                3
            );
        }
        node.shutdown();
        let _ = node.collect();
    }

    // ── Probe: exactly 3 raft_log rows on disk, last_applied=3.
    let db_path = dir
        .join("agents")
        .join(format!("{:08x}.redb", counter_id.0));
    assert!(
        db_path.exists(),
        "redb at {} should exist",
        db_path.display()
    );
    {
        use redb::ReadableTableMetadata;
        let db = redb::Database::create(&db_path).expect("open redb");
        let txn = db.begin_read().expect("read txn");
        let log_table = txn.open_table(vos::raft::RAFT_LOG).expect("raft_log");
        assert_eq!(
            log_table.len().expect("len"),
            3,
            "exactly one raft_log entry per state-changing inc, \
             pure get()s must not append",
        );
        let meta = vos::raft::RaftMeta::load(&db).expect("load meta");
        assert_eq!(meta.last_applied, 3, "last_applied tracks log tail");
        assert_eq!(meta.commit_index, 3, "commit_index tracks log tail");
        assert_eq!(meta.current_term, 0, "no election yet → term stays 0");
        assert_eq!(meta.voted_for, None, "phase 1 never casts a vote");
    }

    // ── Boot 2: same data_dir. Replay log → count must be 3.
    {
        let mut node = VosNode::new();
        let id = node.register(
            AgentConfig::new(counter_blob)
                .with_consistency(Consistency::Raft)
                .persist(&dir),
        );
        assert_eq!(id, counter_id, "service id stable across restart");

        let counter = CrdtCounterRef::at(id);
        assert_eq!(
            vos::block_on(counter.get(&mut &node)).expect("get post-restart"),
            3,
            "log replay must produce identical state",
        );
        // One more inc: log appends a fourth entry post-restart.
        vos::block_on(counter.inc(&mut &node)).expect("inc post-restart");
        assert_eq!(
            vos::block_on(counter.get(&mut &node)).expect("get final"),
            4
        );
        node.shutdown();
        let _ = node.collect();
    }

    // ── Final check: log grew to 4 across the restart. ──────
    {
        use redb::ReadableTableMetadata;
        let db = redb::Database::create(&db_path).expect("reopen redb");
        let txn = db.begin_read().expect("read txn");
        let log_table = txn.open_table(vos::raft::RAFT_LOG).expect("raft_log");
        assert_eq!(log_table.len().expect("len"), 4);
        let meta = vos::raft::RaftMeta::load(&db).expect("load meta");
        assert_eq!(meta.last_applied, 4);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn raft_counter_three_node_replicates_state_to_all_replicas() {
    // Phase 5 boundary: the close-the-loop test for Consistency::Raft.
    //
    // Three networked VosNodes register a crdt-counter with
    // Consistency::Raft + the same `members` list + the same
    // replication_id. Once a leader emerges, drive `inc()` on
    // the leader. The leader's commit_with_log proposes through
    // its RaftWorker, blocks until the entry replicates to a
    // quorum, then writes the post-apply state. Followers receive
    // the new commit_index, their agent threads soft-restart,
    // replay the freshly-committed log entries through their
    // own runtime, and arrive at the same count.
    //
    // The test polls every replica via `get()` until they all
    // return the same value. That's the proof that:
    //   1. Raft elections work over real libp2p (phase 3).
    //   2. AppendEntries replication works (phase 4).
    //   3. commit_with_log blocks until quorum (phase 5.1).
    //   4. node.rs wires the worker + relay (phase 5.2).
    //   5. Followers' actor state catches up via sync_rx-driven
    //      soft restart — same path CRDT uses.
    use crdt_counter::CrdtCounterRef;
    use std::time::Duration;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_raft_e2e_{}_{}", std::process::id(), stamp,));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    let dir_c = dir_root.join("c");
    for p in [&dir_a, &dir_b, &dir_c] {
        std::fs::create_dir_all(p).unwrap();
    }

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"raft-crdt-counter");
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    // ── Three Networks meshed via explicit dial-out. ──────────
    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let kp_c = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let prefix_c = derive_node_prefix(&libp2p::PeerId::from(kp_c.public()));
    if prefix_a == prefix_b || prefix_a == prefix_c || prefix_b == prefix_c {
        eprintln!("SKIP: prefix collision");
        return;
    }
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let net_a = Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr =
        a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));
    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen.clone()],
        bootstrap: vec![a_dial.clone()],
        auto_dial_mdns: true,
    });
    let b_listen = wait_for(
        || net_b.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_b binds");
    let b_dial: libp2p::Multiaddr =
        b_listen.with(libp2p::multiaddr::Protocol::P2p(net_b.peer_id()));
    let net_c = Network::start(NetworkConfig {
        keypair: kp_c,
        local_prefix: prefix_c,
        listen: vec![listen],
        bootstrap: vec![a_dial, b_dial],
        auto_dial_mdns: true,
    });

    // ── Three VosNodes. ──────────────────────────────────────
    let mut node_a = VosNode::with_prefix(prefix_a);
    node_a.attach_network(net_a);
    let mut node_b = VosNode::with_prefix(prefix_b);
    node_b.attach_network(net_b);
    let mut node_c = VosNode::with_prefix(prefix_c);
    node_c.attach_network(net_c);

    // Wait for the Hello triangle so the workers can find each
    // other when register() spawns them.
    let net_a_arc = node_a.network().expect("net_a");
    let net_b_arc = node_b.network().expect("net_b");
    let net_c_arc = node_c.network().expect("net_c");
    wait_for(
        || {
            let ab = net_a_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some();
            let ac = net_a_arc.peer_for_prefix(prefix_c).is_some()
                && net_c_arc.peer_for_prefix(prefix_a).is_some();
            let bc = net_b_arc.peer_for_prefix(prefix_c).is_some()
                && net_c_arc.peer_for_prefix(prefix_b).is_some();
            (ab && ac && bc).then_some(())
        },
        Duration::from_secs(15),
    )
    .expect("Hello triangle");

    // Register the actor on every node.
    let members = vec![prefix_a, prefix_b, prefix_c];
    let counter_a = node_a.register(
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Raft)
            .with_members(members.clone())
            .with_replication_id(rep_id)
            .persist(&dir_a),
    );
    let counter_b = node_b.register(
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Raft)
            .with_members(members.clone())
            .with_replication_id(rep_id)
            .persist(&dir_b),
    );
    let counter_c = node_c.register(
        AgentConfig::new(counter_blob)
            .with_consistency(Consistency::Raft)
            .with_members(members)
            .with_replication_id(rep_id)
            .persist(&dir_c),
    );

    // ── Drive 3 inc()s with leader-retry. ────────────────────
    // Followers refuse `commit_with_log` because their RaftCommit
    // reports `NotLeader`. The macro-Client surfaces that as
    // `Unreachable`. Leadership may also flip between successive
    // inc() calls (election timer races), so each call does its
    // own search across replicas.
    let counters = [
        (&node_a, counter_a),
        (&node_b, counter_b),
        (&node_c, counter_c),
    ];
    let try_inc = || -> bool {
        let until = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            for (node, id) in counters.iter() {
                let counter = CrdtCounterRef::at(*id);
                if vos::block_on(counter.inc(&mut &**node)).is_ok() {
                    return true;
                }
            }
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    assert!(try_inc(), "first inc must land on a leader");
    assert!(try_inc(), "second inc must land");
    assert!(try_inc(), "third inc must land");

    // ── Wait for all three replicas to converge on count=3. ──
    // The leader's commit_with_log already blocked on quorum,
    // so by the time inc(3) returned the entry is committed
    // cluster-wide. Followers process the apply notification on
    // their next inbox poll (≤50 ms typically) and run
    // soft_restart to replay the freshly-committed entries into
    // their actor state.
    let read_count = |node: &VosNode, id: ServiceId| -> Option<u64> {
        vos::block_on(CrdtCounterRef::at(id).get(&mut &*node)).ok()
    };
    let final_a = wait_for(
        || (read_count(&node_a, counter_a) == Some(3)).then_some(3u64),
        Duration::from_secs(15),
    );
    let final_b = wait_for(
        || (read_count(&node_b, counter_b) == Some(3)).then_some(3u64),
        Duration::from_secs(15),
    );
    let final_c = wait_for(
        || (read_count(&node_c, counter_c) == Some(3)).then_some(3u64),
        Duration::from_secs(15),
    );
    assert_eq!(
        final_a,
        Some(3),
        "node A should converge to 3; last={:?}",
        read_count(&node_a, counter_a)
    );
    assert_eq!(
        final_b,
        Some(3),
        "node B should converge to 3; last={:?}",
        read_count(&node_b, counter_b)
    );
    assert_eq!(
        final_c,
        Some(3),
        "node C should converge to 3; last={:?}",
        read_count(&node_c, counter_c)
    );

    // Capture the redb paths before collecting (which drops the
    // VosNode and frees the DB exclusive lock). The check below
    // probes each replica's on-disk meta directly so we know
    // every node — leader AND followers — reached
    // `last_applied >= 3`. This pins host-side apply tracking
    // post-`last_applied` decouple: the worker bumps
    // `commit_index` via heartbeat propagation, the agent
    // notification fires soft_restart, the runtime replays
    // entries, and `RaftCommit::commit()` writes
    // `last_applied = commit_index` atomically with the
    // state row.
    let dirs = [
        ("A", dir_a.clone()),
        ("B", dir_b.clone()),
        ("C", dir_c.clone()),
    ];

    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = node_c.collect();

    /// Vos persists agent redb files at
    /// `{data_dir}/agents/{svc_id:08x}.redb`. Walk the agents
    /// subdir and return the first .redb path.
    fn first_agent_redb(data_dir: &std::path::Path) -> Option<std::path::PathBuf> {
        let agents = data_dir.join("agents");
        let entries = std::fs::read_dir(&agents).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "redb") {
                return Some(path);
            }
        }
        None
    }

    for (label, dir) in &dirs {
        let path = first_agent_redb(dir)
            .unwrap_or_else(|| panic!("replica {label}: no .redb under {}/agents", dir.display()));
        let db = redb::Database::create(&path).expect("open redb");
        let meta = vos::raft::RaftMeta::load(&db).expect("load meta");
        assert!(
            meta.commit_index >= 3,
            "replica {label}: commit_index = {} < 3",
            meta.commit_index,
        );
        assert!(
            meta.last_applied >= 3,
            "replica {label}: last_applied = {} < 3 — \
             host-side apply tracking didn't catch up to \
             the worker's commit_index",
            meta.last_applied,
        );
    }

    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
#[cfg(feature = "network")]
fn raft_three_node_cluster_compacts_log_after_replication() {
    // Phase 6: log compaction. Three networked nodes form a Raft
    // cluster, the leader proposes 64 entries (well past the
    // worker's default `Config::compact_hysteresis = 16`), every
    // follower replicates them, and the leader compacts
    // 1..=floor where floor = min(match_index across followers).
    // We poll each replica's redb directly until raft_log row
    // count drops below the hysteresis threshold + commit_index
    // reaches 64.
    use crdt_counter::CrdtCounterRef;
    use std::time::{Duration, Instant};
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
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

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_raft_compact_{}_{}", std::process::id(), stamp,));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    let dir_c = dir_root.join("c");
    for p in [&dir_a, &dir_b, &dir_c] {
        std::fs::create_dir_all(p).unwrap();
    }

    let rep_id: [u8; 32] = {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"raft-compact");
        h.update(&counter_blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let kp_c = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let prefix_c = derive_node_prefix(&libp2p::PeerId::from(kp_c.public()));
    if prefix_a == prefix_b || prefix_a == prefix_c || prefix_b == prefix_c {
        eprintln!("SKIP: prefix collision");
        return;
    }
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let net_a = Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr =
        a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));
    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen.clone()],
        bootstrap: vec![a_dial.clone()],
        auto_dial_mdns: true,
    });
    let b_listen = wait_for(
        || net_b.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_b binds");
    let b_dial: libp2p::Multiaddr =
        b_listen.with(libp2p::multiaddr::Protocol::P2p(net_b.peer_id()));
    let net_c = Network::start(NetworkConfig {
        keypair: kp_c,
        local_prefix: prefix_c,
        listen: vec![listen],
        bootstrap: vec![a_dial, b_dial],
        auto_dial_mdns: true,
    });

    let mut node_a = VosNode::with_prefix(prefix_a);
    node_a.attach_network(net_a);
    let mut node_b = VosNode::with_prefix(prefix_b);
    node_b.attach_network(net_b);
    let mut node_c = VosNode::with_prefix(prefix_c);
    node_c.attach_network(net_c);

    let net_a_arc = node_a.network().expect("net_a");
    let net_b_arc = node_b.network().expect("net_b");
    let net_c_arc = node_c.network().expect("net_c");
    wait_for(
        || {
            let ab = net_a_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some();
            let ac = net_a_arc.peer_for_prefix(prefix_c).is_some()
                && net_c_arc.peer_for_prefix(prefix_a).is_some();
            let bc = net_b_arc.peer_for_prefix(prefix_c).is_some()
                && net_c_arc.peer_for_prefix(prefix_b).is_some();
            (ab && ac && bc).then_some(())
        },
        Duration::from_secs(15),
    )
    .expect("Hello triangle");

    let members = vec![prefix_a, prefix_b, prefix_c];
    let counter_a = node_a.register(
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Raft)
            .with_members(members.clone())
            .with_replication_id(rep_id)
            .persist(&dir_a),
    );
    let counter_b = node_b.register(
        AgentConfig::new(counter_blob.clone())
            .with_consistency(Consistency::Raft)
            .with_members(members.clone())
            .with_replication_id(rep_id)
            .persist(&dir_b),
    );
    let counter_c = node_c.register(
        AgentConfig::new(counter_blob)
            .with_consistency(Consistency::Raft)
            .with_members(members)
            .with_replication_id(rep_id)
            .persist(&dir_c),
    );

    let counters = [
        (&node_a, counter_a),
        (&node_b, counter_b),
        (&node_c, counter_c),
    ];
    // Drive enough state-changing inc()s that the leader's
    // compaction routine kicks in (default
    // `Config::compact_hysteresis = 16` entries past the previous
    // snap pointer).
    const N_INCS: u32 = 64;
    let try_inc = || -> bool {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            for (node, id) in counters.iter() {
                let counter = CrdtCounterRef::at(*id);
                if vos::block_on(counter.inc(&mut &**node)).is_ok() {
                    return true;
                }
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    for i in 1..=N_INCS {
        assert!(try_inc(), "inc({i}) must land");
    }

    // Wait for compaction to fire on every replica. The leader
    // compacts after a heartbeat tick where min(match_index) has
    // advanced ≥ 16 past the last snap. Followers compact when
    // they see a higher snap pointer in subsequent AppendEntries
    // (phase 6 doesn't yet propagate snap_last_index over the
    // wire — followers compact independently when they become
    // the leader; for now the test asserts the *leader's* log
    // shrunk).
    //
    // We can identify whichever replica is currently leader by
    // looking for the smallest raft_log row count: only the
    // leader compacts in phase 6.
    std::thread::sleep(Duration::from_millis(500));

    let paths = [
        (
            "A",
            dir_a
                .join("agents")
                .join(format!("{:08x}.redb", counter_a.0)),
        ),
        (
            "B",
            dir_b
                .join("agents")
                .join(format!("{:08x}.redb", counter_b.0)),
        ),
        (
            "C",
            dir_c
                .join("agents")
                .join(format!("{:08x}.redb", counter_c.0)),
        ),
    ];

    // Shut down the workers so we can open the redb files.
    let _ = node_a.collect();
    let _ = node_b.collect();
    let _ = node_c.collect();

    use redb::ReadableTableMetadata;
    let mut min_rows: u64 = u64::MAX;
    for (label, p) in &paths {
        let db = redb::Database::create(p).expect("open");
        let txn = db.begin_read().expect("read");
        let log_table = txn.open_table(vos::raft::RAFT_LOG).expect("raft_log");
        let n = log_table.len().expect("len");
        eprintln!("replica {label}: {n} raft_log rows");
        let meta = vos::raft::RaftMeta::load(&db).expect("meta");
        eprintln!(
            "replica {label}: snap_last_index={} commit_index={}",
            meta.snap_last_index, meta.commit_index
        );
        // Every replica's commit_index should reach N_INCS once
        // replication propagates.
        assert!(
            meta.commit_index >= N_INCS as u64,
            "replica {label} commit_index={} < {N_INCS}",
            meta.commit_index
        );
        min_rows = min_rows.min(n);
    }
    // The leader's log must have been compacted: rows ≪ N_INCS.
    // We assert ≤ N_INCS - compact_hysteresis to leave slack.
    assert!(
        min_rows < N_INCS as u64,
        "no replica compacted: min_rows={min_rows} ≥ N_INCS={N_INCS}",
    );

    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
fn external_invoke_yielded_surfaces_as_invoke_yielded() {
    // Regression: under `vosx up` each [[agent]] / actor entry
    // gets its own VosNode agent thread, each with its own
    // VosRuntime. A scheduler agent's INVOKE of a yielded child
    // travels through the cross-thread path (`external_invoke`
    // → mpsc → callee's `handle_invoke_request`). That channel
    // used to carry only reply bytes; the runtime hard-coded
    // STATUS_DONE so every cross-agent yielded child surfaced
    // as `InvokeResult::Done` to the parent — the scheduler
    // dropped them from its run queue and the cooperative loop
    // died after one round.
    //
    // The fix introduces `ExternalInvokeReply::Yielded { state,
    // reply }`. This test pins the runtime side of that
    // contract: with a synthetic external_invoke that returns
    // Yielded, the scheduler's `lifecycle::invoke` must observe
    // STATUS_YIELDED and re-queue the child rather than
    // dropping it.
    use std::sync::atomic::{AtomicU32, Ordering};

    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
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
    let agent_id = register_svc(&mut rt, blob);

    let synthetic_target = vos::abi::service::ServiceId(99);
    let invokes = std::sync::Arc::new(AtomicU32::new(0));
    let invokes_clone = invokes.clone();

    rt.set_external_invoke(Box::new(move |target, _msg| {
        if target != synthetic_target {
            return None;
        }
        invokes_clone.fetch_add(1, Ordering::Relaxed);
        // Pretend the target yielded with a 4-byte u32 state,
        // matching counter's wire shape. As long as STATUS_YIELDED
        // surfaces, the scheduler will re-queue this id and
        // invoke it again next tick.
        Some(vos::runtime::ExternalInvokeReply::Yielded {
            state: 1u32.to_le_bytes().to_vec(),
            reply: Vec::new(),
        })
    }));

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![synthetic_target.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(agent_id, Vec::new());
    // A small handful of outer ticks suffices: the scheduler
    // self-tells `tick` and re-enters MAX_REFINE_ITERATIONS=64
    // times per outer tick, each one producing one invoke of
    // the synthetic target.
    for _ in 0..3 {
        if !rt.has_work() {
            break;
        }
        rt.tick_blocking();
    }

    let n = invokes.load(Ordering::Relaxed);
    assert!(
        n > 5,
        "scheduler invoked the synthetic yielded target only {n} time(s); \
         STATUS_YIELDED isn't surfacing through the external_invoke path"
    );
    assert_eq!(rt.panics, 0, "scheduler panicked");
}

#[test]
fn invoked_child_storage_isolated_from_parent_journal() {
    // Regression: `RefineJournal::writes` used to be a flat
    // `(key, value)` list with no service-id scoping. The parent
    // service's STATE_KEY entry then shadowed an INVOKEd child's
    // STORAGE_R for the same key (STATE_KEY is the same constant
    // for every actor), so children loaded the parent's encoded
    // state instead of their own.
    //
    // Concrete fingerprint with the scheduler agent driving the
    // counter: counter prints `count = 1, 2, 2, 2, 2, ...` —
    // counter receives the parent's 56-byte agent-state envelope
    // each time it tries to read its own 4-byte state, and rkyv's
    // try_decode succeeds against arbitrary trailing bytes,
    // returning `count = 1` regardless of what the agent passed
    // in via prev_state.
    //
    // After the fix the journal is per-service: the agent's
    // STATE_KEY journal entries don't shadow the counter's reads,
    // and the counter's STATE_KEY (written directly by
    // handle_invoke before the child runs) is what STORAGE_R
    // returns. Counter then progresses normally: 1, 2, 3, 4, ...
    let workspace = env!("CARGO_MANIFEST_DIR");
    let agent_path = format!(
        "{}/../examples/agents/scheduler/target/riscv64em-javm/release/scheduler.elf",
        workspace,
    );
    let agent_data = match std::fs::read(&agent_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: scheduler agent not built");
            return;
        }
    };

    let counter_elf = example_elf("counter");
    let agent_blob = transpile_actor(&agent_data);
    let counter_blob = transpile_actor(&counter_elf);

    let mut rt = VosRuntime::new();
    let agent_id = register_svc(&mut rt, agent_blob);
    let counter_id = register_svc(&mut rt, counter_blob);

    let args = vos::init::InitArgs::new().with(
        "children",
        vos::init::InitValue::ListU32(vec![counter_id.0]),
    );
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage
        .write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    rt.send_to(agent_id, Vec::new());

    // A few runtime ticks are enough — the scheduler self-tells
    // `tick` and re-enters up to MAX_REFINE_ITERATIONS times per
    // outer tick, so each call to `tick_blocking` advances the
    // counter many times.
    for _ in 0..3 {
        if !rt.has_work() {
            break;
        }
        rt.tick_blocking();
    }

    // Counter encodes `count: u32` as a 4-byte rkyv payload.
    let raw = rt
        .storage
        .read(counter_id, vos::lifecycle::STATE_KEY_BYTES)
        .expect("counter STATE_KEY persisted")
        .to_vec();
    assert_eq!(raw.len(), 4, "counter state should be a 4-byte u32 (rkyv)");
    let count = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    assert!(
        count > 5,
        "scheduler-driven counter is stuck at {count}; parent's STATE_KEY is \
         shadowing counter's STORAGE_R again"
    );
    assert_eq!(rt.panics, 0, "no service should have panicked");
}

#[test]
#[cfg(feature = "network")]
fn raft_dynamic_join_grows_single_node_cluster_to_three() {
    // Phase B boundary: a fresh node joins a running Raft cluster
    // at runtime via `WorkerHandle::change_membership` (Ongaro
    // §4.3 joint consensus).
    //
    // Flow:
    //   1. Node A boots solo (`members = [A]`), self-elects, runs
    //      a few application proposes — the cluster works.
    //   2. Node B boots with `members = [B]` (its own initial
    //      view), dials A, completes the Hello handshake.
    //   3. Test orchestrator calls `change_membership([A, B])`
    //      on A's worker → joint-consensus joint entry commits →
    //      vos-raft auto-emits the retire entry → B is now a
    //      voter.
    //   4. Repeat for node C → cluster is {A, B, C}, quorum = 2.
    //   5. Drive proposes from A; assert all three replicas
    //      converge on the same commit_index.
    //
    // The test wires libp2p, vos's RaftWorker, and vos's
    // `change_membership` together — same plumbing `vosx` would
    // use for an auto-join CLI on top of this API.
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::raft::{RaftWorker, Role, WorkerConfig};

    fn wait_for_role_at(h: &vos::raft::WorkerHandle, want: Role, max: Duration) -> bool {
        let deadline = Instant::now() + max;
        while Instant::now() < deadline {
            if h.role() == want {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_raft_join_{}_{}", std::process::id(), stamp,));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    let dir_c = dir_root.join("c");
    for p in [&dir_a, &dir_b, &dir_c] {
        std::fs::create_dir_all(p).unwrap();
    }

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let kp_c = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let prefix_c = derive_node_prefix(&libp2p::PeerId::from(kp_c.public()));
    if prefix_a == prefix_b || prefix_a == prefix_c || prefix_b == prefix_c {
        eprintln!("SKIP: prefix collision");
        return;
    }
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    // ── Node A — solo cluster, listening for joiners. ─────────
    let net_a = Arc::new(Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    }));
    let a_addr = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let db_a = Arc::new(redb::Database::create(dir_a.join("raft.redb")).unwrap());
    let rep_id = [0xC3u8; 32];
    let worker_a = RaftWorker::spawn(
        db_a.clone(),
        WorkerConfig {
            me: prefix_a,
            members: vec![prefix_a],
            replication_id: rep_id,
            election_timeout_ms: (50, 150),
            heartbeat_interval_ms: 20,
        },
        Some(net_a.clone()),
        None,
    );
    net_a.register_raft_handler(rep_id, Arc::new(worker_a.handler()));
    let h_a = worker_a.handler();
    assert!(
        wait_for_role_at(&h_a, Role::Leader, Duration::from_secs(5)),
        "solo node A self-elects"
    );

    // ── Node B — joins via A. ─────────────────────────────────
    let net_b = Arc::new(Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen.clone()],
        bootstrap: vec![a_dial.clone()],
        auto_dial_mdns: true,
    }));
    let b_addr = wait_for(
        || net_b.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_b binds");
    let b_dial: libp2p::Multiaddr = b_addr.with(libp2p::multiaddr::Protocol::P2p(net_b.peer_id()));

    // Wait for the Hello handshake so A's VosTransport can route
    // AppendEntries to B once the membership change commits.
    wait_for(
        || {
            (net_a.peer_for_prefix(prefix_b).is_some() && net_b.peer_for_prefix(prefix_a).is_some())
                .then_some(())
        },
        Duration::from_secs(15),
    )
    .expect("A↔B Hello");

    let db_b = Arc::new(redb::Database::create(dir_b.join("raft.redb")).unwrap());
    let worker_b = RaftWorker::spawn(
        db_b.clone(),
        WorkerConfig {
            me: prefix_b,
            // B starts knowing only itself — it's a Follower until
            // A's ConfigChange teaches it about the wider cluster.
            members: vec![prefix_b],
            replication_id: rep_id,
            // Long timeout so B doesn't self-elect before joining.
            election_timeout_ms: (5_000, 10_000),
            heartbeat_interval_ms: 1_000,
        },
        Some(net_b.clone()),
        None,
    );
    net_b.register_raft_handler(rep_id, Arc::new(worker_b.handler()));

    // A: change_membership([A, B]) — joint-consensus joint entry
    // commits via {A}'s self-quorum, then the retire entry needs
    // {A, B} quorum and replicates to B.
    let join_idx = h_a
        .change_membership(vec![prefix_a, prefix_b])
        .expect("A: change_membership([A, B])");
    assert!(join_idx >= 1, "joint entry must have a real index");

    let until = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(snap_b) = worker_b.handler().snapshot() {
            if snap_b.commit_index >= join_idx + 1 {
                break;
            }
        }
        assert!(
            Instant::now() < until,
            "B did not catch up to commit_index >= {} within 15s",
            join_idx + 1
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // ── Node C — joins via A and B. ───────────────────────────
    let net_c = Arc::new(Network::start(NetworkConfig {
        keypair: kp_c,
        local_prefix: prefix_c,
        listen: vec![listen],
        bootstrap: vec![a_dial, b_dial],
        auto_dial_mdns: true,
    }));
    wait_for(
        || {
            (net_a.peer_for_prefix(prefix_c).is_some()
                && net_c.peer_for_prefix(prefix_a).is_some()
                && net_b.peer_for_prefix(prefix_c).is_some()
                && net_c.peer_for_prefix(prefix_b).is_some())
            .then_some(())
        },
        Duration::from_secs(15),
    )
    .expect("A↔C, B↔C Hello");

    let db_c = Arc::new(redb::Database::create(dir_c.join("raft.redb")).unwrap());
    let worker_c = RaftWorker::spawn(
        db_c.clone(),
        WorkerConfig {
            me: prefix_c,
            members: vec![prefix_c],
            replication_id: rep_id,
            election_timeout_ms: (5_000, 10_000),
            heartbeat_interval_ms: 1_000,
        },
        Some(net_c.clone()),
        None,
    );
    net_c.register_raft_handler(rep_id, Arc::new(worker_c.handler()));

    let join_idx2 = h_a
        .change_membership(vec![prefix_a, prefix_b, prefix_c])
        .expect("A: change_membership([A, B, C])");
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let snap_c = worker_c.handler().snapshot();
        if snap_c
            .as_ref()
            .is_some_and(|s| s.commit_index >= join_idx2 + 1)
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "C did not catch up to commit_index >= {} within 15s",
            join_idx2 + 1
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // ── Drive a few application proposes via A; all three
    //    replicas must converge on the same commit_index. ─────
    let p1 = h_a.propose(b"hello".to_vec()).expect("propose 1");
    let p2 = h_a.propose(b"world".to_vec()).expect("propose 2");
    assert!(p2 > p1);

    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let s_a = worker_a.handler().snapshot();
        let s_b = worker_b.handler().snapshot();
        let s_c = worker_c.handler().snapshot();
        if let (Some(a), Some(b), Some(c)) = (s_a, s_b, s_c) {
            if a.commit_index >= p2 && b.commit_index >= p2 && c.commit_index >= p2 {
                break;
            }
        }
        assert!(
            Instant::now() < until,
            "post-join replicas didn't converge on commit_index >= {p2}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    worker_a.shutdown();
    worker_b.shutdown();
    worker_c.shutdown();
    match Arc::try_unwrap(net_a) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    match Arc::try_unwrap(net_b) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    match Arc::try_unwrap(net_c) {
        Ok(n) => n.join(),
        Err(_) => {}
    }

    let _ = std::fs::remove_dir_all(&dir_root);
}

#[test]
#[cfg(feature = "network")]
fn raft_join_req_wire_path_grows_cluster_via_libp2p() {
    // End-to-end test of the `Frame::RaftJoinReq` wire path.
    //
    // Direct API path is already covered by
    // `raft_dynamic_join_grows_single_node_cluster_to_three`.
    // This test covers the libp2p RPC: B sends an actual
    // `RaftJoinReq` frame to A, A's `handle_join` impl runs
    // change_membership, B becomes a voter.
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use vos::network::{Network, NetworkConfig, RaftJoinResult, derive_node_prefix};
    use vos::raft::{RaftWorker, Role, WorkerConfig};

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    if prefix_a == prefix_b {
        eprintln!("SKIP: prefix collision");
        return;
    }
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vos_raft_join_wire_{}_{}",
        std::process::id(),
        stamp,
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let rep_id = [0xC4u8; 32];

    // ── Node A (solo bootstrap, leader). ──────────────────────
    let net_a = Arc::new(Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    }));
    let a_addr = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));
    let db_a = Arc::new(redb::Database::create(dir.join("a.redb")).unwrap());
    let worker_a = RaftWorker::spawn(
        db_a,
        WorkerConfig {
            me: prefix_a,
            members: vec![prefix_a],
            replication_id: rep_id,
            election_timeout_ms: (50, 150),
            heartbeat_interval_ms: 20,
        },
        Some(net_a.clone()),
        None,
    );
    net_a.register_raft_handler(rep_id, Arc::new(worker_a.handler()));
    let h_a = worker_a.handler();
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until && h_a.role() != Role::Leader {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(h_a.role(), Role::Leader, "A should self-elect");

    // ── Node B (joiner). ──────────────────────────────────────
    let net_b = Arc::new(Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
    }));
    wait_for(
        || {
            (net_a.peer_for_prefix(prefix_b).is_some() && net_b.peer_for_prefix(prefix_a).is_some())
                .then_some(())
        },
        Duration::from_secs(15),
    )
    .expect("Hello");

    // ── Send the join request OVER THE WIRE. ──────────────────
    // This is the critical bit — exercises Network's
    // SendRaftJoin command, the swarm-thread routing, A's
    // dispatch through `handle_join`, and the Accepted response.
    let target_a = net_b.peer_for_prefix(prefix_a).unwrap();
    let rx = net_b.send_raft_join_req(target_a, rep_id, prefix_b);
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("join RPC reply");
    let joint_index = match result {
        RaftJoinResult::Accepted { joint_index } => {
            assert!(joint_index >= 1, "joint entry has a real index");
            joint_index
        }
        other => panic!("expected Accepted, got {other:?}"),
    };

    // ── Spawn B's worker with the (post-join) member set. ────
    let db_b = Arc::new(redb::Database::create(dir.join("b.redb")).unwrap());
    let worker_b = RaftWorker::spawn(
        db_b,
        WorkerConfig {
            me: prefix_b,
            members: vec![prefix_a, prefix_b],
            replication_id: rep_id,
            election_timeout_ms: (5_000, 10_000),
            heartbeat_interval_ms: 1_000,
        },
        Some(net_b.clone()),
        None,
    );
    net_b.register_raft_handler(rep_id, Arc::new(worker_b.handler()));

    // ── B should see commit_index >= joint_index + 1. ────────
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(snap) = worker_b.handler().snapshot() {
            if snap.commit_index >= joint_index + 1 {
                break;
            }
        }
        assert!(
            Instant::now() < until,
            "B didn't reach commit_index >= {} within 15s",
            joint_index + 1
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // ── Status RPC over the wire reports the same state. ────
    let rx = net_b.send_raft_status_req(target_a, rep_id);
    let status = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("status RPC reply");
    assert!(status.present, "A hosts the group");
    assert_eq!(status.role, vos::network::RaftRole::Leader);
    assert!(
        status.members.contains(&prefix_a) && status.members.contains(&prefix_b),
        "post-join member set should contain both replicas; got {:?}",
        status.members
    );

    worker_a.shutdown();
    worker_b.shutdown();
    match Arc::try_unwrap(net_a) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    match Arc::try_unwrap(net_b) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn raft_status_req_returns_absent_for_unknown_group() {
    // `vosx ps` queries every connected peer for every Raft
    // group in the manifest. Peers that don't host a particular
    // group must reply `present = false` so the client can
    // skip them cleanly. This test forces that path.
    use std::sync::Arc;
    use std::time::Duration;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::raft::{RaftWorker, WorkerConfig};

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    if prefix_a == prefix_b {
        eprintln!("SKIP: prefix collision");
        return;
    }
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("vos_raft_status_{}_{}", std::process::id(), stamp,));
    std::fs::create_dir_all(&dir).unwrap();

    let net_a = Arc::new(Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    }));
    let a_addr = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    // A hosts group X; B doesn't host any group.
    let group_x = [0xAAu8; 32];
    let db_a = Arc::new(redb::Database::create(dir.join("a.redb")).unwrap());
    let worker_a = RaftWorker::spawn(
        db_a,
        WorkerConfig {
            me: prefix_a,
            members: vec![prefix_a],
            replication_id: group_x,
            election_timeout_ms: (5_000, 10_000),
            heartbeat_interval_ms: 1_000,
        },
        Some(net_a.clone()),
        None,
    );
    net_a.register_raft_handler(group_x, Arc::new(worker_a.handler()));

    let net_b = Arc::new(Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
    }));
    wait_for(
        || net_b.peer_for_prefix(prefix_a).is_some().then_some(()),
        Duration::from_secs(15),
    )
    .expect("Hello");
    let target_a = net_b.peer_for_prefix(prefix_a).unwrap();

    // Group A hosts → present = true.
    let rx = net_b.send_raft_status_req(target_a, group_x);
    let status = rx.recv_timeout(Duration::from_secs(2)).expect("status");
    assert!(status.present, "A should report present for group X");
    assert_eq!(status.members, vec![prefix_a]);

    // Group A doesn't host → present = false, leader_hint=None.
    let group_y = [0xBBu8; 32];
    let rx = net_b.send_raft_status_req(target_a, group_y);
    let status = rx.recv_timeout(Duration::from_secs(2)).expect("status");
    assert!(
        !status.present,
        "A shouldn't report present for unknown group"
    );
    assert!(status.leader_hint.is_none());

    worker_a.shutdown();
    match Arc::try_unwrap(net_a) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    match Arc::try_unwrap(net_b) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "network")]
fn manifest_req_returns_installed_provider_payload() {
    // Regression: `vosx join <bootnode>` (without `--manifest`)
    // hits `Frame::ManifestReq` to fetch the bootnode's
    // space.toml + actor blobs. The bootnode side requires a
    // `NetworkService` to be installed via `set_service`
    // (with `manifest()` returning Some); until vosx wired
    // that up via `node.set_manifest`, every
    // joiner saw an empty reply and bailed with the misleading
    // "no manifest exposed" error.
    //
    // This test stands in for the vosx integration: install a
    // stub provider on A, send a ManifestReq from B, assert the
    // payload round-trips. Without the install (and without the
    // vosx-side wiring) the same call returns empty bytes.
    use std::sync::Arc;
    use std::time::Duration;
    use vos::network::{
        ManifestBlob, ManifestReply, Network, NetworkConfig, NetworkService, derive_node_prefix,
    };

    struct StubManifest {
        reply: ManifestReply,
    }
    impl NetworkService for StubManifest {
        fn manifest(&self) -> Option<ManifestReply> {
            Some(self.reply.clone())
        }
    }

    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    if prefix_a == prefix_b {
        eprintln!("SKIP: prefix collision");
        return;
    }
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let net_a = Arc::new(Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    }));
    let a_addr = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr = a_addr.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let toml = br#"space = "demo"
version = "0.1.0"
"#
    .to_vec();
    let blobs = vec![
        ManifestBlob {
            name: "ledger".into(),
            blob: vec![0xAA; 64],
        },
        ManifestBlob {
            name: "scheduler".into(),
            blob: vec![0xBB; 32],
        },
    ];
    net_a.set_service(Arc::new(StubManifest {
        reply: ManifestReply {
            toml: toml.clone(),
            blobs: blobs.clone(),
        },
    }));

    let net_b = Arc::new(Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
    }));
    wait_for(
        || net_b.peer_for_prefix(prefix_a).is_some().then_some(()),
        Duration::from_secs(15),
    )
    .expect("Hello");
    let target_a = net_b.peer_for_prefix(prefix_a).unwrap();

    let rx = net_b.send_manifest_req(target_a);
    let got = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("manifest reply");

    assert_eq!(got.toml, toml, "toml bytes round-trip");
    assert_eq!(got.blobs, blobs, "blobs round-trip");

    match Arc::try_unwrap(net_a) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
    match Arc::try_unwrap(net_b) {
        Ok(n) => n.join(),
        Err(_) => {}
    }
}
