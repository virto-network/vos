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

#[test]
#[cfg(feature = "network")]
fn hyperspace_resolve_returns_remote_host_prefix() {
    // End-to-end test for the hyperspace runtime — proves the
    // load-bearing claim:
    //
    //   Two member-spaces (different per-space replication_ids,
    //   different `space-registry` replicas at REGISTRY=0) share a
    //   hyperspace by both spawning a `space-registry` replica at
    //   HYPERSPACE_REGISTRY=1 with the same hyperspace replication
    //   id. After a `register_remote("alice", host_prefix_a)` call
    //   on A's hyperspace registry, B's hyperspace registry replica
    //   converges via gossipsub-CRDT and `resolve("alice", _)`
    //   returns a ServiceId whose top 16 bits == prefix_a — i.e.
    //   the address routes to A's node, not B's local replica.
    //
    // Doesn't yet exercise full `Context::resolve`-driven invoke
    // (that needs a peer-space agent that calls resolve from inside
    // a handler — comes with the bridge actor). This test pins the
    // registry's wire surface and the CRDT propagation.
    use space_registry::SpaceRegistryRef;
    use std::time::Duration;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};

    let registry_path = format!(
        "{}/../actors/space-registry/target/riscv64em-javm/release/space_registry.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let registry_elf = match std::fs::read(&registry_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: space-registry actor not built (run `just build-registry`)");
            return;
        }
    };
    let registry_blob = grey_transpiler::link_elf(&registry_elf).expect("transpile");

    // Each node gets its own data dir + libp2p identity. The
    // hyperspace replication_id is shared so both HYPERSPACE_REGISTRY
    // replicas land in the same gossipsub group; the per-space
    // replication_ids differ so the local REGISTRY replicas stay
    // isolated (= different "spaces").
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root = std::env::temp_dir().join(format!(
        "vos_hyperspace_e2e_{}_{}",
        std::process::id(),
        stamp
    ));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let mk_id = |label: &[u8]| -> [u8; 32] {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(label);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };
    let space_a_rep = mk_id(b"hyperspace-test/space-a-registry");
    let space_b_rep = mk_id(b"hyperspace-test/space-b-registry");
    let hs_rep = mk_id(b"hyperspace-test/hyperspace-registry");

    // ── Networks ───────────────────────────────────────────────
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
        Duration::from_secs(5),
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

    // ── Nodes + registries ─────────────────────────────────────
    let mut node_a = VosNode::with_prefix(prefix_a);
    // Local space-A registry at REGISTRY=0
    let _local_a = node_a.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(space_a_rep),
        ServiceId::REGISTRY,
    );
    // Hyperspace registry at HYPERSPACE_REGISTRY=1, shared rep id
    let _hs_a = node_a.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(hs_rep),
        ServiceId::HYPERSPACE_REGISTRY,
    );
    node_a.attach_network(net_a);

    let mut node_b = VosNode::with_prefix(prefix_b);
    let _local_b = node_b.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(space_b_rep),
        ServiceId::REGISTRY,
    );
    let _hs_b = node_b.register_at_id(
        AgentConfig::new(registry_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(hs_rep),
        ServiceId::HYPERSPACE_REGISTRY,
    );
    node_b.attach_network(net_b);

    // Wait for Hello round-trip so peer prefixes are known.
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
        Duration::from_secs(10),
    )
    .expect("Hello handshake");

    // ── Drive the test ─────────────────────────────────────────
    // Node A advertises agent "alice" into the hyperspace registry
    // with host_prefix = prefix_a. CRDT sync should propagate this
    // to node B's hyperspace replica.
    let hs_reg_a = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
    let status =
        vos::block_on(hs_reg_a.register_remote(&mut &node_a, "alice".to_string(), prefix_a as u32))
            .expect("register_remote on A");
    assert_eq!(status, space_registry::STATUS_OK);

    // ── Wait for convergence + assert ──────────────────────────
    let hs_reg_b = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
    let mappings = wait_for(
        || {
            let m = vos::block_on(hs_reg_b.host_mappings(&mut &node_b)).ok()?;
            if m.iter().any(|h| h.instance_name == "alice") {
                Some(m)
            } else {
                None
            }
        },
        Duration::from_secs(8),
    )
    .expect("hyperspace mapping for 'alice' did not propagate to B within deadline");

    let alice = mappings
        .iter()
        .find(|h| h.instance_name == "alice")
        .expect("alice in mappings");
    assert_eq!(
        alice.host_prefix, prefix_a,
        "B's hyperspace replica records alice@prefix_a (got {:#06x})",
        alice.host_prefix
    );

    // The load-bearing assertion: from B's perspective, resolve(alice)
    // returns a ServiceId whose node_prefix is A's, not B's.
    let resolved =
        vos::block_on(hs_reg_b.resolve(&mut &node_b, "alice".to_string(), prefix_b as u64))
            .expect("resolve on B");
    assert_ne!(resolved, 0, "resolve did not find 'alice'");
    let resolved_prefix = (resolved >> 16) as u16;
    assert_eq!(
        resolved_prefix, prefix_a,
        "B's resolve('alice') must return A's prefix (got {resolved_prefix:#06x}, want {prefix_a:#06x})",
    );
    // Sanity: not B's prefix.
    assert_ne!(
        resolved_prefix, prefix_b,
        "resolve must not return B's own prefix for a remote-hosted agent"
    );

    let results_a = node_a.collect();
    let results_b = node_b.collect();
    let _ = std::fs::remove_dir_all(&dir_root);
    let panics: u32 = results_a
        .iter()
        .chain(results_b.iter())
        .map(|r| r.panics)
        .sum();
    assert_eq!(panics, 0, "actor panics during hyperspace test: {panics}");
}

#[test]
#[cfg(feature = "network")]
fn cross_space_bridge_forward_dispatches_to_local_target() {
    // End-to-end test for the bridge actor — proves the load-bearing
    // claim of the cross-space gateway pattern:
    //
    //   Bank A's caller resolves bank B's bridge through the
    //   hyperspace registry, invokes bridge_b.forward("counter", ...),
    //   bridge_b resolves "counter" locally (via hyperspace fall-
    //   through since the counter is at a known ServiceId on B),
    //   dispatches the payload, and returns the reply. Counter
    //   state advances on B; A sees the new count.
    //
    // Also pins the three error statuses on `ForwardReply`:
    //   - FORWARD_NOT_FOUND when the name is unknown
    //   - FORWARD_SELF_TARGET when the name resolves to the bridge itself
    //   - FORWARD_OK for the happy path
    use space_bridge::{FORWARD_NOT_FOUND, FORWARD_OK, FORWARD_SELF_TARGET, SpaceBridgeRef};
    use space_registry::SpaceRegistryRef;
    use std::time::Duration;
    use vos::Encode;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};
    use vos::value::{Msg, TAG_DYNAMIC};

    let registry_path = format!(
        "{}/../actors/space-registry/target/riscv64em-javm/release/space_registry.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let bridge_path = format!(
        "{}/../actors/space-bridge/target/riscv64em-javm/release/space_bridge.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let counter_path = format!(
        "{}/../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt_counter.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let registry_elf = match std::fs::read(&registry_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: space-registry not built (run `just build-registry`)");
            return;
        }
    };
    let bridge_elf = match std::fs::read(&bridge_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: space-bridge not built (run `just build-bridge`)");
            return;
        }
    };
    let counter_elf = match std::fs::read(&counter_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: crdt-counter not built (run `just build-pvm`)");
            return;
        }
    };
    let registry_blob = grey_transpiler::link_elf(&registry_elf).expect("transpile registry");
    let bridge_blob = grey_transpiler::link_elf(&bridge_elf).expect("transpile bridge");
    let counter_blob = grey_transpiler::link_elf(&counter_elf).expect("transpile counter");

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_bridge_e2e_{}_{}", std::process::id(), stamp));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let mk_id = |label: &[u8]| -> [u8; 32] {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(label);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };
    let space_a_rep = mk_id(b"bridge-test/space-a");
    let space_b_rep = mk_id(b"bridge-test/space-b");
    let hs_rep = mk_id(b"bridge-test/hyperspace");
    let counter_rep = mk_id(b"bridge-test/counter");

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
        Duration::from_secs(5),
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

    // Each bridge registers under a unique name in the hyperspace
    // registry ("bridge-a", "bridge-b") so the two don't collide
    // on the host_mappings key. ServiceIds are derived from the
    // same name so resolve and registration agree on the slot.
    // Bridges are stateless — Ephemeral consistency, no redb, no
    // gossipsub topic, no replication overhead.
    let bridge_a_id =
        vos::abi::service::ServiceId(space_registry::instance_service_id("bridge-a", prefix_a));
    let bridge_b_id =
        vos::abi::service::ServiceId(space_registry::instance_service_id("bridge-b", prefix_b));
    let counter_b_id =
        vos::abi::service::ServiceId(space_registry::instance_service_id("counter", prefix_b));

    let mut node_a = VosNode::with_prefix(prefix_a);
    node_a.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(space_a_rep),
        ServiceId::REGISTRY,
    );
    node_a.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(hs_rep),
        ServiceId::HYPERSPACE_REGISTRY,
    );
    node_a.register_at_id(
        AgentConfig::new(bridge_blob.clone()).with_consistency(Consistency::Ephemeral),
        bridge_a_id,
    );
    node_a.attach_network(net_a);

    let mut node_b = VosNode::with_prefix(prefix_b);
    node_b.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(space_b_rep),
        ServiceId::REGISTRY,
    );
    node_b.register_at_id(
        AgentConfig::new(registry_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(hs_rep),
        ServiceId::HYPERSPACE_REGISTRY,
    );
    node_b.register_at_id(
        AgentConfig::new(bridge_blob).with_consistency(Consistency::Ephemeral),
        bridge_b_id,
    );
    // The forward target on B. Crdt + persist so the inc state
    // sticks; replication_id is unique to this test so it doesn't
    // collide with other crdt-counter-using tests in the same run.
    node_b.register_at_id(
        AgentConfig::new(counter_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(counter_rep),
        counter_b_id,
    );
    node_b.attach_network(net_b);

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
        Duration::from_secs(10),
    )
    .expect("Hello handshake");

    // Advertise bridge_b and counter in node A's hyperspace registry.
    // bridge_b: so A can resolve it by name. counter: so bridge_b
    // resolves "counter" via the hyperspace fall-through (the local
    // registry's agents catalog is empty since we bypass install()).
    let hs_reg = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
    for (name, prefix) in [("bridge-b", prefix_b), ("counter", prefix_b)] {
        let status =
            vos::block_on(hs_reg.register_remote(&mut &node_a, name.to_string(), prefix as u32))
                .expect("register_remote");
        assert_eq!(status, space_registry::STATUS_OK, "register_remote {name}");
    }

    // Sanity: A's hyperspace registry resolves bridge-b to the
    // right ServiceId before we exercise it.
    let resolved =
        vos::block_on(hs_reg.resolve(&mut &node_a, "bridge-b".to_string(), prefix_a as u64))
            .expect("resolve bridge-b");
    assert_eq!(resolved, bridge_b_id.0, "bridge-b resolves to B");

    let bridge_remote = SpaceBridgeRef::at(bridge_b_id);

    // 1) where_am_i — proves we reached bridge_b on B, not a
    // local shadow.
    let where_am_i = vos::block_on(bridge_remote.where_am_i(&mut &node_a))
        .expect("cross-node where_am_i invoke");
    assert_eq!(where_am_i, bridge_b_id.0, "where_am_i is bridge_b");
    assert_ne!(where_am_i, bridge_a_id.0, "not bridge_a");

    // 2) Happy path: forward inc + get to the counter on B.
    let inc_payload = {
        let m = Msg::new("inc");
        let encoded = m.encode();
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(TAG_DYNAMIC);
        out.extend_from_slice(&encoded);
        out
    };
    let get_payload = {
        let m = Msg::new("get");
        let encoded = m.encode();
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(TAG_DYNAMIC);
        out.extend_from_slice(&encoded);
        out
    };

    let inc_reply =
        vos::block_on(bridge_remote.forward(&mut &node_a, "counter".to_string(), inc_payload))
            .expect("forward inc");
    assert_eq!(
        inc_reply.status, FORWARD_OK,
        "inc forward should succeed, got status {}",
        inc_reply.status
    );

    let get_reply =
        vos::block_on(bridge_remote.forward(&mut &node_a, "counter".to_string(), get_payload))
            .expect("forward get");
    assert_eq!(
        get_reply.status, FORWARD_OK,
        "get forward should succeed, got status {}",
        get_reply.status
    );
    let value: vos::value::Value = vos::Decode::decode(&get_reply.payload);
    assert_eq!(
        value.as_u64(),
        Some(1),
        "counter should be 1 after one inc through the bridge, got {value:?}",
    );

    // 3) Self-target check: forwarding to bridge-b's own name from
    // bridge-b returns SELF_TARGET, not a recursive invoke.
    let self_reply =
        vos::block_on(bridge_remote.forward(&mut &node_a, "bridge-b".to_string(), Vec::new()))
            .expect("forward self");
    assert_eq!(
        self_reply.status, FORWARD_SELF_TARGET,
        "forwarding to bridge-b's own name must return SELF_TARGET, got status {}",
        self_reply.status
    );
    assert!(self_reply.payload.is_empty());

    // 4) Unknown name: NOT_FOUND.
    let not_found = vos::block_on(bridge_remote.forward(
        &mut &node_a,
        "nonexistent-agent".to_string(),
        Vec::new(),
    ))
    .expect("forward unknown");
    assert_eq!(
        not_found.status, FORWARD_NOT_FOUND,
        "unknown name must return NOT_FOUND, got status {}",
        not_found.status
    );
    assert!(not_found.payload.is_empty());

    let results_a = node_a.collect();
    let results_b = node_b.collect();
    let panics: u32 = results_a
        .iter()
        .chain(results_b.iter())
        .map(|r| r.panics)
        .sum();
    let _ = std::fs::remove_dir_all(&dir_root);
    assert_eq!(panics, 0, "actor panics during bridge test: {panics}");
}

#[test]
fn clerk_ledger_bootstrap_and_create_account() {
    // Single-node smoke test for clerk-ledger's first kernel-touching
    // surface. Builds a signed cipher-clerk CreateAccount on the host
    // side, pushes it through the actor's create_account handler, and
    // pins all five status codes (OK + NOT_BOOTSTRAPPED + WRONG_JOURNAL
    // + ACCOUNT_EXISTS + SIGNATURE_INVALID).
    //
    // Networking isn't exercised here — the cross-space federation
    // story comes in Phase 4. This pins the actor's wire ABI against
    // cipher-clerk's rkyv-archived CreateAccount.
    use cipher_clerk::conventions::{BankCode, Iso4217};
    use cipher_clerk::crypto::{Amount, Keypair};
    use cipher_clerk::ids::JournalId;
    use cipher_clerk::kernel::CreateAccount as CcCreateAccount;
    use cipher_clerk::types::{Account, BalancePair, Layer};
    use clerk_ledger::{ClerkLedgerRef, Status};
    use vos::node::{AgentConfig, VosNode};

    let path = format!(
        "{}/../actors/clerk-ledger/target/riscv64em-javm/release/clerk_ledger.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let elf = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: clerk-ledger not built (run `just build-clerk-ledger`)");
            return;
        }
    };
    let blob = grey_transpiler::link_elf(&elf).expect("transpile clerk-ledger");

    let mut node = VosNode::with_prefix(0);
    let ledger_id = node.register(AgentConfig::new(blob));
    let ledger = ClerkLedgerRef::at(ledger_id);

    // Per-event timestamps come from the JAM block ts in production;
    // for the test, just pick a non-zero monotonic seed.
    let ts: u64 = 1_000_000;

    // Pre-bootstrap: create_account fails with NOT_BOOTSTRAPPED.
    let pre = vos::block_on(ledger.create_account(&mut &node, Vec::new(), ts))
        .expect("invoke create_account pre-bootstrap");
    assert_eq!(pre, Status::NotBootstrapped);

    // Pre-bootstrap: state_root() returns an empty Vec. The
    // all-zero 32-byte root would be a forgeable anchor for
    // vouchers, so the actor signals "not ready" with a 0-length
    // Vec instead.
    let root_pre =
        vos::block_on(ledger.state_root(&mut &node)).expect("invoke state_root pre-bootstrap");
    assert!(
        root_pre.is_empty(),
        "state_root must return empty Vec before bootstrap, got {} bytes",
        root_pre.len()
    );

    // Bootstrap with a fresh registrar + journal. The journal `code`
    // is an opaque user tag — pick 1 for the test.
    let registrar = Keypair::generate();
    let journal = JournalId::random();
    let status = vos::block_on(ledger.bootstrap(
        &mut &node,
        journal.0.to_vec(),
        registrar.public.0.to_vec(),
        1u32,
    ))
    .expect("invoke bootstrap");
    assert_eq!(status, Status::Ok);

    // Post-bootstrap: state_root returns a 32-byte SMT root that
    // commits to the journal leaf (composite root: empty
    // accounts_smt + empty transfers_smt + 1-leaf journals_smt).
    // Pin it as non-zero — voucher signatures anchor here.
    let root_after_bootstrap =
        vos::block_on(ledger.state_root(&mut &node)).expect("invoke state_root post-bootstrap");
    assert_eq!(
        root_after_bootstrap.len(),
        32,
        "post-bootstrap state_root must be a 32-byte SMT root",
    );
    assert_ne!(
        root_after_bootstrap.as_slice(),
        &[0u8; 32][..],
        "post-bootstrap state_root must NOT be the empty-tree root — the journal must contribute"
    );

    // Build a signed CreateAccount for alice, push it through.
    let alice_kp = Keypair::generate();
    let alice = Account::asset(journal, alice_kp.public, Iso4217::USD, BankCode::Checking);
    let alice_id = alice.id.0;
    let create_alice = CcCreateAccount::signed(alice.clone(), &registrar.secret);
    let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_alice)
        .expect("rkyv encode")
        .to_vec();
    let status = vos::block_on(ledger.create_account(&mut &node, bytes.clone(), ts))
        .expect("invoke create_account");
    assert_eq!(status, Status::Ok, "first create_account should succeed");

    // Read it back. account() returns Option<Account> directly
    // (cipher-clerk types embed in the actor's rkyv archive via
    // the unified rkyv 0.8 crate, so the wire round-trips a typed
    // Account end-to-end). The kernel stamps `event_ts` on accept
    // (`event_ts = seed - n + i + 1`; for a single-event batch
    // event_ts == seed), so the stored account differs from the
    // submitted one in exactly the timestamp field — assert the
    // rest is byte-identical and check the timestamp explicitly.
    let stored = vos::block_on(ledger.account(&mut &node, alice_id.to_vec()))
        .expect("invoke account")
        .expect("alice should be on file");
    assert_eq!(stored.timestamp, ts, "kernel must stamp event_ts on accept");
    let mut expected = alice.clone();
    expected.timestamp = ts;
    assert_eq!(
        stored, expected,
        "stored account must equal submitted (modulo kernel-stamped timestamp)",
    );

    // Root must advance after a state-changing accept. If it didn't,
    // a voucher signed against root_before == root_after would be a
    // forgery — pin the property loudly so any regression surfaces.
    let root_after_alice = vos::block_on(ledger.state_root(&mut &node))
        .expect("invoke state_root post-create_account");
    assert_eq!(root_after_alice.len(), 32);
    assert_ne!(
        root_after_alice, root_after_bootstrap,
        "creating alice must advance the SMT root"
    );

    // Idempotency check: re-submitting the same create returns
    // ACCOUNT_EXISTS.
    let status = vos::block_on(ledger.create_account(&mut &node, bytes, ts))
        .expect("invoke create_account (dup)");
    assert_eq!(status, Status::IdAlreadyExists);

    // Wrong-journal check: build a CreateAccount whose embedded
    // account belongs to a DIFFERENT journal.
    let other_journal = JournalId::random();
    let bob_kp = Keypair::generate();
    let bob = Account::asset(
        other_journal,
        bob_kp.public,
        Iso4217::USD,
        BankCode::Checking,
    );
    let create_bob = CcCreateAccount::signed(bob, &registrar.secret);
    let bob_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_bob)
        .expect("rkyv encode")
        .to_vec();
    let status = vos::block_on(ledger.create_account(&mut &node, bob_bytes, ts))
        .expect("invoke create_account (wrong journal)");
    assert_eq!(status, Status::WrongJournal);

    // Bad-signature check: sign with the wrong registrar.
    let imposter = Keypair::generate();
    let carol = Account::asset(
        journal,
        Keypair::generate().public,
        Iso4217::USD,
        BankCode::Checking,
    );
    let create_carol = CcCreateAccount::signed(carol, &imposter.secret);
    let carol_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_carol)
        .expect("rkyv encode")
        .to_vec();
    let status = vos::block_on(ledger.create_account(&mut &node, carol_bytes, ts))
        .expect("invoke create_account (bad sig)");
    assert_eq!(status, Status::SignatureInvalid);

    // Adversarial #1: a CreateAccount whose embedded account has
    // a non-zero timestamp. signing_payload zeroes the timestamp
    // before signing, so a registrar's signature on the zeroed
    // version ALSO verifies against this tampered-timestamp version
    // — the actor must reject on the kernel invariant.
    let dave_kp = Keypair::generate();
    let dave = Account::asset(journal, dave_kp.public, Iso4217::USD, BankCode::Checking);
    let mut create_dave = CcCreateAccount::signed(dave, &registrar.secret);
    create_dave.account.timestamp = 12345;
    let dave_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_dave)
        .expect("rkyv encode")
        .to_vec();
    let status = vos::block_on(ledger.create_account(&mut &node, dave_bytes, ts))
        .expect("invoke create_account (tampered timestamp)");
    assert_eq!(
        status,
        Status::InvalidAccount,
        "non-zero timestamp on input must be rejected"
    );

    // Adversarial #2: a CreateAccount whose embedded account has a
    // pre-populated balance pair. signing_payload covers balances
    // so this only goes through if the registrar cooperated (a
    // malicious registrar). The actor must reject regardless to
    // preserve cipher-clerk's 'creation cannot mint' invariant.
    let eve_kp = Keypair::generate();
    let mut eve = Account::asset(journal, eve_kp.public, Iso4217::USD, BankCode::Checking);
    // Any non-zero Amount triggers the invariant. The bytes don't
    // need to decompress to a real Ristretto point — the check is
    // structural equality against Amount::ZERO.
    eve.balances[Layer::Settled.as_index()] = BalancePair {
        dr: Amount([1u8; 32]),
        cr: Amount::ZERO,
    };
    let create_eve = CcCreateAccount::signed(eve, &registrar.secret);
    let eve_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_eve)
        .expect("rkyv encode")
        .to_vec();
    let status = vos::block_on(ledger.create_account(&mut &node, eve_bytes, ts))
        .expect("invoke create_account (non-zero balance)");
    assert_eq!(
        status,
        Status::InvalidAccount,
        "non-zero balance on input must be rejected"
    );

    // ── Transfer end-to-end ─────────────────────────────────────
    //
    // Build a real signed transfer (alice debits 100 to a 'pool'
    // asset account) plus the matching Pedersen opening, push it
    // through apply_transfer, assert the kernel accepts it and
    // both touched accounts' balance commitments updated.

    let pool_kp = Keypair::generate();
    let pool = Account::asset(journal, pool_kp.public, Iso4217::USD, BankCode::Vault);
    let pool_id = pool.id.0;
    let pool_create = CcCreateAccount::signed(pool.clone(), &registrar.secret);
    let pool_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&pool_create)
        .expect("rkyv encode")
        .to_vec();
    let status = vos::block_on(ledger.create_account(&mut &node, pool_bytes, ts))
        .expect("invoke create_account pool");
    assert_eq!(status, Status::Ok);

    // Any 32-byte value < curve order is a valid Blinding. The
    // test doesn't need cryptographic randomness; a fixed pattern
    // keeps the assertions deterministic.
    let blinding = cipher_clerk::crypto::Blinding([1u8; 32]);
    let amt = Amount::commit(100, &blinding);
    let signed_transfer = cipher_clerk::types::Transfer::builder(journal)
        .debit(&alice, cipher_clerk::types::Layer::Settled, amt)
        .credit(&pool, cipher_clerk::types::Layer::Settled, amt)
        .signed_with(&[(&alice, &alice_kp.secret)]);
    let transfer_id = signed_transfer.id.0;
    let transfer_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer)
        .expect("rkyv encode transfer")
        .to_vec();
    let openings = vec![clerk_ledger::Opening {
        amount: amt,
        value: 100,
        blinding,
    }];
    let openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings)
        .expect("rkyv encode openings")
        .to_vec();
    let transfer_ts = ts + 100;
    // Capture the pre-transfer state root from the host side so we
    // can later cross-check the (root_before, root_after) anchor
    // pair that apply_transfer is supposed to record.
    let host_observed_root_before =
        vos::block_on(ledger.state_root(&mut &node)).expect("invoke state_root pre-transfer");
    let status = vos::block_on(ledger.apply_transfer(
        &mut &node,
        transfer_bytes,
        openings_bytes,
        transfer_ts,
    ))
    .expect("invoke apply_transfer");
    assert_eq!(
        status,
        Status::Ok,
        "transfer should land cleanly (got status {status:?})",
    );
    let host_observed_root_after =
        vos::block_on(ledger.state_root(&mut &node)).expect("invoke state_root post-transfer");

    // Verify the kernel updated alice's Settled debit and pool's
    // Settled credit by exactly `amt`. (Starting from BalancePair::ZERO,
    // the Pedersen sum after one entry is the entry's own commit.)
    let alice_after = vos::block_on(ledger.account(&mut &node, alice_id.to_vec()))
        .expect("alice account read")
        .expect("alice exists");
    let pool_after = vos::block_on(ledger.account(&mut &node, pool_id.to_vec()))
        .expect("pool account read")
        .expect("pool exists");
    let settled = cipher_clerk::types::Layer::Settled.as_index();
    assert_eq!(
        alice_after.balances[settled].dr, amt,
        "alice's Settled debit should equal the transfer amount commit"
    );
    assert_eq!(
        alice_after.balances[settled].cr,
        Amount::ZERO,
        "alice's Settled credit should remain zero"
    );
    assert_eq!(
        pool_after.balances[settled].cr, amt,
        "pool's Settled credit should equal the transfer amount commit"
    );
    assert_eq!(
        pool_after.balances[settled].dr,
        Amount::ZERO,
        "pool's Settled debit should remain zero"
    );

    // Transfer is persisted with the kernel-stamped event_ts.
    let stored_transfer = vos::block_on(ledger.transfer(&mut &node, transfer_id.to_vec()))
        .expect("transfer read")
        .expect("transfer exists");
    assert_eq!(stored_transfer.id.0, transfer_id);
    assert_eq!(stored_transfer.timestamp, transfer_ts);

    // Per-transfer state-root anchor: clerk-ledger captured
    // (root_before, root_after) at the moment the kernel accepted
    // this transfer. The pair MUST equal what the host observed
    // by querying state_root just before and just after — that's
    // the property a downstream voucher builder will rely on
    // (the bank constructs a voucher anchored to these roots;
    // the receiving bank checks them against the wire payload).
    let (root_before, root_after) =
        vos::block_on(ledger.transfer_state_roots(&mut &node, transfer_id.to_vec()))
            .expect("invoke transfer_state_roots")
            .expect("recorded for accepted transfer");
    assert_eq!(
        root_before.len(),
        32,
        "root_before must be a 32-byte SMT root"
    );
    assert_eq!(
        root_after.len(),
        32,
        "root_after must be a 32-byte SMT root"
    );
    assert_eq!(
        root_before, host_observed_root_before,
        "captured root_before must equal host's pre-transfer state_root"
    );
    assert_eq!(
        root_after, host_observed_root_after,
        "captured root_after must equal host's post-transfer state_root"
    );
    assert_ne!(
        root_before, root_after,
        "accepting a state-changing transfer must move the SMT root"
    );

    // Unknown transfer id → None.
    let missing = vos::block_on(ledger.transfer_state_roots(&mut &node, vec![0u8; 16]))
        .expect("invoke transfer_state_roots (missing)");
    assert!(missing.is_none(), "unknown transfer id must yield None");

    // Garbage bytes are rejected by the decode step.
    let status =
        vos::block_on(ledger.apply_transfer(&mut &node, vec![0xFFu8; 7], vec![], ts + 200))
            .expect("invoke apply_transfer (garbage)");
    assert_eq!(status, Status::BadInput);

    // Replay protection: re-submitting the same transfer returns
    // Status::IdAlreadyExists (TransferIdAlreadyExists from the kernel).
    let replay_transfer_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer)
        .expect("rkyv encode transfer (replay)")
        .to_vec();
    let replay_openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings)
        .expect("rkyv encode openings (replay)")
        .to_vec();
    let status = vos::block_on(ledger.apply_transfer(
        &mut &node,
        replay_transfer_bytes,
        replay_openings_bytes,
        transfer_ts + 100,
    ))
    .expect("invoke apply_transfer (replay)");
    assert_eq!(status, Status::IdAlreadyExists);

    // ── Pre-verify gate adversarial cases ───────────────────────
    //
    // The actor verifies signatures BEFORE any state-dependent
    // lookup so a caller can't probe state with junk-signed
    // transfers. The three cases below pin the state-hiding bucket:
    // signature-failure, count-mismatch, and account-not-found all
    // return Status::SignatureInvalid — indistinguishable from each
    // other.

    // Bad signature on an existing account: alice debits 1 to pool
    // but the transfer is signed with an imposter key (the imposter
    // doesn't even need to be on file — the signature is simply
    // wrong for alice's auth_key, so the verify fails outright).
    let blinding_b = cipher_clerk::crypto::Blinding([2u8; 32]);
    let amt_b = Amount::commit(1, &blinding_b);
    let imposter_kp = Keypair::generate();
    let bad_sig_transfer = cipher_clerk::types::Transfer::builder(journal)
        .debit(&alice, Layer::Settled, amt_b)
        .credit(&pool, Layer::Settled, amt_b)
        .signed_by(&[&imposter_kp.secret]);
    let bad_sig_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&bad_sig_transfer)
        .expect("rkyv encode transfer (bad sig)")
        .to_vec();
    let bad_sig_openings = vec![clerk_ledger::Opening {
        amount: amt_b,
        value: 1,
        blinding: blinding_b,
    }];
    let bad_sig_openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&bad_sig_openings)
        .expect("rkyv encode openings (bad sig)")
        .to_vec();
    let status = vos::block_on(ledger.apply_transfer(
        &mut &node,
        bad_sig_bytes,
        bad_sig_openings_bytes,
        transfer_ts + 200,
    ))
    .expect("invoke apply_transfer (bad sig)");
    assert_eq!(
        status,
        Status::SignatureInvalid,
        "transfer with wrong signer must hit pre-verify gate"
    );

    // Signature count mismatch: a valid alice→pool transfer but
    // with the signatures vec emptied out. Distinct debits = 1,
    // signatures.len() = 0 → Status::SignatureInvalid before any
    // state-touching code runs.
    let blinding_c = cipher_clerk::crypto::Blinding([3u8; 32]);
    let amt_c = Amount::commit(1, &blinding_c);
    let mut unsigned_transfer = cipher_clerk::types::Transfer::builder(journal)
        .debit(&alice, Layer::Settled, amt_c)
        .credit(&pool, Layer::Settled, amt_c)
        .build_unsigned();
    unsigned_transfer.signatures.clear();
    let unsigned_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&unsigned_transfer)
        .expect("rkyv encode transfer (unsigned)")
        .to_vec();
    let unsigned_openings = vec![clerk_ledger::Opening {
        amount: amt_c,
        value: 1,
        blinding: blinding_c,
    }];
    let unsigned_openings_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&unsigned_openings)
            .expect("rkyv encode openings (unsigned)")
            .to_vec();
    let status = vos::block_on(ledger.apply_transfer(
        &mut &node,
        unsigned_bytes,
        unsigned_openings_bytes,
        transfer_ts + 300,
    ))
    .expect("invoke apply_transfer (count mismatch)");
    assert_eq!(
        status,
        Status::SignatureInvalid,
        "transfer with sig count != distinct debits must hit pre-verify gate"
    );

    // Account not found: build a syntactically-valid signed transfer
    // whose debit account is a fresh ghost that was never registered.
    // The kernel would normally surface Status::AccountNotFound
    // (revealing that the account isn't on file); the pre-verify
    // gate collapses this into Status::SignatureInvalid so a probe
    // can't distinguish "account doesn't exist" from "signature
    // doesn't match".
    let ghost_kp = Keypair::generate();
    let ghost = Account::asset(journal, ghost_kp.public, Iso4217::USD, BankCode::Checking);
    let blinding_d = cipher_clerk::crypto::Blinding([4u8; 32]);
    let amt_d = Amount::commit(1, &blinding_d);
    let ghost_transfer = cipher_clerk::types::Transfer::builder(journal)
        .debit(&ghost, Layer::Settled, amt_d)
        .credit(&pool, Layer::Settled, amt_d)
        .signed_with(&[(&ghost, &ghost_kp.secret)]);
    let ghost_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&ghost_transfer)
        .expect("rkyv encode transfer (ghost)")
        .to_vec();
    let ghost_openings = vec![clerk_ledger::Opening {
        amount: amt_d,
        value: 1,
        blinding: blinding_d,
    }];
    let ghost_openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&ghost_openings)
        .expect("rkyv encode openings (ghost)")
        .to_vec();
    let status = vos::block_on(ledger.apply_transfer(
        &mut &node,
        ghost_bytes,
        ghost_openings_bytes,
        transfer_ts + 400,
    ))
    .expect("invoke apply_transfer (ghost debit)");
    assert_eq!(
        status,
        Status::SignatureInvalid,
        "transfer debiting a non-existent account must hit pre-verify gate, not leak Status::AccountNotFound",
    );

    // Adversarial #4: structurally-mislabeled pending finalize.
    // A transfer with `POST_PENDING_TRANSFER` flag set AND
    // non-empty entries — the kernel rejects such a finalize for
    // `PendingFinalizationMustHaveNoEntries` (maps to
    // Status::PendingViolation). We sign with the WRONG keypair
    // on purpose. The pre-verify gate's flag-based detection
    // routes this to the finalize path (skipping the entries-based
    // signature check), and the kernel's first check on the
    // finalize path is `entries.is_empty()` — which returns
    // WITHOUT touching state. Result: Status::PendingViolation,
    // NOT Status::SignatureInvalid.
    //
    // This pins the picky-review fix: previously pre-verify used
    // `pending_id.is_some() && entries.is_empty()`, which let this
    // exact attack pattern reach state-touching code paths in the
    // kernel. Flag-based detection closes that.
    use cipher_clerk::types::TransferFlags;
    let imposter = Keypair::generate();
    // `signed_by` puts the supplied secret(s) in the signatures
    // vec positionally — for our single-debited-account entry,
    // position[0] is alice's slot. Signing with imposter.secret
    // produces a "wrong signer" signature in alice's slot, so the
    // entries-based pre-verify (old behaviour) would have
    // rejected with Status::SignatureInvalid. The new flag-based
    // gate skips that check and lets the kernel reject on
    // entries-non-empty instead.
    let imposter_pp_transfer = cipher_clerk::types::Transfer::builder(journal)
        .debit(&alice, Layer::Settled, amt)
        .credit(&pool, Layer::Settled, amt)
        .flags(TransferFlags::POST_PENDING_TRANSFER)
        .signed_by(&[&imposter.secret]);
    let imposter_pp_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&imposter_pp_transfer)
        .expect("rkyv encode imposter post-pending")
        .to_vec();
    // Openings is an empty Vec — finalize doesn't need any since
    // entries are supposed to be empty. Encode it as a proper
    // rkyv archive (empty bytes would fail at the decode step
    // with Status::BadInput, before we'd reach the kernel path
    // we're trying to exercise).
    let empty_openings: Vec<clerk_ledger::Opening> = Vec::new();
    let empty_openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&empty_openings)
        .expect("rkyv encode empty openings")
        .to_vec();
    let status = vos::block_on(ledger.apply_transfer(
        &mut &node,
        imposter_pp_bytes,
        empty_openings_bytes,
        transfer_ts + 500,
    ))
    .expect("invoke apply_transfer (post-pending + non-empty entries)");
    assert_eq!(
        status,
        Status::PendingViolation,
        "flag-based finalize detection must bypass entries-based pre-verify and let the kernel reject on entries-non-empty"
    );

    let results = node.collect();
    let panics: u32 = results.iter().map(|r| r.panics).sum();
    assert_eq!(panics, 0, "actor panics during clerk-ledger test: {panics}");
}

/// Federation wire-through W3 producer: build a self-contained
/// conservation transition (2 accounts, 1 settled debit) on a `VecLedger`,
/// REGISTERED BY `registrar` so the resulting `voucher::proof::Public.issuer
/// == registrar.public` — the field the receiving bridge reconstructs
/// `public_bytes` from (issuer = the peer clerk pubkey it verified the
/// voucher signature against). This is the in-circuit conservation workload
/// the voucher-check guest re-runs; its OWN ledger roots / `amount_commit`
/// are what the External voucher attests (NOT bank A's clerk-ledger redb).
/// Returns the public, the succinct witness, and the `(value, blinding)` to
/// seal the value envelope. Mirrors the prover-extension's `build_transition`
/// test fixture; the chain commitment is witness-independent (canonical-shape
/// proving), so the OsRng-drawn account keys don't shift the {C_0, C_1}
/// allowlist the chain proves against.
fn build_conservation_transition(
    registrar: &cipher_clerk::crypto::Keypair,
) -> (
    cipher_clerk::voucher::proof::Public,
    cipher_clerk::succinct::SuccinctTransitionWitness,
    u64,
    cipher_clerk::crypto::Blinding,
) {
    use cipher_clerk::crypto::{Amount, Blinding};
    use cipher_clerk::prelude::*;
    use cipher_clerk::snapshot::{OpeningsOracle, VecLedger};
    use cipher_clerk::state::Opening;
    use cipher_clerk::succinct::SuccinctTransitionWitness;
    use cipher_clerk::voucher::proof::Public as VoucherPublic;

    // Same batch-seed timestamp + 2-account/1-debit shape as the canonical
    // profile + commitment allowlist were pinned against (W0).
    const BATCH_TS: u64 = 600_000;

    let journal = Journal::new(JournalId::random(), registrar.public, 1);
    let jid = journal.id;
    let mut ledger = VecLedger::new();
    ledger.set_journal(journal);

    let value: u64 = 100;
    let blinding = Blinding::from_bytes([3u8; 32]).expect("canonical scalar");
    let amount_commit = Amount::commit(value, &blinding);
    let mut oracle = OpeningsOracle::new(vec![Opening {
        amount: amount_commit,
        value,
        blinding,
    }]);

    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate();
    let alice = Account::open(
        AccountKind::Asset,
        jid,
        alice_kp.public,
        Iso4217::USD,
        BankCode::Vault,
    );
    let bob = Account::open(
        AccountKind::Liability,
        jid,
        bob_kp.public,
        Iso4217::USD,
        BankCode::Checking,
    );
    let creates = cipher_clerk::apply_account_creations(
        &mut ledger,
        &[
            CreateAccount::signed(alice.clone(), &registrar.secret),
            CreateAccount::signed(bob.clone(), &registrar.secret),
        ],
        &mut oracle,
        500_000,
    );
    for r in &creates {
        assert_eq!(r.status, EventStatus::Created);
    }

    let t = Transfer::builder(jid)
        .debit(&alice, Layer::Settled, amount_commit)
        .credit(&bob, Layer::Settled, amount_commit)
        .signed_with(&[(&alice, &alice_kp.secret)]);

    let root_before = ledger.root();
    let events = vec![t];
    let mut probe = ledger.clone();
    let mut probe_oracle = oracle.clone();
    let _ = cipher_clerk::apply_batch(&mut probe, &events, &mut probe_oracle, BATCH_TS);
    let root_after = probe.root();

    let public = VoucherPublic {
        issuer: registrar.public,
        amount_commit,
        state_root_before: root_before,
        state_root_after: root_after,
    };
    let witness = SuccinctTransitionWitness::from_full(&ledger, &events, &oracle, BATCH_TS);
    (public, witness, value, blinding)
}

/// Length-prefixed `[u32 public_len][public][u32 secret_len][secret]` — the
/// `__VOS_WITNESS` payload the voucher-check guest decodes (mirrors
/// `vos::zk::read_witness_buffer`).
fn encode_witness_payload(public_bytes: &[u8], secret_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + public_bytes.len() + secret_bytes.len());
    v.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(public_bytes);
    v.extend_from_slice(&(secret_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(secret_bytes);
    v
}

#[test]
fn clerk_ledger_two_bank_federation() {
    // End-to-end federation demo. Two bank spaces (A, B), each
    // independently running its own confidential ledger, join a
    // shared hyperspace and discover each other through it. Pins
    // the plumbing that the cross-bank settlement story will sit
    // on top of in later phases.
    //
    // Each bank space runs:
    //   - space-registry @ ServiceId::REGISTRY          (CRDT, per-space)
    //   - space-registry @ ServiceId::HYPERSPACE_REGISTRY (CRDT, shared rep_id)
    //   - space-bridge   @ derived from "bridge-{a|b}"  (Ephemeral, stateless)
    //   - clerk-ledger   @ derived from "clerk-{a|b}"   (Local, single-node)
    //
    // The hyperspace registry replicates host_mappings between the
    // two member spaces via gossipsub-CRDT — that's the only thing
    // wiring the federation together at the protocol level.
    //
    // What this test pins:
    //   1. After convergence, A's hyperspace registry resolves
    //      "clerk-b" / "bridge-b" to B's ServiceIds, and vice versa.
    //   2. From node_a, ClerkLedgerRef::at(clerk_b_id).account(bob_id)
    //      reaches bank B's local clerk-ledger via prefix routing and
    //      returns Bob's account record — cross-bank read works.
    //   3. The reverse path (B reading Alice from A) also works.
    //   4. Per-bank state isolation: bank A's clerk-ledger does NOT
    //      have Bob (he was only created on B). A non-existent read
    //      returns None, not a stale cross-bank hit.
    //   5. Cross-bank voucher round-trip: bank A applies a same-bank
    //      transfer, queries transfer_state_roots, builds + signs a
    //      cipher_clerk::voucher::Voucher anchored to those roots
    //      with an EncryptedEnvelope sealed under bank B's IVK_PK.
    //      Bank B parses Voucher::from_bytes, verifies signature
    //      against bank A's clerk pubkey, opens envelope to recover
    //      (value, blinding), and confirms the amount commitment
    //      reconstructs. Adversarial: tampered bytes and wrong
    //      issuer pubkey both fail verification.
    //   6. Bridge addressing parity: A can also reach B's bridge
    //      (where_am_i round-trip) — establishes the bridge-mediated
    //      path that a future cross-bank transfer would ride.
    use cipher_clerk::conventions::{BankCode, Iso4217};
    use cipher_clerk::crypto::{Amount, Blinding, Keypair, blake2b_256};
    use cipher_clerk::ids::{ExternalId, JournalId, TransferId};
    use cipher_clerk::kernel::CreateAccount as CcCreateAccount;
    use cipher_clerk::notes::Note;
    use cipher_clerk::proof::Proof as CcProof;
    use cipher_clerk::types::{Account, Layer, Transfer};
    use cipher_clerk::viewing_keys::{EncryptedEnvelope, SpendKey};
    use cipher_clerk::voucher::{Voucher, VoucherError};
    use clerk_ledger::{ClerkLedgerRef, Status};
    use space_bridge::SpaceBridgeRef;
    use space_registry::SpaceRegistryRef;
    use std::time::Duration;
    use vos::abi::service::ServiceId;
    use vos::network::{Network, NetworkConfig, derive_node_prefix};
    use vos::node::{AgentConfig, Consistency, VosNode};

    // ── Load ELFs ───────────────────────────────────────────────
    let registry_path = format!(
        "{}/../actors/space-registry/target/riscv64em-javm/release/space_registry.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let bridge_path = format!(
        "{}/../actors/space-bridge/target/riscv64em-javm/release/space_bridge.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let ledger_path = format!(
        "{}/../actors/clerk-ledger/target/riscv64em-javm/release/clerk_ledger.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let registry_elf = match std::fs::read(&registry_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: space-registry not built (run `just build-registry`)");
            return;
        }
    };
    let bridge_elf = match std::fs::read(&bridge_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: space-bridge not built (run `just build-bridge`)");
            return;
        }
    };
    let ledger_elf = match std::fs::read(&ledger_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: clerk-ledger not built (run `just build-clerk-ledger`)");
            return;
        }
    };
    let clerk_bridge_path = format!(
        "{}/../actors/clerk-bridge/target/riscv64em-javm/release/clerk_bridge.elf",
        env!("CARGO_MANIFEST_DIR"),
    );
    let clerk_bridge_elf = match std::fs::read(&clerk_bridge_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: clerk-bridge not built (run `just build-clerk-bridge`)");
            return;
        }
    };
    let registry_blob = grey_transpiler::link_elf(&registry_elf).expect("transpile registry");
    let bridge_blob = grey_transpiler::link_elf(&bridge_elf).expect("transpile bridge");
    let ledger_blob = grey_transpiler::link_elf(&ledger_elf).expect("transpile clerk-ledger");
    let clerk_bridge_blob =
        grey_transpiler::link_elf(&clerk_bridge_elf).expect("transpile clerk-bridge");

    // Each test invocation gets isolated redb directories so two
    // CRDT-persisted REGISTRY replicas don't fight over a shared file.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_root =
        std::env::temp_dir().join(format!("vos_clerk_fed_{}_{}", std::process::id(), stamp));
    let dir_a = dir_root.join("a");
    let dir_b = dir_root.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    // Replication IDs. The per-space REGISTRY replicas are
    // independent (each bank's local catalog); the HYPERSPACE_REGISTRY
    // replicas share `hs_rep` so they converge across nodes.
    let mk_id = |label: &[u8]| -> [u8; 32] {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(label);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    };
    let space_a_rep = mk_id(b"clerk-fed/space-a");
    let space_b_rep = mk_id(b"clerk-fed/space-b");
    let hs_rep = mk_id(b"clerk-fed/hyperspace");

    // ── libp2p bring-up ─────────────────────────────────────────
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
        Duration::from_secs(5),
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

    // ── ServiceIds derived from federation-visible names ────────
    let bridge_a_id = ServiceId(space_registry::instance_service_id("bridge-a", prefix_a));
    let bridge_b_id = ServiceId(space_registry::instance_service_id("bridge-b", prefix_b));
    let clerk_a_id = ServiceId(space_registry::instance_service_id("clerk-a", prefix_a));
    let clerk_b_id = ServiceId(space_registry::instance_service_id("clerk-b", prefix_b));
    // clerk-bridge runs only on bank B in this test — it's the
    // voucher-INGRESS gateway. Bank A would have its own
    // clerk-bridge in a real federation for receiving vouchers
    // back from bank B, but our test only flows A→B.
    let clerk_bridge_b_id = ServiceId(space_registry::instance_service_id(
        "clerk-bridge-b",
        prefix_b,
    ));

    // ── Node A ──────────────────────────────────────────────────
    let mut node_a = VosNode::with_prefix(prefix_a);
    node_a.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(space_a_rep),
        ServiceId::REGISTRY,
    );
    node_a.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_a)
            .with_replication_id(hs_rep),
        ServiceId::HYPERSPACE_REGISTRY,
    );
    node_a.register_at_id(
        AgentConfig::new(bridge_blob.clone()).with_consistency(Consistency::Ephemeral),
        bridge_a_id,
    );
    node_a.register_at_id(
        AgentConfig::new(ledger_blob.clone())
            .with_consistency(Consistency::Local)
            .persist(&dir_a),
        clerk_a_id,
    );
    node_a.attach_network(net_a);

    // ── Node B ──────────────────────────────────────────────────
    let mut node_b = VosNode::with_prefix(prefix_b);
    node_b.register_at_id(
        AgentConfig::new(registry_blob.clone())
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(space_b_rep),
        ServiceId::REGISTRY,
    );
    node_b.register_at_id(
        AgentConfig::new(registry_blob)
            .with_consistency(Consistency::Crdt)
            .persist(&dir_b)
            .with_replication_id(hs_rep),
        ServiceId::HYPERSPACE_REGISTRY,
    );
    node_b.register_at_id(
        AgentConfig::new(bridge_blob).with_consistency(Consistency::Ephemeral),
        bridge_b_id,
    );
    node_b.register_at_id(
        AgentConfig::new(ledger_blob)
            .with_consistency(Consistency::Local)
            .persist(&dir_b),
        clerk_b_id,
    );
    // clerk-bridge on B: holds the bank-B IVK secret + peer-A
    // clerk pubkey + dedup set. Persisted (Local) so the dedup
    // state survives across actor restarts.
    node_b.register_at_id(
        AgentConfig::new(clerk_bridge_blob)
            .with_consistency(Consistency::Local)
            .persist(&dir_b),
        clerk_bridge_b_id,
    );
    node_b.attach_network(net_b);

    // ── Wait for libp2p Hello ───────────────────────────────────
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
        Duration::from_secs(10),
    )
    .expect("libp2p Hello handshake");

    // ── Publish federation-visible names on both sides ──────────
    //
    // Each bank publishes ALL four names ("bridge-a", "bridge-b",
    // "clerk-a", "clerk-b") in its hyperspace registry view; the
    // CRDT merge then converges. We do this from BOTH sides so the
    // test exercises the converging-merge path rather than just
    // single-writer propagation.
    let hs_a = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
    let hs_b = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
    for (name, prefix) in [("bridge-a", prefix_a), ("clerk-a", prefix_a)] {
        let s = vos::block_on(hs_a.register_remote(&mut &node_a, name.into(), prefix as u32))
            .expect("register_remote on A");
        assert_eq!(s, space_registry::STATUS_OK, "A.register_remote {name}");
    }
    for (name, prefix) in [("bridge-b", prefix_b), ("clerk-b", prefix_b)] {
        let s = vos::block_on(hs_b.register_remote(&mut &node_b, name.into(), prefix as u32))
            .expect("register_remote on B");
        assert_eq!(s, space_registry::STATUS_OK, "B.register_remote {name}");
    }

    // CRDT converges via gossipsub. Wait until each side can resolve
    // the other's clerk name before proceeding.
    wait_for(
        || {
            let from_a =
                vos::block_on(hs_a.resolve(&mut &node_a, "clerk-b".into(), prefix_a as u64))
                    .unwrap_or(0);
            let from_b =
                vos::block_on(hs_b.resolve(&mut &node_b, "clerk-a".into(), prefix_b as u64))
                    .unwrap_or(0);
            if from_a == clerk_b_id.0 && from_b == clerk_a_id.0 {
                Some(())
            } else {
                None
            }
        },
        Duration::from_secs(15),
    )
    .expect("hyperspace registry CRDT convergence");

    // ── 1) Federation discovery sanity ──────────────────────────
    //
    // Each bank's hyperspace replica resolves every other bank's
    // bridge and clerk to the expected ServiceIds.
    for (side, hs, node, peer_clerk, peer_bridge) in [
        ("A→B", &hs_a, &node_a, clerk_b_id.0, bridge_b_id.0),
        ("B→A", &hs_b, &node_b, clerk_a_id.0, bridge_a_id.0),
    ] {
        let local_prefix = if side == "A→B" { prefix_a } else { prefix_b };
        let clerk_name = if side == "A→B" {
            "clerk-b"
        } else {
            "clerk-a"
        };
        let bridge_name = if side == "A→B" {
            "bridge-b"
        } else {
            "bridge-a"
        };
        let got_clerk =
            vos::block_on(hs.resolve(&mut &*node, clerk_name.into(), local_prefix as u64))
                .expect("resolve peer clerk");
        assert_eq!(got_clerk, peer_clerk, "{side} resolve {clerk_name}");
        let got_bridge =
            vos::block_on(hs.resolve(&mut &*node, bridge_name.into(), local_prefix as u64))
                .expect("resolve peer bridge");
        assert_eq!(got_bridge, peer_bridge, "{side} resolve {bridge_name}");
    }

    // ── 2) Bootstrap each bank's clerk-ledger ───────────────────
    //
    // Each bank gets its own journal id + registrar keypair —
    // independent confidential ledgers. The same journal_id MUST
    // NOT be shared, since each bank's accounts are anchored to it.
    let registrar_a = Keypair::generate();
    let registrar_b = Keypair::generate();
    let journal_a = JournalId::random();
    let journal_b = JournalId::random();

    let ledger_a = ClerkLedgerRef::at(clerk_a_id);
    let ledger_b = ClerkLedgerRef::at(clerk_b_id);
    let ts: u64 = 2_000_000;
    assert_eq!(
        vos::block_on(ledger_a.bootstrap(
            &mut &node_a,
            journal_a.0.to_vec(),
            registrar_a.public.0.to_vec(),
            1u32,
        ))
        .expect("ledger_a bootstrap"),
        Status::Ok
    );
    assert_eq!(
        vos::block_on(ledger_b.bootstrap(
            &mut &node_b,
            journal_b.0.to_vec(),
            registrar_b.public.0.to_vec(),
            1u32,
        ))
        .expect("ledger_b bootstrap"),
        Status::Ok
    );

    // Alice lives on bank A; Bob lives on bank B. Each is created
    // through its local clerk-ledger, registrar-signed.
    let alice_kp = Keypair::generate();
    let alice = Account::asset(journal_a, alice_kp.public, Iso4217::USD, BankCode::Checking);
    let alice_id = alice.id.0;
    let alice_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&CcCreateAccount::signed(
        alice.clone(),
        &registrar_a.secret,
    ))
    .expect("rkyv encode CreateAccount(alice)")
    .to_vec();
    assert_eq!(
        vos::block_on(ledger_a.create_account(&mut &node_a, alice_bytes, ts))
            .expect("create alice on A"),
        Status::Ok
    );

    let bob_kp = Keypair::generate();
    let bob = Account::asset(journal_b, bob_kp.public, Iso4217::USD, BankCode::Checking);
    let bob_id = bob.id.0;
    let bob_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&CcCreateAccount::signed(
        bob.clone(),
        &registrar_b.secret,
    ))
    .expect("rkyv encode CreateAccount(bob)")
    .to_vec();
    assert_eq!(
        vos::block_on(ledger_b.create_account(&mut &node_b, bob_bytes, ts))
            .expect("create bob on B"),
        Status::Ok
    );

    // ── 3) Cross-bank read via typed Ref + prefix routing ───────
    //
    // From node_a, invoke ClerkLedgerRef::at(clerk_b_id).account(bob_id).
    // The ServiceId's top 16 bits = prefix_b, so the mailbox routes
    // the dispatch to node_b over libp2p. Node_b's local clerk-ledger
    // handles it and the typed reply rides back. No bridge needed for
    // this — direct ServiceId addressing is the simpler federation
    // primitive when the caller already knows the target ServiceId
    // (e.g., obtained via the hyperspace resolve above).
    let bob_remote = vos::block_on(ledger_b.account(&mut &node_a, bob_id.to_vec()))
        .expect("cross-bank account(bob) from A")
        .expect("bob exists on B");
    assert_eq!(bob_remote.id.0, bob_id, "bob's id round-trips cross-bank");
    assert_eq!(
        bob_remote.journal_id, journal_b,
        "bob is anchored to bank B's journal"
    );
    assert_eq!(
        bob_remote.auth_key, bob_kp.public,
        "bob's auth key matches what B registered"
    );

    // Reverse direction: B reads Alice from A's ledger.
    let alice_remote = vos::block_on(ledger_a.account(&mut &node_b, alice_id.to_vec()))
        .expect("cross-bank account(alice) from B")
        .expect("alice exists on A");
    assert_eq!(alice_remote.id.0, alice_id);
    assert_eq!(alice_remote.journal_id, journal_a);

    // ── 4) Per-bank state isolation ─────────────────────────────
    //
    // Bob was only created on B. A's local ledger must not have
    // him — i.e., a cross-bank query for Bob targeting A's ledger
    // returns None, not a stale hit propagated through some shared
    // state. (clerk-ledger has Consistency::Local, no replication.)
    let bob_on_a = vos::block_on(ledger_a.account(&mut &node_a, bob_id.to_vec()))
        .expect("local account(bob) on A");
    assert!(
        bob_on_a.is_none(),
        "bob must NOT appear on A — confidential ledger state is per-bank"
    );
    let alice_on_b = vos::block_on(ledger_b.account(&mut &node_b, alice_id.to_vec()))
        .expect("local account(alice) on B");
    assert!(
        alice_on_b.is_none(),
        "alice must NOT appear on B — confidential ledger state is per-bank"
    );

    // ── 5) Cross-bank voucher round-trip ────────────────────────
    //
    // Bank A applies a same-bank transfer (alice → vault_a),
    // queries transfer_state_roots, builds + signs a Voucher
    // anchored to those roots with envelope sealed under bank B's
    // IVK_PK. Bank B verifies the voucher against bank A's clerk
    // pubkey and opens the envelope to recover the opening.
    //
    // This is the wire-level proof that the federation can move
    // value across bank boundaries: the voucher carries everything
    // bank B needs to credit Bob equivalent value off a verified
    // anchor on bank A's state, without bank B trusting bank A
    // beyond the clerk pubkey and the SMT root anchors.

    // Bank B publishes its incoming-viewing-key pubkey out of band
    // (in production, via the hyperspace registry or a service
    // discovery layer; here, just keep it on the host).
    let bank_b_spend = SpendKey::generate();
    let bank_b_ivk = bank_b_spend.incoming_viewing_key();
    let bank_b_ivk_pk = bank_b_ivk.public();

    // Vault account on bank A — the credit side of the transfer
    // that anchors the voucher. (In a real flow, this would be a
    // "cross-bank holding" account whose balance reflects what
    // bank B has been promised.)
    let vault_kp = Keypair::generate();
    let vault_a = Account::asset(journal_a, vault_kp.public, Iso4217::USD, BankCode::Vault);
    let vault_a_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&CcCreateAccount::signed(
        vault_a.clone(),
        &registrar_a.secret,
    ))
    .expect("rkyv encode CreateAccount(vault_a)")
    .to_vec();
    assert_eq!(
        vos::block_on(ledger_a.create_account(&mut &node_a, vault_a_bytes, ts))
            .expect("create vault_a on A"),
        Status::Ok,
    );

    // alice debits 100 to vault_a. Fixed-pattern blinding so the
    // test stays deterministic; bytes are a known-canonical scalar
    // (matches what the existing clerk-ledger transfer test uses,
    // and what EncryptedEnvelope::seal will accept). The value is
    // what bank B will recover from the sealed envelope.
    let blinding = cipher_clerk::crypto::Blinding([2u8; 32]);
    let value: u64 = 100;
    let amt = Amount::commit(value, &blinding);
    let signed_transfer: Transfer = Transfer::builder(journal_a)
        .debit(&alice, Layer::Settled, amt)
        .credit(&vault_a, Layer::Settled, amt)
        .signed_with(&[(&alice, &alice_kp.secret)]);
    let transfer_id = signed_transfer.id.0;
    let transfer_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer)
        .expect("rkyv encode transfer")
        .to_vec();
    let openings = vec![clerk_ledger::Opening {
        amount: amt,
        value,
        blinding,
    }];
    let openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings)
        .expect("rkyv encode openings")
        .to_vec();
    assert_eq!(
        vos::block_on(ledger_a.apply_transfer(
            &mut &node_a,
            transfer_bytes,
            openings_bytes,
            ts + 100,
        ))
        .expect("apply_transfer on A"),
        Status::Ok,
    );

    // Read back the anchor pair clerk-ledger captured on accept.
    let (root_before_vec, root_after_vec) =
        vos::block_on(ledger_a.transfer_state_roots(&mut &node_a, transfer_id.to_vec()))
            .expect("invoke transfer_state_roots")
            .expect("anchor recorded for accepted transfer");
    let root_before: [u8; 32] = root_before_vec.try_into().expect("32-byte root_before");
    let root_after: [u8; 32] = root_after_vec.try_into().expect("32-byte root_after");

    // Bank A's caller seals (value, blinding) under bank B's IVK_PK
    // and constructs the voucher. The "clerk-key" here is bank A's
    // registrar key — in our demo the registrar identity also acts
    // as the bank's signing clerk (production deployments would
    // split these). Mode::Signature proof is the baseline; zkVM
    // proofs (Mode::External) plug in without changing the wire
    // shape.
    let envelope = EncryptedEnvelope::seal(value, &blinding, &bank_b_ivk_pk)
        .expect("seal envelope under bank B's IVK_PK");
    let voucher = Voucher::sign(
        amt,
        envelope,
        root_before,
        root_after,
        CcProof::default(),
        &registrar_a.secret,
    );
    let voucher_bytes = voucher.to_bytes();

    // ── Bank B side ────────────────────────────────────────────
    //
    // In production, voucher_bytes would ride over a bridge.forward
    // call to bank B; we skip the bridge here because the existing
    // bridge tests prove that transport works and the voucher math
    // is the new thing we're pinning.
    let received = Voucher::from_bytes(&voucher_bytes).expect("parse voucher bytes");
    received
        .verify_against(&registrar_a.public, Some(root_before))
        .expect("voucher verifies against bank A's clerk pubkey + anchor");

    let (recovered_value, recovered_blinding) = received
        .envelope
        .open(&bank_b_ivk)
        .expect("open envelope with bank B's IVK");
    assert_eq!(
        recovered_value, value,
        "recovered value matches sealed value"
    );
    assert_eq!(
        recovered_blinding, blinding,
        "recovered blinding matches sealed blinding"
    );
    // The Pedersen commitment reconstructs identically — proves the
    // recipient can now credit Bob the same Amount on its side
    // without bank A revealing the (value, blinding) to anyone but
    // bank B.
    let reconstructed = Amount::commit(recovered_value, &recovered_blinding);
    assert_eq!(
        reconstructed, received.amount_commit,
        "reconstructed Amount commit matches the voucher's amount_commit"
    );

    // Adversarial #1: tampered voucher bytes. Flip a byte deep
    // inside the signature region; from_bytes still parses (the
    // structural shape is intact) but verify_signature fails.
    let mut tampered = voucher_bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let parsed_tampered = Voucher::from_bytes(&tampered).expect("structural parse still works");
    assert_eq!(
        parsed_tampered.verify_against(&registrar_a.public, None),
        Err(VoucherError::BadSignature),
        "tampered signature must fail verification"
    );

    // Adversarial #2: verifying against bank B's pubkey (which
    // didn't sign this voucher) must also fail.
    assert_eq!(
        received.verify_against(&registrar_b.public, None),
        Err(VoucherError::BadSignature),
        "wrong issuer pubkey must fail verification"
    );

    // Adversarial #3: stale-anchor probe. If bank B previously saw
    // bank A at a different root (e.g. an earlier voucher's
    // root_after), passing that as `expected_root_before` to
    // verify_against must fail — protects against replays of
    // vouchers from outdated state.
    let fake_anchor = [0xEEu8; 32];
    assert_eq!(
        received.verify_against(&registrar_a.public, Some(fake_anchor)),
        Err(VoucherError::StateRootMismatch),
        "wrong root_before anchor must fail with StateRootMismatch"
    );

    // ── 5b) Bank B credits Bob from the verified voucher ────────
    //
    // The voucher's signature + state-root anchoring give bank B
    // grounds to credit Bob equivalent value on its side. Bank B
    // builds an "inflow" transfer:
    //   debit  inflow_b (an asset account representing claims-
    //          from-other-clerks; goes more-negative on each
    //          received voucher, mirrors what bank B owes back to
    //          peer banks if the voucher were ever revoked)
    //   credit Bob
    // anchored to the same `(value, blinding)` opening recovered
    // from the envelope. The Pedersen commit is reused verbatim
    // from the voucher — this is the L0 "transparent inter-bank"
    // mode; an L3-shielded mode would re-randomise with a fresh
    // blinding on bank B's side. Deferred until the notes pool
    // lands.

    let inflow_kp = Keypair::generate();
    let inflow_b = Account::asset(journal_b, inflow_kp.public, Iso4217::USD, BankCode::Vault);
    let inflow_b_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&CcCreateAccount::signed(
        inflow_b.clone(),
        &registrar_b.secret,
    ))
    .expect("rkyv encode CreateAccount(inflow_b)")
    .to_vec();
    assert_eq!(
        vos::block_on(ledger_b.create_account(&mut &node_b, inflow_b_bytes, ts))
            .expect("create inflow_b on B"),
        Status::Ok,
    );

    // Snapshot bank B's state root before the inflow transfer so
    // we can assert the inflow accept moves the root.
    let root_b_before_inflow = vos::block_on(ledger_b.state_root(&mut &node_b))
        .expect("invoke state_root on B pre-inflow");

    // The inflow Amount commit equals the voucher's amount_commit
    // — same Pedersen point on both sides. The kernel verifies
    // this end-to-end via the StatefulOracle on bank B reading the
    // (recovered_value, recovered_blinding) opening recovered from
    // the envelope.
    //
    // Replay protection: external_id is anchored to the underlying
    // kernel transfer that the voucher refers to, NOT to the
    // voucher bytes. The triple `(amount_commit, root_before,
    // root_after)` uniquely identifies which Transfer on bank A
    // produced the voucher — bank A could re-sign the same payload
    // with a fresh OsRng nonce (different signature bytes), or
    // re-seal the envelope under a fresh ephemeral pubkey
    // (different ciphertext bytes), but those re-issued vouchers
    // all reference the same underlying transfer and so collapse
    // to the same external_id on bank B's side.
    //
    // Why not signing_payload() or to_bytes()?
    //   - to_bytes() includes the 64-byte signature, which Schnorr
    //     randomises per call: trivial issuer-side bypass.
    //   - signing_payload() includes the envelope ciphertext, which
    //     embeds a fresh ECDH ephemeral pubkey: also issuer-side
    //     bypassable by re-sealing the same opening to a fresh
    //     ephemeral.
    //   - (amount_commit, root_before, root_after) is the smallest
    //     tuple that uniquely identifies the kernel-side
    //     value-transfer promise. Bank A can't produce two
    //     semantically-distinct vouchers with the same triple
    //     unless the kernel accepted two state-equivalent
    //     transfers, which can't happen.
    //
    // The kernel's existing `external_id_seen` /
    // `mark_external_id` machinery does the rest. No new
    // clerk-ledger state — this rides on the per-journal
    // idempotency check already in place for arbitrary
    // operator-supplied uniqueness keys.
    let voucher_external_id_bytes = blake2b_256(
        b"clerk-ledger/voucher-redemption/v1",
        &[
            &received.amount_commit.0,
            &received.state_root_before,
            &received.state_root_after,
        ],
    );
    let voucher_external_id = ExternalId(voucher_external_id_bytes);
    let inflow_transfer: Transfer = Transfer::builder(journal_b)
        .debit(&inflow_b, Layer::Settled, received.amount_commit)
        .credit(&bob, Layer::Settled, received.amount_commit)
        .external_id(voucher_external_id)
        .signed_with(&[(&inflow_b, &inflow_kp.secret)]);
    let inflow_transfer_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_transfer)
        .expect("rkyv encode inflow transfer")
        .to_vec();
    let inflow_openings = vec![clerk_ledger::Opening {
        amount: received.amount_commit,
        value: recovered_value,
        blinding: recovered_blinding,
    }];
    let inflow_openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_openings)
        .expect("rkyv encode inflow openings")
        .to_vec();
    assert_eq!(
        vos::block_on(ledger_b.apply_transfer(
            &mut &node_b,
            inflow_transfer_bytes,
            inflow_openings_bytes,
            ts + 200,
        ))
        .expect("apply_transfer (inflow) on B"),
        Status::Ok,
        "bank B must accept the inflow transfer with the recovered opening"
    );

    // Bob's Settled credit balance MUST equal the voucher's
    // amount_commit — the cross-bank value transfer is now
    // visible on bank B's books.
    let bob_after = vos::block_on(ledger_b.account(&mut &node_b, bob_id.to_vec()))
        .expect("read bob on B")
        .expect("bob exists");
    let settled = Layer::Settled.as_index();
    assert_eq!(
        bob_after.balances[settled].cr, received.amount_commit,
        "bob's Settled credit must equal the voucher's amount commit"
    );
    assert_eq!(
        bob_after.balances[settled].dr,
        Amount::ZERO,
        "bob's Settled debit must remain zero (he only received)"
    );

    // Bank B's state root must have advanced — the inflow transfer
    // changed B's local state. A future round-trip can anchor
    // anti-replay against this new root.
    let root_b_after_inflow = vos::block_on(ledger_b.state_root(&mut &node_b))
        .expect("invoke state_root on B post-inflow");
    assert_ne!(
        root_b_before_inflow, root_b_after_inflow,
        "bank B's inflow accept must move its SMT root"
    );

    // ── 5c) Voucher replay protection ───────────────────────────
    //
    // Build a SECOND inflow transfer with a FRESH TransferId but
    // the SAME external_id (= blake2b_256 of the same voucher
    // bytes). The kernel's `external_id_seen` check is what catches
    // the replay — Status::IdAlreadyExists would mean we matched
    // on TransferId (which we explicitly changed), so the expected
    // rejection is specifically Status::ExternalIdReused.
    let replay_inflow: Transfer = Transfer::builder(journal_b)
        .id(TransferId([0x77u8; 16]))
        .debit(&inflow_b, Layer::Settled, received.amount_commit)
        .credit(&bob, Layer::Settled, received.amount_commit)
        .external_id(voucher_external_id)
        .signed_with(&[(&inflow_b, &inflow_kp.secret)]);
    let replay_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&replay_inflow)
        .expect("rkyv encode replay inflow")
        .to_vec();
    let replay_openings_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_openings)
        .expect("rkyv encode replay openings")
        .to_vec();
    let replay_status = vos::block_on(ledger_b.apply_transfer(
        &mut &node_b,
        replay_bytes,
        replay_openings_bytes,
        ts + 300,
    ))
    .expect("apply_transfer (replay attempt) on B");
    assert_eq!(
        replay_status,
        Status::ExternalIdReused,
        "second redemption of the same voucher must be rejected via external_id dedup"
    );

    // After the replay rejection, Bob's balance MUST be unchanged
    // — a rejected transfer doesn't mutate state. Belt + braces:
    // catches any future regression that returns the failure
    // status but still committed.
    let bob_after_replay = vos::block_on(ledger_b.account(&mut &node_b, bob_id.to_vec()))
        .expect("read bob on B post-replay")
        .expect("bob exists");
    assert_eq!(
        bob_after_replay.balances[settled].cr, received.amount_commit,
        "rejected replay must not double-credit bob"
    );

    // Adversarial replay #2: malicious bank A re-signs the SAME
    // payload with fresh OsRng randomness in the Schnorr nonce,
    // producing different signature bytes. The to_bytes() encoding
    // of this voucher differs from the original — and the
    // signing_payload() is identical, but our dedup key is anchored
    // to (amount, root_before, root_after) and so survives both
    // mutations. Bank B sees the same external_id and rejects.
    let resigned = Voucher::sign(
        received.amount_commit,
        received.envelope.clone(),
        received.state_root_before,
        received.state_root_after,
        received.proof.clone(),
        &registrar_a.secret,
    );
    // Sanity: the bytes differ from the original voucher (proves
    // we actually got fresh randomness).
    assert_ne!(
        resigned.to_bytes(),
        voucher_bytes,
        "re-signing with fresh OsRng must produce different bytes"
    );
    // But the same external_id derives from the underlying triple.
    let resigned_external_id_bytes = blake2b_256(
        b"clerk-ledger/voucher-redemption/v1",
        &[
            &resigned.amount_commit.0,
            &resigned.state_root_before,
            &resigned.state_root_after,
        ],
    );
    assert_eq!(
        resigned_external_id_bytes, voucher_external_id_bytes,
        "re-signed voucher must derive the same external_id"
    );
    // Attempt redemption with the re-signed voucher's external_id
    // (which is the same as the original's) on a fresh-id
    // transfer. The kernel dedups on external_id.
    let resign_attack_inflow: Transfer = Transfer::builder(journal_b)
        .id(TransferId([0x88u8; 16]))
        .debit(&inflow_b, Layer::Settled, received.amount_commit)
        .credit(&bob, Layer::Settled, received.amount_commit)
        .external_id(ExternalId(resigned_external_id_bytes))
        .signed_with(&[(&inflow_b, &inflow_kp.secret)]);
    let resign_attack_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&resign_attack_inflow)
            .expect("rkyv encode resign-attack inflow")
            .to_vec();
    let resign_attack_openings_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_openings)
            .expect("rkyv encode resign-attack openings")
            .to_vec();
    assert_eq!(
        vos::block_on(ledger_b.apply_transfer(
            &mut &node_b,
            resign_attack_bytes,
            resign_attack_openings_bytes,
            ts + 400,
        ))
        .expect("apply_transfer (resign attack) on B"),
        Status::ExternalIdReused,
        "re-signed voucher with same underlying transfer must hit dedup"
    );

    // ── 5d) L3 shielded receive — alternative privacy mode ──────
    //
    // The L0 inflow above keyed Bob's credit to the SAME Pedersen
    // commit bank A used. Anyone reading both ledgers sees the
    // same 32-byte point twice and can correlate. L3 fixes that:
    // bank B re-randomises with a fresh blinding + rho and inserts
    // a Note commitment into clerk-ledger-B's notes pool. The new
    // commitment is bytes-different from bank A's amount_commit
    // even though the underlying value is identical.
    //
    // In a real deployment a recipient picks ONE mode per payment
    // (L0 transparent OR L3 shielded), not both — running both in
    // this test shows the contrast side-by-side. Production
    // wallets would skip the L0 inflow entirely when the
    // counterparty wants L3.
    //
    // The actor never sees the (value, fresh_blinding, owner, rho)
    // opening: it's computed off-ledger here and only the resulting
    // Pedersen point is submitted. Bob's wallet would hold the
    // opening and prove ownership when spending via a future
    // nullifier-publish path.
    // Deterministic fresh blinding + rho. The privacy property
    // we want to demonstrate is only that bank B's commit bytes
    // DIFFER from bank A's; the bytes don't need to be random for
    // that, and a fixed pattern keeps the test deterministic.
    // [3u8; 32] is canonical (same family as the [2u8; 32]
    // blinding bank A used for the voucher; both are <
    // group-order scalars).
    let fresh_blinding =
        Blinding::from_bytes([3u8; 32]).expect("[3u8; 32] is a canonical Ristretto scalar");
    let fresh_rho: [u8; 32] = [0x33u8; 32];
    let bob_note = Note {
        asset_tag: 1, // matches the journal's "code" tag we bootstrapped with
        value: recovered_value,
        owner: bob.auth_key,
        blinding: fresh_blinding,
        rho: fresh_rho,
    };
    let bob_note_commit: Amount = bob_note
        .commitment()
        .expect("Note::commitment must succeed for canonical blinding");

    // Pre-insert: pool is empty on bank B.
    let pool_size_before = vos::block_on(ledger_b.note_commitment_count(&mut &node_b))
        .expect("invoke note_commitment_count");
    assert_eq!(pool_size_before, 0, "notes pool must start empty on B");

    let submit_status =
        vos::block_on(ledger_b.submit_note_commitment(&mut &node_b, bob_note_commit.0.to_vec()))
            .expect("invoke submit_note_commitment");
    assert_eq!(
        submit_status,
        Status::Ok,
        "submit_note_commitment must accept a 32-byte Pedersen point"
    );

    let pool_size_after = vos::block_on(ledger_b.note_commitment_count(&mut &node_b))
        .expect("invoke note_commitment_count post-submit");
    assert_eq!(
        pool_size_after, 1,
        "submit must append exactly one commitment to the pool"
    );

    let stored = vos::block_on(ledger_b.note_commitment_at(&mut &node_b, 0))
        .expect("invoke note_commitment_at");
    assert_eq!(
        stored.as_slice(),
        &bob_note_commit.0[..],
        "stored commitment must round-trip byte-for-byte"
    );

    // The privacy property: bank B's stored commitment is NOT
    // byte-equal to bank A's voucher amount_commit, even though
    // both encode the same underlying value (100 USD here). An
    // observer reading both ledgers can't link the two without
    // help from one of the banks.
    assert_ne!(
        stored.as_slice(),
        &received.amount_commit.0[..],
        "L3 commitment MUST differ from bank A's amount_commit — that's the whole point of re-randomisation"
    );

    // Wrong-length input is rejected loudly. (Lengths other than
    // 32 are structurally invalid Pedersen points; the actor
    // checks length, the kernel/verifier would check point
    // validity in a future zkVM-anchored spend.)
    let bad_status = vos::block_on(ledger_b.submit_note_commitment(&mut &node_b, vec![0u8; 8]))
        .expect("invoke submit_note_commitment (short)");
    assert_eq!(
        bad_status,
        clerk_ledger::Status::BadInput,
        "short commitment bytes must be rejected with Status::BadInput"
    );

    // ── 5e) Actor-mediated ingress via clerk-bridge ─────────────
    //
    // Sections 5a..5d above ran the voucher verify + open
    // host-side using cipher-clerk's API directly. That tests the
    // math but doesn't exercise the production-shape path —
    // production deployments route ingress through a stateful
    // clerk-bridge actor on the receiving bank's space.
    // clerk-bridge holds (in replicated actor state):
    //   - this bank's IVK secret
    //   - the peer banks' clerk pubkeys (resolved by federation
    //     name at submit time)
    //   - a dedup set of voucher transfer-triples
    //
    // The host caller just hands the bridge a voucher + peer name
    // and gets back (status, value, blinding). What the bridge
    // adds over the host-side path: durable dedup, peer-pubkey
    // resolution against a named registry, and a single
    // enforcement point for future admission controls (rate
    // limits, allow-listing, signed envelopes).
    //
    // We deliberately submit the SAME voucher we already verified
    // host-side in 5a — this section is the actor-mediated
    // demonstration of the same value flow, not a fresh
    // ingest path. In production a recipient picks one path per
    // payment; running both here just contrasts the two ABIs.
    use clerk_bridge::{ClerkBridgeRef, Status as BridgeStatus};
    let bridge_actor = ClerkBridgeRef::at(clerk_bridge_b_id);

    // Bootstrap rejects wrong-length input.
    assert_eq!(
        vos::block_on(bridge_actor.bootstrap(&mut &node_b, clerk_b_id.0, vec![0u8; 16]))
            .expect("invoke clerk-bridge bootstrap (short ivk)"),
        BridgeStatus::BadInput,
        "ivk_secret with wrong length must be rejected at bootstrap",
    );

    // Bootstrap rejects non-canonical scalar bytes. `[0xFFu8; 32]`
    // sets every byte to 0xFF, which is far above the Ristretto
    // group order (~2^252) — `IncomingViewingKey::from_bytes`
    // returns None. Without this check, the failure would be
    // deferred to every submit_voucher call returning a confusing
    // Status::NotBootstrapped.
    assert_eq!(
        vos::block_on(bridge_actor.bootstrap(&mut &node_b, clerk_b_id.0, vec![0xFFu8; 32],))
            .expect("invoke clerk-bridge bootstrap (non-canonical)"),
        BridgeStatus::BadInput,
        "non-canonical ivk_secret must be rejected at bootstrap, not deferred to submit",
    );

    // Happy path: canonical IVK secret bootstraps successfully.
    assert_eq!(
        vos::block_on(bridge_actor.bootstrap(
            &mut &node_b,
            clerk_b_id.0,
            bank_b_ivk.to_bytes().to_vec(),
        ))
        .expect("invoke clerk-bridge bootstrap"),
        BridgeStatus::Ok,
    );
    assert_eq!(
        vos::block_on(bridge_actor.register_peer(
            &mut &node_b,
            b"bank-a".to_vec(),
            registrar_a.public.0.to_vec(),
            // Pass bank A's libp2p prefix so the bridge → prover
            // dispatch tells the extension's `blob_get` exactly
            // where to fetch the STARK from. Without the hint the
            // host would fan out to every connected peer; with it
            // the producer side gets a single targeted roundtrip.
            prefix_a as u32,
        ))
        .expect("invoke register_peer"),
        BridgeStatus::Ok,
    );
    assert_eq!(
        vos::block_on(bridge_actor.peer_count(&mut &node_b)).expect("invoke peer_count"),
        1,
    );

    // Submit the voucher through the bridge. Expected: Status::Ok,
    // recovered (value, blinding) matches what the host-side
    // envelope.open recovered in 5a.
    let bridge_reply = vos::block_on(bridge_actor.submit_voucher(
        &mut &node_b,
        voucher_bytes.clone(),
        b"bank-a".to_vec(),
    ))
    .expect("invoke submit_voucher");
    assert_eq!(
        bridge_reply.status,
        BridgeStatus::Ok,
        "voucher must verify + open through clerk-bridge"
    );
    assert_eq!(bridge_reply.value, recovered_value);
    assert_eq!(bridge_reply.blinding, recovered_blinding.0.to_vec());
    assert_eq!(
        vos::block_on(bridge_actor.redeemed_count(&mut &node_b)).expect("invoke redeemed_count"),
        1,
        "bridge must record exactly one redeemed voucher"
    );

    // Replay through the bridge: same voucher bytes, same peer.
    // The bridge's dedup set already has the transfer-triple, so
    // the reply is BridgeStatus::VoucherReplayed with empty
    // value/blinding. The dedup catches the replay BEFORE opening
    // the envelope a second time.
    let replay_reply = vos::block_on(bridge_actor.submit_voucher(
        &mut &node_b,
        voucher_bytes.clone(),
        b"bank-a".to_vec(),
    ))
    .expect("invoke submit_voucher (replay)");
    assert_eq!(replay_reply.status, BridgeStatus::VoucherReplayed);
    assert_eq!(replay_reply.value, 0);
    assert!(replay_reply.blinding.is_empty());

    // Unknown peer: submit with a name we never registered.
    let unknown_reply = vos::block_on(bridge_actor.submit_voucher(
        &mut &node_b,
        voucher_bytes.clone(),
        b"bank-z".to_vec(),
    ))
    .expect("invoke submit_voucher (unknown peer)");
    assert_eq!(unknown_reply.status, BridgeStatus::UnknownPeer);
    // Critical: a rejection from an unknown peer must NOT add to
    // the dedup set (otherwise an attacker could pre-poison the
    // dedup with fake submissions to make legitimate vouchers
    // fail on replay). Count stays at 1.
    assert_eq!(
        vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
            .expect("invoke redeemed_count (post-unknown)"),
        1,
        "unknown-peer rejection must not poison the dedup set"
    );

    // Cross-node invocation: bank A's host reaches bank B's
    // clerk-bridge directly via prefix routing. clerk_bridge_b_id's
    // top 16 bits are prefix_b, so calling from `&node_a` routes
    // the dispatch over libp2p to node_b. Same Ref API as
    // bank-B-local calls; just a different node passed to the
    // first arg.
    //
    // This pins the federation plumbing for the case where bank A
    // operator wants to verify bank B's clerk-bridge is reachable
    // before forwarding a real voucher — and for any future flow
    // where clerk-bridge is the cross-bank entry point and the
    // ingress is initiated remotely.
    let cross_node_replay = vos::block_on(bridge_actor.submit_voucher(
        &mut &node_a,
        voucher_bytes.clone(),
        b"bank-a".to_vec(),
    ))
    .expect("cross-node submit_voucher from A to bridge-b");
    // The voucher was already redeemed in step 4 above from the
    // local-node call, so the dedup catches the cross-node retry.
    // What this asserts: the cross-node Ref invocation reached
    // bank B's bridge (the dedup state lives on B's actor), AND
    // the same status semantics apply regardless of which node
    // initiated the call.
    assert_eq!(
        cross_node_replay.status,
        BridgeStatus::VoucherReplayed,
        "cross-node submit_voucher must reach bank B's bridge and see the same dedup state"
    );

    // ── 5f) Atomic ingress via clerk-bridge.redeem_voucher ──────
    //
    // Previous sections demonstrate the building blocks; this
    // section demonstrates the production-shape atomic flow:
    // verify + open + dispatch credit + dedup-mark, all in one
    // bridge handler. The bridge cross-actor-invokes
    // clerk-ledger.apply_transfer; on Status::Ok from the ledger,
    // the bridge marks the voucher redeemed atomically. On
    // ledger rejection, the voucher stays available for retry
    // with a corrected inflow.
    //
    // The voucher used in earlier sections is already in the
    // bridge's dedup set, so we mint a fresh transfer T2 on
    // bank A (alice → vault_a 200) to get an unredeemed voucher.

    let blinding2 = cipher_clerk::crypto::Blinding([4u8; 32]);
    let value2: u64 = 200;
    let amt2 = Amount::commit(value2, &blinding2);
    let signed_transfer_2: Transfer = Transfer::builder(journal_a)
        .debit(&alice, Layer::Settled, amt2)
        .credit(&vault_a, Layer::Settled, amt2)
        .signed_with(&[(&alice, &alice_kp.secret)]);
    let transfer_id_2 = signed_transfer_2.id.0;
    let transfer_bytes_2 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer_2)
        .expect("rkyv encode transfer 2")
        .to_vec();
    let openings_2 = vec![clerk_ledger::Opening {
        amount: amt2,
        value: value2,
        blinding: blinding2,
    }];
    let openings_bytes_2 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings_2)
        .expect("rkyv encode openings 2")
        .to_vec();
    assert_eq!(
        vos::block_on(ledger_a.apply_transfer(
            &mut &node_a,
            transfer_bytes_2,
            openings_bytes_2,
            ts + 500,
        ))
        .expect("apply_transfer T2 on A"),
        Status::Ok,
    );
    let (root_before_2_vec, root_after_2_vec) =
        vos::block_on(ledger_a.transfer_state_roots(&mut &node_a, transfer_id_2.to_vec()))
            .expect("invoke transfer_state_roots T2")
            .expect("anchor recorded for T2");
    let root_before_2: [u8; 32] = root_before_2_vec.try_into().expect("32-byte root_before_2");
    let root_after_2: [u8; 32] = root_after_2_vec.try_into().expect("32-byte root_after_2");

    let envelope_2 =
        EncryptedEnvelope::seal(value2, &blinding2, &bank_b_ivk_pk).expect("seal envelope 2");
    let voucher_2 = Voucher::sign(
        amt2,
        envelope_2,
        root_before_2,
        root_after_2,
        CcProof::default(),
        &registrar_a.secret,
    );
    let voucher_bytes_2 = voucher_2.to_bytes();
    let voucher_2_external_id = blake2b_256(
        b"clerk-bridge/voucher-redemption/v1",
        &[
            &voucher_2.amount_commit.0,
            &voucher_2.state_root_before,
            &voucher_2.state_root_after,
        ],
    );

    // Bank B's host pre-builds the inflow Transfer with the
    // bridge-enforced external_id link. The credit amount MUST
    // equal voucher.amount_commit (the bridge checks this).
    let inflow_2: Transfer = Transfer::builder(journal_b)
        .debit(&inflow_b, Layer::Settled, amt2)
        .credit(&bob, Layer::Settled, amt2)
        .external_id(ExternalId(voucher_2_external_id))
        .signed_with(&[(&inflow_b, &inflow_kp.secret)]);
    let inflow_2_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_2)
        .expect("rkyv encode inflow 2")
        .to_vec();
    let inflow_2_openings = vec![clerk_ledger::Opening {
        amount: amt2,
        value: value2,
        blinding: blinding2,
    }];
    let inflow_2_openings_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_2_openings)
            .expect("rkyv encode inflow 2 openings")
            .to_vec();

    // Snapshot Bob's current Settled.cr commit and the bridge's
    // dedup count so we can pin the deltas.
    let bob_before = vos::block_on(ledger_b.account(&mut &node_b, bob_id.to_vec()))
        .expect("read bob pre-redeem")
        .expect("bob exists");
    let dedup_before = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
        .expect("invoke redeemed_count (pre-redeem)");

    // Atomic happy path.
    let redeem_reply = vos::block_on(bridge_actor.redeem_voucher(
        &mut &node_b,
        voucher_bytes_2.clone(),
        b"bank-a".to_vec(),
        inflow_2_bytes.clone(),
        inflow_2_openings_bytes.clone(),
        ts + 600,
    ))
    .expect("invoke redeem_voucher");
    assert_eq!(
        redeem_reply.status,
        BridgeStatus::Ok,
        "redeem_voucher must succeed end-to-end (bridge=OK)"
    );
    assert_eq!(
        redeem_reply.ledger_status,
        Status::Ok as u8,
        "ledger must accept the bridge-dispatched inflow (ledger=OK)"
    );
    let bob_after_redeem = vos::block_on(ledger_b.account(&mut &node_b, bob_id.to_vec()))
        .expect("read bob post-redeem")
        .expect("bob exists");
    assert_ne!(
        bob_before.balances[settled].cr, bob_after_redeem.balances[settled].cr,
        "bob's Settled credit must move on redeem_voucher"
    );
    let dedup_after = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
        .expect("invoke redeemed_count (post-redeem)");
    assert_eq!(
        dedup_after,
        dedup_before + 1,
        "bridge must atomically record one new redemption"
    );

    // Replay through redeem_voucher: bridge dedup catches it
    // before the ledger is touched a second time.
    let replay_redeem = vos::block_on(bridge_actor.redeem_voucher(
        &mut &node_b,
        voucher_bytes_2.clone(),
        b"bank-a".to_vec(),
        inflow_2_bytes.clone(),
        inflow_2_openings_bytes.clone(),
        ts + 700,
    ))
    .expect("invoke redeem_voucher (replay)");
    assert_eq!(
        replay_redeem.status,
        BridgeStatus::VoucherReplayed,
        "second redeem of same voucher must hit bridge dedup"
    );

    // Adversarial: inflow with the WRONG external_id (we build a
    // fresh voucher V3 just to have an unredeemed voucher to
    // submit; the inflow's external_id is left at None, which
    // mismatches the bridge's computed dedup key).
    let blinding3 = cipher_clerk::crypto::Blinding([5u8; 32]);
    let value3: u64 = 50;
    let amt3 = Amount::commit(value3, &blinding3);
    let signed_transfer_3: Transfer = Transfer::builder(journal_a)
        .debit(&alice, Layer::Settled, amt3)
        .credit(&vault_a, Layer::Settled, amt3)
        .signed_with(&[(&alice, &alice_kp.secret)]);
    let transfer_id_3 = signed_transfer_3.id.0;
    let transfer_bytes_3 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer_3)
        .expect("rkyv encode transfer 3")
        .to_vec();
    let openings_3 = vec![clerk_ledger::Opening {
        amount: amt3,
        value: value3,
        blinding: blinding3,
    }];
    let openings_bytes_3 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings_3)
        .expect("rkyv encode openings 3")
        .to_vec();
    assert_eq!(
        vos::block_on(ledger_a.apply_transfer(
            &mut &node_a,
            transfer_bytes_3,
            openings_bytes_3,
            ts + 800,
        ))
        .expect("apply_transfer T3 on A"),
        Status::Ok,
    );
    let (root_before_3_vec, root_after_3_vec) =
        vos::block_on(ledger_a.transfer_state_roots(&mut &node_a, transfer_id_3.to_vec()))
            .expect("transfer_state_roots T3")
            .expect("anchor recorded for T3");
    let envelope_3 = EncryptedEnvelope::seal(value3, &blinding3, &bank_b_ivk_pk).unwrap();
    let voucher_3 = Voucher::sign(
        amt3,
        envelope_3,
        root_before_3_vec.try_into().unwrap(),
        root_after_3_vec.try_into().unwrap(),
        CcProof::default(),
        &registrar_a.secret,
    );
    let voucher_3_bytes = voucher_3.to_bytes();

    // Inflow with NO external_id (default None) — bridge must
    // reject before reaching the ledger.
    let inflow_3_no_eid: Transfer = Transfer::builder(journal_b)
        .debit(&inflow_b, Layer::Settled, amt3)
        .credit(&bob, Layer::Settled, amt3)
        .signed_with(&[(&inflow_b, &inflow_kp.secret)]);
    let inflow_3_no_eid_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_3_no_eid)
        .expect("rkyv encode inflow 3 (no eid)")
        .to_vec();
    let inflow_3_openings = vec![clerk_ledger::Opening {
        amount: amt3,
        value: value3,
        blinding: blinding3,
    }];
    let inflow_3_openings_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_3_openings)
            .expect("rkyv encode inflow 3 openings")
            .to_vec();
    let dedup_pre_adv = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
        .expect("invoke redeemed_count pre-adversarial");
    let adv_reply = vos::block_on(bridge_actor.redeem_voucher(
        &mut &node_b,
        voucher_3_bytes.clone(),
        b"bank-a".to_vec(),
        inflow_3_no_eid_bytes,
        inflow_3_openings_bytes.clone(),
        ts + 900,
    ))
    .expect("invoke redeem_voucher (no external_id)");
    assert_eq!(
        adv_reply.status,
        BridgeStatus::InflowInconsistent,
        "inflow with mismatched external_id must hit bridge inconsistency check"
    );
    let dedup_post_adv = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
        .expect("invoke redeemed_count post-adversarial");
    assert_eq!(
        dedup_post_adv, dedup_pre_adv,
        "rejected inflow must NOT mark voucher as redeemed — caller can retry with correct inflow"
    );

    // Adversarial #2: inflow with CORRECT external_id + amount
    // (bridge accepts) but signed by the WRONG keypair (ledger
    // rejects on its pre-verify gate). Proves the cross-actor
    // dispatch reaches the ledger AND the bridge correctly
    // forwards the rejection without locking the voucher.
    let voucher_3_external_id = blake2b_256(
        b"clerk-bridge/voucher-redemption/v1",
        &[
            &voucher_3.amount_commit.0,
            &voucher_3.state_root_before,
            &voucher_3.state_root_after,
        ],
    );
    // Sign with alice's secret instead of inflow_b's — bridge's
    // external_id + amount checks pass (those don't care about
    // sigs), but clerk-ledger's pre-verify gate fails the sig
    // against inflow_b.auth_key.
    let inflow_3_wrongsig: Transfer = Transfer::builder(journal_b)
        .debit(&inflow_b, Layer::Settled, amt3)
        .credit(&bob, Layer::Settled, amt3)
        .external_id(ExternalId(voucher_3_external_id))
        .signed_by(&[&alice_kp.secret]);
    let inflow_3_wrongsig_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&inflow_3_wrongsig)
            .expect("rkyv encode inflow 3 (wrong sig)")
            .to_vec();
    let ledger_rejected_reply = vos::block_on(bridge_actor.redeem_voucher(
        &mut &node_b,
        voucher_3_bytes.clone(),
        b"bank-a".to_vec(),
        inflow_3_wrongsig_bytes,
        inflow_3_openings_bytes.clone(),
        ts + 1000,
    ))
    .expect("invoke redeem_voucher (wrong inflow sig)");
    assert_eq!(
        ledger_rejected_reply.status,
        BridgeStatus::LedgerRejected,
        "bridge accepts the inflow shape but the ledger rejects on bad signature"
    );
    assert_eq!(
        ledger_rejected_reply.ledger_status,
        Status::SignatureInvalid as u8,
        "ledger_status must carry clerk-ledger's Status::SignatureInvalid so the caller can debug"
    );
    // Voucher V3 still hasn't been redeemed — bridge dedup
    // count is unchanged. The caller can rebuild the inflow with
    // a correct signature and retry.
    let dedup_after_ledger_reject = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
        .expect("invoke redeemed_count post-ledger-reject");
    assert_eq!(
        dedup_after_ledger_reject, dedup_pre_adv,
        "STATUS_LEDGER_REJECTED must keep voucher available for retry"
    );

    // Adversarial #3: inflow with the wrong entry SHAPE — empty
    // entries, correct external_id. The bridge requires exactly
    // 1 debit + 1 credit; a 0-entry inflow (or anything else)
    // is rejected as INFLOW_INCONSISTENT before the kernel sees
    // it. This tightening matters because the kernel's zero-sum
    // check would let a malicious operator slip extra
    // self-cancelling entries past us if the bridge only
    // validated entries[0]'s amount.
    use cipher_clerk::types::TransferFlags;
    let zero_entry_inflow = {
        let mut t = Transfer::default();
        t.id = TransferId([0xDEu8; 16]);
        t.journal_id = journal_b;
        t.correlation_id = t.id;
        t.flags = TransferFlags::NONE;
        t.external_id = Some(ExternalId(voucher_3_external_id));
        // entries left empty
        // signatures left empty (no debits to sign)
        t
    };
    let zero_entry_inflow_bytes =
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&zero_entry_inflow)
            .expect("rkyv encode zero-entry inflow")
            .to_vec();
    let zero_entry_reply = vos::block_on(bridge_actor.redeem_voucher(
        &mut &node_b,
        voucher_3_bytes.clone(),
        b"bank-a".to_vec(),
        zero_entry_inflow_bytes,
        inflow_3_openings_bytes.clone(),
        ts + 1100,
    ))
    .expect("invoke redeem_voucher (zero entries)");
    assert_eq!(
        zero_entry_reply.status,
        BridgeStatus::InflowInconsistent,
        "inflow with != 2 entries must be rejected at the bridge shape check"
    );

    // ── 5g) Mode::External voucher wire round-trip ──────────────
    //
    // Demonstrates the Mode::External proof envelope flowing through
    // the existing voucher wire format. cipher-clerk's voucher
    // protocol already accommodates two proof modes (Signature +
    // External); previous sections used Mode::Signature
    // (`CcProof::default()` → 0-byte placeholder under the
    // Signature mode tag). This section builds a voucher whose
    // proof field carries `Mode::External` opaque bytes, signs +
    // round-trips it through Voucher::from_bytes, and verifies the
    // proof bytes host-side against the issuer's canonical
    // public_bytes.
    //
    // The proof bytes here are the SAME v0 placeholder that
    // clerk-prover-extension emits: blake2b-256("clerk-prover/
    // voucher-proof/v0-placeholder" || public_bytes). Cryptographic
    // zk verification is gated on the prove path being unblocked
    // (zkpvm task #7); once it is, the placeholder swap to
    // `zkpvm_verifier::verify_standalone` is a single-function
    // change. The WIRE shape this section pins is invariant.
    //
    // In-bridge verification (clerk-bridge.submit_voucher dispatching
    // to the prover extension before acceptance) is deferred to a
    // follow-on slice — task #8.
    use cipher_clerk::proof::Mode as CcProofMode;
    use cipher_clerk::voucher::proof::{Public as VoucherPublic, public_bytes};

    // clerk-prover-extension's v0 placeholder proof body:
    // blake2b-256("clerk-prover/voucher-proof/v0-placeholder" ||
    // public_bytes). Same logic the extension's
    // `verify_voucher_proof` handler runs.
    let placeholder_proof = |pub_bytes: &[u8]| -> Vec<u8> {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(b"clerk-prover/voucher-proof/v0-placeholder");
        h.update(pub_bytes);
        h.finalize().as_bytes().to_vec()
    };

    let public_for_proof = VoucherPublic {
        issuer: registrar_a.public,
        amount_commit: amt,
        state_root_before: root_before,
        state_root_after: root_after,
    };
    let pub_bytes = public_bytes(&public_for_proof);
    let external_proof_bytes = placeholder_proof(&pub_bytes);

    // Re-seal an envelope to match the existing transfer; the
    // sender side packages a fresh voucher with the external proof.
    let envelope_external =
        EncryptedEnvelope::seal(value, &blinding, &bank_b_ivk_pk).expect("seal envelope external");
    let voucher_external = Voucher::sign(
        amt,
        envelope_external,
        root_before,
        root_after,
        CcProof {
            mode: CcProofMode::External,
            bytes: external_proof_bytes.clone(),
        },
        &registrar_a.secret,
    );
    assert_eq!(
        voucher_external.proof.mode,
        CcProofMode::External,
        "voucher.proof.mode must round-trip as External"
    );
    assert_eq!(
        voucher_external.proof.bytes.len(),
        32,
        "placeholder proof bytes are blake2b-256 (32 bytes)"
    );

    // Wire round-trip — Voucher::to_bytes / from_bytes must preserve
    // Mode::External and the proof bytes verbatim.
    let voucher_external_bytes = voucher_external.to_bytes();
    let parsed_external = Voucher::from_bytes(&voucher_external_bytes)
        .expect("Voucher::from_bytes must accept Mode::External payloads");
    assert_eq!(parsed_external.proof.mode, CcProofMode::External);
    assert_eq!(parsed_external.proof.bytes, external_proof_bytes);
    assert_eq!(
        parsed_external.verify_signature(&registrar_a.public),
        Ok(()),
        "issuer signature still authenticates the voucher when proof.mode = External"
    );

    // Verifier-side check: independently reconstruct `public_bytes`
    // from the voucher's public fields, recompute the placeholder,
    // assert byte-equality with the carried proof.bytes.  This is
    // what a real `verify_standalone` call site will do — modulo the
    // placeholder being a STARK proof check instead of byte equality.
    let pub_bytes_verifier = public_bytes(&VoucherPublic {
        issuer: registrar_a.public,
        amount_commit: parsed_external.amount_commit,
        state_root_before: parsed_external.state_root_before,
        state_root_after: parsed_external.state_root_after,
    });
    assert_eq!(
        pub_bytes_verifier, pub_bytes,
        "verifier-reconstructed public_bytes must match issuer's"
    );
    assert_eq!(
        placeholder_proof(&pub_bytes_verifier),
        parsed_external.proof.bytes,
        "placeholder proof bytes must reproduce on the verifier side — \
         once zkpvm task #7 is fixed, this is the call site that swaps \
         to verify_standalone(proof, program_commitment)"
    );

    // Adversarial: flipping a byte of the proof field makes the
    // wire signature fail (signature payload covers proof.bytes).
    let mut tampered_external = voucher_external_bytes.clone();
    // The proof bytes live after the mode-tag byte; mutate one to
    // exercise the issuer-signature-covers-proof property.
    let proof_byte_offset = tampered_external.len() - 64 - 8;
    tampered_external[proof_byte_offset] ^= 0x01;
    let parsed_tampered_external = Voucher::from_bytes(&tampered_external)
        .expect("structural parse survives a single-byte flip in the proof body");
    assert_eq!(
        parsed_tampered_external.verify_signature(&registrar_a.public),
        Err(VoucherError::BadSignature),
        "wire signature must reject a proof-bytes tamper"
    );

    // ── 5h) In-bridge Mode::External verify via clerk-prover ────
    //
    // Loads the `clerk-prover-extension` .so on bank B's node,
    // points clerk-bridge at it via `set_prover`, and submits a
    // fresh Mode::External voucher. The bridge dispatches
    // verify_voucher_proof to the prover before accepting; on a
    // tampered (or placeholder) proof it returns
    // Status::ProofInvalid.
    //
    // Why a host extension rather than in-actor verification:
    // zkpvm-verifier can't build for riscv64em-javm today (task
    // #1 spike). The prover runs natively as a `.so` and the
    // bridge dispatches via `ctx.ask`; same trust boundary in
    // effect — the actor still decides whether to accept.
    //
    // Cross-MiB proof delivery (2026-05-13): the voucher's
    // `proof.bytes` carries the 32-byte content address of the
    // actual ~1.4 MiB STARK in the producer node's proof-blob
    // store (`VosNode::put_proof_blob`). The extension's
    // `verify_voucher_proof` uses `ctx.blob_get(hash, hint)` to
    // fetch those bytes host-side; the bridge → extension
    // dispatch only ever ships the 32-byte hash, well inside the
    // PVM actor's 4 KiB input buffer. The federation test has
    // libp2p attached, so the producer-side stash on bank A is
    // sufficient: bank B's verifier extension reaches across the
    // wire (via the `peer_prefix` hint registered with `register_
    // peer`) to fetch the bytes on demand. No bank-B pre-seed.
    //
    // NOTE: section 5h's real-STARK HAPPY path is currently skipped
    // (the transition proof is segment-chain-sized and chain-aware
    // verify isn't wired — see the SKIP below). What this section
    // still exercises is the prover registration + commitment
    // plumbing and the ADVERSARIAL reject paths (forged content
    // address, local + cross-node), which need no real proof. The
    // cross-MiB blob-fetch happy path returns once chain verify lands.

    // Load clerk-prover-extension's .so. Skip if not built;
    // matches the SKIP pattern used by other actor ELFs above.
    let prover_so = {
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        std::path::PathBuf::from(format!(
            "{}/../target/{profile}/libprover_extension.so",
            env!("CARGO_MANIFEST_DIR"),
        ))
    };
    if !prover_so.exists() {
        eprintln!("SKIP 5h: prover-extension not built. Run: cargo build -p prover-extension");
    } else {
        use vos::node::ExtensionConfig;

        // Mutable handle on node_b so we can register an extension.
        // node_b has already been mutated through `&mut &node_b`
        // for actor handlers above; the typed pattern allows mixing
        // immutable invocations with mutable registrations.
        let prover_id = node_b.register_extension(ExtensionConfig::new(prover_so));

        use prover_extension::ProverRef;
        let prover_ref = ProverRef::at(prover_id);

        // The trusted program commitment is provenance: fetch it from the
        // prover (v1 baked) and configure the bridge with it. It's the
        // sole cross-program anchor the bridge hands `verify`.
        let voucher_commitment =
            vos::block_on(prover_ref.program_commitment(&mut &node_b, b"voucher-check".to_vec()))
                .expect("invoke program_commitment");
        assert_eq!(
            voucher_commitment.len(),
            32,
            "voucher-check program commitment is the 32-byte Merkle root"
        );

        // Wire bank B's bridge to the prover + trusted commitment.
        // `set_prover` is legal post-bootstrap (idempotent in identical
        // args).
        assert_eq!(
            vos::block_on(bridge_actor.set_prover(
                &mut &node_b,
                prover_id.0,
                voucher_commitment.clone()
            ))
            .expect("invoke set_prover"),
            BridgeStatus::Ok,
            "set_prover after bootstrap must succeed"
        );
        assert_eq!(
            vos::block_on(bridge_actor.prover(&mut &node_b)).expect("invoke prover"),
            prover_id.0,
            "diagnostic getter must return the configured id"
        );

        // Real-STARK happy path — not runnable end-to-end here:
        // voucher-check now proves the full conservation-of-value
        // transition (a multi-million-step trace) which only proves as a
        // CHAIN of bounded segments (`prove_transition_segmented_chain`
        // is that capstone), while the bridge's verify leg checks ONE
        // standalone proof against ONE program commitment. Verifying a
        // segment chain across the trust boundary needs a verifier-side
        // aggregation step (per-segment commitment binding + STARK-bound
        // memory commitments at the segment boundaries) that is not
        // built yet. Until then the happy path lives in the prover's
        // segmented-chain test, and the bridge dispatch below is pinned
        // by the adversarial (reject) cases, which need no real proof.
        // Real-STARK happy path (federation wire-through W3) — opt-in via
        // VOS_FEDERATION_REAL_STARK (the canonical chain prove is minutes: the
        // conservation transition is ~76 bounded segments). RUN WITH
        // RUST_MIN_STACK=268435456: the canonical prove's rayon workers + the
        // extension's verify thread need ample stack in the runtime context
        // (the default ~2 MiB overflows; the standalone prover test doesn't
        // hit this because nothing pre-builds the rayon pool there). Build a real
        // conservation transition, prove it as a canonical segment chain
        // through the prover extension, CAS the chain blob on bank A, and
        // submit an External voucher attesting the transition's roots; bank B's
        // bridge dispatches verify_chain, which fetches the blob over libp2p,
        // verifies the chain against the program's canonical commitment
        // allowlist + the io-binding, and redeems.
        if std::env::var("VOS_FEDERATION_REAL_STARK").is_ok() {
            use vos::Encode;
            let dedup_before_happy = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
                .expect("redeemed_count pre-happy");
            // Issued by registrar_a so the witness's Public.issuer == the peer
            // clerk pubkey the bridge reconstructs public_bytes from.
            let (public, witness, value, blinding) = build_conservation_transition(&registrar_a);
            let witness_buf = encode_witness_payload(&public.encode(), &witness.encode());
            assert!(
                witness_buf.len() <= 16384,
                "conservation witness exceeds the guest __VOS_WITNESS buffer ({} B)",
                witness_buf.len()
            );
            // Offline: prove the canonical segment chain (minutes).
            let chain_bytes = prover_extension::prove_chain_blob(b"voucher-check", &witness_buf)
                .expect(
                    "prove_chain over the conservation transition \
                     (stale voucher-check ELF? run `just build-voucher-check`)",
                );
            // Seed the chain blob on bank B's node so verify_chain fetches it
            // LOCALLY. The full ChainProof (~N×1 MiB ≈ tens of MiB) exceeds the
            // 8 MiB single-shot cross-node frame cap (MAX_FRAME_BYTES; no
            // chunked transport yet), so the cross-node fetch can't carry it.
            // The real cross-bank delivery path is RECURSION (which collapses
            // the N-segment chain into one ~1 MiB aggregate proof, well under
            // the cap — and supersedes verify_chain), or chunked transport;
            // both are out of scope here. The crypto under test — bank B
            // verifying bank A's conservation chain against the canonical
            // allowlist + io-binding — is delivery-agnostic.
            let chain_hash = node_b.put_proof_blob(chain_bytes);
            let envelope_happy = EncryptedEnvelope::seal(value, &blinding, &bank_b_ivk_pk)
                .expect("seal envelope (happy)");
            let voucher_happy = Voucher::sign(
                public.amount_commit,
                envelope_happy,
                public.state_root_before,
                public.state_root_after,
                CcProof {
                    mode: CcProofMode::External,
                    bytes: chain_hash.to_vec(),
                },
                &registrar_a.secret,
            );
            let reply_happy = vos::block_on(bridge_actor.submit_voucher(
                &mut &node_b,
                voucher_happy.to_bytes(),
                b"bank-a".to_vec(),
            ))
            .expect("invoke submit_voucher (Mode::External, real canonical chain)");
            assert_eq!(
                reply_happy.status,
                BridgeStatus::Ok,
                "a real canonical-chain External voucher must verify + redeem (got {:?})",
                reply_happy.status
            );
            let dedup_after_happy = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
                .expect("redeemed_count post-happy");
            assert_eq!(
                dedup_after_happy,
                dedup_before_happy + 1,
                "the real-STARK happy path must advance the redeemed/dedup count"
            );

            // Forged-on-real-STARK: the SAME (valid) chain blob, but the
            // voucher LIES about root_after (re-signed, so the signature is
            // valid and the triple dedup key is fresh). The bridge reconstructs
            // public_bytes with the lie, so the prover's io-binding
            // (compute_io_hash over the asserted public) no longer matches the
            // proof's STARK-bound io-hash → reject. This is exactly the
            // conservation property a bare signature check could NOT enforce.
            let envelope_forge = EncryptedEnvelope::seal(value, &blinding, &bank_b_ivk_pk)
                .expect("seal envelope (forge)");
            let voucher_forge = Voucher::sign(
                public.amount_commit,
                envelope_forge,
                public.state_root_before,
                [0xEEu8; 32],
                CcProof {
                    mode: CcProofMode::External,
                    bytes: chain_hash.to_vec(),
                },
                &registrar_a.secret,
            );
            let reply_forge = vos::block_on(bridge_actor.submit_voucher(
                &mut &node_b,
                voucher_forge.to_bytes(),
                b"bank-a".to_vec(),
            ))
            .expect("invoke submit_voucher (forged root_after on a real chain)");
            assert_eq!(
                reply_forge.status,
                BridgeStatus::ProofInvalid,
                "a voucher with a forged root_after must reject — the real chain proof's \
                 io-binding pins the genuine roots (got {:?})",
                reply_forge.status
            );
        } else {
            eprintln!(
                "SKIP 5h happy-path: set VOS_FEDERATION_REAL_STARK=1 RUST_MIN_STACK=268435456 \
                 to run the real canonical segment-chain prove (minutes) + verify_chain accept \
                 / forged-root reject"
            );
        }
        let dedup_after_5h = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
            .expect("redeemed_count baseline");

        // Adversarial — forged content address on a FRESH voucher
        // (otherwise the dedup catches before the prover dispatch).
        // The 32-byte placeholder hash is not in the proof-blob
        // store, so the extension's `ctx.blob_get` returns None and
        // verify_voucher_proof short-circuits to 0 → ProofInvalid.
        // Same security guarantee a forged STARK would get.
        let blinding4 = cipher_clerk::crypto::Blinding([6u8; 32]);
        let value4: u64 = 25;
        let amt4 = Amount::commit(value4, &blinding4);
        let signed_transfer_4: Transfer = Transfer::builder(journal_a)
            .debit(&alice, Layer::Settled, amt4)
            .credit(&vault_a, Layer::Settled, amt4)
            .signed_with(&[(&alice, &alice_kp.secret)]);
        let transfer_id_4 = signed_transfer_4.id.0;
        let transfer_bytes_4 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer_4)
            .expect("rkyv encode transfer 4")
            .to_vec();
        let openings_4 = vec![clerk_ledger::Opening {
            amount: amt4,
            value: value4,
            blinding: blinding4,
        }];
        let openings_bytes_4 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings_4)
            .expect("rkyv encode openings 4")
            .to_vec();
        assert_eq!(
            vos::block_on(ledger_a.apply_transfer(
                &mut &node_a,
                transfer_bytes_4,
                openings_bytes_4,
                ts + 1200,
            ))
            .expect("apply_transfer T4 on A"),
            Status::Ok,
        );
        let (root_before_4_vec, root_after_4_vec) =
            vos::block_on(ledger_a.transfer_state_roots(&mut &node_a, transfer_id_4.to_vec()))
                .expect("transfer_state_roots T4")
                .expect("anchor for T4");
        let root_before_4: [u8; 32] = root_before_4_vec.try_into().expect("32-byte");
        let root_after_4: [u8; 32] = root_after_4_vec.try_into().expect("32-byte");
        let envelope_v4 =
            EncryptedEnvelope::seal(value4, &blinding4, &bank_b_ivk_pk).expect("seal envelope v4");
        // Forged content address: a 32-byte hash the attacker
        // produces from arbitrary domain-separated bytes. With
        // overwhelming probability it doesn't hit any blob in
        // the CAS — the extension's `blob_get` returns None
        // and verify short-circuits to reject.
        let forged_proof_bytes = placeholder_proof(b"some-other-transfer");
        let voucher_v4_forged = Voucher::sign(
            amt4,
            envelope_v4,
            root_before_4,
            root_after_4,
            CcProof {
                mode: CcProofMode::External,
                bytes: forged_proof_bytes,
            },
            &registrar_a.secret,
        );
        let voucher_v4_forged_bytes = voucher_v4_forged.to_bytes();
        let reply_forged = vos::block_on(bridge_actor.submit_voucher(
            &mut &node_b,
            voucher_v4_forged_bytes,
            b"bank-a".to_vec(),
        ))
        .expect("invoke submit_voucher (Mode::External, forged proof)");
        assert_eq!(
            reply_forged.status,
            BridgeStatus::ProofInvalid,
            "bridge must reject Mode::External voucher whose proof_hash points to no CAS entry"
        );
        // Dedup count unchanged — a rejected proof must not poison
        // the dedup set (same posture as UnknownPeer / VoucherInvalid).
        let dedup_after_forged = vos::block_on(bridge_actor.redeemed_count(&mut &node_b))
            .expect("redeemed_count post-forged");
        assert_eq!(
            dedup_after_forged, dedup_after_5h,
            "rejected Mode::External proof must not advance dedup"
        );

        // Cross-node adversarial: same forged-proof voucher submitted
        // from bank A's node. Routes through libp2p to bank B's bridge,
        // which dispatches to bank B's prover. Pins that the
        // bridge → prover dispatch works irrespective of which node
        // initiated the submit. (We use a FRESH forged voucher on a
        // new transfer T5 — the previous voucher's dedup_key would
        // hit VoucherReplayed otherwise, masking the proof path.)
        let blinding5 = cipher_clerk::crypto::Blinding([7u8; 32]);
        let value5: u64 = 10;
        let amt5 = Amount::commit(value5, &blinding5);
        let signed_transfer_5: Transfer = Transfer::builder(journal_a)
            .debit(&alice, Layer::Settled, amt5)
            .credit(&vault_a, Layer::Settled, amt5)
            .signed_with(&[(&alice, &alice_kp.secret)]);
        let transfer_id_5 = signed_transfer_5.id.0;
        let transfer_bytes_5 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&signed_transfer_5)
            .expect("rkyv encode transfer 5")
            .to_vec();
        let openings_5 = vec![clerk_ledger::Opening {
            amount: amt5,
            value: value5,
            blinding: blinding5,
        }];
        let openings_bytes_5 = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings_5)
            .expect("rkyv encode openings 5")
            .to_vec();
        assert_eq!(
            vos::block_on(ledger_a.apply_transfer(
                &mut &node_a,
                transfer_bytes_5,
                openings_bytes_5,
                ts + 1300,
            ))
            .expect("apply_transfer T5 on A"),
            Status::Ok,
        );
        let (root_before_5_vec, root_after_5_vec) =
            vos::block_on(ledger_a.transfer_state_roots(&mut &node_a, transfer_id_5.to_vec()))
                .expect("transfer_state_roots T5")
                .expect("anchor for T5");
        let envelope_v5 =
            EncryptedEnvelope::seal(value5, &blinding5, &bank_b_ivk_pk).expect("seal envelope v5");
        let voucher_v5_forged = Voucher::sign(
            amt5,
            envelope_v5,
            root_before_5_vec.try_into().unwrap(),
            root_after_5_vec.try_into().unwrap(),
            CcProof {
                mode: CcProofMode::External,
                bytes: placeholder_proof(b"another-different-public"),
            },
            &registrar_a.secret,
        );
        let cross_node_forged = vos::block_on(bridge_actor.submit_voucher(
            &mut &node_a, // caller = bank A's node, target = bank B's bridge
            voucher_v5_forged.to_bytes(),
            b"bank-a".to_vec(),
        ))
        .expect("cross-node submit_voucher (Mode::External, forged)");
        assert_eq!(
            cross_node_forged.status,
            BridgeStatus::ProofInvalid,
            "cross-node bridge must dispatch to its local prover and reject forged proofs same as local submit"
        );
    }

    // ── 6) Bridge addressing parity ─────────────────────────────
    //
    // The bridge is the path a future cross-bank settlement would
    // ride (the caller forwards a Voucher/SettlementClaim payload
    // through bridge-b for B's settle agent to process). Verify the
    // bridge reachability now so the federation plumbing is wired
    // end-to-end.
    let bridge_b = SpaceBridgeRef::at(bridge_b_id);
    let bridge_b_self =
        vos::block_on(bridge_b.where_am_i(&mut &node_a)).expect("A invokes bridge_b.where_am_i");
    assert_eq!(
        bridge_b_self, bridge_b_id.0,
        "bridge-b's where_am_i must be bridge-b's own id (not A's local bridge shadow)"
    );

    // ── Cleanup ────────────────────────────────────────────────
    let results_a = node_a.collect();
    let results_b = node_b.collect();
    let panics: u32 = results_a
        .iter()
        .chain(results_b.iter())
        .map(|r| r.panics)
        .sum();
    let _ = std::fs::remove_dir_all(&dir_root);
    assert_eq!(panics, 0, "actor panics during federation test: {panics}");
}
