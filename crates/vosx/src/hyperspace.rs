//! Hyperspace plumbing: announcing local services into the
//! registry and keeping their `last_seen` fresh via periodic
//! heartbeats.
//!
//! Both helpers run *after* the network is attached so the
//! local replica's CRDT layer fans the work out to the rest
//! of the hyperspace.

use std::time::Duration;

use vos::abi::service::ServiceId;
use vos::node::{InvokeHandle, VosNode};

/// One service to announce + heartbeat. Built up during agent
/// registration in `cmd_start`, then handed to
/// [`flush_registry_announces`] after the network is attached.
pub struct AnnouncePlan {
    pub name: String,
    pub owner_prefix: u16,
    pub service_id: u16,
    pub roles: Vec<String>,
}

/// Send an `announce(...)` to the local registry replica via
/// the macro-generated [`registry::RegistryClient`] for every
/// plan. The local replica fans the entries out through the
/// CRDT layer; in a single-host setup this is just a
/// same-process invoke.
pub fn flush_registry_announces(node: &VosNode, plans: &[AnnouncePlan]) {
    let client = registry::RegistryClient::at(node, ServiceId::REGISTRY);
    for plan in plans {
        match client.announce(
            plan.name.clone(),
            plan.owner_prefix as u32,
            plan.service_id as u32,
            plan.roles.clone(),
        ) {
            Ok(()) => eprintln!("vosx: registered '{}' in registry", plan.name),
            Err(e) => eprintln!(
                "vosx: warning: registry announce for '{}' failed: {e}",
                plan.name,
            ),
        }
    }
}

/// Background heartbeat loop. Each tick walks `names` and
/// fires a `heartbeat(name)` invoke at `ServiceId::REGISTRY`.
/// Exits when the owning node flips its shutdown flag. Replies
/// are ignored — `heartbeat` doesn't return anything
/// meaningful, and the next tick recovers from any transient
/// miss.
///
/// Inlines the wire encoding rather than using
/// `RegistryClient` because the loop runs against an
/// `InvokeHandle` (off the main thread, after `run_forever`
/// has the `&VosNode`).
pub fn heartbeat_loop(handle: InvokeHandle, names: Vec<String>, interval: Duration) {
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;

    // Sleep up front so we don't double-announce immediately
    // after the initial flush.
    let slice = Duration::from_millis(100);
    let mut waited = Duration::ZERO;
    loop {
        while waited < interval {
            if handle.is_shutting_down() {
                return;
            }
            std::thread::sleep(slice);
            waited += slice;
        }
        waited = Duration::ZERO;
        for name in &names {
            if handle.is_shutting_down() {
                return;
            }
            let m = Msg::new("heartbeat").with("name", name.as_str());
            let encoded = m.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            let _ = handle.invoke_with_timeout(
                ServiceId::REGISTRY,
                payload,
                Duration::from_secs(2),
            );
        }
    }
}
