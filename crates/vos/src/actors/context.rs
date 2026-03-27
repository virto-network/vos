use super::Actor;
use alloc::vec::Vec;

/// Execution context passed to message handlers.
///
/// Queues effects (transfers, storage writes, spawns) during handler
/// execution. Effects are flushed after each handler via hostcalls.
pub struct Context<A: Actor> {
    id: ServiceId,
    stop_requested: bool,
    pending_sends: Vec<PendingSend>,
    pending_writes: Vec<(Vec<u8>, Vec<u8>)>,
    pending_spawns: Vec<[u8; 32]>,
    _phantom: core::marker::PhantomData<A>,
}

pub use vos_abi::service::ServiceId;

/// A queued transfer to another service.
struct PendingSend {
    target: ServiceId,
    payload: Vec<u8>,
}

impl<A: Actor> Context<A> {
    pub fn new(id: ServiceId) -> Self {
        Self {
            id,
            stop_requested: false,
            pending_sends: Vec::new(),
            pending_writes: Vec::new(),
            pending_spawns: Vec::new(),
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get this actor's service ID.
    pub fn id(&self) -> ServiceId {
        self.id
    }

    /// Send a message to another service. The payload is provided as a
    /// preimage and a transfer with the hash is queued.
    pub fn send(&mut self, target: ServiceId, payload: &[u8]) {
        self.pending_sends.push(PendingSend {
            target,
            payload: payload.to_vec(),
        });
    }

    /// Queue a key-value write to per-service storage.
    pub fn store(&mut self, key: &[u8], value: &[u8]) {
        self.pending_writes.push((key.to_vec(), value.to_vec()));
    }

    /// Queue a new service spawn from a code hash.
    pub fn spawn(&mut self, code_hash: [u8; 32]) {
        self.pending_spawns.push(code_hash);
    }

    /// Request the actor to stop after the current message.
    pub fn stop(&mut self) {
        self.stop_requested = true;
    }

    /// Check if a stop has been requested.
    pub fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    /// Flush all queued effects via hostcalls.
    ///
    /// On non-RISC-V targets this is a no-op (effects are only meaningful
    /// when running inside the PVM).
    pub fn flush_effects(&mut self) {
        #[cfg(feature = "guest")]
        {
            use vos_abi::guest::hostcalls;

            // Flush storage writes
            for (key, value) in self.pending_writes.drain(..) {
                hostcalls::write(&key, &value);
            }

            // Flush sends: provide preimage + transfer
            for send in self.pending_sends.drain(..) {
                // The host computes the hash — we pass a zero hash and let
                // the provide hostcall return the real hash. For now, we
                // send the payload directly as the memo (vosx handles it).
                let hash = [0u8; 32]; // placeholder — host computes
                hostcalls::provide(&hash, &send.payload);
                // Transfer with memo = raw payload for now
                hostcalls::transfer(send.target, 0, 0, &send.payload);
            }

            // Flush spawns
            for code_hash in self.pending_spawns.drain(..) {
                hostcalls::new_service(&code_hash);
            }
        }

        #[cfg(not(feature = "guest"))]
        {
            self.pending_writes.clear();
            self.pending_sends.clear();
            self.pending_spawns.clear();
        }
    }
}
