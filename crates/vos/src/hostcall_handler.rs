//! Hostcall handler — processes JAR-aligned hostcalls from guest services.
//!
//! Replaces the old SyscallHandler+VFS. Uses per-service KV storage
//! and a preimage store instead of file descriptors.

use vos_abi::error;
use vos_abi::hostcall::{self, accumulate};
use vos_abi::service::ServiceId;

/// Result of dispatching a hostcall.
pub enum HostcallResult {
    /// Hostcall handled, return this value to the caller.
    Value(u64),
    /// Transfer hostcall — runtime should route to target service.
    Transfer {
        target: ServiceId,
        amount: u64,
        gas_limit: u64,
        memo_ptr: u64,
        memo_len: u64,
    },
}

/// Trait for accessing a guest service's memory.
pub trait MemoryAccess {
    fn read_guest(&self, service: ServiceId, ptr: u64, dst: &mut [u8]) -> usize;
    fn write_guest(&mut self, service: ServiceId, ptr: u64, src: &[u8]) -> usize;
}

/// Handles hostcalls from guest services.
///
/// Manages per-service KV storage and a shared preimage store.
pub struct HostcallHandler {
    pub storage: ServiceStorage,
    pub preimages: PreimageStore,
}

/// Per-service key-value storage.
#[cfg(feature = "std")]
pub struct ServiceStorage {
    data: std::collections::HashMap<(u32, Vec<u8>), Vec<u8>>,
}

#[cfg(not(feature = "std"))]
pub struct ServiceStorage;

/// Preimage store: hash → data.
#[cfg(feature = "std")]
pub struct PreimageStore {
    data: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

#[cfg(not(feature = "std"))]
pub struct PreimageStore;

impl Default for HostcallHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl HostcallHandler {
    pub fn new() -> Self {
        Self {
            storage: ServiceStorage::new(),
            preimages: PreimageStore::new(),
        }
    }

    /// Dispatch a hostcall. Returns either a direct value or a
    /// transfer action for the runtime to route.
    pub fn dispatch(
        &mut self,
        caller: ServiceId,
        call_id: u32,
        args: &HostcallArgs,
    ) -> HostcallResult {
        match call_id {
            hostcall::GAS => HostcallResult::Value(args.a0), // placeholder: return remaining gas
            hostcall::GROW_HEAP => HostcallResult::Value(error::HOST_OK),
            accumulate::INFO => HostcallResult::Value(caller.0 as u64),
            accumulate::CHECKPOINT => HostcallResult::Value(error::HOST_OK),
            accumulate::YIELD => HostcallResult::Value(error::HOST_OK),

            accumulate::READ => {
                // args: a0=key_ptr, a1=key_len, a2=val_buf_ptr, a3=val_buf_len
                // Actual read requires memory access — handled at driver level
                HostcallResult::Value(error::HOST_NONE)
            }
            accumulate::WRITE => {
                // args: a0=key_ptr, a1=key_len, a2=val_ptr, a3=val_len
                // Actual write requires memory access — handled at driver level
                HostcallResult::Value(error::HOST_OK)
            }
            hostcall::FETCH => {
                // args: a0=hash_ptr/buf_ptr, a1=buf_ptr/buf_len (depends on mode)
                HostcallResult::Value(error::HOST_NONE)
            }
            accumulate::PROVIDE => {
                // args: a0=hash_ptr, a1=data_ptr, a2=data_len
                HostcallResult::Value(error::HOST_OK)
            }
            accumulate::TRANSFER => {
                HostcallResult::Transfer {
                    target: ServiceId(args.a0 as u32),
                    amount: args.a1,
                    gas_limit: args.a2,
                    memo_ptr: args.a3,
                    memo_len: args.a4,
                }
            }
            accumulate::NEW => {
                // args: a0=code_hash_ptr
                HostcallResult::Value(error::HOST_OK)
            }

            hostcall::DEBUG_WRITE => {
                // Handled at driver level (prints to host stderr)
                HostcallResult::Value(error::HOST_OK)
            }

            _ => HostcallResult::Value(error::HOST_WHAT),
        }
    }
}

#[cfg(feature = "std")]
impl ServiceStorage {
    pub fn new() -> Self {
        Self {
            data: std::collections::HashMap::new(),
        }
    }

    pub fn read(&self, service: ServiceId, key: &[u8]) -> Option<&[u8]> {
        self.data.get(&(service.0, key.to_vec())).map(|v| v.as_slice())
    }

    pub fn write(&mut self, service: ServiceId, key: &[u8], value: &[u8]) {
        self.data.insert((service.0, key.to_vec()), value.to_vec());
    }
}

#[cfg(not(feature = "std"))]
impl ServiceStorage {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "std")]
impl PreimageStore {
    pub fn new() -> Self {
        Self {
            data: std::collections::HashMap::new(),
        }
    }

    pub fn store(&mut self, hash: [u8; 32], data: Vec<u8>) {
        self.data.insert(hash, data);
    }

    pub fn fetch(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.data.get(hash).map(|v| v.as_slice())
    }
}

#[cfg(not(feature = "std"))]
impl PreimageStore {
    pub fn new() -> Self {
        Self
    }
}

/// Raw hostcall arguments. Up to 6 register-sized values.
#[derive(Debug, Default)]
pub struct HostcallArgs {
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
}
