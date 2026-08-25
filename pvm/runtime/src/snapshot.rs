//! Portable invocation-kernel snapshots.
//!
//! Snapshots contain only consensus-visible machine state. Native code,
//! virtual-memory windows, and other backend caches are reconstructed from the
//! canonical program blob during restore.

use alloc::vec::Vec;

/// Current portable kernel snapshot wire version.
pub const KERNEL_SNAPSHOT_VERSION: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum SnapshotIsaMode {
    Jar,
    Conformance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum SnapshotVmState {
    Idle,
    Running,
    WaitingForReply,
    Halted,
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum SnapshotAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum CapabilitySnapshot {
    Untyped,
    Data {
        backing_offset: u32,
        page_count: u32,
        base_offset: Option<u32>,
        access: Option<SnapshotAccess>,
        mapped_bitmap: Vec<u8>,
    },
    Code {
        code_cap_id: u16,
    },
    Handle {
        vm_index: u16,
        vm_generation: u16,
        max_gas: Option<u64>,
    },
    Callable {
        vm_index: u16,
        vm_generation: u16,
        max_gas: Option<u64>,
    },
    Protocol {
        id: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct CapabilitySlotSnapshot {
    pub slot: u8,
    pub original: bool,
    pub capability: CapabilitySnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct VmSnapshot {
    pub state: SnapshotVmState,
    pub code_cap_id: u16,
    pub registers: Vec<u64>,
    pub entry_registers: Vec<u64>,
    pub pc: u32,
    pub capabilities: Vec<CapabilitySlotSnapshot>,
    pub caller: Option<u16>,
    pub entry_index: u32,
    pub gas: u64,
    pub heap_base: u32,
    pub heap_top: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct VmSlotSnapshot {
    pub generation: u16,
    pub vm: Option<VmSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct VmArenaSnapshot {
    pub slots: Vec<VmSlotSnapshot>,
    /// Exact LIFO allocation order for vacant generational slots.
    pub free_list: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct CallFrameSnapshot {
    pub caller_vm_id: u16,
    pub ipc_cap_idx: Option<u8>,
    pub ipc_base_page: Option<u32>,
    pub ipc_access: Option<SnapshotAccess>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct PendingProtocolCall {
    pub slot: u8,
    pub vm_index: u16,
    /// PC immediately after the protocol-call instruction.
    pub resume_pc: u32,
    pub result_registers: [u8; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct MemoryPageRef {
    pub page_index: u32,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct MemoryBlock {
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
pub struct KernelSnapshot {
    pub version: u16,
    /// Blake2b-256 commitment to the canonical root program plus the ordered
    /// dormant-program blobs and the HANDLE slots through which they are
    /// owned. This binds immutable code and static capability layouts to the
    /// continuation without embedding those reconstructible bytes.
    pub invocation_layout_hash: [u8; 32],
    pub isa_mode: SnapshotIsaMode,
    pub memory_pages: u32,
    pub mem_cycles: u8,
    pub next_code_id: u16,
    pub code_hashes: Vec<[u8; 32]>,
    pub untyped_offset: u32,
    pub active_vm: u16,
    pub arena: VmArenaSnapshot,
    pub call_stack: Vec<CallFrameSnapshot>,
    /// Non-zero physical pages mapped to content-addressed blocks.
    pub memory: Vec<MemoryPageRef>,
    /// Deduplicated page contents. Blocks may be stored independently by a
    /// content-addressed continuation store.
    pub blocks: Vec<MemoryBlock>,
    pub pending_call: PendingProtocolCall,
}

impl KernelSnapshot {
    pub fn to_bytes(&self) -> Vec<u8> {
        scale::Encode::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        let (snapshot, consumed) =
            <Self as scale::Decode>::decode(bytes).map_err(|_| SnapshotError::Decode)?;
        if consumed != bytes.len() {
            return Err(SnapshotError::TrailingBytes);
        }
        if snapshot.version != KERNEL_SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(snapshot.version));
        }
        Ok(snapshot)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    #[error("kernel is not suspended at a protocol-call boundary")]
    NotAtProtocolBoundary,
    #[error("unsupported kernel snapshot version {0}")]
    UnsupportedVersion(u16),
    #[error("snapshot decode failed")]
    Decode,
    #[error("snapshot has trailing bytes")]
    TrailingBytes,
    #[error("snapshot does not match the canonical program")]
    ProgramMismatch,
    #[error("snapshot memory is invalid")]
    InvalidMemory,
    #[error("snapshot VM arena is invalid")]
    InvalidArena,
    #[error("snapshot capability state is invalid")]
    InvalidCapability,
    #[error("snapshot scheduler state is invalid")]
    InvalidScheduler,
}
