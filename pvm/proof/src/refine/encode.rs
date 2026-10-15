//! The bytes a refine bundle's commitments hash.

use alloc::vec::Vec;

use super::{RefineHostBoundary, RefineMachineId, RefineSliceExit};

pub(super) fn put_refine_host_boundary(bytes: &mut Vec<u8>, boundary: &RefineHostBoundary) {
    bytes.push(boundary.call);
    put_u32(bytes, boundary.slices_before);
    put_u32(bytes, boundary.slices_after);
    bytes.extend_from_slice(&boundary.state_before);
    bytes.extend_from_slice(&boundary.state_after);
    for &register in &boundary.registers_before {
        put_u64(bytes, register);
    }
    for &register in &boundary.registers_after {
        put_u64(bytes, register);
    }
}

pub(super) fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn put_machine_id(bytes: &mut Vec<u8>, identity: RefineMachineId) {
    match identity {
        RefineMachineId::Outer { program } => {
            bytes.push(0);
            bytes.extend_from_slice(&program.0);
        }
        RefineMachineId::Inner {
            slot,
            generation,
            program,
        } => {
            bytes.push(1);
            put_u32(bytes, slot);
            put_u64(bytes, generation);
            bytes.extend_from_slice(&program.0);
        }
    }
}

pub(super) fn put_exit(bytes: &mut Vec<u8>, exit: RefineSliceExit) {
    match exit {
        RefineSliceExit::Halt => bytes.push(0),
        RefineSliceExit::Panic => bytes.push(1),
        RefineSliceExit::OutOfGas => bytes.push(2),
        RefineSliceExit::PageFault(address) => {
            bytes.push(3);
            put_u32(bytes, address);
        }
        RefineSliceExit::HostCall(call) => {
            bytes.push(4);
            put_u64(bytes, call);
        }
    }
}

pub(super) fn put_segment_state(bytes: &mut Vec<u8>, state: &crate::SegmentState) {
    put_u32(bytes, state.pc);
    put_u64(bytes, state.timestamp);
    for &register in &state.registers {
        put_u64(bytes, register);
    }
    bytes.extend_from_slice(&state.memory_commitment);
    bytes.extend_from_slice(&state.memory_root);
}

#[cfg(not(feature = "poseidon2-channel"))]
pub(super) fn commitment_bytes(commitment: &crate::recursion_pcs::ProverMerkleHash) -> [u8; 32] {
    commitment.0
}

#[cfg(feature = "poseidon2-channel")]
pub(super) fn commitment_bytes(commitment: &crate::recursion_pcs::ProverMerkleHash) -> [u8; 32] {
    commitment.to_bytes()
}
