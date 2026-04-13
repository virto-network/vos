//! JAM-aligned work-item operands and digests.
//!
//! This module mirrors the on-chain `WorkResult` / `WorkDigest` /
//! `encode_operand` shapes from `grey-state` so that anything VOS hands to
//! a service's accumulate stage is byte-identical to what an on-chain
//! validator would hand it. Most JAM-only header fields (package_hash,
//! exports_root, authorizer_hash, auth_output) are zero off-chain, but
//! the *layout* matches — services parsing operands cannot tell whether
//! they were built by vosx or by a JAM core.
//!
//! Reference: GP §C.5 (work result encoding) and `grey-state`
//! `accumulate.rs::encode_operand`.

use crate::abi::service::ServiceId;

/// Outcome of a single refine PVM invocation, mirroring grey's
/// `WorkResult` discriminated union.
///
/// Tag values are wire-stable: they are written into operand bytes and
/// read back by accumulate code. Do not renumber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkResult {
    /// Refine halted normally with output bytes (registers ω[7]=ptr, ω[8]=len).
    Ok(Vec<u8>),
    /// Refine ran out of gas before halting.
    OutOfGas,
    /// Refine panicked, page-faulted, or hit an illegal instruction.
    Panic,
    /// Refine emitted invalid `export(4)` segments.
    BadExports,
    /// Service code blob was malformed.
    BadCode,
    /// Service code blob exceeded the max size.
    CodeOversize,
}

impl WorkResult {
    /// Wire tag byte (GP §C.5).
    pub fn tag(&self) -> u8 {
        match self {
            WorkResult::Ok(_) => 0,
            WorkResult::OutOfGas => 1,
            WorkResult::Panic => 2,
            WorkResult::BadExports => 3,
            WorkResult::BadCode => 4,
            WorkResult::CodeOversize => 5,
        }
    }
}

/// Per-work-item digest produced by refine, consumed by accumulate.
///
/// Off-chain, most JAM-specific header fields are zero — they exist
/// only so the encoded bytes match the on-chain shape. The fields that
/// actually carry information off-chain are `service_id`, `payload_hash`,
/// `accumulate_gas`, `result`, and `gas_used`.
#[derive(Debug, Clone)]
pub struct WorkDigest {
    pub service_id: ServiceId,
    /// blake2-style hash of the refine input bytes. Off-chain we use a
    /// simple deterministic hash (see `payload_hash` helper) so the field
    /// is observable but not cryptographically meaningful until we bridge.
    pub payload_hash: [u8; 32],
    /// Gas budget the resulting operand carries into accumulate. Set by
    /// the caller of refine; defaults from `GasConfig` off-chain.
    pub accumulate_gas: u64,
    pub result: WorkResult,
    /// Gas consumed by the refine PVM. Observable to accumulate.
    pub gas_used: u64,

    // ── JAM-shape header fields, zero off-chain ─────────────────────
    pub code_hash: [u8; 32],
    pub imports_count: u16,
    pub extrinsics_count: u16,
    pub extrinsics_size: u32,
    pub exports_count: u16,
}

impl WorkDigest {
    /// Build a digest for an off-chain refine invocation. JAM header
    /// fields are zeroed.
    pub fn off_chain(
        service_id: ServiceId,
        payload_hash: [u8; 32],
        accumulate_gas: u64,
        result: WorkResult,
        gas_used: u64,
    ) -> Self {
        Self {
            service_id,
            payload_hash,
            accumulate_gas,
            result,
            gas_used,
            code_hash: [0u8; 32],
            imports_count: 0,
            extrinsics_count: 0,
            extrinsics_size: 0,
            exports_count: 0,
        }
    }
}

/// Header bytes shared across all operands in a single work report:
/// package_hash, exports_root, authorizer_hash, auth_output. Off-chain
/// these are all zero / empty, but kept as a struct so a future on-chain
/// bridge can populate them without changing call sites.
#[derive(Debug, Clone, Default)]
pub struct OperandHeader {
    pub package_hash: [u8; 32],
    pub exports_root: [u8; 32],
    pub authorizer_hash: [u8; 32],
    pub auth_output: Vec<u8>,
}

/// Encode a single operand exactly as `grey-state::encode_operand`:
///
/// `package_hash || exports_root || authorizer_hash || payload_hash`
/// `|| accumulate_gas (LE u64) || result_tag [|| len:u32 || data]`
/// `|| auth_output_len:u32 || auth_output`
pub fn encode_operand(header: &OperandHeader, digest: &WorkDigest) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&header.package_hash);
    buf.extend_from_slice(&header.exports_root);
    buf.extend_from_slice(&header.authorizer_hash);
    buf.extend_from_slice(&digest.payload_hash);
    buf.extend_from_slice(&digest.accumulate_gas.to_le_bytes());
    buf.push(digest.result.tag());
    if let WorkResult::Ok(data) = &digest.result {
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf.extend_from_slice(&(header.auth_output.len() as u32).to_le_bytes());
    buf.extend_from_slice(&header.auth_output);
    buf
}

/// Item blob discriminator bytes (GP §C.33).
pub const ITEM_TAG_OPERAND: u8 = 0x00;
pub const ITEM_TAG_TRANSFER: u8 = 0x01;

/// Wrap an encoded operand with the item discriminator.
pub fn item_operand(operand_bytes: Vec<u8>) -> Vec<u8> {
    let mut item = Vec::with_capacity(1 + operand_bytes.len());
    item.push(ITEM_TAG_OPERAND);
    item.extend_from_slice(&operand_bytes);
    item
}

/// Encode a deferred transfer item (GP eq C.31). Off-chain VOS doesn't
/// have an authorizer or amounts, so sender is the originating service,
/// destination is the target, amount is zero, gas_limit defaults to the
/// runtime's default refine gas, and the memo is the transfer payload
/// padded to 128 bytes.
pub fn item_transfer(
    sender: ServiceId,
    destination: ServiceId,
    memo: &[u8],
    gas_limit: u64,
) -> Vec<u8> {
    let mut item = Vec::with_capacity(1 + 4 + 4 + 8 + 128 + 8);
    item.push(ITEM_TAG_TRANSFER);
    item.extend_from_slice(&sender.0.to_le_bytes());
    item.extend_from_slice(&destination.0.to_le_bytes());
    item.extend_from_slice(&0u64.to_le_bytes()); // amount = 0 (coinless)
    let mut memo_buf = [0u8; 128];
    let copy_len = memo.len().min(128);
    memo_buf[..copy_len].copy_from_slice(&memo[..copy_len]);
    item.extend_from_slice(&memo_buf);
    item.extend_from_slice(&gas_limit.to_le_bytes());
    item
}

/// Compute a deterministic 32-byte payload hash for refine inputs.
///
/// Off-chain we use a simple folding hash (not cryptographically secure)
/// so refine inputs are observable as digest fields without pulling in
/// blake2. When we bridge on-chain, swap this for the real hash function.
pub fn payload_hash(input: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &byte) in input.iter().enumerate() {
        h[i % 32] ^= byte.wrapping_add((i as u8).wrapping_mul(31));
    }
    // Mix the length in so empty/single-byte inputs don't all collide.
    let len_bytes = (input.len() as u64).to_le_bytes();
    for i in 0..8 {
        h[i] ^= len_bytes[i];
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workresult_tags_are_stable() {
        assert_eq!(WorkResult::Ok(vec![]).tag(), 0);
        assert_eq!(WorkResult::OutOfGas.tag(), 1);
        assert_eq!(WorkResult::Panic.tag(), 2);
        assert_eq!(WorkResult::BadExports.tag(), 3);
        assert_eq!(WorkResult::BadCode.tag(), 4);
        assert_eq!(WorkResult::CodeOversize.tag(), 5);
    }

    #[test]
    fn encode_ok_operand_layout() {
        let header = OperandHeader::default();
        let digest = WorkDigest::off_chain(
            ServiceId(7),
            [0u8; 32],
            12345,
            WorkResult::Ok(vec![0xAA, 0xBB, 0xCC]),
            999,
        );
        let bytes = encode_operand(&header, &digest);

        // 32 (package) + 32 (exports) + 32 (auth) + 32 (payload) = 128
        // + 8 (accumulate_gas) = 136
        // + 1 (result tag) = 137
        // + 4 (data len) + 3 (data) = 144
        // + 4 (auth_output len) + 0 (auth_output) = 148
        assert_eq!(bytes.len(), 148);

        // accumulate_gas at offset 128
        assert_eq!(&bytes[128..136], &12345u64.to_le_bytes());
        // result tag at offset 136
        assert_eq!(bytes[136], 0);
        // data length at offset 137
        assert_eq!(&bytes[137..141], &3u32.to_le_bytes());
        // data
        assert_eq!(&bytes[141..144], &[0xAA, 0xBB, 0xCC]);
        // auth_output length
        assert_eq!(&bytes[144..148], &0u32.to_le_bytes());
    }

    #[test]
    fn encode_error_operands_have_no_data_field() {
        let header = OperandHeader::default();
        let digest = WorkDigest::off_chain(
            ServiceId(1),
            [0u8; 32],
            0,
            WorkResult::OutOfGas,
            0,
        );
        let bytes = encode_operand(&header, &digest);
        // 128 + 8 + 1 + 4 = 141 (no data length, no data)
        assert_eq!(bytes.len(), 141);
        assert_eq!(bytes[136], 1); // OutOfGas tag
    }

    #[test]
    fn item_transfer_layout() {
        let item = item_transfer(ServiceId(1), ServiceId(2), b"hello", 50_000);
        // 1 (tag) + 4 (sender) + 4 (dest) + 8 (amount) + 128 (memo) + 8 (gas) = 153
        assert_eq!(item.len(), 153);
        assert_eq!(item[0], ITEM_TAG_TRANSFER);
        assert_eq!(&item[1..5], &1u32.to_le_bytes());
        assert_eq!(&item[5..9], &2u32.to_le_bytes());
        assert_eq!(&item[9..17], &0u64.to_le_bytes());
        assert_eq!(&item[17..22], b"hello");
        // remaining memo bytes are zero
        assert!(item[22..145].iter().all(|&b| b == 0));
        assert_eq!(&item[145..153], &50_000u64.to_le_bytes());
    }

    #[test]
    fn payload_hash_distinguishes_inputs() {
        assert_ne!(payload_hash(b""), payload_hash(b"a"));
        assert_ne!(payload_hash(b"a"), payload_hash(b"b"));
        assert_ne!(payload_hash(b"abc"), payload_hash(b"abcd"));
        // determinism
        assert_eq!(payload_hash(b"hello"), payload_hash(b"hello"));
    }
}
