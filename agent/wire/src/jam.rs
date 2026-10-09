//! Gray Paper 0.8.0 structures the agent exchanges with a JAM node, in the
//! Gray Paper's encoding (naturals are variable length, appendix C).

use alloc::vec::Vec;

use vos_pvm_program::{encode_nat, read_nat};

/// Refine's arguments, `E(c, i, s, ↕payload, H(p))`: core index, work item
/// index, service id, the work item's payload and the work package hash.
/// Spike SJ confirmed this layout on PolkaJam 0.1.29.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefineArgs {
    pub core: u64,
    pub item: u64,
    pub service: u64,
    pub payload: Vec<u8>,
    pub package_hash: [u8; 32],
}

impl RefineArgs {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_nat(self.core, &mut bytes);
        encode_nat(self.item, &mut bytes);
        encode_nat(self.service, &mut bytes);
        encode_nat(self.payload.len() as u64, &mut bytes);
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.package_hash);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (core, at) = read_nat(bytes, 0)?;
        let (item, used) = read_nat(bytes, at)?;
        let at = at + used;
        let (service, used) = read_nat(bytes, at)?;
        let at = at + used;
        let (len, used) = read_nat(bytes, at)?;
        let at = at + used;
        let end = at.checked_add(usize::try_from(len).ok()?)?;
        let payload = bytes.get(at..end)?.to_vec();
        let package_hash = bytes.get(end..end + 32)?.try_into().ok()?;
        (bytes.len() == end + 32).then_some(Self {
            core,
            item,
            service,
            payload,
            package_hash,
        })
    }
}

/// Why a work item produced no output. `OutOfGas` (1) was captured from
/// PolkaJam; the others follow the Gray Paper's numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkError {
    OutOfGas = 1,
    Panic = 2,
    BadExports = 3,
    Oversize = 4,
    Bad = 5,
    Big = 6,
}

/// One accumulate input, fetched with its kind byte: a work item's operand
/// or a deferred transfer. Both layouts were captured from PolkaJam 0.1.29
/// (Gray Paper 0.8.0) and are pinned by fixture tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccumulateInput {
    Operand(Operand),
    Transfer(Transfer),
}

impl AccumulateInput {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Operand(operand) => {
                bytes.push(0);
                operand.encode_to(&mut bytes);
            }
            Self::Transfer(transfer) => {
                bytes.push(1);
                transfer.encode_to(&mut bytes);
            }
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        match kind {
            0 => Operand::decode(rest).map(Self::Operand),
            1 => Transfer::decode(rest).map(Self::Transfer),
            _ => None,
        }
    }
}

/// What refine produced for one work item, with its context,
/// `E(p, e, a, y, g, O(result), ↕trace)`: the gas limit is a natural, the
/// hashes are 32 bytes each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub package_hash: [u8; 32],
    pub segment_root: [u8; 32],
    pub authorizer: [u8; 32],
    pub payload_hash: [u8; 32],
    pub gas_limit: u64,
    pub result: Result<Vec<u8>, WorkError>,
    pub auth_trace: Vec<u8>,
}

impl Operand {
    fn encode_to(&self, bytes: &mut Vec<u8>) {
        for hash in [
            &self.package_hash,
            &self.segment_root,
            &self.authorizer,
            &self.payload_hash,
        ] {
            bytes.extend_from_slice(hash);
        }
        encode_nat(self.gas_limit, bytes);
        match &self.result {
            Ok(output) => {
                bytes.push(0);
                encode_nat(output.len() as u64, bytes);
                bytes.extend_from_slice(output);
            }
            Err(error) => bytes.push(*error as u8),
        }
        encode_nat(self.auth_trace.len() as u64, bytes);
        bytes.extend_from_slice(&self.auth_trace);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let hash = |at: usize| -> Option<[u8; 32]> { bytes.get(at..at + 32)?.try_into().ok() };
        let package_hash = hash(0)?;
        let segment_root = hash(32)?;
        let authorizer = hash(64)?;
        let payload_hash = hash(96)?;
        let (gas_limit, used) = read_nat(bytes, 128)?;
        let mut at = 128 + used;
        let tag = *bytes.get(at)?;
        at += 1;
        let result = match tag {
            0 => {
                let (len, used) = read_nat(bytes, at)?;
                at += used;
                let end = at.checked_add(usize::try_from(len).ok()?)?;
                let output = bytes.get(at..end)?.to_vec();
                at = end;
                Ok(output)
            }
            1 => Err(WorkError::OutOfGas),
            2 => Err(WorkError::Panic),
            3 => Err(WorkError::BadExports),
            4 => Err(WorkError::Oversize),
            5 => Err(WorkError::Bad),
            6 => Err(WorkError::Big),
            _ => return None,
        };
        let (len, used) = read_nat(bytes, at)?;
        at += used;
        let end = at.checked_add(usize::try_from(len).ok()?)?;
        let auth_trace = bytes.get(at..end)?.to_vec();
        (bytes.len() == end).then_some(Self {
            package_hash,
            segment_root,
            authorizer,
            payload_hash,
            gas_limit,
            result,
            auth_trace,
        })
    }
}

/// A deferred transfer, `E4(s) ∥ E4(d) ∥ E8(a) ∥ m ∥ E8(g)`: fixed-width
/// little-endian fields and a 128-byte memo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub source: u32,
    pub destination: u32,
    pub amount: u64,
    pub memo: [u8; 128],
    pub gas: u64,
}

impl Transfer {
    const LEN: usize = 4 + 4 + 8 + 128 + 8;

    fn encode_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.source.to_le_bytes());
        bytes.extend_from_slice(&self.destination.to_le_bytes());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.memo);
        bytes.extend_from_slice(&self.gas.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN {
            return None;
        }
        Some(Self {
            source: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            destination: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            amount: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            memo: bytes[16..144].try_into().ok()?,
            gas: u64::from_le_bytes(bytes[144..152].try_into().ok()?),
        })
    }
}
