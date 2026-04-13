//! Registry protocol for VOS services.
//!
//! Defines the wire protocol for a registry service that:
//! - Stores and resolves PVM code blobs by name+version
//! - Maps service names to ServiceIds (address resolution)
//!
//! The registry is itself a VOS service at well-known `ServiceId(0)`.
//! Any service can query it via TRANSFER/INVOKE.
//!
//! ## Protocol tags
//!
//! | Tag | Operation | Payload |
//! |-----|-----------|---------|
//! | 0x01 | Publish blob | `[name][version][blob]` |
//! | 0x02 | Resolve blob | `[name][version]` → code hash |
//! | 0x03 | Register address | `[name][service_id: u32 LE]` |
//! | 0x04 | Resolve address | `[name]` → service_id |

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const TAG_PUBLISH: u8 = 0x01;
pub const TAG_RESOLVE: u8 = 0x02;
pub const TAG_REGISTER_ADDR: u8 = 0x03;
pub const TAG_RESOLVE_ADDR: u8 = 0x04;

/// A package identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageId {
    pub name: String,
    pub version: String,
}

/// A registry request.
#[derive(Debug, Clone)]
pub enum RegistryRequest {
    /// Publish a code blob under the given name and version.
    Publish { id: PackageId, blob: Vec<u8> },
    /// Resolve a package to its code hash.
    Resolve { id: PackageId },
}

/// A registry response.
#[derive(Debug, Clone)]
pub enum RegistryResponse {
    /// The code hash for the requested package.
    Found { hash: [u8; 32] },
    /// Package not found.
    NotFound,
}

impl RegistryRequest {
    /// Encode a request to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Publish { id, blob } => {
                out.push(TAG_PUBLISH);
                push_str(&mut out, &id.name);
                push_str(&mut out, &id.version);
                out.extend_from_slice(blob);
            }
            Self::Resolve { id } => {
                out.push(TAG_RESOLVE);
                push_str(&mut out, &id.name);
                push_str(&mut out, &id.version);
            }
        }
        out
    }

    /// Decode a request from the wire format.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let mut pos = 1;
        let tag = bytes[0];
        match tag {
            TAG_PUBLISH => {
                let name = read_str(bytes, &mut pos)?;
                let version = read_str(bytes, &mut pos)?;
                let blob = bytes.get(pos..)?.to_vec();
                Some(Self::Publish {
                    id: PackageId { name, version },
                    blob,
                })
            }
            TAG_RESOLVE => {
                let name = read_str(bytes, &mut pos)?;
                let version = read_str(bytes, &mut pos)?;
                Some(Self::Resolve {
                    id: PackageId { name, version },
                })
            }
            _ => None,
        }
    }
}

impl RegistryResponse {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Found { hash } => {
                let mut out = Vec::with_capacity(33);
                out.push(0x01);
                out.extend_from_slice(hash);
                out
            }
            Self::NotFound => vec![0x00],
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        match bytes[0] {
            0x01 if bytes.len() >= 33 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[1..33]);
                Some(Self::Found { hash })
            }
            0x00 => Some(Self::NotFound),
            _ => None,
        }
    }
}

// ── Address resolution ────────────────────────────────────────────────

/// An address resolution request.
#[derive(Debug, Clone)]
pub enum AddrRequest {
    /// Register a name → ServiceId mapping.
    Register { name: String, service_id: u32 },
    /// Resolve a name to its ServiceId.
    Resolve { name: String },
}

/// An address resolution response.
#[derive(Debug, Clone)]
pub enum AddrResponse {
    Found(u32),
    NotFound,
}

impl AddrRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Register { name, service_id } => {
                out.push(TAG_REGISTER_ADDR);
                push_str(&mut out, name);
                out.extend_from_slice(&service_id.to_le_bytes());
            }
            Self::Resolve { name } => {
                out.push(TAG_RESOLVE_ADDR);
                push_str(&mut out, name);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() { return None; }
        let mut pos = 1;
        match bytes[0] {
            TAG_REGISTER_ADDR => {
                let name = read_str(bytes, &mut pos)?;
                if pos + 4 > bytes.len() { return None; }
                let service_id = u32::from_le_bytes([
                    bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
                ]);
                Some(Self::Register { name, service_id })
            }
            TAG_RESOLVE_ADDR => {
                let name = read_str(bytes, &mut pos)?;
                Some(Self::Resolve { name })
            }
            _ => None,
        }
    }
}

impl AddrResponse {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Found(id) => {
                let mut out = Vec::with_capacity(5);
                out.push(0x01);
                out.extend_from_slice(&id.to_le_bytes());
                out
            }
            Self::NotFound => vec![0x00],
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() { return None; }
        match bytes[0] {
            0x01 if bytes.len() >= 5 => {
                let id = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                Some(Self::Found(id))
            }
            0x00 => Some(Self::NotFound),
            _ => None,
        }
    }
}

// --- Wire helpers ---

fn push_str(out: &mut Vec<u8>, s: &str) {
    let len = s.len() as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 2 > bytes.len() {
        return None;
    }
    let len = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > bytes.len() {
        return None;
    }
    let s = core::str::from_utf8(&bytes[*pos..*pos + len]).ok()?;
    *pos += len;
    Some(String::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_publish() {
        let req = RegistryRequest::Publish {
            id: PackageId {
                name: String::from("greeter"),
                version: String::from("0.1.0"),
            },
            blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = req.encode();
        let decoded = RegistryRequest::decode(&encoded).unwrap();
        match decoded {
            RegistryRequest::Publish { id, blob } => {
                assert_eq!(id.name, "greeter");
                assert_eq!(id.version, "0.1.0");
                assert_eq!(blob, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn request_roundtrip_resolve() {
        let req = RegistryRequest::Resolve {
            id: PackageId {
                name: String::from("counter"),
                version: String::from("1.0.0"),
            },
        };
        let encoded = req.encode();
        let decoded = RegistryRequest::decode(&encoded).unwrap();
        match decoded {
            RegistryRequest::Resolve { id } => {
                assert_eq!(id.name, "counter");
                assert_eq!(id.version, "1.0.0");
            }
            _ => panic!("expected Resolve"),
        }
    }

    #[test]
    fn addr_register_roundtrip() {
        let req = AddrRequest::Register {
            name: String::from("greeter"),
            service_id: 0x00A3_0005,
        };
        let encoded = req.encode();
        match AddrRequest::decode(&encoded).unwrap() {
            AddrRequest::Register { name, service_id } => {
                assert_eq!(name, "greeter");
                assert_eq!(service_id, 0x00A3_0005);
            }
            _ => panic!("expected Register"),
        }
    }

    #[test]
    fn addr_resolve_roundtrip() {
        let req = AddrRequest::Resolve { name: String::from("counter") };
        let encoded = req.encode();
        match AddrRequest::decode(&encoded).unwrap() {
            AddrRequest::Resolve { name } => assert_eq!(name, "counter"),
            _ => panic!("expected Resolve"),
        }
    }

    #[test]
    fn addr_response_roundtrip() {
        let found = AddrResponse::Found(0x00A3_0005);
        let enc = found.encode();
        match AddrResponse::decode(&enc).unwrap() {
            AddrResponse::Found(id) => assert_eq!(id, 0x00A3_0005),
            _ => panic!("expected Found"),
        }

        let not_found = AddrResponse::NotFound;
        let enc = not_found.encode();
        assert!(matches!(AddrResponse::decode(&enc).unwrap(), AddrResponse::NotFound));
    }

    #[test]
    fn response_roundtrip() {
        let found = RegistryResponse::Found { hash: [0x42; 32] };
        let enc = found.encode();
        match RegistryResponse::decode(&enc).unwrap() {
            RegistryResponse::Found { hash } => assert_eq!(hash, [0x42; 32]),
            _ => panic!("expected Found"),
        }

        let not_found = RegistryResponse::NotFound;
        let enc = not_found.encode();
        assert!(matches!(
            RegistryResponse::decode(&enc).unwrap(),
            RegistryResponse::NotFound
        ));
    }
}
