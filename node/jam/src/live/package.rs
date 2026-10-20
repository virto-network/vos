//! A work package built and submitted by hand, its extrinsics beside it:
//! Gray Paper 0.8.0's encoding, sent through PolkaJam's `submitWorkPackage`
//! (JIP-2), which takes the package and its extrinsics' data apart. `jamt
//! item` attaches no extrinsic; a JAM statements service's `Submit` carries
//! its proof as one, since JAM-NP's CE 133 bounds the package itself at
//! 204,802 bytes and extrinsics travel beside it, under `W_B` alone.
//!
//! The package is authorized as `jamt` authorizes its own, by PolkaJam's
//! bootstrap service (its auth code host) and its authorizer, with no
//! token and no configuration ([`BOOTSTRAP_AUTHORIZER`]); its context
//! anchors at the finalized block, the lookup anchor its parent, as `jamt`
//! anchors its own.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use vos_tree::Hash;
use vos_wire::result::digest;

use super::rpc::decoded;
use super::{PolkaJam, failed};
use crate::Error;

/// The code hash of PolkaJam's bootstrap authorizer, which service 0 hosts:
/// what `jamt` 0.1.29 (PolkaJam v0.8.0) names in every package it builds,
/// read from one it submitted.
pub const BOOTSTRAP_AUTHORIZER: Hash = [
    0xf8, 0xd8, 0x6b, 0x97, 0xd6, 0x53, 0x19, 0xa0, 0x78, 0xe5, 0x84, 0x0f, 0x16, 0x14, 0xc2, 0x96,
    0xa5, 0x25, 0x42, 0x17, 0x79, 0x4d, 0xcc, 0x91, 0x0e, 0x72, 0xca, 0x17, 0x4e, 0x3c, 0x2e, 0x86,
];

/// A work item: its service and that service's code hash, its gas limits,
/// its payload and its extrinsics' data; it imports and exports nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkItem {
    pub service: u32,
    pub code_hash: Hash,
    pub refine_gas: u64,
    pub accumulate_gas: u64,
    pub payload: Vec<u8>,
    pub extrinsics: Vec<Vec<u8>>,
}

/// A block the context names: its header's hash, its slot and its
/// posterior state root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub hash: Hash,
    pub slot: u32,
    pub state_root: Hash,
}

/// A work package's refinement context: its anchor, with the anchor's
/// accumulation-output root, and its lookup anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub anchor: Block,
    pub beefy_root: Hash,
    pub lookup: Block,
}

/// A work package of `items`, authorized by PolkaJam's bootstrap
/// authorizer, in Gray Paper 0.8.0's encoding: `E4(auth host) ‖ auth code
/// hash ‖ context ‖ ↕token ‖ ↕configuration ‖ ↕items`; the context
/// `anchor ‖ E4(slot) ‖ state root ‖ beefy root ‖ lookup anchor ‖ E4(slot)
/// ‖ state root ‖ ↕prerequisites`; an item `E4(service) ‖ code hash ‖
/// E8(refine gas) ‖ E8(accumulate gas) ‖ E2(exports) ‖ ↕payload ‖ ↕imports
/// ‖ ↕(extrinsic hash, E4(length))`.
pub fn encode_package(context: &Context, items: &[WorkItem]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&BOOTSTRAP_AUTHORIZER);
    for (block, beefy) in [
        (&context.anchor, Some(&context.beefy_root)),
        (&context.lookup, None),
    ] {
        out.extend_from_slice(&block.hash);
        out.extend_from_slice(&block.slot.to_le_bytes());
        out.extend_from_slice(&block.state_root);
        if let Some(beefy) = beefy {
            out.extend_from_slice(beefy);
        }
    }
    // No prerequisites, no token, no configuration.
    out.extend_from_slice(&[0, 0, 0]);
    vos_pvm_program::encode_nat(items.len() as u64, &mut out);
    for item in items {
        out.extend_from_slice(&item.service.to_le_bytes());
        out.extend_from_slice(&item.code_hash);
        out.extend_from_slice(&item.refine_gas.to_le_bytes());
        out.extend_from_slice(&item.accumulate_gas.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        vos_pvm_program::encode_nat(item.payload.len() as u64, &mut out);
        out.extend_from_slice(&item.payload);
        out.push(0);
        vos_pvm_program::encode_nat(item.extrinsics.len() as u64, &mut out);
        for extrinsic in &item.extrinsics {
            out.extend_from_slice(&digest(extrinsic));
            out.extend_from_slice(&(extrinsic.len() as u32).to_le_bytes());
        }
    }
    out
}

/// A header's hash as the RPC gives it, base64.
fn header(value: &serde_json::Value) -> Result<(String, Hash), Error> {
    let text = value
        .as_str()
        .ok_or_else(|| failed("a header hash that is not a string"))?;
    let hash = decoded(value)?
        .and_then(|bytes| Hash::try_from(bytes).ok())
        .ok_or_else(|| failed("a header hash of another length"))?;
    Ok((text.to_string(), hash))
}

/// A block as the RPC names one: its header's hash (base64, and its bytes)
/// and its slot.
fn named(answer: &serde_json::Value) -> Result<(String, Hash, u32), Error> {
    let (text, hash) = header(&answer["header_hash"])?;
    let slot = answer["slot"]
        .as_u64()
        .and_then(|slot| u32::try_from(slot).ok())
        .ok_or_else(|| failed("a block without a slot"))?;
    Ok((text, hash, slot))
}

impl PolkaJam {
    /// The parent of block `head` (base64): its hash and slot.
    pub fn parent(&self, head: &str) -> Result<(String, Hash, u32), Error> {
        named(&self.call("parent", json!([head]))?)
    }

    /// A hash-valued call at block `head`.
    fn root(&self, method: &str, head: &str) -> Result<Hash, Error> {
        header(&self.call(method, json!([head]))?).map(|(_, hash)| hash)
    }

    /// The chain's genesis block's hash: the finalized block's ancestor at
    /// slot 0.
    pub fn genesis(&self) -> Result<Hash, Error> {
        let (mut head, mut hash, mut slot) = named(&self.call("finalizedBlock", json!([]))?)?;
        while slot != 0 {
            (head, hash, slot) = self.parent(&head)?;
        }
        Ok(hash)
    }

    /// A context anchored at the finalized block, its parent the lookup
    /// anchor, as `jamt` anchors its packages.
    pub fn context(&self) -> Result<Context, Error> {
        let (head, hash, slot) = named(&self.call("finalizedBlock", json!([]))?)?;
        let (parent, parent_hash, parent_slot) = self.parent(&head)?;
        Ok(Context {
            anchor: Block {
                hash,
                slot,
                state_root: self.root("stateRoot", &head)?,
            },
            beefy_root: self.root("beefyRoot", &head)?,
            lookup: Block {
                hash: parent_hash,
                slot: parent_slot,
                state_root: self.root("stateRoot", &parent)?,
            },
        })
    }

    /// The code hash of `service` at the finalized block: the first field
    /// of its account's encoding, past its version byte.
    pub fn code_hash(&self, service: u64) -> Result<Hash, Error> {
        let (head, _) = self.finalized()?;
        let data = decoded(&self.call("serviceData", json!([head, service]))?)?
            .ok_or_else(|| failed(format!("no service {service}")))?;
        data.get(1..33)
            .and_then(|hash| Hash::try_from(hash).ok())
            .ok_or_else(|| failed("a service account cut short"))
    }

    /// Submit a package of `items` to the guarantors of `core`, anchored at
    /// the finalized block, with every item's extrinsics: the package's
    /// encoding.
    pub fn submit_package(&self, core: u16, items: &[WorkItem]) -> Result<Vec<u8>, Error> {
        let package = encode_package(&self.context()?, items);
        let extrinsics: Vec<String> = items
            .iter()
            .flat_map(|item| &item.extrinsics)
            .map(|extrinsic| STANDARD.encode(extrinsic))
            .collect();
        self.call(
            "submitWorkPackage",
            json!([core, STANDARD.encode(&package), extrinsics]),
        )?;
        Ok(package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The package `jamt` 0.1.29 submitted for a 1,000-byte payload to
    /// service 0, encoded again from its fields: byte for byte, 266 bytes
    /// past its payload; and the extrinsics named after the payload.
    #[test]
    fn a_package_encodes_as_jamts() {
        let hash = |text: &str| -> Hash { hex::decode(text).unwrap().try_into().unwrap() };
        let context = Context {
            anchor: Block {
                hash: hash("e68d25d23fb4b603650232389b0477e82eb49aa30a177a98ec47f8345cf06304"),
                slot: 9_455_011,
                state_root: hash(
                    "e749a3b5b9abf46a614ee765ac57740b0fb0bd816299d485f35163660d1c1424",
                ),
            },
            beefy_root: hash("ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"),
            lookup: Block {
                hash: hash("e0e8fdb0daae02297f29659339913d393d3813b54c6d758fead5263e23078557"),
                slot: 9_455_010,
                state_root: hash(
                    "32926a1b4ccd8b35610313e1c64114a9b7ed32da3917314810578788c705dbc0",
                ),
            },
        };
        let item = WorkItem {
            service: 0,
            code_hash: hash("dd0eb77dee6704574f0877d35c8542a4e8eb7dc705c22cae58f241b25b39d718"),
            refine_gas: 1_000_000_000,
            accumulate_gas: 10_000_000,
            payload: vec![0xab; 1000],
            extrinsics: Vec::new(),
        };
        let package = encode_package(&context, std::slice::from_ref(&item));
        assert_eq!(package.len(), 1266);
        // The bytes before its payload, as jamt sent them.
        let head = concat!(
            "00000000f8d86b97d65319a078e5840f1614c296a5254217794dcc910e72ca174e3c2e86e68d25d2",
            "3fb4b603650232389b0477e82eb49aa30a177a98ec47f8345cf06304a3459000e749a3b5b9abf46a",
            "614ee765ac57740b0fb0bd816299d485f35163660d1c1424ad3228b676f7d3cd4284a5443f17f196",
            "2b36e491b30a40b2405849e597ba5fb5e0e8fdb0daae02297f29659339913d393d3813b54c6d758f",
            "ead5263e23078557a245900032926a1b4ccd8b35610313e1c64114a9b7ed32da3917314810578788",
            "c705dbc00000000100000000dd0eb77dee6704574f0877d35c8542a4e8eb7dc705c22cae58f241b2",
            "5b39d71800ca9a3b000000008096980000000000000083e8",
        );
        assert_eq!(hex::encode(&package[..264]), head);
        assert_eq!(
            &package[package.len() - 1002..package.len() - 2],
            &[0xab; 1000][..]
        );
        assert_eq!(
            &package[package.len() - 2..],
            &[0, 0],
            "no import, no extrinsic"
        );

        // A payload past 16 KiB takes a 3-byte length: the builder's
        // framing bound, its imports' count at 1 byte here, not 3.
        let large = WorkItem {
            payload: vec![0; 200_000],
            ..item.clone()
        };
        let package = encode_package(&context, &[large]);
        assert_eq!(package.len(), 200_000 + crate::builder::PACKAGE_FRAMING - 2);

        let with = WorkItem {
            extrinsics: vec![vec![1, 2, 3]],
            ..item
        };
        let package = encode_package(&context, &[with]);
        assert_eq!(package.len(), 1266 + 36);
        assert_eq!(&package[package.len() - 37..package.len() - 36], &[1]);
        assert_eq!(
            &package[package.len() - 36..package.len() - 4],
            &digest(&[1, 2, 3])
        );
        assert_eq!(&package[package.len() - 4..], &3u32.to_le_bytes());
    }
}
