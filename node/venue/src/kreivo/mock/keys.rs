//! The pallet's raw storage keys (`spaces-pallet.md` §5, §9):
//! `twox128("Spaces") ++ twox128(item) ++` each key part under its pinned
//! hasher, the part SCALE-encoded.

use super::types::{AccountId, Space};
pub use crate::kreivo::calls::keys::{blake2_128, twox64, twox128};
use crate::kreivo::calls::keys::{blake2_128_concat, twox64_concat};

/// The pallet's storage prefix.
pub const PALLET: &[u8] = b"Spaces";

/// The storage items, by their names in the design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    Spaces,
    SovereignOf,
    Authorities,
    AnchorKeys,
    Anchors,
    Last,
    Equivocations,
    Budget,
    Formats,
    Programs,
    Seen,
    Paused,
}

impl Item {
    pub fn name(self) -> &'static str {
        match self {
            Self::Spaces => "Spaces",
            Self::SovereignOf => "SovereignOf",
            Self::Authorities => "Authorities",
            Self::AnchorKeys => "AnchorKeys",
            Self::Anchors => "Anchors",
            Self::Last => "Last",
            Self::Equivocations => "Equivocations",
            Self::Budget => "Budget",
            Self::Formats => "Formats",
            Self::Programs => "Programs",
            Self::Seen => "Seen",
            Self::Paused => "Paused",
        }
    }

    /// `twox128("Spaces") ++ twox128(item)`.
    pub fn prefix(self) -> Vec<u8> {
        [twox128(PALLET), twox128(self.name().as_bytes())].concat()
    }
}

fn key(item: Item, parts: &[&[u8]]) -> Vec<u8> {
    let mut key = item.prefix();
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

pub fn spaces(space: &Space) -> Vec<u8> {
    key(Item::Spaces, &[space])
}

pub fn sovereign_of(account: &AccountId) -> Vec<u8> {
    key(Item::SovereignOf, &[&blake2_128_concat(account)])
}

pub fn authorities(space: &Space, who: &AccountId) -> Vec<u8> {
    key(Item::Authorities, &[space, &blake2_128_concat(who)])
}

pub fn anchor_keys(space: &Space, anchor_key: &[u8; 32]) -> Vec<u8> {
    key(Item::AnchorKeys, &[space, anchor_key])
}

pub fn anchors(space: &Space, kind: u8, window: u64) -> Vec<u8> {
    key(
        Item::Anchors,
        &[
            space,
            &twox64_concat(&[kind]),
            &twox64_concat(&window.to_le_bytes()),
        ],
    )
}

pub fn last(space: &Space, kind: u8) -> Vec<u8> {
    key(Item::Last, &[space, &twox64_concat(&[kind])])
}

pub fn equivocations(space: &Space, kind: u8, window: u64) -> Vec<u8> {
    key(
        Item::Equivocations,
        &[
            space,
            &twox64_concat(&[kind]),
            &twox64_concat(&window.to_le_bytes()),
        ],
    )
}

/// Every `Equivocations` entry of `space` is under it.
pub fn equivocations_of(space: &Space) -> Vec<u8> {
    key(Item::Equivocations, &[space])
}

pub fn budget(space: &Space) -> Vec<u8> {
    key(Item::Budget, &[space])
}

pub fn formats(format: u32) -> Vec<u8> {
    key(Item::Formats, &[&twox64_concat(&format.to_le_bytes())])
}

pub fn programs(program: &[u32; 8]) -> Vec<u8> {
    let bytes: Vec<u8> = program.iter().flat_map(|word| word.to_le_bytes()).collect();
    key(Item::Programs, &[&blake2_128_concat(&bytes)])
}

pub fn seen(id: &[u8; 32]) -> Vec<u8> {
    key(Item::Seen, &[id])
}

pub fn paused() -> Vec<u8> {
    Item::Paused.prefix()
}

/// The space and window of an `Anchors` key: after the prefix (32 bytes),
/// the space (32), the kind's hash and byte (8 + 1), the window's hash and
/// bytes (8 + 8).
pub fn anchors_parts(key: &[u8]) -> Option<(Space, u64)> {
    let space = key.get(32..64)?.try_into().ok()?;
    let window = key.get(81..89)?.try_into().ok()?;
    Some((space, u64::from_le_bytes(window)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// FRAME's well-known keys: `System.Account`'s prefix and
    /// `Timestamp.Now`.
    #[test]
    fn the_hashers_are_frames() {
        assert_eq!(
            hex(&[twox128(b"System"), twox128(b"Account")].concat()),
            "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9"
        );
        assert_eq!(
            hex(&[twox128(b"Timestamp"), twox128(b"Now")].concat()),
            "f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb"
        );
        // Alice's `System.Account` entry: `Blake2_128Concat` of her key.
        let alice: [u8; 32] = [
            0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9,
            0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7,
            0xa5, 0x6d, 0xa2, 0x7d,
        ];
        assert_eq!(
            hex(&blake2_128_concat(&alice)),
            "de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
    }

    /// An `Anchors` key splits back into its space and window.
    #[test]
    fn an_anchors_key_splits() {
        let key = anchors(&[7; 32], 0, 0x0102_0304_0506_0708);
        assert_eq!(key.len(), 32 + 32 + 9 + 16);
        assert_eq!(anchors_parts(&key), Some(([7; 32], 0x0102_0304_0506_0708)));
    }
}
