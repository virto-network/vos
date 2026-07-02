//! Wire types: published KeyPackages, announced channels, and the
//! canonical KeyPackage hash.

use alloc::string::String;
use alloc::vec::Vec;

use crate::consts::KP_HASH_DOMAIN_TAG;

/// One published KeyPackage. `kp` is opaque to the directory —
/// validation happens MLS-side on the inviter.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct KpRow {
    pub owner: String,
    pub hash: [u8; 32],
    pub kp: Vec<u8>,
    pub claimed: bool,
}

/// One announced channel.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ChannelRow {
    pub name: String,
    pub creator: String,
}

/// Canonical KeyPackage hash — see [`crate::KP_HASH_DOMAIN_TAG`].
pub fn kp_hash(serialized_kp: &[u8]) -> [u8; 32] {
    vos::crypto::blake2b_hash(KP_HASH_DOMAIN_TAG, &[serialized_kp])
}
