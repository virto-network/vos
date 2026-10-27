//! The device secret from a secret source (`proving.md` §8, pin K): the
//! source's HMAC takes [`source_input`] of the space's handle, and its
//! 32-byte output `o` gives `s` by [`derive_secret`], again at each use.

use blake2::{Blake2b512, Digest as _};
use sha2::Sha256;
use vos_wire::credentials::{P, Tag, Words, compress};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Digest;

/// The source input's domain.
const INPUT_DOMAIN: &[u8] = b"vos/device/input/v1";
/// The derivation's domain.
const SECRET_DOMAIN: &[u8] = b"vos/device/secret/v1";

/// A member's secret `s`: eight M31 words. Zeroized on drop; no `Clone`,
/// no `Debug`, nothing that shows its words outside the crate.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecret(pub(crate) Words);

/// The message a secret source's HMAC takes for the space whose handle is
/// `handle`: `SHA-256("vos/device/input/v1" ‖ handle)`, a security key's
/// salt as it is.
pub fn source_input(handle: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(INPUT_DOMAIN)
        .chain_update(handle)
        .finalize()
        .into()
}

/// The secret a source's output `source_output` gives for `handle`:
/// `w = BLAKE2b-512("vos/device/secret/v1" ‖ handle ‖ o)`, word `i` of `s`
/// `u64_le(w[8i..8i + 8]) mod p`. The caller zeroizes its `o` once this
/// returns; `w` is zeroized here.
pub fn derive_secret(source_output: &[u8; 32], handle: &[u8; 32]) -> DeviceSecret {
    let mut hasher = Blake2b512::new();
    hasher.update(SECRET_DOMAIN);
    hasher.update(handle);
    hasher.update(source_output);
    let mut w: [u8; 64] = hasher.finalize().into();
    let mut secret = DeviceSecret([0; 8]);
    for (word, bytes) in secret.0.iter_mut().zip(w.chunks_exact(8)) {
        let mut wide = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
        *word = (wide % u64::from(P)) as u32;
        wide.zeroize();
    }
    w.zeroize();
    secret
}

/// `member(s) = C(T(member), s)`: the digest the credential actor's tree
/// holds under the member's leaf.
pub fn member(secret: &DeviceSecret) -> Digest {
    Digest(compress(&Tag::Member.block(), &secret.0))
}

/// `owner(s) = C(T(owner), s)`: the digest a ledger row's owner names.
pub fn owner(secret: &DeviceSecret) -> Digest {
    Digest(compress(&Tag::Owner.block(), &secret.0))
}

/// `nullifier = C(C(T(nf), s), scope)`: the member's pseudonym in `scope`.
pub(crate) fn nullifier(secret: &DeviceSecret, scope: &Digest) -> Digest {
    let mut key = compress(&Tag::Nf.block(), &secret.0);
    let nullifier = compress(&key, &scope.0);
    key.zeroize();
    Digest(nullifier)
}
