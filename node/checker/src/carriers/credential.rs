//! A member's device credential as needles (`proving.md` §8,
//! `pvm/device/SECURITY.md`): what its secret source gives and all that
//! follows from it, which nothing but the device holds, and where the
//! member sits in the credential actor's tree, which a credentialed call
//! never carries.

use std::fmt;

use blake2::{Blake2b512, Digest as _};
use vos_wire::credentials::{self, EMPTY, P, Path, Tag, Words};

use super::{Kind, Needle, Needles, SMALL_FLOOR};

/// The derivation's domain, as `vos_device::derive_secret` hashes it.
const SECRET_DOMAIN: &[u8] = b"vos/device/secret/v1";

/// `w` and `s` from a secret source's output `source_output` for the
/// space whose handle is `handle`, computed apart from the device library:
/// `w = BLAKE2b-512("vos/device/secret/v1" ‖ handle ‖ o)`, word `i` of `s`
/// `u64_le(w[8i..8i + 8]) mod p`.
pub fn derive(source_output: &[u8; 32], handle: &[u8; 32]) -> ([u8; 64], Words) {
    let w: [u8; 64] = Blake2b512::new()
        .chain_update(SECRET_DOMAIN)
        .chain_update(handle)
        .chain_update(source_output)
        .finalize()
        .into();
    let words = core::array::from_fn(|i| {
        let wide = u64::from_le_bytes(w[8 * i..8 * i + 8].try_into().expect("eight bytes"));
        (wide % u64::from(P)) as u32
    });
    (w, words)
}

impl Needles {
    /// `member`'s device secret, from its source's output `source_output`
    /// for the space's `handle`: `o`, `w`, `s` and each of its words, the
    /// nullifier's key `C(T(nf), s)`, and the BLAKE2b-256 and BLAKE3 of `o`
    /// and of `s`'s bytes. Returns `s`'s words.
    pub fn device_secret(
        &mut self,
        member: &str,
        source_output: &[u8; 32],
        handle: &[u8; 32],
    ) -> Words {
        let (w, words) = derive(source_output, handle);
        let secret = credentials::digest(&words);
        let nf_key = credentials::digest(&credentials::compress(&Tag::Nf.block(), &words));
        let name = |what: &str| format!("{member}: {what}");
        self.push(Needle::bytes(
            Kind::DeviceSecret,
            name("the source's output"),
            source_output,
        ));
        self.push(Needle::bytes(Kind::DeviceSecret, name("w"), &w));
        self.push(Needle::field(Kind::DeviceSecret, name("s"), &secret));
        self.push(Needle::field(
            Kind::DeviceSecret,
            name("the nullifier's key"),
            &nf_key,
        ));
        for (at, &word) in words.iter().enumerate() {
            self.push(Needle::word(
                Kind::DeviceSecret,
                name(&format!("s's word {at}")),
                word,
            ));
        }
        for (what, bytes) in [("o", &source_output[..]), ("s", &secret[..])] {
            let hashes = [
                ("BLAKE2b-256", vos_wire::vos_anchor::blake2b_256(&[bytes])),
                ("BLAKE3", *blake3::hash(bytes).as_bytes()),
            ];
            for (hash, digest) in hashes {
                self.push(Needle::bytes(
                    Kind::DeviceSecret,
                    name(&format!("{hash} of {what}")),
                    &digest,
                ));
            }
        }
        words
    }

    /// Where `member` sits: its member digest `digest`, its leaf, its slot
    /// from [`SMALL_FLOOR`] up (by its digits and hex, matched whole), and
    /// each sibling of `path` that is not the empty subtree at its level
    /// (which every tree holds).
    pub fn member_place(&mut self, member: &str, digest: &credentials::Digest, path: &Path) {
        let name = |what: &str| format!("{member}: {what}");
        self.push(Needle::field(
            Kind::MemberPlace,
            name("the member digest"),
            digest,
        ));
        if let Some(words) = credentials::words(digest) {
            self.push(Needle::field(
                Kind::MemberPlace,
                name("the leaf"),
                &credentials::digest(&credentials::leaf(&words)),
            ));
        }
        if u64::from(path.slot) >= SMALL_FLOOR {
            self.0.push(Needle::digits(
                Kind::MemberPlace,
                name("the slot"),
                u64::from(path.slot),
            ));
        }
        for (level, sibling) in path.siblings.0.iter().enumerate() {
            if *sibling != credentials::digest(&EMPTY[level]) {
                self.push(Needle::field(
                    Kind::MemberPlace,
                    name(&format!("the sibling at level {level}")),
                    sibling,
                ));
            }
        }
    }

    /// A device kernel's arguments before its `public` last bytes, which
    /// hold the member's path and `s`.
    pub fn kernel_arguments(&mut self, member: &str, arguments: &[u8], public: usize) {
        let private = &arguments[..arguments.len().saturating_sub(public)];
        self.push(Needle::bytes(
            Kind::DeviceSecret,
            format!("{member}: a device kernel's arguments"),
            private,
        ));
    }

    /// The randomness `proof`'s masks were drawn from, each value as it
    /// was drawn (`vos_pvm_recair::masked::drawn_in`).
    pub fn drawn<W: fmt::Display>(&mut self, proof: &str, drawn: &[(W, Vec<u8>)]) {
        for (at, (what, bytes)) in drawn.iter().enumerate() {
            self.push(Needle::bytes(
                Kind::WrapRandomness,
                format!("{proof}: {what} ({at})"),
                bytes,
            ));
        }
    }
}
