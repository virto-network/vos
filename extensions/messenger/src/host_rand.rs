//! Host-seeded, forward-ratcheting deterministic CSPRNG for the MLS RNG.
//!
//! MLS draws all of a member's node-private key material (KeyPackage init
//! keys, leaf/path encryption keys, init/joiner secrets, the per-message AEAD
//! reuse guard) from a randomness source. A deterministic PVM actor has no OS
//! entropy, so [`HostRand`] replaces it with a CSPRNG whose only entropy is a
//! 32-byte secret seed provisioned once by the host: the output is a pure
//! function of `(seed, boot context, draw counter)`, so a replayer of the
//! replicated DAG — who never holds the seed — cannot predict it, while a PVM
//! port reproduces it from the same host-fed inputs.
//!
//! mls-rs takes randomness through its `CipherSuiteProvider` rather than a
//! standalone RNG trait, and the RustCrypto provider draws OS entropy *inside*
//! `signature_key_generate`/`kem_generate`/`hpke_seal`. Routing every one of
//! those through this stream is the determinism work; it is staged separately
//! (a custom `CipherSuiteProvider`) from the functional mls-rs port, so on the
//! host build this CSPRNG is not yet wired into mls-rs — it is retained here
//! for that wiring, and to derive the signer secret deterministically.
//!
//! Two randomness planes are kept strictly apart. The **secret seed** is the
//! only confidentiality root; it is the HKDF IKM and nothing else ever is. A
//! **public beacon** (operational fairness) may only ever enter as HKDF `info`
//! on the output branch — never as IKM, salt, or the ratchet input — so
//! confidentiality holds on the seed alone even if the beacon is known (RFC
//! 9180 §9.7.5). That separation is enforced structurally here: there is no
//! method that folds external bytes into the ratchet state.

#![allow(dead_code)]

use core::cell::{Cell, RefCell};
use core::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Global domain tag. Any change to the construction MUST bump the version
/// suffix — it re-forks every derived stream.
const DOMAIN: &[u8] = b"vos-msg/csprng/v1";
/// Boot-state derivation branch (folds in device + boot-epoch).
const INIT_LABEL: &[u8] = b"init";
/// Per-draw output branch (the only branch the beacon may touch).
const OUTPUT_LABEL: &[u8] = b"output";
/// State-advance branch — secret-only, never sees the beacon.
const RATCHET_LABEL: &[u8] = b"ratchet";

/// The CSPRNG state is exactly one HMAC-SHA256 output (= the HKDF PRK width),
/// so `Hkdf::from_prk` never rejects it.
const STATE_LEN: usize = 32;

/// A public, replicated randomness beacon (the verifiable-randomness hedge).
/// Deliberately a distinct type from the secret seed with **no** conversion
/// into it: a beacon may only be handed to [`HostRand::set_beacon`], whose
/// value is read at exactly one site — the `info` argument of the
/// output-branch expand. There is no `reseed`/`mix_entropy`/`set_prk` method
/// anywhere, so the beacon cannot reach the IKM or the ratchet by construction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicBeacon(pub [u8; 32]);

/// Error from a CSPRNG draw. The only failure is an output length beyond
/// HKDF's `255 * HashLen` ceiling (8160 bytes) — unreachable for any MLS draw.
#[derive(Debug)]
pub(crate) struct HostRandError;

impl fmt::Display for HostRandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("host CSPRNG draw exceeded the HKDF output length ceiling")
    }
}

impl core::error::Error for HostRandError {}

/// Forward-ratcheting deterministic CSPRNG. `&self` methods advance the
/// ratchet through interior mutability; the messenger dispatch model is
/// single-threaded, so a `RefCell`/`Cell` is sufficient.
pub(crate) struct HostRand {
    /// The current ratchet PRK. `Zeroizing<[u8; 32]>` (not `Vec`): a fixed
    /// array never reallocates, so the old PRK is overwritten in place on
    /// every advance with no abandoned heap copy, and the wrapper wipes it
    /// on drop.
    state: RefCell<Zeroizing<[u8; STATE_LEN]>>,
    /// Monotonic per-draw counter — the reuse teeth: every output binds a
    /// distinct, never-reused counter into its `info`.
    ctr: Cell<u64>,
    /// Optional public hedge, output-branch `info` only.
    beacon: Cell<Option<[u8; 32]>>,
}

impl HostRand {
    /// Boot the CSPRNG before its first draw.
    ///
    /// - `seed`: the 32-byte secret root (HKDF IKM); the ONLY confidentiality
    ///   source. Never logged, never replicated.
    /// - `boot_token`: a per-boot uniqueness value that MUST differ across
    ///   every process start / warm restart / fork. Non-secret (salt slot).
    /// - `device_id`: a per-device-unique tag, so two devices that share a
    ///   seed still fork their streams.
    /// - `boot_epoch`: a persisted, monotonically-increasing counter advanced
    ///   before the first draw of a boot.
    /// - `persisted_ctr`: the last durably-recorded draw counter; the stream
    ///   is fast-forwarded past it so a resurrected snapshot can never re-emit
    ///   a consumed `(counter, output)` pair. `0` on a first boot.
    pub(crate) fn boot(
        seed: &[u8; 32],
        boot_token: &[u8],
        device_id: &[u8],
        boot_epoch: u64,
        persisted_ctr: u64,
    ) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(boot_token), seed);
        let mut state = Zeroizing::new([0u8; STATE_LEN]);
        let dev_len = (device_id.len() as u32).to_be_bytes();
        hk.expand_multi_info(
            &[
                DOMAIN,
                INIT_LABEL,
                &dev_len,
                device_id,
                &boot_epoch.to_be_bytes(),
            ],
            state.as_mut_slice(),
        )
        .expect("32-byte boot state is within the HKDF length ceiling");

        let rand = HostRand {
            state: RefCell::new(state),
            ctr: Cell::new(0),
            beacon: Cell::new(None),
        };
        while rand.ctr.get() < persisted_ctr {
            rand.ratchet();
        }
        rand
    }

    /// Set the public beacon hedge for subsequent draws. The value is read
    /// solely inside the output-branch `info`; it never touches the seed,
    /// salt, or ratchet.
    pub(crate) fn set_beacon(&self, beacon: PublicBeacon) {
        self.beacon.set(Some(beacon.0));
    }

    /// The current draw counter — for persisting alongside the MLS store so a
    /// later boot can fast-forward past it.
    pub(crate) fn counter(&self) -> u64 {
        self.ctr.get()
    }

    /// Draw `out.len()` bytes from the current state and advance the ratchet.
    pub(crate) fn draw_into(&self, out: &mut [u8]) -> Result<(), HostRandError> {
        let i = self.ctr.get();
        let beacon = self.beacon.get();
        let state = self.state.borrow();

        {
            let hk = Hkdf::<Sha256>::from_prk(state.as_slice())
                .expect("32-byte state is a valid HKDF PRK");
            let beacon_bytes = beacon.unwrap_or_default();
            let beacon_slice: &[u8] = if beacon.is_some() { &beacon_bytes } else { &[] };
            let beacon_len = (beacon_slice.len() as u32).to_be_bytes();
            hk.expand_multi_info(
                &[
                    DOMAIN,
                    OUTPUT_LABEL,
                    &i.to_be_bytes(),
                    &beacon_len,
                    beacon_slice,
                ],
                out,
            )
            .map_err(|_| HostRandError)?;
        }

        drop(state);
        self.ratchet();
        Ok(())
    }

    /// Draw a fixed-size array.
    pub(crate) fn random_array<const N: usize>(&self) -> Result<[u8; N], HostRandError> {
        let mut out = [0u8; N];
        self.draw_into(&mut out)?;
        Ok(out)
    }

    /// Advance the ratchet one step: derive the next state from the current
    /// one under the ratchet label (never the beacon), overwrite the old PRK
    /// in place (wiping it), and bump the counter.
    fn ratchet(&self) {
        let i = self.ctr.get();
        let mut state = self.state.borrow_mut();
        let mut next = Zeroizing::new([0u8; STATE_LEN]);
        {
            let hk = Hkdf::<Sha256>::from_prk(state.as_slice())
                .expect("32-byte state is a valid HKDF PRK");
            hk.expand_multi_info(
                &[DOMAIN, RATCHET_LABEL, &i.to_be_bytes()],
                next.as_mut_slice(),
            )
            .expect("32-byte next state is within the HKDF length ceiling");
        }
        state.copy_from_slice(next.as_slice());
        next.zeroize();
        self.ctr.set(i + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; 32] = [1u8; 32];
    const TOKEN_A: [u8; 32] = [2u8; 32];

    fn boot(seed: &[u8; 32], token: &[u8], device: &[u8], epoch: u64) -> HostRand {
        HostRand::boot(seed, token, device, epoch, 0)
    }

    fn first32(r: &HostRand) -> [u8; 32] {
        r.random_array::<32>().unwrap()
    }

    /// Same (seed, boot context) ⇒ byte-identical draw sequences.
    #[test]
    fn same_seed_and_context_is_deterministic() {
        let a = boot(&SEED_A, &TOKEN_A, b"dev", 7);
        let b = boot(&SEED_A, &TOKEN_A, b"dev", 7);
        for _ in 0..8 {
            assert_eq!(
                a.random_array::<32>().unwrap(),
                b.random_array::<32>().unwrap()
            );
        }
    }

    /// A fresh boot_token, a bumped boot_epoch, or a different device_id each
    /// forks the stream.
    #[test]
    fn boot_context_forks_the_stream() {
        let base = first32(&boot(&SEED_A, &TOKEN_A, b"dev", 7));
        let other_token = first32(&boot(&SEED_A, &[9u8; 32], b"dev", 7));
        let other_epoch = first32(&boot(&SEED_A, &TOKEN_A, b"dev", 8));
        let other_device = first32(&boot(&SEED_A, &TOKEN_A, b"dev2", 7));
        assert_ne!(base, other_token, "fresh boot_token must fork the stream");
        assert_ne!(base, other_epoch, "bumped boot_epoch must fork the stream");
        assert_ne!(base, other_device, "distinct device_id must fork the stream");
    }

    /// A different seed forks the stream.
    #[test]
    fn distinct_seed_forks_the_stream() {
        let a = first32(&boot(&SEED_A, &TOKEN_A, b"dev", 7));
        let b = first32(&boot(&[42u8; 32], &TOKEN_A, b"dev", 7));
        assert_ne!(a, b);
    }

    /// The counter advances monotonically and a fast-forwarded boot never
    /// re-emits a consumed draw.
    #[test]
    fn ratchet_is_monotonic_and_never_rewinds() {
        let r = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            assert!(seen.insert(r.random_array::<32>().unwrap()));
        }
        assert_eq!(r.counter(), 16);

        let resumed = HostRand::boot(&SEED_A, &TOKEN_A, b"dev", 0, 16);
        assert!(resumed.counter() >= 16);
        for _ in 0..16 {
            assert!(seen.insert(resumed.random_array::<32>().unwrap()));
        }
    }

    /// The beacon hedges the OUTPUT only and never steers the ratchet.
    #[test]
    fn beacon_is_output_info_only() {
        let a = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        let b = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        a.set_beacon(PublicBeacon([0xAA; 32]));
        b.set_beacon(PublicBeacon([0xBB; 32]));
        let out_a = a.random_array::<32>().unwrap();
        let out_b = b.random_array::<32>().unwrap();
        assert_ne!(out_a, out_b, "different beacons must hedge the output");
        assert_eq!(
            *a.state.borrow(),
            *b.state.borrow(),
            "the beacon must never steer the ratchet state",
        );
    }
}
