//! Host-seeded, forward-ratcheting deterministic CSPRNG behind the MLS RNG.
//!
//! OpenMLS draws all of its node-private key material (KeyPackage init
//! keys, leaf/path encryption keys, init/joiner secrets, the per-message
//! AEAD reuse guard) from its provider's `rand()`. Stock
//! `OpenMlsRustCrypto` wires that to a `ChaCha20Rng::from_entropy()`, which
//! needs OS entropy and is therefore unavailable to a deterministic PVM
//! actor. [`HostRand`] replaces it with a CSPRNG whose only entropy is a
//! 32-byte secret seed provisioned once by the host: the output is a pure
//! function of `(seed, boot context, draw counter)`, so a replayer of the
//! replicated DAG — who never holds the seed — cannot predict it, while a
//! future PVM port can reproduce it from the same host-fed inputs.
//!
//! Two randomness planes are kept strictly apart. The **secret seed** is
//! the only confidentiality root; it is the HKDF IKM and nothing else ever
//! is. A **public beacon** (operational fairness) may only ever enter
//! as HKDF `info` on the output branch — never as IKM, salt, or the ratchet
//! input — so confidentiality holds on the seed alone even if the beacon is
//! known (RFC 9180 §9.7.5). That separation is enforced structurally here:
//! there is no method that folds external bytes into the ratchet state.
//!
//! Construction (HMAC-SHA256 throughout, matching ciphersuite 1's KDF):
//!
//! - boot: `prk = HKDF-Extract(salt = boot_token, ikm = seed)`, then
//!   `state0 = HKDF-Expand(prk, info = DOMAIN‖"init"‖device_id‖boot_epoch)`.
//!   The non-secret `boot_token` (per-boot OS entropy / host VM-generation
//!   value) in the salt slot, the `device_id`, and the persisted monotonic
//!   `boot_epoch` make the stream diverge across a cold clone, a live-RAM
//!   fork, and a second device that copied the seed — the three ways used
//!   randomness gets re-emitted (key/nonce reuse, the Ristenpart–Yilek GCM
//!   catastrophe).
//! - per draw `i`: `out = HKDF-Expand(state, info = DOMAIN‖"output"‖i‖beacon)`;
//!   ratchet `state' = HKDF-Expand(state, info = DOMAIN‖"ratchet"‖i)`; the
//!   old state is zeroized in place; `i` is monotonic and never rewound.
//!   Distinct labels make `out` and `state'` independent PRF streams off the
//!   same PRK, so compromising `state'` cannot back-compute a past `out`.
//!
//! "Zeroized in place" covers the persisted ratchet cell (the `Zeroizing`
//! state); it does NOT reach the transient PRK-equivalent HMAC scratch that
//! `hkdf::Hkdf::from_prk` keys and drops un-wiped (the crate has no
//! `ZeroizeOnDrop`). That scratch is a same-process, same-call exposure only —
//! an attacker who can read it already holds the seed — so the forward-secrecy
//! guarantee rests on the persisted state being wiped, which it is.

use core::cell::{Cell, RefCell};
use core::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use openmls_traits::random::OpenMlsRand;

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
/// anywhere, so the beacon cannot reach the IKM or the ratchet by
/// construction. Wired into the live messenger via [`VosProvider::set_beacon`]
/// (fed from the chronos service's latest finalized round); absent chronos
/// leaves it unset, which is a no-op on the stream.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicBeacon(pub [u8; 32]);

/// Error from a CSPRNG draw. The only failure is an output length beyond
/// HKDF's `255 * HashLen` ceiling (8160 bytes) — unreachable for any MLS
/// draw, but `random_vec` takes an arbitrary length, so it is surfaced
/// rather than panicked.
#[derive(Debug)]
pub(crate) struct HostRandError;

impl fmt::Display for HostRandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("host CSPRNG draw exceeded the HKDF output length ceiling")
    }
}

impl std::error::Error for HostRandError {}

/// Forward-ratcheting deterministic CSPRNG. `&self` methods (the
/// [`OpenMlsRand`] contract) advance the ratchet through interior
/// mutability; the messenger dispatch model is single-threaded, so a
/// `RefCell`/`Cell` (no `std::sync`) is sufficient and keeps the eventual
/// no_std PVM port clean.
pub(crate) struct HostRand {
    /// The current ratchet PRK. `Zeroizing<[u8; 32]>` (not `Vec`): a fixed
    /// array never reallocates, so the old PRK is overwritten in place on
    /// every advance with no abandoned heap copy, and the wrapper wipes it
    /// on drop.
    state: RefCell<Zeroizing<[u8; STATE_LEN]>>,
    /// Monotonic per-draw counter. Not secret (it is just an index), but it
    /// is the reuse teeth: every output binds a distinct, never-reused
    /// counter into its `info`.
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
    ///   every process start / warm restart / fork. Non-secret (it sits in
    ///   the salt slot); on native it is fresh OS entropy, in the PVM it is a
    ///   host-fed VM-generation value.
    /// - `device_id`: a per-device-unique tag, so two devices that share a
    ///   seed still fork their streams.
    /// - `boot_epoch`: a persisted, monotonically-increasing counter advanced
    ///   before the first draw of a boot, so even a resumed live-RAM snapshot
    ///   diverges on its second resume.
    /// - `persisted_ctr`: the last durably-recorded draw counter; the stream
    ///   is fast-forwarded past it so a resurrected snapshot can never
    ///   re-emit a consumed `(counter, output)` pair. `0` on a first boot.
    pub(crate) fn boot(
        seed: &[u8; 32],
        boot_token: &[u8],
        device_id: &[u8],
        boot_epoch: u64,
        persisted_ctr: u64,
    ) -> Self {
        // Extract folds the secret seed (IKM) and the non-secret boot token
        // (salt) into a fresh PRK; Expand binds the device and boot epoch
        // into the initial state. expand into a 32-byte buffer never errors.
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
        // Fast-forward only; never rewind.
        while rand.ctr.get() < persisted_ctr {
            rand.ratchet();
        }
        rand
    }

    /// Set the public beacon hedge for subsequent draws. The value is read
    /// solely inside the output-branch `info` (see [`Self::draw_into`]); it
    /// never touches the seed, salt, or ratchet.
    pub(crate) fn set_beacon(&self, beacon: PublicBeacon) {
        self.beacon.set(Some(beacon.0));
    }

    /// The current draw counter — for persisting alongside the MLS store so a
    /// later boot can fast-forward past it.
    #[cfg(test)]
    pub(crate) fn counter(&self) -> u64 {
        self.ctr.get()
    }

    /// Draw `out.len()` bytes from the current state and advance the ratchet.
    /// Output and state are derived from the same PRK under distinct labels,
    /// so they are independent; the ratchet step runs before the bytes are
    /// returned so a crash that loses the advance lands on a fresh stream
    /// after reboot rather than re-emitting these bytes.
    fn draw_into(&self, out: &mut [u8]) -> Result<(), HostRandError> {
        let i = self.ctr.get();
        let beacon = self.beacon.get();
        let state = self.state.borrow();

        // Output branch. The beacon is length-framed so absent / empty / any
        // value can never alias another context's `info` encoding.
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

    /// Advance the ratchet one step: derive the next state from the current
    /// one under the ratchet label (never the beacon), overwrite the old PRK
    /// in place (wiping it), and bump the counter. Used both per draw and to
    /// fast-forward at boot.
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

impl OpenMlsRand for HostRand {
    type Error = HostRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        self.draw_into(&mut out)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        self.draw_into(&mut out)?;
        Ok(out)
    }
}

/// MLS provider returning [`HostRand`] from `rand()` while delegating
/// `crypto()` to stock RustCrypto and `storage()` to the in-memory map the
/// messenger snapshots. Unlike `OpenMlsRustCrypto`, `rand()` does NOT return
/// the RustCrypto — its OS-seeded ChaCha is reached only by
/// `signature_key_gen` (which the messenger never calls; identities are built
/// from a seeded draw via `mls::derive_signer`) and by HPKE Seal's own
/// per-call ephemeral (a known, deferred non-determinism — the seal keypair
/// is not reachable through the provider).
pub(crate) struct VosProvider {
    crypto: openmls_rust_crypto::RustCrypto,
    rand: HostRand,
    storage: openmls_rust_crypto::MemoryStorage,
}

impl VosProvider {
    /// Assemble a provider over a freshly-booted CSPRNG and an empty storage
    /// map (callers restore the map afterwards via `storage().values`).
    pub(crate) fn new(rand: HostRand) -> Self {
        VosProvider {
            crypto: openmls_rust_crypto::RustCrypto::default(),
            rand,
            storage: openmls_rust_crypto::MemoryStorage::default(),
        }
    }

    /// Hedge subsequent draws with a public beacon (output-branch `info` only;
    /// see [`HostRand::set_beacon`]). The messenger calls this between opening
    /// the provider and the first MLS draw, passing the latest finalized
    /// chronos beacon; with no beacon the stream is unchanged.
    pub(crate) fn set_beacon(&self, beacon: PublicBeacon) {
        self.rand.set_beacon(beacon);
    }
}

impl openmls_traits::OpenMlsProvider for VosProvider {
    type CryptoProvider = openmls_rust_crypto::RustCrypto;
    type RandProvider = HostRand;
    type StorageProvider = openmls_rust_crypto::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
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

    /// Same (seed, boot context) ⇒ byte-identical draw sequences. This is the
    /// determinism property the eventual PVM port relies on.
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
        // Different draw lengths still share the stream's per-counter output.
        let c = boot(&SEED_A, &TOKEN_A, b"dev", 7);
        let d = boot(&SEED_A, &TOKEN_A, b"dev", 7);
        assert_eq!(
            c.random_vec(16).unwrap(),
            &d.random_array::<16>().unwrap()[..]
        );
    }

    /// A fresh boot_token, a bumped boot_epoch, or a different device_id each
    /// forks the stream — the three reuse defenses (cold clone, live-RAM
    /// fork, same-seed two devices).
    #[test]
    fn boot_context_forks_the_stream() {
        let base = first32(&boot(&SEED_A, &TOKEN_A, b"dev", 7));
        let other_token = first32(&boot(&SEED_A, &[9u8; 32], b"dev", 7));
        let other_epoch = first32(&boot(&SEED_A, &TOKEN_A, b"dev", 8));
        let other_device = first32(&boot(&SEED_A, &TOKEN_A, b"dev2", 7));
        assert_ne!(base, other_token, "fresh boot_token must fork the stream");
        assert_ne!(base, other_epoch, "bumped boot_epoch must fork the stream");
        assert_ne!(
            base, other_device,
            "distinct device_id must fork the stream"
        );
    }

    /// A different seed forks the stream (the seed is the confidentiality
    /// root; everything else is freshness).
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

        // Boot a replica fast-forwarded past the 16 consumed draws: its next
        // outputs must be disjoint from everything already emitted.
        let resumed = HostRand::boot(&SEED_A, &TOKEN_A, b"dev", 0, 16);
        assert!(resumed.counter() >= 16);
        for _ in 0..16 {
            assert!(seen.insert(resumed.random_array::<32>().unwrap()));
        }
    }

    /// Forward secrecy: ratcheting overwrites the state in place, so the
    /// pre-ratchet PRK is gone from the cell.
    #[test]
    fn ratchet_overwrites_old_state() {
        let r = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        let snapshot: [u8; STATE_LEN] = **r.state.borrow();
        r.ratchet();
        let after: [u8; STATE_LEN] = **r.state.borrow();
        assert_ne!(snapshot, after, "state must change on ratchet");
    }

    /// The beacon hedges the OUTPUT only and never steers the ratchet:
    /// fixed seed + two beacons ⇒ identical next-state, different output.
    #[test]
    fn beacon_is_output_info_only() {
        // Same starting state in two instances; set different beacons, take
        // one output each, then compare the resulting ratchet states.
        let a = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        let b = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        a.set_beacon(PublicBeacon([0xAA; 32]));
        b.set_beacon(PublicBeacon([0xBB; 32]));
        let out_a = a.random_array::<32>().unwrap();
        let out_b = b.random_array::<32>().unwrap();
        assert_ne!(out_a, out_b, "different beacons must hedge the output");
        // The post-draw states must be identical — the ratchet ignored the
        // beacon (it derives only from the pre-draw state + counter).
        assert_eq!(
            *a.state.borrow(),
            *b.state.borrow(),
            "the beacon must never steer the ratchet state",
        );
        // And a no-beacon instance ratchets to that same state too.
        let c = boot(&SEED_A, &TOKEN_A, b"dev", 0);
        let _ = c.random_array::<32>().unwrap();
        assert_eq!(*a.state.borrow(), *c.state.borrow());
    }

    /// The provider-level passthrough hedges the underlying HostRand the same
    /// way: same seed with the beacon set vs unset diverge the draw, while the
    /// same seed + same beacon reproduce it — the property the messenger relies
    /// on when it feeds the latest finalized chronos beacon.
    #[test]
    fn provider_set_beacon_hedges_the_output() {
        use openmls_traits::OpenMlsProvider;
        let hedged = VosProvider::new(boot(&SEED_A, &TOKEN_A, b"dev", 0));
        let plain = VosProvider::new(boot(&SEED_A, &TOKEN_A, b"dev", 0));
        hedged.set_beacon(PublicBeacon([0xCD; 32]));
        let h = hedged.rand().random_array::<32>().unwrap();
        let p = plain.rand().random_array::<32>().unwrap();
        assert_ne!(h, p, "a set beacon must perturb the provider's draw");

        let same = VosProvider::new(boot(&SEED_A, &TOKEN_A, b"dev", 0));
        same.set_beacon(PublicBeacon([0xCD; 32]));
        assert_eq!(
            h,
            same.rand().random_array::<32>().unwrap(),
            "the same seed + beacon must reproduce the draw"
        );
    }
}
