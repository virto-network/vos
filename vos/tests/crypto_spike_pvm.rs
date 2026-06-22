//! P2.0 — in-JAVM crypto execution gate (see docs/design/messaging-pvm-native.md).
//!
//! The compile spike (`actors/_crypto_spike`) proved the ciphersuite-1 stack
//! *links* and transpiles for the PVM. This test closes the remaining gap:
//! correct *execution*. It loads the spike ELF, transpiles it, runs it through
//! `VosRuntime`, drives each parametric `tv_*` handler over several inputs, and
//! asserts the PVM-computed bytes are **bit-exact** against host RustCrypto over
//! the same inputs — for SHA-256, HKDF, X25519, Ed25519, and AES-128-GCM.
//!
//! It also drives the self-scheduling `warm_rounds` handler, which re-runs the
//! whole crypto stack across `new_warm` re-entries (the recorded JAVM
//! warm-restart bug surface) and asserts every round reproduces round 0. The
//! host reproduces the round fold and asserts the actor reached all rounds with
//! zero guest panics — proving the crypto path is clean across a warm restart.
//!
//! The spike is `_`-prefixed and not built by the repo `justfile`; build it with
//! `cd actors/_crypto_spike && cargo +nightly actor`. If the ELF is absent the
//! test SKIPs loudly rather than failing the suite.

use vos::abi::service::ServiceId;
use vos::runtime::VosRuntime;
use vos::value::{Msg, TAG_DYNAMIC, Value};
use vos::{Decode, Encode};

// These MUST mirror `actors/_crypto_spike/src/lib.rs` byte-for-byte.
const HKDF_SALT: &[u8] = b"vos-p2.0/hkdf-salt";
const HKDF_INFO: &[u8] = b"vos-p2.0/hkdf-info";
const X25519_PEER_SK: [u8; 32] = [9u8; 32];
const WARM_ROUNDS: u32 = 4;
const BOOT_ROUNDS: usize = 4;
const BOOT_REC_LEN: usize = 72; // boot_token(32) ‖ device_id(32) ‖ boot_epoch(u64 LE)

/// Read the pre-built spike ELF, or `None` (with a loud SKIP) if absent.
fn spike_elf() -> Option<Vec<u8>> {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{workspace}/../actors/_crypto_spike/target/riscv64em-javm/release/crypto_spike.elf"
    );
    match std::fs::read(&path) {
        Ok(d) => Some(d),
        Err(_) => {
            eprintln!(
                "SKIP: crypto_spike ELF not built at {path}\n      \
                 run: cd actors/_crypto_spike && cargo +nightly actor"
            );
            None
        }
    }
}

/// Register the transpiled spike in a fresh runtime.
fn boot() -> (VosRuntime, ServiceId) {
    let elf = spike_elf().expect("spike ELF present (checked by caller)");
    let blob = grey_transpiler::link_elf(&elf).expect("transpile crypto_spike");
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_service_blob(blob);
    let id = rt.register_service(blob_idx);
    (rt, id)
}

/// Invoke a `#[msg]` handler by wire name with an optional `input: Vec<u8>` arg,
/// drive it to completion, and return the decoded reply `Value`.
fn call(rt: &mut VosRuntime, id: ServiceId, name: &str, input: Option<&[u8]>) -> Value {
    let msg = match input {
        Some(bytes) => Msg::new(name).with("input", bytes.to_vec()),
        None => Msg::new(name),
    };
    let mut payload = vec![TAG_DYNAMIC];
    payload.extend_from_slice(&msg.encode());
    rt.send_to(id, payload);
    rt.run_blocking();
    let reply = rt
        .take_last_reply(id)
        .unwrap_or_else(|| panic!("handler `{name}` produced no reply (panicked?)"));
    // A Unit-returning handler (e.g. `warm_rounds`) yields an empty reply; the
    // runtime still records it as `Some(empty)`, distinct from a panic (`None`).
    if reply.is_empty() {
        return Value::Unit;
    }
    <Value as Decode>::decode(&reply)
}

/// Invoke a handler expected to return bytes.
fn call_bytes(rt: &mut VosRuntime, id: ServiceId, name: &str, input: &[u8]) -> Vec<u8> {
    match call(rt, id, name, Some(input)) {
        Value::Bytes(b) => b,
        Value::Unit => Vec::new(),
        other => panic!("handler `{name}` returned {other:?}, expected bytes"),
    }
}

// ── Host reference computations (RustCrypto) ──

fn host_sha256(input: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(input).to_vec()
}

fn host_hkdf(ikm: &[u8]) -> Vec<u8> {
    use sha2::Sha256;
    let hk = hkdf::Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut okm = [0u8; 64];
    hk.expand(HKDF_INFO, &mut okm).unwrap();
    okm.to_vec()
}

fn host_x25519(sk: &[u8; 32]) -> Vec<u8> {
    let local = x25519_dalek::StaticSecret::from(*sk);
    let peer_pub =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(X25519_PEER_SK));
    local.diffie_hellman(&peer_pub).as_bytes().to_vec()
}

fn host_ed25519(seed: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    signing.sign(msg).to_bytes().to_vec()
}

fn host_aes(key: &[u8; 16], nonce: &[u8; 12], pt: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, KeyInit};
    let cipher = aes_gcm::Aes128Gcm::new(GenericArray::from_slice(key));
    cipher
        .encrypt(GenericArray::from_slice(nonce), pt)
        .expect("host aes-gcm seal")
}

#[test]
fn pvm_sha256_matches_host_rustcrypto() {
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();
    // Empty, short, block-boundary, and multi-block inputs.
    let mut multi = Vec::new();
    for i in 0..200u32 {
        multi.push((i % 251) as u8);
    }
    for input in [
        Vec::new(),
        b"abc".to_vec(),
        vec![0x42u8; 64],
        vec![0xa5u8; 65],
        multi,
    ] {
        let got = call_bytes(&mut rt, id, "tv_sha256", &input);
        assert_eq!(got, host_sha256(&input), "sha256 diverged for {} bytes", input.len());
    }
    assert_eq!(rt.panics, 0, "guest panicked during sha256 vectors");
}

#[test]
fn pvm_hkdf_matches_host_rustcrypto() {
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();
    for ikm in [vec![0u8; 32], b"ikm-material".to_vec(), vec![0xff; 80]] {
        let got = call_bytes(&mut rt, id, "tv_hkdf", &ikm);
        assert_eq!(got.len(), 64);
        assert_eq!(got, host_hkdf(&ikm), "hkdf diverged for {}-byte ikm", ikm.len());
    }
    assert_eq!(rt.panics, 0, "guest panicked during hkdf vectors");
}

#[test]
fn pvm_x25519_matches_host_rustcrypto() {
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();
    let secrets: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        s
    }];
    for sk in secrets {
        let got = call_bytes(&mut rt, id, "tv_x25519", &sk);
        assert_eq!(got, host_x25519(&sk), "x25519 DH diverged");
    }
    assert_eq!(rt.panics, 0, "guest panicked during x25519 vectors");
}

#[test]
fn pvm_ed25519_matches_host_rustcrypto() {
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();
    let cases: [(&[u8; 32], &[u8]); 3] = [
        (&[3u8; 32], b""),
        (&[5u8; 32], b"message"),
        (&[7u8; 32], b"a slightly longer message body for ed25519"),
    ];
    for (seed, msg) in cases {
        let mut input = seed.to_vec();
        input.extend_from_slice(msg);
        let got = call_bytes(&mut rt, id, "tv_ed25519", &input);
        assert_eq!(got.len(), 64);
        assert_eq!(got, host_ed25519(seed, msg), "ed25519 signature diverged");
    }
    assert_eq!(rt.panics, 0, "guest panicked during ed25519 vectors");
}

#[test]
fn pvm_aes128gcm_matches_host_rustcrypto() {
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 12];
    for pt in [b"".to_vec(), b"plaintext".to_vec(), vec![0x5au8; 100]] {
        let mut input = key.to_vec();
        input.extend_from_slice(&nonce);
        input.extend_from_slice(&pt);
        let got = call_bytes(&mut rt, id, "tv_aes", &input);
        assert_eq!(got, host_aes(&key, &nonce, &pt), "aes-gcm ciphertext diverged");
        // ciphertext = plaintext length + 16-byte GCM tag.
        assert_eq!(got.len(), pt.len() + 16);
    }
    assert_eq!(rt.panics, 0, "guest panicked during aes vectors");
}

#[test]
fn pvm_crypto_clean_across_warm_restart() {
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();

    // The per-round self-check digest (computed in `new()` on cold start).
    let digest = match call(&mut rt, id, "probe", None) {
        Value::Bytes(b) => b,
        other => panic!("probe returned {other:?}"),
    };
    assert_eq!(digest.len(), 32, "self-check digest must be 32 bytes");
    assert_eq!(rt.panics, 0, "cold-start self-check panicked");

    // Drive the warm-restart rounds. A single run_blocking pumps round 0
    // (cold/restored) plus the `new_warm` re-entries via self-tell; the
    // in-handler assert turns any post-restart crypto divergence into a panic.
    let _ = call(&mut rt, id, "warm_rounds", None);
    assert_eq!(
        rt.panics, 0,
        "crypto diverged or panicked across a warm restart"
    );

    // All rounds must have executed.
    let rounds = match call(&mut rt, id, "warm_count", None) {
        v => v.as_u64().expect("warm_count is a number"),
    };
    assert_eq!(rounds as u32, WARM_ROUNDS, "warm rounds did not all run");

    // Reproduce the order-dependent fold the actor accumulated and compare.
    let acc = match call(&mut rt, id, "warm_result", None) {
        Value::Bytes(b) => b,
        other => panic!("warm_result returned {other:?}"),
    };
    let mut expected = vec![0u8; 32];
    for _ in 0..WARM_ROUNDS {
        let mut h = sha2::Sha256::new();
        use sha2::Digest;
        h.update(&expected);
        h.update(&digest);
        expected = h.finalize().to_vec();
    }
    assert_eq!(acc, expected, "warm-restart fold diverged from host reproduction");
    assert_eq!(rt.panics, 0, "guest panicked during warm-restart gate");
}

#[test]
fn pvm_boot_context_fresh_across_warm_restart() {
    // P2.1 — the BOOT_CONTEXT host seam. The actor reads a boot context on each
    // (re)instantiation; round 0 is the cold entry, rounds 1.. are `new_warm`
    // re-entries (self-tell). The host must mint a FRESH boot_token and advance
    // boot_epoch on every one, while keeping device_id stable — so a CSPRNG
    // re-booted from this can never re-emit used randomness after a warm restart.
    let Some(_) = spike_elf() else { return };
    let (mut rt, id) = boot();

    let _ = call(&mut rt, id, "boot_collect", None);
    assert_eq!(rt.panics, 0, "guest panicked gathering boot contexts");

    let report = match call(&mut rt, id, "boot_report", None) {
        Value::Bytes(b) => b,
        other => panic!("boot_report returned {other:?}"),
    };
    assert_eq!(
        report.len(),
        BOOT_ROUNDS * BOOT_REC_LEN,
        "expected {BOOT_ROUNDS} boot-context records"
    );

    let mut tokens = std::collections::HashSet::new();
    let mut device0: Option<[u8; 32]> = None;
    let mut prev_epoch: Option<u64> = None;
    for r in 0..BOOT_ROUNDS {
        let rec = &report[r * BOOT_REC_LEN..(r + 1) * BOOT_REC_LEN];
        let token: [u8; 32] = rec[0..32].try_into().unwrap();
        let device: [u8; 32] = rec[32..64].try_into().unwrap();
        let epoch = u64::from_le_bytes(rec[64..72].try_into().unwrap());

        // Fresh, non-zero token on every (re)instantiation.
        assert_ne!(token, [0u8; 32], "round {r}: boot_token must be fresh OS entropy");
        assert!(tokens.insert(token), "round {r}: boot_token repeated across a restart");

        // Stable device id across restarts (and non-zero).
        assert_ne!(device, [0u8; 32], "round {r}: device_id must be set");
        match device0 {
            None => device0 = Some(device),
            Some(d0) => assert_eq!(device, d0, "round {r}: device_id changed across a restart"),
        }

        // Monotonically increasing boot_epoch.
        if let Some(p) = prev_epoch {
            assert_eq!(epoch, p + 1, "round {r}: boot_epoch must increment by one per boot");
        }
        prev_epoch = Some(epoch);
    }
    assert_eq!(rt.panics, 0, "guest panicked during boot-context gate");
}
