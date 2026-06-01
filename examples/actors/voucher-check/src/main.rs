//! voucher-check — PVM guest binary whose execution IS the witness for a
//! `cipher_clerk::voucher::proof::check` proof.
//!
//! ## Two entry paths
//!
//! Both run `cipher_clerk::voucher::proof::check`; the difference is
//! how (Public, Secret) reach the function.
//!
//! 1. **`start` (lifecycle on_start hook)** — reads (Public, Secret)
//!    from a static BSS buffer `WITNESS_BUFFER`. The prover writes
//!    the rkyv-archived bytes into the flat-mem region backing that
//!    buffer before `TracingPvm::run` and the trace ingests them via
//!    a normal `volatile_read`. Falls back to a hardcoded witness
//!    when the buffer is empty (e.g. a regular `vosx run` invocation,
//!    or a v0 smoke test). The buffer's address is exposed via the
//!    public `voucher_check_witness_addr` extern fn so the prover can
//!    find it without parsing the ELF symbol table.
//!
//! 2. **`verify_check(public_bytes, secret_bytes)` (mailbox message)**
//!    — production-shape path: take the witness as message args. Used
//!    when invoking the actor through the actor framework's normal
//!    INVOKE channel (cross-actor call from a host extension or
//!    another actor). The prove path doesn't currently use this —
//!    static BSS is deterministic per-ELF, mailbox payloads embed
//!    runtime-allocated pointers that drift between runs.
//!
//! Returns `1` on success, `0` if either argument fails to decode.
//! A check-rule violation panics inside `check` and surfaces as
//! `Trap` exit + non-zero panics counter.

use cipher_clerk::crypto::{Amount, AuthKey, Blinding};
use cipher_clerk::voucher::proof::{self, Public, Secret};
use vos::prelude::*;

/// Static witness buffer the prover patches before tracing.
///
/// Layout (little-endian):
///   bytes  0..4    public_bytes length (`u32`, 0 = no witness)
///   bytes  4..N    public_bytes (rkyv archive of `Public`)
///   bytes  N..N+4  secret_bytes length (`u32`)
///   bytes  N+4..M  secret_bytes (rkyv archive of `Secret`)
///
/// `1024` bytes is enough for the current (Public, Secret) — Public
/// is ~128 B archived, Secret is ~64 B. Bumped via the `static`
/// declaration if either type grows.
///
/// Lives in `.bss` (initial value all zeros). The prover finds its
/// runtime address via the `voucher_check_witness_addr` ABI fn and
/// overwrites the leading bytes in flat_mem before tracing.
#[unsafe(no_mangle)]
static mut WITNESS_BUFFER: [u8; 1024] = [0u8; 1024];

/// ABI: returns the address of `WITNESS_BUFFER`. The prover calls
/// this once via host-side ELF symbol resolution (or runs the
/// actor briefly with `Opcode::Trap` patched in to read the value
/// from the trace) to learn where to inject the witness.
///
/// `#[no_mangle]` + `extern "C"` so the symbol survives strip and
/// has a stable name across rustc versions.
#[unsafe(no_mangle)]
pub extern "C" fn voucher_check_witness_addr() -> usize {
    let r = &raw const WITNESS_BUFFER;
    r as usize
}

#[actor]
struct VoucherCheck;

#[messages]
impl VoucherCheck {
    fn new() -> Self {
        VoucherCheck
    }

    /// Lifecycle `on_start` hook. Reads (Public, Secret) from
    /// `WITNESS_BUFFER`; falls back to a hardcoded witness when the
    /// buffer's length prefix is zero. Calls
    /// `cipher_clerk::voucher::proof::check` — Trap on success,
    /// panic on rule violation.
    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) -> u8 {
        let (public, secret) = match read_witness_buffer() {
            Some((p, s)) => (p, s),
            None => hardcoded_witness(),
        };
        proof::check(&public, &secret);
        1
    }

    /// Mailbox message handler — production-shape (Public, Secret)
    /// passing via actor framework. See module docs for why the
    /// prove path uses `start` instead.
    #[msg]
    async fn verify_check(
        &self,
        _ctx: &mut Context<Self>,
        public_bytes: Vec<u8>,
        secret_bytes: Vec<u8>,
    ) -> u8 {
        let Ok(public) = vos::rkyv::from_bytes::<Public, vos::rkyv::rancor::Error>(&public_bytes)
        else {
            return 0;
        };
        let Ok(secret) = vos::rkyv::from_bytes::<Secret, vos::rkyv::rancor::Error>(&secret_bytes)
        else {
            return 0;
        };
        proof::check(&public, &secret);
        1
    }
}

/// Decode (Public, Secret) from the static buffer if the length
/// prefixes are non-zero and the rkyv archives decode cleanly.
/// Returns `None` if the buffer is empty or any decode fails — the
/// caller falls back to the hardcoded witness.
fn read_witness_buffer() -> Option<(Public, Secret)> {
    let buf_ptr = &raw const WITNESS_BUFFER as *const u8;
    let buf_len = (&raw const WITNESS_BUFFER as *const [u8; 1024]).cast::<u8>();
    let _ = buf_len; // suppress unused warning on non-RV builds
    // SAFETY: WITNESS_BUFFER is a 1024-byte static; pointer arithmetic
    // up to 1024 bytes stays in-bounds. `read_volatile` so the read
    // isn't elided when the buffer is initially all-zero.
    let public_len = unsafe { core::ptr::read_volatile(buf_ptr as *const u32) } as usize;
    if public_len == 0 || public_len + 4 + 4 > 1024 {
        return None;
    }
    let public_bytes = unsafe {
        let mut v = Vec::with_capacity(public_len);
        for i in 0..public_len {
            v.push(core::ptr::read_volatile(buf_ptr.add(4 + i)));
        }
        v
    };
    let secret_len_off = 4 + public_len;
    let secret_len = unsafe {
        core::ptr::read_volatile(buf_ptr.add(secret_len_off) as *const u32)
    } as usize;
    if secret_len == 0 || secret_len_off + 4 + secret_len > 1024 {
        return None;
    }
    let secret_bytes = unsafe {
        let mut v = Vec::with_capacity(secret_len);
        for i in 0..secret_len {
            v.push(core::ptr::read_volatile(buf_ptr.add(secret_len_off + 4 + i)));
        }
        v
    };
    let public =
        vos::rkyv::from_bytes::<Public, vos::rkyv::rancor::Error>(&public_bytes).ok()?;
    let secret =
        vos::rkyv::from_bytes::<Secret, vos::rkyv::rancor::Error>(&secret_bytes).ok()?;
    Some((public, secret))
}

/// Fallback hardcoded (Public, Secret). Bytes are chosen so `check`
/// passes: `amount_commit == Pedersen(amount, blinding)` and
/// `sender_balance_before >= amount`. Used when the static buffer
/// hasn't been patched (regular invocation outside the prover).
fn hardcoded_witness() -> (Public, Secret) {
    let amount: u64 = 100;
    let amount_blinding =
        Blinding::from_bytes([2u8; 32]).expect("[2u8; 32] is a canonical Ristretto scalar");
    let amount_commit = Amount::commit(amount, &amount_blinding);
    let public = Public {
        issuer: AuthKey([0x11u8; 32]),
        amount_commit,
        state_root_before: [0xAAu8; 32],
        state_root_after: [0xBBu8; 32],
    };
    let secret = Secret {
        amount,
        amount_blinding,
        sender_balance_before: 1_000,
    };
    (public, secret)
}
