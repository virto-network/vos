//! The JAM statements service's program (`--features pvm-guest`, built by
//! `just check-no-std` for the PVM target): refine at instruction 0,
//! accumulate at instruction 5, each on the venue guests' runtime (its own
//! 1 MiB stack, a 64 MiB arena).
//!
//! - **Refine** reads its arguments, `E(c, i, s, ↕payload, H(p))`, judges
//!   the item (`vos_statement_service::refine`), reading a statement's
//!   proof from the item's first extrinsic (`fetch` kind 4), and returns
//!   the verdict's encoding then the gas it took by its own count (8,
//!   little-endian).
//! - **Accumulate** reads `E(t, s, n)`, fetches each input (`fetch` kind
//!   15), applies the operands (`vos_statement_service::accumulate`) with
//!   `read` and `write`, and writes the gas it took by its own count under
//!   `state::keys::GAS`.
//!
//! The deployment's constants are [`CONFIG`], a block of read-only data
//! `vos_statement_service::config::configure` fills in the linked program.

#![no_std]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
#![no_main]

extern crate alloc;

#[path = "../../../src/bin/guest/runtime.rs"]
#[macro_use]
mod runtime;

use alloc::vec::Vec;
use core::arch::global_asm;

use runtime::{STACK_BYTES, gas_left};
use vos_statement_service::accumulate::{Operand, accumulate};
use vos_statement_service::config::{self, Config};
use vos_statement_service::natural;
use vos_statement_service::refine::{Extrinsics, refine, venue};
use vos_statement_service::state::{Storage, keys};

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "lla t0, VERIFY_STACK",
    "li t1, {size}",
    "add sp, t0, t1",
    "jal ra, refine_main",
    "mv ra, s0",
    "ret",
    ".global accumulate",
    ".type accumulate, @function",
    "accumulate:",
    "mv s0, ra",
    "lla t0, VERIFY_STACK",
    "li t1, {size}",
    "add sp, t0, t1",
    "jal ra, accumulate_main",
    "mv ra, s0",
    "ret",
    size = const STACK_BYTES,
);

/// The deployment's constants, as `config::configure` set them in the
/// linked program; [`config::UNSET`] as built, which pins nothing.
#[used]
#[unsafe(no_mangle)]
static CONFIG: [u8; config::BYTES] = config::UNSET;

/// The deployment's constants: a block that does not decode pins nothing.
fn config() -> Config {
    // SAFETY: a read of an initialised static; volatile, so the block is
    // read as the linked program holds it, never folded from `UNSET`.
    let block = unsafe { core::ptr::read_volatile(&raw const CONFIG) };
    Config::decode(&block).unwrap_or(Config {
        genesis: [0; 32],
        genesis_ms: 0,
        pins: Vec::new(),
    })
}

// ── Host calls ───────────────────────────────────────────────────────────

const FETCH: u64 = 2;
const READ: u64 = 4;
const WRITE: u64 = 5;
const NONE: u64 = u64::MAX;
/// `fetch` kinds: the running item's extrinsic φ11, accumulate's input φ11.
const OUR_EXTRINSIC: u64 = 4;
const INPUT: u64 = 15;
/// `read`'s service: the running one.
const SELF_SERVICE: u64 = u64::MAX;

/// The whole of a value `fetch` of `kind` and index `index` serves: none
/// when there is none.
fn fetch(kind: u64, index: u64) -> Option<Vec<u8>> {
    let len = fetch_len(kind, index)?;
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    let got = hostcall!(
        FETCH,
        [bytes.as_mut_ptr() as u64, 0, len as u64, kind, index, 0]
    );
    if got != len as u64 {
        return None;
    }
    // SAFETY: the host wrote all `len` bytes.
    unsafe { bytes.set_len(len) };
    Some(bytes)
}

/// The length of the value `fetch` of `kind` and index `index` serves,
/// asking for none of it.
fn fetch_len(kind: u64, index: u64) -> Option<usize> {
    let mut none = [0u8; 1];
    let len = hostcall!(FETCH, [none.as_mut_ptr() as u64, 0, 0, kind, index, 0]);
    (len != NONE).then(|| usize::try_from(len).ok()).flatten()
}

/// The running item's first extrinsic: the statement's proof.
struct Proof;

impl Extrinsics for Proof {
    fn proof_len(&mut self) -> Option<usize> {
        fetch_len(OUR_EXTRINSIC, 0)
    }

    fn proof(&mut self, len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        let got = hostcall!(
            FETCH,
            [
                bytes.as_mut_ptr() as u64,
                0,
                len as u64,
                OUR_EXTRINSIC,
                0,
                0
            ]
        );
        if got != len as u64 {
            return Vec::new();
        }
        // SAFETY: the host wrote all `len` bytes.
        unsafe { bytes.set_len(len) };
        bytes
    }
}

/// The service's storage, through `read` and `write`.
struct Service;

impl Storage for Service {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let len = hostcall!(
            READ,
            [SELF_SERVICE, key.as_ptr() as u64, key.len() as u64, 0, 0, 0]
        );
        let len = usize::try_from(len).ok().filter(|_| len != NONE)?;
        let mut value: Vec<u8> = Vec::with_capacity(len);
        let got = hostcall!(
            READ,
            [
                SELF_SERVICE,
                key.as_ptr() as u64,
                key.len() as u64,
                value.as_mut_ptr() as u64,
                0,
                len as u64
            ]
        );
        if got != len as u64 {
            return None;
        }
        // SAFETY: the host wrote all `len` bytes.
        unsafe { value.set_len(len) };
        Some(value)
    }

    /// A write the host refuses (`FULL`: the service's balance below the
    /// threshold the write would raise, or anything but a length or `NONE`)
    /// traps, so the whole accumulate reverts: no outcome lands without
    /// the rows it reports.
    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        let value = value.unwrap_or_default();
        let answer = hostcall!(
            WRITE,
            [
                key.as_ptr() as u64,
                key.len() as u64,
                value.as_ptr() as u64,
                value.len() as u64,
                0,
                0
            ]
        );
        if answer != NONE && answer > u64::from(u32::MAX) {
            trap();
        }
    }

    fn corrupt(&mut self, _: &[u8]) -> ! {
        trap()
    }
}

/// Stop the invocation with a panic: on accumulate, every write reverts.
fn trap() -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { core::arch::asm!("unimp", options(noreturn)) }
}

// ── The entries ──────────────────────────────────────────────────────────

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

/// Refine's arguments: the service and the payload.
fn refine_args(args: &[u8]) -> Option<(u32, &[u8])> {
    let (_, at) = natural(args, 0)?;
    let (_, at) = natural(args, at)?;
    let (service, at) = natural(args, at)?;
    let (len, at) = natural(args, at)?;
    let end = at.checked_add(usize::try_from(len).ok()?)?;
    Some((u32::try_from(service).ok()?, args.get(at..end)?))
}

/// # Safety
///
/// The host maps the argument window at (`args`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn refine_main(args: *const u8, len: u64) -> Output {
    let start = gas_left();
    // SAFETY: see the function's contract.
    let args = unsafe { core::slice::from_raw_parts(args, len as usize) };
    let config = config();
    let mut output = match refine_args(args) {
        Some((service, payload)) => refine(&config, venue(&config, service), payload, &mut Proof),
        None => vos_statement_service::verdict::Verdict::Refused {
            kind: None,
            code: 1,
        },
    }
    .encode();
    output.extend_from_slice(&start.saturating_sub(gas_left()).to_le_bytes());
    let output = output.leak();
    Output {
        address: output.as_ptr() as u64,
        len: output.len() as u64,
    }
}

/// # Safety
///
/// The host maps the argument window at (`args`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn accumulate_main(args: *const u8, len: u64) -> Output {
    let start = gas_left();
    // SAFETY: see the function's contract.
    let args = unsafe { core::slice::from_raw_parts(args, len as usize) };
    let parsed = natural(args, 0).and_then(|(slot, at)| {
        let (service, at) = natural(args, at)?;
        let (count, _) = natural(args, at)?;
        Some((slot, u32::try_from(service).ok()?, count))
    });
    if let Some((slot, service, count)) = parsed {
        let operands: Vec<Operand> = (0..count)
            .filter_map(|index| fetch(INPUT, index))
            .filter_map(|input| Operand::decode_input(&input))
            .collect();
        let config = config();
        let venue = venue(&config, service);
        accumulate(&config, venue, slot, &operands, &mut Service);
    }
    let gas = start.saturating_sub(gas_left());
    Service.write(keys::GAS, Some(&gas.to_le_bytes()));
    Output { address: 0, len: 0 }
}
