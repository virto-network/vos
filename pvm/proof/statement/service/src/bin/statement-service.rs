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
//! - **Accumulate** reads `E(t, s, n)`, then takes the inputs one at a
//!   time: it fetches an input's operand up to its authorizer's trace,
//!   which it never reads (`fetch` kind 15, twice: the head, then up to
//!   the result's end), applies it (`vos_statement_service::accumulate::
//!   take`) with `read` and `write`, calls `checkpoint`, so a later item
//!   that runs the invocation out of gas or memory reverts from there, and
//!   frees what the item allocated. Then it drops the rows past their hour
//!   and writes the gas it took by its own count under `state::keys::GAS`.
//!
//! The deployment's constants are [`CONFIG`], a block of read-only data
//! `vos_statement_service::config::configure` fills in the linked program.
//! Unset or undecodable, refine refuses every item and accumulate applies
//! none.

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

use runtime::{Call, FetchKind, HEAP, NONE, Output, STACK_BYTES, gas_left};
use vos_abi::jam::{Operand, RefineArgs};
use vos_pvm_program::read_nat;
use vos_statement_service::accumulate::{finish, take, time};
use vos_statement_service::config::{self, Config};
use vos_statement_service::refine::{Extrinsics, refine, refine_unconfigured, venue};
use vos_statement_service::state::{Storage, keys};
use vos_statement_service::verdict::{RegisterCode, Verdict};

entries!("_start" => "refine_main", "accumulate" => "accumulate_main");

/// The deployment's constants, as `config::configure` set them in the
/// linked program; [`config::UNSET`] as built, which configures nothing.
#[used]
#[unsafe(no_mangle)]
static CONFIG: [u8; config::BYTES] = config::UNSET;

/// The deployment's constants: none when the block is unset or does not
/// decode, and the service then refuses every item and holds no state.
fn config() -> Option<Config> {
    // SAFETY: a read of an initialised static; volatile, so the block is
    // read as the linked program holds it, never folded from `UNSET`.
    let block = unsafe { core::ptr::read_volatile(&raw const CONFIG) };
    config::configured(&block)
}

// ── Host calls ───────────────────────────────────────────────────────────

/// `read`'s service: the running one.
const SELF_SERVICE: u64 = u64::MAX;

/// The value `fetch` of `kind` and index `index` serves, all `len` bytes of
/// it: none when the host writes another count.
fn fetch_exact(kind: FetchKind, index: u64, len: usize) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    let got = hostcall!(
        Call::Fetch,
        [
            bytes.as_mut_ptr() as u64,
            0,
            len as u64,
            kind as u64,
            index,
            0
        ]
    );
    if got != len as u64 {
        return None;
    }
    // SAFETY: the host wrote all `len` bytes.
    unsafe { bytes.set_len(len) };
    Some(bytes)
}

/// The first `len` bytes of the value `fetch` of `kind` and index `index`
/// serves, or all of a shorter one, and the whole value's length: none
/// when there is none.
fn fetch_prefix(kind: FetchKind, index: u64, len: usize) -> Option<(Vec<u8>, usize)> {
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    let whole = hostcall!(
        Call::Fetch,
        [
            bytes.as_mut_ptr() as u64,
            0,
            len as u64,
            kind as u64,
            index,
            0
        ]
    );
    let whole = usize::try_from(whole).ok().filter(|_| whole != NONE)?;
    // SAFETY: the host wrote the value's first `min(len, whole)` bytes.
    unsafe { bytes.set_len(len.min(whole)) };
    Some((bytes, whole))
}

/// Accumulate's input `index` as the operand it holds, its authorizer's
/// trace not fetched: none for a deferred transfer, or for bytes that are
/// no input.
fn input_operand(index: u64) -> Option<Operand> {
    // The input's kind byte, then its operand's head; the rest up to the
    // result's end, which the input must hold.
    let (head, whole) = fetch_prefix(FetchKind::Input, index, 1 + Operand::HEAD)?;
    if *head.first()? != 0 {
        return None;
    }
    let end = Operand::untraced_len(head.get(1..)?)?.checked_add(1)?;
    if end > whole {
        return None;
    }
    let bytes = if end <= head.len() {
        head
    } else {
        fetch_prefix(FetchKind::Input, index, end)?.0
    };
    Operand::decode_untraced(bytes.get(1..end)?)
}

/// `checkpoint`: what the invocation wrote so far stands should a later
/// part of it run out of gas or trap.
fn checkpoint() {
    hostcall!(Call::Checkpoint, [0; 6]);
}

/// The length of the value `fetch` of `kind` and index `index` serves,
/// asking for none of it.
fn fetch_len(kind: FetchKind, index: u64) -> Option<usize> {
    let mut none = [0u8; 1];
    let len = hostcall!(
        Call::Fetch,
        [none.as_mut_ptr() as u64, 0, 0, kind as u64, index, 0]
    );
    (len != NONE).then(|| usize::try_from(len).ok()).flatten()
}

/// The running item's first extrinsic: the statement's proof.
struct Proof;

impl Extrinsics for Proof {
    fn proof_len(&mut self) -> Option<usize> {
        fetch_len(FetchKind::OurExtrinsic, 0)
    }

    fn proof(&mut self, len: usize) -> Vec<u8> {
        fetch_exact(FetchKind::OurExtrinsic, 0, len).unwrap_or_default()
    }
}

/// The service's storage, through `read` and `write`.
struct Service;

impl Storage for Service {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let len = hostcall!(
            Call::Read,
            [SELF_SERVICE, key.as_ptr() as u64, key.len() as u64, 0, 0, 0]
        );
        let len = usize::try_from(len).ok().filter(|_| len != NONE)?;
        let mut value: Vec<u8> = Vec::with_capacity(len);
        let got = hostcall!(
            Call::Read,
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
    /// traps, so the accumulate reverts from the last checkpoint, the item
    /// being applied and those after it: no outcome lands without the rows
    /// it reports.
    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        let value = value.unwrap_or_default();
        let answer = hostcall!(
            Call::Write,
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

/// # Safety
///
/// The host maps the argument window at (`args`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn refine_main(args: *const u8, len: u64) -> Output {
    let start = gas_left();
    // SAFETY: see the function's contract.
    let args = unsafe { core::slice::from_raw_parts(args, len as usize) };
    let config = config();
    let service = RefineArgs::decode(args).and_then(|args| {
        let service = u32::try_from(args.service).ok()?;
        Some((service, args.payload))
    });
    let mut output = match (config, service) {
        (None, service) => {
            refine_unconfigured(service.as_ref().map_or(&[][..], |(_, payload)| payload))
        }
        (Some(config), Some((service, payload))) => {
            refine(&config, venue(&config, service), &payload, &mut Proof)
        }
        (_, None) => Verdict::Refused {
            kind: None,
            code: RegisterCode::Item as u32,
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
    let parsed = read_nat(args, 0).and_then(|(slot, at)| {
        let (service, used) = read_nat(args, at)?;
        let (count, _) = read_nat(args, at.checked_add(used)?)?;
        Some((slot, u32::try_from(service).ok()?, count))
    });
    if let (Some(config), Some((slot, service, count))) = (config(), parsed) {
        let venue = venue(&config, service);
        let now = time(&config, slot);
        let mut taken = 0usize;
        for index in 0..count {
            let mark = HEAP.mark();
            if let Some(operand) = input_operand(index) {
                take(&mut Service, venue, now, &operand);
                taken = taken.saturating_add(1);
            }
            checkpoint();
            // SAFETY: what the item allocated was dropped with it, and
            // nothing allocated before it was freed.
            unsafe { HEAP.reset(mark) };
        }
        finish(&mut Service, now, taken);
    }
    let gas = start.saturating_sub(gas_left());
    Service.write(keys::GAS, Some(&gas.to_le_bytes()));
    Output { address: 0, len: 0 }
}
