//! The final verifier and the venue's check over it as a runtime-style
//! Wasm blob, linking `format::MASKED_WRAP`.
//!
//! Exports, called the way a runtime API is (the host allocates the input
//! with the runtime's allocator and passes `(ptr, len)`):
//! - `verify(ptr, len) -> u32`, the input the proof's format (a
//!   little-endian `u32`, one the blob links), the 24 public words (each a
//!   little-endian `u32`), then the wrap proof in its format's encoding: 1
//!   accept, 0 refuse, 2 undecodable, 3 a short input;
//! - `decode(ptr, len) -> u32`: the decode alone, 1 if it decodes;
//! - `judge(ptr, len) -> u32`, the input a judgement's
//!   (`vos_statement::model::judge_bytes`): its code, 0 accepted; the
//!   accepted statement's id is then at `statement_id()`, 32 bytes;
//! - `anchor_digests(ptr, len) -> u32`, the input a golden vector of
//!   `vos-anchor` (`vos_anchor::vectors::Vector`'s encoding): 1 when it
//!   decodes, its digests then at `digests()`, 160 bytes; 0 otherwise.
//!
//! Blake2b-256 is computed in the blob.

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

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

use vos_pvm_final_verifier::PUBLIC_WORDS;

// ── sp-io's host allocator ABI, as `RuntimeAllocator` uses it ───────────

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn ext_allocator_malloc_version_1(size: u32) -> u32;
    fn ext_allocator_free_version_1(ptr: u32);
}

struct RuntimeAllocator;

#[global_allocator]
static ALLOCATOR: RuntimeAllocator = RuntimeAllocator;

type Offset = u16;
const OFFSET_LENGTH: usize = core::mem::size_of::<Offset>();

/// The alignment the host's allocations have.
const HOST_ALIGN: usize = 8;

// The host aligns to 8: an allocation aligned to 8 or less is the host's
// own, with nothing before or after it. A larger alignment is padded by
// `align` bytes and the pointer moved past at least `OFFSET_LENGTH` of
// them to the next aligned address, the distance kept in the bytes just
// before it. `realloc` is GlobalAlloc's default (allocate, copy, free).
unsafe impl GlobalAlloc for RuntimeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        let padding = if align <= HOST_ALIGN { 0 } else { align };
        let Some(bytes) = size
            .checked_add(padding)
            .and_then(|bytes| u32::try_from(bytes).ok())
        else {
            return core::ptr::null_mut();
        };
        let ptr = unsafe { ext_allocator_malloc_version_1(bytes) } as *mut u8;
        if ptr.is_null() || padding == 0 {
            return ptr;
        }
        let Some(offset) = ptr
            .wrapping_add(OFFSET_LENGTH)
            .align_offset(align)
            .checked_add(OFFSET_LENGTH)
            .filter(|&offset| offset <= padding && offset <= Offset::MAX as usize)
        else {
            unsafe { ext_allocator_free_version_1(ptr as u32) };
            return core::ptr::null_mut();
        };
        // SAFETY: the host allocated `size + align` bytes from `ptr`, and
        // `OFFSET_LENGTH <= offset <= align`: the offset's bytes and the
        // `size` bytes after `ptr + offset` are within them.
        unsafe {
            let ptr = ptr.add(offset);
            (ptr.sub(OFFSET_LENGTH) as *mut Offset).write_unaligned(offset as Offset);
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.align() <= HOST_ALIGN {
            unsafe { ext_allocator_free_version_1(ptr as u32) };
            return;
        }
        // SAFETY: `ptr` came from `alloc` at this layout's alignment, its
        // offset in the bytes just before it.
        unsafe {
            let offset = (ptr.sub(OFFSET_LENGTH) as *const Offset).read_unaligned();
            ext_allocator_free_version_1(ptr.sub(offset as usize) as u32);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

// ── Exports ─────────────────────────────────────────────────────────────

/// The `len` bytes the host wrote at `ptr`: none for an empty input or a
/// null pointer, from which no slice may be made.
fn input<'a>(ptr: u32, len: u32) -> &'a [u8] {
    if ptr == 0 || len == 0 {
        return &[];
    }
    // SAFETY: the host wrote `len` bytes at `ptr`, not null, in this
    // instance's memory.
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// The input's format, its words and its proof's bytes.
fn split(bytes: &[u8]) -> Option<(u32, [u32; PUBLIC_WORDS], &[u8])> {
    let (format, bytes) = bytes.split_first_chunk::<4>()?;
    let (words, proof) = bytes.split_at_checked(4 * PUBLIC_WORDS)?;
    let (chunks, _) = words.as_chunks::<4>();
    let mut words = [0; PUBLIC_WORDS];
    for (word, bytes) in words.iter_mut().zip(chunks) {
        *word = u32::from_le_bytes(*bytes);
    }
    Some((u32::from_le_bytes(*format), words, proof))
}

fn decoded(format: u32, proof: &[u8]) -> Option<vos_pvm_final_verifier::Decoded> {
    vos_pvm_final_verifier::decode(format, vos_pvm_final_verifier::LINKED, proof).ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn verify(ptr: u32, len: u32) -> u32 {
    let Some((format, words, proof)) = split(input(ptr, len)) else {
        return 3;
    };
    let Some(proof) = decoded(format, proof) else {
        return 2;
    };
    match proof.verify(&words) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn decode(ptr: u32, len: u32) -> u32 {
    split(input(ptr, len)).is_some_and(|(format, _, proof)| decoded(format, proof).is_some()) as u32
}

/// The last accepted statement's id.
static mut STATEMENT_ID: [u8; 32] = [0; 32];

#[unsafe(no_mangle)]
pub extern "C" fn judge(ptr: u32, len: u32) -> u32 {
    let verdict = vos_statement::model::judge_bytes(input(ptr, len));
    if let Ok(id) = &verdict {
        // SAFETY: an instance runs one call at a time.
        unsafe { STATEMENT_ID = id.0 };
    }
    vos_statement::code(&verdict)
}

#[unsafe(no_mangle)]
pub extern "C" fn statement_id() -> u32 {
    core::ptr::addr_of!(STATEMENT_ID) as u32
}

/// The last golden vector's digests.
static mut DIGESTS: [u8; vos_anchor::vectors::Digests::BYTES] =
    [0; vos_anchor::vectors::Digests::BYTES];

#[unsafe(no_mangle)]
pub extern "C" fn anchor_digests(ptr: u32, len: u32) -> u32 {
    let Ok(vector) = vos_anchor::vectors::Vector::decode(input(ptr, len)) else {
        return 0;
    };
    // SAFETY: an instance runs one call at a time.
    unsafe { DIGESTS = vector.digests().to_bytes() };
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn digests() -> u32 {
    core::ptr::addr_of!(DIGESTS) as u32
}
