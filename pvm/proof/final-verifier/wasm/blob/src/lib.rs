//! The final verifier and the venue's check over it as a runtime-style
//! Wasm blob.
//!
//! Exports, called the way a runtime API is (the host allocates the input
//! with the runtime's allocator and passes `(ptr, len)`):
//! - `verify(ptr, len) -> u32`, the input the 24 public words (each a
//!   little-endian `u32`), then the wrap proof (postcard): 1 accept, 0
//!   refuse, 2 undecodable, 3 a short input;
//! - `decode(ptr, len) -> u32`: the decode alone, 1 if it decodes;
//! - `judge(ptr, len) -> u32`, the input a judgement's
//!   (`vos_statement::model::judge_bytes`): its code, 0 accepted; the
//!   accepted statement's id is then at `statement_id()`, 32 bytes.
//!
//! Blake2b-256 is computed in the blob.

#![no_std]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

use vos_final_verifier::PUBLIC_WORDS;

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

// The same alignment scheme as `sp_io::global_alloc_wasm`: the host aligns
// to 8, larger alignments are padded and the offset kept just before the
// returned pointer. `realloc` is GlobalAlloc's default (allocate, copy,
// free), as there.
unsafe impl GlobalAlloc for RuntimeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        let ptr = unsafe { ext_allocator_malloc_version_1((size + align.saturating_sub(8)) as u32) }
            as *mut u8;
        let offset = ptr.align_offset(align);
        if offset > Offset::MAX as usize || ptr.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: the host allocated `size + align - 8` bytes from `ptr`.
        unsafe {
            let ptr = ptr.add(offset);
            (ptr.sub(OFFSET_LENGTH) as *mut Offset).write_unaligned(offset as Offset);
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        // SAFETY: `ptr` came from `alloc`, its offset just before it.
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

fn input<'a>(ptr: u32, len: u32) -> &'a [u8] {
    // SAFETY: the host wrote `len` bytes at `ptr` in this instance's memory.
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// The input's words and its proof's bytes.
fn split(bytes: &[u8]) -> Option<([u32; PUBLIC_WORDS], &[u8])> {
    let (words, proof) = bytes.split_at_checked(4 * PUBLIC_WORDS)?;
    let words =
        core::array::from_fn(|i| u32::from_le_bytes(words[4 * i..4 * i + 4].try_into().unwrap()));
    Some((words, proof))
}

#[unsafe(no_mangle)]
pub extern "C" fn verify(ptr: u32, len: u32) -> u32 {
    let Some((words, proof)) = split(input(ptr, len)) else {
        return 3;
    };
    let Ok(proof) = vos_final_verifier::decode(proof) else {
        return 2;
    };
    match vos_final_verifier::verify(proof, &words) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn decode(ptr: u32, len: u32) -> u32 {
    split(input(ptr, len)).is_some_and(|(_, proof)| vos_final_verifier::decode(proof).is_ok())
        as u32
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
