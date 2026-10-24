//! The guests' allocator: a bump over an arena of `N` bytes.
//!
//! An invocation verifies one proof, or applies one block's operands, and
//! ends: what it frees is reclaimed only when it is the arena's last block,
//! so an allocation is a few instructions, which on the PVM's per-block gas
//! is most of what a decode costs.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

#[repr(C, align(4096))]
struct Arena<const N: usize>([u8; N]);

/// What the allocator has handed out.
pub struct State {
    /// The bump offset into the arena: where the next block starts.
    pub top: usize,
    /// The highest `top` held before it last fell: kept as it falls, which
    /// is rarer than it rises.
    fallen_from: usize,
    live: usize,
    /// The most bytes live at once.
    pub peak_live: usize,
    pub allocs: usize,
}

pub struct Heap<const N: usize> {
    arena: UnsafeCell<Arena<N>>,
    state: UnsafeCell<State>,
}

// SAFETY: a PVM invocation is single-threaded.
unsafe impl<const N: usize> Sync for Heap<N> {}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`) and \
              arena offsets below `N`, and a free never exceeds what is live"
)]
impl<const N: usize> Heap<N> {
    pub const fn new() -> Self {
        Self {
            arena: UnsafeCell::new(Arena([0; N])),
            state: UnsafeCell::new(State {
                top: 0,
                fallen_from: 0,
                live: 0,
                peak_live: 0,
                allocs: 0,
            }),
        }
    }

    fn base(&self) -> usize {
        self.arena.get() as usize
    }

    #[allow(clippy::mut_from_ref)]
    pub fn state(&self) -> &mut State {
        // SAFETY: single-threaded, and no borrow outlives a call.
        unsafe { &mut *self.state.get() }
    }

    /// Whether the block of `bytes` at `ptr` is the arena's last.
    fn is_last(&self, ptr: *mut u8, bytes: usize) -> bool {
        ptr as usize + bytes == self.base() + self.state().top
    }

    /// Move the top to `top`, the height it leaves kept should it fall: a
    /// max without a branch, as a branch ends a block of the PVM's gas.
    fn move_top(&self, top: usize) {
        let state = self.state();
        let (kept, from) = (state.fallen_from, state.top);
        let higher = usize::from(kept < from).wrapping_neg();
        state.fallen_from = kept ^ ((kept ^ from) & higher);
        state.top = top;
    }

    /// The highest top reached: how much of the arena an invocation
    /// touched.
    #[allow(
        dead_code,
        reason = "the statements service reports no high-water mark"
    )]
    pub fn peak_top(&self) -> usize {
        let state = self.state();
        state.fallen_from.max(state.top)
    }

    fn account(&self, grow: usize, shrink: usize) {
        let state = self.state();
        state.live = state.live + grow - shrink;
        state.peak_live = state.peak_live.max(state.live);
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`) and \
              arena offsets below `N`, and a free never exceeds what is live"
)]
unsafe impl<const N: usize> GlobalAlloc for Heap<N> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let state = self.state();
        state.allocs += 1;
        let base = self.base();
        let start = (base + state.top).next_multiple_of(layout.align()) - base;
        let end = start + layout.size();
        if end > N {
            return core::ptr::null_mut();
        }
        state.top = end;
        self.account(layout.size(), 0);
        (base + start) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.account(0, layout.size());
        if self.is_last(ptr, layout.size()) {
            self.move_top(self.state().top - layout.size());
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let top = self.state().top;
        if self.is_last(ptr, layout.size()) && top - layout.size() + new_size <= N {
            self.move_top(top - layout.size() + new_size);
            self.account(new_size, layout.size());
            return ptr;
        }
        // SAFETY: as GlobalAlloc::realloc's default.
        unsafe {
            let new = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !new.is_null() {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            new
        }
    }
}
