//! A program's heap: power-of-two size classes over an arena, each with a
//! free list, so short-lived allocations cost a few instructions and freed
//! memory is reused. Blocks past the largest class go on one first-fit
//! list. Fresh memory is bumped from the arena's start. In an actor's
//! program (`ACTOR`) a handler or a kernel, whose program holds only the
//! arena's first [`vos_wire::abi::INVOCATION_HEAP`] bytes, is given none
//! past them: its allocation fails there, and the invocation traps. A
//! workflow, whose machine maps the whole arena, marks itself so
//! ([`whole_arena`]) before it allocates. Pages a program never touches
//! cost nothing to run, but the pool prices a machine by its mapped pages,
//! so the arena is sized per program: [`crate::program_runtime!`] takes it.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

/// Classes 16 B ..= 128 KiB.
const SMALLEST: u32 = 4;
const CLASSES: usize = 14;
const LARGEST: usize = 1 << (SMALLEST as usize + CLASSES - 1);
const PAGE: usize = 4096;

/// Whether the running invocation maps its actor's whole arena: a
/// workflow's does, a handler's and a kernel's hold its first
/// [`vos_wire::abi::INVOCATION_HEAP`] bytes.
struct Whole(UnsafeCell<bool>);

// SAFETY: a program runs on one thread.
unsafe impl Sync for Whole {}

static WHOLE: Whole = Whole(UnsafeCell::new(false));

/// Mark the running invocation a workflow's, whose machine maps its actor's
/// whole arena: the heap gives it all of it. A workflow's entry calls it
/// before it allocates; its snapshot keeps the mark.
pub fn whole_arena() {
    // SAFETY: single-threaded.
    unsafe { *WHOLE.0.get() = true };
}

/// Whether the running invocation was marked a workflow's.
fn whole() -> bool {
    // SAFETY: single-threaded.
    unsafe { *WHOLE.0.get() }
}

struct State {
    /// The next untouched byte of the arena.
    next: usize,
    /// Free blocks per class: each holds the next one's address, or 0.
    free: [usize; CLASSES],
    /// Free blocks past the largest class, each starting with the next
    /// one's address and its own size.
    large: usize,
}

/// `ARENA` bytes a heap allocates from, page-aligned.
#[repr(C, align(4096))]
pub struct Arena<const ARENA: usize>(UnsafeCell<[u8; ARENA]>);

// SAFETY: a program runs on one thread.
unsafe impl<const ARENA: usize> Sync for Arena<ARENA> {}

impl<const ARENA: usize> Default for Arena<ARENA> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ARENA: usize> Arena<ARENA> {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; ARENA]))
    }
}

/// A heap over an arena of `ARENA` bytes, its state apart from it. An
/// actor program's (`ACTOR`) gives a handler or a kernel the arena's first
/// [`vos_wire::abi::INVOCATION_HEAP`] bytes alone, a workflow marked
/// ([`whole_arena`]) all of it; any other program's, all of it.
pub struct Heap<const ARENA: usize, const ACTOR: bool = false> {
    arena: &'static Arena<ARENA>,
    state: UnsafeCell<State>,
}

// SAFETY: a program runs on one thread.
unsafe impl<const ARENA: usize, const ACTOR: bool> Sync for Heap<ARENA, ACTOR> {}

/// A block's class, from its size and alignment; `None` past the largest.
fn class(layout: &Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()).max(1 << SMALLEST);
    (size <= LARGEST).then(|| (size.next_power_of_two().trailing_zeros() - SMALLEST) as usize)
}

impl<const ARENA: usize, const ACTOR: bool> Heap<ARENA, ACTOR> {
    pub const fn new(arena: &'static Arena<ARENA>) -> Self {
        Self {
            arena,
            state: UnsafeCell::new(State {
                next: 0,
                free: [0; CLASSES],
                large: 0,
            }),
        }
    }

    /// The arena bytes the running invocation may allocate.
    fn usable(&self) -> usize {
        if ACTOR && !whole() {
            ARENA.min(vos_wire::abi::INVOCATION_HEAP)
        } else {
            ARENA
        }
    }

    /// Fresh arena bytes, aligned as asked; null past what the invocation
    /// maps of the arena.
    fn bump(&self, size: usize, align: usize) -> *mut u8 {
        // SAFETY: single-threaded.
        let state = unsafe { &mut *self.state.get() };
        let base = self.arena.0.get() as usize;
        let start = (base + state.next).next_multiple_of(align) - base;
        match start.checked_add(size) {
            Some(end) if end <= self.usable() => {
                state.next = end;
                (base + start) as *mut u8
            }
            _ => core::ptr::null_mut(),
        }
    }
}

unsafe impl<const ARENA: usize, const ACTOR: bool> GlobalAlloc for Heap<ARENA, ACTOR> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: single-threaded.
        let state = unsafe { &mut *self.state.get() };
        match class(&layout) {
            Some(class) => {
                let head = state.free[class];
                if head != 0 {
                    // SAFETY: a free block's first word links the next one.
                    state.free[class] = unsafe { *(head as *const usize) };
                    return head as *mut u8;
                }
                let size = 1usize << (class as u32 + SMALLEST);
                self.bump(size, size.min(PAGE))
            }
            None => {
                let size = layout.size().next_multiple_of(PAGE);
                let mut previous: *mut usize = &mut state.large;
                // SAFETY: the list links blocks this heap freed, each
                // starting with its next link and its size.
                unsafe {
                    while *previous != 0 {
                        let block = *previous as *mut usize;
                        if *block.add(1) >= size {
                            *previous = *block;
                            return block.cast();
                        }
                        previous = block;
                    }
                }
                self.bump(size, PAGE)
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: single-threaded; `ptr` came from `alloc` with `layout`.
        let state = unsafe { &mut *self.state.get() };
        match class(&layout) {
            Some(class) => {
                // SAFETY: the block holds at least 16 bytes and is free.
                unsafe { *(ptr as *mut usize) = state.free[class] };
                state.free[class] = ptr as usize;
            }
            None => {
                let block = ptr as *mut usize;
                // SAFETY: as above, with room for the two-word header.
                unsafe {
                    *block = state.large;
                    *block.add(1) = layout.size().next_multiple_of(PAGE);
                }
                state.large = ptr as usize;
            }
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the new layout keeps the old alignment.
        let grown = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // A block of the same class already fits.
        if class(&layout).is_some() && class(&layout) == class(&grown) {
            return ptr;
        }
        // SAFETY: GlobalAlloc's contract.
        let new = unsafe { self.alloc(grown) };
        if !new.is_null() {
            // SAFETY: both blocks hold at least the smaller size.
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ARENA: Arena<{ 1 << 20 }> = Arena::new();
    static HEAP: Heap<{ 1 << 20 }> = Heap::new(&ARENA);

    #[test]
    fn freed_blocks_are_reused_and_a_handler_holds_the_invocation_heap() {
        let heap = &HEAP;
        let small = Layout::from_size_align(24, 8).unwrap();
        // SAFETY: allocations of nonzero size, freed with their layouts.
        unsafe {
            let a = heap.alloc(small);
            let b = heap.alloc(small);
            assert_ne!(a, b);
            assert_eq!(a as usize % 32, 0, "a block aligns to its class");
            heap.dealloc(a, small);
            assert_eq!(heap.alloc(small), a, "the class's free list");

            let large = Layout::from_size_align(200 << 10, 8).unwrap();
            let c = heap.alloc(large);
            heap.dealloc(c, large);
            let smaller = Layout::from_size_align(150 << 10, 8).unwrap();
            assert_eq!(heap.alloc(smaller), c, "first fit");

            let grown = heap.realloc(b, small, 30);
            assert_eq!(grown, b, "the same class grows in place");
            let moved = heap.realloc(b, Layout::from_size_align(30, 8).unwrap(), 100);
            assert_ne!(moved, b);

            let huge = Layout::from_size_align(2 << 20, 8).unwrap();
            assert!(heap.alloc(huge).is_null(), "past the arena");
        }
        // One test alone marks the invocation, which every heap reads.
        only_a_workflow_allocates_past_the_invocation_heap();
    }

    /// A handler or a kernel is given the arena's first 512 KiB alone; a
    /// workflow, marked, the whole arena.
    fn only_a_workflow_allocates_past_the_invocation_heap() {
        static ARENA: Arena<{ 2 << 20 }> = Arena::new();
        static HEAP: Heap<{ 2 << 20 }, true> = Heap::new(&ARENA);
        static PROGRAM_ARENA: Arena<{ 2 << 20 }> = Arena::new();
        static PROGRAM: Heap<{ 2 << 20 }> = Heap::new(&PROGRAM_ARENA);
        let past = Layout::from_size_align(vos_wire::abi::INVOCATION_HEAP + 1, 8).unwrap();
        let within = Layout::from_size_align(vos_wire::abi::INVOCATION_HEAP, 8).unwrap();
        // SAFETY: allocations of nonzero size.
        unsafe {
            assert!(!PROGRAM.alloc(past).is_null(), "a program's heap is whole");
            assert!(HEAP.alloc(past).is_null(), "a handler's heap ends there");
            assert!(!HEAP.alloc(within).is_null());
            whole_arena();
            assert!(!HEAP.alloc(past).is_null(), "a workflow's does not");
        }
    }
}
