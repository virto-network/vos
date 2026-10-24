//! The guests' allocator (`src/bin/guest/heap.rs`), on the host over a
//! small arena: blocks aligned, the last block reclaimed, in LIFO order, a
//! block at the top grown or shrunk in place, one below it moved above it,
//! the peak kept, and no block past the arena.

use std::alloc::{GlobalAlloc, Layout};

#[allow(dead_code)]
#[path = "../src/bin/guest/heap.rs"]
mod heap;

use heap::Heap;

const N: usize = 4096;

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

#[test]
fn blocks_are_aligned() {
    let heap = Box::new(Heap::<N>::new());
    unsafe {
        let byte = heap.alloc(layout(1, 1));
        for align in [2, 8, 64, 256] {
            let block = heap.alloc(layout(8, align));
            assert_eq!(block as usize % align, 0, "{align}");
            assert!(block > byte);
        }
    }
}

#[test]
fn the_last_block_is_reclaimed_in_lifo_order() {
    let heap = Box::new(Heap::<N>::new());
    unsafe {
        let a = heap.alloc(layout(16, 8));
        let b = heap.alloc(layout(32, 8));
        let c = heap.alloc(layout(64, 8));
        assert_eq!(heap.state().top, 112);
        // Not the last: nothing reclaimed.
        heap.dealloc(a, layout(16, 8));
        assert_eq!(heap.state().top, 112);
        heap.dealloc(c, layout(64, 8));
        assert_eq!(heap.state().top, 48);
        heap.dealloc(b, layout(32, 8));
        assert_eq!(heap.state().top, 16);
        assert_eq!(heap.peak_top(), 112);
        assert_eq!(heap.state().peak_live, 112);
        assert_eq!(heap.alloc(layout(8, 8)), b, "the reclaimed space reused");
    }
}

#[test]
fn a_block_at_the_top_grows_in_place() {
    let heap = Box::new(Heap::<N>::new());
    unsafe {
        let block = heap.alloc(layout(16, 8));
        block.write_bytes(7, 16);
        let grown = heap.realloc(block, layout(16, 8), 1024);
        assert_eq!(grown, block);
        assert_eq!(heap.state().top, 1024);
        assert_eq!(*grown.add(15), 7);
    }
}

#[test]
fn a_block_below_the_top_moves_above_it_to_shrink_or_grow() {
    let heap = Box::new(Heap::<N>::new());
    unsafe {
        let block = heap.alloc(layout(64, 8));
        block.write_bytes(9, 64);
        let above = heap.alloc(layout(8, 8));
        let shrunk = heap.realloc(block, layout(64, 8), 16);
        assert!(shrunk > above, "copied above the top");
        assert_eq!(*shrunk.add(15), 9);
        assert_eq!(heap.state().top, 72 + 16);
        let grown = heap.realloc(shrunk, layout(16, 8), 128);
        assert_eq!(grown, shrunk, "now the last block, grown in place");
        assert_eq!(*grown.add(15), 9);
        assert_eq!(heap.state().top, 72 + 128);
    }
}

#[test]
fn the_last_block_shrunk_gives_its_tail_back() {
    let heap = Box::new(Heap::<N>::new());
    unsafe {
        let block = heap.alloc(layout(256, 8));
        assert_eq!(heap.realloc(block, layout(256, 8), 32), block);
        assert_eq!(heap.state().top, 32);
        assert_eq!(heap.peak_top(), 256);
        heap.dealloc(block, layout(32, 8));
        assert_eq!(heap.state().top, 0);
    }
}

#[test]
fn an_exhausted_arena_answers_null() {
    let heap = Box::new(Heap::<N>::new());
    unsafe {
        let block = heap.alloc(layout(N - 8, 8));
        assert!(!block.is_null());
        assert!(heap.alloc(layout(16, 8)).is_null());
        assert!(heap.realloc(block, layout(N - 8, 8), N + 8).is_null());
        assert!(!heap.alloc(layout(8, 8)).is_null(), "what fits still does");
    }
}
