use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

const HEAP_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct BumpHeap {
    arena: UnsafeCell<[u8; HEAP_SIZE]>,
    offset: UnsafeCell<usize>,
}

unsafe impl Sync for BumpHeap {}

impl BumpHeap {
    const fn new() -> Self {
        Self {
            arena: UnsafeCell::new([0; HEAP_SIZE]),
            offset: UnsafeCell::new(0),
        }
    }
}

unsafe impl GlobalAlloc for BumpHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let offset = unsafe { &mut *self.offset.get() };
        let align = layout.align();
        let aligned = (*offset + align - 1) & !(align - 1);
        let end = aligned + layout.size();
        if end > HEAP_SIZE {
            return core::ptr::null_mut();
        }
        *offset = end;
        unsafe { (self.arena.get() as *mut u8).add(aligned) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // bump allocator never frees
    }
}

#[global_allocator]
static HEAP: BumpHeap = BumpHeap::new();
