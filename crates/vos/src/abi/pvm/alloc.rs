use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

const HEAP_SIZE: usize = 64 * 1024;

/// Minimum block size: must fit a `FreeNode` (2 × usize = 16 bytes on rv64).
const MIN_BLOCK: usize = core::mem::size_of::<FreeNode>();

/// Prepended immediately before the returned payload pointer.
/// Stores enough to recover the original block on dealloc.
#[repr(C)]
struct AllocHeader {
    /// Pointer to the start of the block (may differ from header due to
    /// alignment padding between block start and payload).
    block_start: *mut u8,
    /// Total block size (from block_start).
    block_size: usize,
}

const HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// Node in the sorted-by-address free list.
#[repr(C)]
struct FreeNode {
    size: usize,
    next: *mut FreeNode,
}

/// Linked-list free-list allocator over a fixed 64 KiB arena.
///
/// - First-fit allocation with block splitting.
/// - Deallocation with immediate coalescing of adjacent free blocks.
/// - Single-threaded (PVM guarantee).
#[repr(C, align(16))]
struct FreeListHeap {
    arena: UnsafeCell<[u8; HEAP_SIZE]>,
    head: UnsafeCell<*mut FreeNode>,
    initialised: UnsafeCell<bool>,
}

unsafe impl Sync for FreeListHeap {}

impl FreeListHeap {
    const fn new() -> Self {
        Self {
            arena: UnsafeCell::new([0; HEAP_SIZE]),
            head: UnsafeCell::new(core::ptr::null_mut()),
            initialised: UnsafeCell::new(false),
        }
    }

    unsafe fn ensure_init(&self) {
        let init = unsafe { &mut *self.initialised.get() };
        if *init {
            return;
        }
        *init = true;
        let base = self.arena.get() as *mut u8;
        let node = base as *mut FreeNode;
        unsafe {
            (*node).size = HEAP_SIZE;
            (*node).next = core::ptr::null_mut();
        }
        *unsafe { &mut *self.head.get() } = node;
    }
}

unsafe impl GlobalAlloc for FreeListHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.ensure_init() };

        let payload_align = layout.align().max(HEADER_SIZE); // at least header-aligned
        let payload_size = layout.size();

        let head = unsafe { &mut *self.head.get() };
        let mut prev: *mut FreeNode = core::ptr::null_mut();
        let mut cur: *mut FreeNode = *head;

        while !cur.is_null() {
            let block = cur as *mut u8;
            let block_size = unsafe { (*cur).size };
            let next = unsafe { (*cur).next };

            // The payload goes at the first aligned address that leaves
            // room for the header before it.
            let earliest_payload = (block as usize) + HEADER_SIZE;
            let payload_addr = (earliest_payload + payload_align - 1) & !(payload_align - 1);
            let end = payload_addr + payload_size;
            let used = end - block as usize;

            if used > block_size {
                prev = cur;
                cur = next;
                continue;
            }

            let used = used.max(MIN_BLOCK);
            let remainder = block_size - used;

            if remainder >= MIN_BLOCK {
                // Split: create a free node in the leftover space.
                let leftover = unsafe { block.add(used) } as *mut FreeNode;
                unsafe {
                    (*leftover).size = remainder;
                    (*leftover).next = next;
                }
                if prev.is_null() {
                    *head = leftover;
                } else {
                    unsafe { (*prev).next = leftover; }
                }
            } else {
                // Use entire block (no split).
                if prev.is_null() {
                    *head = next;
                } else {
                    unsafe { (*prev).next = next; }
                }
            }

            // Write header immediately before the payload.
            let header = (payload_addr - HEADER_SIZE) as *mut AllocHeader;
            let actual_block_size = if remainder >= MIN_BLOCK { used } else { block_size };
            unsafe {
                (*header).block_start = block;
                (*header).block_size = actual_block_size;
            }

            return payload_addr as *mut u8;
        }

        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let header = unsafe { &*((ptr as usize - HEADER_SIZE) as *const AllocHeader) };
        let block = header.block_start;
        let size = header.block_size;

        // Insert into the free list in address order, then coalesce.
        let head = unsafe { &mut *self.head.get() };
        let mut prev: *mut FreeNode = core::ptr::null_mut();
        let mut cur: *mut FreeNode = *head;

        // Find insertion point (sorted by address).
        while !cur.is_null() && (cur as *mut u8) < block {
            prev = cur;
            cur = unsafe { (*cur).next };
        }

        // Create a free node at block.
        let node = block as *mut FreeNode;
        unsafe {
            (*node).size = size;
            (*node).next = cur;
        }
        if prev.is_null() {
            *head = node;
        } else {
            unsafe { (*prev).next = node; }
        }

        // Coalesce with next neighbour.
        if !cur.is_null() {
            let node_end = unsafe { block.add((*node).size) };
            if node_end == cur as *mut u8 {
                unsafe {
                    (*node).size += (*cur).size;
                    (*node).next = (*cur).next;
                }
            }
        }

        // Coalesce with previous neighbour.
        if !prev.is_null() {
            let prev_end = unsafe { (prev as *mut u8).add((*prev).size) };
            if prev_end == block {
                unsafe {
                    (*prev).size += (*node).size;
                    (*prev).next = (*node).next;
                }
            }
        }
    }
}

#[global_allocator]
static HEAP: FreeListHeap = FreeListHeap::new();
