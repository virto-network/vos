/// Marker trait for types that can be returned as a message reply.
pub trait Reply {}

// Common reply types
impl Reply for () {}
impl Reply for bool {}
impl Reply for u8 {}
impl Reply for u16 {}
impl Reply for u32 {}
impl Reply for u64 {}
impl Reply for i8 {}
impl Reply for i16 {}
impl Reply for i32 {}
impl Reply for i64 {}

/// A slot where a reply will be written. The caller holds the read side,
/// the handler writes into it. No allocation — this is a fixed memory location.
pub struct ReplySender<R> {
    slot: *mut Option<R>,
}

impl<R> ReplySender<R> {
    /// Create a new reply sender pointing to the given slot.
    ///
    /// # Safety
    /// The caller must ensure the slot outlives the sender and is not
    /// accessed concurrently (guaranteed by single-threaded PVM execution).
    pub(crate) unsafe fn new(slot: *mut Option<R>) -> Self {
        Self { slot }
    }

    /// Write the reply value. Can only be called once.
    pub fn send(self, value: R) {
        // SAFETY: single-threaded PVM execution, slot lifetime guaranteed by caller
        unsafe {
            *self.slot = Some(value);
        }
    }
}
