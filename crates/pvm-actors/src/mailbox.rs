/// A fixed-capacity, single-producer single-consumer ring buffer.
///
/// No allocation — the buffer is inline. Used as the actor's message queue.
/// The host or other actors push messages in, the executor pops them out
/// during `poll`.
pub struct Mailbox<T, const N: usize> {
    buf: [Option<T>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<T, const N: usize> Mailbox<T, N> {
    const NONE: Option<T> = None;

    /// Create an empty mailbox.
    pub const fn new() -> Self {
        Self {
            buf: [Self::NONE; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Push a message. Returns `Err(msg)` if the mailbox is full.
    pub fn push(&mut self, msg: T) -> Result<(), T> {
        if self.len == N {
            return Err(msg);
        }
        self.buf[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    /// Pop the next message, if any.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let msg = self.buf[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        msg
    }

    /// Number of pending messages.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the mailbox is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the mailbox is full.
    pub fn is_full(&self) -> bool {
        self.len == N
    }
}

impl<T, const N: usize> Default for Mailbox<T, N> {
    fn default() -> Self {
        Self::new()
    }
}
