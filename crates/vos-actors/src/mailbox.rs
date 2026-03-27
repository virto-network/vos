/// A fixed-capacity, single-producer single-consumer ring buffer.
pub struct Mailbox<T, const N: usize> {
    buf: [Option<T>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<T, const N: usize> Mailbox<T, N> {
    const NONE: Option<T> = None;

    pub const fn new() -> Self {
        Self {
            buf: [Self::NONE; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, msg: T) -> Result<(), T> {
        if self.len == N {
            return Err(msg);
        }
        self.buf[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let msg = self.buf[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        msg
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn peek(&self) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        self.buf[self.head].as_ref()
    }

    pub fn is_full(&self) -> bool {
        self.len == N
    }
}

impl<T, const N: usize> Default for Mailbox<T, N> {
    fn default() -> Self {
        Self::new()
    }
}
