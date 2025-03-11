use embassy_executor::{raw, Spawner};

#[unsafe(export_name = "__pender")]
fn __pender(context: *mut ()) {}

pub struct Executor {
    inner: raw::Executor,
    signaler: &'static Signaler,
}

impl Executor {
    pub fn new() -> Self {
        let signaler = Box::leak(Box::new(Signaler::new()));
        Executor {
            inner: raw::Executor::new(signaler as *mut Signaler as *mut ()),
            signaler,
        }
    }

    pub fn run(&'static mut self, init: impl FnOnce(Spawner)) {
        init(self.inner.spawner());
        loop {
            unsafe { self.inner.poll() };
            self.signaler.wait()
        }
    }
}

struct Signaler;
impl Signaler {
    fn new() -> Self {
        Self
    }

    fn wait(&self) {}

    fn signal(&self) {}
}
