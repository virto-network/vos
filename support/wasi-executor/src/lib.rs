use embassy_executor::{Spawner, raw};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::poll_fn,
    task::{Poll, Waker},
};
use wasi::io::poll::Pollable;

thread_local! {
    static IO: RefCell<WasiIo> = const { RefCell::new(WasiIo::new()) };
}

#[unsafe(export_name = "__pender")]
fn __pender(_context: *mut ()) {
    println!("pender...")
}

pub fn run(init: impl FnOnce(Spawner)) {
    let exec = Box::leak(Box::new(raw::Executor::new(&mut ())));
    init(exec.spawner());
    loop {
        println!("...polling");
        unsafe { exec.poll() };

        // Check if we have any pollables to wait on
        let has_pollables = IO.with_borrow(|io| !io.pollables.is_empty());

        if has_pollables {
            IO.with_borrow_mut(|io| io.wait())
        } else {
            // No pollables and executor finished polling - exit
            println!("No pollables, exiting");
            break;
        }
    }
}

pub async fn wait_pollable(pollable: &Pollable) {
    poll_fn(|cx| {
        if pollable.ready() {
            println!("pollable ready");
            // IO.with_borrow_mut(|io| io.pollables.remove(pollable));
            return Poll::Ready(());
        }
        IO.with_borrow_mut(|io| io.pollables.insert(pollable, cx.waker().clone()));
        Poll::Pending
    })
    .await
}

struct WasiIo {
    pollables: BTreeMap<*const Pollable, Waker>,
}

impl WasiIo {
    const fn new() -> Self {
        Self {
            pollables: BTreeMap::new(),
        }
    }

    fn wait(&mut self) {
        let pollables = unsafe {
            self.pollables
                .keys()
                .map(|&p| &*p)
                .collect::<Vec<&Pollable>>()
        };
        println!("waiting {} ~~", pollables.len());

        // If there are no pollables to wait on, just return
        // This allows the executor to continue running without blocking
        if pollables.is_empty() {
            println!("~~ no pollables to wait on");
            return;
        }

        let ready = wasi::io::poll::poll(pollables.as_slice());
        let len = ready.len();
        for i in ready {
            let p = pollables[i as usize];
            let waker = self
                .pollables
                .remove(&(p as *const Pollable))
                .expect("pollable exists");
            waker.wake();
        }
        println!("~~ waited {}", len);
    }
}
