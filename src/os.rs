#[cfg(feature = "std")]
extern crate std;

use embassy_executor::{Executor, SendSpawner, SpawnToken};
use heapless::String;
use pacman::Cmd;
use serde::Deserialize;
use static_cell::StaticCell;

pub type RawMutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
pub type Channel<T, const N: usize = 1> = embassy_sync::channel::Channel<RawMutex, T, N>;
pub type Sender<'c, T, const N: usize = 1> = embassy_sync::channel::Sender<'c, RawMutex, T, N>;
pub type Receiver<'c, T, const N: usize = 1> = embassy_sync::channel::Receiver<'c, RawMutex, T, N>;
pub type Signal<T> = embassy_sync::signal::Signal<RawMutex, T>;
pub type Pipe<const N: usize = 1> = embassy_sync::pipe::Pipe<RawMutex, N>;
pub type CmdIo = Pipe<128>; // ?
pub type UserId = String<16>;

pub mod io;
pub mod pacman;
pub mod shell;
pub mod vm;

/// OS groups and wires together the commponents that make up the embedded OS
/// it sets up resources and runs forever waiting for connections
/// to start interactive sessions that run installed applications for a given user
pub struct Os {
    sys_bus: Channel<SysMsg>,
    shell_mgr: Worker,
    user_apps: Worker,
}

pub enum SysMsg {
    Auth(UserId),
}

#[derive(Deserialize)]
pub struct Config {
    /// System service handling authentication
    session_manager: Cmd,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            session_manager: Cmd::new("auth"),
        }
    }
}

impl Os {
    pub fn boot(cfg: Config) {
        // pub fn boot(cfg: Config) -> &'static Self {
        static OS: StaticCell<Os> = StaticCell::new();
        let os = OS.init(Os {
            shell_mgr: Worker::new(),
            user_apps: Worker::new(),
            sys_bus: Channel::new(),
        });
        os.shell_mgr.run(shell::handle_connections);
        os.user_apps.run(vm::run);
        // os
    }
}

///
pub struct Worker {
    exec: Executor,
}

impl Worker {
    fn new() -> Self {
        Worker {
            exec: Executor::new(),
        }
    }

    fn run<T, S>(&'static mut self, task: T)
    where
        T: FnOnce(SendSpawner) -> SpawnToken<S>,
    {
        #[cfg(not(feature = "web"))]
        self.exec.run(|s| s.must_spawn(task(s.make_send())));
        #[cfg(feature = "web")]
        self.exec.start(|s| s.must_spawn(task(s.make_send())));
    }
}
