#[cfg(feature = "std")]
extern crate std;

use core::cell::LazyCell;
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
pub type Pipe<const N: usize = 1024> = embassy_sync::pipe::Pipe<RawMutex, N>;
pub type UserId = String<16>;

pub type Rng = rand::rngs::StdRng;
// TODO
pub const RNG: LazyCell<Rng> = LazyCell::new(|| <Rng as rand::SeedableRng>::from_seed([0; 32]));

pub mod pacman;
pub mod ports;
pub mod shell;
pub mod vm;

pub mod net {
    pub use core::net::*;
    pub use edge_net::*;
    use nal::{TcpAccept, TcpBind};

    #[cfg(feature = "std")]
    pub type Stack = edge_net::std::Stack;
    pub type Socket = <<Stack as TcpBind>::Accept<'static> as TcpAccept>::Socket<'static>;

    pub const STACK: Stack = Stack::new();
    pub const fn stack() -> &'static Stack {
        &STACK
    }

    pub async fn listen(port: u16) -> Result<(SocketAddr, Socket), ()> {
        pub const ADDR: [u8; 4] = [0, 0, 0, 0];
        log::debug!("Listening on port {port}");
        stack()
            .bind((ADDR, port).into())
            .await
            .map_err(|_| ())?
            .accept()
            .await
            .map_err(|_| ())
    }
}

/// OS groups and wires together the commponents that make up the embedded OS
/// it sets up resources and runs forever waiting for connections
/// to start interactive sessions that run installed applications for a given user
pub struct Os {
    sys_bus: Channel<SysMsg>,
    session_mgr: Worker,
    user_apps: Worker,
}

pub enum SysMsg {
    Auth(UserId),
}

#[derive(Deserialize)]
pub struct Config {
    /// System service that can handle authentication
    pub auth_cmd: Cmd,
    pub system_ports: ports::Config,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            auth_cmd: Cmd::new("auth"),
            system_ports: Default::default(),
        }
    }
}

impl Os {
    pub fn boot(cfg: Config) {
        // pub fn boot(cfg: Config) -> &'static Self {
        static OS: StaticCell<Os> = StaticCell::new();
        let os = OS.init(Os {
            session_mgr: Worker::new(),
            user_apps: Worker::new(),
            sys_bus: Channel::new(),
        });
        log::debug!("Booting up");

        os.session_mgr
            .run(|s| ports::handle_connections(s, cfg.system_ports));
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
