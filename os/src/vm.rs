use embassy_executor::SendSpawner;
use miniserde::Deserialize;

use super::{Actuator, DataTy, Pipe, Receiver};
use crate::pacman;
// use heapless::{String, Vec};

#[embassy_executor::task]
pub async fn run(s: SendSpawner, cfg: Config, ch: Receiver<'static, (DataTy, Pipe)>) {
    let mut vm = WasiActuator::configure(cfg).await;

    loop {
        let (ty, pipe) = ch.receive().await;
        let DataTy::Action(action) = ty else {
            log::warn!("wrong action type");
            continue;
        };
        vm.execute(&action, pipe).await;
    }
}

#[derive(Default, Deserialize)]
pub struct Config {}

pub struct WasiActuator {
    engine: wasmtime::Engine,
}

impl WasiActuator {
    async fn configure(_cfg: Config) -> Self {
        WasiActuator {
            engine: wasmtime::Engine::default(),
        }
    }
}

impl super::Actuator for WasiActuator {
    async fn execute(&mut self, action: &super::Action, input: super::Pipe) -> Result<(), ()> {
        let bin = pacman::load(&action).await;

        todo!()
    }
}
