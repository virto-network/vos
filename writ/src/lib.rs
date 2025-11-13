#![feature(ascii_char, ascii_char_variants)]
#![allow(async_fn_in_trait)]

pub use embassy_executor as executor;
pub use log;
use miniserde::json;
pub use pico_args as args;
pub use pico_args::Arguments;
pub use task::*;
#[cfg(feature = "net")]
pub use wasync::net;
use wasync::wasi::clocks::wall_clock::now;
pub use wasync::{fs, io, run, wasi};
pub use writ_macro::{bin, main};

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
}
use wasi::clocks::wall_clock::Datetime;

pub mod logger;
pub mod protocol;
mod task;

pub trait TaskStorage<S> {
    type Error;
    async fn initialize(name: &str) -> Result<Datetime, Self::Error>;
    async fn update(name: &str, state: &S) -> Result<(), Self::Error>;
    async fn restore(name: &str) -> Result<Option<(Datetime, S)>, Self::Error>;
}

pub struct NoStore;
impl<S> TaskStorage<S> for NoStore {
    type Error = ();
    async fn initialize(_name: &str) -> Result<Datetime, Self::Error> {
        Ok(now())
    }
    async fn update(name: &str, state: &S) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn restore(name: &str) -> Result<Option<(Datetime, S)>, Self::Error> {
        Ok(None)
    }
}

impl State for json::Value {
    const META: &'static task::Metadata = &task::Metadata::simple_crud_task();
    type Storage = NoStore;
}

#[derive(Debug)]
pub struct TyDef {
    pub name: &'static str,
    pub desc: &'static str,
    pub args: &'static [Arg],
}

#[derive(Debug)]
pub struct Arg {
    pub name: &'static str,
    pub ty: &'static str,
}
