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
pub use wasync::{fs, io, run, wasi};
pub use writ_macro::{bin, main};

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
}

pub mod logger;
pub mod protocol;
pub mod storage;
mod task;

pub trait State: Sized {
    const META: &'static Metadata;
    type Storage: storage::TaskStorage<Self>;
}

impl State for json::Value {
    const META: &'static task::Metadata = &task::Metadata::simple_crud_task();
    type Storage = storage::NoStore;
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
