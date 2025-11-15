#![feature(ascii_char, ascii_char_variants)]
#![allow(async_fn_in_trait)]

pub use embassy_executor as executor;
pub use log;
use miniserde::json;
pub use pico_args as args;
pub use pico_args::Arguments;
pub use protocol::Protocol;
pub use task::*;
#[cfg(feature = "net")]
pub use wasync::net;
pub use wasync::{fs, io, run, wasi};
pub use writ_macro::{main, task};

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
}

pub mod logger;
mod protocol;
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

///
pub enum Action {
    Query(
        &'static str,
        Box<dyn Iterator<Item = (&'static str, json::Value)>>,
    ),
    Command(
        &'static str,
        Box<dyn Iterator<Item = (&'static str, json::Value)>>,
    ),
}
impl Action {
    pub fn name(&self) -> &str {
        match self {
            Action::Query(name, _) => name,
            Action::Command(name, _) => name,
        }
    }

    pub fn params(&self) -> &dyn Iterator<Item = (&'static str, json::Value)> {
        match self {
            Action::Query(_, iterator) => &*iterator,
            Action::Command(_, iterator) => &*iterator,
        }
    }
}
