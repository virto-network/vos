#![feature(macro_metavar_expr)]

pub use log;
#[cfg(any(feature = "os-std", feature = "os-rv", feature = "os-web"))]
pub use os;

#[cfg(feature = "bin")]
pub mod bin_protocol;
#[cfg(feature = "bin")]
pub use vos_macro::bin;
#[cfg(feature = "bin")]
pub mod bin_prelude {
    pub use super::bin_protocol as protocol;
    pub use env_logger as logger;
    pub use log;
    pub use miniserde::{json, Deserialize, Serialize};
    pub use wstd::prelude::*;
    pub use wstd::*;
}
