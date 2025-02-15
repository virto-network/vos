pub use log;
#[cfg(any(feature = "os-std", feature = "os-rv", feature = "os-web"))]
pub use os;
#[cfg(feature = "bin")]
pub use vos_macro::bin;

#[cfg(feature = "bin")]
pub mod bin_prelude {
    pub use log;
    pub use miniserde::{json, Deserialize, Serialize};
    pub use wstd::*;
}
