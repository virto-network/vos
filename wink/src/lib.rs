pub use env_logger as logger;
pub use protocol;
pub use wink_macro::bin;
pub use wstd::{io, main, runtime};

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
    pub use wstd::prelude::*;
}
