#![feature(impl_trait_in_assoc_type)]
#![allow(async_fn_in_trait)]
#![cfg_attr(not(test), no_std)]

// although we include alloc core OS components should avoid doing allocations
extern crate alloc;

#[cfg(any(feature = "os-std", feature = "os-web", feature = "os-rv"))]
pub mod os;
pub use log;
pub use vos_macro::bin;

pub mod prelude {
    pub use alloc::borrow::Cow;
    pub use alloc::boxed::Box;
    pub use alloc::string::String;
    pub use alloc::vec::Vec;
    pub use log;
}

#[cfg(feature = "rv")]
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
#[cfg(feature = "std")]
#[global_allocator]
static HEAP: mimalloc::MiMalloc = mimalloc::MiMalloc;
