//! The default agent's host calls and inner machines, which its program
//! (`main.rs`) and test guests that drive machines as it does share.

#![no_std]

extern crate alloc;

pub mod host;
pub mod machines;
