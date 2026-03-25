//! # pvx-scape
//!
//! libc-compatible shim for PVM child actors. Provides standard I/O
//! functions that route through the executor's syscall ABI.
//!
//! When a child actor calls `write()`, `read()`, etc., pvx-scape
//! translates these into PVM host calls (`ecalli`) that the executor
//! intercepts and handles.
//!
//! ## How it works
//!
//! ```text
//! Child actor (Rust + std)
//!     │
//!     ├─ std::io::Write::write()
//!     │     └─ libc::write()        ← pvx-scape provides this
//!     │           └─ ecall           ← RISC-V syscall instruction
//!     │                 └─ ecalli    ← transpiled to PVM host call
//!     │                       └─ executor handles FdWrite
//!     │
//!     ├─ println!()
//!     │     └─ same path via stdout fd
//! ```
//!
//! ## Target
//!
//! This crate is meant to be compiled for `riscv64em-unknown-none-elf`.
//! On other targets, stub implementations panic at runtime (useful for
//! type-checking but not execution).

#![no_std]

pub mod io;
pub mod mem;
pub mod syscall;
