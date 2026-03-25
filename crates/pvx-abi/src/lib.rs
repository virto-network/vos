//! # pvx-abi
//!
//! Shared ABI definitions between the PVM executor and child actor programs.
//!
//! This crate defines the contract:
//! - **Actor ABI**: entry points that every child PVM program exports
//! - **Syscall ABI**: "system calls" children make to the executor
//! - **Message format**: how messages are encoded across the boundary
//! - **Error codes**: shared error representation
//!
//! Both the executor and child programs depend on this crate. It is
//! `no_std` and `no_alloc` — only plain data types and constants.

#![no_std]

pub mod actor;
pub mod msg;
pub mod syscall;
