//! The venue as a JAM refine program, linking format 28 beside 39
//! (`--features pvm-guest,test-formats`): `final-verify`'s program
//! (`src/bin/final-verify.rs`) for the test policy's fixtures.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "../guest.rs"]
mod guest;
