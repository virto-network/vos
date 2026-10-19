//! The venue as a JAM refine program, linking format 28 beside 39
//! (`--features pvm-guest,test-formats`): `final-verify`'s program
//! (`src/bin/final-verify.rs`) for the test policy's fixtures.

#![no_std]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
#![no_main]

extern crate alloc;

mod guest;
