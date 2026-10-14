//! The shop with a heap past what a workflow may write: none of its
//! workflows may start.

#![no_std]
#![no_main]

vos_sdk::actor_program!(shop::shop, heap = 17 << 20);
