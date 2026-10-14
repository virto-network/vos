//! The shop's program, its workflows in it: a heap that holds what its
//! workflows hold but the largest steps, which `big` holds.

#![no_std]
#![no_main]

vos_sdk::actor_program!(shop::shop, heap = 4 << 20);
