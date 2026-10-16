//! The bounds actor with a heap past what a handler's program holds: its
//! workflows allocate from all of it, its handlers from its first 512 KiB.

#![no_std]
#![no_main]

vos_sdk::actor_program!(bounds::bounds, heap = 2 << 20);
