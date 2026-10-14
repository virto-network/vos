//! The shop with a heap that holds `hog`'s largest step and `fill`'s most
//! pages: what an actor pays for in every invocation, so only the tests
//! that need it install it.

#![no_std]
#![no_main]

vos_sdk::actor_program!(shop::shop, heap = 12 << 20);
