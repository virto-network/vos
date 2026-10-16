//! The shop with a heap that fits what a JAM service's agent may run: an
//! upgrade of the default-heap shop on JAM.

#![no_std]
#![no_main]

vos_sdk::actor_program!(shop::shop, heap = 640 << 10);
