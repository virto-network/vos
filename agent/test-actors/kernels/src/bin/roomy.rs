//! The kernels' actor with a heap past what a kernel's program holds: its
//! kernels are laid out as the default build's, its workflows' heap is
//! larger.

#![no_std]
#![no_main]

vos_sdk::actor_program!(kernels::kernels, heap = 4 << 20);
