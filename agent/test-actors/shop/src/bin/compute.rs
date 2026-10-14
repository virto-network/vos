//! The program of the shop's workflow `compute`, with a heap for its data.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_compute, heap = 4 << 20);
