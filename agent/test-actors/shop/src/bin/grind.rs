//! The program of the shop's workflow `grind`, with a heap for its words.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_grind, heap = 4 << 20);
