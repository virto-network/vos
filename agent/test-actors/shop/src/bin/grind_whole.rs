//! The program of the shop's workflow `grind_whole`, with a heap for its words.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_grind_whole, heap = 4 << 20);
