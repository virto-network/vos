//! The program of the shop's workflow `splurge`, with a heap for what it fills.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_splurge, heap = 8 << 20);
