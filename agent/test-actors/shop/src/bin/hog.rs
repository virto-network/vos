//! The program of the shop's workflow `hog`, with a heap past a step's
//! pages.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_hog, heap = 12 << 20);
