//! The shop's workflow `hog` with more memory than a workflow may write.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_hog, heap = 17 << 20);
