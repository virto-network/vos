//! The program of the shop's workflow `chain`.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(shop::Shop::__vos_workflow_chain);
