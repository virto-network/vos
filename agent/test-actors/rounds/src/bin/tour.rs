//! The program of the rounds' workflow `tour`.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(rounds::Rounds::__vos_workflow_tour);
