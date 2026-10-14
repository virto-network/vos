//! The program of the ledger's workflow `tally`.

#![no_std]
#![no_main]

vos_sdk::workflow_program!(ledger::Ledger::__vos_workflow_tally);
