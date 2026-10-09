//! The program of the ledger's attestable `checksum`.

#![no_std]
#![no_main]

vos_sdk::attestable_program!(ledger::Ledger::__vos_attest_checksum);
