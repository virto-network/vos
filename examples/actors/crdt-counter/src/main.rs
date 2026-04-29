//! Bin entry. `vos::pvm_main!` emits `_start` / `accumulate`
//! and the `.vos_meta` static; the actor itself lives in `lib.rs`
//! so consumers can `use crdt_counter::CrdtCounterClient` to
//! drive it without depending on the bin.

#![no_std]
#![no_main]

vos::pvm_main!(crdt_counter::CrdtCounter);
