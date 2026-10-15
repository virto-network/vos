//! Accumulate: apply work results to the agent's storage, in order.
//!
//! On a VOS node, each work result's writes ([`vos_wire::apply`]). On JAM,
//! where refine applied the result to the tree over the whole keyspace,
//! only the root moves: a package's output names the root it was refined
//! on, which must be the one stored, and a time that must fit the slot.
//! Taking it, accumulate keeps its exports' segment root and solicits the
//! programs it names. A VOS node's operands name no package; a JAM node's
//! always do.

use alloc::vec::Vec;

use vos_tree::{Blake2b, Hash, empty_root};
use vos_wire::apply::{Host, State, apply};
use vos_wire::jam::AccumulateInput;
use vos_wire::package::{EXPORTS, Exports, JamOutput, ROOT, timely};
use vos_wire::result::split_output;
use vos_wire::{Decode, Encode};

use crate::host::{fetch_input, read, solicit, write};

pub fn run(arguments: &[u8]) {
    let (slot, used) = vos_pvm_program::read_nat(arguments, 0).expect("the timeslot");
    let (_, more) = vos_pvm_program::read_nat(arguments, used).expect("the service");
    let (count, _) = vos_pvm_program::read_nat(arguments, used + more).expect("the input count");
    for index in 0..count {
        let Some(bytes) = fetch_input(index) else {
            continue;
        };
        let Some(AccumulateInput::Operand(operand)) = AccumulateInput::decode(&bytes) else {
            continue;
        };
        let Ok(output) = operand.result else {
            continue;
        };
        if operand.package_hash != [0; 32] {
            swap(slot, &output, &operand.package_hash, &operand.segment_root);
        } else if let Some((result, pages)) = split_output(&output) {
            apply(&mut Storage, &result, Host::Vos { pages: &pages });
        }
    }
}

/// The service's storage, through `read` and `write`.
struct Storage;

impl State for Storage {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        read(key)
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        write(key, value.unwrap_or(&[]));
    }
}

/// Take a JAM package's root after, if it was refined on the root stored
/// and its time fits `slot`, with the segment root of its exports;
/// otherwise nothing changes.
fn swap(slot: u64, bytes: &[u8], package: &[u8; 32], segments: &[u8; 32]) {
    let Ok((output, used)) = JamOutput::decode(bytes) else {
        return;
    };
    let Ok(root) = read(ROOT).map_or_else(|| Ok(empty_root(&Blake2b)), Hash::try_from) else {
        return;
    };
    if used == bytes.len() && output.root_before == root && timely(output.time, slot) {
        write(ROOT, &output.root_after);
        let exports = Exports {
            package: *package,
            root: *segments,
            pages: output.pages,
            segments: output.exports,
        };
        write(EXPORTS, &exports.encode());
        for (program, len) in &output.solicit {
            solicit(&program.0, *len);
        }
    }
}
