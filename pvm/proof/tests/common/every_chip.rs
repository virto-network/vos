//! A segment proved over every chip of the segment AIR, each at the log size
//! its rows take: the ones its run does not use at their fewest rows.

use vos_pvm_proof::shape::ProofShape;
use vos_pvm_proof::{Proof, SideNote, chip_idx, format::Format};

/// The segment `segment` makes, called once to size its chips and once to
/// prove it, proved under `format` over every chip ([`chip_idx::ALL`]).
pub fn prove_every_chip(segment: impl Fn() -> SideNote, format: &'static Format) -> Proof {
    let mut sized = segment();
    vos_pvm_proof::prepare_side_note_for_verification(&mut sized);
    sized.ingest_memory_pages();
    let chips = vos_pvm_proof::all_components();
    let mut log_sizes = vec![0; chips.len()];
    for producers in [true, false] {
        for (chip, component) in chips.iter().enumerate() {
            if component.is_producer() == producers {
                log_sizes[chip] = if producers {
                    component.generate_component_trace(&mut sized)
                } else {
                    component.generate_component_trace_immut(&sized)
                }
                .log_size();
            }
        }
    }
    let shape = ProofShape {
        components: chip_idx::ALL,
        log_sizes,
    };
    vos_pvm_proof::prove_shaped(&mut segment(), &shape, format).expect("proves")
}
