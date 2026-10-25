//! Fuzz target: arbitrary bytes through `vos-anchor`'s decoders, each a
//! venue's reading of what a space hands it: `SpaceGenesis::decode` (a
//! registration's genesis), `Anchor::decode` and the golden vectors'
//! `Vector::decode`; then the clock, the digests and the id over what
//! decoded.
//!
//! Properties: **no panic, no abort**, and **one encoding:** a value that
//! decodes re-encodes to the bytes. The clock's arithmetic is checked
//! (`window`, `boundary`, `representative`: none past `u64`), so any
//! decoded clock is read at any time and window without overflow.
//!
//! Seed the corpus with the golden vectors (`examples/seed.rs`):
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! cargo fuzz run anchor_decode -- -max_total_time=300
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_anchor::vectors::Vector;
use vos_anchor::{space_id, Anchor, SpaceGenesis, VenueId, WindowClock};

/// A venue's id from the bytes' first 32, or zeros.
fn venue(data: &[u8]) -> VenueId {
    let mut id = [0; 32];
    let n = data.len().min(32);
    id[..n].copy_from_slice(&data[..n]);
    VenueId(id)
}

/// The clock read at `t` and at the windows around it, every result
/// consistent: `t` before the boundary of its window, and not before the
/// boundary of the one before.
fn read(clock: &WindowClock, t: u64) {
    if let Some(w) = clock.window(t) {
        if let Some(boundary) = clock.boundary(w) {
            assert!(t < boundary, "t in its window");
        }
        if let Some(previous) = w.checked_sub(1).and_then(|w| clock.boundary(w)) {
            assert!(previous <= t, "t past the previous window");
        }
    }
    let _ = clock.boundary(t);
    let _ = clock.registrable();
    let _ = clock.representative();
}

fuzz_target!(|data: &[u8]| {
    let t = data
        .first_chunk::<8>()
        .map_or(0, |bytes| u64::from_le_bytes(*bytes));
    if let Ok(genesis) = SpaceGenesis::decode(data) {
        assert_eq!(genesis.encode(), data, "one encoding");
        let _ = space_id(&genesis);
        read(&genesis.clock, t);
        if let Some(clock) = genesis.clock.representative() {
            read(&clock, t);
        }
    }
    if let Ok(anchor) = Anchor::decode(data) {
        assert_eq!(anchor.encode(), data, "one encoding");
        let _ = anchor.digest(&venue(data));
    }
    if let Ok(vector) = Vector::decode(data) {
        assert_eq!(vector.encode(), data, "one encoding");
        let _ = vector.digests().to_bytes();
    }
    read(&WindowClock::DEFAULT, t);
});
