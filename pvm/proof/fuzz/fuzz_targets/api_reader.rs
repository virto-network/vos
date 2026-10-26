//! Fuzz target: arbitrary bytes, split at arbitrary points, through
//! `vos-api`'s frame reader, as a node, a relay and a client read them,
//! over QUIC's framing and a byte stream's.
//!
//! Properties: **no panic, no abort**; **every frame within its bound**
//! (a request's body within its kind's limit, of a known kind, relayed
//! where the reader relays; an answer's within `MAX_ANSWER`); **a frame
//! error is the reader's last event**; and **splitting changes nothing:**
//! the same bytes in one push give the same events.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_api::{Event, Framing, Kind, Reader, Requests, MAX_ANSWER};

/// Every event `reader` gives for `chunks`, then at their end.
fn events(mut reader: Reader, chunks: &[&[u8]]) -> Vec<Event> {
    let mut events = Vec::new();
    for chunk in chunks {
        reader.push(chunk);
        while let Some(event) = reader.event() {
            events.push(event);
        }
    }
    events.extend(reader.finish());
    events
}

fuzz_target!(|data: &[u8]| {
    let Some((&cuts, data)) = data.split_first() else {
        return;
    };
    // The first byte picks where the rest is split: every `cuts + 1`
    // bytes.
    let step = usize::from(cuts) + 1;
    let chunks: Vec<&[u8]> = data.chunks(step).collect();
    for framing in [Framing::Quic, Framing::Stream] {
        let readers = [
            (Reader::requests(framing, Requests::All), Some(false)),
            (Reader::requests(framing, Requests::Relayed), Some(true)),
            (Reader::answers(framing), None),
        ];
        for (reader, relay) in readers {
            let whole = events(
                match relay {
                    Some(true) => Reader::requests(framing, Requests::Relayed),
                    Some(false) => Reader::requests(framing, Requests::All),
                    None => Reader::answers(framing),
                },
                &[data],
            );
            let split = events(reader, &chunks);
            assert_eq!(whole, split, "splitting changed the events");
            for (at, event) in split.iter().enumerate() {
                match event {
                    Event::Frame(frame) => match relay {
                        Some(relayed) => {
                            let kind = Kind::from_u16(frame.kind).expect("a known kind");
                            assert!(frame.body.len() as u32 <= kind.limit());
                            assert!(!relayed || kind.relayed());
                        }
                        None => assert!(frame.body.len() as u32 <= MAX_ANSWER),
                    },
                    Event::Error { .. } => assert_eq!(at, split.len() - 1, "an error ends it"),
                }
            }
        }
    }
});
