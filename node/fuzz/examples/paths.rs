//! Lists what each input of the checked-in corpus (`replay/<target>.tar`,
//! unpacked into `target/replay/<target>/`) reaches: the events the node
//! API's reader gives it, or whether it decodes as its target's input,
//! counted by verdict a target.
//!
//! ```text
//! cd node/fuzz
//! python3 -I ../../pvm/proof/fuzz/corpus.py unpack replay target/replay
//! cargo run --release --example paths
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use vos_abi::ids::AgentId;
use vos_abi::Decode;
use vos_api::{Event, Framing, Operated, Reader, Requests};
use vos_wire::ingress::Credentialed;

/// The verdicts `bytes` reaches as `target`'s input.
fn paths(target: &str, bytes: &[u8]) -> Vec<String> {
    match target {
        "api_reader" => {
            let Some((&cuts, data)) = bytes.split_first() else {
                return vec!["empty".into()];
            };
            let mut reader = Reader::requests(Framing::Stream, Requests::All);
            for chunk in data.chunks(usize::from(cuts) + 1) {
                reader.push(chunk);
            }
            let mut paths = Vec::new();
            while let Some(event) = reader.event() {
                paths.push(match event {
                    Event::Frame(frame) => format!("frame {:#06x}", frame.kind),
                    Event::Error { error, .. } => format!("{error:?}"),
                });
            }
            paths.extend(
                reader
                    .finish()
                    .map(|event| format!("at the end: {event:?}")),
            );
            paths
        }
        "operated_decode" => vec![match Operated::decode_exact(bytes) {
            Some(_) => "an envelope".into(),
            None => "no envelope".into(),
        }],
        "credentialed_decode" => vec![match <(AgentId, Credentialed)>::decode_exact(bytes) {
            Some(_) => "a proven call".into(),
            None => "no proven call".into(),
        }],
        _ => vec!["an unknown target".into()],
    }
}

fn main() {
    let replay = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/replay");
    let mut targets: Vec<_> = std::fs::read_dir(&replay)
        .expect("the replay corpus, unpacked: `python3 -I ../../pvm/proof/fuzz/corpus.py unpack replay target/replay`")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    targets.sort();
    for directory in targets {
        let target = directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a target's name")
            .to_owned();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut inputs = 0;
        for entry in std::fs::read_dir(&directory).expect("the target's corpus") {
            let bytes = std::fs::read(entry.expect("an entry").path()).expect("an input");
            inputs += 1;
            for path in paths(&target, &bytes) {
                *counts.entry(path).or_default() += 1;
            }
        }
        println!("{target}: {inputs} inputs");
        for (path, count) in counts {
            println!("  {count:>5}  {path}");
        }
    }
}
