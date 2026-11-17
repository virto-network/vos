//! The statements service's refine as `service_item` runs it and
//! `examples/paths.rs` labels it: an input framed as an item and its first
//! extrinsic, refined at one venue whose deployment pins the golden
//! fixtures' programs.

#![allow(dead_code)]

use std::sync::OnceLock;

use vos_statement_service::config::Config;
use vos_statement_service::refine::{refine, venue, Extrinsics};
use vos_statement_service::verdict::Verdict;

/// The deployment: a test chain's genesis, the fixtures' programs pinned.
pub fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let mut pins = Vec::new();
        for fixture in vos_statement::fixtures::load(&vos_statement::fixtures::directory()) {
            if !pins.contains(&fixture.input.program) {
                pins.push(fixture.input.program);
            }
        }
        Config {
            genesis: [0x4a; 32],
            genesis_ms: 1_735_732_800_000,
            pins,
        }
    })
}

/// The item's first extrinsic, if it has one.
struct Proof<'a>(Option<&'a [u8]>);

impl Extrinsics for Proof<'_> {
    fn proof_len(&mut self) -> Option<usize> {
        self.0.map(<[u8]>::len)
    }

    fn proof(&mut self, len: usize) -> Vec<u8> {
        self.0.unwrap_or_default()[..len].to_vec()
    }
}

/// An input's item and extrinsic: its first four bytes, little-endian, the
/// item's length (at most the rest's); the item; the rest, if any, the
/// extrinsic.
pub fn split(data: &[u8]) -> (&[u8], Option<&[u8]>) {
    let Some((len, rest)) = data.split_first_chunk::<4>() else {
        return (data, None);
    };
    let len = (u32::from_le_bytes(*len) as usize).min(rest.len());
    let (item, proof) = rest.split_at(len);
    (item, (!proof.is_empty()).then_some(proof))
}

/// `item` and `proof` framed as an input.
pub fn frame(item: &[u8], proof: Option<&[u8]>) -> Vec<u8> {
    let mut data = (item.len() as u32).to_le_bytes().to_vec();
    data.extend_from_slice(item);
    data.extend_from_slice(proof.unwrap_or_default());
    data
}

/// Refine's verdict on the input `data`.
pub fn verdict(data: &[u8]) -> Verdict {
    let config = config();
    let (item, proof) = split(data);
    refine(config, venue(config, 7), item, &mut Proof(proof))
}

/// A verdict's kind: refine's admission of an item, a statement's code, or
/// a refusal's kind and code.
pub fn label(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Register(_) => "Register".into(),
        Verdict::Anchor { .. } => "Anchor".into(),
        Verdict::Control { .. } => "Control".into(),
        Verdict::Submit(judged) => format!("Submit({})", judged.code),
        Verdict::Refused { kind, code } => format!("Refused({kind:?}, {code})"),
    }
}
