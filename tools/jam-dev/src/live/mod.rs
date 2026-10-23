//! A PolkaJam node: its JSON-RPC for state and segments, and `jamt` for
//! services, preimages and work items; work packages with extrinsics, built
//! and submitted by RPC ([`package`]), and a JAM statements service's
//! client ([`statements`]).
//!
//! A package goes as a work package of one item, so its exports are the
//! package's from index 0. Its payload goes in a file, which `jamt item`
//! reads; its imports are named by segment root, `sr:<root>:<index>`,
//! which keep working as long as DA holds the segments.
//!
//! The builder reads the chain at its finalized block, so what it commits
//! no reorganization undoes. `jamt` anchors a package at the finalized
//! block too, and a refine there finds a preimage only once that block is
//! past the slot the preimage became available in: the builder waits for
//! that before a package that needs one.

mod jamt;
pub mod package;
mod rpc;
pub mod statements;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use vos_tree::Hash;
use vos_wire::defaults::SESSION_SKEW_MS;
use vos_wire::package::{EPOCH_MS, EXPORTS, MAX_SEGMENTS, ROOT, SLOT_MS};

use rpc::decoded;
use vos_jam::Error;
use vos_jam::Runner;
use vos_jam::Segments;
use vos_jam::builder::{MAX_INPUT, Prepared};
use vos_jam::{Chain, Landed, MAX_REFINE_OUTPUT};

/// The slots past a preimage's arrival the finalized block must be before
/// a package that needs it: it must be past that slot; one more is margin.
const ANCHOR_MARGIN: u64 = 2;
/// The RPC errors in a row a wait takes before it stops.
const TRANSIENT: u32 = 10;

/// A PolkaJam node, by its RPC's address, and the `jamt` that reaches it.
#[derive(Clone, Debug)]
pub struct PolkaJam {
    /// `host:port` of its JSON-RPC over HTTP.
    pub rpc: String,
    pub jamt: PathBuf,
    /// Where payloads are written for `jamt` to read.
    pub files: PathBuf,
    /// Shown each package [`PolkaJam::submit_package`] submitted: none in a
    /// node's client.
    pub watch: Option<Watch>,
}

/// What sees each work package a [`PolkaJam`] submitted, once the node
/// took it: its encoding and its extrinsics, as they went. A run that
/// audits what reached the chain keeps them.
#[derive(Clone)]
pub struct Watch(pub Arc<Watching>);

/// A [`Watch`]'s function: a package's encoding and its extrinsics.
pub type Watching = dyn Fn(&[u8], &[Vec<u8>]) + Send + Sync;

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Watch")
    }
}

/// The protocol's parameters the builder reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub max_refine_gas: u64,
    pub slot_period_sec: u64,
    pub max_imports: u64,
    pub max_exports: u64,
    pub max_input: u64,
    pub max_report_elective_data: u64,
}

impl Parameters {
    /// What of the agent's and its builder's limits these parameters do
    /// not hold, by name: none when they agree.
    pub fn disagreements(&self) -> Vec<&'static str> {
        [
            ("slot period", self.slot_period_sec * 1000 == SLOT_MS),
            (
                "refine output",
                self.max_report_elective_data as usize == MAX_REFINE_OUTPUT,
            ),
            ("imports", self.max_imports as usize == MAX_SEGMENTS),
            ("exports", self.max_exports as usize == MAX_SEGMENTS),
            ("input", self.max_input as usize >= MAX_INPUT),
        ]
        .into_iter()
        .filter(|(_, agree)| !agree)
        .map(|(what, _)| what)
        .collect()
    }
}

fn failed(what: impl std::fmt::Display) -> Error {
    Error::Node(what.to_string())
}

impl PolkaJam {
    pub fn parameters(&self) -> Result<Parameters, Error> {
        let answer = self.call("parameters", json!([]))?;
        let fields = &answer["V1"];
        let field = |name: &str| {
            fields[name]
                .as_u64()
                .ok_or_else(|| failed(format!("no parameter {name}")))
        };
        Ok(Parameters {
            max_refine_gas: field("max_refine_gas")?,
            slot_period_sec: field("slot_period_sec")?,
            max_imports: field("max_imports")?,
            max_exports: field("max_exports")?,
            max_input: field("max_input")?,
            max_report_elective_data: field("max_report_elective_data")?,
        })
    }

    /// The finalized block: its header hash, as the RPC names it, and its
    /// slot.
    pub fn finalized(&self) -> Result<(String, u64), Error> {
        let answer = self.call("finalizedBlock", json!([]))?;
        let hash = answer["header_hash"]
            .as_str()
            .ok_or_else(|| failed("a head without a hash"))?;
        let slot = answer["slot"]
            .as_u64()
            .ok_or_else(|| failed("a head without a slot"))?;
        Ok((hash.to_string(), slot))
    }

    /// A value of `service`'s storage at block `head`.
    pub(crate) fn value(
        &self,
        head: &str,
        service: u64,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let answer = self.call("serviceValue", json!([head, service, STANDARD.encode(key)]))?;
        decoded(&answer)
    }

    /// The slots at which `service`'s request for the preimage of `hash`,
    /// `len` bytes long, changed, at block `head`; `None` when it has none.
    pub(crate) fn request(
        &self,
        head: &str,
        service: u64,
        hash: &Hash,
        len: u64,
    ) -> Result<Option<Vec<u64>>, Error> {
        let answer = self.call(
            "serviceRequest",
            json!([head, service, STANDARD.encode(hash), len]),
        )?;
        if answer.is_null() {
            return Ok(None);
        }
        let slots = answer
            .as_array()
            .ok_or_else(|| failed("a request that is not a list"))?;
        slots
            .iter()
            .map(|slot| slot.as_u64().ok_or_else(|| failed("a slot")))
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Segments of the package whose exports' segment root is `root`.
    pub(crate) fn fetch(&self, root: &Hash, indices: &[u32]) -> Result<Vec<Vec<u8>>, Error> {
        let answer = self.call("fetchSegments", json!([STANDARD.encode(root), indices]))?;
        answer
            .as_array()
            .ok_or_else(|| failed("segments that are not a list"))?
            .iter()
            .map(|segment| decoded(segment)?.ok_or_else(|| failed("a missing segment")))
            .collect()
    }

    /// The agent `service` as the finalized block holds it, both its keys
    /// read there; and that block's slot.
    pub(crate) fn landed(&self, service: u64) -> Result<(Landed, u64), Error> {
        let (head, slot) = self.finalized()?;
        let landed = Landed::read(
            self.value(&head, service, ROOT)?.as_deref(),
            self.value(&head, service, EXPORTS)?.as_deref(),
        )?;
        Ok((landed, slot))
    }

    /// Wait until `service`'s preimage of `hash`, `len` bytes, can be
    /// looked up by a package `jamt` anchors now: available at the
    /// finalized block, which is `ANCHOR_MARGIN` slots past its arrival.
    /// The slot it became available in.
    pub fn await_preimage(
        &self,
        service: u64,
        hash: &Hash,
        len: u64,
        timeout: Duration,
    ) -> Result<u64, Error> {
        let until = Instant::now() + timeout;
        loop {
            let (head, slot) = self.finalized()?;
            let since = self
                .request(&head, service, hash, len)?
                .and_then(|slots| available(&slots));
            if let Some(since) = since
                && slot >= since + ANCHOR_MARGIN
            {
                return Ok(since);
            }
            if Instant::now() > until {
                return Err(failed(format!(
                    "preimage {} never available",
                    hex::encode(hash)
                )));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// The slot a preimage's request history says it has been available since:
/// `[x]`, or `[x, y, z]` once provided again; `None` when it is not, as
/// `[]` (asked for), or `[x, y]` (provided, then forgotten).
fn available(slots: &[u64]) -> Option<u64> {
    match slots {
        [since] | [_, _, since] => Some(*since),
        _ => None,
    }
}

/// A node's segments, fetched by RPC.
struct Fetched(PolkaJam);

impl Segments for Fetched {
    fn segment(&self, root: &Hash, index: u32) -> Option<Vec<u8>> {
        self.0.fetch(root, &[index]).ok()?.pop()
    }
}

/// An agent's service on a PolkaJam node, as its builder's chain.
pub struct Live {
    pub node: PolkaJam,
    pub service: u64,
}

impl Chain for Live {
    fn segments(&self) -> Arc<dyn Segments> {
        Arc::new(Fetched(self.node.clone()))
    }

    fn submit(&mut self, _: &Runner, prepared: &Prepared) -> Result<String, Error> {
        self.node.item(
            self.service,
            &prepared.payload,
            prepared.exports(),
            &prepared.segments,
        )
    }

    /// Poll the finalized block until it holds another root than the one
    /// the package was built on, or until its slot starts past the
    /// package's window, the batch's time and the session skew, after
    /// which accumulate refuses it in any later block. A few RPC errors in
    /// a row are waited out.
    fn wait(&mut self, prepared: &Prepared) -> Result<Landed, Error> {
        let window = prepared.package.batch.time + SESSION_SKEW_MS;
        let mut errors = 0;
        loop {
            match self.node.landed(self.service) {
                Ok((landed, slot)) => {
                    errors = 0;
                    let closed = EPOCH_MS + slot * SLOT_MS > window;
                    if landed.root != prepared.package.root || closed {
                        return Ok(landed);
                    }
                }
                Err(error) if errors == TRANSIENT => return Err(error),
                Err(_) => errors += 1,
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn landed(&self) -> Result<Landed, Error> {
        self.node.landed(self.service).map(|(landed, _)| landed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preimage is available from its history's last arrival, and not
    /// while only asked for or once forgotten.
    #[test]
    fn a_preimage_is_available_from_its_last_arrival() {
        assert_eq!(available(&[5]), Some(5));
        assert_eq!(available(&[5, 9, 12]), Some(12));
        assert_eq!(available(&[]), None);
        assert_eq!(available(&[5, 9]), None);
    }

    /// The service's storage read as the chain's view of the agent: the
    /// empty tree's root before its first package, and the last exports.
    #[test]
    fn the_storage_reads_as_what_landed() {
        use vos_wire::Encode;
        use vos_wire::package::Exports;
        let empty = Landed::read(None, None).unwrap();
        assert_eq!(empty.root, vos_tree::empty_root(&vos_tree::Blake2b));
        assert_eq!(empty.exports, None);
        let exports = Exports {
            package: [9; 32],
            root: [1; 32],
            pages: 2,
            segments: 3,
        };
        let landed = Landed::read(Some(&[5; 32]), Some(&exports.encode())).unwrap();
        assert_eq!((landed.root, landed.exports), ([5; 32], Some(exports)));
        assert!(Landed::read(Some(&[5; 31]), None).is_err());
    }
}
