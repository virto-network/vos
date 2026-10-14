//! A PolkaJam node: its JSON-RPC for state and segments, and `jamt` for
//! services, preimages and work items.
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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vos_tree::Hash;
use vos_wire::defaults::SESSION_SKEW_MS;
use vos_wire::package::{EPOCH_MS, EXPORTS, ROOT, SLOT_MS};

use crate::Error;
use crate::builder::Prepared;
use crate::chain::{Chain, Landed};
use crate::da::Segments;
use crate::simulate::Runner;

/// The slots past a preimage's arrival the finalized block must be before
/// a package that needs it: it must be past that slot; one more is margin.
pub const ANCHOR_MARGIN: u64 = 2;
/// The RPC errors in a row a wait takes before it stops.
const TRANSIENT: u32 = 10;
/// How long a `jamt` command may take.
const JAMT_TIMEOUT: Duration = Duration::from_secs(300);

/// A PolkaJam node, by its RPC's address, and the `jamt` that reaches it.
#[derive(Clone, Debug)]
pub struct Node {
    /// `host:port` of its JSON-RPC over HTTP.
    pub rpc: String,
    pub jamt: PathBuf,
    /// Where payloads are written for `jamt` to read.
    pub files: PathBuf,
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

fn failed(what: impl std::fmt::Display) -> Error {
    Error::Node(what.to_string())
}

impl Node {
    /// One JSON-RPC call: its result.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let mut stream = TcpStream::connect(&self.rpc).map_err(failed)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(failed)?;
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.rpc,
            body.len()
        )
        .map_err(failed)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(failed)?;
        let mut answer: Value = serde_json::from_slice(&http_body(&response)?).map_err(failed)?;
        if let Some(error) = answer.get("error") {
            return Err(failed(format!("{method}: {error}")));
        }
        Ok(answer["result"].take())
    }

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

    /// The best block, or the finalized one: its header hash, as the RPC
    /// names it, and its slot.
    pub fn head(&self, finalized: bool) -> Result<(String, u64), Error> {
        let method = if finalized {
            "finalizedBlock"
        } else {
            "bestBlock"
        };
        let answer = self.call(method, json!([]))?;
        let hash = answer["header_hash"]
            .as_str()
            .ok_or_else(|| failed("a head without a hash"))?;
        let slot = answer["slot"]
            .as_u64()
            .ok_or_else(|| failed("a head without a slot"))?;
        Ok((hash.to_string(), slot))
    }

    /// A value of `service`'s storage at block `head`.
    pub fn value(&self, head: &str, service: u64, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let answer = self.call("serviceValue", json!([head, service, STANDARD.encode(key)]))?;
        decoded(&answer)
    }

    /// The slots at which `service`'s request for the preimage of `hash`,
    /// `len` bytes long, changed, at the finalized block; `None` when it
    /// has none.
    pub fn request(&self, service: u64, hash: &Hash, len: u64) -> Result<Option<Vec<u64>>, Error> {
        let (head, _) = self.head(true)?;
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
    pub fn fetch(&self, root: &Hash, indices: &[u32]) -> Result<Vec<Vec<u8>>, Error> {
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
    pub fn landed(&self, service: u64) -> Result<(Landed, u64), Error> {
        let (head, slot) = self.head(true)?;
        let landed = Landed::read(
            self.value(&head, service, ROOT)?.as_deref(),
            self.value(&head, service, EXPORTS)?.as_deref(),
        )?;
        Ok((landed, slot))
    }

    /// Run `jamt` with `args`, for at most [`JAMT_TIMEOUT`]: what it
    /// printed, on its output and on its errors.
    fn jamt(&self, args: &[&str]) -> Result<(String, String), Error> {
        let mut child = Command::new(&self.jamt)
            .arg("--rpc")
            .arg(format!("ws://{}", self.rpc))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(failed)?;
        let until = Instant::now() + JAMT_TIMEOUT;
        while child.try_wait().map_err(failed)?.is_none() {
            if Instant::now() > until {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed(format!("jamt {} timed out", args[0])));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let output = child.wait_with_output().map_err(failed)?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() {
            return Err(failed(format!(
                "jamt {}: {}",
                args[0],
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok((stdout, stderr))
    }

    /// Create a service of `code`, a service blob, endowed with `amount`:
    /// its id.
    pub fn create_service(&self, code: &Path, amount: u64) -> Result<u64, Error> {
        let (printed, _) = self.jamt(&[
            "create-service",
            "--raw",
            &code.to_string_lossy(),
            &amount.to_string(),
        ])?;
        service_id(&printed)
    }

    /// Provide `preimage`, a file, which `service` solicited.
    pub fn provide(&self, service: u64, preimage: &Path) -> Result<(), Error> {
        self.jamt(&[
            "provide",
            &format!("{service:08x}"),
            &preimage.to_string_lossy(),
        ])
        .map(drop)
    }

    /// Submit a work package of one item to `service`: `payload`, which
    /// exports `exports` segments and imports `imports`, by segment root.
    /// What `jamt` said of it, its lines joined: the package's hash, cut
    /// short, and its anchor among them.
    pub fn item(
        &self,
        service: u64,
        payload: &[u8],
        exports: u32,
        imports: &[(Hash, u32)],
    ) -> Result<String, Error> {
        std::fs::create_dir_all(&self.files).map_err(failed)?;
        let file = self.files.join("payload.bin");
        std::fs::write(&file, payload).map_err(failed)?;
        let mut args = vec!["item".to_string(), "-e".into(), exports.to_string()];
        for (root, index) in imports {
            args.push("-i".into());
            args.push(format!("sr:{}:{index}", hex::encode(root)));
        }
        args.push(format!("{service:08x}"));
        args.push(file.to_string_lossy().into_owned());
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (stdout, stderr) = self.jamt(&args)?;
        let lines: Vec<&str> = stdout.lines().chain(stderr.lines()).collect();
        Ok(lines.join("; "))
    }

    /// Wait until `service`'s preimage of `hash`, `len` bytes, can be
    /// looked up by a package `jamt` anchors now: available at the
    /// finalized block, which is [`ANCHOR_MARGIN`] slots past its arrival.
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
            let since = self
                .request(service, hash, len)?
                .and_then(|slots| available(&slots));
            if let Some(since) = since
                && self.head(true)?.1 >= since + ANCHOR_MARGIN
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
pub fn available(slots: &[u64]) -> Option<u64> {
    match slots {
        [since] | [_, _, since] => Some(*since),
        _ => None,
    }
}

/// The service id `jamt create-service --raw` printed, in hex.
fn service_id(printed: &str) -> Result<u64, Error> {
    u64::from_str_radix(printed.trim(), 16)
        .map_err(|_| failed(format!("a service id: {printed:?}")))
}

/// The body of an HTTP response: as sent, or its chunks joined.
fn http_body(response: &[u8]) -> Result<Vec<u8>, Error> {
    let at = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| failed("an HTTP response without a body"))?;
    let head = String::from_utf8_lossy(&response[..at]).to_ascii_lowercase();
    let body = &response[at + 4..];
    match head.contains("transfer-encoding: chunked") {
        true => unchunked(body),
        false => Ok(body.to_vec()),
    }
}

/// A JSON value of base64, decoded; `None` for null.
fn decoded(value: &Value) -> Result<Option<Vec<u8>>, Error> {
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or_else(|| failed("base64 that is not a string"))?;
    STANDARD.decode(text).map(Some).map_err(failed)
}

/// An HTTP body sent in chunks, joined.
fn unchunked(mut body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let at = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| failed("a chunk without its size"))?;
        let size = std::str::from_utf8(&body[..at]).map_err(failed)?;
        let size = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
            .map_err(failed)?;
        if size == 0 {
            return Ok(out);
        }
        let chunk = body
            .get(at + 2..at + 2 + size)
            .ok_or_else(|| failed("a chunk cut short"))?;
        out.extend_from_slice(chunk);
        body = body.get(at + 4 + size..).unwrap_or_default();
    }
}

/// A node's segments, fetched by RPC.
struct Fetched(Node);

impl Segments for Fetched {
    fn segment(&self, root: &Hash, index: u32) -> Option<Vec<u8>> {
        self.0.fetch(root, &[index]).ok()?.pop()
    }
}

/// An agent's service on a PolkaJam node, as its builder's chain.
pub struct Live {
    pub node: Node,
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
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    use super::*;

    /// A node whose RPC answers each call with the next of `answers`, as
    /// HTTP bodies: and the calls it was made, their bodies.
    fn canned(answers: Vec<String>) -> (Node, std::thread::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc = listener.local_addr().unwrap().to_string();
        let served = std::thread::spawn(move || {
            let mut calls = Vec::new();
            for answer in answers {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                calls.push(serde_json::from_slice(&body).unwrap());
                let mut stream = reader.into_inner();
                stream.write_all(answer.as_bytes()).unwrap();
            }
            calls
        });
        let node = Node {
            rpc,
            jamt: PathBuf::from("jamt"),
            files: std::env::temp_dir(),
        };
        (node, served)
    }

    fn sent(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn chunked(body: &str) -> String {
        let (a, b) = body.split_at(body.len() / 2);
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
            a.len(),
            b.len()
        )
    }

    #[test]
    fn rpc_calls_read_their_results_and_errors() {
        let parameters = r#"{"jsonrpc":"2.0","id":1,"result":{"V1":{"max_refine_gas":1000000000,"slot_period_sec":6,"max_imports":3072,"max_exports":3072,"max_input":13791360,"max_report_elective_data":49152,"core_count":2}}}"#;
        let head = r#"{"jsonrpc":"2.0","id":1,"result":{"header_hash":"aGVhZA==","slot":9}}"#;
        let request = r#"{"jsonrpc":"2.0","id":1,"result":[7]}"#;
        let segments = r#"{"jsonrpc":"2.0","id":1,"result":["AQID",null]}"#;
        let error =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}"#;
        let (node, served) = canned(vec![
            sent(parameters),
            chunked(head),
            sent(head),
            sent(request),
            sent(segments),
            sent(error),
        ]);
        assert_eq!(
            node.parameters().unwrap(),
            Parameters {
                max_refine_gas: 1_000_000_000,
                slot_period_sec: 6,
                max_imports: 3072,
                max_exports: 3072,
                max_input: 13_791_360,
                max_report_elective_data: 49_152,
            }
        );
        assert_eq!(node.head(false).unwrap(), ("aGVhZA==".into(), 9));
        assert_eq!(node.request(1, &[2; 32], 3).unwrap(), Some(vec![7]));
        let fetched = node.fetch(&[4; 32], &[0, 1]);
        assert!(fetched.is_err(), "a missing segment: {fetched:?}");
        let error = node.call("parameters", json!([])).unwrap_err();
        assert!(matches!(&error, Error::Node(said) if said.contains("Invalid params")));
        let calls = served.join().unwrap();
        assert_eq!(calls[0]["method"], "parameters");
        assert_eq!(calls[1]["method"], "bestBlock");
        assert_eq!(calls[3]["method"], "serviceRequest");
        assert_eq!(calls[3]["params"][0], "aGVhZA==", "at the finalized block");
        assert_eq!(calls[3]["params"][3], 3);
        assert_eq!(calls[4]["params"][1], json!([0, 1]));
    }

    #[test]
    fn segments_and_values_decode_from_base64() {
        assert_eq!(decoded(&json!("AQID")).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(decoded(&Value::Null).unwrap(), None);
        assert!(decoded(&json!(7)).is_err());
        assert!(decoded(&json!("!!")).is_err());
    }

    #[test]
    fn a_chunked_body_is_joined() {
        let body = b"4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(unchunked(body).unwrap(), b"{\"a\":1}");
        assert!(unchunked(b"9\r\nshort").is_err());
        assert!(http_body(b"HTTP/1.1 200 OK\r\n").is_err());
    }

    #[test]
    fn a_service_id_reads_as_jamt_prints_it() {
        assert_eq!(service_id("0000002a\n").unwrap(), 42);
        assert!(service_id("Created service").is_err());
    }

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
