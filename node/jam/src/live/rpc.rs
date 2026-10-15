//! The node's JSON-RPC over HTTP: a call, and its answer's body.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::{PolkaJam, failed};
use crate::Error;

impl PolkaJam {
    /// One JSON-RPC call: its result.
    pub(crate) fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
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
pub(super) fn decoded(value: &Value) -> Result<Option<Vec<u8>>, Error> {
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

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::path::PathBuf;

    use super::*;
    use crate::live::Parameters;

    /// A node whose RPC answers each call with the next of `answers`, as
    /// HTTP bodies: and the calls it was made, their bodies.
    fn canned(answers: Vec<String>) -> (PolkaJam, std::thread::JoinHandle<Vec<Value>>) {
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
        let node = PolkaJam {
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
        let (head, slot) = node.finalized().unwrap();
        assert_eq!((&*head, slot), ("aGVhZA==", 9));
        assert_eq!(node.request(&head, 1, &[2; 32], 3).unwrap(), Some(vec![7]));
        let fetched = node.fetch(&[4; 32], &[0, 1]);
        assert!(fetched.is_err(), "a missing segment: {fetched:?}");
        let error = node.call("parameters", json!([])).unwrap_err();
        assert!(matches!(&error, Error::Node(said) if said.contains("Invalid params")));
        let calls = served.join().unwrap();
        assert_eq!(calls[0]["method"], "parameters");
        assert_eq!(calls[1]["method"], "finalizedBlock");
        assert_eq!(calls[2]["method"], "serviceRequest");
        assert_eq!(calls[2]["params"][0], "aGVhZA==", "at the finalized block");
        assert_eq!(calls[2]["params"][3], 3);
        assert_eq!(calls[3]["params"][1], json!([0, 1]));
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
}
