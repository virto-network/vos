//! The golden fixtures (`proving.md` A.6) as the venues' harnesses read
//! them, from `pvm/proof/fixtures`: each a case, a venue's state, a
//! statement, a proof and the verdict every venue must reach.
//!
//! - `wrap.proof` and the other `wrap-*.proof`: final proofs, postcard;
//! - [`CASES`]: the cases, each its name, its proof's file, a [`Patch`] of
//!   that proof's bytes if any, its [`Input`] and its verdict's code
//!   (`crate::code`), in this module's encoding ([`encode`]).
//!
//! The generator (`pvm/proof/tests/fixtures.rs`) writes them, and refuses
//! fixtures it no longer makes.

use alloc::string::String;
use alloc::vec::Vec;
use std::path::{Path, PathBuf};

use crate::DecodeError;
use crate::codec::{self, Reader};
use crate::model::Input;

/// The cases' file.
pub const CASES: &str = "statements.cases";

/// The fixtures' directory, `pvm/proof/fixtures`.
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

/// Bytes made from a proof's: `removed` bytes at `offset` replaced by
/// `inserted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub offset: u32,
    pub removed: u32,
    pub inserted: Vec<u8>,
}

impl Patch {
    /// The patch that makes `to` from `from`: the bytes between their
    /// common prefix and their common suffix.
    pub fn between(from: &[u8], to: &[u8]) -> Self {
        let prefix = from.iter().zip(to).take_while(|(a, b)| a == b).count();
        let suffix = from[prefix..]
            .iter()
            .rev()
            .zip(to[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Self {
            offset: prefix as u32,
            removed: (from.len() - prefix - suffix) as u32,
            inserted: to[prefix..to.len() - suffix].to_vec(),
        }
    }

    pub fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        let (offset, removed) = (self.offset as usize, self.removed as usize);
        [
            &bytes[..offset],
            &self.inserted[..],
            &bytes[offset + removed..],
        ]
        .concat()
    }
}

/// A case as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    /// The proof's file, under the fixtures' directory.
    pub proof: String,
    pub patch: Option<Patch>,
    pub input: Input,
    /// The verdict's code: 0 accepted, else the refusal's.
    pub verdict: u32,
}

/// The cases' encoding: a compact count, then each case's name and proof
/// file (a compact length and the bytes), its patch (a byte, 0 or 1, then
/// the offset and the removed count as little-endian `u32`s and the
/// inserted bytes), its input ([`Input::encode`]) and its verdict
/// (a little-endian `u32`).
pub fn encode(cases: &[Case]) -> Vec<u8> {
    let mut out = Vec::new();
    codec::compact(&mut out, cases.len() as u64);
    for case in cases {
        for text in [&case.name, &case.proof] {
            codec::compact(&mut out, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        match &case.patch {
            None => out.push(0),
            Some(patch) => {
                out.push(1);
                out.extend_from_slice(&patch.offset.to_le_bytes());
                out.extend_from_slice(&patch.removed.to_le_bytes());
                codec::compact(&mut out, patch.inserted.len() as u64);
                out.extend_from_slice(&patch.inserted);
            }
        }
        out.extend_from_slice(&case.input.encode());
        out.extend_from_slice(&case.verdict.to_le_bytes());
    }
    out
}

/// The cases `bytes` encode.
pub fn decode(bytes: &[u8]) -> Result<Vec<Case>, DecodeError> {
    let mut reader = Reader::new(bytes);
    let count = reader.count(1)?;
    let text = |reader: &mut Reader<'_>| {
        String::from_utf8(reader.bytes()?).map_err(|_| DecodeError::Noncanonical)
    };
    let mut cases = Vec::with_capacity(count);
    for _ in 0..count {
        let name = text(&mut reader)?;
        let proof = text(&mut reader)?;
        let patch = match reader.u8()? {
            0 => None,
            1 => Some(Patch {
                offset: reader.u32()?,
                removed: reader.u32()?,
                inserted: reader.bytes()?,
            }),
            _ => return Err(DecodeError::Noncanonical),
        };
        let at = reader.used();
        let (input, used) = Input::decode_prefix(&bytes[at..])?;
        reader.take(used)?;
        let verdict = reader.u32()?;
        cases.push(Case {
            name,
            proof,
            patch,
            input,
            verdict,
        });
    }
    reader.finish()?;
    Ok(cases)
}

/// A fixture, ready to judge.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub name: String,
    pub input: Input,
    /// The proof's bytes, patched.
    pub proof: Vec<u8>,
    pub verdict: u32,
}

impl Fixture {
    /// A judgement's bytes (`crate::model::judge_bytes`): the input, then
    /// the proof.
    pub fn bytes(&self) -> Vec<u8> {
        [self.input.encode(), self.proof.clone()].concat()
    }
}

/// The fixtures under `directory`.
///
/// # Panics
/// When a file is missing or does not decode.
pub fn load(directory: &Path) -> Vec<Fixture> {
    let read = |name: &str| {
        let path = directory.join(name);
        std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "{}: {error}; `just fixtures` writes the fixtures",
                path.display()
            )
        })
    };
    let cases = decode(&read(CASES)).expect("the cases decode");
    cases
        .into_iter()
        .map(|case| {
            let proof = read(&case.proof);
            Fixture {
                name: case.name,
                input: case.input,
                proof: case
                    .patch
                    .map_or(proof.clone(), |patch| patch.apply(&proof)),
                verdict: case.verdict,
            }
        })
        .collect()
}
