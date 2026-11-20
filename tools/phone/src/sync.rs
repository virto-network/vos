//! Sealed sync on the phone (`vos-phone sync`): PG6's 1 MiB catch-up, the
//! device's part. Two devices, each a light node's store under one
//! directory, paired in one device group over a scripted agent log
//! (`group.rs`); the notes actor installed on both; the writer records a
//! mebibyte of titles in a fresh scope and pushes it sealed, the reader
//! catches the scope up from its start: every envelope opened and its node
//! applied through the merge entry, one synced batch a page. The agent is
//! a stand-in in the process that stores the envelopes and answers `push`
//! and `since` as `Personal` does (deduplicated by id, the epoch checked,
//! pages of at most 60 KiB): what is timed is the device's, and the round
//! trips over the network are not in it.
//!
//! `vos-phone sync --dir DIR [--rounds N] [--shapes small,large]`: one
//! `sync` line a shape: small titles (1,000 bytes) or the largest a call
//! takes; the catch-up's and the push's p50 and p95 in milliseconds over
//! the rounds (each a fresh scope), the envelopes and the bytes read, and
//! the writer's calls.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_light::personal::{Answer, Frontier, Link, SealedSync};
use vos_light::release::Package;
use vos_light::route::Route;
use vos_wire::personal::{
    ANSWER_BYTES, Envelope, Header, MAX_ENVELOPE, PersonalError, Pushed, Scope, Woken, envelope_id,
};

use crate::group::{Device, household};
use crate::light::{AGENT, NOTES, embedded, percentile};

/// An envelope the stand-in holds: its id and its bytes.
type Held = ([u8; 32], Vec<u8>);

/// The stand-in agent: each scope's envelopes in the order taken, their
/// ids, and the confirmed epoch.
#[derive(Default)]
struct Agent {
    confirmed: u64,
    now: u64,
    scopes: BTreeMap<Scope, Vec<Held>>,
    ids: BTreeMap<[u8; 32], u64>,
}

impl Agent {
    fn push(&mut self, envelope: &[u8]) -> Result<Pushed, PersonalError> {
        self.now += 1;
        if envelope.len() > MAX_ENVELOPE {
            return Err(PersonalError::TooLarge);
        }
        let header = Header::parse(envelope).ok_or(PersonalError::Malformed)?;
        let id = envelope_id(envelope);
        if let Some(position) = self.ids.get(&id) {
            return Ok(Pushed {
                at: self.now,
                position: *position,
                id,
            });
        }
        if header.epoch != self.confirmed {
            return Err(PersonalError::StaleEpoch {
                confirmed: self.confirmed,
            });
        }
        let scope = self.scopes.entry(header.scope).or_default();
        scope.push((id, envelope.to_vec()));
        let position = scope.len() as u64;
        self.ids.insert(id, position);
        Ok(Pushed {
            at: self.now,
            position,
            id,
        })
    }

    fn since(&self, scope: Scope, position: u64) -> Vec<Envelope> {
        let mut page = Vec::new();
        let mut bytes = 0;
        let held = self.scopes.get(&scope).map_or(&[][..], Vec::as_slice);
        for (at, (id, envelope)) in held.iter().enumerate().skip(position as usize) {
            bytes += Envelope::FRAMING + envelope.len();
            if bytes > ANSWER_BYTES && !page.is_empty() {
                break;
            }
            page.push(Envelope {
                position: at as u64 + 1,
                id: *id,
                bytes: envelope.clone(),
            });
        }
        page
    }
}

/// The link to the stand-in, through the onion as far as the light node is
/// concerned: no request of the bench leaves the process.
struct Local<'a>(&'a mut Agent);

impl Link for Local<'_> {
    type Error = std::convert::Infallible;

    fn route(&self) -> Route {
        Route::Onion
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Self::Error> {
        Ok(envelopes
            .iter()
            .map(|envelope| self.0.push(envelope))
            .collect())
    }

    fn since(
        &mut self,
        scope: Scope,
        position: u64,
    ) -> Result<Result<Vec<Envelope>, PersonalError>, Self::Error> {
        Ok(Ok(self.0.since(scope, position)))
    }

    fn wake(&mut self) -> Result<Result<Woken, PersonalError>, Self::Error> {
        Ok(Ok(Woken {
            at: self.0.now,
            settled: true,
        }))
    }

    /// No device is removed in the bench.
    fn frontier(&mut self, _: u32) -> Answer<Frontier, Self::Error> {
        Ok(Ok(Vec::new()))
    }
}

fn sealed<T>(
    agent: &mut Agent,
    device: &mut Device,
    instance: InstanceId,
    f: impl FnOnce(&mut SealedSync<'_, Local<'_>>) -> T,
) -> T {
    let mut link = Local(agent);
    let mut sync =
        SealedSync::new(&device.light, &mut device.group, &mut link, vec![instance]).unwrap();
    f(&mut sync)
}

pub fn sync(args: &[String]) {
    let mut dir = None;
    let mut rounds = 3usize;
    let mut shapes = vec!["small".to_string(), "large".to_string()];
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--dir" => dir = args.next().cloned(),
            "--rounds" => {
                rounds = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .expect("--rounds N")
            }
            "--shapes" => {
                shapes = args
                    .next()
                    .expect("--shapes small,large")
                    .split(',')
                    .map(str::to_string)
                    .collect()
            }
            other => panic!("unknown flag {other}"),
        }
    }
    let dir = dir.expect("--dir DIR");
    embedded(&[AGENT, NOTES]);
    let notes = Package::decode_exact(NOTES).expect("the embedded package decodes");
    let (mut devices, _) = household(&Path::new(&dir).join("sync"), 2);
    let mut agent = Agent {
        confirmed: devices[0].group.confirmed(),
        ..Agent::default()
    };
    let title = MethodId(vos_light::method_id("title"));
    let (writer, reader) = devices.split_at_mut(1);
    let (writer, reader) = (&mut writer[0], &mut reader[0]);
    for (n, shape) in shapes.iter().enumerate() {
        let len = match shape.as_str() {
            "small" => 1000,
            "large" => vos_light::MAX_ARGUMENTS - 12,
            other => panic!("unknown shape {other}"),
        };
        let operations = (1 << 20) / len + 1;
        let (mut catch_ups, mut pushes, mut calls) = (Vec::new(), Vec::new(), Vec::new());
        let (mut envelopes, mut bytes) = (0, 0);
        for round in 0..rounds {
            let instance = InstanceId(100 + 16 * n as u32 + round as u32);
            for device in [&mut *writer, &mut *reader] {
                let outcome = device.light.install(instance, &notes, Vec::new()).unwrap();
                assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
                let scope = device.light.scope_id(instance).unwrap().0;
                device.group.key(scope).unwrap();
            }
            for key in 0..operations as u64 {
                let text = format!("{key:08}").repeat(len / 8);
                let started = Instant::now();
                let outcome = writer
                    .light
                    .call(instance, title, (key, text).encode())
                    .unwrap();
                calls.push(started.elapsed().as_secs_f64() * 1e3);
                assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
            }
            let started = Instant::now();
            let pushed = sealed(&mut agent, writer, instance, |sync| sync.push(instance)).unwrap();
            pushes.push(started.elapsed().as_secs_f64() * 1e3);
            assert_eq!(pushed.pushed.len(), operations);
            let started = Instant::now();
            let caught =
                sealed(&mut agent, reader, instance, |sync| sync.catch_up(instance)).unwrap();
            catch_ups.push(started.elapsed().as_secs_f64() * 1e3);
            assert!(caught.passed.is_empty() && caught.waiting.is_none());
            assert_eq!(caught.ingested.unwrap().applied.len(), operations);
            envelopes = caught.envelopes;
            bytes = caught.bytes;
        }
        println!(
            r#"{{"sync":"catch_up","shape":"{shape}","rounds":{rounds},"envelopes":{envelopes},"bytes":{bytes},"catch_up_p50_ms":{:.1},"catch_up_p95_ms":{:.1},"push_p50_ms":{:.1},"push_p95_ms":{:.1},"call_p50_ms":{:.2},"call_p95_ms":{:.2}}}"#,
            percentile(&mut catch_ups, 50),
            percentile(&mut catch_ups, 95),
            percentile(&mut pushes, 50),
            percentile(&mut pushes, 95),
            percentile(&mut calls, 50),
            percentile(&mut calls, 95),
        );
    }
}
