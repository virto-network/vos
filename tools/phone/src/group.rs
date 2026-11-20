//! The device group on the phone (`vos-phone group`): groups of devices,
//! each a light node's store under one directory, paired and then updated
//! round after round, each device's part of a round timed: the committer's
//! commit (built and held, one synced batch), each other device's reading
//! of the candidate and its evidence (the evidence verified, the commit
//! processed on a copy, its vote), and each device's reading of the votes
//! (verified, counted, the copy swapped in, one synced batch). The agent's
//! part is a script of its control log, chained as `Personal` chains it:
//! what a device spends is the bench's.
//!
//! `vos-phone group --dir DIR [--devices 3,8] [--rounds N]`: one `group`
//! line a group size, every time in microseconds (p50 and p95 over the
//! rounds), and the sizes in bytes: a handshake, the MLS state, what the
//! device keeps of the log, the archive.

use std::path::Path;
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use vos_abi::ids::{InstanceId, Session};
use vos_light::group::{Agent, DeviceGroup, Event, Prepared};
use vos_light::{Config, Light};
use vos_wire::ingress::call_message;
use vos_wire::personal::{
    AdminCall, AdminClass, Attestation, Body, DeviceId, Entry, NewDevice, chain,
};

use crate::light::AGENT;

pub(crate) const IDENTITY: [u8; 32] = [0x1d; 32];
const INSTANCE: InstanceId = InstanceId(5);
/// The batch time the script starts at, and a round's step.
const T0: u64 = 1_800_000_000_000;

fn agent() -> Agent {
    Agent {
        identity: IDENTITY,
        instance: INSTANCE,
    }
}

/// The agent's control log, as `Personal` would write it for these
/// rounds.
pub(crate) struct Script {
    entries: Vec<(u64, Entry)>,
    chain: [u8; 32],
    pub(crate) now: u64,
}

impl Script {
    fn append(&mut self, body: Body) -> u64 {
        let index = self.entries.len() as u64;
        self.now += 1;
        let linked = chain(&self.chain, index, self.now, &body);
        self.chain = linked;
        self.entries.push((
            index,
            Entry {
                at: self.now,
                body,
                chain: linked,
            },
        ));
        index
    }
}

pub(crate) struct Device {
    pub(crate) light: Light,
    pub(crate) group: DeviceGroup,
    sync: SigningKey,
    admin: SigningKey,
}

/// Device `n`'s keys: its sync key its light node's, its scopes' author.
fn keys(light: &Light, n: u8) -> (SigningKey, SigningKey, NewDevice) {
    let sync = light.sync_key().clone();
    let admin = SigningKey::from_bytes(&[n | 0x80; 32]);
    let device = NewDevice {
        sync: sync.verifying_key().to_bytes(),
        admin: admin.verifying_key().to_bytes(),
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: true,
        },
        nullifier: [n; 32],
        label: vec![n; 8],
    };
    (sync, admin, device)
}

/// Device `n`'s votes, signed.
fn votes(device: &Device, id: DeviceId, events: Vec<Event>, script: &mut Script) {
    for event in events {
        if let Event::Vote {
            epoch,
            vote,
            message,
        } = event
        {
            let index = script
                .entries
                .iter()
                .rev()
                .find_map(|(index, entry)| {
                    matches!(entry.body, Body::Candidate { .. }).then_some(*index)
                })
                .expect("a candidate");
            let signature = device.sync.sign(&message).to_bytes();
            script.append(Body::Vote {
                device: id,
                epoch,
                candidate: index,
                vote,
                signature,
            });
        }
    }
}

/// One round: `committer`'s commit (adding `add`, if given), its candidate
/// with the set of every member, its evidence, every member's vote, and
/// every device's reading of them. Each part's time, in microseconds.
struct Round {
    commit: u64,
    process: Vec<u64>,
    confirm: Vec<u64>,
    handshake: usize,
}

fn round(
    devices: &mut [Device],
    committer: usize,
    script: &mut Script,
    prepared: Prepared,
    commit_us: u64,
) -> Round {
    let arguments = prepared.arguments();
    let committer_admin = devices[committer].admin.verifying_key().to_bytes();
    let members: Vec<DeviceId> = devices
        .iter()
        .filter_map(|device| device.group.id())
        .collect();
    let added = prepared
        .effect
        .add
        .as_ref()
        .map(|_| members.len() as DeviceId);
    let index = script.append(Body::Candidate {
        call: AdminCall {
            origin: committer_admin,
            method: vos_wire::personal::method::COMMIT.0,
            arguments: arguments.clone(),
        },
        by: committer as DeviceId,
        epoch: prepared.epoch,
        added,
        set: members.clone(),
    });
    let session = Session {
        key: committer_admin,
        name: [7; 16],
        t0: script.now,
    };
    let message = call_message(
        &IDENTITY,
        &session,
        index,
        INSTANCE,
        vos_wire::personal::method::COMMIT,
        &arguments,
    );
    let signature = devices[committer].admin.sign(&message).to_bytes();
    let group = &mut devices[committer].group;
    group.signed_commit(message.clone(), signature).unwrap();
    group.called_commit(index).unwrap();
    script.append(Body::Evidence {
        index,
        message,
        signature,
        welcome: prepared.welcome.clone(),
    });
    let confirmed = Event::Confirmed {
        epoch: prepared.epoch,
    };
    let mut process = Vec::new();
    let mut done = vec![false; devices.len()];
    for (at, device) in devices.iter_mut().enumerate() {
        let unread = unread(device, script);
        let started = Instant::now();
        let events = device.group.follow(unread).unwrap();
        if at != committer && device.group.id().is_some() {
            process.push(started.elapsed().as_micros() as u64);
        }
        done[at] = events.contains(&confirmed);
        if let Some(id) = device.group.id() {
            votes(device, id, events, script);
        }
    }
    let mut confirm = Vec::new();
    for (at, device) in devices.iter_mut().enumerate() {
        let unread = unread(device, script);
        let started = Instant::now();
        let events = device.group.follow(unread).unwrap();
        if !done[at] {
            confirm.push(started.elapsed().as_micros() as u64);
            assert!(events.contains(&confirmed), "{events:?}");
        }
    }
    Round {
        commit: commit_us,
        process,
        confirm,
        handshake: prepared.handshake.len(),
    }
}

/// The log's entries past `device`'s cursor.
fn unread(device: &Device, script: &Script) -> Vec<(u64, Entry)> {
    script.entries[device.group.cursor() as usize..].to_vec()
}

fn quantile(times: &mut [u64], q: usize) -> u64 {
    times.sort_unstable();
    times
        .get((times.len() * q / 100).min(times.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0)
}

/// `size` devices, each a light node's store under `root`, the first
/// claiming the agent and pairing the rest, each pairing confirmed by every
/// device: the devices and the agent's log.
pub(crate) fn household(root: &Path, size: usize) -> (Vec<Device>, Script) {
    let _ = std::fs::remove_dir_all(root);
    let mut script = Script {
        entries: Vec::new(),
        chain: [0; 32],
        now: T0,
    };
    let mut devices: Vec<Device> = Vec::new();
    for n in 0..size {
        let light =
            Light::open(&root.join(n.to_string()), AGENT, Config::default()).expect("opens");
        let (sync, admin, device) = keys(&light, n as u8 + 1);
        if n == 0 {
            script.append(Body::Assigned {
                device: 0,
                kit: Vec::new(),
            });
            let group = DeviceGroup::create(light.store(), agent(), device, Vec::new(), script.now)
                .unwrap();
            devices.push(Device {
                light,
                group,
                sync,
                admin,
            });
            continue;
        }
        let package = DeviceGroup::key_package(light.store(), &device, script.now).unwrap();
        let (prepared, pairing) = devices[0]
            .group
            .pair(device.clone(), package, script.now)
            .unwrap();
        let group = DeviceGroup::join(light.store(), device, pairing, Vec::new()).unwrap();
        devices.push(Device {
            light,
            group,
            sync,
            admin,
        });
        round(&mut devices, 0, &mut script, prepared, 0);
    }
    (devices, script)
}

pub fn group(args: &[String]) {
    let mut dir = None;
    let mut sizes = vec![3usize, 8];
    let mut rounds = 20usize;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--dir" => dir = args.next().cloned(),
            "--devices" => {
                sizes = args
                    .next()
                    .expect("--devices N,M")
                    .split(',')
                    .map(|n| n.parse().expect("a group size"))
                    .collect()
            }
            "--rounds" => {
                rounds = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .expect("--rounds N")
            }
            other => panic!("unknown flag {other}"),
        }
    }
    let dir = dir.expect("--dir DIR");
    if AGENT.is_empty() {
        eprintln!(
            "built without the release artifacts: `just build-programs build-test-actors`, then build again"
        );
        std::process::exit(2);
    }
    for size in sizes {
        let root = Path::new(&dir).join(format!("group-{size}"));
        let (mut devices, mut script) = household(&root, size);
        // Past the paired devices' probation, as the log's time runs.
        script.now += vos_wire::personal::Policy::DEFAULT.probation_ms;
        let scope = [0x6e; 16];
        for device in &mut devices {
            device.group.key(scope).unwrap();
        }
        let (mut commits, mut processes, mut confirms) = (Vec::new(), Vec::new(), Vec::new());
        let mut handshake = 0;
        for at in 0..rounds {
            let committer = at % size;
            let started = Instant::now();
            let prepared = devices[committer].group.commit(None, script.now).unwrap();
            let commit_us = started.elapsed().as_micros() as u64;
            let done = round(&mut devices, committer, &mut script, prepared, commit_us);
            commits.push(done.commit);
            processes.extend(done.process);
            confirms.extend(done.confirm);
            handshake = done.handshake;
        }
        let key = devices[0].group.key(scope).unwrap();
        for device in &mut devices {
            assert_eq!(
                device.group.key(scope).unwrap(),
                key,
                "one key on every device"
            );
        }
        let (state, follow, archive) = devices[0].group.stored_bytes().unwrap();
        println!(
            r#"{{"group":"rounds","devices":{size},"rounds":{rounds},"commit_p50_us":{},"commit_p95_us":{},"process_p50_us":{},"process_p95_us":{},"confirm_p50_us":{},"confirm_p95_us":{},"handshake_bytes":{handshake},"mls_state_bytes":{state},"log_state_bytes":{follow},"archive_bytes":{archive},"log_entries":{}}}"#,
            quantile(&mut commits, 50),
            quantile(&mut commits, 95),
            quantile(&mut processes, 50),
            quantile(&mut processes, 95),
            quantile(&mut confirms, 50),
            quantile(&mut confirms, 95),
            script.entries.len(),
        );
    }
}
