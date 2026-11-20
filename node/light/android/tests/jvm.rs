// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every type of the facility's own interface crosses into its parcelable
//! and back unchanged, on a JVM running the classes the SDK's `aidl`
//! generates from `IVosPersonal`'s AIDL and s4's contract's beside it
//! (`just facility-contract`, on s4's harness).

#![cfg(feature = "jvm")]

use std::path::{Path, PathBuf};

use jni::JValue;
use jni::{jni_sig, jni_str};
use s4_credential_contract::Onion;
use s4_credential_contract::java::{JavaError, Parcel};
use s4_credential_contract::jvm::{compile, round_trip, with_vm};
use vos_facility::personal::contract::{
    AIDL, Alarm, Claim, Claimed, Device, Home, KitKind, KitView, Membership, Notice, Owed,
    PairCode, Paired, Pending, PersonalStatus, Phase, Posted, REGISTRY, Refused, Remedy, Seen,
    Synced, Tor, Why,
};

#[test]
fn every_type_crosses_its_parcelable_unchanged() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("personal-jvm");
    let (compiled, android) = compile(
        &[Path::new(AIDL), Path::new(s4_credential_contract::AIDL)],
        &out,
    );
    with_vm(&[&compiled, &android], &[REGISTRY], |env| {
        let onion = Onion {
            key: [6; 32],
            ssh_host_key: [7; 32],
        };
        round_trip(
            env,
            Synced {
                enrollments: 3,
                synced: 2,
                failed: 1,
                bytes_down: 41_000,
                bytes_up: 9_000,
                millis: 2_400,
                notices: Pending::ALL
                    .iter()
                    .map(|pending| Notice {
                        pending: *pending,
                        index: 17,
                        at: 1_700_000_000_000,
                        matures: u64::MAX,
                        fresh: true,
                        by: u32::MAX,
                        by_kit: true,
                        contested: true,
                        alarm: Alarm::Rollback,
                        remedy: Remedy::RePair,
                        targeted: true,
                        kit_only: true,
                    })
                    .collect(),
                seen: vec![Seen {
                    device: u32::MAX,
                    at: 1_700_000_000_000,
                }],
                failures: "the agent refused: NotAdmitted".into(),
            },
        );
        round_trip(env, Synced::default());
        let home = Home {
            space: [1; 32],
            handle: [2; 32],
            agent: u32::MAX,
            identity: [3; 32],
            homes: 3,
            credentials: 9,
            onions: vec![
                onion,
                Onion {
                    key: [8; 32],
                    ..onion
                },
            ],
        };
        round_trip(env, home.clone());
        for kit in KitKind::ALL {
            round_trip(
                env,
                Claim {
                    home: home.clone(),
                    kit: *kit,
                    label: "my phone".into(),
                },
            );
        }
        round_trip(
            env,
            Claimed {
                agent: 11,
                device: u32::MAX,
            },
        );
        round_trip(
            env,
            PairCode {
                code: vec![5; 300].into(),
                expires_ms: 1_700_000_000_000,
            },
        );
        round_trip(
            env,
            Paired {
                device: 1,
                memberships: 2,
            },
        );
        for owed in Owed::ALL {
            round_trip(
                env,
                Membership {
                    space: [1; 32],
                    handle: [2; 32],
                    agent: 5,
                    instance: 9,
                    owed: *owed,
                },
            );
        }
        round_trip(
            env,
            Device {
                id: 2,
                label: "tablet".into(),
                strong: true,
                standing: 3,
                seen: 1_700_000_000_000,
                removed: false,
                me: true,
            },
        );
        round_trip(
            env,
            KitView {
                devices: vec![Device {
                    id: 0,
                    label: "lost phone".into(),
                    strong: true,
                    standing: 2,
                    seen: 1_700_000_000_000,
                    removed: false,
                    me: false,
                }],
                operations: vec![Notice {
                    pending: Pending::Remove,
                    index: 9,
                    by_kit: true,
                    contested: true,
                    ..Notice::default()
                }],
            },
        );
        round_trip(env, KitView::default());
        round_trip(
            env,
            Posted {
                index: u64::MAX,
                at: 1_700_000_000_000,
            },
        );
        for (at, phase) in Phase::ALL.iter().enumerate() {
            round_trip(
                env,
                PersonalStatus {
                    phase: *phase,
                    matures: 1_700_000_000_000,
                    home: home.clone(),
                    agent: 4,
                    device: u32::MAX,
                    tor: Tor::ALL[at % Tor::ALL.len()],
                    tor_why: "a network that blocks Tor".into(),
                    owed: 2,
                    standing: Alarm::ALL
                        .iter()
                        .zip(Remedy::ALL.iter().cycle())
                        .map(|(alarm, remedy)| Notice {
                            pending: Pending::Alarm,
                            alarm: *alarm,
                            remedy: *remedy,
                            ..Notice::default()
                        })
                        .collect(),
                    repair: "its row p/home does not decode".into(),
                },
            );
        }
        round_trip(env, PersonalStatus::default());
        for why in Why::ALL {
            round_trip(
                env,
                Refused {
                    why: *why,
                    device: 3,
                    detail: "NotAdmitted".into(),
                },
            );
        }

        // What the other side may hand over, read strictly: an enum's byte
        // of no value, a count below zero.
        let membership = Membership {
            space: [1; 32],
            handle: [2; 32],
            agent: 5,
            instance: 9,
            owed: Owed::Enroll,
        }
        .to_java(env)
        .unwrap();
        env.set_field(
            &membership,
            jni_str!("owed"),
            jni_sig!("B"),
            JValue::Byte(9),
        )?;
        assert!(matches!(
            Membership::from_java(env, &membership),
            Err(JavaError::Shape(_))
        ));
        let paired = Paired {
            device: 1,
            memberships: 2,
        }
        .to_java(env)
        .unwrap();
        env.set_field(
            &paired,
            jni_str!("memberships"),
            jni_sig!("I"),
            JValue::Int(-1),
        )?;
        assert!(Paired::from_java(env, &paired).is_err());
        Ok(())
    });
}
