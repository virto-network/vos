// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The shared phone double (`vos_light::testing::Phone`) as the facility's
//! client lends it (the `testing` feature): its device's sources, its
//! secret source, and its prompts behind the chrome's forms, each form read
//! back into the prompt it shows.

use vos_light::space::{Approval, Card, Prompts as _};
pub use vos_light::testing::Phone;
use vos_light::testing::hmac;
use vos_wire::credentials::Onion;
use zeroize::Zeroizing;

use crate::node::{Device, Prompts};
use crate::source::{BoxFuture, Kind, Output, Reference, Source, SourceError};
use crate::{Answer, Form};
use s4_credential_contract::KeyAnswer;

/// The card a form's rows show: the home's handle and each onion.
fn card(form: &Form) -> Card {
    let row = |label: &str| {
        form.rows
            .iter()
            .find(|(named, _)| named == label)
            .map(|(_, value)| value.clone())
    };
    let bytes = |text: String| -> [u8; 32] {
        hex::decode(text)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("32 bytes in hex")
    };
    let mut onions = Vec::new();
    while let Some(address) = row(&format!("Onion {}", onions.len() + 1)) {
        let host = row(&format!("Onion {} host key", onions.len() + 1)).expect("its host key");
        onions.push(Onion {
            key: vos_light::tor::onion_key(&address).expect("an onion's address"),
            ssh_host_key: bytes(host),
        });
    }
    Card {
        handle: bytes(row("Home").expect("the kit's card")),
        onions,
    }
}

fn answered(confirmed: bool, form: &Form) -> Answer {
    if !confirmed {
        return Answer::Declined;
    }
    Answer::Confirmed {
        choice: 0,
        values: form
            .fields
            .iter()
            .map(|field| field.value.clone())
            .collect(),
    }
}

fn key_answer(result: Result<Vec<u8>, vos_light::space::Error>) -> KeyAnswer {
    match result {
        Ok(bytes) => KeyAnswer::Done(bytes.into()),
        Err(vos_light::space::Error::Declined) => KeyAnswer::Declined,
        Err(error) => KeyAnswer::Failed(error.to_string()),
    }
}

impl Prompts for Phone {
    fn confirm(&self, form: Form) -> Answer {
        match form.title.as_str() {
            "Your recovery phrase" => {
                let words: Vec<&str> = form
                    .rows
                    .iter()
                    .filter(|(label, _)| label.parse::<u8>().is_ok())
                    .map(|(_, word)| word.as_str())
                    .collect();
                let shown =
                    self.show_phrase(&words.join(" "), &card(&form), form.notice.as_deref());
                answered(shown, &form)
            }
            "Your recovery key's card" => {
                let shown = self.show_card(&card(&form), form.notice.as_deref());
                answered(shown, &form)
            }
            crate::personal::CHECK_PHRASE => {
                // The user reads the asked words off what they wrote.
                let phrase = self.phrase();
                let words: Vec<&str> = phrase.split(' ').collect();
                let values = form
                    .fields
                    .iter()
                    .map(|field| {
                        let at: usize = field
                            .label
                            .strip_prefix("Word ")
                            .and_then(|at| at.parse().ok())
                            .expect("a word's position");
                        words[at - 1].to_owned()
                    })
                    .collect();
                Answer::Confirmed { choice: 0, values }
            }
            crate::personal::ENTER_PHRASE => match self.enter_phrase() {
                Some(words) => Answer::Confirmed {
                    choice: 0,
                    values: vec![words.to_string()],
                },
                None => Answer::Declined,
            },
            "Approve a new admin key" => {
                let row = |label: &str| {
                    form.rows
                        .iter()
                        .find(|(named, _)| named == label)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default()
                };
                let device = row("Device");
                let (id, label) = device.split_once(' ').unwrap_or((&device, ""));
                let approval = Approval {
                    device: id.parse().unwrap_or(0),
                    label: label.trim_matches(['(', ')']).to_owned(),
                    check: row("Key check"),
                    hardware: row("Key kept in") == "hardware",
                };
                let approved = self.approve_admin(&approval);
                answered(approved, &form)
            }
            _ => {
                let filled = form
                    .fields
                    .iter()
                    .map(|field| field.value.clone())
                    .collect();
                match self.answer(format!("{form:?}"), filled) {
                    Some(values) => Answer::Confirmed { choice: 0, values },
                    None => Answer::Declined,
                }
            }
        }
    }

    fn create_key(&self, kind: Kind) -> KeyAnswer {
        match kind {
            Kind::Keystore => key_answer(self.create_source()),
            Kind::SecurityKey | Kind::Kit => key_answer(self.create_kit_key()),
            Kind::Admin => key_answer(self.create_admin().map(|admin| {
                let flags = u8::from(admin.hardware) | u8::from(admin.verified_boot) << 1;
                [&admin.key[..], &[flags]].concat()
            })),
        }
    }

    fn evaluate_key(&self, kind: Kind, key: &[u8], input: &[u8; 32]) -> KeyAnswer {
        match kind {
            // One security key, its discoverable credential the kit's.
            Kind::SecurityKey | Kind::Kit => {
                key_answer(self.kit_secret(key, input).map(|out| out.to_vec()))
            }
            Kind::Keystore => key_answer(self.evaluate_source(key, input).map(|out| out.to_vec())),
            Kind::Admin => KeyAnswer::Failed("an admin key evaluates nothing".into()),
        }
    }

    fn stage(&self, stage: crate::personal::Stage) {
        self.stages.lock().unwrap().push(stage as u8);
    }

    fn progress(&self, text: &str) {
        self.said.lock().unwrap().push(text.to_owned());
    }

    fn sign_key(&self, kind: Kind, key: &[u8], message: &[u8]) -> KeyAnswer {
        assert_eq!(kind, Kind::Admin, "only the admin key signs");
        let Ok(key) = <[u8; 32]>::try_from(key) else {
            return KeyAnswer::Failed("no such key".into());
        };
        key_answer(
            self.sign_admin(&key, message)
                .map(|signature| signature.to_vec()),
        )
    }
}

impl Device for Phone {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }
}

impl Source for Phone {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }

    fn create(&self, kind: Kind) -> BoxFuture<'_, Result<Reference, SourceError>> {
        let made = match kind {
            Kind::SecurityKey => Reference::SecurityKey {
                credential: self.create_kit_key().unwrap_or_default(),
            },
            _ => Reference::Keystore {
                alias: String::from_utf8(self.new_alias()).expect("an alias"),
            },
        };
        Box::pin(async move { Ok(made) })
    }

    fn evaluate<'a>(
        &'a self,
        reference: &'a Reference,
        input: [u8; 32],
    ) -> BoxFuture<'a, Result<Output, SourceError>> {
        let output = match reference {
            Reference::Keystore { alias } => self
                .keystore(alias.as_bytes(), &input)
                .map_err(SourceError::Failed),
            Reference::SecurityKey { .. } => Ok(hmac(&self.security_key, &input)),
        };
        Box::pin(async move { output.map(|bytes| Output::new(Zeroizing::new(bytes))) })
    }
}
