// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A payment, paid once per confirmed form: every proof made for a form
//! names one key, drawn for it and kept before its first proof leaves, and
//! the ledger pays a key once (`Payments.transfer`). A payment whose answer
//! was lost (the connection, a gateway that withheld it, a restart) is
//! settled by the ledger's own word before the next payment's form: paid,
//! or not paid once its proof can no longer run.

use std::time::Instant;

use vos_abi::ids::MethodId;
use vos_light::wire;
use vos_wire::ingress::CredentialRefusal;

use super::clock::CLOCK_SKEW_MS;
use super::{Inner, Kernel, Learned, PROVING, SENDING, Session, declined, describe, store_error};
use crate::chrome::{Answer, Chrome, Field, Form, short};
use crate::enrollment::{Enrollment, Guard, Method, Pending};
use crate::job::now_ms;
use crate::{Code, Paid, Pay, Refusal, refused};
use s4_credential_contract::{TRANSFER, account};
use vos_light::route::Purpose;

/// The most payments a device holds pending at a space: past it, a new one
/// waits for the ledger to settle the last.
const MOST_PENDING: usize = 8;
/// A payment's answer lost on the way: what the user is told, so a retry
/// is known to be safe.
const LOST: &str = "the payment's answer did not arrive: pay the same again to learn whether \
                    it was paid; it is paid once";

/// The last payment proved, its request sent again as it is for the same
/// form while its proof may still run.
#[derive(Clone)]
pub(super) struct Payment {
    key: [u8; 32],
    expires_ms: u64,
    request: Vec<u8>,
}

/// What a payment's answer settles of it.
enum Settles {
    /// The transfer ran: paid, or refused by the ledger for good.
    Ran,
    /// The proof will not run again (its binding ran, or its expiry
    /// passed): a new proof under the same key settles it.
    ProveAgain,
    /// Nothing known: the payment stays pending.
    Unknown,
}

fn settles(answer: &[u8]) -> Settles {
    use vos_abi::abi::Refusal as Node;
    match wire::credentialed_answer(answer) {
        Ok(wire::Answer::Ran { .. }) => Settles::Ran,
        Ok(wire::Answer::Expiry { .. })
        | Ok(wire::Answer::Refused(CredentialRefusal::Replayed)) => Settles::ProveAgain,
        Ok(wire::Answer::Other(body)) => match super::answer::node_refusal(&body) {
            Some(Node::Replayed | Node::CredentialExpired) => Settles::ProveAgain,
            _ => Settles::Unknown,
        },
        _ => Settles::Unknown,
    }
}

/// A fresh key for one confirmed form.
fn draw_key() -> Result<[u8; 32], Refusal> {
    let mut key = [0; 32];
    getrandom::getrandom(&mut key).map_err(|_| {
        refused(
            Code::Prove,
            "the system gave no randomness for a payment's key",
        )
    })?;
    Ok(key)
}

impl Session {
    /// `pay`: a transfer from this device's account, as the user confirmed
    /// it, proved, and paid once whatever becomes of its answer.
    pub async fn pay(&self, request: Pay, chrome: &dyn Chrome) -> Result<Paid, Refusal> {
        let enrollment = self.enrolled()?;
        let method = Self::pinned(
            &enrollment,
            request.agent,
            request.instance,
            &request.method,
            |method| method.guard == Guard::Owner && method.name == TRANSFER,
        )?;
        self.carried(&enrollment)?;
        self.inner.admits(&enrollment, Kernel::Owner).await?;
        self.apart(Learned::Named)?;
        self.read_clock_meanwhile(&enrollment);
        let earlier = self.settle_pending(&enrollment, method).await?;
        let (mut payee, mut amount) = (request.payee.clone(), request.amount.to_string());
        let mut notice = (!earlier.is_empty()).then(|| earlier.join(" "));
        let (payee, amount) = loop {
            let form = Form {
                title: "Confirm the payment".into(),
                detail: format!(
                    "{} this device to pay from its account. What you confirm here is \
                     what is paid.",
                    self.origin_line()
                ),
                rows: vec![
                    ("Space handle".into(), short(&enrollment.handle)),
                    ("Method".into(), describe(method).1),
                    ("From".into(), "this device's account".into()),
                ],
                fields: vec![
                    Field {
                        label: "To account".into(),
                        value: payee.clone(),
                    },
                    Field {
                        label: "Amount".into(),
                        value: amount.clone(),
                    },
                ],
                notice: notice.take(),
                choices: vec!["Pay".into()],
                code: None,
            };
            let Answer::Confirmed { values, .. } = chrome.confirm(form).await else {
                return Err(declined());
            };
            let [to, how_much] = values.as_slice() else {
                return Err(refused(Code::Arguments, "the form answered other fields"));
            };
            (payee, amount) = (to.trim().to_owned(), how_much.trim().to_owned());
            match (account(&payee), amount.parse::<u64>()) {
                (Ok(to), Ok(how_much)) if how_much > 0 => break (to, how_much),
                (Err(_), _) => {
                    notice = Some(
                        "An account's name is 1 to 32 ASCII letters, digits, `.`, `_` or `-`."
                            .into(),
                    )
                }
                _ => notice = Some("The amount is a whole number above zero.".into()),
            }
        };
        let paid = |answer: Vec<u8>, proving_ms: u64| Paid {
            answer,
            proving_ms,
            payee: payee.clone(),
            amount,
        };
        let store = &self.inner.store;
        // The same form confirmed again while it is pending is that
        // payment: its key, so the ledger pays it once.
        let pending = store.pending(&self.origin).map_err(store_error)?;
        let held = pending.into_iter().find(|pending| {
            pending.owner == enrollment.owner && pending.payee == payee && pending.amount == amount
        });
        let now = self.node_now(&enrollment).await?;
        let tree = self.tree();
        if let Some(held) = &held {
            let again = tree.as_ref().and_then(|tree| {
                tree.payment
                    .lock()
                    .expect("payment poisoned")
                    .clone()
                    .filter(|last| last.key == held.key && now + 5_000 < last.expires_ms)
            });
            if let Some(again) = again {
                chrome.stage(SENDING);
                let answer = self
                    .send_payment(&enrollment, &held.key, &again.request)
                    .await?;
                if !matches!(settles(&answer), Settles::ProveAgain) {
                    return Ok(paid(answer, 0));
                }
            }
        }
        let mut pending = match held {
            Some(held) => held,
            None => Pending {
                owner: enrollment.owner,
                key: draw_key()?,
                payee: payee.clone(),
                amount,
                expires_ms: 0,
            },
        };
        let mut proving_ms = 0;
        let mut now = now;
        // Once more when the answer says that proof will not run again:
        // the ledger's answer to the same key then settles it.
        for _ in 0..2 {
            let started = Instant::now();
            let call = self.call_at(
                &enrollment,
                method,
                vos_light::transfer_arguments(&payee, amount, &pending.key),
                now,
            )?;
            pending.expires_ms = call.expires_ms;
            store
                .keep_pending(&self.origin, &pending)
                .map_err(store_error)?;
            let secret = self.secret(&enrollment).await?;
            chrome.stage(PROVING);
            let bytes = Inner::prove(
                &self.inner,
                Kernel::Owner,
                call,
                move |prover, program, call| {
                    let proof = prover.prove_owner(&secret, call, program);
                    drop(secret);
                    proof
                },
            )
            .await?;
            proving_ms += started.elapsed().as_millis() as u64;
            if let Some(tree) = &tree {
                *tree.payment.lock().expect("payment poisoned") = Some(Payment {
                    key: pending.key,
                    expires_ms: pending.expires_ms,
                    request: bytes.clone(),
                });
            }
            chrome.stage(SENDING);
            let answer = self.send_payment(&enrollment, &pending.key, &bytes).await?;
            match settles(&answer) {
                Settles::ProveAgain => now = self.node_now(&enrollment).await?,
                _ => return Ok(paid(answer, proving_ms)),
            }
        }
        Err(refused(Code::Api, LOST))
    }

    /// A payment's request sent: its answer, the payment forgotten once
    /// the answer settles it. A lost answer leaves it pending, and says so.
    async fn send_payment(
        &self,
        enrollment: &Enrollment,
        key: &[u8; 32],
        request: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        let answer = match self.send(enrollment, request).await {
            Ok(answer) => answer,
            Err(refusal) if refusal.code == Code::Api => return Err(refused(Code::Api, LOST)),
            Err(refusal) => return Err(refusal),
        };
        if matches!(settles(&answer), Settles::Ran) {
            self.inner
                .store
                .settled(&self.origin, key)
                .map_err(store_error)?;
        }
        Ok(answer)
    }

    /// The payments this enrollment holds pending, each asked of the
    /// ledger (`Payments.paid`, by its external id alone, a fetch of its
    /// own): one it paid is settled as paid; one it did not, once its
    /// proof can no longer run by the device's own clock (past its expiry
    /// by more than the node's clock may differ), as not paid; any other
    /// stays pending, and a form confirmed with its values pays it once.
    /// What became of each, for the form. Read only in a payment's
    /// session, which names the account already.
    async fn settle_pending(
        &self,
        enrollment: &Enrollment,
        method: &Method,
    ) -> Result<Vec<String>, Refusal> {
        let store = &self.inner.store;
        let pending: Vec<_> = store
            .pending(&self.origin)
            .map_err(store_error)?
            .into_iter()
            .filter(|pending| pending.owner == enrollment.owner)
            .collect();
        let mut said = Vec::new();
        let mut open = 0;
        for pending in pending {
            let what = format!("{} to {}", pending.amount, pending.payee);
            match self.paid(enrollment, method, &pending).await {
                Ok(true) => {
                    store
                        .settled(&self.origin, &pending.key)
                        .map_err(store_error)?;
                    said.push(format!("Your earlier payment of {what} was paid."));
                }
                Ok(false) if now_ms() > pending.expires_ms.saturating_add(CLOCK_SKEW_MS) => {
                    store
                        .settled(&self.origin, &pending.key)
                        .map_err(store_error)?;
                    said.push(format!("Your earlier payment of {what} was not paid."));
                }
                _ => {
                    open += 1;
                    said.push(format!(
                        "Your earlier payment of {what} has no answer yet: paying the same \
                         again pays it once."
                    ));
                }
            }
        }
        if open >= MOST_PENDING {
            return Err(refused(
                Code::Refused,
                "earlier payments have no answer yet: try again in a few minutes",
            ));
        }
        Ok(said)
    }

    /// Whether the ledger paid under `pending`'s key, by its own read.
    async fn paid(
        &self,
        enrollment: &Enrollment,
        method: &Method,
        pending: &Pending,
    ) -> Result<bool, Refusal> {
        let identity = enrollment
            .agent(method.agent)
            .ok_or_else(|| refused(Code::NotPinned, "the ledger's agent was not pinned"))?
            .identity;
        let now = self.node_now(enrollment).await?;
        let external = vos_wire::payments::external_id(&pending.owner, &pending.key);
        let query = wire::query_request(
            method.agent,
            &identity,
            method.instance,
            MethodId(vos_light::method_id("paid")),
            vos_abi::Encode::encode(&external),
            now + super::EXPIRY_MS,
        )
        .map_err(|error| refused(Code::Prove, error.to_string()))?;
        let answer = self
            .inner
            .net
            .request_for(enrollment.routes(), Purpose::Fetch, &query, Some(self.id))
            .await
            .map_err(|error| refused(Code::Api, error))?;
        wire::query_answer::<bool>(&answer).map_err(|error| refused(Code::Api, error.to_string()))
    }
}
