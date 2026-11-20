//! The demo's screens.

use super::service::{Errors, method_error, payment_error, response as response_of};
use super::*;

/// Which screen is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Enroll,
    SignIn,
    Pay,
}

#[derive(Clone)]
pub enum Message {
    Show(Screen),
    Account(String),
    Payee(String),
    Amount(String),
    Enroll,
    Enrollment(EffectOutput),
    Enrolled(EffectOutput),
    Held(EffectOutput),
    Claim,
    Claimed(EffectOutput),
    SignIn,
    Proved(Screen, EffectOutput),
    Pay,
    Balance(EffectOutput),
    Refreshed(EffectOutput),
}

/// One connection's screens.
pub struct Screens {
    demo: Demo,
    screen: Screen,
    /// The name of the account the member claims.
    account: String,
    payee: String,
    amount: String,
    /// The device's member and owner digests, once it enrolled.
    digests: Option<([u8; 32], [u8; 32])>,
    status: String,
    proving: Option<u64>,
    balance: Option<String>,
}

impl Screens {
    pub fn new(demo: Demo) -> Self {
        Self {
            demo,
            screen: Screen::Enroll,
            account: String::new(),
            payee: String::new(),
            amount: String::new(),
            digests: None,
            status: String::new(),
            proving: None,
            balance: None,
        }
    }
}

fn service(operation: &str, args: Value, done: fn(EffectOutput) -> Message) -> Effect<Message> {
    Effect::host_service(
        operation,
        identifier(SERVICE),
        identifier(operation),
        args,
        done,
    )
}

fn facility(
    operation: &str,
    args: Value,
    done: impl Fn(EffectOutput) -> Message + Send + 'static,
) -> Effect<Message> {
    Effect::new(
        operation,
        EffectRequest::Facility {
            facility: s4_server::rui::protocol::TypeRef::new(identifier(FACILITY), 1)
                .expect("major 1"),
            operation: identifier(operation),
            args,
        },
        done,
    )
}

fn map_bytes(value: &Value, name: &str) -> Option<Vec<u8>> {
    match value {
        Value::Map(map) => match map.get(name)? {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn map_unsigned(value: &Value, name: &str) -> Option<u64> {
    match value {
        Value::Map(map) => match map.get(name)? {
            Value::Integer(s4_server::rui::protocol::Integer::Unsigned(value)) => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

fn map_text(value: &Value, name: &str) -> Option<String> {
    match value {
        Value::Map(map) => match map.get(name)? {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn short(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
}

impl Screens {
    /// The enrollment of `member` and `owner` for the account typed, as the
    /// service takes it.
    fn enrollment(&self, member: [u8; 32], owner: [u8; 32]) -> Value {
        object([
            ("member", Value::Bytes(member.to_vec())),
            ("owner", Value::Bytes(owner.to_vec())),
            ("account", Value::from(self.account.clone())),
        ])
    }

    fn failed(&mut self, output: EffectOutput) {
        self.status = match output {
            EffectOutput::HostService(Err(error)) => error.message,
            EffectOutput::Facility(Err(error)) => format!("{}: {}", error.code, error.message),
            _ => "an unexpected answer".into(),
        };
    }

    /// The device's result: what it proved, sent by the facility itself,
    /// and the node's answer, which the screen shows. Nothing the device
    /// hands back is relayed: anything but a node's answer is refused here.
    fn proved(&mut self, screen: Screen, output: EffectOutput, cx: &mut Cx<Message>) {
        let EffectOutput::Facility(Ok(answer)) = output else {
            return self.failed(output);
        };
        let Some(answer) = map_bytes(&answer, "answer")
            .and_then(|bytes| Response::decode_exact(&bytes))
            .map(|response| (answer, response))
        else {
            self.status = "the device's result holds no node's answer".into();
            return;
        };
        let (result, response) = answer;
        self.proving = map_unsigned(&result, "proving_ms");
        if screen == Screen::Pay
            && let (Some(payee), Some(amount)) =
                (map_text(&result, "payee"), map_unsigned(&result, "amount"))
        {
            // What the device confirmed, whatever this document held.
            self.payee = payee;
            self.amount = amount.to_string();
        }
        let proving = self
            .proving
            .map_or_else(String::new, |ms| format!(" (proved in {ms} ms)"));
        let errors: Errors = match screen {
            Screen::Pay => payment_error,
            _ => method_error,
        };
        let reply = match response_of(&response, errors) {
            Ok(reply) => reply,
            Err(why) => {
                let unknown = matches!(
                    response,
                    Response::Rejected(Rejection::Credential(
                        CredentialRefusal::RootUnknown | CredentialRefusal::RootStale
                    ))
                );
                if unknown {
                    cx.effect(facility("refresh", Value::Null, Message::Refreshed));
                    self.status =
                        format!("{why}: the device reads the tree again; try again shortly");
                } else {
                    self.status = format!("Not done: {why}{proving}");
                }
                return;
            }
        };
        match screen {
            Screen::Pay => {
                self.status = format!("Paid {} to {}{proving}", self.amount, self.payee);
                // The payer's account, read by the owner digest the device
                // showed: the one it paid from.
                if let Some((_, owner)) = self.digests {
                    cx.effect(service(
                        "balance",
                        object([("owner", Value::Bytes(owner.to_vec()))]),
                        Message::Balance,
                    ));
                }
            }
            _ => {
                let pseudonym = Option::<[u8; 32]>::decode_exact(&reply)
                    .flatten()
                    .map_or_else(|| "a member".into(), |nullifier| short(&nullifier));
                self.status = format!("Signed in as {pseudonym}{proving}");
            }
        }
    }
}

impl App for Screens {
    type Message = Message;

    fn view(&self, _context: &ViewContext) -> View<Message> {
        let mut page = view::column()
            .gap(1.0)
            .padding(2.0)
            .text("VOS: a member's device proves; this server only shows")
            .row(|row| {
                row.gap(1.0)
                    .button("Enroll", Message::Show(Screen::Enroll))
                    .button("Sign in", Message::Show(Screen::SignIn))
                    .button("Pay", Message::Show(Screen::Pay))
            });
        page = match self.screen {
            Screen::Enroll => {
                let page = page
                    .text("Enroll this device")
                    .child(
                        view::field(self.account.clone(), Message::Account)
                            .placeholder("Your account's name"),
                    )
                    .button("Enroll this device", Message::Enroll);
                match self.digests {
                    Some(_) => page
                        .text(
                            "Your device showed its two digests in its own window: read \
                             them from there to the space's operator, then claim them.",
                        )
                        .button("Claim", Message::Claim),
                    // The session s4 carries over Tor after an enrollment
                    // claims what that session held, its digests never
                    // shown here, so this one signs in.
                    None => page
                        .text(
                            "Enrolled already? Once the operator invited your digests, claim \
                             them here, then sign in from this session.",
                        )
                        .button("Claim my invitation", Message::Claim),
                }
            }
            // A session the device's digests were shown in signs in
            // nothing: this server would join the sign-in to them.
            Screen::SignIn if self.digests.is_some() => page.text(
                "This session showed your device's digests: reconnect, and sign in from the \
                 new session, so this server cannot join the sign-in to them.",
            ),
            Screen::SignIn => page
                .text("Sign in with your device")
                .button("Sign in with my device", Message::SignIn),
            Screen::Pay => {
                let page = page
                    .text("Pay from this device's account")
                    .child(
                        view::field(self.payee.clone(), Message::Payee).placeholder("To account"),
                    )
                    .child(view::field(self.amount.clone(), Message::Amount).placeholder("Amount"))
                    .button("Send the payment", Message::Pay);
                match &self.balance {
                    Some(balance) => page.text(balance.clone()),
                    None => page,
                }
            }
        };
        View::new(page.text(self.status.clone()))
    }

    fn update(&mut self, message: Message, cx: &mut Cx<Message>) {
        match message {
            Message::Show(screen) => {
                self.screen = screen;
                self.status.clear();
            }
            Message::Account(account) => self.account = account,
            Message::Payee(payee) => self.payee = payee,
            Message::Amount(amount) => self.amount = amount,
            Message::Enroll => {
                self.status = "Asking the device…".into();
                cx.effect(service("enrollment", Value::Null, Message::Enrollment));
            }
            Message::Enrollment(output) => {
                let EffectOutput::HostService(Ok(args)) = output else {
                    return self.failed(output);
                };
                cx.effect(facility("enroll", args, Message::Enrolled));
            }
            Message::Enrolled(output) => {
                let EffectOutput::Facility(Ok(answer)) = &output else {
                    return self.failed(output);
                };
                let digest = |name| {
                    map_bytes(answer, name).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                };
                match (digest("member"), digest("owner")) {
                    (Some(member), Some(owner)) => {
                        self.digests = Some((member, owner));
                        self.status = "Enrolled on this device…".into();
                        // Held for the claim from the session s4 carries
                        // over Tor next.
                        cx.effect(service(
                            "hold",
                            self.enrollment(member, owner),
                            Message::Held,
                        ));
                    }
                    _ => self.status = "the device's digests do not decode".into(),
                }
            }
            Message::Held(output) => match output {
                EffectOutput::HostService(Ok(_)) => {
                    self.status = "Enrolled on this device: once the operator invited you, claim \
                                   here or from the next session"
                        .into()
                }
                other => self.failed(other),
            },
            Message::Claim => {
                self.status = "Claiming…".into();
                let args = match self.digests {
                    Some((member, owner)) => self.enrollment(member, owner),
                    None => Value::Null,
                };
                cx.effect(service("claim", args, Message::Claimed));
            }
            Message::Claimed(output) => match output {
                EffectOutput::HostService(Ok(Value::Array(slots))) => {
                    let slots: Vec<String> = slots.iter().map(display).collect();
                    self.status = match self.digests {
                        Some(_) => format!(
                            "Claimed: member at slot {}, account {}. Pay from here; sign in \
                             from a new session.",
                            slots.join(", "),
                            self.account
                        ),
                        None => format!(
                            "Claimed: member at slot {}. Sign in or pay from here.",
                            slots.join(", ")
                        ),
                    };
                }
                other => self.failed(other),
            },
            Message::SignIn => {
                self.status = "Asking the device…".into();
                self.proving = None;
                cx.effect(facility(
                    "sign_in",
                    object([
                        ("agent", Value::from(self.demo.agent)),
                        ("instance", Value::from(self.demo.poll)),
                        ("method", Value::from(LOGIN)),
                        ("arguments", Value::Bytes(().encode())),
                    ]),
                    |output| Message::Proved(Screen::SignIn, output),
                ));
            }
            Message::Pay => {
                let Ok(amount) = self.amount.trim().parse::<u64>() else {
                    self.status = "The amount is a whole number".into();
                    return;
                };
                self.status = "Asking the device…".into();
                self.proving = None;
                cx.effect(facility(
                    "pay",
                    object([
                        ("agent", Value::from(self.demo.agent)),
                        ("instance", Value::from(self.demo.payments)),
                        ("method", Value::from(TRANSFER)),
                        ("payee", Value::from(self.payee.clone())),
                        ("amount", Value::from(amount)),
                    ]),
                    |output| Message::Proved(Screen::Pay, output),
                ));
            }
            Message::Proved(screen, output) => self.proved(screen, output, cx),
            Message::Balance(output) => match output {
                EffectOutput::HostService(Ok(held)) => {
                    self.balance = Some(
                        match (map_text(&held, "name"), map_unsigned(&held, "balance")) {
                            (Some(name), Some(balance)) => format!("Balance of {name}: {balance}"),
                            _ => "This device holds no account".into(),
                        },
                    )
                }
                other => self.failed(other),
            },
            Message::Refreshed(_) => {}
        }
    }
}

fn display(value: &Value) -> String {
    match value {
        Value::Integer(s4_server::rui::protocol::Integer::Unsigned(value)) => value.to_string(),
        Value::Null => "no such account".into(),
        other => format!("{other:?}"),
    }
}
