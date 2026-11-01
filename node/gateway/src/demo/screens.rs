//! The demo's screens.

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
    Row(String),
    Payee(String),
    Amount(String),
    Enroll,
    Enrollment(EffectOutput),
    Enrolled(EffectOutput),
    Claim,
    Claimed(EffectOutput),
    SignIn,
    /// Sign in with a device proof of the device actor's kernel.
    SignInKernel,
    Proved(Screen, EffectOutput),
    Relayed(Screen, EffectOutput),
    Pay,
    Balance(EffectOutput),
    Refreshed(EffectOutput),
}

/// One connection's screens.
pub struct Screens {
    demo: Demo,
    screen: Screen,
    row: String,
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
            row: String::new(),
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
    fn failed(&mut self, output: EffectOutput) {
        self.status = match output {
            EffectOutput::HostService(Err(error)) => error.message,
            EffectOutput::Facility(Err(error)) => format!("{}: {}", error.code, error.message),
            _ => "an unexpected answer".into(),
        };
    }

    fn proved(&mut self, screen: Screen, output: EffectOutput, cx: &mut Cx<Message>) {
        let EffectOutput::Facility(Ok(answer)) = output else {
            return self.failed(output);
        };
        let Some(request) = map_bytes(&answer, "request") else {
            self.status = "the device's answer holds no request".into();
            return;
        };
        self.proving = map_unsigned(&answer, "proving_ms");
        if screen == Screen::Pay
            && let (Some(payee), Some(amount)) =
                (map_text(&answer, "payee"), map_unsigned(&answer, "amount"))
        {
            // What the device confirmed, whatever this document held.
            self.payee = payee;
            self.amount = amount.to_string();
        }
        self.status = "Sending the proof…".into();
        let screen_name = match screen {
            Screen::Pay => "pay",
            _ => "sign_in",
        };
        cx.effect(Effect::host_service(
            "relay",
            identifier(SERVICE),
            identifier("relay"),
            object([
                ("request", Value::Bytes(request)),
                ("screen", Value::from(screen_name)),
            ]),
            move |output| Message::Relayed(screen, output),
        ));
    }

    fn relayed(&mut self, screen: Screen, output: EffectOutput, cx: &mut Cx<Message>) {
        let EffectOutput::HostService(Ok(answer)) = output else {
            return self.failed(output);
        };
        let proving = self
            .proving
            .map_or_else(String::new, |ms| format!(" (proved in {ms} ms)"));
        let ran = matches!(&answer, Value::Map(map) if map.get("ran") == Some(&Value::Bool(true)));
        if !ran {
            let why = map_text(&answer, "why").unwrap_or_default();
            let unknown = matches!(&answer, Value::Map(map) if map.get("root_unknown") == Some(&Value::Bool(true)));
            if unknown {
                cx.effect(facility("refresh", Value::Null, Message::Refreshed));
                self.status =
                    format!("{why}: the device fetches its path again; try again shortly");
            } else {
                self.status = format!("Not done: {why}{proving}");
            }
            return;
        }
        let reply = map_bytes(&answer, "reply").unwrap_or_default();
        match screen {
            Screen::Pay => {
                self.status = format!("Paid {} to {}{proving}", self.amount, self.payee);
                cx.effect(service(
                    "balance",
                    object([("row", Value::from(self.row.clone()))]),
                    Message::Balance,
                ));
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
            .text("VOS: a member's device proves; this server only relays")
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
                        view::field(self.row.clone(), Message::Row).placeholder("Your row's name"),
                    )
                    .button("Enroll this device", Message::Enroll);
                match self.digests {
                    Some(_) => page
                        .text(
                            "Your device showed its two digests in its own window: read \
                             them from there to the space's operator, then claim them.",
                        )
                        .button("Claim", Message::Claim),
                    None => page,
                }
            }
            Screen::SignIn => {
                let page = page
                    .text("Sign in with your device")
                    .button("Sign in with my device", Message::SignIn);
                match self.demo.device {
                    Some(_) => {
                        page.button("Sign in with my device's kernel", Message::SignInKernel)
                    }
                    None => page,
                }
            }
            Screen::Pay => {
                let page = page
                    .text("Pay from your row")
                    .child(view::field(self.row.clone(), Message::Row).placeholder("From row"))
                    .child(view::field(self.payee.clone(), Message::Payee).placeholder("To row"))
                    .child(view::field(self.amount.clone(), Message::Amount).placeholder("Amount"))
                    .button("Send the payment", Message::Pay);
                match &self.balance {
                    Some(balance) => page.text(format!("Balance of {}: {balance}", self.row)),
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
            Message::Row(row) => self.row = row,
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
                        self.status = "Enrolled on this device".into();
                    }
                    _ => self.status = "the device's digests do not decode".into(),
                }
            }
            Message::Claim => {
                let Some((member, owner)) = self.digests else {
                    return;
                };
                self.status = "Claiming…".into();
                cx.effect(service(
                    "claim",
                    object([
                        ("member", Value::Bytes(member.to_vec())),
                        ("owner", Value::Bytes(owner.to_vec())),
                        ("row", Value::from(self.row.clone())),
                    ]),
                    Message::Claimed,
                ));
            }
            Message::Claimed(output) => match output {
                EffectOutput::HostService(Ok(slot)) => {
                    self.status = format!(
                        "Claimed: member at slot {}, row {}",
                        display(&slot),
                        self.row
                    );
                }
                other => self.failed(other),
            },
            Message::SignIn | Message::SignInKernel => {
                let instance = match (&message, &self.demo.device) {
                    (Message::SignInKernel, Some(device)) => device.instance,
                    _ => self.demo.poll,
                };
                self.status = "Asking the device…".into();
                self.proving = None;
                cx.effect(facility(
                    "sign_in",
                    object([
                        ("agent", Value::from(self.demo.agent)),
                        ("instance", Value::from(instance)),
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
                        ("instance", Value::from(self.demo.purses)),
                        ("method", Value::from(TRANSFER)),
                        ("payer", Value::from(self.row.clone())),
                        ("payee", Value::from(self.payee.clone())),
                        ("amount", Value::from(amount)),
                    ]),
                    |output| Message::Proved(Screen::Pay, output),
                ));
            }
            Message::Proved(screen, output) => self.proved(screen, output, cx),
            Message::Relayed(screen, output) => self.relayed(screen, output, cx),
            Message::Balance(output) => match output {
                EffectOutput::HostService(Ok(balance)) => self.balance = Some(display(&balance)),
                other => self.failed(other),
            },
            Message::Refreshed(_) => {}
        }
    }
}

fn display(value: &Value) -> String {
    match value {
        Value::Integer(s4_server::rui::protocol::Integer::Unsigned(value)) => value.to_string(),
        Value::Null => "no such row".into(),
        other => format!("{other:?}"),
    }
}
