#![allow(async_fn_in_trait)]
/// Minimal(quick'n dirty) implementation of the nu plugin protocol
/// https://www.nushell.sh/contributor-book/plugins.html
use miniserde::json::{self, Number};
use miniserde::Serialize;
use nu_types::{Hello, Response};
use wstd::{
    io,
    time::{Duration, Timer},
};

pub use nu_types::{ActionSignature, Flag, NuType, SignatureDetail};

const NU_VERSION: &str = "0.102.0";
const VERSION: &str = "0.1.0";

pub trait Bin: Default {
    fn signature() -> Vec<ActionSignature>;
    async fn call(&mut self, cmd: &str, args: Vec<NuType>) -> Result<Box<dyn Serialize>, String>;
}

pub async fn run<B: Bin>(
    args: impl Iterator<Item = String>,
    input: impl io::AsyncRead,
    out: impl io::AsyncWrite,
) {
    use futures_concurrency::future::Race;

    let mut args = args.skip(1);
    match args.next() {
        Some(flag) if flag == "--stdio" => {}
        Some(_) | None => {
            return log::error!("unexpected flags");
        }
    }

    let timeout = async {
        Timer::after(Duration::from_millis(2000)).wait().await;
    };
    let handle_io = async {
        if let Err(e) = nu_protocol::<B>(input, out).await {
            log::error!("{e:?}");
        }
    };
    (timeout, handle_io).race().await
}

#[derive(Debug)]
pub enum Error {
    Serde,
    Io,
    Protocol,
    NotSupported,
    CallInvalidInput,
}
impl From<io::Error> for Error {
    fn from(_value: io::Error) -> Self {
        Error::Io
    }
}
impl From<miniserde::Error> for Error {
    fn from(_value: miniserde::Error) -> Self {
        Error::Serde
    }
}

/// handle nu engine messages and respond accordingly
async fn nu_protocol<B: Bin>(
    mut input: impl io::AsyncRead,
    mut out: impl io::AsyncWrite,
) -> Result<(), Error> {
    use nu_types::Request as Req;

    // miniserde only supports json
    out.write_all(b"\x04json").await?;
    // say hello first
    respond(
        &mut out,
        Response {
            Hello: Some(Hello {
                protocol: "nu-plugin".into(),
                version: NU_VERSION.into(),
                features: vec![],
            }),
            ..Default::default()
        },
    )
    .await?;

    let mut line = String::new();
    loop {
        let req = read_line(&mut input, &mut line).await?;
        log::error!("stdin line: '{req}'");
        if req.is_empty() || req == "\"Goodbye\"" {
            return Ok(());
        }
        let req = json::from_str::<Req>(&req)?;

        match req {
            Req {
                Hello: Some(_hello),
                ..
            } => { // TODO Already said hello, could check protocol versions though
            }
            Req {
                Call: Some(call), ..
            } => handle_call_request::<B>(&mut out, call).await?,
            Req {
                EngineCallResponse: Some(_r),
                ..
            } => return Err(Error::NotSupported),
            Req {
                Signal: Some(_r), ..
            } => return Err(Error::NotSupported),
            _ => return Err(Error::Protocol),
        };
    }
}

async fn handle_call_request<B: Bin>(
    mut out: &mut impl io::AsyncWrite,
    call: json::Value,
) -> Result<(), Error> {
    use nu_types::{CallType, Metadata, Response, Value};
    // we expect calls to come in a 2 element array
    let Value::Array(mut call) = call else {
        return Err(Error::CallInvalidInput);
    };
    let Value::Number(Number::U64(call_id)) = call.swap_remove(0) else {
        return Err(Error::CallInvalidInput);
    };
    match call.remove(0) {
        Value::String(s) if s == "Signature" => {
            respond(
                &mut out,
                Response {
                    CallResponse: Some((
                        call_id,
                        CallType {
                            Signature: Some(B::signature()),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                },
            )
            .await?;
        }
        Value::String(s) if s == "Metadata" => {
            respond(
                &mut out,
                Response {
                    CallResponse: Some((
                        call_id,
                        CallType {
                            Metadata: Some(Metadata {
                                version: VERSION.into(),
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                },
            )
            .await?;
        }
        Value::Object(mut call) => match call.pop_first() {
            Some((k, Value::Object(call))) if k == "Run" => {
                let (cmd_name, args) = parse_call(call).ok_or(Error::CallInvalidInput)?;
                log::error!("calling {cmd_name} with {args:?}");
                // TODO restore/persist program state
                let mut program = B::default();
                match program.call(&cmd_name, args).await {
                    Ok(output) => {
                        log::error!("program returned {:?}", json::to_string(&output))
                    }
                    Err(msg) => {
                        respond(
                            out,
                            Response {
                                CallResponse: Some((
                                    call_id,
                                    CallType {
                                        Error: Some(nu_types::Error { msg }),
                                        ..Default::default()
                                    },
                                )),
                                ..Default::default()
                            },
                        )
                        .await?;
                    }
                }
            }
            Some((k, Value::Object(_))) if k == "CustomValueOp" => return Err(Error::NotSupported),
            Some(_) | None => return Err(Error::Protocol),
        },
        _ => {}
    };
    Ok(())
}

fn parse_call(mut call: json::Object) -> Option<(String, Vec<NuType>)> {
    use json::Value;
    let Value::String(cmd_name) = call.remove("name")? else {
        return None;
    };
    // For now we asume all programs are "program sub-command"
    let (_, cmd_name) = cmd_name.split_once(' ')?;
    let Value::Object(mut args) = call.remove("call")? else {
        return None;
    };
    // our macro assumes named arguments
    let Value::Array(args) = args.remove("named")? else {
        return None;
    };
    let mut parsed_args = Vec::with_capacity(args.len());
    for arg in args {
        let Value::Array(mut arg) = arg else {
            return None;
        };
        let Value::String(_name) = arg.swap_remove(0) else {
            return None;
        };
        let Value::Object(mut val) = arg.remove(0) else {
            return None;
        };
        let (ty, Value::Object(mut val)) = val.pop_first()? else {
            return None;
        };
        let ty = match (ty.as_str(), val.remove("val")) {
            ("Binary", Some(Value::Array(val))) => NuType::Binary(val),
            ("Bool", Some(Value::Bool(val))) => NuType::Bool(val),
            ("Date", Some(Value::String(val))) => NuType::Date(val),
            ("Duration", Some(Value::String(val))) => NuType::Duration(val),
            ("Filesize", Some(Value::String(val))) => NuType::Filesize(val),
            ("Float", Some(Value::Number(Number::F64(val)))) => NuType::Float(val),
            ("Int", Some(Value::Number(Number::I64(val)))) => NuType::Int(val),
            ("List", Some(Value::Array(val))) => NuType::List(val),
            ("Nothing", Some(Value::Null)) => NuType::Nothing,
            ("Number", Some(Value::Number(Number::U64(val)))) => NuType::Number(val),
            ("Record", Some(Value::Object(val))) => NuType::Record(val),
            ("String", Some(Value::String(val))) => NuType::String(val),
            ("Glob", Some(Value::String(val))) => NuType::Glob(val),
            ("Table", Some(Value::Object(val))) => NuType::Table(val),
            _ => return None,
        };
        parsed_args.push(ty);
    }
    Some((cmd_name.into(), parsed_args))
}

async fn respond(out: &mut impl io::AsyncWrite, msg: Response) -> io::Result<()> {
    let msg = json::to_string(&msg);
    out.write_all(msg.as_bytes()).await?;
    out.write(b"\n").await?;
    out.flush().await?;
    Ok(())
}

async fn read_line(reader: &mut impl io::AsyncRead, out: &mut String) -> io::Result<String> {
    let mut buf = [0u8; 128];
    loop {
        if let Some(i) = out.chars().position(|b| b == '\n' || b == '\r') {
            out.remove(i);
            let new = out.split_off(i);
            return Ok(std::mem::replace(out, new));
        }
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    Ok(std::mem::take(out))
}

// miniserde doesn't support enums with data or skipping options so we simulate an enum with a struct
// https://github.com/dtolnay/miniserde/issues/60
macro_rules! fake_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        #[derive(Default, Debug)]
        #[allow(non_snake_case)]
        pub struct $name { $(pub $variant: Option<$variant>),* }
    };
}
macro_rules! ser_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        fake_enum!(pub enum $name { $($variant $(-$($o)?)?,)* });
        impl Serialize for $name {
            fn begin(&self) -> miniserde::ser::Fragment {
                struct Serializer<'a>{
                    data: &'a $name,
                    done: bool,
                }
                impl<'a> miniserde::ser::Map for Serializer<'a> {
                    fn next(&mut self) -> Option<(Cow<str>, &dyn Serialize)> {
                        if self.done { return None }
                        // a "fake enum" should only have one *Some* propery
                        // we check properties one by one and return the first with data
                        $(if let Some(p) = self.data.$variant.as_ref() {
                            self.done = true;
                            return Some((Cow::Borrowed(stringify!($variant)), p as &dyn Serialize));
                        };)*
                        None
                    }
                }
                miniserde::ser::Fragment::Map(Box::new(Serializer { data: self, done: false }))
            }
        }
    }
}
macro_rules! de_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        fake_enum!(pub enum $name { $($variant $(-$($o)?)?,)* });
        impl Deserialize for $name {
            fn begin(out: &mut Option<Self>) -> &mut dyn miniserde::de::Visitor {
                miniserde::make_place!(Place);
                impl miniserde::de::Visitor for Place<$name> {
                    fn map(&mut self) -> miniserde::Result<Box<dyn miniserde::de::Map + '_>> {
                        Ok(Box::new(Map {
                            out: &mut self.out,
                            val: $name { ..Default::default() },
                        }))
                    }
                }
                struct Map<'a> { out: &'a mut Option<$name>, val: $name }
                impl<'a> miniserde::de::Map for Map<'a> {
                    fn key(&mut self, k: &str) -> miniserde::Result<&mut dyn miniserde::de::Visitor> {
                        match k {
                            $(stringify!($variant) => { Ok(Deserialize::begin(&mut self.val.$variant)) },)*
                            _ => Err(miniserde::Error),
                        }
                    }
                    fn finish(&mut self) -> miniserde::Result<()> {
                        let substitute = $name { ..Default::default() };
                        *self.out = Some(std::mem::replace(&mut self.val, substitute));
                        Ok(())
                    }
                }
                Place::new(out)
            }
        }
    }
}

pub mod nu_types {
    use miniserde::{
        json::{self, Number},
        Deserialize, Serialize,
    };
    use std::borrow::Cow;
    // using arbitrary json value as replacement for nu's Value and other types
    // https://www.nushell.sh/contributor-book/plugin_protocol_reference.html#value-types
    pub type Value = miniserde::json::Value;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Hello {
        pub protocol: String,
        pub version: String,
        pub features: Vec<Value>,
    }

    de_enum! {
        pub enum Request {
            Hello,
            Call,
            EngineCallResponse,
            Signal-,
        }
    }

    type Call = Value;
    type Signal = String;
    type EngineCallResponse = (u64, ());

    ser_enum! {
        pub enum Response {
            Hello,
            CallResponse,
            EngineCall,
            // Option,
            Data,
            End-,
            Drop-,
            Ack-,
        }
    }
    type CallResponse = (u64, CallType);
    ser_enum! {
        pub enum CallType {
            Metadata,
            Signature,
            Error,
        }
    }
    #[derive(Debug, Serialize)]
    pub struct EngineCall {}
    #[derive(Debug, Serialize)]
    pub struct Data {}
    type End = u64;
    type Drop = u64;
    type Ack = u64;
    pub type Signature = Vec<ActionSignature>;

    #[derive(Debug, Serialize)]
    pub struct Metadata {
        pub version: String,
    }
    // https://docs.rs/nu-protocol/latest/nu_protocol/struct.LabeledError.html
    #[derive(Debug, Serialize)]
    pub struct Error {
        pub msg: String,
    }

    //--------------------------

    #[derive(Debug)]
    pub enum NuType {
        Binary(json::Array),
        Bool(bool),
        Date(String),
        Duration(String),
        Filesize(String),
        Float(f64),
        Int(i64),
        List(json::Array),
        Nothing,
        Number(u64),
        Record(json::Object),
        String(String),
        Glob(String),
        Table(json::Object),
    }

    impl TryFrom<NuType> for Vec<u8> {
        type Error = ();
        fn try_from(value: NuType) -> Result<Self, Self::Error> {
            let NuType::Binary(value) = value else {
                return Err(());
            };
            value
                .into_iter()
                .map(|v| {
                    let Value::Number(Number::U64(n)) = v else {
                        return None;
                    };
                    u8::try_from(n).ok()
                })
                .collect::<Option<_>>()
                .ok_or(())
        }
    }
    impl TryFrom<NuType> for bool {
        type Error = ();
        fn try_from(value: NuType) -> Result<Self, Self::Error> {
            let NuType::Bool(value) = value else {
                return Err(());
            };
            Ok(value)
        }
    }
    impl TryFrom<NuType> for String {
        type Error = ();
        fn try_from(value: NuType) -> Result<Self, Self::Error> {
            let NuType::String(value) = value else {
                return Err(());
            };
            Ok(value)
        }
    }
    impl TryFrom<NuType> for u64 {
        type Error = ();
        fn try_from(value: NuType) -> Result<Self, Self::Error> {
            let NuType::Number(value) = value else {
                return Err(());
            };
            Ok(value)
        }
    }

    //--------------------------

    #[derive(Debug, Serialize)]
    pub struct ActionSignature {
        pub sig: SignatureDetail,
        pub examples: Vec<BinExample>,
    }
    #[derive(Debug, Serialize)]
    pub struct SignatureDetail {
        pub name: String,
        pub description: String,
        pub extra_description: String,
        pub search_terms: Vec<String>,
        pub required_positional: Vec<PositionalArg>,
        pub optional_positional: Vec<PositionalArg>,
        pub rest_positional: Option<PositionalArg>,
        pub named: Vec<Flag>,
        pub input_output_types: Vec<(Type, Type)>,
        pub allow_variants_without_examples: bool,
        pub is_filter: bool,
        pub creates_scope: bool,
        pub allows_unknown_args: bool,
        pub category: Category,
    }
    #[derive(Debug, Serialize)]
    pub struct Flag {
        pub long: String,
        pub short: Option<String>, // char
        pub arg: Option<SyntaxShape>,
        pub required: bool,
        pub desc: String,
        pub var_id: Option<VarId>,
        pub default_value: Option<Value>,
    }
    #[derive(Debug, Serialize)]
    pub struct BinExample {
        pub example: String,
        pub description: String,
        pub result: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct PositionalArg {
        pub name: String,
        pub desc: String,
        pub shape: SyntaxShape,
        pub var_id: Option<VarId>,
        pub default_value: Option<Value>,
    }

    // https://docs.rs/nu-protocol/latest/nu_protocol/enum.Type.html
    type Type = Value;
    // https://docs.rs/nu-protocol/latest/nu_protocol/enum.Category.html
    type Category = String;
    // https://docs.rs/nu-protocol/latest/nu_protocol/enum.SyntaxShape.html
    type SyntaxShape = json::Value;
    type VarId = usize;
}
