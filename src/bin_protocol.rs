//! Minimal(quick'n dirty) implementation of the nu plugin protocol
///! https://www.nushell.sh/contributor-book/plugins.html
use miniserde::{
    json::{self, Number},
    Deserialize, Serialize,
};
use res::{Call, Response};
use wstd::{
    io,
    time::{Duration, Timer},
};

// using arbitrary json value as replacement for nu's Value and other types
// https://www.nushell.sh/contributor-book/plugin_protocol_reference.html#value-types
pub use json::Value;
pub use res::{ActionSignature, Flag, SignatureDetail};

const NU_VERSION: &str = "0.101.0";
const VERSION: &str = "0.1.0";

pub trait Bin {
    fn signature() -> Vec<ActionSignature>;
}

macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}

pub async fn run<B: Bin>(
    args: impl Iterator<Item = String>,
    mut input: impl io::AsyncRead,
    mut out: impl io::AsyncWrite,
) -> Result<(), Error> {
    use futures_concurrency::future::Race;

    let mut args = args.skip(1);
    match args.next() {
        Some(flag) if flag == "--stdio" => {}
        Some(_) | None => {
            log::error!("unexpected flags");
            return Ok(());
        }
    }

    // miniserde only supports json
    out.write_all(b"\x04json").await?;

    let timeout = async {
        Timer::after(Duration::from_millis(2000)).wait().await;
        Ok(())
    };
    (timeout, handle_io::<B>(input, out)).race().await
}

#[derive(Debug)]
pub enum Error {
    Serde,
    Io,
    Protocol,
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Error::Io
    }
}
impl From<miniserde::Error> for Error {
    fn from(value: miniserde::Error) -> Self {
        Error::Serde
    }
}

/// handle nu engine messages and respond accordingly
async fn handle_io<B: Bin>(
    mut input: impl io::AsyncRead,
    mut out: impl io::AsyncWrite,
) -> Result<(), Error> {
    use req::Request as Req;
    let mut count = 0;
    let mut line = String::new();
    loop {
        count += 1;
        let req = read_line(&mut input, &mut line).await?;
        log::debug!("stdin line: '{req}'");
        ensure!(!req.is_empty(), Error::Protocol);
        let req = json::from_str::<Req>(&req)?;

        match req {
            Req {
                Hello: Some(hello), ..
            } => {
                ensure!(count == 1, Error::Protocol);
                respond(&mut out, hello).await?;
            }
            Req {
                Call: Some(call), ..
            } => match call {
                Value::Array(a) => {
                    let Value::Number(Number::U64(call_id)) = a.get(0).ok_or(Error::Protocol)?
                    else {
                        return Err(Error::Protocol);
                    };
                    match a.get(1).ok_or(Error::Protocol)? {
                        Value::String(s) if s == "Signature" => {
                            let signature = Response {
                                CallResponse: Some((
                                    *call_id,
                                    Call {
                                        Signature: Some(B::signature()),
                                        ..Default::default()
                                    },
                                )),
                                ..Default::default()
                            };
                            respond(&mut out, signature).await?;
                        }
                        Value::Object(object) => todo!(),
                        _ => {}
                    }
                }
                _ => {}
            },
            Req {
                EngineCallResponse: Some(r),
                ..
            } => {}
            Req {
                Signal: Some(r), ..
            } => {}
            Req {
                Goodbye: Some(s), ..
            } => {}
            _ => {}
        };
    }
}

async fn respond(out: &mut impl io::AsyncWrite, msg: impl Into<Response>) -> io::Result<()> {
    let msg = msg.into();
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

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    protocol: String,
    version: String,
    features: Vec<String>,
}

macro_rules! variant_conversion {
    // hack to skip impl From for types that already implement it
    ($name:ident, $variant:ident -$(optional $o:tt)?) => {};
    ($name:ident, $variant:ident) => {
        #[allow(non_snake_case)]
        impl From<$variant> for $name {
            fn from($variant: $variant) -> Self {
                $name {
                    $variant: Some($variant),
                    ..Default::default()
                }
            }
        }
    };
}
macro_rules! fake_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        #[derive(Default, Debug)]
        #[allow(non_snake_case)]
        pub struct $name { $(pub $variant: Option<$variant>),* }
        $(variant_conversion!{$name, $variant $(-$($o)?)?})*
    };
}

mod req {
    use miniserde::{make_place, Deserialize};

    macro_rules! de_enum {
        (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
            fake_enum!(pub enum $name { $($variant $(-$($o)?)?,)* });
            impl Deserialize for $name {
                fn begin(out: &mut Option<Self>) -> &mut dyn miniserde::de::Visitor {
                    make_place!(Place);
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

    type Hello = super::Hello;
    type Value = super::Value;

    de_enum! {
        pub enum Request {
            Hello,
            Call,
            EngineCallResponse,
            Signal-,
            Goodbye-,
        }
    }

    de_enum! {
        pub enum CallType {
            Metadata-,
            Signature-,
            Run,
            CustomValueOp-,
        }
    }

    #[derive(Deserialize, Debug)]
    pub struct Run {
        pub name: String,
        pub call: CallBody,
        pub input: PipelineData,
    }

    #[derive(Deserialize, Debug)]
    pub struct CallBody {
        pub head: Value,
        pub positional: Vec<Value>,
        pub named: Vec<(String, Value)>,
    }

    de_enum! {
        pub enum PipelineData {
            Empty-,
            Value-,
            // ListStream,
            // ByteStream,
        }
    }
    type Call = Value;
    // type Call = (u32, CallType);
    type Empty = String;
    type EngineCallResponse = (u64, ());
    type Metadata = String;
    type Signature = String;
    type Signal = String;
    type Goodbye = String;
    type CustomValueOp = Value;
}

mod res {
    use miniserde::{json, Serialize};
    use std::borrow::Cow;
    // miniserde doesn't support enums with data or skipping options
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

    type Hello = super::Hello;
    type Value = super::Value;

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

    type CallResponse = (u64, Call);
    ser_enum! {
        pub enum Call {
            Signature,
            Metadata,
            Error,
            // Ordering,
            PipelineData,
        }
    }

    ser_enum! {
        pub enum PipelineData {
            Empty,
            Value,
            // ListStream,
            // ByteStream,
        }
    }
    type Empty = String;

    #[derive(Debug, Serialize)]
    struct EngineCall {}
    #[derive(Debug, Serialize)]
    struct Data {}
    type End = u64;
    type Drop = u64;
    type Ack = u64;

    type Signature = Vec<ActionSignature>;

    #[derive(Debug, Serialize)]
    struct Metadata {
        version: String,
    }
    // https://docs.rs/nu-protocol/latest/nu_protocol/struct.LabeledError.html
    #[derive(Debug, Serialize)]
    struct Error {
        msg: String,
    }
    //---------------------

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
    type Type = json::Value;
    // https://docs.rs/nu-protocol/latest/nu_protocol/enum.Category.html
    type Category = json::Value;
    // https://docs.rs/nu-protocol/latest/nu_protocol/enum.SyntaxShape.html
    type SyntaxShape = json::Value;
    type VarId = usize;
}
