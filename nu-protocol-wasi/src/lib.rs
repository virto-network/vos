#![feature(macro_metavar_expr)]
#![allow(async_fn_in_trait)]
use miniserde::Serialize;
/// Minimal(quick'n dirty) implementation of the nu plugin protocol
/// https://www.nushell.sh/contributor-book/plugins.html
use miniserde::json::{self, Number};
use types::{Hello, Response};
use wstd::io;

mod types;

pub use types::{ActionSignature, Flag, NuType, SignatureDetail};

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
    let mut args = args.skip(1);
    match args.next() {
        Some(flag) if flag == "--stdio" => {}
        Some(_) | None => {
            return log::error!("unexpected flags");
        }
    }

    if let Err(e) = nu_protocol::<B>(input, out).await {
        log::error!("{e:?}");
    }
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
    use types::Request as Req;

    // miniserde only supports json
    out.write_all(b"\x04json").await?;
    // say hello first
    respond(&mut out, Response {
        Hello: Some(Hello {
            protocol: "nu-plugin".into(),
            version: NU_VERSION.into(),
            features: vec![],
        }),
        ..Default::default()
    })
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
    use types::{CallType, Metadata, Response, Value};
    // we expect calls to come in a 2 element array
    let Value::Array(mut call) = call else {
        return Err(Error::CallInvalidInput);
    };
    let Value::Number(Number::U64(call_id)) = call.swap_remove(0) else {
        return Err(Error::CallInvalidInput);
    };
    match call.remove(0) {
        Value::String(s) if s == "Signature" => {
            respond(&mut out, Response {
                CallResponse: Some((call_id, CallType {
                    Signature: Some(B::signature()),
                    ..Default::default()
                })),
                ..Default::default()
            })
            .await?;
        }
        Value::String(s) if s == "Metadata" => {
            respond(&mut out, Response {
                CallResponse: Some((call_id, CallType {
                    Metadata: Some(Metadata {
                        version: VERSION.into(),
                    }),
                    ..Default::default()
                })),
                ..Default::default()
            })
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
                        respond(out, Response {
                            CallResponse: Some((call_id, CallType {
                                Error: Some(types::Error { msg }),
                                ..Default::default()
                            })),
                            ..Default::default()
                        })
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
