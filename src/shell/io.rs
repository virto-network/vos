use futures_util::{Sink, Stream};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
mod http;
#[cfg(target_arch = "wasm32")]
mod js_worker;

#[cfg(not(target_arch = "wasm32"))]
pub use http::Cfg;
#[cfg(target_arch = "wasm32")]
pub use js_worker::Cfg;

pub trait InputStream: Stream<Item = Input> + 'static {}
impl<T: Stream<Item = Input> + 'static> InputStream for T {}

pub trait OutputSink: Sink<Result, Error = ()> {}
impl<T: Sink<Result, Error = ()>> OutputSink for T {}

pub fn setup(cfg: Cfg) -> (impl InputStream, impl OutputSink) {
    #[cfg(target_arch = "wasm32")]
    let io = js_worker::setup(cfg);
    #[cfg(not(target_arch = "wasm32"))]
    let io = http::setup(cfg);
    io
}

pub type Result = core::result::Result<Output, ()>;
pub type Id = u32;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Input {
    Empty,
    Prompt(String),
    Auth(String, Auth),
    Open(String),
    Answer(String),
    Data(Vec<u8>),
}

#[serde(rename_all = "camelCase")]
#[derive(Debug, Deserialize)]
pub enum Auth {
    Pwd { user: String, pwd: String },
    Authenticator(AuthenticatorResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorResponse {}

type Challenge = [u8; 32];

#[derive(Debug, Serialize)]
pub struct Message {
    id: Id,
    ts: u32,
    msg: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Output {
    Empty,
    Busy,
    Msg(Message),
    MsgUpdate { id: Id, msg: String },
    WaitingAuth(Challenge),
    WaitingInput(String),
    WaitintData,
}
