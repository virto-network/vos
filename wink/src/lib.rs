use static_cell::StaticCell;
use wasi_executor::Executor;

pub use embassy_executor as executor;
pub use env_logger as logger;
pub use pico_args as args;
pub use protocol;
pub use wink_macro::bin;

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
}

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

pub fn async_runtime() -> &'static mut Executor {
    EXECUTOR.init(Executor::new())
}

#[cfg(feature = "stand-alone")]
pub mod http {
    use embassy_time as _;
    use miniserde::json;
    use protocol::Bin;
    use simple_http_server::{Error, HttpError, simple_serve};

    pub async fn serve(port: u16, mgr: &impl protocol::BinManager) -> Result<(), Error> {
        let stack = wasi_net::Stack::new();
        let _res = simple_serve(
            stack,
            port,
            move |path, _params, _headers, _maybe_body| async move {
                let mut bin = mgr.get_bin().await.unwrap();
                let (_bin_name, cmd) = path.split_once('/').ok_or_else(|| HttpError::NotFound)?;
                let res = match bin.call(cmd, vec![]).await {
                    Ok(res) => res,
                    Err(err) => {
                        log::warn!("Bin response: {err}");
                        return Err(simple_http_server::HttpError::Internal);
                    }
                };
                // Ok(json::to_string(&res).as_bytes())
                Ok(b"Hello world".as_slice())
            },
        )
        .await?;
        Ok(())
    }
}

pub enum RunMode {
    Nu,
    #[cfg(feature = "stand-alone")]
    StandAloneHttp(u16),
}
impl RunMode {
    pub fn from_args() -> Option<Self> {
        let mut args = pico_args::Arguments::from_env();
        if args.contains("--stdio") {
            return Some(RunMode::Nu);
        }
        #[cfg(feature = "stand-alone")]
        {
            let port = args
                .opt_value_from_str("--port")
                .expect("--port")
                .unwrap_or(8080);
            return Some(RunMode::StandAloneHttp(port));
        }
        None
    }
}

pub struct Cmd {
    pub name: &'static str,
    pub desc: &'static str,
    pub args: &'static [Arg],
}

pub struct Arg {
    pub name: &'static str,
    pub ty: &'static str,
}

pub fn to_nu_signature(ns: &str, cmds: &[&Cmd]) -> Vec<protocol::ActionSignature> {
    cmds.iter()
        .map(|cmd| protocol::ActionSignature {
            sig: protocol::SignatureDetail {
                name: format!("{ns} {}", cmd.name),
                description: cmd.desc,
                extra_description: "",
                search_terms: [],
                required_positional: [],
                optional_positional: [],
                rest_positional: None,
                named: cmd
                    .args
                    .iter()
                    .map(|arg| protocol::Flag {
                        long: arg.name,
                        short: None,
                        arg: Some(arg.ty),
                        required: true,
                        desc: "",
                        var_id: None,
                        default_value: None,
                    })
                    .collect(),
                input_output_types: [],
                allow_variants_without_examples: true,
                is_filter: false,
                creates_scope: false,
                allows_unknown_args: false,
                category: "Misc",
            },
            examples: [],
        })
        .collect()
}

pub mod io {
    pub use embedded_io_async::{Error, ErrorType, Read, Write};

    pub fn stdio() -> StdIo {
        StdIo
    }

    pub struct StdIo;

    impl Read for StdIo {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            todo!()
        }
    }

    impl Write for StdIo {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            todo!()
        }
    }

    impl ErrorType for StdIo {
        type Error = std::io::Error;
    }
}
