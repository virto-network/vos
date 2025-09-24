use static_cell::StaticCell;

pub use embassy_executor as executor;
pub use env_logger as logger;
pub use pico_args as args;
pub use pico_args::Arguments;
pub use protocol;
pub use wasi_executor::run;
pub use wasi_io as io;
pub use wink_macro::{bin, main};

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
}

#[cfg(feature = "http")]
pub mod http {
    use embassy_time as _;
    // use miniserde::json;
    use protocol::{Bin, BinManager};
    use simple_http_server::{Error, HttpError, simple_serve};

    pub async fn serve<B: BinManager>(port: u16, mgr: B) -> Result<(), Error<std::io::Error>> {
        let stack = wasi_io::net::Stack::new();
        let signature = B::bin_signature();
        let bin = mgr.get_bin().await.expect("Bin instantiated");
        simple_serve(
            &stack,
            port,
            bin,
            async |bin, path, _params, _headers, _maybe_body| {
                println!("[wink][handler] got: {path}");
                let (_bin_name, cmd) = path.split_once('/').ok_or_else(|| HttpError::NotFound)?;
                println!("calling: '{cmd}'");
                signature
                    .iter()
                    .find(|c| c.sig.name == cmd)
                    .ok_or(HttpError::NotFound)?;
                let res = match bin.call(cmd, vec![]).await {
                    Ok(res) => res,
                    Err(err) => {
                        // log::warn!("Bin response: {err}");
                        println!("Bin response: {err}");
                        return Err(HttpError::Internal);
                    }
                };
                // Ok(json::to_string(&res).as_bytes())
                Ok(b"Hello world".as_slice())
            },
        )
        .await
    }

    pub async fn run_server<B: BinManager>(port: u16, mgr: B) {
        if let Err(e) = serve(port, mgr).await {
            log::error!("Http server: {e:?}");
        }
    }
}

pub async fn run_nu_plugin(mgr: impl protocol::BinManager) {
    let mut nu = protocol::NuPlugin::new(mgr, io::stdio());
    if let Err(e) = nu.handle_io().await {
        log::error!("Nu protocol: {e:?}");
    }
}

pub enum RunMode {
    Nu,
    #[cfg(feature = "http")]
    HttpServer(u16),
}
impl RunMode {
    pub fn from_args(mut args: Arguments) -> Option<Self> {
        if args.contains("--stdio") {
            return Some(RunMode::Nu);
        }
        #[cfg(feature = "http")]
        {
            let port = args
                .opt_value_from_str("--port")
                .expect("--port")
                .unwrap_or(8888);
            return Some(RunMode::HttpServer(port));
        }
        #[cfg(not(feature = "stand-alone"))]
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

pub fn to_nu_signature(ns: &str, cmds: &[&Cmd]) -> Vec<protocol::CmdSignature> {
    cmds.iter()
        .map(|cmd| protocol::CmdSignature {
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
