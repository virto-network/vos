pub use env_logger as logger;
pub use pico_args as args;
pub use protocol;
pub use wink_macro::bin;

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
    pub use wstd::prelude::*;
}

pub fn run<Bin: protocol::Bin>() {
    logger::init();
    if let Err(e) = match run_mode() {
        RunMode::Nu => wstd::runtime::block_on(async {
            protocol::nu_protocol::<Bin>(wstd::io::stdin(), wstd::io::stdout())
                .await
                .map_err(|e| format!("Nu protocol: {e:?}"))
        }),
        RunMode::StandAloneHttp(port) => {
            wstd::runtime::block_on(async { http::serve(port).await.map_err(|e| format!("{e:?}")) })
        }
    } {
        log::error!("{e}")
    }
}

enum RunMode {
    Nu,
    StandAloneHttp(u16),
}

fn run_mode() -> RunMode {
    let mut args = pico_args::Arguments::from_env();
    if args.contains("--stdio") {
        return RunMode::Nu;
    }
    RunMode::StandAloneHttp(0)
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

mod http {
    pub async fn serve(_port: u16) -> Result<(), ()> {
        Ok(())
    }
}
