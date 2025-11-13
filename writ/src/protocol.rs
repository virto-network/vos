use pico_args::Arguments;

pub enum Protocol {
    Simple,
    Nu,
    HttpRpc(u16),
}

impl Protocol {
    pub fn from_args(mut args: Arguments) -> Self {
        if args.contains("--stdio") {
            return Protocol::Nu;
        };
        if let Ok(port) = args.opt_value_from_str::<_, u16>("--port") {
            Protocol::HttpRpc(port.unwrap_or(8888))
        } else {
            Protocol::Simple
        }
    }
}

pub mod nu {
    use crate::{Metadata, State, Task, io::stdio};
    use nu_protocol::{CmdSignature, Flag, NuPlugin, SignatureDetail};

    pub async fn run_plugin<S: State>(task: &mut crate::Task<S>) {
        let signature = to_nu_signature(task.name(), Task::<S>::metadata());
        let mut nu = NuPlugin::new(stdio(), &signature, &mut *task);
        if let Err(e) = nu.handle_io(async |_, _, _| Ok(())).await {
            log::error!("Nu protocol: {e:?}");
        }
    }

    pub fn to_nu_signature(ns: &str, meta: &Metadata) -> &'static [CmdSignature] {
        let signature = meta
            .commands
            .iter()
            .map(|cmd| CmdSignature {
                sig: SignatureDetail {
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
                        .map(|arg| Flag {
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
            .collect::<Box<[_]>>();
        Box::leak(signature)
    }
}

#[cfg(feature = "http")]
pub mod http_rpc {
    use embassy_time as _;
    // use miniserde::json;
    use simple_serve::{Action, Error, HttpError, Method};

    pub async fn serve_task<T: Task>(
        port: u16,
        id: Option<T::Id>,
    ) -> Result<(), Error<std::io::Error>> {
        let task = T::get_or_new(id).await;
        simple_serve::rpc(port, task, async |task, action| {
            // signature
            //     .iter()
            //     .filter_map(|c| c.sig.name.split_once(' '))
            //     .find(|c| c.0 == bin_name && c.1 == cmd)
            //     .ok_or(HttpError::NotFound)?;

            log::debug!("Calling {bin_name} '{cmd}'");
            let res = match bin.call(cmd, vec![]).await {
                Ok(res) => res,
                Err(err) => {
                    log::warn!("Bin response: {err}");
                    return Err(HttpError::Internal);
                }
            };
            // Ok(json::to_string(&res).as_bytes())
            Ok(b"Hello world".as_slice())
        })
        .await
    }

    pub async fn run_server<B: BinManager>(port: u16, mgr: B) {
        if let Err(e) = serve_task(port, mgr).await {
            log::error!("Http server: {e:?}");
        }
    }
}
