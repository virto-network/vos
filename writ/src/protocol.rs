use crate::State;
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

    pub fn detect() -> Self {
        Self::from_args(Arguments::from_env())
    }

    pub async fn wait_for_actions<S: State>(
        &self,
        task_name: &str,
        on_action: impl AsyncFnMut(crate::Action) -> Result<(), ()>,
    ) {
        match self {
            Protocol::Simple => todo!(),
            Protocol::Nu => nu::wait_for_actions(task_name, S::META, on_action).await,
            Protocol::HttpRpc(_) => todo!(),
        };
    }
}

mod nu {
    use crate::{Metadata, TyDef, io::stdio};
    use miniserde::json;
    use nu_protocol::{Args, CmdSignature, Flag, NuPlugin, SignatureDetail};

    pub async fn wait_for_actions(
        task_name: &str,
        meta: &Metadata,
        mut on_action: impl AsyncFnMut(crate::Action) -> Result<(), ()>,
    ) {
        let signature = to_nu_signature(task_name, meta);
        let mut nu = NuPlugin::new(stdio(), &signature);
        nu.inititial_handshake()
            .await
            .expect("Nu initial handshake");

        while let Some((call_id, name, params)) = nu.next_run_call().await.unwrap() {
            let action = if let Some(ty) = verify_action_exists(&name, meta.queries) {
                let params = verify_params(params, ty);
                crate::Action::Query(ty.name, params)
            } else if let Some(ty) = verify_action_exists(&name, meta.commands) {
                let params = verify_params(params, ty);
                crate::Action::Command(ty.name, params)
            } else {
                continue;
            };
            // TODO return and send values from handler
            if let Err(_) = on_action(action).await {
                log::warn!("{task_name}::{name} returned error");
                let _ = nu.respond_error(call_id, "".into()).await;
            } else {
                let _ = nu.respond_success(call_id, Vec::new()).await;
            }
        }
    }

    fn verify_action_exists<'a>(name: &str, def: &'a [&'a TyDef]) -> Option<&'a TyDef> {
        def.into_iter().find(|t| name == t.name).map(|t| *t)
    }

    fn verify_params(
        mut params: Args,
        ty: &TyDef,
    ) -> Box<dyn Iterator<Item = (&str, json::Value)>> {
        Box::new(
            ty.args
                .iter()
                .filter_map(move |a| Some((a.name, params.remove(a.name)?))),
        ) as Box<dyn Iterator<Item = _>>
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
mod http_rpc {
    use embassy_time as _;
    // use miniserde::json;
    use simple_serve::{Action, Error, HttpError, Method};

    pub async fn serve_task(port: u16, name: &str) -> Result<(), Error<std::io::Error>> {
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
