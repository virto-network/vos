pub use env_logger as logger;
pub use pico_args as args;
pub use protocol;
pub use wink_macro::bin;
pub use wstd::{io, runtime};

pub mod prelude {
    pub use log;
    pub use miniserde::{Deserialize, Serialize, json};
    pub use wstd::prelude::*;
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
