//! `vosx help-schema` — emit the full CLI as JSON.
//!
//! Built from clap's `Command` introspection, so the schema
//! always matches what the binary actually accepts. Designed
//! for LLM consumption and for tooling that wants to discover
//! every subcommand + argument without parsing `--help` text.

use clap::{Arg, ArgAction, Command};
use serde::Serialize;

#[derive(Serialize)]
pub struct CommandSchema {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_about: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ArgSchema>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subcommands: Vec<CommandSchema>,
}

#[derive(Serialize)]
pub struct ArgSchema {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<char>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_help: Option<String>,
    pub required: bool,
    pub positional: bool,
    pub repeatable: bool,
    pub takes_value: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value_names: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub default_values: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub possible_values: Vec<String>,
}

pub fn build(cmd: &Command) -> CommandSchema {
    CommandSchema {
        name: cmd.get_name().to_string(),
        about: cmd.get_about().map(ToString::to_string),
        long_about: cmd.get_long_about().map(ToString::to_string),
        args: cmd.get_arguments().map(arg_schema).collect(),
        subcommands: cmd.get_subcommands().map(build).collect(),
    }
}

fn arg_schema(arg: &Arg) -> ArgSchema {
    let action = arg.get_action();
    let takes_value = !matches!(
        action,
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Help | ArgAction::Version,
    );
    let repeatable = matches!(action, ArgAction::Append | ArgAction::Count,);
    let value_names = arg
        .get_value_names()
        .map(|s| s.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    let default_values = arg
        .get_default_values()
        .iter()
        .map(|os| os.to_string_lossy().into_owned())
        .collect();
    let possible_values = arg
        .get_possible_values()
        .iter()
        .map(|pv| pv.get_name().to_string())
        .collect();
    ArgSchema {
        name: arg.get_id().to_string(),
        long: arg.get_long().map(ToString::to_string),
        short: arg.get_short(),
        help: arg.get_help().map(ToString::to_string),
        long_help: arg.get_long_help().map(ToString::to_string),
        required: arg.is_required_set(),
        positional: arg.get_long().is_none() && arg.get_short().is_none(),
        repeatable,
        takes_value,
        value_names,
        default_values,
        possible_values,
    }
}
