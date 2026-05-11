//! `vosx <target> <method> [args]` — schema-aware dispatch
//! against any agent or extension instance in a space's registry.
//!
//! Phase 4 of the CLI-dispatch plan. Built on top of
//! [`DaemonClient::invoke_dyn`] + [`DaemonClient::meta_for_instance`]
//! so the wire path is identical to `vosx space call`; the new
//! surface is just (a) more ergonomic (no `space call <space>`
//! prefix), (b) schema-aware (positional args coerce against the
//! handler's declared types), and (c) doubles as the discovery
//! mechanism — `vosx <target>` with no method prints the CLI-
//! exposed handler list.
//!
//! ## Surface
//!
//! ```text
//! vosx <target>                    # list CLI-exposed methods
//! vosx <target> <method>           # invoke (no args)
//! vosx <target> <method> k=v ...   # invoke with typed args
//! vosx <target> --help             # same as `vosx <target>`
//! ```
//!
//! Global `--space <name>` selects which space's daemon to dial;
//! `VOSX_SPACE` env var is the fallback; if a user has exactly
//! one space registered, that one wins implicitly. Multi-space
//! deployments without either signal error with a list.
//!
//! ## Routing precedence
//!
//! `main` decides whether to enter this module by peeking argv
//! before clap. The verb must be neither a built-in subcommand
//! (`run`, `space`, `help-schema`, `help`) nor a path-like token
//! (contains `/` or `\`, or starts with `.`). Path-likes still
//! flow into `commands::run` as one-shot ELF execution.

use anyhow::{Context, anyhow, bail};
use vos::metadata::{ParsedMessage, ParsedMeta};
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;
use crate::spaces_index;

/// Parsed result of stripping global flags out of the dynamic-
/// dispatch argv slice. Positional[0] is the target name,
/// Positional[1] is the method (if any), the rest are typed
/// args (`key=value`).
#[cfg_attr(test, derive(Debug))]
struct ParsedArgv {
    space: Option<String>,
    positional: Vec<String>,
    wants_help: bool,
}

/// Entry point. `argv` is everything after the executable name —
/// global flags + positionals mixed together. We re-walk it here
/// rather than relying on clap because the verb (positional[0])
/// determines whether we're even allowed to enter this module,
/// and re-parsing keeps the routing decision in one place.
pub fn dispatch(argv: &[String]) -> anyhow::Result<()> {
    let parsed = parse_argv(argv)?;

    if parsed.positional.is_empty() {
        bail!("vosx: no target. Try `vosx <agent-or-extension> <method>`.");
    }

    let target = &parsed.positional[0];
    let method = parsed.positional.get(1).filter(|s| !s.is_empty());
    let method_args: Vec<&str> = parsed
        .positional
        .iter()
        .skip(2)
        .map(String::as_str)
        .collect();

    let space = resolve_space(parsed.space.as_deref())?;

    DaemonClient::with_connect(&space, |client| {
        // Always fetch meta first. The schema drives both the
        // "list methods" surface (no method given / --help) and
        // arg coercion below.
        let meta_bytes = client.meta_for_instance(target)?;
        let meta = if meta_bytes.is_empty() {
            None
        } else {
            vos::metadata::decode(&meta_bytes)
        };

        // Side-effect: write the decoded schema back to the
        // CLI cache so `vosx --help` can discover this target
        // without dialling the daemon. Strictly an optimisation
        // — failures are swallowed inside `update_target`.
        if let Some(m) = &meta {
            crate::cli_cache::update_target(&space, target, m);
        }

        let Some(method) = method else {
            // `vosx <target>` (or `--help`) → list surface.
            return print_target_surface(target, meta.as_ref());
        };

        if parsed.wants_help {
            return print_method_surface(target, method, meta.as_ref());
        }

        let method_meta = meta
            .as_ref()
            .and_then(|m| m.messages.iter().find(|msg| msg.name == *method));

        if let Some(m) = &meta {
            // Schema known but method missing → reject up front
            // with a list of what IS available. Saves a daemon
            // round trip on a clear typo.
            if method_meta.is_none() {
                let avail = m
                    .messages
                    .iter()
                    .filter(|msg| msg.exposed_to_cli)
                    .map(|msg| msg.name.as_str())
                    .collect::<Vec<_>>();
                let hint = if avail.is_empty() {
                    String::from(" (no CLI-exposed methods declared)")
                } else {
                    format!(" (available: {})", avail.join(", "))
                };
                bail!("unknown method '{method}' on '{target}'{hint}");
            }
        }

        let msg = build_msg(method, method_meta, &method_args)?;
        let target_id = client.resolve_target(target)?;
        tracing::debug!("invoking {method} on {target_id}");
        let reply = client.invoke_dyn(target_id, &msg)?;

        if output::is_json() {
            output::print_json(&unwrap_json_string(output::value_to_json(&reply)));
        } else {
            match reply {
                Value::Unit => println!("()"),
                Value::Str(s) if looks_like_json_object_or_array(&s) => {
                    // `vosx gateway status` returns a JSON-shaped
                    // string; in text mode the user is most
                    // likely scanning for fields, so print the
                    // payload verbatim rather than rust-Debug-
                    // formatting the wrapping `Str(...)`.
                    println!("{s}");
                }
                other => println!("{other:?}"),
            }
        }
        Ok(())
    })
}

/// `true` when `s` starts with `{` or `[` (after whitespace) —
/// the cheap "looks like a JSON container" predicate the JSON-
/// unwrap heuristic gates on. Conservative: doesn't fire on
/// JSON numbers, booleans, or `null`, since those are
/// ambiguous with a handler that genuinely returned the string
/// literal.
fn looks_like_json_object_or_array(s: &str) -> bool {
    matches!(s.trim_start().chars().next(), Some('{' | '['))
}

/// Heuristic: when a handler returned `Value::Str(json_blob)`
/// (e.g. `vosx gateway status`), the default JSON rendering
/// produces a quoted string containing JSON — forcing the
/// reader to parse it twice. Detect the case (Value::Str shape,
/// starts with `{`/`[`, parses as JSON) and unwrap so the outer
/// JSON layer renders the object/array directly.
///
/// Limited to JSON containers so a handler that legitimately
/// returned, say, `"42"` or `"true"` doesn't get re-interpreted
/// as a JSON number / boolean.
fn unwrap_json_string(json: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::String(s) = &json
        && looks_like_json_object_or_array(s)
        && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s)
        && (parsed.is_object() || parsed.is_array())
    {
        return parsed;
    }
    json
}

fn parse_argv(argv: &[String]) -> anyhow::Result<ParsedArgv> {
    let mut space: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut wants_help = false;

    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        match a.as_str() {
            "--space" => {
                space = Some(
                    argv.get(i + 1)
                        .ok_or_else(|| anyhow!("`--space` requires a value"))?
                        .clone(),
                );
                i += 2;
                continue;
            }
            s if s.starts_with("--space=") => {
                space = Some(s.trim_start_matches("--space=").to_string());
            }
            // Global flags that don't take a value; main already
            // handled them (or will via tracing/output state).
            // Re-recognised here so we don't trip on them as
            // mystery positionals.
            "-v" | "--verbose" => {}
            "--help" | "-h" => {
                wants_help = true;
            }
            "--format" => {
                i += 2; // skip value
                continue;
            }
            s if s.starts_with("--format=") => {}
            _ => positional.push(a.clone()),
        }
        i += 1;
    }
    Ok(ParsedArgv {
        space,
        positional,
        wants_help,
    })
}

/// Resolve the space name. Explicit `--space` wins; then
/// `VOSX_SPACE` env; then the single-entry rule for users with
/// exactly one space in their index. A multi-space user without
/// either signal gets a list rather than a silent pick.
fn resolve_space(arg: Option<&str>) -> anyhow::Result<String> {
    if let Some(s) = arg {
        return Ok(s.to_string());
    }
    if let Ok(s) = std::env::var("VOSX_SPACE")
        && !s.is_empty()
    {
        return Ok(s);
    }
    let index = spaces_index::load().with_context(|| "loading spaces index")?;
    match index.spaces.as_slice() {
        [only] => Ok(only.name.clone()),
        [] => bail!(
            "no spaces registered. Create one with `vosx space new --name <name>` or pass `--space <name>` explicitly."
        ),
        many => {
            let names = many.iter().map(|s| s.name.as_str()).collect::<Vec<_>>();
            bail!(
                "multiple spaces registered: {}. Pass `--space <name>` or set VOSX_SPACE=<name>.",
                names.join(", "),
            )
        }
    }
}

fn build_msg(
    method: &str,
    method_meta: Option<&ParsedMessage>,
    args: &[&str],
) -> anyhow::Result<Msg> {
    let mut msg = Msg::new(method);
    for a in args {
        let (k, v) = a
            .split_once('=')
            .ok_or_else(|| anyhow!("arg '{a}' must be 'key=value'"))?;
        let field_ty = method_meta
            .and_then(|m| m.fields.iter().find(|f| f.name == k))
            .map(|f| f.ty.as_str());
        msg = apply_arg(msg, k, v, field_ty)?;
    }
    Ok(msg)
}

/// Coerce one `key=value` argument onto an in-progress `Msg`.
/// When a schema-declared type is available we honor it
/// strictly (so `a=notanumber` for a `u64` arg errors here
/// rather than at the actor); without a schema, the same loose
/// heuristic `space call` uses (numeric → u64, true/false →
/// bool, else string) keeps the no-schema path working.
fn apply_arg(msg: Msg, k: &str, v: &str, field_ty: Option<&str>) -> anyhow::Result<Msg> {
    let parse_err = |ty: &str| anyhow!("arg '{k}': expected {ty}, got {v:?}");
    Ok(match field_ty {
        Some("u8") => msg.with(k, v.parse::<u8>().map_err(|_| parse_err("u8"))?),
        Some("u16") => msg.with(k, v.parse::<u16>().map_err(|_| parse_err("u16"))?),
        Some("u32") => msg.with(k, v.parse::<u32>().map_err(|_| parse_err("u32"))?),
        Some("u64") => msg.with(k, v.parse::<u64>().map_err(|_| parse_err("u64"))?),
        Some("i32") => msg.with(k, v.parse::<i32>().map_err(|_| parse_err("i32"))?),
        Some("i64") => msg.with(k, v.parse::<i64>().map_err(|_| parse_err("i64"))?),
        Some("bool") => msg.with(k, v.parse::<bool>().map_err(|_| parse_err("bool"))?),
        Some("String") => msg.with(k, v.to_string()),
        // No schema or unrecognised type — fall back to the
        // legacy heuristic so `space call`-equivalent commands
        // keep working on agents that haven't registered meta.
        _ => {
            if let Ok(n) = v.parse::<u64>() {
                msg.with(k, n)
            } else if let Ok(b) = v.parse::<bool>() {
                msg.with(k, b)
            } else {
                msg.with(k, v.to_string())
            }
        }
    })
}

fn print_target_surface(target: &str, meta: Option<&ParsedMeta>) -> anyhow::Result<()> {
    let Some(m) = meta else {
        bail!(
            "no schema registered for '{target}'. \
             Either the name is unknown or its program predates schema forwarding — \
             run `vosx space agents <space>` to see installed agents."
        );
    };
    if output::is_json() {
        let methods: Vec<_> = m
            .messages
            .iter()
            .filter(|msg| msg.exposed_to_cli)
            .map(|msg| {
                serde_json::json!({
                    "name": msg.name,
                    "is_query": msg.is_query,
                    "fields": msg.fields.iter().map(|f| serde_json::json!({
                        "name": f.name,
                        "type": f.ty,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        output::print_json(&serde_json::json!({
            "target": target,
            "actor_name": m.actor_name,
            "methods": methods,
        }));
        return Ok(());
    }
    println!("usage: vosx {target} <method> [key=value ...]");
    println!();
    println!("actor: {}", m.actor_name);
    let exposed: Vec<&ParsedMessage> = m.messages.iter().filter(|x| x.exposed_to_cli).collect();
    if exposed.is_empty() {
        println!();
        println!("(no CLI-exposed methods declared)");
        return Ok(());
    }
    println!();
    println!("methods:");
    for msg in exposed {
        let q = if msg.is_query { " (query)" } else { "" };
        if msg.fields.is_empty() {
            println!("  {}(){q}", msg.name);
        } else {
            let args = msg
                .fields
                .iter()
                .map(|f| format!("{}={}", f.name, f.ty))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  {}  {args}{q}", msg.name);
        }
    }
    Ok(())
}

fn print_method_surface(
    target: &str,
    method: &str,
    meta: Option<&ParsedMeta>,
) -> anyhow::Result<()> {
    let Some(m) = meta else {
        bail!("no schema registered for '{target}'; can't render method help");
    };
    let Some(msg) = m.messages.iter().find(|x| x.name == method) else {
        bail!("unknown method '{method}' on '{target}'");
    };
    if output::is_json() {
        output::print_json(&serde_json::json!({
            "target": target,
            "method": msg.name,
            "is_query": msg.is_query,
            "fields": msg.fields.iter().map(|f| serde_json::json!({
                "name": f.name,
                "type": f.ty,
            })).collect::<Vec<_>>(),
        }));
        return Ok(());
    }
    let args = if msg.fields.is_empty() {
        String::new()
    } else {
        format!(
            " {}",
            msg.fields
                .iter()
                .map(|f| format!("{}={}", f.name, f.ty))
                .collect::<Vec<_>>()
                .join(" "),
        )
    };
    let q = if msg.is_query { " (query)" } else { "" };
    println!("usage: vosx {target} {method}{args}{q}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_argv_extracts_space_flag_in_either_position() {
        let p = parse_argv(&s(&["--space", "demo", "gateway", "stop"])).unwrap();
        assert_eq!(p.space.as_deref(), Some("demo"));
        assert_eq!(p.positional, s(&["gateway", "stop"]));

        let p = parse_argv(&s(&["gateway", "--space=demo", "stop"])).unwrap();
        assert_eq!(p.space.as_deref(), Some("demo"));
        assert_eq!(p.positional, s(&["gateway", "stop"]));
    }

    #[test]
    fn parse_argv_help_flag_routes_to_help_path() {
        let p = parse_argv(&s(&["gateway", "--help"])).unwrap();
        assert!(p.wants_help);
        assert_eq!(p.positional, s(&["gateway"]));
    }

    #[test]
    fn parse_argv_swallows_format_value() {
        // `main` already applied --format; the dispatcher must
        // not mistake `json` for a positional.
        let p = parse_argv(&s(&["--format", "json", "gateway"])).unwrap();
        assert_eq!(p.positional, s(&["gateway"]));
    }

    #[test]
    fn parse_argv_rejects_dangling_space() {
        let err = parse_argv(&s(&["--space"])).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "{err}");
    }

    #[test]
    fn build_msg_uses_schema_type_when_present() {
        // Schema says `a: u64`, so a non-u64 input is rejected
        // up front — the legacy heuristic would silently fall
        // back to a String and the actor would reject it later
        // with a less helpful message.
        let field = vos::metadata::ParsedField {
            name: "a".into(),
            ty: "u64".into(),
        };
        let m = ParsedMessage {
            name: "add".into(),
            is_query: false,
            fields: vec![field],
            exposed_to_cli: true,
        };
        let err = build_msg("add", Some(&m), &["a=notanumber"]).unwrap_err();
        assert!(err.to_string().contains("u64"), "{err}");
    }

    #[test]
    fn unwrap_json_string_unwraps_object_payloads() {
        // Status handler shape: handler returns Value::Str(json),
        // outer layer wraps as JSON string → user sees a quoted
        // string containing JSON. The heuristic should strip the
        // outer quoting.
        let outer = serde_json::Value::String(r#"{"port":8443,"running":true}"#.into());
        let unwrapped = unwrap_json_string(outer);
        assert!(
            unwrapped.is_object(),
            "expected JSON object, got {unwrapped}"
        );
        assert_eq!(unwrapped["port"], 8443);
        assert_eq!(unwrapped["running"], true);
    }

    #[test]
    fn unwrap_json_string_unwraps_array_payloads() {
        let outer = serde_json::Value::String("[1, 2, 3]".into());
        let unwrapped = unwrap_json_string(outer);
        assert!(unwrapped.is_array(), "expected JSON array, got {unwrapped}");
    }

    #[test]
    fn unwrap_json_string_leaves_bare_string_alone() {
        // `"hello world"` is legitimately the handler's return —
        // unwrapping would lose the type.
        let outer = serde_json::Value::String("hello world".into());
        let unwrapped = unwrap_json_string(outer.clone());
        assert_eq!(unwrapped, outer);
    }

    #[test]
    fn unwrap_json_string_leaves_quoted_number_alone() {
        // `"42"` is valid JSON (a number) BUT also a valid string;
        // the conservative heuristic gates on `{`/`[` start so
        // numbers stay strings.
        let outer = serde_json::Value::String("42".into());
        let unwrapped = unwrap_json_string(outer.clone());
        assert_eq!(unwrapped, outer);
    }

    #[test]
    fn unwrap_json_string_passes_through_non_strings() {
        let v = serde_json::json!({"already": "object"});
        let unwrapped = unwrap_json_string(v.clone());
        assert_eq!(unwrapped, v);
    }

    #[test]
    fn unwrap_json_string_handles_malformed_payload() {
        // `{`-prefixed but not valid JSON: keep the string as-is,
        // don't crash. Handlers returning raw bytes that happen
        // to start with `{` shouldn't break dispatch.
        let outer = serde_json::Value::String("{not valid".into());
        let unwrapped = unwrap_json_string(outer.clone());
        assert_eq!(unwrapped, outer);
    }

    #[test]
    fn build_msg_without_schema_uses_heuristic_typing() {
        // No method_meta → loose typing, same as `space call`.
        // Round-trip through encode/decode so we actually
        // observe how each `Value` arrived on the wire — a
        // future refactor that flipped a numeric to a string
        // would silently regress the `vosx <agent> <method>`
        // shape for any actor that hasn't registered meta.
        use vos::value::Value;
        let msg = build_msg("anything", None, &["x=42", "y=true", "z=hi"]).unwrap();
        assert_eq!(
            msg.args.get("x").map(|v| matches!(v, Value::U64(42))),
            Some(true),
            "numeric heuristic should produce U64(42)",
        );
        assert_eq!(
            msg.args.get("y").map(|v| matches!(v, Value::Bool(true))),
            Some(true),
            "true/false heuristic should produce Bool",
        );
        assert_eq!(
            msg.args
                .get("z")
                .map(|v| matches!(v, Value::Str(s) if s == "hi")),
            Some(true),
            "non-numeric, non-bool heuristic should produce Str",
        );
    }
}
