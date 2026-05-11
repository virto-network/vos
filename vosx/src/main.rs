//! `vosx` — JAM-aligned PVM executor + space orchestrator.
//!
//! Top-level surface is intentionally tiny: every space-related
//! operation lives under `vosx space *`. The remaining
//! top-level commands are for things that don't fit the space
//! model — currently just `run` for raw ELF/PVM execution.
//!
//! The earlier manifest-driven commands (`new`, `up`, `join`,
//! `ls`, `ps`, `call`) folded into `vosx space *`; they had
//! different semantics (`up` started a node from a TOML
//! template; `space up` boots the registry-driven daemon)
//! and the registry-as-truth model supersedes the
//! manifest-as-truth model that originally drove them.
//! `space up --manifest <path>` (declarative reconciliation
//! of a manifest into a space's registry) is a future addition.

use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

mod blob_store;
mod bundled;
mod cli_cache;
mod commands;
mod help_schema;
mod output;
mod paths;
mod spaces_index;

use output::Format;
use spaces_index::IndexError;

/// Exit codes. Anything not listed here is `0` (success).
///
/// - `1` — runtime error (I/O, network, daemon hung, registry
///   returned an error status). The default; agents can retry.
/// - `2` — usage error. Clap exits 2 on parse failures, and we
///   reuse the same code when the binary is invoked with no
///   command.
/// - `3` — not found. The space, agent, or program named in
///   the command doesn't exist locally / on the daemon. Agents
///   can treat this as "fix your input" rather than "retry".
const EXIT_RUNTIME_ERROR: i32 = 1;
const EXIT_USAGE_ERROR: i32 = 2;
const EXIT_NOT_FOUND: i32 = 3;

#[derive(Parser)]
#[command(name = "vosx", about = "JAM-aligned PVM executor + space orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Raw ELF/PVM blob to run as a one-shot. Equivalent to
    /// `vosx run <file>`. Anything space-related needs an
    /// explicit `vosx space *` subcommand.
    file: Option<PathBuf>,

    /// Output format. `text` (default) is human-readable;
    /// `json` emits a single JSON value per command for scripts
    /// and LLM consumption. Inherited by all subcommands.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,

    /// Enable progress / status chatter on stderr. Off by
    /// default — only warnings and errors print. Inherited by
    /// all subcommands.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Run a single PVM/ELF program with no manifest (one-shot).
    /// No registry, no networking — just boot the kernel,
    /// deliver the supplied work items, halt.
    Run {
        program: PathBuf,
        /// Deliver file contents as a FETCH work item (repeatable).
        #[arg(long, value_name = "FILE")]
        payload: Vec<PathBuf>,
        /// Deliver hex-encoded bytes as a FETCH work item (repeatable).
        #[arg(long, value_name = "HEX")]
        hex: Vec<String>,
        /// Set gas limit.
        #[arg(long, default_value_t = 100_000_000)]
        gas: u64,
    },
    /// Per-space lifecycle and operations.
    Space {
        #[command(subcommand)]
        command: commands::space::SpaceCommand,
    },
    /// Emit the full CLI schema as pretty-printed JSON. Walks
    /// every subcommand + argument from clap's introspection,
    /// so the dump always matches what the binary accepts.
    /// Designed for LLM and tooling consumption — pipe into
    /// `jq '.subcommands[] | .name'` to enumerate verbs.
    HelpSchema,
}

/// Initialize the global tracing subscriber. Default level is
/// `warn` (quiet); `-v` raises it to `info` for one-time state
/// changes; `RUST_LOG` overrides everything for power users
/// who want `debug` or per-target filtering. Also bridges the
/// `log` facade so vos's actor-side `log::*` calls reach the
/// same subscriber.
fn init_tracing(verbose: bool) {
    let default_level = if verbose { "info" } else { "warn" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    let _ = tracing_log::LogTracer::init();
}

fn main() {
    // Pre-parser: peek argv and decide whether to enter the
    // dynamic-dispatch path before handing off to clap. clap's
    // Subcommand derive only knows the built-in verbs (`run`,
    // `space`, `help-schema`); a `vosx gateway stop` invocation
    // would otherwise slip through as the `file` positional and
    // fail with a confusing "no such ELF" error.
    //
    // The verb is the first non-flag argv token. We route to the
    // dynamic dispatcher when:
    //
    //   * the verb exists,
    //   * it's not a built-in (`run`, `space`, `help-schema`,
    //     `help`),
    //   * and it's not a path-like token (one-shot ELF run still
    //     takes precedence so `vosx ./foo.elf` keeps working).
    //
    // Anything else falls through to `Cli::parse()` so clap's
    // own --help / --version / parse-error machinery stays intact.
    let raw_argv: Vec<String> = std::env::args().skip(1).collect();

    // Top-level `vosx --help` / `vosx -h` / `vosx help` gets a
    // post-script with cache-discovered targets so a user
    // skimming the help can see e.g. `gateway`, `math`,
    // `counter` listed alongside the built-in subcommands.
    // Subcommand help (`vosx space --help`) is unchanged —
    // clap handles those before we'd see them.
    if is_top_level_help(&raw_argv) {
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
        if let Some(summary) = cli_cache::render_summary() {
            println!();
            print!("{summary}");
        }
        return;
    }

    if should_dynamic_dispatch(&raw_argv) {
        // Mirror the global-flag side-effects clap would have
        // applied. Verbose + format are read off the same argv
        // since the pre-parser hasn't consumed them.
        let verbose = raw_argv.iter().any(|a| a == "-v" || a == "--verbose");
        init_tracing(verbose);
        if let Some(fmt) = extract_format_flag(&raw_argv) {
            output::set(fmt);
        }
        if let Err(e) = commands::dynamic::dispatch(&raw_argv) {
            report_error(e);
        }
        return;
    }

    let cli = Cli::parse();
    init_tracing(cli.verbose);
    output::set(cli.format);

    match cli.command {
        Some(Command::Run {
            program,
            payload,
            hex,
            gas,
        }) => {
            commands::run::run(&program, &payload, &hex, gas);
        }
        Some(Command::Space { command }) => {
            if let Err(e) = commands::space::run(command) {
                report_error(e);
            }
        }
        Some(Command::HelpSchema) => {
            let schema = help_schema::build(&Cli::command());
            match serde_json::to_string_pretty(&schema) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(EXIT_RUNTIME_ERROR);
                }
            }
        }
        None => match cli.file {
            Some(p) => commands::run::run(&p, &[], &[], 100_000_000),
            None => {
                eprintln!(
                    "vosx: no command. Try `vosx space new --name foo`, \
                     `vosx run path/to.elf`, or `vosx --help`."
                );
                std::process::exit(EXIT_USAGE_ERROR);
            }
        },
    }
}

/// `true` when argv is asking for the top-level `--help` /
/// `-h` and nothing else of substance — so we can intercept,
/// print clap's standard help, and append the cache-derived
/// "discovered targets" section. Subcommand help
/// (`vosx space --help`) is excluded so clap's own help
/// machinery handles it cleanly.
fn is_top_level_help(argv: &[String]) -> bool {
    let mut saw_help = false;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--help" | "-h" | "help" => saw_help = true,
            // Global no-value flags we tolerate alongside --help.
            "-v" | "--verbose" => {}
            // Global value-taking flags — skip the value too.
            "--format" => i += 1,
            s if s.starts_with("--format=") => {}
            // Anything else (built-in subcommand, dynamic verb,
            // unknown flag) → not a pure top-level help.
            _ => return false,
        }
        i += 1;
    }
    saw_help
}

/// Decide whether argv should bypass clap into the dynamic
/// dispatcher. The first non-flag token is the candidate verb;
/// any of the built-in subcommand names — including clap's
/// auto-generated `help` — falls back to clap. A path-like token
/// (one with `/` or `\`, or starting with `.`) is preserved for
/// the existing one-shot ELF run path.
fn should_dynamic_dispatch(argv: &[String]) -> bool {
    const BUILTIN_VERBS: &[&str] = &["run", "space", "help-schema", "help"];
    // Skip global flags; only `--format` / `--space` take a
    // value, the rest are boolean-shaped. We do NOT recognise
    // `--space` here (it's a dynamic-only flag) — its presence
    // is a strong "user wants dynamic dispatch" signal anyway.
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        match a.as_str() {
            "--format" => {
                i += 2;
                continue;
            }
            s if s.starts_with("--format=") => {}
            "--space" => return true,
            s if s.starts_with("--space=") => return true,
            "-v" | "--verbose" => {}
            "--help" | "-h" | "--version" | "-V" => return false,
            _ => {
                if a.starts_with('-') {
                    // Unknown flag — let clap surface the error.
                    return false;
                }
                if BUILTIN_VERBS.contains(&a.as_str()) {
                    return false;
                }
                if a.contains('/') || a.contains('\\') || a.starts_with('.') {
                    return false;
                }
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Pluck `--format <value>` / `--format=<value>` out of argv
/// without disturbing the rest. clap would also handle these
/// but only on the path through `Cli::parse`; the dynamic path
/// re-implements just enough flag parsing to honor the same
/// global flag.
fn extract_format_flag(argv: &[String]) -> Option<Format> {
    use clap::ValueEnum;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => {
                let v = argv.get(i + 1)?;
                return Format::from_str(v, true).ok();
            }
            s if s.starts_with("--format=") => {
                return Format::from_str(s.trim_start_matches("--format="), true).ok();
            }
            _ => i += 1,
        }
    }
    None
}

/// Print an error and exit with the appropriate code. In JSON
/// mode the error envelope goes to stderr too — tools parsing
/// stdout get nothing on the failure path, and structured
/// failure detail is one line away on fd 2.
fn report_error(e: anyhow::Error) -> ! {
    let code = exit_code_for(&e);
    if output::is_json() {
        let envelope = serde_json::json!({
            "error": e.to_string(),
            "code": code,
        });
        eprintln!("{envelope}");
    } else {
        eprintln!("error: {e}");
    }
    std::process::exit(code)
}

/// Inspect the error chain to pick a code. `IndexError::NotFound`
/// is the only "not found" we can detect typed today (returned
/// by `spaces_index::find` when a space name/id doesn't match);
/// registry-status not-founds still surface as plain anyhow
/// strings and map to runtime-error.
fn exit_code_for(e: &anyhow::Error) -> i32 {
    if let Some(IndexError::NotFound(_)) = e.downcast_ref::<IndexError>() {
        return EXIT_NOT_FOUND;
    }
    EXIT_RUNTIME_ERROR
}

#[cfg(test)]
mod routing_tests {
    use super::{is_top_level_help, should_dynamic_dispatch};

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_argv_uses_clap_path() {
        // Lets clap's "no command" error surface as-is.
        assert!(!should_dynamic_dispatch(&s(&[])));
    }

    #[test]
    fn builtin_verbs_use_clap_path() {
        for v in ["run", "space", "help-schema", "help"] {
            assert!(!should_dynamic_dispatch(&s(&[v])), "verb={v}");
        }
    }

    #[test]
    fn path_like_first_positional_runs_one_shot() {
        // The existing `vosx ./foo.elf` shape must keep working.
        for v in ["./foo.elf", "/abs/path.elf", "rel\\path"] {
            assert!(!should_dynamic_dispatch(&s(&[v])), "verb={v}");
        }
    }

    #[test]
    fn standalone_help_flag_uses_clap_path() {
        // `vosx --help` and `vosx --version` are handled by clap.
        assert!(!should_dynamic_dispatch(&s(&["--help"])));
        assert!(!should_dynamic_dispatch(&s(&["-h"])));
        assert!(!should_dynamic_dispatch(&s(&["--version"])));
        assert!(!should_dynamic_dispatch(&s(&["-V"])));
    }

    #[test]
    fn unknown_flag_falls_back_to_clap() {
        // Clap surfaces the better error message for unknown flags.
        assert!(!should_dynamic_dispatch(&s(&["--unknown"])));
    }

    #[test]
    fn non_builtin_word_triggers_dynamic_dispatch() {
        // The actual Phase-4 ergonomic surface.
        assert!(should_dynamic_dispatch(&s(&["gateway"])));
        assert!(should_dynamic_dispatch(&s(&["gateway", "stop"])));
        assert!(should_dynamic_dispatch(&s(&["math", "add", "a=2", "b=3"])));
    }

    #[test]
    fn global_flags_with_values_skip_correctly() {
        // `--format json gateway stop` — the json value isn't a verb.
        assert!(should_dynamic_dispatch(&s(&[
            "--format", "json", "gateway"
        ])));
        assert!(should_dynamic_dispatch(&s(&["--format=json", "gateway"])));
        assert!(should_dynamic_dispatch(&s(&["-v", "gateway"])));
    }

    #[test]
    fn space_flag_alone_forces_dynamic() {
        // `--space` only makes sense in the dynamic path; its
        // presence is a strong signal even before the verb.
        assert!(should_dynamic_dispatch(&s(&["--space", "demo"])));
        assert!(should_dynamic_dispatch(&s(&["--space=demo", "gateway"])));
    }

    #[test]
    fn format_before_builtin_verb_still_uses_clap() {
        // `--format json space agents demo` — clap can handle it.
        assert!(!should_dynamic_dispatch(&s(&["--format", "json", "space"])));
    }

    #[test]
    fn top_level_help_recognises_flag_variants() {
        // The intercept point in `main` keys on this to decide
        // whether to render the extended help (clap output +
        // cache-derived target list).
        assert!(is_top_level_help(&s(&["--help"])));
        assert!(is_top_level_help(&s(&["-h"])));
        assert!(is_top_level_help(&s(&["help"])));
    }

    #[test]
    fn top_level_help_tolerates_globals() {
        // `vosx --format json --help` is still a top-level
        // help request; we want the JSON-mode help output too.
        assert!(is_top_level_help(&s(&["--format", "json", "--help"])));
        assert!(is_top_level_help(&s(&["-v", "--help"])));
        assert!(is_top_level_help(&s(&["--format=json", "-h"])));
    }

    #[test]
    fn top_level_help_excludes_subcommand_help() {
        // `vosx space --help` is subcommand help — clap should
        // handle that path, not our extended renderer.
        assert!(!is_top_level_help(&s(&["space", "--help"])));
        assert!(!is_top_level_help(&s(&["run", "--help"])));
    }

    #[test]
    fn top_level_help_without_flag_is_not_help() {
        // Just to make sure tolerating globals didn't accidentally
        // treat plain `--format json` as a help request.
        assert!(!is_top_level_help(&s(&[])));
        assert!(!is_top_level_help(&s(&["--format", "json"])));
        assert!(!is_top_level_help(&s(&["-v"])));
    }
}
