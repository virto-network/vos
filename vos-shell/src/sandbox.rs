//! The sandbox boundary.
//!
//! The console's `EngineState` gets nushell's core language (`nu-cmd-lang`:
//! `if`/`let`/`for`/`match`/`def`/…) plus the SAFE data-manipulation built-ins
//! from `nu-command` (`each`/`where`/`get`/`select`/`str`/`math`/`sort`/`help`/
//! …). It deliberately does NOT get the filesystem (`open`/`save`/`ls`/`cp`/
//! `rm`), network (`http`/`port`), process (`run-external`/`^cmd`/`ps`), or
//! interactive (`input`/`clear`) commands: those live behind `nu-command`'s
//! `os`/`network` Cargo features, which we turn OFF, so they are not even
//! compiled in. The sandbox is the *absence* of those decls at the dependency
//! level — not a runtime allow/deny list that could be misconfigured.
//!
//! A genuinely unknown command parses as an external call and then fails to
//! compile to IR (no external runner is registered with `os` off), so nothing
//! executes. [`friendly_unknown_command`] turns that internal IR error into a
//! clear message.

use nu_protocol::engine::EngineState;

/// A fresh sandboxed engine: core language + safe data commands.
pub fn base_engine_state() -> EngineState {
    let engine = nu_cmd_lang::add_default_context(EngineState::new());
    // Safe data commands only — `os`/`network` features are off (see Cargo.toml).
    nu_command::add_shell_command_context(engine)
}

/// True if a `ShellError` text is the IR-compile failure nushell emits when a
/// command resolves to an (unavailable) external — i.e. an unknown command in
/// our sandbox. Lets the engine rewrite the cryptic internal error.
pub fn is_unknown_command_error(text: &str) -> bool {
    text.contains("Can't evaluate block in IR mode")
        || text.contains("missing compiled representation")
}

/// The user-facing message for an unknown / disabled command.
pub fn friendly_unknown_command() -> String {
    "unknown command — filesystem, network, and external (^) commands are \
     disabled in this sandbox; type a known actor command (see the browser)"
        .to_string()
}
