//! The sandbox boundary.
//!
//! The console's `EngineState` is built from `nu-cmd-lang` ONLY — nushell's
//! core language (control flow, bindings, `describe`, …). Because
//! `nu-command` / `nu-cli` / `nu-std` are not dependencies, the filesystem
//! (`open`, `ls`, `save`), network (`http`), and process (`run-external`,
//! `^cmd`) command sets simply do not exist in the engine. The sandbox is
//! the *absence* of those decls, enforced at compile time by the dependency
//! graph — not a runtime allow/deny list that could be misconfigured.
//!
//! A missing command parses as an external call and then fails to compile to
//! IR (no external runner is registered), so nothing executes — verified in
//! the Phase 0 spike. [`friendly_unknown_command`] turns that internal IR
//! error into a clear message.

use nu_protocol::engine::EngineState;

/// A fresh sandboxed engine: `nu-cmd-lang` core only.
pub fn base_engine_state() -> EngineState {
    nu_cmd_lang::add_default_context(EngineState::new())
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
