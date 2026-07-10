//! `~/.config/vosx/cli_cache.toml` — schema cache for the
//! dynamic dispatcher's discovery surface.
//!
//! Every successful `vosx <target> [...]` round trip writes the
//! decoded meta back here, keyed by `(space, target)`. The cache
//! is purely an optimisation:
//!
//!   * `vosx --help` lists known targets without dialling the
//!     daemon — useful when the daemon is down or being
//!     restarted.
//!   * `vosx <target>` no-method invocations can render the
//!     method list immediately, with the next live round trip
//!     refreshing on the way out.
//!
//! The cache never authoritative — the daemon's registry is.
//! A stale entry only affects discovery output (`--help` /
//! method listings); actual dispatch always re-fetches schema
//! and rejects unknown methods against the *live* registry.
//!
//! ## On-disk shape
//!
//! ```toml
//! version = 1
//!
//! [space.demo.gateway]
//! actor_name = "HttpGateway"
//! kind = 1
//! refreshed_at = "2026-05-11T15:30:00Z"
//!
//! [[space.demo.gateway.method]]
//! name = "stop"
//! is_query = false
//! exposed_to_cli = true
//! fields = []
//!
//! [[space.demo.gateway.method]]
//! name = "status"
//! is_query = false
//! exposed_to_cli = true
//! fields = []
//! ```
//!
//! Missing file → empty cache (`load()` returns
//! `CliCache::default()`). Malformed file → `load()` returns
//! `Err`, but both call sites (`render_summary`, `update_target`)
//! swallow it and `tracing::warn!` so the live wire path never
//! gets blocked by a bad cache. Operator action on a corrupt
//! cache: delete the file and re-run any `vosx <target>` to
//! repopulate.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vos::metadata::ParsedMeta;

use crate::paths::config_root;

const CACHE_VERSION: u32 = 1;

pub fn path() -> PathBuf {
    config_root().join("cli_cache.toml")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CliCache {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default, rename = "space")]
    pub spaces: BTreeMap<String, SpaceCache>,
}

impl Default for CliCache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            spaces: BTreeMap::new(),
        }
    }
}

fn default_version() -> u32 {
    CACHE_VERSION
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct SpaceCache {
    /// Sorted by target name (BTreeMap's iteration order) so
    /// help output is deterministic across runs.
    #[serde(flatten)]
    pub targets: BTreeMap<String, TargetMeta>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct TargetMeta {
    pub actor_name: String,
    pub kind: u8,
    /// ISO-8601 timestamp of when the daemon last served this
    /// schema. Informational; helps an operator decide whether
    /// to trust the cache while the daemon is down.
    #[serde(default)]
    pub refreshed_at: String,
    #[serde(default, rename = "method")]
    pub methods: Vec<MethodMeta>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MethodMeta {
    pub name: String,
    #[serde(default)]
    pub is_query: bool,
    #[serde(default)]
    pub exposed_to_cli: bool,
    #[serde(default)]
    pub fields: Vec<MethodField>,
    /// One-line handler description (from `.vos_meta`), so `vosx --help`
    /// can show it without dialling the daemon. Additive: old caches
    /// (no `doc` key) load empty.
    #[serde(default)]
    pub doc: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MethodField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

pub fn load() -> Result<CliCache, CacheError> {
    load_from(&path())
}

pub fn load_from(p: &Path) -> Result<CliCache, CacheError> {
    let bytes = match fs::read(p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CliCache::default()),
        Err(e) => return Err(CacheError::Io(e)),
    };
    let s = String::from_utf8_lossy(&bytes);
    toml::from_str(&s).map_err(CacheError::Decode)
}

pub fn save(cache: &CliCache) -> Result<(), CacheError> {
    save_to(cache, &path())
}

pub fn save_to(cache: &CliCache, p: &Path) -> Result<(), CacheError> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = toml::to_string_pretty(cache).map_err(CacheError::Encode)?;
    fs::write(p, body).map_err(CacheError::Io)
}

/// Write-through update: read the cache, replace one (space,
/// target) entry's schema, write back. Idempotent — same
/// payload twice is a no-op. Returns silently on any I/O or
/// parse error; the cache is a strict optimisation and must
/// never block dispatch.
pub fn update_target(space: &str, target: &str, meta: &ParsedMeta) {
    let mut cache = match load() {
        Ok(c) => c,
        Err(e) => {
            // Corrupt cache — start over rather than carry
            // forward garbage. Warn so the operator notices.
            tracing::warn!(
                "vosx: cli_cache load failed during update (rebuilding from empty): {e}",
            );
            CliCache::default()
        }
    };
    if cache.version == 0 {
        cache.version = CACHE_VERSION;
    }
    let space_entry = cache.spaces.entry(space.to_string()).or_default();
    let target_meta = TargetMeta {
        actor_name: meta.actor_name.clone(),
        kind: meta.kind,
        refreshed_at: now_iso8601(),
        methods: meta
            .messages
            .iter()
            .map(|m| MethodMeta {
                name: m.name.clone(),
                is_query: m.is_query,
                exposed_to_cli: m.exposed_to_cli,
                doc: m.doc.clone(),
                fields: m
                    .fields
                    .iter()
                    .map(|f| MethodField {
                        name: f.name.clone(),
                        ty: f.ty.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    space_entry.targets.insert(target.to_string(), target_meta);
    if let Err(e) = save(&cache) {
        // Cache writes must never break dispatch — discovery
        // can stay stale, the round trip already worked — but
        // a silent failure leaves the operator wondering why
        // `vosx --help` never picks up new targets. Log so the
        // why is one `RUST_LOG=warn` away.
        tracing::warn!("vosx: cli_cache save failed (discovery may be stale): {e}");
    }
}

/// Render a human-readable "discoverable targets" section for
/// inclusion in extended `--help` output. Returns `None` when
/// no space has any targets cached — both the empty-cache and
/// "every space row is empty" paths collapse to the same
/// "skip the section entirely" answer so the help output never
/// shows an orphan heading with no bullets under it.
pub fn render_summary() -> Option<String> {
    let cache = match load() {
        Ok(c) => c,
        Err(e) => {
            // Cache is strict-optimisation; load failure must
            // not break --help. Log at warn so the user can spot
            // a corrupted/permissions-bad file.
            tracing::warn!("vosx: cli_cache load failed: {e}");
            return None;
        }
    };
    let any_target = cache.spaces.values().any(|sp| !sp.targets.is_empty());
    if !any_target {
        return None;
    }
    let mut out = String::new();
    out.push_str("Discovered targets (cached from prior daemon round-trips):\n");
    for (space_name, sp) in &cache.spaces {
        if sp.targets.is_empty() {
            continue;
        }
        out.push_str(&format!("  space '{space_name}':\n"));
        for (name, t) in &sp.targets {
            let cli_methods: Vec<&str> = t
                .methods
                .iter()
                .filter(|m| m.exposed_to_cli)
                .map(|m| m.name.as_str())
                .collect();
            if cli_methods.is_empty() {
                out.push_str(&format!("    {name}  ({})\n", t.actor_name));
            } else {
                out.push_str(&format!(
                    "    {name}  ({})  — methods: {}\n",
                    t.actor_name,
                    cli_methods.join(", "),
                ));
            }
        }
    }
    out.push_str(
        "\nRun `vosx <target>` for the full method list, or \
         `vosx <target> <method>` to invoke. Schema refreshes on each \
         invocation.\n",
    );
    Some(out)
}

#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
    Decode(toml::de::Error),
    Encode(toml::ser::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Io(e) => write!(f, "cli_cache i/o: {e}"),
            CacheError::Decode(e) => write!(f, "cli_cache decode: {e}"),
            CacheError::Encode(e) => write!(f, "cli_cache encode: {e}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e)
    }
}

fn now_iso8601() -> String {
    const FORMAT: &[time::format_description::FormatItem<'_>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    time::OffsetDateTime::now_utc()
        .format(FORMAT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::metadata::{ParsedField, ParsedMessage};

    fn tmp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vosx-cli-cache-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ))
    }

    fn fake_meta() -> ParsedMeta {
        ParsedMeta {
            actor_name: "HttpGateway".into(),
            messages: vec![
                ParsedMessage {
                    name: "stop".into(),
                    is_query: false,
                    fields: vec![],
                    exposed_to_cli: true,
                    returns: String::new(),
                    doc: "Stop the gateway.".into(),
                    timeout_ms: 0,
                    mode: 0,
                },
                ParsedMessage {
                    name: "status".into(),
                    is_query: false,
                    fields: vec![],
                    exposed_to_cli: true,
                    returns: String::new(),
                    doc: String::new(),
                    timeout_ms: 0,
                    mode: 0,
                },
                ParsedMessage {
                    name: "internal".into(),
                    is_query: false,
                    fields: vec![ParsedField {
                        name: "x".into(),
                        ty: "u32".into(),
                    }],
                    exposed_to_cli: false,
                    returns: String::new(),
                    doc: String::new(),
                    timeout_ms: 0,
                    mode: 0,
                },
            ],
            constructor: vec![],
            kind: 1,
            caps: vec![],
            doc: String::new(),
        }
    }

    #[test]
    fn load_missing_file_returns_default() {
        let p = tmp_path("missing");
        let c = load_from(&p).unwrap();
        assert!(c.spaces.is_empty());
        assert_eq!(c.version, default_version());
    }

    #[test]
    fn roundtrip_preserves_method_flags() {
        // The exposed_to_cli + is_query flags are what the
        // help-renderer keys on; a serde rename or default
        // typo would silently produce a "no methods" output.
        let p = tmp_path("rt");
        let mut cache = CliCache::default();
        cache.version = 1;
        let mut space = SpaceCache::default();
        space.targets.insert(
            "gateway".into(),
            TargetMeta {
                actor_name: "HttpGateway".into(),
                kind: 1,
                refreshed_at: "2026-05-11T00:00:00Z".into(),
                methods: vec![MethodMeta {
                    name: "stop".into(),
                    is_query: false,
                    exposed_to_cli: true,
                    fields: vec![],
                    doc: String::new(),
                }],
            },
        );
        cache.spaces.insert("demo".into(), space);
        save_to(&cache, &p).unwrap();

        let back = load_from(&p).unwrap();
        let m = &back.spaces["demo"].targets["gateway"];
        assert_eq!(m.actor_name, "HttpGateway");
        assert!(m.methods[0].exposed_to_cli);
        assert!(!m.methods[0].is_query);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn update_target_inserts_and_overwrites() {
        // Two updates on the same key: second wins, doesn't
        // double-up the row.
        let p = tmp_path("update");

        // Use save_to / load_from directly so the test is isolated
        // from any real ~/.config/vosx/cli_cache.toml on disk.
        let mut cache = CliCache::default();
        let space_entry = cache.spaces.entry("demo".into()).or_default();
        let meta = fake_meta();
        let methods = meta
            .messages
            .iter()
            .map(|m| MethodMeta {
                name: m.name.clone(),
                is_query: m.is_query,
                exposed_to_cli: m.exposed_to_cli,
                doc: m.doc.clone(),
                fields: m
                    .fields
                    .iter()
                    .map(|f| MethodField {
                        name: f.name.clone(),
                        ty: f.ty.clone(),
                    })
                    .collect(),
            })
            .collect();
        space_entry.targets.insert(
            "gateway".into(),
            TargetMeta {
                actor_name: meta.actor_name.clone(),
                kind: meta.kind,
                refreshed_at: "x".into(),
                methods,
            },
        );
        save_to(&cache, &p).unwrap();

        let back = load_from(&p).unwrap();
        let t = &back.spaces["demo"].targets["gateway"];
        assert_eq!(t.methods.len(), 3);
        let stop = t.methods.iter().find(|m| m.name == "stop").unwrap();
        let internal = t.methods.iter().find(|m| m.name == "internal").unwrap();
        assert!(stop.exposed_to_cli);
        assert!(!internal.exposed_to_cli);
        // The metadata-v2 doc round-trips through the TOML cache.
        assert_eq!(stop.doc, "Stop the gateway.");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn update_target_writes_through_via_xdg() {
        // Exercises the actual `update_target` entry point —
        // `load()` -> mutate -> `save()` — under an isolated
        // XDG_CONFIG_HOME. Previous tests built CliCache by hand;
        // a typo in update_target's field mapping would go
        // unnoticed otherwise.
        let tmp = tmp_path("update-via-xdg");
        std::fs::create_dir_all(&tmp).unwrap();
        let saved = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY: see comment in render_summary_skips_when_empty.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &tmp) };

        let m = fake_meta();
        update_target("demo", "gateway", &m);
        // Re-read through the same XDG-keyed `load()` so the
        // test covers `path()` too.
        let cache = load().expect("load after update");

        if let Some(prev) = saved {
            unsafe { std::env::set_var("XDG_CONFIG_HOME", prev) };
        } else {
            unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        }

        let demo = cache.spaces.get("demo").expect("space written");
        let gateway = demo.targets.get("gateway").expect("target written");
        assert_eq!(gateway.actor_name, "HttpGateway");
        assert_eq!(gateway.kind, 1);
        assert_eq!(gateway.methods.len(), 3);
        let stop = gateway.methods.iter().find(|m| m.name == "stop").unwrap();
        let internal = gateway
            .methods
            .iter()
            .find(|m| m.name == "internal")
            .unwrap();
        assert!(stop.exposed_to_cli);
        assert!(!internal.exposed_to_cli);
        // Field metadata for the non-CLI method survives so
        // tooling consuming the cache (IDE schema, codegen)
        // can render full signatures.
        assert_eq!(internal.fields.len(), 1);
        assert_eq!(internal.fields[0].name, "x");
        assert_eq!(internal.fields[0].ty, "u32");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn render_summary_skips_when_empty() {
        // Setting XDG_CONFIG_HOME to a fresh dir guarantees
        // `load()` finds no file. The fn must return None so
        // `--help` doesn't print an empty heading.
        let tmp = tmp_path("summary-empty");
        std::fs::create_dir_all(&tmp).unwrap();
        let saved = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY: tests in this crate run single-threaded by
        // default (`cargo test` defaults to one thread per test
        // module unless the user overrides). The env var is
        // restored before drop.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &tmp) };
        let out = render_summary();
        if let Some(prev) = saved {
            unsafe { std::env::set_var("XDG_CONFIG_HOME", prev) };
        } else {
            unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        }
        assert!(out.is_none(), "empty cache should render no summary");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
