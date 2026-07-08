//! Engine integration tests against an in-memory mock backend. No daemon.
//!
//! Proves: actors register as nu subcommands, args coerce against the schema,
//! replies render, the auth gate (`Forbidden`) surfaces, control flow + the
//! sandbox hold, and late discovery (`refresh`) picks up new agents.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vos::abi::service::ServiceId;
use vos::metadata::{ParsedField, ParsedMessage, ParsedMeta};
use vos::value::{Msg, Value};

use vos_shell::ConsoleEngine;
use vos_shell::backend::{AgentInfo, BackendError, SpaceClient};

/// Build a one-actor schema from `(method, [(field, ty)], is_query, exposed)`.
fn meta(actor: &str, msgs: &[(&str, &[(&str, &str)], bool, bool)]) -> ParsedMeta {
    ParsedMeta {
        actor_name: actor.to_string(),
        messages: msgs
            .iter()
            .map(|(name, fields, is_query, exposed)| ParsedMessage {
                name: name.to_string(),
                is_query: *is_query,
                fields: fields
                    .iter()
                    .map(|(n, t)| ParsedField {
                        name: n.to_string(),
                        ty: t.to_string(),
                    })
                    .collect(),
                exposed_to_cli: *exposed,
                returns: String::new(),
            })
            .collect(),
        constructor: vec![],
        kind: 0,
        caps: vec![],
    }
}

#[derive(Default)]
struct Mock {
    agents: Vec<AgentInfo>,
    schemas: HashMap<String, ParsedMeta>,
    ids: HashMap<String, u32>,
    calls: Mutex<Vec<Msg>>,
}

impl Mock {
    fn add(&mut self, name: &str, id: u32, schema: ParsedMeta) {
        self.agents.push(AgentInfo {
            instance_name: name.to_string(),
            program_name: name.to_string(),
        });
        self.schemas.insert(name.to_string(), schema);
        self.ids.insert(name.to_string(), id);
    }
}

impl SpaceClient for Mock {
    fn list_agents(&self) -> Result<Vec<AgentInfo>, BackendError> {
        Ok(self.agents.clone())
    }
    fn resolve_target(&self, name: &str) -> Result<ServiceId, BackendError> {
        self.ids
            .get(name)
            .map(|id| ServiceId(*id))
            .ok_or_else(|| BackendError::NotFound(name.to_string()))
    }
    fn raw_meta(&self, _name: &str) -> Result<Vec<u8>, BackendError> {
        Ok(vec![]) // schema() is overridden, so this is unused
    }
    fn schema(&self, name: &str) -> Result<Option<ParsedMeta>, BackendError> {
        Ok(self.schemas.get(name).cloned())
    }
    fn invoke(&self, _target: ServiceId, msg: &Msg) -> Result<Value, BackendError> {
        self.calls.lock().unwrap().push(msg.clone());
        match msg.name.as_str() {
            // add a b -> a + b, exercising arg coercion end to end
            "add" => {
                let a = msg.args.get_u64("a").unwrap_or(0);
                let b = msg.args.get_u64("b").unwrap_or(0);
                Ok(Value::U64(a + b))
            }
            "boom" => Err(BackendError::Forbidden),
            _ => Ok(Value::Unit),
        }
    }
}

fn counter_schema() -> ParsedMeta {
    meta(
        "counter",
        &[
            ("add", &[("a", "u64"), ("b", "u64")], false, true),
            ("boom", &[], false, true),
            // exposed_to_cli=false: the console still registers it (full
            // interface), unlike the top-level vosx CLI surface.
            ("ping", &[], true, false),
        ],
    )
}

#[test]
fn actor_command_invokes_and_renders() {
    let mut mock = Mock::default();
    mock.add("counter", 0x0101, counter_schema());
    let mut engine = ConsoleEngine::new(Arc::new(mock)).unwrap();

    let r = engine.eval("counter add 2 3");
    assert!(!r.is_error, "got error: {}", r.output);
    assert_eq!(r.output, "5");
}

#[test]
fn args_coerce_against_schema_type() {
    let mock = Arc::new({
        let mut m = Mock::default();
        m.add("counter", 0x0101, counter_schema());
        m
    });
    let mut engine = ConsoleEngine::new(mock.clone()).unwrap();
    assert!(!engine.eval("counter add 10 20").is_error);

    let calls = mock.calls.lock().unwrap();
    let last = calls.last().unwrap();
    assert_eq!(last.name, "add");
    assert_eq!(last.args.get_u64("a"), Some(10));
    assert_eq!(last.args.get_u64("b"), Some(20));
}

#[test]
fn forbidden_surfaces_as_permission_denied() {
    let mut mock = Mock::default();
    mock.add("counter", 0x0101, counter_schema());
    let mut engine = ConsoleEngine::new(Arc::new(mock)).unwrap();

    let r = engine.eval("counter boom");
    assert!(r.is_error);
    assert!(r.forbidden, "expected forbidden flag, output: {}", r.output);
    assert!(
        r.output.contains("permission denied"),
        "output: {}",
        r.output
    );
}

#[test]
fn full_interface_is_exposed_regardless_of_cli_tag() {
    let mut mock = Mock::default();
    mock.add("counter", 0x0101, counter_schema());
    let mut engine = ConsoleEngine::new(Arc::new(mock)).unwrap();

    // `ping` has exposed_to_cli=false but the console exposes the full
    // interface, so it IS a registered command (mock returns Unit → "").
    let r = engine.eval("counter ping");
    assert!(!r.is_error, "got error: {}", r.output);

    // A genuinely unknown method is still an error.
    assert!(engine.eval("counter no_such_method").is_error);
}

#[test]
fn control_flow_composes_over_actor_commands() {
    let mut mock = Mock::default();
    mock.add("counter", 0x0101, counter_schema());
    let mut engine = ConsoleEngine::new(Arc::new(mock)).unwrap();

    let r = engine.eval("if true { counter add 1 1 } else { counter add 9 9 }");
    assert!(!r.is_error, "got error: {}", r.output);
    assert_eq!(r.output, "2");

    // REPL state persists across lines.
    assert!(!engine.eval("let x = 41").is_error);
    let r = engine.eval("counter add $x 1");
    assert!(!r.is_error, "got error: {}", r.output);
    assert_eq!(r.output, "42");
}

#[test]
fn sandbox_rejects_filesystem_and_external() {
    let mut mock = Mock::default();
    mock.add("counter", 0x0101, counter_schema());
    let mut engine = ConsoleEngine::new(Arc::new(mock)).unwrap();

    for src in [
        "open /etc/passwd",
        "ls /",
        "^ls",
        "http get https://example.com",
    ] {
        let r = engine.eval(src);
        assert!(r.is_error, "`{src}` should be rejected by the sandbox");
    }
}

#[test]
fn refresh_picks_up_late_agents() {
    // Start with no agents; add one; refresh; it becomes invokable.
    let store: Arc<Mutex<Mock>> = Arc::new(Mutex::new(Mock::default()));
    // The engine needs an Arc<dyn SpaceClient>; use a thin forwarding handle.
    struct Handle(Arc<Mutex<Mock>>);
    impl SpaceClient for Handle {
        fn list_agents(&self) -> Result<Vec<AgentInfo>, BackendError> {
            self.0.lock().unwrap().list_agents()
        }
        fn resolve_target(&self, name: &str) -> Result<ServiceId, BackendError> {
            self.0.lock().unwrap().resolve_target(name)
        }
        fn raw_meta(&self, name: &str) -> Result<Vec<u8>, BackendError> {
            self.0.lock().unwrap().raw_meta(name)
        }
        fn schema(&self, name: &str) -> Result<Option<ParsedMeta>, BackendError> {
            self.0.lock().unwrap().schema(name)
        }
        fn invoke(&self, target: ServiceId, msg: &Msg) -> Result<Value, BackendError> {
            self.0.lock().unwrap().invoke(target, msg)
        }
    }

    let mut engine = ConsoleEngine::new(Arc::new(Handle(store.clone()))).unwrap();
    assert!(engine.eval("counter add 1 1").is_error); // not installed yet

    store
        .lock()
        .unwrap()
        .add("counter", 0x0101, counter_schema());
    let n = engine.refresh().unwrap();
    assert!(n >= 1);

    let r = engine.eval("counter add 1 1");
    assert!(!r.is_error, "got error: {}", r.output);
    assert_eq!(r.output, "2");
}
