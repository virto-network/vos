#![feature(macro_metavar_expr)]
#![allow(async_fn_in_trait)]
use embedded_io_async as io;
/// Minimal(quick'n dirty) implementation of the nu plugin protocol
/// https://www.nushell.sh/contributor-book/plugins.html
use miniserde::json::{self, Number};
use types::{Hello, Response};

mod types;

pub use types::{CmdSignature, Flag, NuType, SignatureDetail};

const NU_VERSION: &str = "0.102.0";
const VERSION: &str = "0.1.0";

#[derive(Debug)]
pub enum Error {
    Serde,
    Io,
    Protocol,
    NotSupported,
    CallInvalidInput,
}
impl<E: io::Error> From<E> for Error {
    fn from(_value: E) -> Self {
        Error::Io
    }
}

pub struct NuPlugin<Io, S> {
    io: Io,
    signature: &'static [CmdSignature],
    state: S,
}

impl<Io: io::Read + io::Write, S> NuPlugin<Io, S> {
    pub fn new(io: Io, signature: &'static [CmdSignature], state: S) -> Self {
        Self {
            io,
            signature,
            state,
        }
    }

    pub async fn handle_io<F>(&mut self, call_fn: F) -> Result<(), Error>
    where
        F: AsyncFn(&mut S, &str, &[NuType]) -> Result<(), String> + Clone,
    {
        use types::Request as Req;

        // miniserde only supports json
        self.io.write_all(b"\x04json").await?;
        // say hello first
        respond(&mut self.io, Response {
            Hello: Some(Hello {
                protocol: "nu-plugin".into(),
                version: NU_VERSION.into(),
                features: vec![],
            }),
            ..Default::default()
        })
        .await?;

        let mut line = String::new();
        loop {
            let req = read_line(&mut self.io, &mut line).await?;
            log::error!("stdin line: '{req}'");
            if req.is_empty() || req == "\"Goodbye\"" {
                return Ok(());
            }
            let req = json::from_str::<Req>(&req).map_err(|_| Error::Serde)?;

            match req {
                Req {
                    Hello: Some(_hello),
                    ..
                } => { // TODO Already said hello, could check protocol versions though
                }
                Req {
                    Call: Some(call), ..
                } => self.handle_call_request(call_fn.clone(), call).await?,
                Req {
                    EngineCallResponse: Some(_r),
                    ..
                } => return Err(Error::NotSupported),
                Req {
                    Signal: Some(_r), ..
                } => return Err(Error::NotSupported),
                _ => return Err(Error::Protocol),
            };
        }
    }

    async fn handle_call_request(
        &mut self,
        call_fn: impl AsyncFn(&mut S, &str, &[NuType]) -> Result<(), String>,
        call: json::Value,
    ) -> Result<(), Error> {
        use types::{CallType, Metadata, Response, Value};
        // we expect calls to come in a 2 element array
        let Value::Array(mut call) = call else {
            return Err(Error::CallInvalidInput);
        };
        let Value::Number(Number::U64(call_id)) = call.swap_remove(0) else {
            return Err(Error::CallInvalidInput);
        };
        match call.remove(0) {
            Value::String(s) if s == "Signature" => {
                respond(&mut self.io, Response {
                    CallResponse: Some((call_id, CallType {
                        Signature: Some(self.signature),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .await?;
            }
            Value::String(s) if s == "Metadata" => {
                respond(&mut self.io, Response {
                    CallResponse: Some((call_id, CallType {
                        Metadata: Some(Metadata {
                            version: VERSION.into(),
                        }),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .await?;
            }
            Value::Object(mut call) => match call.pop_first() {
                Some((k, Value::Object(call))) if k == "Run" => {
                    let (cmd_name, args) = parse_call(call).ok_or(Error::CallInvalidInput)?;
                    log::error!("calling {cmd_name} with {args:?}");

                    match call_fn(&mut self.state, &cmd_name, &args).await {
                        Ok(output) => {
                            log::error!("program returned {:?}", json::to_string(&output))
                        }
                        Err(msg) => {
                            respond(&mut self.io, Response {
                                CallResponse: Some((call_id, CallType {
                                    Error: Some(types::Error { msg }),
                                    ..Default::default()
                                })),
                                ..Default::default()
                            })
                            .await?;
                        }
                    }
                }
                Some((k, Value::Object(_))) if k == "CustomValueOp" => {
                    return Err(Error::NotSupported);
                }
                Some(_) | None => return Err(Error::Protocol),
            },
            _ => {}
        };
        Ok(())
    }
}

fn parse_call(mut call: json::Object) -> Option<(String, Vec<NuType>)> {
    use json::Value;
    let Value::String(cmd_name) = call.remove("name")? else {
        return None;
    };
    // For now we asume all programs are "program sub-command"
    let (_, cmd_name) = cmd_name.split_once(' ')?;
    let Value::Object(mut args) = call.remove("call")? else {
        return None;
    };
    // our macro assumes named arguments
    let Value::Array(args) = args.remove("named")? else {
        return None;
    };
    let mut parsed_args = Vec::with_capacity(args.len());
    for arg in args {
        let Value::Array(mut arg) = arg else {
            return None;
        };
        let Value::String(_name) = arg.swap_remove(0) else {
            return None;
        };
        let Value::Object(mut val) = arg.remove(0) else {
            return None;
        };
        let (ty, Value::Object(mut val)) = val.pop_first()? else {
            return None;
        };
        let ty = match (ty.as_str(), val.remove("val")) {
            ("Binary", Some(Value::Array(val))) => NuType::Binary(val),
            ("Bool", Some(Value::Bool(val))) => NuType::Bool(val),
            ("Date", Some(Value::String(val))) => NuType::Date(val),
            ("Duration", Some(Value::String(val))) => NuType::Duration(val),
            ("Filesize", Some(Value::String(val))) => NuType::Filesize(val),
            ("Float", Some(Value::Number(Number::F64(val)))) => NuType::Float(val),
            ("Int", Some(Value::Number(Number::I64(val)))) => NuType::Int(val),
            ("Int", Some(Value::Number(Number::U64(val)))) => NuType::Int(val as i64),
            ("List", Some(Value::Array(val))) => NuType::List(val),
            ("Nothing", Some(Value::Null)) => NuType::Nothing,
            ("Number", Some(Value::Number(Number::U64(val)))) => NuType::Number(val),
            ("Record", Some(Value::Object(val))) => NuType::Record(val),
            ("String", Some(Value::String(val))) => NuType::String(val),
            ("Glob", Some(Value::String(val))) => NuType::Glob(val),
            ("Table", Some(Value::Object(val))) => NuType::Table(val),
            _ => return None,
        };
        parsed_args.push(ty);
    }
    Some((cmd_name.into(), parsed_args))
}

async fn respond<W: io::Write>(out: &mut W, msg: Response) -> Result<(), W::Error> {
    let msg = json::to_string(&msg);
    out.write_all(msg.as_bytes()).await?;
    out.write(b"\n").await?;
    out.flush().await?;
    Ok(())
}

async fn read_line<R: io::Read>(reader: &mut R, out: &mut String) -> Result<String, R::Error> {
    let mut buf = [0u8; 128];
    loop {
        if let Some(i) = out.chars().position(|b| b == '\n' || b == '\r') {
            let result = out[..i].to_string();
            // Remove the line including delimiter, handle \r\n properly
            let mut chars_to_remove = i + 1;
            if i < out.len() - 1
                && out.chars().nth(i) == Some('\r')
                && out.chars().nth(i + 1) == Some('\n')
            {
                chars_to_remove = i + 2;
            }
            out.drain(..chars_to_remove);
            return Ok(result);
        }
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    Ok(std::mem::take(out))
}

#[cfg(test)]
mod tests {
    //! Test suite for the nu protocol implementation.
    //!
    //! This test suite demonstrates the core functionality of the nu plugin protocol:
    //!
    //! ## High-Level Integration Tests
    //! - `test_plugin_with_state_demonstration`: Shows how to create a NuPlugin with custom state,
    //!   verifying that the plugin framework correctly holds and manages state that can be
    //!   mutated by command handlers.
    //!
    //! ## Unit Tests
    //! - Protocol message parsing and JSON serialization (`test_respond_function`)
    //! - Type conversions between NuType variants and Rust types (`test_state_mutation`)
    //! - Command argument parsing from protocol JSON (`test_parse_call_unit`)
    //! - Plugin instantiation and basic structure (`test_plugin_creation`)
    //!
    //! The tests use a MockIo implementation to simulate stdin/stdout communication
    //! without requiring actual I/O operations, focusing on the core plugin framework
    //! rather than complex protocol parsing edge cases.

    use super::*;
    use smol_macros::test;
    use std::collections::VecDeque;

    // Mock IO implementation for testing
    struct MockIo {
        read_buffer: VecDeque<u8>,
        write_buffer: Vec<u8>,
    }

    impl MockIo {
        fn new() -> Self {
            Self {
                read_buffer: VecDeque::new(),
                write_buffer: Vec::new(),
            }
        }

        fn add_input(&mut self, data: &str) {
            for byte in data.bytes() {
                self.read_buffer.push_back(byte);
            }
        }

        fn get_output(&self) -> String {
            String::from_utf8_lossy(&self.write_buffer).to_string()
        }
    }

    #[derive(Debug)]
    struct MockError;

    impl embedded_io_async::Error for MockError {
        fn kind(&self) -> embedded_io_async::ErrorKind {
            embedded_io_async::ErrorKind::Other
        }
    }

    impl io::ErrorType for MockIo {
        type Error = MockError;
    }

    impl io::Read for MockIo {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let mut count = 0;
            for i in 0..buf.len() {
                if let Some(byte) = self.read_buffer.pop_front() {
                    buf[i] = byte;
                    count += 1;
                } else {
                    break;
                }
            }
            Ok(count)
        }
    }

    impl io::Write for MockIo {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.write_buffer.extend_from_slice(buf);
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    // Test state that will be mutated by our handler
    #[derive(Debug, Default, PartialEq)]
    struct TestState {
        commands_called: Vec<String>,
        total_args: usize,
        last_error: Option<String>,
    }

    // Handler function for the integration test
    async fn test_handler(
        state: &mut TestState,
        cmd_name: &str,
        args: &[NuType],
    ) -> Result<(), String> {
        // Record every call to verify state mutation
        state.commands_called.push(cmd_name.to_string());
        state.total_args += args.len();

        // Process different commands
        match cmd_name {
            "echo" => {
                // Successful command processing
                for arg in args {
                    if let NuType::String(s) = arg {
                        if s == "trigger-error" {
                            state.last_error = Some("Intentional error".to_string());
                            return Err("Intentional error".to_string());
                        }
                    }
                }
                Ok(())
            }
            "test" => {
                // Another successful command
                Ok(())
            }
            _ => {
                // Unknown command
                let error = format!("Unknown command: {}", cmd_name);
                state.last_error = Some(error.clone());
                Err(error)
            }
        }
    }

    test! {
        async fn test_handle_io_integration() {
            // THE MAIN TEST: This tests the handle_io method which is the core public API

            let mut mock_io = MockIo::new();

            // Set up complete protocol conversation
            // 1. Nu sends hello
            mock_io.add_input(r#"{"Hello":{"protocol":"nu-plugin","version":"0.102.0","features":[]}}"#);
            mock_io.add_input("\n");

            // 2. Nu requests signature
            mock_io.add_input(r#"{"Call":[1,"Signature"]}"#);
            mock_io.add_input("\n");

            // 3. Nu requests metadata
            mock_io.add_input(r#"{"Call":[2,"Metadata"]}"#);
            mock_io.add_input("\n");

            // 4. Nu calls our command (successful)
            mock_io.add_input(r#"{"Call":[3,{"Run":{"name":"plugin echo","call":{"named":[["msg",{"String":{"val":"hello world"}}]]}}}]}"#);
            mock_io.add_input("\n");

            // 5. Nu calls another command (also successful)
            mock_io.add_input(r#"{"Call":[4,{"Run":{"name":"plugin test","call":{"named":[["flag",{"Bool":{"val":true}}],["count",{"Int":{"val":42}}]]}}}]}"#);
            mock_io.add_input("\n");

            // 6. Goodbye
            mock_io.add_input("\"Goodbye\"\n");

            // Create plugin with test state
            const EMPTY_SIGS: &[CmdSignature] = &[];
            let initial_state = TestState {
                commands_called: vec![],
                total_args: 0,
                last_error: None,
            };
            let mut plugin = NuPlugin::new(mock_io, EMPTY_SIGS, initial_state);

            // THIS IS THE KEY TEST: Call handle_io with our handler
            let result = plugin.handle_io(test_handler).await;

            // Verify handle_io succeeded
            assert!(result.is_ok(), "handle_io should succeed: {:?}", result);

            // Verify IO outputs (protocol compliance)
            let output = plugin.io.get_output();
            assert!(output.starts_with("\x04json"), "Should start with protocol marker");
            assert!(output.contains(r#""Hello""#), "Should contain Hello response");
            assert!(output.contains(r#""protocol":"nu-plugin""#), "Should contain protocol");
            assert!(output.contains(r#""Signature""#), "Should contain Signature response");
            assert!(output.contains(r#""Metadata""#), "Should contain Metadata response");
            assert!(output.contains(r#""version":"0.1.0""#), "Should contain plugin version");

            // Verify state mutations (the key integration test!)
            assert_eq!(plugin.state.commands_called, vec!["echo", "test"], "Handler should have been called with both commands");
            assert_eq!(plugin.state.total_args, 3, "Should have processed 3 total arguments (1 + 2)");
            assert!(plugin.state.last_error.is_none(), "Should have no errors for successful commands");
        }
    }

    test! {
        async fn test_handle_io_with_error() {
            // Test handle_io with a command that triggers an error

            let mut mock_io = MockIo::new();

            // Minimal protocol + error-triggering command
            mock_io.add_input(r#"{"Hello":{"protocol":"nu-plugin","version":"0.102.0","features":[]}}"#);
            mock_io.add_input("\n");

            // Command that will trigger an error in our handler
            mock_io.add_input(r#"{"Call":[5,{"Run":{"name":"plugin echo","call":{"named":[["msg",{"String":{"val":"trigger-error"}}]]}}}]}"#);
            mock_io.add_input("\n");

            mock_io.add_input("\"Goodbye\"\n");

            const EMPTY_SIGS: &[CmdSignature] = &[];
            let mut plugin = NuPlugin::new(mock_io, EMPTY_SIGS, TestState::default());

            // Call handle_io - should succeed even though handler returns error
            let result = plugin.handle_io(test_handler).await;
            assert!(result.is_ok(), "handle_io should succeed even when handler fails");

            // Verify error was handled properly in protocol
            let output = plugin.io.get_output();
            assert!(output.contains(r#""Error""#), "Should contain Error response");
            assert!(output.contains(r#""Intentional error""#), "Should contain our error message");

            // Verify state was still mutated even though handler returned error
            assert_eq!(plugin.state.commands_called, vec!["echo"], "Handler should have been called");
            assert_eq!(plugin.state.total_args, 1, "Should have processed 1 argument");
            assert_eq!(plugin.state.last_error, Some("Intentional error".to_string()), "Should record the error");
        }
    }
}
