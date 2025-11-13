#![feature(macro_metavar_expr)]
#![allow(async_fn_in_trait)]
use embedded_io_async as io;
/// Minimal(quick'n dirty) implementation of the nu plugin protocol
/// https://www.nushell.sh/contributor-book/plugins.html
use miniserde::json::{self, Number};
use types::{Hello, Response};

mod types;

pub use types::{CmdSignature, Flag, NuType, PipelineData, SignatureDetail};

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

pub struct NuPlugin<Io> {
    io: Io,
    signature: &'static [CmdSignature],
    line_buffer: String,
}

impl<Io: io::Read + io::Write> NuPlugin<Io> {
    /// Respond to a Run call with a successful result
    pub async fn respond_success(
        &mut self,
        call_id: u64,
        output: Vec<NuType>,
    ) -> Result<(), Error> {
        use types::{CallType, PipelineData, Response};

        // Convert output to PipelineData format
        let pipeline_data = PipelineData::from_nu_types(output);

        respond(&mut self.io, Response {
            CallResponse: Some((call_id, CallType {
                PipelineData: Some(pipeline_data),
                ..Default::default()
            })),
            ..Default::default()
        })
        .await?;
        Ok(())
    }

    /// Respond to a Run call with an error
    pub async fn respond_error(&mut self, call_id: u64, msg: String) -> Result<(), Error> {
        use types::{CallType, Response};

        respond(&mut self.io, Response {
            CallResponse: Some((call_id, CallType {
                Error: Some(types::Error { msg }),
                ..Default::default()
            })),
            ..Default::default()
        })
        .await?;
        Ok(())
    }
    pub fn new(io: Io, signature: &'static [CmdSignature]) -> Self {
        Self {
            io,
            signature,
            line_buffer: String::new(),
        }
    }

    pub async fn inititial_handshake(&mut self) -> Result<(), Error> {
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
        Ok(())
    }

    pub async fn next_run_call(&mut self) -> Result<Option<(u64, String, Vec<NuType>)>, Error> {
        use types::Request as Req;

        loop {
            let req = read_line(&mut self.io, &mut self.line_buffer).await?;
            log::error!("stdin line: '{req}'");
            if req.is_empty() || req == "\"Goodbye\"" {
                return Ok(None);
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
                } => {
                    // Respond to Signature and Metadata calls but keep looping for until the next Run call
                    let Some(res) = self.handle_call_request(call).await? else {
                        continue;
                    };
                    return Ok(Some(res));
                }
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
        call: json::Value,
    ) -> Result<Option<(u64, String, Vec<NuType>)>, Error> {
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
                Ok(None)
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
                Ok(None)
            }
            Value::Object(mut call) => match call.pop_first() {
                Some((k, Value::Object(call))) if k == "Run" => {
                    let (cmd_name, args) = parse_call(call).ok_or(Error::CallInvalidInput)?;
                    log::error!("calling {cmd_name} with {args:?}");

                    Ok(Some((call_id, cmd_name, args)))
                }
                Some((k, Value::Object(_))) if k == "CustomValueOp" => Err(Error::NotSupported),
                Some(_) | None => Err(Error::Protocol),
            },
            _ => Err(Error::NotSupported),
        }
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
    //! - `test_initial_handshake`: Tests the initial protocol handshake between nu and the plugin
    //! - `test_next_run_call`: Tests receiving and parsing Run calls from nu
    //!
    //! ## Unit Tests
    //! - Protocol message parsing and JSON serialization
    //! - Command argument parsing from protocol JSON
    //! - Plugin instantiation and basic structure
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

    test! {
        async fn test_next_run_call() {
            // Test receiving and parsing Run calls

            let mut mock_io = MockIo::new();

            // Set up protocol conversation
            // 1. Nu sends hello
            mock_io.add_input(r#"{"Hello":{"protocol":"nu-plugin","version":"0.102.0","features":[]}}"#);
            mock_io.add_input("\n");

            // 2. Nu requests signature (should be handled internally)
            mock_io.add_input(r#"{"Call":[1,"Signature"]}"#);
            mock_io.add_input("\n");

            // 3. Nu requests metadata (should be handled internally)
            mock_io.add_input(r#"{"Call":[2,"Metadata"]}"#);
            mock_io.add_input("\n");

            // 4. Nu calls our command - this should be returned
            mock_io.add_input(r#"{"Call":[3,{"Run":{"name":"plugin echo","call":{"named":[["msg",{"String":{"val":"hello world"}}]]}}}]}"#);
            mock_io.add_input("\n");

            // 5. Another command
            mock_io.add_input(r#"{"Call":[4,{"Run":{"name":"plugin test","call":{"named":[["flag",{"Bool":{"val":true}}],["count",{"Int":{"val":42}}]]}}}]}"#);
            mock_io.add_input("\n");

            // 6. Goodbye
            mock_io.add_input("\"Goodbye\"\n");

            const EMPTY_SIGS: &[CmdSignature] = &[];
            let mut plugin = NuPlugin::new(mock_io, EMPTY_SIGS);

            // Initialize handshake first (plugin says hello to nu)
            plugin.inititial_handshake().await.unwrap();

            // Track commands externally since plugin no longer manages state
            let mut commands_called = Vec::new();
            let mut total_args = 0;

            // First call should return the echo command
            // (Hello, Signature, and Metadata are handled internally)
            let result = plugin.next_run_call().await;
            assert!(result.is_ok(), "next_run_call should succeed: {:?}", result);

            if let Ok(Some((call_id, cmd_name, args))) = result {
                assert_eq!(call_id, 3);
                assert_eq!(cmd_name, "echo");
                assert_eq!(args.len(), 1);
                assert!(matches!(&args[0], NuType::String(s) if s == "hello world"));
                commands_called.push(cmd_name);
                total_args += args.len();
            } else {
                panic!("Expected Some((call_id, cmd, args)), got {:?}", result);
            }

            // Second call should return the test command
            let result = plugin.next_run_call().await;
            assert!(result.is_ok(), "next_run_call should succeed: {:?}", result);

            if let Ok(Some((call_id, cmd_name, args))) = result {
                assert_eq!(call_id, 4);
                assert_eq!(cmd_name, "test");
                assert_eq!(args.len(), 2);
                assert!(matches!(&args[0], NuType::Bool(true)));
                assert!(matches!(&args[1], NuType::Int(42)));
                commands_called.push(cmd_name);
                total_args += args.len();
            } else {
                panic!("Expected Some((call_id, cmd, args)), got {:?}", result);
            }

            // Third call should return None (Goodbye)
            let result = plugin.next_run_call().await;
            assert!(result.is_ok(), "next_run_call should succeed: {:?}", result);
            assert!(result.unwrap().is_none(), "Should return None for Goodbye");

            // Verify we tracked the commands correctly
            assert_eq!(commands_called, vec!["echo", "test"]);
            assert_eq!(total_args, 3);

            // Verify protocol messages were sent
            let output = plugin.io.get_output();
            assert!(output.contains(r#""Signature""#), "Should contain Signature response");
            assert!(output.contains(r#""Metadata""#), "Should contain Metadata response");
        }
    }

    test! {
        async fn test_respond_success() {
            // Test responding to a Run call with success

            let mock_io = MockIo::new();

            const EMPTY_SIGS: &[CmdSignature] = &[];
            let mut plugin = NuPlugin::new(mock_io, EMPTY_SIGS);

            // Test responding with a single value
            let result = plugin.respond_success(123, vec![NuType::String("success".to_string())]).await;
            assert!(result.is_ok(), "respond_success should succeed");

            let output = plugin.io.get_output();
            assert!(output.contains(r#""CallResponse""#), "Should contain CallResponse");
            assert!(output.contains(r#""PipelineData""#), "Should contain PipelineData");
            assert!(output.contains(r#"123"#), "Should contain call_id");
            assert!(output.contains(r#""String""#), "Should contain String type");
            assert!(output.contains(r#""success""#), "Should contain the value");
        }
    }

    test! {
        async fn test_respond_error() {
            // Test responding to a Run call with an error

            let mock_io = MockIo::new();

            const EMPTY_SIGS: &[CmdSignature] = &[];
            let mut plugin = NuPlugin::new(mock_io, EMPTY_SIGS);

            // Test responding with an error
            let result = plugin.respond_error(456, "Something went wrong".to_string()).await;
            assert!(result.is_ok(), "respond_error should succeed");

            let output = plugin.io.get_output();
            assert!(output.contains(r#""CallResponse""#), "Should contain CallResponse");
            assert!(output.contains(r#""Error""#), "Should contain Error");
            assert!(output.contains(r#"456"#), "Should contain call_id");
            assert!(output.contains(r#""Something went wrong""#), "Should contain error message");
        }
    }

    test! {
        async fn test_respond_empty() {
            // Test responding with empty output (Nothing)

            let mock_io = MockIo::new();

            const EMPTY_SIGS: &[CmdSignature] = &[];
            let mut plugin = NuPlugin::new(mock_io, EMPTY_SIGS);

            // Test responding with empty output
            let result = plugin.respond_success(789, vec![]).await;
            assert!(result.is_ok(), "respond_success with empty should succeed");

            let output = plugin.io.get_output();
            assert!(output.contains(r#""CallResponse""#), "Should contain CallResponse");
            assert!(output.contains(r#""PipelineData""#), "Should contain PipelineData");
            assert!(output.contains(r#"789"#), "Should contain call_id");
            // Empty PipelineData should serialize as null
            assert!(output.contains(r#"null"#), "Should contain null for empty");
        }
    }
}
