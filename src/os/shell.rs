use crate::os;
use alloc::{boxed::Box, string::String, vec::Vec};
use chrono::{DateTime, FixedOffset};
use core::cell::RefCell;

pub const MAX_CONNECTIONS: usize = 2;
#[embassy_executor::task(pool_size = MAX_CONNECTIONS)]
pub async fn new_session(io: os::Pipe) {
    let sh = Shell::new(io);
    sh.process_prompt().await;
}

pub struct Shell {
    engine: RefCell<interpreter::Engine>,
    io: os::Pipe,
}

impl Shell {
    pub fn new(io: os::Pipe) -> Self {
        Shell {
            engine: interpreter::Engine::new().into(),
            io,
        }
    }

    pub async fn process_prompt(&self) {
        // let Io(input, output) = self.io;
        // let prompt = input.read_text().await;
        // let out = self.eval(&prompt).unwrap_or(DataStream::Empty);
        // log::debug!("{:?}", out);
    }

    pub fn cd(&mut self, path: &str) {}

    pub fn cwd(&self) -> &str {
        ""
    }

    fn eval(&self, input: &str) -> Result<DataStream, ()> {
        self.engine.borrow_mut().eval(input).map_err(|e| ())
    }
}

pub enum DataStream {
    Empty,
    Value(Value),
    ValueStream(os::Channel<Value>),
    ByteStream(os::Pipe),
}

pub enum Value {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    // Glob { val: String, no_expand: bool },
    // Filesize(Filesize),
    Duration(i64),
    Date(DateTime<FixedOffset>),
    // Range(Box<Range>),
    Record(Box<Record>),
    List(Vec<Value>),
    // Error {
    //     error: Box<ShellError>,
    // },
    Binary(Vec<u8>),
    // CellPath(CellPath),
    // Custom(Box<dyn CustomValue>),
    Nothing,
}

struct Record(heapless::FnvIndexMap<String, Value, 16>);

#[cfg(feature = "nu")]
mod interpreter {
    use nu_engine::{
        command_prelude::{EngineState, PipelineData, ShellError, Stack, StateWorkingSet, Value},
        get_eval_block,
    };

    pub struct Engine {
        state: EngineState,
    }

    impl Engine {
        pub fn new() -> Self {
            Self {
                state: EngineState::new(),
            }
        }

        pub fn eval(&mut self, prompt: &str) -> Result<super::DataStream, ShellError> {
            let engine = EngineState::new();
            let mut stack = Stack::new();
            let delta = {
                let ws = StateWorkingSet::new(&engine);
                // ws.add_decl(Box::new());
                ws.render()
            };
            self.state.merge_delta(delta);
            self.state.cwd(Some(&stack));

            let mut ws = StateWorkingSet::new(&engine);
            let b = nu_parser::parse(&mut ws, None, prompt.as_bytes(), false);
            let eval = get_eval_block(&engine);
            let data = eval(&engine, &mut stack, &b, PipelineData::empty())?;
            log::debug!("{:?}", data);
            Ok(data.into())
        }
    }

    impl From<PipelineData> for super::DataStream {
        fn from(value: PipelineData) -> Self {
            match value {
                PipelineData::Empty => Self::Empty,
                PipelineData::Value(value, _) => Self::Value(value.into()),
                PipelineData::ListStream(list_stream, _) => todo!(),
                PipelineData::ByteStream(byte_stream, _) => todo!(),
            }
        }
    }
    impl From<Value> for super::Value {
        fn from(value: Value) -> Self {
            match value {
                Value::Bool { val, .. } => Self::Bool(val),
                Value::Int { val, .. } => Self::Int(val),
                Value::Float { val, .. } => Self::Float(val),
                Value::String { val, .. } => todo!(),
                Value::Glob { val, .. } => unimplemented!(),
                Value::Filesize { val, .. } => unimplemented!(),
                Value::Duration { val, .. } => Self::Duration(val),
                Value::Date { val, .. } => Self::Date(val),
                Value::Range { val, .. } => unimplemented!(),
                Value::Record { val, .. } => todo!(),
                Value::List { vals, .. } => todo!(),
                Value::Closure { val, .. } => unimplemented!(),
                Value::Error { error, .. } => todo!(),
                Value::Binary { val, .. } => Self::Binary(val),
                Value::CellPath { val, .. } => unimplemented!(),
                Value::Custom { val, .. } => unimplemented!(),
                Value::Nothing { .. } => Self::Nothing,
            }
        }
    }
}

#[cfg(not(feature = "nu"))]
mod interpreter {
    pub struct Engine;
    impl Engine {
        pub fn new() -> Self {
            Self
        }

        pub fn eval(&mut self, prompt: &str) -> Result<(), ()> {
            Ok(())
        }
    }
}
