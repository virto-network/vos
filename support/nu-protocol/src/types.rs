use miniserde::{
    Deserialize, Serialize,
    json::{self, Number},
};
use std::borrow::Cow;
// miniserde doesn't support enums with data or skipping options so we simulate an enum with a struct
// https://github.com/dtolnay/miniserde/issues/60
macro_rules! fake_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        #[derive(Default, Debug)]
        #[allow(non_snake_case)]
        pub struct $name { $(pub $variant: Option<$variant>),* }
    };
}
macro_rules! ser_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        fake_enum!(pub enum $name { $($variant $(-$($o)?)?,)* });
        impl Serialize for $name {
            fn begin(&self) -> miniserde::ser::Fragment {
                struct Serializer<'a>{
                    data: &'a $name,
                    done: bool,
                }
                impl<'a> miniserde::ser::Map for Serializer<'a> {
                    fn next(&mut self) -> Option<(Cow<str>, &dyn Serialize)> {
                        if self.done { return None }
                        // a "fake enum" should only have one *Some* propery
                        // we check properties one by one and return the first with data
                        $(if let Some(p) = self.data.$variant.as_ref() {
                            self.done = true;
                            return Some((Cow::Borrowed(stringify!($variant)), p as &dyn Serialize));
                        };)*
                        None
                    }
                }
                miniserde::ser::Fragment::Map(Box::new(Serializer { data: self, done: false }))
            }
        }
    }
}
macro_rules! de_enum {
    (pub enum $name:ident { $($variant:ident $(-$(optional $o:tt)?)?,)* }) => {
        fake_enum!(pub enum $name { $($variant $(-$($o)?)?,)* });
        impl Deserialize for $name {
            fn begin(out: &mut Option<Self>) -> &mut dyn miniserde::de::Visitor {
                miniserde::make_place!(Place);
                impl miniserde::de::Visitor for Place<$name> {
                    fn map(&mut self) -> miniserde::Result<Box<dyn miniserde::de::Map + '_>> {
                        Ok(Box::new(Map {
                            out: &mut self.out,
                            val: $name { ..Default::default() },
                        }))
                    }
                }
                struct Map<'a> { out: &'a mut Option<$name>, val: $name }
                impl<'a> miniserde::de::Map for Map<'a> {
                    fn key(&mut self, k: &str) -> miniserde::Result<&mut dyn miniserde::de::Visitor> {
                        match k {
                            $(stringify!($variant) => { Ok(Deserialize::begin(&mut self.val.$variant)) },)*
                            _ => Err(miniserde::Error),
                        }
                    }
                    fn finish(&mut self) -> miniserde::Result<()> {
                        let substitute = $name { ..Default::default() };
                        *self.out = Some(std::mem::replace(&mut self.val, substitute));
                        Ok(())
                    }
                }
                Place::new(out)
            }
        }
    }
}

// using arbitrary json value as replacement for nu's Value and other types
// https://www.nushell.sh/contributor-book/plugin_protocol_reference.html#value-types
pub type Value = miniserde::json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: String,
    pub version: String,
    pub features: Vec<Value>,
}

de_enum! {
    pub enum Request {
        Hello,
        Call,
        EngineCallResponse,
        Signal-,
    }
}

type Call = Value;
type Signal = String;
type EngineCallResponse = (u64, ());

ser_enum! {
    pub enum Response {
        Hello,
        CallResponse,
        EngineCall,
        // Option,
        Data,
        End-,
        Drop-,
        Ack-,
    }
}
type CallResponse = (u64, CallType);
ser_enum! {
    pub enum CallType {
        Metadata,
        Signature,
        Error,
        PipelineData,
    }
}
#[derive(Debug, Serialize)]
pub struct EngineCall {}
#[derive(Debug, Serialize)]
pub struct Data {}
type End = u64;
type Drop = u64;
type Ack = u64;
pub type Signature = &'static [CmdSignature];

#[derive(Debug, Serialize)]
pub struct Metadata {
    pub version: String,
}
// https://docs.rs/nu-protocol/latest/nu_protocol/struct.LabeledError.html
#[derive(Debug, Serialize)]
pub struct Error {
    pub msg: String,
}

//--------------------------

#[derive(Debug)]
pub enum NuType {
    Binary(json::Array),
    Bool(bool),
    Date(String),
    Duration(String),
    Filesize(String),
    Float(f64),
    Int(i64),
    List(json::Array),
    Nothing,
    Number(u64),
    Record(json::Object),
    String(String),
    Glob(String),
    Table(json::Object),
}

ser_enum! {
    pub enum PipelineData {
        Empty,
        Value,
        ListStream,
    }
}

type Empty = ();
type ListStream = Vec<Value>;

impl PipelineData {
    pub fn from_nu_types(values: Vec<NuType>) -> Self {
        if values.is_empty() {
            PipelineData {
                Empty: Some(()),
                Value: None,
                ListStream: None,
            }
        } else if values.len() == 1 {
            let mut values = values;
            PipelineData {
                Empty: None,
                Value: Some(nu_type_to_value(values.remove(0))),
                ListStream: None,
            }
        } else {
            PipelineData {
                Empty: None,
                Value: None,
                ListStream: Some(values.into_iter().map(nu_type_to_value).collect()),
            }
        }
    }
}

fn nu_type_to_value(nu_type: NuType) -> Value {
    match nu_type {
        NuType::Binary(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Array(val));
            obj.insert("Binary".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Bool(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Bool(val));
            obj.insert("Bool".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Date(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::String(val));
            obj.insert("Date".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Duration(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::String(val));
            obj.insert("Duration".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Filesize(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::String(val));
            obj.insert("Filesize".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Float(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Number(Number::F64(val)));
            obj.insert("Float".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Int(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Number(Number::I64(val)));
            obj.insert("Int".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::List(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Array(val));
            obj.insert("List".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Nothing => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Null);
            obj.insert("Nothing".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Number(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Number(Number::U64(val)));
            obj.insert("Number".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Record(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Object(val));
            obj.insert("Record".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::String(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::String(val));
            obj.insert("String".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Glob(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::String(val));
            obj.insert("Glob".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
        NuType::Table(val) => {
            let mut obj = json::Object::new();
            let mut inner = json::Object::new();
            inner.insert("val".to_string(), Value::Object(val));
            obj.insert("Table".to_string(), Value::Object(inner));
            Value::Object(obj)
        }
    }
}

impl TryFrom<NuType> for Vec<u8> {
    type Error = ();
    fn try_from(value: NuType) -> Result<Self, Self::Error> {
        let NuType::Binary(value) = value else {
            return Err(());
        };
        value
            .into_iter()
            .map(|v| {
                let Value::Number(Number::U64(n)) = v else {
                    return None;
                };
                u8::try_from(n).ok()
            })
            .collect::<Option<_>>()
            .ok_or(())
    }
}
impl TryFrom<NuType> for bool {
    type Error = ();
    fn try_from(value: NuType) -> Result<Self, Self::Error> {
        let NuType::Bool(value) = value else {
            return Err(());
        };
        Ok(value)
    }
}
impl TryFrom<NuType> for String {
    type Error = ();
    fn try_from(value: NuType) -> Result<Self, Self::Error> {
        let NuType::String(value) = value else {
            return Err(());
        };
        Ok(value)
    }
}
impl TryFrom<NuType> for u64 {
    type Error = ();
    fn try_from(value: NuType) -> Result<Self, Self::Error> {
        let NuType::Number(value) = value else {
            return Err(());
        };
        Ok(value)
    }
}

//--------------------------

#[derive(Debug, Serialize)]
pub struct CmdSignature {
    pub sig: SignatureDetail,
    pub examples: [BinExample; 0],
}
#[derive(Debug, Serialize)]
pub struct SignatureDetail {
    pub name: String,
    pub description: &'static str,
    pub extra_description: &'static str,
    pub search_terms: [&'static str; 0],
    pub required_positional: [PositionalArg; 0],
    pub optional_positional: [PositionalArg; 0],
    pub rest_positional: Option<PositionalArg>,
    pub named: Vec<Flag>,
    pub input_output_types: [(Type, Type); 0],
    pub allow_variants_without_examples: bool,
    pub is_filter: bool,
    pub creates_scope: bool,
    pub allows_unknown_args: bool,
    pub category: Category,
}
#[derive(Debug, Serialize)]
pub struct Flag {
    pub long: &'static str,
    pub short: Option<&'static str>, // char
    pub arg: Option<SyntaxShape>,
    pub required: bool,
    pub desc: &'static str,
    pub var_id: Option<VarId>,
    pub default_value: Option<Value>,
}
#[derive(Debug, Serialize)]
pub struct BinExample {
    pub example: String,
    pub description: String,
    pub result: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PositionalArg {
    pub name: String,
    pub desc: String,
    pub shape: SyntaxShape,
    pub var_id: Option<VarId>,
    pub default_value: Option<Value>,
}

// https://docs.rs/nu-protocol/latest/nu_protocol/enum.Type.html
type Type = Value;
// https://docs.rs/nu-protocol/latest/nu_protocol/enum.Category.html
type Category = &'static str;
// https://docs.rs/nu-protocol/latest/nu_protocol/enum.SyntaxShape.html
type SyntaxShape = &'static str;
type VarId = usize;
