use super::{Input, InputStream, Output, OutputSink};

pub struct Cfg {}

pub fn setup(cfg: Cfg) -> (impl InputStream, impl OutputSink) {
    // TODO dummy
    (
        futures_util::stream::once(async { Input::Prompt("hello".into()) }),
        futures_util::sink::unfold(Output::Empty, |o, _| async { Ok(o) }),
    )
}
