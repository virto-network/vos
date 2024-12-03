use super::Stream;

pub struct HttpIo {
    session: usize,
}

impl super::Io for HttpIo {
    type Cfg = ();

    async fn connection(_cfg: Self::Cfg) -> Self {
        Self { session: 0 }
    }

    async fn io_stream(&self) -> super::Stream {
        todo!()
    }
}
