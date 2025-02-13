use core::convert::Infallible;

use super::{Channel, Pipe, Receiver, Sender, Signal};
use embedded_io_async::{ErrorType, Read, Write};
use heapless::String;
use serde::{Deserialize, Serialize};

pub type Input = DataStream;
pub type Output = DataStream;

impl DataStream {
    pub fn new() -> Self {
        DataStream::Empty
    }

    // pub async fn read_text<const N: usize>(&self) -> String<N> {
    //     self.wait_ready().await;
    //     let mut txt = String::new();
    //     loop {
    //         let t = self.text.receive().await;
    //         if let Err(_) = txt.push_str(&t) {
    //             break;
    //         }
    //     }
    //     txt
    // }
}

impl Read for DataStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.raw.read(buf).await)
    }
}
impl Write for DataStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(self.raw.write(buf).await)
    }
}
impl ErrorType for DataStream {
    type Error = Infallible;
}

///
pub struct Io(pub Input, pub Output);

impl Default for Io {
    fn default() -> Self {
        Io(Input::new(), Output::new())
    }
}
impl Read for Io {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).await
    }
}

impl Write for Io {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.1.write(buf).await
    }
}

impl ErrorType for Io {
    type Error = Infallible;
}
