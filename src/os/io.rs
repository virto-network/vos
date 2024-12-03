use super::{Channel, Pipe, Receiver, Sender, Signal};
use heapless::String;
use serde::{Deserialize, Serialize};

// #[cfg(feature = "std")]
// pub mod http;
// #[cfg(feature = "web")]
// pub mod web;

pub type Input = Stream;
pub type Output = Stream;

pub type Token = String<32>;

pub struct Stream {
    text: Channel<Token, 1024>,
    data: Pipe,
    state: Signal<Status>,
}

pub enum Status {
    Ready,
    Typing,
    Streaming,
}

impl Stream {
    pub fn new() -> Self {
        Stream {
            text: Channel::new(),
            data: Pipe::new(),
            state: Signal::new(),
        }
    }

    pub async fn read_text<const N: usize>(&self) -> String<N> {
        self.wait_ready().await;
        let mut txt = String::new();
        loop {
            let t = self.text.receive().await;
            if let Err(_) = txt.push_str(&t) {
                break;
            }
        }
        txt
    }

    pub async fn wait_ready(&self) {
        while let Status::Ready = self.state.wait().await {}
    }
}
