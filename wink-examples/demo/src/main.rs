#[wink::bin]
mod demo {
    #[wink(storage)]
    #[derive(Default)]
    pub struct Demo {
        counter: usize,
    }

    impl Demo {
        #[wink(message)]
        pub fn echo(&mut self, msg: String) -> String {
            self.counter += 1;
            log::info!("echo called {} time(s)", self.counter);
            msg
        }
    }
}
