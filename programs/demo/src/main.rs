#[vos::bin]
mod demo {
    #[vos(storage)]
    #[derive(Default)]
    pub struct Demo {
        counter: usize,
    }

    impl Demo {
        #[vos(message)]
        pub fn echo(&mut self, msg: String) -> String {
            self.counter += 1;
            log::info!("echo called {} time(s)", self.counter);
            msg
        }
    }
}
