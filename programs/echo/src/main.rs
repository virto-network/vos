#[vos::bin]
mod echo {
    #[vos(storage)]
    #[derive(Default)]
    pub struct Echo {
        counter: usize,
    }

    impl Echo {
        #[vos(constructor)]
        pub fn new() -> Self {
            Default::default()
        }

        #[vos(message)]
        pub fn echo(&mut self, msg: String) -> String {
            self.counter += 1;
            log::info!("echo called {} time(s)", self.counter);
            msg
        }
    }
}
