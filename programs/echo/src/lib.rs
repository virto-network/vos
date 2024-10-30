#[vos::bin]
pub mod echo {
    #[vos(storage)]
    struct Echo {
        counter: usize,
    }

    impl Echo {
        #[vos(constructor)]
        fn new() -> Self {
            Echo { counter: 0 }
        }

        #[vos(message)]
        fn echo(&self, msg: String) -> String {
            self.count += 1;
            msg
        }
    }
}
