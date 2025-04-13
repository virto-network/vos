#![feature(impl_trait_in_assoc_type)]

#[wink::bin]
mod demo {
    use std::collections::BTreeMap;

    #[wink(storage)]
    #[derive(Default)]
    pub struct Demo {
        counts: BTreeMap<String, usize>,
    }

    impl Demo {
        /// Tells how many times it has been called by who
        #[wink(message)]
        pub fn count(&mut self, who: String) -> String {
            let count = self.counts.get(&who).copied().unwrap_or_default() + 1;
            self.counts.insert(who, count);
            format!("called {} time(s)", count)
        }
    }
}
