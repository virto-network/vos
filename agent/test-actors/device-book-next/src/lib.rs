//! The device book's next release: its fields and handlers as they are,
//! and a grow-only set of the devices the user retired beside them, which
//! the first release has no handler for.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_wire::books::{BookError, LABEL_BYTES, SETTING_BYTES, VALUE_BYTES};

#[actor]
pub struct DeviceBook {
    labels: crdt::Map<u32, String>,
    settings: crdt::Map<(u32, String), Vec<u8>, Ordered>,
    /// The devices retired.
    retired: crdt::GSet<u32>,
}

#[messages]
impl DeviceBook {
    pub fn new() -> Self {
        Self {
            labels: Default::default(),
            settings: Default::default(),
            retired: Default::default(),
        }
    }

    #[msg(merge)]
    pub async fn label(&mut self, device: u32, label: String) -> Result<(), BookError> {
        if label.len() > LABEL_BYTES {
            return Err(BookError::Bounds);
        }
        self.labels.insert(&device, &label);
        Ok(())
    }

    #[msg(merge)]
    pub async fn unlabel(&mut self, device: u32) {
        self.labels.remove(&device);
    }

    #[msg(merge)]
    pub async fn set(
        &mut self,
        device: u32,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), BookError> {
        if name.is_empty() || name.len() > SETTING_BYTES || value.len() > VALUE_BYTES {
            return Err(BookError::Bounds);
        }
        self.settings.insert(&(device, name), &value);
        Ok(())
    }

    #[msg(merge)]
    pub async fn unset(&mut self, device: u32, name: String) {
        self.settings.remove(&(device, name));
    }

    /// Retire `device`, for good.
    #[msg(merge)]
    pub async fn retire(&mut self, device: u32) {
        self.retired.insert(&device);
    }

    #[msg]
    pub async fn label_of(&self, device: u32) -> Option<String> {
        self.labels.get(&device)
    }

    #[msg(gas = 50_000_000)]
    pub async fn labels(&self) -> Vec<(u32, String)> {
        self.labels.iter(None).collect()
    }

    #[msg(gas = 50_000_000)]
    pub async fn settings(&self, device: u32) -> Vec<(String, Vec<u8>)> {
        self.settings
            .iter(Some(&(device, String::new())))
            .take_while(|((at, _), _)| *at == device)
            .map(|((_, name), value)| (name, value))
            .collect()
    }

    /// The devices retired.
    #[msg(gas = 50_000_000)]
    pub async fn retired(&self) -> Vec<u32> {
        self.retired.iter(None).collect()
    }
}
