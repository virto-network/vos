//! `DeviceBook`, a local actor (`light-node.md` §3.1): the labels and
//! settings of the user's devices, by their ids in the device set. The
//! device set's authority is the personal agent's log (§3.5); this is its
//! user-facing mirror, which any of the user's devices edits offline and
//! every device converges on.
//!
//! Each field is a last-writer-wins map: a label, or a setting, is its
//! latest admitted write's, a removal a write of none. A merge handler
//! refuses what is out of bounds, so its operation is never recorded, and
//! a device applying a peer's that its handler refuses quarantines it.
//!
//! The actor's struct holds merge fields alone, so a later release adds
//! fields beside these and runs every earlier release's operations.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_wire::books::{BookError, LABEL_BYTES, SETTING_BYTES, VALUE_BYTES};

#[actor]
pub struct DeviceBook {
    /// Each device's label.
    labels: crdt::Map<u32, String>,
    /// Each device's settings, by the device and the setting's name: a
    /// device's settings lie together.
    settings: crdt::Map<(u32, String), Vec<u8>, Ordered>,
}

#[messages]
impl DeviceBook {
    /// Label `device`.
    #[msg(merge)]
    pub async fn label(&mut self, device: u32, label: String) -> Result<(), BookError> {
        if label.len() > LABEL_BYTES {
            return Err(BookError::Bounds);
        }
        self.labels.insert(&device, &label);
        Ok(())
    }

    /// Drop `device`'s label.
    #[msg(merge)]
    pub async fn unlabel(&mut self, device: u32) {
        self.labels.remove(&device);
    }

    /// Set `device`'s setting `name` to `value`.
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

    /// Drop `device`'s setting `name`.
    #[msg(merge)]
    pub async fn unset(&mut self, device: u32, name: String) {
        self.settings.remove(&(device, name));
    }

    /// `device`'s label.
    #[msg]
    pub async fn label_of(&self, device: u32) -> Option<String> {
        self.labels.get(&device)
    }

    /// Every device's label.
    #[msg(gas = 50_000_000)]
    pub async fn labels(&self) -> Vec<(u32, String)> {
        self.labels.iter(None).collect()
    }

    /// `device`'s settings, by name.
    #[msg(gas = 50_000_000)]
    pub async fn settings(&self, device: u32) -> Vec<(String, Vec<u8>)> {
        self.settings
            .iter(Some(&(device, String::new())))
            .take_while(|((at, _), _)| *at == device)
            .map(|((_, name), value)| (name, value))
            .collect()
    }
}
