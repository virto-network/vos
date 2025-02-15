use core::{ops::Deref, str::FromStr};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use heapless::{String, Vec};
use miniserde::{Deserialize, de::Visitor, make_place};

pub use super::sensors::OsSensor;
pub type RawMutex = CriticalSectionRawMutex;
pub type Channel<T, const N: usize = 1> = embassy_sync::channel::Channel<RawMutex, T, N>;
pub type Sender<'c, T, const N: usize = 1> = embassy_sync::channel::Sender<'c, RawMutex, T, N>;
pub type Receiver<'c, T, const N: usize = 1> = embassy_sync::channel::Receiver<'c, RawMutex, T, N>;
pub type Signal<T> = embassy_sync::signal::Signal<RawMutex, T>;
pub type Pipe<const N: usize = 1024> = embassy_sync::pipe::Pipe<RawMutex, N>;
pub type Action = String<32>;
pub type UserId = String<16>;
pub type Descriptor = u32;
pub type Rng = rand::rngs::StdRng;

pub struct CfgString(pub String<32>);
impl Deserialize for CfgString {
    fn begin(out: &mut Option<Self>) -> &mut dyn miniserde::de::Visitor {
        make_place!(Place);
        impl Visitor for Place<CfgString> {
            fn string(&mut self, s: &str) -> miniserde::Result<()> {
                self.out = Some(CfgString(
                    String::from_str(s).map_err(|_| miniserde::Error)?,
                ));
                Ok(())
            }
        }
        Place::new(out)
    }
}
impl Deref for CfgString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

pub struct CfgBytes(pub Vec<u8, 32>);
impl Deserialize for CfgBytes {
    fn begin(out: &mut Option<Self>) -> &mut dyn miniserde::de::Visitor {
        make_place!(Place);
        impl Visitor for Place<CfgBytes> {
            fn string(&mut self, s: &str) -> miniserde::Result<()> {
                if !s.starts_with("0x") {
                    return Err(miniserde::Error);
                }
                let out =
                    s[2..]
                        .chars()
                        .array_chunks()
                        .try_fold(Vec::new(), |mut vec, chars| {
                            let [h, l] = chars.map(|char| {
                                let c = &[char as u8];
                                u8::from_str_radix(unsafe { core::str::from_utf8_unchecked(c) }, 16)
                                    .unwrap_or_default()
                            });
                            vec.push((h << 4) | l).map_err(|_| miniserde::Error)?;
                            Ok(vec)
                        })?;
                self.out = Some(CfgBytes(out));
                Ok(())
            }
        }
        Place::new(out)
    }
}
impl Deref for CfgBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}
