//! The connections the client opens, an hour at a time, in the foreground
//! and in the background, for the bound on rendezvous (at most 30 an
//! hour in the foreground, `light-node.md` §6.7).
//!
//! Each onion connection is one rendezvous: its stream goes under an
//! isolation token of its own, so arti builds it circuits of its own, a
//! descriptor fetch, an introduction and the rendezvous circuit (about
//! three circuits a rendezvous; arti keys an onion's descriptor by
//! isolation, so none is shared). An attempt that fails or misses its
//! deadline is counted too: it built circuits all the same. A clearnet
//! connection builds none, and is counted apart.

use std::collections::VecDeque;
use std::fmt;

use vos_abi::{Decode, Encode};

use crate::route::Purpose;

/// The hours kept, the newest last: two days.
pub const HOURS: usize = 48;

/// What was opened in an hour, in the foreground or in the background.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Opened {
    /// Onion connections asked of Tor, each a rendezvous, by purpose
    /// ([`Purpose`] as its index).
    pub rendezvous: [u32; Purpose::ALL.len()],
    /// Of them, those that failed or missed their deadline.
    pub failed: u32,
    /// Clearnet connections, which take no circuit.
    pub clearnet: u32,
}

impl Opened {
    /// Every rendezvous of the hour.
    pub fn rendezvous(&self) -> u32 {
        self.rendezvous.iter().sum()
    }

    fn add(&mut self, other: &Opened) {
        for (count, more) in self.rendezvous.iter_mut().zip(other.rendezvous) {
            *count += more;
        }
        self.failed += other.failed;
        self.clearnet += other.clearnet;
    }

    /// The rendezvous made for `purpose`.
    pub fn of(&self, purpose: Purpose) -> u32 {
        self.rendezvous[purpose as usize]
    }
}

/// Encoded as its counts by purpose (as many as it names, a later
/// purpose's read as none), then the failed and the clearnet counts.
impl Encode for Opened {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.rendezvous.to_vec().encode_to(buf);
        (self.failed, self.clearnet).encode_to(buf);
    }
}

impl Decode for Opened {
    fn decode(data: &[u8]) -> Result<(Self, usize), vos_abi::DecodeError> {
        let (counts, used) = Vec::<u32>::decode(data)?;
        let ((failed, clearnet), more) = <(u32, u32)>::decode(&data[used..])?;
        let mut rendezvous = [0; Purpose::ALL.len()];
        for (count, decoded) in rendezvous.iter_mut().zip(counts) {
            *count = decoded;
        }
        Ok((
            Self {
                rendezvous,
                failed,
                clearnet,
            },
            used + more,
        ))
    }
}

impl fmt::Display for Opened {
    /// `N rendezvous (F failed; purpose n, …), C clearnet`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} rendezvous ({} failed",
            self.rendezvous(),
            self.failed
        )?;
        for purpose in Purpose::ALL {
            let count = self.of(purpose);
            if count > 0 {
                write!(f, "; {} {count}", name(purpose))?;
            }
        }
        write!(f, "), {} clearnet", self.clearnet)
    }
}

/// A purpose's name in a tally's line.
fn name(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Proven => "proven",
        Purpose::Fetch => "fetch",
        Purpose::Feed => "feed",
        Purpose::Member => "member",
        Purpose::Personal => "personal",
        Purpose::Background => "background",
        Purpose::Screens => "screens",
    }
}

/// One hour's connections. Encoded, a process keeps its tally across
/// restarts ([`super::Client::restore_opened`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Hour {
    /// The hour, counted from the Unix epoch by the device's clock.
    pub hour: u64,
    /// While the app was in the foreground.
    pub foreground: Opened,
    /// While it was not: a background job's.
    pub background: Opened,
}

impl fmt::Display for Hour {
    /// `rendezvous hour H (from S s): foreground …; background …`, `S` the
    /// hour's first second since the Unix epoch.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rendezvous hour {} (from {} s): foreground {}; background {}",
            self.hour,
            self.hour * 3_600,
            self.foreground,
            self.background
        )
    }
}

/// How a connection went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dialed {
    Onion { purpose: Purpose, failed: bool },
    Clearnet,
}

/// The hours, and whether the app is in the foreground now.
#[derive(Default)]
pub(crate) struct Tally {
    hours: VecDeque<Hour>,
    foreground: bool,
}

impl Tally {
    pub(crate) fn set_foreground(&mut self, foreground: bool) {
        self.foreground = foreground;
    }

    /// Count `dialed` in hour `hour`.
    pub(crate) fn record(&mut self, hour: u64, dialed: Dialed) {
        if self.hours.back().is_none_or(|last| last.hour != hour) {
            if self.hours.len() == HOURS {
                self.hours.pop_front();
            }
            self.hours.push_back(Hour {
                hour,
                ..Hour::default()
            });
        }
        let last = self.hours.back_mut().expect("the hour pushed");
        let opened = match self.foreground {
            true => &mut last.foreground,
            false => &mut last.background,
        };
        match dialed {
            Dialed::Onion { purpose, failed } => {
                opened.rendezvous[purpose as usize] += 1;
                opened.failed += u32::from(failed);
            }
            Dialed::Clearnet => opened.clearnet += 1,
        }
    }

    /// `hours` a process before this one kept, counted in with this
    /// one's, the newest [`HOURS`] kept.
    pub(crate) fn restore(&mut self, hours: &[Hour]) {
        let mut merged: Vec<Hour> = self.hours.iter().copied().collect();
        for hour in hours {
            match merged.iter_mut().find(|kept| kept.hour == hour.hour) {
                Some(kept) => {
                    kept.foreground.add(&hour.foreground);
                    kept.background.add(&hour.background);
                }
                None => merged.push(*hour),
            }
        }
        merged.sort_by_key(|hour| hour.hour);
        let skip = merged.len().saturating_sub(HOURS);
        self.hours = merged.into_iter().skip(skip).collect();
    }

    pub(crate) fn hours(&self) -> Vec<Hour> {
        self.hours.iter().copied().collect()
    }
}

/// The hour now, from the Unix epoch, by the device's clock.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / 3_600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_hour_counts_the_foregrounds_and_the_backgrounds_apart() {
        let mut tally = Tally::default();
        tally.set_foreground(true);
        tally.record(
            10,
            Dialed::Onion {
                purpose: Purpose::Feed,
                failed: false,
            },
        );
        tally.record(
            10,
            Dialed::Onion {
                purpose: Purpose::Proven,
                failed: true,
            },
        );
        tally.set_foreground(false);
        tally.record(
            10,
            Dialed::Onion {
                purpose: Purpose::Background,
                failed: false,
            },
        );
        tally.record(11, Dialed::Clearnet);
        let hours = tally.hours();
        assert_eq!(hours.len(), 2);
        assert_eq!(hours[0].foreground.rendezvous(), 2);
        assert_eq!(hours[0].foreground.failed, 1);
        assert_eq!(hours[0].background.of(Purpose::Background), 1);
        assert_eq!(hours[1].background.clearnet, 1);
        assert_eq!(
            hours[0].to_string(),
            "rendezvous hour 10 (from 36000 s): foreground 2 rendezvous (1 failed; proven 1; \
             feed 1), 0 clearnet; background 1 rendezvous (0 failed; background 1), 0 clearnet"
        );
        for hour in 12..12 + HOURS as u64 {
            tally.record(hour, Dialed::Clearnet);
        }
        let hours = tally.hours();
        assert_eq!(hours.len(), HOURS);
        assert_eq!(hours[0].hour, 12);
        // A restart's tally takes the last one's in, its own counts beside.
        let mut restarted = Tally::default();
        restarted.record(12 + HOURS as u64 - 1, Dialed::Clearnet);
        let kept = Vec::<Hour>::decode_exact(&hours.encode()).unwrap();
        restarted.restore(&kept);
        let hours = restarted.hours();
        assert_eq!(hours.len(), HOURS);
        assert_eq!(hours.last().unwrap().background.clearnet, 2);
    }
}
