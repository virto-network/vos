//! `vos-anchor`'s space id and window clock, as its own encoding writes
//! them: the id's 32 bytes; the clock's origin, then its length, each a
//! little-endian `u64`.

use alloc::vec::Vec;

use vos_anchor::{SpaceId, WindowClock};

use crate::{Decode, DecodeError, Encode};

impl Encode for SpaceId {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for SpaceId {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        <[u8; 32]>::decode(data).map(|(id, used)| (SpaceId(id), used))
    }
}

impl Encode for WindowClock {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        WindowClock::encode_to(self, buf);
    }
}

impl Decode for WindowClock {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (origin_ms, used) = u64::decode(data)?;
        let (length_ms, more) = u64::decode(&data[used..])?;
        Ok((
            WindowClock {
                origin_ms,
                length_ms,
            },
            used + more,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each encodes as `vos-anchor` encodes it, and decodes back.
    #[test]
    fn as_vos_anchor_encodes_them() {
        let space = SpaceId([7; 32]);
        assert_eq!(space.encode(), [7; 32]);
        assert_eq!(SpaceId::decode(&[7; 32]).unwrap(), (space, 32));
        let clock = WindowClock {
            origin_ms: 0x0102_0304_0506_0708,
            length_ms: 600_000,
        };
        let mut anchor = Vec::new();
        WindowClock::encode_to(&clock, &mut anchor);
        assert_eq!(Encode::encode(&clock), anchor);
        assert_eq!(WindowClock::decode(&anchor).unwrap(), (clock, 16));
        assert!(WindowClock::decode(&anchor[..15]).is_err());
    }
}
