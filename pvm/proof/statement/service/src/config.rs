//! What a deployment of the service fixes: the JAM chain's genesis hash and
//! genesis time, and the programs it pins. Constants, changed by redeploy:
//! the program carries them in a fixed block of its read-only data,
//! [`UNSET`] as built, which [`configure`] fills in the linked program
//! before it is deployed, so the service's code hash commits to them.
//!
//! The block is [`MARKER`], then the genesis hash (32), the genesis time
//! (8, little-endian), the pins' count (1) and [`MAX_PINS`] pins, each a
//! program id's 32 bytes; past the count, zeros. An unconfigured program
//! pins nothing, so it refuses every statement as of another program than
//! its pins (code 3).

use alloc::vec::Vec;

use vos_statement::vos_anchor::codec::Reader;
use vos_statement::{DecodeError, ProgramId};

/// The block's first bytes, found once in a linked program.
pub const MARKER: [u8; 32] = *b"vos/statement-service/config/v2\0";
/// The most programs a deployment pins.
pub const MAX_PINS: usize = 16;
/// A pin's bytes: the program id.
const PIN_BYTES: usize = 32;
/// The block's bytes, the marker among them.
pub const BYTES: usize = 32 + 32 + 8 + 1 + MAX_PINS * PIN_BYTES;

/// The block as built: the marker, then zeros, a configuration of no pin.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a constant's evaluation: `at` runs below the marker's length, within the block"
)]
pub const UNSET: [u8; BYTES] = {
    let mut block = [0u8; BYTES];
    let mut at = 0;
    while at < MARKER.len() {
        block[at] = MARKER[at];
        at += 1;
    }
    block
};

/// A deployment's constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The JAM chain's genesis hash, which the venue's id hashes
    /// (`VenueId::jam`).
    pub genesis: [u8; 32],
    /// The JAM chain's genesis time, ms since the Unix epoch: slot t
    /// starts at `genesis_ms + t × 6 s`, the venue's time.
    pub genesis_ms: u64,
    /// The programs whose statements it judges.
    pub pins: Vec<ProgramId>,
}

/// Why a configuration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// More pins than [`MAX_PINS`], or one program pinned twice.
    Pins,
    /// The program holds no configuration block, or more than one.
    Block,
}

impl Config {
    /// The block holding it.
    pub fn encode(&self) -> Result<[u8; BYTES], ConfigError> {
        let pins = u8::try_from(self.pins.len()).map_err(|_| ConfigError::Pins)?;
        let twice = self.pins.iter().enumerate().any(|(at, pin)| {
            self.pins
                .iter()
                .skip(at.saturating_add(1))
                .any(|other| other == pin)
        });
        if usize::from(pins) > MAX_PINS || twice {
            return Err(ConfigError::Pins);
        }
        let mut body = Vec::with_capacity(BYTES);
        body.extend_from_slice(&MARKER);
        body.extend_from_slice(&self.genesis);
        body.extend_from_slice(&self.genesis_ms.to_le_bytes());
        body.push(pins);
        for pin in &self.pins {
            body.extend_from_slice(&pin.to_bytes());
        }
        body.resize(BYTES, 0);
        body.try_into().map_err(|_| ConfigError::Pins)
    }

    /// The configuration a block holds: its marker, at most
    /// [`MAX_PINS`] pins, each program id canonical, and zeros past them.
    pub fn decode(block: &[u8; BYTES]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(block);
        if reader.array::<32>()? != MARKER {
            return Err(DecodeError::Noncanonical);
        }
        let genesis = reader.array()?;
        let genesis_ms = reader.u64()?;
        let count = usize::from(reader.u8()?);
        if count > MAX_PINS {
            return Err(DecodeError::Noncanonical);
        }
        let pins = (0..count)
            .map(|_| ProgramId::decode_from(&mut reader))
            .collect::<Result<Vec<_>, _>>()?;
        let rest = reader.take(BYTES.saturating_sub(reader.used()))?;
        if rest.iter().any(|&byte| byte != 0) {
            return Err(DecodeError::Noncanonical);
        }
        Ok(Self {
            genesis,
            genesis_ms,
            pins,
        })
    }
}

/// `program`, a linked service program, configured: its one block replaced
/// by `config`'s.
pub fn configure(program: &mut [u8], config: &Config) -> Result<(), ConfigError> {
    let block = config.encode()?;
    let mut found = program
        .windows(MARKER.len())
        .enumerate()
        .filter(|(_, window)| *window == MARKER)
        .map(|(at, _)| at);
    let (Some(at), None) = (found.next(), found.next()) else {
        return Err(ConfigError::Block);
    };
    let end = at.checked_add(BYTES).ok_or(ConfigError::Block)?;
    program
        .get_mut(at..end)
        .ok_or(ConfigError::Block)?
        .copy_from_slice(&block);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn config() -> Config {
        Config {
            genesis: [0x4a; 32],
            genesis_ms: 1_735_732_800_000,
            pins: vec![ProgramId([1, 2, 3, 4, 5, 6, 7, 8]), ProgramId([9; 8])],
        }
    }

    /// A configuration's block decodes to it; the unset block to one of no
    /// pin; a block of a word at `p`, of a byte past the pins, or of
    /// another marker is refused.
    #[test]
    fn a_block_decodes_to_its_configuration() {
        let block = config().encode().unwrap();
        assert_eq!(Config::decode(&block), Ok(config()));
        assert_eq!(
            Config::decode(&UNSET),
            Ok(Config {
                genesis: [0; 32],
                genesis_ms: 0,
                pins: Vec::new()
            })
        );
        let first_word = 32 + 32 + 8 + 1;
        let mut high = block;
        high[first_word..first_word + 4].copy_from_slice(&((1u32 << 31) - 1).to_le_bytes());
        assert!(Config::decode(&high).is_err(), "a word at p");
        for at in [32 + 32 + 8, BYTES - 1, 0] {
            let mut bad = block;
            bad[at] = 0xff;
            assert!(Config::decode(&bad).is_err(), "{at}");
        }
    }

    /// A program is configured at its one block; one without it, or with
    /// two, is refused, as is a pin twice or past `MAX_PINS`.
    #[test]
    fn a_program_is_configured_at_its_one_block() {
        let mut program = [&[7u8; 100][..], &UNSET, &[9u8; 50]].concat();
        configure(&mut program, &config()).unwrap();
        let block: [u8; BYTES] = program[100..100 + BYTES].try_into().unwrap();
        assert_eq!(Config::decode(&block), Ok(config()));
        assert_eq!(&program[..100], &[7; 100]);
        assert_eq!(&program[100 + BYTES..], &[9; 50]);
        configure(
            &mut program,
            &Config {
                pins: vec![],
                ..config()
            },
        )
        .unwrap();

        let mut twice = [&UNSET[..], &UNSET].concat();
        assert_eq!(configure(&mut twice, &config()), Err(ConfigError::Block));
        assert_eq!(configure(&mut [0; 700], &config()), Err(ConfigError::Block));
        let mut doubled = config();
        doubled.pins.push(doubled.pins[0]);
        assert_eq!(doubled.encode(), Err(ConfigError::Pins));
        let many = Config {
            pins: (0..=MAX_PINS as u32).map(|i| ProgramId([i; 8])).collect(),
            ..config()
        };
        assert_eq!(many.encode(), Err(ConfigError::Pins));
    }
}
