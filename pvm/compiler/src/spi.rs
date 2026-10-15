//! GP standard-program (SPI) blob emitter.
//!
//! Serializes the standard PVM program format — the blob
//! `vos_pvm::spi::parse_standard_program` consumes. This is the byte-for-byte
//! inverse of that parser and its `deblob_compact` code decoder:
//!
//! ```text
//!   program:  E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s) ‖ o ‖ w ‖ E₄(|c|) ‖ c
//!   c:        E(|j|) ‖ E₁(z_j) ‖ E(|code|) ‖ jump_table ‖ code ‖ packed_bitmask
//! ```
//!
//! where `o` = read-only data, `w` = read-write data, `z` = additional zeroed
//! heap pages, `s` = stack size in bytes, `z_j` = the jump-table entry width
//! in bytes, `Eₙ(·)` is a fixed-width little-endian integer, and `E(·)` is
//! the standard natural encoding. No metadata prefix is emitted or accepted:
//! the result is one canonical bare program blob.

/// A JAM service's metadata, which its code blob carries before its
/// program, as PolkaJam's own services do: a version (0), then its name,
/// version, license and authors.
pub struct ServiceMetadata<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub license: &'a str,
    pub authors: &'a [&'a str],
}

impl ServiceMetadata<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8];
        for text in [self.name, self.version, self.license] {
            encode_bytes(text.as_bytes(), &mut out);
        }
        vos_pvm_program::encode_nat(self.authors.len() as u64, &mut out);
        for author in self.authors {
            encode_bytes(author.as_bytes(), &mut out);
        }
        out
    }
}

/// A standard program made a JAM service's code blob, `E(↕metadata) ‖
/// program`: what `jamt create-service` takes.
pub fn service_blob(program: &[u8], metadata: &ServiceMetadata) -> Vec<u8> {
    let mut blob = Vec::with_capacity(program.len() + 64);
    encode_bytes(&metadata.encode(), &mut blob);
    blob.extend_from_slice(program);
    blob
}

/// Gray Paper bytes with their length, a natural, first.
fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    vos_pvm_program::encode_nat(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    /// A service blob is its metadata, length-prefixed, then the program,
    /// as the probe service PolkaJam ran was built.
    #[test]
    fn a_service_blob_carries_its_metadata_first() {
        let metadata = super::ServiceMetadata {
            name: "vos-agent",
            version: "0.1.0",
            license: "AGPL-3.0-or-later",
            authors: &["VOS"],
        };
        let encoded = metadata.encode();
        assert_eq!(
            encoded,
            [
                &[0, 9][..],
                b"vos-agent",
                &[5],
                b"0.1.0",
                &[17],
                b"AGPL-3.0-or-later",
                &[1, 3],
                b"VOS"
            ]
            .concat()
        );
        let blob = super::service_blob(&[7, 8], &metadata);
        assert_eq!(
            blob,
            [&[encoded.len() as u8][..], &encoded, &[7, 8]].concat()
        );
    }
}
