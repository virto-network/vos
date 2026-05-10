//! Actor message metadata — static descriptors for introspection.
//!
//! Metadata is embedded in ELF binaries in the `.vos_meta` section as a
//! self-contained binary blob (no pointers). vosx reads this section to
//! discover actor names, messages, and their argument types without running
//! the binary.
//!
//! ## Binary format
//!
//! ```text
//! [actor_name_len:u16 LE][actor_name_bytes...]
//! [msg_count:u16 LE]
//!   [name_len:u16 LE][name_bytes...]
//!   [is_query:u8]
//!   [field_count:u16 LE]
//!     [name_len:u16 LE][name_bytes...]
//!     [ty_len:u16 LE][ty_bytes...]
//!   ...
//! ...
//! ```

/// Field descriptor — name and type as strings.
pub struct FieldMeta {
    pub name: &'static str,
    pub ty: &'static str,
}

/// Message descriptor — name, query flag, and fields.
pub struct MessageMeta {
    pub name: &'static str,
    pub is_query: bool,
    pub fields: &'static [FieldMeta],
}

/// Actor descriptor — actor name, messages, and constructor params.
pub struct ActorMeta {
    pub actor_name: &'static str,
    pub messages: &'static [MessageMeta],
    pub constructor: &'static [FieldMeta],
}

// --- Binary serialization (const, used by the macro at compile time) ---

/// Encode a metadata tree into a fixed-size byte array for embedding in
/// `.vos_meta`. Called by the proc macro in a const context.
///
/// The caller provides a buffer size `N` large enough for the data.
/// Returns `(bytes, len)` where `len` is the actual number of bytes written.
pub const fn encode<const N: usize>(meta: &ActorMeta) -> ([u8; N], usize) {
    let mut buf = [0u8; N];
    let mut pos = 0;

    // actor name
    let name = meta.actor_name.as_bytes();
    let [lo, hi] = (name.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut i = 0;
    while i < name.len() {
        buf[pos + i] = name[i];
        i += 1;
    }
    pos += name.len();

    // messages
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;

    let mut m = 0;
    while m < meta.messages.len() {
        let msg = &meta.messages[m];
        // name
        let n = msg.name.as_bytes();
        let [lo, hi] = (n.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < n.len() {
            buf[pos + i] = n[i];
            i += 1;
        }
        pos += n.len();
        // is_query
        buf[pos] = msg.is_query as u8;
        pos += 1;
        // fields
        let [lo, hi] = (msg.fields.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut f = 0;
        while f < msg.fields.len() {
            let field = &msg.fields[f];
            // field name
            let fn_bytes = field.name.as_bytes();
            let [lo, hi] = (fn_bytes.len() as u16).to_le_bytes();
            buf[pos] = lo;
            buf[pos + 1] = hi;
            pos += 2;
            let mut i = 0;
            while i < fn_bytes.len() {
                buf[pos + i] = fn_bytes[i];
                i += 1;
            }
            pos += fn_bytes.len();
            // field type
            let ft_bytes = field.ty.as_bytes();
            let [lo, hi] = (ft_bytes.len() as u16).to_le_bytes();
            buf[pos] = lo;
            buf[pos + 1] = hi;
            pos += 2;
            let mut i = 0;
            while i < ft_bytes.len() {
                buf[pos + i] = ft_bytes[i];
                i += 1;
            }
            pos += ft_bytes.len();
            f += 1;
        }
        m += 1;
    }

    // constructor fields
    let [lo, hi] = (meta.constructor.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;

    let mut c = 0;
    while c < meta.constructor.len() {
        let field = &meta.constructor[c];
        // field name
        let fn_bytes = field.name.as_bytes();
        let [lo, hi] = (fn_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < fn_bytes.len() {
            buf[pos + i] = fn_bytes[i];
            i += 1;
        }
        pos += fn_bytes.len();
        // field type
        let ft_bytes = field.ty.as_bytes();
        let [lo, hi] = (ft_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < ft_bytes.len() {
            buf[pos + i] = ft_bytes[i];
            i += 1;
        }
        pos += ft_bytes.len();
        c += 1;
    }

    (buf, pos)
}

// --- Binary deserialization (std, used by vosx to read from ELF) ---

#[cfg(feature = "std")]
pub use decode::*;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Counter",
            messages: &[
                MessageMeta {
                    name: "run",
                    is_query: false,
                    fields: &[],
                },
                MessageMeta {
                    name: "status",
                    is_query: true,
                    fields: &[FieldMeta {
                        name: "verbose",
                        ty: "bool",
                    }],
                },
            ],
            constructor: &[FieldMeta {
                name: "start",
                ty: "u32",
            }],
        };

        let (buf, len) = encode::<256>(&META);
        let parsed = decode(&buf[..len]).expect("decode failed");

        assert_eq!(parsed.actor_name, "Counter");
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].name, "run");
        assert!(!parsed.messages[0].is_query);
        assert!(parsed.messages[0].fields.is_empty());
        assert_eq!(parsed.messages[1].name, "status");
        assert!(parsed.messages[1].is_query);
        assert_eq!(parsed.messages[1].fields.len(), 1);
        assert_eq!(parsed.messages[1].fields[0].name, "verbose");
        assert_eq!(parsed.messages[1].fields[0].ty, "bool");
        assert_eq!(parsed.constructor.len(), 1);
        assert_eq!(parsed.constructor[0].name, "start");
        assert_eq!(parsed.constructor[0].ty, "u32");
    }
}

#[cfg(feature = "std")]
mod decode {
    extern crate alloc;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Parsed field from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedField {
        pub name: String,
        pub ty: String,
    }

    /// Parsed message from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedMessage {
        pub name: String,
        pub is_query: bool,
        pub fields: Vec<ParsedField>,
    }

    /// Parsed actor metadata from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedMeta {
        pub actor_name: String,
        pub messages: Vec<ParsedMessage>,
        pub constructor: Vec<ParsedField>,
    }

    /// Decode binary metadata from a `.vos_meta` section.
    pub fn decode(data: &[u8]) -> Option<ParsedMeta> {
        let mut pos = 0;

        let actor_name = read_str(data, &mut pos)?;

        let msg_count = read_u16(data, &mut pos)? as usize;
        let mut messages = Vec::with_capacity(msg_count);
        for _ in 0..msg_count {
            let name = read_str(data, &mut pos)?;
            let is_query = *data.get(pos)? != 0;
            pos += 1;
            let field_count = read_u16(data, &mut pos)? as usize;
            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                let fname = read_str(data, &mut pos)?;
                let fty = read_str(data, &mut pos)?;
                fields.push(ParsedField {
                    name: fname,
                    ty: fty,
                });
            }
            messages.push(ParsedMessage {
                name,
                is_query,
                fields,
            });
        }

        // Constructor fields (optional — backward compat with old ELFs)
        let mut constructor = Vec::new();
        if pos < data.len()
            && let Some(ctor_count) = read_u16(data, &mut pos)
        {
            for _ in 0..ctor_count as usize {
                let fname = read_str(data, &mut pos)?;
                let fty = read_str(data, &mut pos)?;
                constructor.push(ParsedField {
                    name: fname,
                    ty: fty,
                });
            }
        }

        Some(ParsedMeta {
            actor_name,
            messages,
            constructor,
        })
    }

    fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
        if *pos + 2 > data.len() {
            return None;
        }
        let val = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Some(val)
    }

    fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
        let len = read_u16(data, pos)? as usize;
        if *pos + len > data.len() {
            return None;
        }
        let s = core::str::from_utf8(&data[*pos..*pos + len]).ok()?;
        *pos += len;
        Some(s.into())
    }

    /// Extract actor metadata from a RISC-V ELF binary by reading the
    /// `.vos_meta` section.
    pub fn from_elf(elf_data: &[u8]) -> Option<ParsedMeta> {
        let section_data = find_elf_section(elf_data, b".vos_meta")?;
        decode(section_data)
    }

    /// Find a named section in a 64-bit little-endian ELF.
    fn find_elf_section<'a>(elf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
        if elf.len() < 64 {
            return None;
        }
        // Verify ELF magic
        if &elf[0..4] != b"\x7fELF" {
            return None;
        }
        // 64-bit little-endian
        if elf[4] != 2 || elf[5] != 1 {
            return None;
        }

        let shoff = u64::from_le_bytes(elf[40..48].try_into().ok()?) as usize;
        let shentsize = u16::from_le_bytes(elf[58..60].try_into().ok()?) as usize;
        let shnum = u16::from_le_bytes(elf[60..62].try_into().ok()?) as usize;
        let shstrndx = u16::from_le_bytes(elf[62..64].try_into().ok()?) as usize;

        if shoff == 0 || shentsize < 64 || shnum == 0 {
            return None;
        }
        if shstrndx >= shnum {
            return None;
        }

        // Read section header string table
        let strtab_hdr = shoff + shstrndx * shentsize;
        if strtab_hdr + 64 > elf.len() {
            return None;
        }
        let strtab_off =
            u64::from_le_bytes(elf[strtab_hdr + 24..strtab_hdr + 32].try_into().ok()?) as usize;
        let strtab_size =
            u64::from_le_bytes(elf[strtab_hdr + 32..strtab_hdr + 40].try_into().ok()?) as usize;
        if strtab_off + strtab_size > elf.len() {
            return None;
        }
        let strtab = &elf[strtab_off..strtab_off + strtab_size];

        // Scan section headers for matching name
        for i in 0..shnum {
            let hdr = shoff + i * shentsize;
            if hdr + 64 > elf.len() {
                continue;
            }
            let name_off = u32::from_le_bytes(elf[hdr..hdr + 4].try_into().ok()?) as usize;
            if name_off >= strtab.len() {
                continue;
            }

            // Compare section name
            let sec_name = &strtab[name_off..];
            if sec_name.len() >= name.len()
                && &sec_name[..name.len()] == name
                && (sec_name.len() == name.len() || sec_name[name.len()] == 0)
            {
                let off = u64::from_le_bytes(elf[hdr + 24..hdr + 32].try_into().ok()?) as usize;
                let size = u64::from_le_bytes(elf[hdr + 32..hdr + 40].try_into().ok()?) as usize;
                if off + size <= elf.len() {
                    return Some(&elf[off..off + size]);
                }
            }
        }
        None
    }
}
