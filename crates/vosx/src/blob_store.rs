// Phase 1 will exercise every public symbol; until then the
// module is loaded but unused.
#![allow(dead_code)]

//! Content-addressed blob cache and source resolver.
//!
//! Programs (PVM ELFs) are referenced by 32-byte blake2b
//! `BlobHash`. The cache lives at `~/.cache/vosx/blobs/{hex_hash}`
//! cross-space — two spaces installing the same program share
//! storage. Resolution order: cache (immediate) → peers (handled
//! by the gossip layer, not here) → external source (file path
//! / URL / IPFS CID).

use std::fs;
use std::io;
use std::path::PathBuf;

/// 32-byte blake2b hash of a blob's bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobHash(pub [u8; 32]);

impl BlobHash {
    pub fn of(bytes: &[u8]) -> Self {
        let h = blake2b_simd::Params::new().hash_length(32).hash(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        BlobHash(out)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, BlobError> {
        let v = hex::decode(s).map_err(|_| BlobError::BadHashHex)?;
        if v.len() != 32 {
            return Err(BlobError::BadHashHex);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(BlobHash(out))
    }
}

impl core::fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlobHash({})", self.to_hex())
    }
}

impl core::fmt::Display for BlobHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Where to fetch a blob's bytes from. The CLI parses
/// `<source>` arguments into one of these — see `BlobSource::parse`.
#[derive(Clone, Debug)]
pub enum BlobSource {
    /// Local file. Always valid; bytes are read on resolve and
    /// the resulting hash is stored back to the cache.
    Path(PathBuf),
    /// IPFS content-id. v1 implementation deferred — when wired
    /// up, fetches via local IPFS gateway / kubo HTTP API.
    Cid(String),
    /// Plain HTTP(S) URL. Bytes are streamed and verified
    /// against the URL's fragment if present.
    Url(String),
    /// Already-known content hash. Resolve hits the cache only;
    /// fails if the cache doesn't have it.
    Hash(BlobHash),
}

impl BlobSource {
    /// Parse a CLI `<source>` argument:
    /// - `ipfs:<cid>` or `Qm…` / `bafy…` → `Cid`
    /// - `https://…` / `http://…` → `Url`
    /// - 64 hex chars → `Hash`
    /// - anything else → `Path`
    pub fn parse(s: &str) -> Self {
        if let Some(cid) = s.strip_prefix("ipfs:") {
            return BlobSource::Cid(cid.to_string());
        }
        if s.starts_with("Qm") || s.starts_with("bafy") || s.starts_with("bafk") {
            return BlobSource::Cid(s.to_string());
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            return BlobSource::Url(s.to_string());
        }
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(h) = BlobHash::from_hex(s) {
                return BlobSource::Hash(h);
            }
        }
        BlobSource::Path(PathBuf::from(s))
    }
}

#[derive(Debug)]
pub enum BlobError {
    Io(io::Error),
    NotInCache(BlobHash),
    HashMismatch { expected: BlobHash, actual: BlobHash },
    BadHashHex,
    NetworkSourceUnsupported,
}

impl core::fmt::Display for BlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlobError::Io(e) => write!(f, "blob i/o: {e}"),
            BlobError::NotInCache(h) => write!(f, "blob {h} not in local cache"),
            BlobError::HashMismatch { expected, actual } => {
                write!(f, "blob hash mismatch: expected {expected}, got {actual}")
            }
            BlobError::BadHashHex => write!(f, "blob hash must be 64 hex chars"),
            BlobError::NetworkSourceUnsupported => {
                write!(f, "network blob sources (cid / url) are not yet implemented")
            }
        }
    }
}

impl std::error::Error for BlobError {}

impl From<io::Error> for BlobError {
    fn from(e: io::Error) -> Self {
        BlobError::Io(e)
    }
}

/// Resolve the cache directory: `$XDG_CACHE_HOME/vosx/blobs` or
/// `~/.cache/vosx/blobs`.
pub fn cache_dir() -> PathBuf {
    crate::paths::blob_cache_dir()
}

/// Path inside the cache for a given hash.
pub fn cache_path_for(hash: &BlobHash) -> PathBuf {
    cache_dir().join(hash.to_hex())
}

/// Resolve `source` to `(hash, bytes)`. Side effect: bytes are
/// written into the local cache so future `Hash` lookups hit
/// without re-resolving.
pub fn resolve(source: &BlobSource) -> Result<(BlobHash, Vec<u8>), BlobError> {
    let bytes = read_source(source)?;
    let hash = BlobHash::of(&bytes);

    if let BlobSource::Hash(expected) = source
        && hash != *expected
    {
        return Err(BlobError::HashMismatch {
            expected: *expected,
            actual: hash,
        });
    }

    write_to_cache(&hash, &bytes)?;
    Ok((hash, bytes))
}

fn read_source(source: &BlobSource) -> Result<Vec<u8>, BlobError> {
    match source {
        BlobSource::Path(p) => Ok(fs::read(p)?),
        BlobSource::Hash(h) => {
            let p = cache_path_for(h);
            match fs::read(&p) {
                Ok(b) => Ok(b),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Err(BlobError::NotInCache(*h)),
                Err(e) => Err(BlobError::Io(e)),
            }
        }
        BlobSource::Cid(_) | BlobSource::Url(_) => Err(BlobError::NetworkSourceUnsupported),
    }
}

fn write_to_cache(hash: &BlobHash, bytes: &[u8]) -> Result<(), BlobError> {
    let dir = cache_dir();
    fs::create_dir_all(&dir)?;
    let p = dir.join(hash.to_hex());
    if p.exists() {
        return Ok(());
    }
    // Atomic-ish: write to a temp file in the same directory,
    // then rename. Same-fs rename is atomic on POSIX so partial
    // bytes never appear under the canonical name.
    let tmp = dir.join(format!("{}.tmp", hash.to_hex()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, &p)?;
    Ok(())
}

/// Direct cache-only lookup for callers that already know the
/// hash and don't want to engage the resolver. Returns `None`
/// when the cache miss; the caller can then ask peers / fall
/// back to a `BlobSource`.
pub fn cache_get(hash: &BlobHash) -> Result<Option<Vec<u8>>, BlobError> {
    let p = cache_path_for(hash);
    match fs::read(&p) {
        Ok(b) => {
            // Defensive re-hash so a corrupted cache file fails
            // loud instead of getting handed to the PVM.
            let actual = BlobHash::of(&b);
            if actual != *hash {
                return Err(BlobError::HashMismatch {
                    expected: *hash,
                    actual,
                });
            }
            Ok(Some(b))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(BlobError::Io(e)),
    }
}

/// Insert raw bytes into the cache, returning their hash. Used
/// when the caller already has the bytes in hand (e.g. fetched
/// from a peer over libp2p) and wants them durable for future
/// lookups.
pub fn cache_put(bytes: &[u8]) -> Result<BlobHash, BlobError> {
    let h = BlobHash::of(bytes);
    write_to_cache(&h, bytes)?;
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests cache-mutating paths against an isolated cache dir.
    /// `XDG_CACHE_HOME` is process-global state, so the tests
    /// share a mutex to avoid stomping on each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_isolated_cache<R>(f: impl FnOnce(&std::path::Path) -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "vosx-blob-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let prev = std::env::var_os("XDG_CACHE_HOME");
        // SAFETY: tests serialize on ENV_LOCK above.
        unsafe { std::env::set_var("XDG_CACHE_HOME", &tmp); }
        let out = f(&tmp);
        match prev {
            Some(v) => unsafe { std::env::set_var("XDG_CACHE_HOME", v); },
            None => unsafe { std::env::remove_var("XDG_CACHE_HOME"); },
        }
        let _ = std::fs::remove_dir_all(&tmp);
        out
    }

    #[test]
    fn parse_source_dispatches_on_shape() {
        match BlobSource::parse("https://example.com/foo.elf") {
            BlobSource::Url(u) => assert_eq!(u, "https://example.com/foo.elf"),
            other => panic!("expected Url, got {other:?}"),
        }
        match BlobSource::parse("ipfs:bafyabc") {
            BlobSource::Cid(c) => assert_eq!(c, "bafyabc"),
            other => panic!("expected Cid, got {other:?}"),
        }
        match BlobSource::parse("Qmaaa") {
            BlobSource::Cid(c) => assert_eq!(c, "Qmaaa"),
            other => panic!("expected Cid, got {other:?}"),
        }
        // 64 hex chars → Hash
        let hash_str = "00".repeat(32);
        match BlobSource::parse(&hash_str) {
            BlobSource::Hash(h) => assert_eq!(h.to_hex(), hash_str),
            other => panic!("expected Hash, got {other:?}"),
        }
        match BlobSource::parse("./local/file.elf") {
            BlobSource::Path(p) => assert_eq!(p, PathBuf::from("./local/file.elf")),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn hash_roundtrips_through_hex() {
        let bytes = b"hello, blob";
        let h = BlobHash::of(bytes);
        let s = h.to_hex();
        let back = BlobHash::from_hex(&s).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn resolve_path_caches_and_then_hash_resolves_from_cache() {
        with_isolated_cache(|_| {
            let tmp = std::env::temp_dir().join(format!(
                "vosx-blob-input-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::write(&tmp, b"my actor bytes").unwrap();

            let (h1, b1) = resolve(&BlobSource::Path(tmp.clone())).expect("resolve path");
            assert_eq!(b1, b"my actor bytes");
            assert!(cache_path_for(&h1).exists(), "cache file written");

            // Delete the input file — Hash lookup must still work.
            std::fs::remove_file(&tmp).unwrap();
            let (h2, b2) = resolve(&BlobSource::Hash(h1)).expect("resolve hash");
            assert_eq!(h1, h2);
            assert_eq!(b1, b2);
        });
    }

    #[test]
    fn resolve_hash_misses_when_not_cached() {
        with_isolated_cache(|_| {
            let h = BlobHash::of(b"never seen");
            match resolve(&BlobSource::Hash(h)) {
                Err(BlobError::NotInCache(missing)) => assert_eq!(missing, h),
                other => panic!("expected NotInCache, got {other:?}"),
            }
        });
    }

    #[test]
    fn cache_put_then_get_roundtrip() {
        with_isolated_cache(|_| {
            let bytes = b"abc";
            let h = cache_put(bytes).unwrap();
            let read_back = cache_get(&h).unwrap();
            assert_eq!(read_back.as_deref(), Some(&bytes[..]));
        });
    }

    #[test]
    fn cache_get_detects_corruption() {
        with_isolated_cache(|_| {
            let bytes = b"the truth";
            let h = cache_put(bytes).unwrap();
            // Corrupt the cache file under the canonical name.
            std::fs::write(cache_path_for(&h), b"a lie").unwrap();
            match cache_get(&h) {
                Err(BlobError::HashMismatch { .. }) => {}
                other => panic!("expected HashMismatch, got {other:?}"),
            }
        });
    }
}
