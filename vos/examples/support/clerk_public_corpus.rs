//! Private, bounded business-corpus inputs and independent six-map reference.
//! No identity key file or Authority implementation is used here.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

use cipher_clerk::helpers::{MemLedger, MemOracle};
use cipher_clerk::merkle::{SMT_DEPTH, build_empty_chain, smt_leaf_hash};
use cipher_clerk::prelude::*;
use cipher_clerk::state::Opening;
use cipher_clerk::state_root::*;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const MAX_PART: usize = 64 * 1024;
pub const MAX_STREAM: u64 = 256 * 1024 * 1024;
pub const MAX_ACCOUNTS: u32 = 1_000;
pub const MAX_TRANSFERS: u32 = 100_000;

pub fn require(value: bool, message: &'static str) -> Result<()> {
    if !value {
        return Err(io::Error::other(message).into());
    }
    Ok(())
}

pub fn id<const N: usize>(value: &str) -> Result<[u8; N]> {
    require(
        value.len() == N * 2
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "noncanonical identifier",
    )?;
    Ok(unhex(value)?
        .try_into()
        .map_err(|_| io::Error::other("identifier length"))?)
}

pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

pub fn unhex(value: &str) -> Result<Vec<u8>> {
    require(
        value.len() % 2 == 0
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "noncanonical byte encoding",
    )?;
    fn digit(byte: u8) -> u8 {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| digit(bytes[0]) * 16 + digit(bytes[1]))
        .collect())
}

pub fn directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && path.canonicalize()? == path
            && metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o700,
        "directory must be canonical, owned and private",
    )?;
    let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(name.as_ptr(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    require(
        !matches!(
            unsafe { filesystem.assume_init() }.f_type as u64,
            0x0102_1994 | 0x8584_58f6
        ),
        "evidence must be disk-backed",
    )
}

pub fn open(path: &Path, maximum: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    require(
        metadata.is_file()
            && metadata.len() <= maximum
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "input must be an owned, bounded private regular file",
    )?;
    Ok(file)
}

pub fn bytes(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open(path, maximum)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= maximum, "file exceeded bound")?;
    Ok(bytes)
}

pub fn digest(bytes: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(bytes)
        .to_hex()
        .to_string()
}

pub fn file_digest(path: &Path, maximum: u64) -> Result<(u64, String)> {
    let mut file = open(path, maximum)?;
    let mut hash = blake2b_simd::Params::new().hash_length(32).to_state();
    let mut count = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        require(count <= maximum, "stream exceeded bound")?;
        hash.update(&buffer[..read]);
    }
    Ok((count, hash.finalize().to_hex().to_string()))
}

/// Publish one immutable tool record. A failed partial staging file is inert;
/// the canonical name is created atomically and never replaced.
pub fn publish(path: &Path, content: &[u8]) -> Result<()> {
    if path.try_exists()? {
        require(
            bytes(path, content.len() as u64)? == content,
            "existing evidence differs",
        )?;
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    let mut random = [0; 16];
    getrandom::getrandom(&mut random).map_err(|_| io::Error::other("evidence nonce entropy"))?;
    let stage = parent.join(format!(".partial-{}", hex(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&stage)?;
    file.write_all(content)?;
    file.sync_all()?;
    fs::hard_link(&stage, path)?;
    File::open(parent)?.sync_all()?;
    fs::remove_file(&stage)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Freeze only the signed business streams. The manifest catalogs secrets,
/// but neither keys.private nor offline account snapshots are opened/copied.
pub fn freeze_stream(source: &Path, destination: &Path, size: u64, expected: &str) -> Result<()> {
    require(size <= MAX_STREAM, "frozen corpus stream exceeds bound")?;
    if !destination.try_exists()? {
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("missing stream parent"))?;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|_| io::Error::other("stream nonce entropy"))?;
        let stage = parent.join(format!(".partial-stream-{}", hex(random)));
        let input = open(source, MAX_STREAM)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&stage)?;
        let copied = io::copy(&mut input.take(size + 1), &mut output)?;
        require(copied == size, "source stream changed while freezing")?;
        output.sync_all()?;
        require(
            file_digest(&stage, MAX_STREAM)? == (size, expected.to_string()),
            "source stream digest changed while freezing",
        )?;
        fs::hard_link(&stage, destination)?;
        File::open(parent)?.sync_all()?;
        fs::remove_file(stage)?;
        File::open(parent)?.sync_all()?;
    }
    require(
        file_digest(destination, MAX_STREAM)? == (size, expected.to_string()),
        "frozen stream differs",
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReport {
    pub file: String,
    pub records: u32,
    pub bytes: u64,
    pub blake2b_256: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Roots {
    pub accounts: String,
    pub transfers: String,
    pub journals: String,
    pub external_ids: String,
    pub voided: String,
    pub pending: String,
    pub composite: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub smoke_only: bool,
    pub reference_only: bool,
    pub public_replay_requires_actual_acceptance_context: bool,
    pub reference_order: String,
    pub account_reference_timestamp_start: u64,
    pub transfer_reference_timestamp_start: u64,
    pub contains_private_business_keys: bool,
    pub authority_authorizations_generated: bool,
    pub journal_id: String,
    pub registrar_public_key: String,
    pub journal_code: u16,
    pub account_count: u32,
    pub transfer_count: u32,
    pub external_id_count: u32,
    pub voided_count: u32,
    pub pending_count: u32,
    pub signature_count_verified: u32,
    pub roots: Roots,
    pub files: Vec<FileReport>,
}

impl Manifest {
    pub fn read(root: &Path) -> Result<(Self, String)> {
        directory(root)?;
        let raw = bytes(&root.join("manifest.toml"), 16 * 1024)?;
        let manifest: Self = toml::from_str(std::str::from_utf8(&raw)?)?;
        require(
            manifest.format == "VOS-CLERK-CORPUS-1"
                && manifest.reference_only
                && manifest.public_replay_requires_actual_acceptance_context
                && !manifest.authority_authorizations_generated
                && manifest.contains_private_business_keys
                && manifest.reference_order == "creates_stream_then_transfers_stream_record_order"
                && (2..=MAX_ACCOUNTS).contains(&manifest.account_count)
                && manifest.account_count % 2 == 0
                && (1..=MAX_TRANSFERS).contains(&manifest.transfer_count)
                && manifest.external_id_count == manifest.transfer_count
                && manifest.voided_count == 0
                && manifest.pending_count == 0
                && manifest.signature_count_verified
                    == manifest.account_count + manifest.transfer_count
                && manifest.smoke_only
                    == (manifest.account_count != MAX_ACCOUNTS
                        || manifest.transfer_count != MAX_TRANSFERS),
            "unsupported corpus manifest",
        )?;
        require(manifest.files.len() == 4, "unexpected corpus file catalog")?;
        require(
            manifest.account_reference_timestamp_start == 500_000
                && manifest.transfer_reference_timestamp_start == 1_000_000,
            "unsupported reference timestamp context",
        )?;
        for name in [
            "creates.corpus",
            "transfers.corpus",
            "accounts.reference",
            "keys.private",
        ] {
            require(
                manifest
                    .files
                    .iter()
                    .filter(|file| file.file == name)
                    .count()
                    == 1,
                "noncanonical corpus file catalog",
            )?;
        }
        id::<16>(&manifest.journal_id)?;
        id::<32>(&manifest.registrar_public_key)?;
        for value in [
            &manifest.roots.accounts,
            &manifest.roots.transfers,
            &manifest.roots.journals,
            &manifest.roots.external_ids,
            &manifest.roots.voided,
            &manifest.roots.pending,
            &manifest.roots.composite,
        ] {
            id::<32>(value)?;
        }
        Ok((manifest, digest(&raw)))
    }

    pub fn stream(&self, root: &Path, name: &str, magic: &[u8; 4], count: u32) -> Result<Stream> {
        let report = self
            .files
            .iter()
            .find(|file| file.file == name)
            .ok_or_else(|| io::Error::other("missing stream"))?;
        require(
            report.records == count && report.bytes <= MAX_STREAM,
            "stream count/size differs",
        )?;
        let (size, hash) = file_digest(&root.join(name), MAX_STREAM)?;
        require(
            size == report.bytes && hash == report.blake2b_256,
            "stream digest differs",
        )?;
        Stream::new(open(&root.join(name), MAX_STREAM)?, magic, count)
    }
}

pub struct Record {
    pub reference_timestamp: u64,
    pub parts: Vec<Vec<u8>>,
}
pub struct Stream {
    file: File,
    remaining: u32,
    consumed: u64,
}

impl Stream {
    fn new(mut file: File, magic: &[u8; 4], expected: u32) -> Result<Self> {
        let mut header = [0; 8];
        file.read_exact(&mut header)?;
        require(
            &header[..4] == magic && u32::from_le_bytes(header[4..].try_into()?) == expected,
            "stream header differs",
        )?;
        Ok(Self {
            file,
            remaining: expected,
            consumed: 8,
        })
    }
    pub fn next(&mut self, parts: u8) -> Result<Option<Record>> {
        if self.remaining == 0 {
            require(self.file.read(&mut [0])? == 0, "trailing stream bytes")?;
            return Ok(None);
        }
        let mut header = [0; 9];
        self.file.read_exact(&mut header)?;
        require(header[8] == parts, "stream part count differs")?;
        self.consumed += 9;
        let mut output = Vec::new();
        for _ in 0..parts {
            let mut length = [0; 4];
            self.file.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            require(
                (1..=MAX_PART).contains(&length),
                "stream part exceeds bound",
            )?;
            self.consumed += 4 + length as u64;
            require(self.consumed <= MAX_STREAM, "stream exceeds bound")?;
            let mut data = vec![0; length];
            self.file.read_exact(&mut data)?;
            output.push(data);
        }
        self.remaining -= 1;
        Ok(Some(Record {
            reference_timestamp: u64::from_le_bytes(header[..8].try_into()?),
            parts: output,
        }))
    }
}

pub fn reference(manifest: &Manifest) -> Result<MemLedger> {
    let mut ledger = MemLedger::new();
    let journal = Journal::new(
        JournalId(id(&manifest.journal_id)?),
        AuthKey(id(&manifest.registrar_public_key)?),
        manifest.journal_code,
    );
    ledger
        .journals_smt
        .insert(journal.id.0, &journal_leaf_content(&journal));
    ledger.journals.insert(journal.id.0, journal);
    Ok(ledger)
}

pub fn apply_create(
    ledger: &mut MemLedger,
    raw: &[u8],
    seed: u64,
    registrar: AuthKey,
) -> Result<()> {
    let event = vos::rkyv::from_bytes::<CreateAccount, vos::rkyv::rancor::Error>(raw)
        .map_err(|_| io::Error::other("invalid signed account encoding"))?;
    require(
        cipher_clerk::crypto::verify_signature(
            &registrar,
            &event.account.signing_payload(),
            &event.signature,
        ),
        "account signature refused",
    )?;
    let result =
        cipher_clerk::apply_account_creations(ledger, &[event], &mut MemOracle::new(), seed);
    require(
        result.len() == 1
            && result[0].status == EventStatus::Created
            && result[0].timestamp == seed,
        "reference account refused",
    )
}

pub fn apply_transfer(
    ledger: &mut MemLedger,
    raw: &[u8],
    raw_openings: &[u8],
    seed: u64,
) -> Result<()> {
    let event = vos::rkyv::from_bytes::<Transfer, vos::rkyv::rancor::Error>(raw)
        .map_err(|_| io::Error::other("invalid signed transfer encoding"))?;
    let openings = vos::rkyv::from_bytes::<Vec<Opening>, vos::rkyv::rancor::Error>(raw_openings)
        .map_err(|_| io::Error::other("invalid openings encoding"))?;
    require(
        event.entries.len() == 2
            && event.signatures.len() == 1
            && event.timestamp == 0
            && event.entries[0].direction == Direction::Debit,
        "unsupported corpus transfer shape",
    )?;
    let debit = ledger
        .accounts
        .get(&event.entries[0].account_id.0)
        .ok_or_else(|| io::Error::other("unknown debit account"))?;
    require(
        cipher_clerk::crypto::verify_signature(
            &debit.auth_key,
            &event.signing_payload(),
            &event.signatures[0],
        ),
        "transfer signature refused",
    )?;
    let mut oracle = MemOracle::new();
    for opening in openings {
        oracle.record(opening.amount, opening.value, opening.blinding);
    }
    let result = cipher_clerk::apply_batch(ledger, &[event], &mut oracle, seed);
    require(
        result.len() == 1
            && result[0].status == EventStatus::Created
            && result[0].timestamp == seed,
        "reference transfer refused",
    )
}

fn subtree(rows: impl Iterator<Item = ([u8; 16], Vec<u8>)>) -> Result<[u8; 32]> {
    let mut leaves = Vec::new();
    for (key, bytes) in rows {
        require(
            leaves.len() < MAX_TRANSFERS as usize,
            "reference subtree exceeds bound",
        )?;
        leaves.push((key, smt_leaf_hash(&bytes)));
    }
    leaves.sort_unstable_by_key(|leaf| leaf.0);
    require(
        leaves.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "duplicate subtree key",
    )?;
    Ok(sparse_root_sorted(
        &leaves,
        0,
        SMT_DEPTH,
        &build_empty_chain(),
    ))
}

pub fn roots(ledger: &MemLedger) -> Result<Roots> {
    let accounts = subtree(
        ledger
            .accounts
            .iter()
            .map(|(id, row)| (*id, account_leaf_content(row))),
    )?;
    let transfers = subtree(
        ledger
            .transfers
            .iter()
            .map(|(id, row)| (*id, transfer_leaf_content(row))),
    )?;
    let journals = subtree(
        ledger
            .journals
            .iter()
            .map(|(id, row)| (*id, journal_leaf_content(row))),
    )?;
    let external_ids = subtree(
        ledger
            .external_ids
            .iter()
            .map(|id| (external_id_key(id), external_id_leaf_content(id))),
    )?;
    let voided = subtree(
        ledger
            .voided
            .iter()
            .map(|id| (*id, voided_leaf_content(id))),
    )?;
    let pending = subtree(
        ledger
            .pending_statuses
            .iter()
            .map(|(id, status)| (*id, pending_leaf_content(id, status.code()))),
    )?;
    let composite = composite_root_from_subroots(
        &accounts,
        &transfers,
        &journals,
        &external_ids,
        &voided,
        &pending,
    );
    Ok(Roots {
        accounts: hex(accounts),
        transfers: hex(transfers),
        journals: hex(journals),
        external_ids: hex(external_ids),
        voided: hex(voided),
        pending: hex(pending),
        composite: hex(composite),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt as _;

    fn private_root() -> std::path::PathBuf {
        // Explicit disk root, never the ambient RAM-backed /tmp fallback.
        let base = std::path::PathBuf::from(
            std::env::var_os("JUST_TEMPDIR").expect("JUST_TEMPDIR must name the disk test root"),
        )
        .canonicalize()
        .unwrap();
        let root = base.join(format!(
            "public-corpus-parser-{}",
            hex(JournalId::random().0)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        directory(&root).unwrap();
        root
    }

    fn record(timestamp: u64, parts: &[&[u8]]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&timestamp.to_le_bytes());
        raw.push(parts.len() as u8);
        for part in parts {
            raw.extend_from_slice(&(part.len() as u32).to_le_bytes());
            raw.extend_from_slice(part);
        }
        raw
    }

    fn stream_file(root: &Path, name: &str, raw: &[u8]) -> File {
        publish(&root.join(name), raw).unwrap();
        open(&root.join(name), MAX_STREAM).unwrap()
    }

    #[test]
    fn bounded_stream_refuses_header_parts_length_truncation_and_trailing_data() {
        let root = private_root();
        let header = [b"CCA1".as_slice(), &1u32.to_le_bytes()].concat();
        let valid = [header.as_slice(), record(500_000, &[b"archive"]).as_slice()].concat();
        let mut stream = Stream::new(stream_file(&root, "valid", &valid), b"CCA1", 1).unwrap();
        let decoded = stream.next(1).unwrap().unwrap();
        assert_eq!(decoded.reference_timestamp, 500_000);
        assert_eq!(decoded.parts, vec![b"archive".to_vec()]);
        assert!(stream.next(1).unwrap().is_none());
        assert!(Stream::new(stream_file(&root, "magic", &valid), b"CCT1", 1).is_err());
        assert!(Stream::new(stream_file(&root, "count", &valid), b"CCA1", 2).is_err());
        let mut stream = Stream::new(stream_file(&root, "parts", &valid), b"CCA1", 1).unwrap();
        assert!(stream.next(2).is_err());
        let oversized = [
            header.as_slice(),
            &0u64.to_le_bytes(),
            &[1],
            &((MAX_PART + 1) as u32).to_le_bytes(),
        ]
        .concat();
        let mut stream =
            Stream::new(stream_file(&root, "oversized", &oversized), b"CCA1", 1).unwrap();
        assert!(stream.next(1).is_err());
        let mut stream = Stream::new(
            stream_file(&root, "truncated", &valid[..valid.len() - 1]),
            b"CCA1",
            1,
        )
        .unwrap();
        assert!(stream.next(1).is_err());
        let trailing = [valid.as_slice(), &[0]].concat();
        let mut stream =
            Stream::new(stream_file(&root, "trailing", &trailing), b"CCA1", 1).unwrap();
        assert!(stream.next(1).unwrap().is_some());
        assert!(stream.next(1).is_err());
    }

    #[test]
    fn immutable_publication_compares_exact_record_and_private_modes() {
        let root = private_root();
        let path = root.join("accepted.json");
        publish(&path, b"retained").unwrap();
        publish(&path, b"retained").unwrap();
        assert!(publish(&path, b"different").is_err());
        assert_eq!(bytes(&path, 8).unwrap(), b"retained");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(
            fs::read_dir(root)
                .unwrap()
                .all(|entry| entry.unwrap().file_name() == "accepted.json")
        );
    }

    #[test]
    fn frozen_stream_keeps_exact_digest_after_source_changes_and_refuses_wrong_input() {
        let root = private_root();
        let source = root.join("source");
        publish(&source, b"original-signed-business-stream").unwrap();
        let expected = digest(b"original-signed-business-stream");
        let frozen = root.join("frozen");
        freeze_stream(&source, &frozen, 31, &expected).unwrap();
        fs::write(&source, b"changed source").unwrap();
        freeze_stream(&source, &frozen, 31, &expected).unwrap();
        assert_eq!(
            bytes(&frozen, 31).unwrap(),
            b"original-signed-business-stream"
        );
        assert!(freeze_stream(&source, &root.join("new"), 31, &expected).is_err());
        assert!(!root.join("new").exists());
        assert!(freeze_stream(&frozen, &root.join("wrong-digest"), 31, &hex([0; 32])).is_err());
        assert!(!root.join("wrong-digest").exists());
        assert!(open(&frozen, 30).is_err());
    }

    #[test]
    fn independent_replay_uses_accepted_business_seeds_and_all_six_maps() {
        let registrar = Keypair::generate();
        let journal = Journal::new(JournalId::random(), registrar.public, 1);
        let debit_key = Keypair::generate();
        let credit_key = Keypair::generate();
        let debit = Account::new(
            AccountId::random(),
            journal.id,
            debit_key.public,
            840,
            100,
            Direction::Debit,
        );
        let credit = Account::new(
            AccountId::random(),
            journal.id,
            credit_key.public,
            840,
            101,
            Direction::Credit,
        );
        let create_debit = CreateAccount::signed(debit.clone(), &registrar.secret);
        let create_credit = CreateAccount::signed(credit.clone(), &registrar.secret);
        let debit_raw = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_debit).unwrap();
        let credit_raw = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create_credit).unwrap();
        let mut oracle = MemOracle::new();
        let amount = oracle.commit(17);
        let (value, blinding) = oracle.openings[&amount.0];
        let openings = vec![Opening {
            amount,
            value,
            blinding,
        }];
        let transfer = Transfer::builder(journal.id)
            .id(TransferId::random())
            .external_id(ExternalId::random())
            .debit(&debit, Layer::Settled, amount)
            .credit(&credit, Layer::Settled, amount)
            .try_signed_with(&[(&debit, &debit_key.secret)])
            .unwrap();
        let transfer_raw = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&transfer).unwrap();
        let openings_raw = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings).unwrap();
        let mut ledgers = [MemLedger::new(), MemLedger::new()];
        for (index, ledger) in ledgers.iter_mut().enumerate() {
            ledger
                .journals_smt
                .insert(journal.id.0, &journal_leaf_content(&journal));
            ledger.journals.insert(journal.id.0, journal.clone());
            let start = [500_000, 10_000_000][index];
            apply_create(ledger, &debit_raw, start, registrar.public).unwrap();
            apply_create(ledger, &credit_raw, start + 1, registrar.public).unwrap();
            apply_transfer(ledger, &transfer_raw, &openings_raw, start + 2).unwrap();
            assert_eq!(ledger.transfers[&transfer.id.0].timestamp, start + 2);
            assert_eq!(
                (
                    ledger.accounts.len(),
                    ledger.transfers.len(),
                    ledger.external_ids.len()
                ),
                (2, 1, 1)
            );
        }
        let synthetic = roots(&ledgers[0]).unwrap();
        let accepted = roots(&ledgers[1]).unwrap();
        assert_ne!(synthetic.accounts, accepted.accounts);
        assert_ne!(synthetic.transfers, accepted.transfers);
        assert_ne!(synthetic.composite, accepted.composite);
        assert_eq!(synthetic.journals, accepted.journals);
        assert_eq!(synthetic.external_ids, accepted.external_ids);
        assert_eq!(synthetic.voided, accepted.voided);
        assert_eq!(synthetic.pending, accepted.pending);
        // MemLedger::root covers only the primary three maps. This independent
        // composite must commit external-id bookkeeping as a fourth map too.
        ledgers[1].external_ids.clear();
        let missing_auxiliary = roots(&ledgers[1]).unwrap();
        assert_eq!(accepted.accounts, missing_auxiliary.accounts);
        assert_ne!(accepted.external_ids, missing_auxiliary.external_ids);
        assert_ne!(accepted.composite, missing_auxiliary.composite);
        let mut invalid = create_debit;
        invalid.signature = Signature::ZERO;
        let raw = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&invalid).unwrap();
        assert!(apply_create(&mut ledgers[1], &raw, 10_000_003, registrar.public).is_err());
    }
}
