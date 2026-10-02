//! Offline, genuinely signed Clerk business corpus and reference kernel state.
//!
//! `cargo run --release -p vos --example clerk_corpus -- --out <absolute-new-dir>`
//! defaults to exactly 1,000 accounts and 100,000 retained settled transfers.
//! Smaller `--accounts`/`--transfers` values are smoke fixtures, not qualification.
//! The existing parent must be canonical, owner-only and disk-backed. All output
//! files are private: openings are confidential and `keys.private` contains only
//! freshly generated business signing keys, NOT Root/API/node credentials.
//!
//! Four streams have a 4-byte kind/version followed by a little-endian u32 count.
//! Each record is timestamp:u64, parts:u8, then (length:u32, bytes) per part:
//! CCA1=(signed CreateAccount); CCT1=(signed Transfer, Vec<Opening>);
//! CCR1=(final Account); CCK1=(account id, public key, secret scalar).
//! The registrar has zero account id in CCK1. Business payloads use exactly the
//! fixture's rkyv encoding; framing is offline tooling, never an Agent ABI.
//! `manifest.toml` is published last and binds counts, byte lengths and BLAKE2b-256
//! digests, reference order and synthetic timestamps. Its account rows/roots are
//! OFFLINE reference state only: a public loader must replay the actual accepted
//! timestamps and order to derive the live expected root. Failed output is
//! retained without replacement; do not reuse its keys
//! as customer credentials. This does not exercise any guest or public API and
//! cannot qualify storage capacity, hardware, latency, recovery or load/soak.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Component, Path, PathBuf};

    use cipher_clerk::crypto::verify_signature;
    use cipher_clerk::helpers::{MemLedger, MemOracle};
    use cipher_clerk::merkle::{SMT_DEPTH, build_empty_chain, smt_leaf_hash};
    use cipher_clerk::prelude::*;
    use cipher_clerk::state::Opening;
    use cipher_clerk::state_root::{
        account_leaf_content, composite_root_from_subroots, external_id_key,
        external_id_leaf_content, journal_leaf_content, pending_leaf_content, sparse_root_sorted,
        transfer_leaf_content, voided_leaf_content,
    };
    use clap::Parser as _;
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroizing;

    const DEFAULT_ACCOUNTS: u32 = 1_000;
    const DEFAULT_TRANSFERS: u32 = 100_000;
    const MAX_PART_BYTES: usize = 64 * 1024;
    const MAX_STREAM_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_MANIFEST_BYTES: usize = 16 * 1024;
    const ACCOUNT_REFERENCE_TIMESTAMP_START: u64 = 500_000;
    const TRANSFER_REFERENCE_TIMESTAMP_START: u64 = 1_000_000;
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[derive(clap::Parser)]
    pub(super) struct Options {
        /// Fresh absolute output under an existing private disk directory.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = DEFAULT_ACCOUNTS)]
        accounts: u32,
        #[arg(long, default_value_t = DEFAULT_TRANSFERS)]
        transfers: u32,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FileReport {
        file: String,
        records: u32,
        bytes: u64,
        blake2b_256: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Roots {
        accounts: String,
        transfers: String,
        journals: String,
        external_ids: String,
        voided: String,
        pending: String,
        composite: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        format: String,
        smoke_only: bool,
        reference_only: bool,
        public_replay_requires_actual_acceptance_context: bool,
        reference_order: String,
        account_reference_timestamp_start: u64,
        transfer_reference_timestamp_start: u64,
        contains_private_business_keys: bool,
        authority_authorizations_generated: bool,
        journal_id: String,
        registrar_public_key: String,
        journal_code: u16,
        account_count: u32,
        transfer_count: u32,
        external_id_count: u32,
        voided_count: u32,
        pending_count: u32,
        signature_count_verified: u32,
        roots: Roots,
        files: Vec<FileReport>,
    }

    struct Stream {
        file: File,
        name: &'static str,
        digest: blake2b_simd::State,
        bytes: u64,
        records: u32,
        expected_records: u32,
    }

    impl Stream {
        fn create(root: &Path, name: &'static str, magic: &[u8; 4], count: u32) -> Result<Self> {
            let mut stream = Self {
                file: private_file(&root.join(name))?,
                name,
                digest: blake2b_simd::Params::new().hash_length(32).to_state(),
                bytes: 0,
                records: 0,
                expected_records: count,
            };
            stream.write(magic)?;
            stream.write(&count.to_le_bytes())?;
            Ok(stream)
        }

        fn write(&mut self, bytes: &[u8]) -> Result<()> {
            let next = self
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::other("stream length overflow"))?;
            require(next <= MAX_STREAM_BYTES, "stream exceeds fixed byte bound")?;
            self.file.write_all(bytes)?;
            self.digest.update(bytes);
            self.bytes = next;
            Ok(())
        }

        fn record(&mut self, timestamp: u64, parts: &[&[u8]]) -> Result<()> {
            require(
                self.records < self.expected_records,
                "surplus stream record",
            )?;
            require((1..=3).contains(&parts.len()), "invalid stream part count")?;
            require(
                parts
                    .iter()
                    .all(|part| !part.is_empty() && part.len() <= MAX_PART_BYTES),
                "invalid stream part length",
            )?;
            self.write(&timestamp.to_le_bytes())?;
            self.write(&[parts.len() as u8])?;
            for part in parts {
                self.write(&(part.len() as u32).to_le_bytes())?;
                self.write(part)?;
            }
            self.records += 1;
            Ok(())
        }

        fn finish(self) -> Result<FileReport> {
            require(
                self.records == self.expected_records,
                "missing stream records",
            )?;
            self.file.sync_all()?;
            Ok(FileReport {
                file: self.name.into(),
                records: self.records,
                bytes: self.bytes,
                blake2b_256: hex(self.digest.finalize().as_bytes()),
            })
        }
    }

    fn require(condition: bool, message: &'static str) -> Result<()> {
        if !condition {
            return Err(io::Error::other(message).into());
        }
        Ok(())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn private_file(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?)
    }

    fn validate_options(options: &Options) -> Result<()> {
        require(
            (2..=DEFAULT_ACCOUNTS).contains(&options.accounts) && options.accounts % 2 == 0,
            "accounts must be even and between 2 and 1000",
        )?;
        require(
            (1..=DEFAULT_TRANSFERS).contains(&options.transfers),
            "transfers must be between 1 and 100000",
        )?;
        require(
            options.out.is_absolute()
                && options
                    .out
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "output must be an absolute non-aliased path",
        )
    }

    fn prepare_output(options: &Options) -> Result<File> {
        validate_options(options)?;
        let parent = options
            .out
            .parent()
            .ok_or_else(|| io::Error::other("output has no parent"))?;
        let metadata = fs::symlink_metadata(parent)?;
        require(
            parent.canonicalize()? == parent
                && metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o700,
            "output parent must be canonical, owned and mode 0700",
        )?;
        let path = CString::new(parent.as_os_str().as_bytes())?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::statfs(path.as_ptr(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let filesystem = unsafe { filesystem.assume_init() };
        require(
            !matches!(filesystem.f_type as u64, 0x0102_1994 | 0x8584_58f6),
            "corpus output must be disk-backed, not tmpfs/ramfs",
        )?;
        fs::DirBuilder::new().mode(0o700).create(&options.out)?;
        File::open(parent)?.sync_all()?;
        Ok(File::open(&options.out)?)
    }

    fn write_key(stream: &mut Stream, id: AccountId, key: &Keypair) -> Result<()> {
        // File writes are unbuffered; no plaintext secret is left in a BufWriter.
        let bytes = Zeroizing::new(key.secret.to_bytes());
        stream.record(0, &[&id.0, &key.public.0, &bytes[..]])
    }

    fn verify_create(create: &CreateAccount, registrar: AuthKey) -> Result<()> {
        require(
            verify_signature(
                &registrar,
                &create.account.signing_payload(),
                &create.signature,
            ),
            "registrar signature verification failed",
        )
    }

    fn verify_transfer(transfer: &Transfer, debit: &Account) -> Result<()> {
        require(
            transfer.entries.len() == 2
                && transfer.signatures.len() == 1
                && transfer.entries[0].account_id == debit.id
                && transfer.entries[0].direction == Direction::Debit,
            "transfer differs from signed two-entry corpus shape",
        )?;
        require(
            verify_signature(
                &debit.auth_key,
                &transfer.signing_payload(),
                &transfer.signatures[0],
            ),
            "debit signature verification failed",
        )
    }

    fn subtree(rows: impl Iterator<Item = ([u8; 16], Vec<u8>)>) -> Result<[u8; 32]> {
        let mut leaves = Vec::new();
        for (key, bytes) in rows {
            require(
                leaves.len() < DEFAULT_TRANSFERS as usize,
                "reference subtree exceeds bound",
            )?;
            leaves.push((key, smt_leaf_hash(&bytes)));
        }
        leaves.sort_unstable_by_key(|leaf| leaf.0);
        require(
            leaves.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "duplicate reference leaf key",
        )?;
        Ok(sparse_root_sorted(
            &leaves,
            0,
            SMT_DEPTH,
            &build_empty_chain(),
        ))
    }

    fn reference_roots(reference: &MemLedger) -> Result<Roots> {
        let accounts = subtree(
            reference
                .accounts
                .iter()
                .map(|(id, row)| (*id, account_leaf_content(row))),
        )?;
        let transfers = subtree(
            reference
                .transfers
                .iter()
                .map(|(id, row)| (*id, transfer_leaf_content(row))),
        )?;
        let journals = subtree(
            reference
                .journals
                .iter()
                .map(|(id, row)| (*id, journal_leaf_content(row))),
        )?;
        let external_ids = subtree(
            reference
                .external_ids
                .iter()
                .map(|id| (external_id_key(id), external_id_leaf_content(id))),
        )?;
        let voided = subtree(
            reference
                .voided
                .iter()
                .map(|id| (*id, voided_leaf_content(id))),
        )?;
        let pending = subtree(
            reference
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
            accounts: hex(&accounts),
            transfers: hex(&transfers),
            journals: hex(&journals),
            external_ids: hex(&external_ids),
            voided: hex(&voided),
            pending: hex(&pending),
            composite: hex(&composite),
        })
    }

    fn publish_manifest(root: &Path, directory: &File, manifest: &Manifest) -> Result<()> {
        let bytes = toml::to_string(manifest)?;
        require(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "manifest exceeds fixed byte bound",
        )?;
        let mut staged = private_file(&root.join("manifest.next"))?;
        staged.write_all(bytes.as_bytes())?;
        staged.sync_all()?;
        directory.sync_all()?;
        // Linux's existing no-clobber primitive keeps an unexpected final
        // manifest untouched. Files/bytes were synchronized before activation.
        let from = CString::new(root.join("manifest.next").as_os_str().as_bytes())?;
        let to = CString::new(root.join("manifest.toml").as_os_str().as_bytes())?;
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        directory.sync_all()?;
        Ok(())
    }

    fn generate(options: &Options) -> Result<Manifest> {
        let directory = prepare_output(options)?;
        let mut creates =
            Stream::create(&options.out, "creates.corpus", b"CCA1", options.accounts)?;
        let mut transfers =
            Stream::create(&options.out, "transfers.corpus", b"CCT1", options.transfers)?;
        let mut expected = Stream::create(
            &options.out,
            "accounts.reference",
            b"CCR1",
            options.accounts,
        )?;
        let mut secrets =
            Stream::create(&options.out, "keys.private", b"CCK1", options.accounts + 1)?;
        let registrar = Keypair::generate();
        write_key(&mut secrets, AccountId::ZERO, &registrar)?;
        let mut reference = MemLedger::new();
        let journal_id = reference.bootstrap_journal(registrar.public, 1);
        let mut oracle = MemOracle::new();
        let mut accounts = Vec::new();
        let mut signature_count_verified = 0;
        for index in 0..options.accounts {
            let key = Keypair::generate();
            let account = Account::new(
                AccountId::random(),
                journal_id,
                key.public,
                840u32,
                (100 + index) as u16,
                if index % 2 == 0 {
                    Direction::Debit
                } else {
                    Direction::Credit
                },
            );
            let create = CreateAccount::signed(account.clone(), &registrar.secret);
            let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&create)
                .map_err(|_| io::Error::other("encode signed account"))?;
            let decoded = vos::rkyv::from_bytes::<CreateAccount, vos::rkyv::rancor::Error>(&bytes)
                .map_err(|_| io::Error::other("decode signed account"))?;
            require(
                decoded == create,
                "account archive roundtrip changed signed data",
            )?;
            verify_create(&decoded, registrar.public)?;
            signature_count_verified += 1;
            let timestamp = ACCOUNT_REFERENCE_TIMESTAMP_START + index as u64;
            let result = cipher_clerk::apply_account_creations(
                &mut reference,
                core::slice::from_ref(&decoded),
                &mut oracle,
                timestamp,
            );
            require(
                result.len() == 1
                    && result[0].status == EventStatus::Created
                    && result[0].timestamp == timestamp,
                "reference account was not accepted exactly",
            )?;
            creates.record(timestamp, &[&bytes])?;
            write_key(&mut secrets, account.id, &key)?;
            accounts.push((account, key));
        }
        for index in 0..options.transfers {
            let pair = (index % (options.accounts / 2)) as usize * 2;
            let (debit, signer) = &accounts[pair];
            let (credit, _) = &accounts[pair + 1];
            let amount = oracle.commit(1 + index as u64 % 97);
            let (value, blinding) = oracle
                .openings
                .get(&amount.0)
                .copied()
                .ok_or_else(|| io::Error::other("missing generated commitment opening"))?;
            let openings = vec![Opening {
                amount,
                value,
                blinding,
            }];
            let transfer = Transfer::builder(journal_id)
                .id(TransferId::random())
                .external_id(ExternalId::random())
                .debit(debit, Layer::Settled, amount)
                .credit(credit, Layer::Settled, amount)
                .try_signed_with(&[(debit, &signer.secret)])
                .map_err(|_| io::Error::other("missing corpus debit signer"))?;
            let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&transfer)
                .map_err(|_| io::Error::other("encode signed transfer"))?;
            let decoded = vos::rkyv::from_bytes::<Transfer, vos::rkyv::rancor::Error>(&bytes)
                .map_err(|_| io::Error::other("decode signed transfer"))?;
            let opening_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&openings)
                .map_err(|_| io::Error::other("encode commitment openings"))?;
            let decoded_openings =
                vos::rkyv::from_bytes::<Vec<Opening>, vos::rkyv::rancor::Error>(&opening_bytes)
                    .map_err(|_| io::Error::other("decode commitment openings"))?;
            require(
                decoded == transfer && decoded_openings == openings && decoded.timestamp == 0,
                "transfer archive roundtrip changed signed data",
            )?;
            verify_transfer(&decoded, debit)?;
            signature_count_verified += 1;
            let timestamp = TRANSFER_REFERENCE_TIMESTAMP_START + index as u64;
            let result = cipher_clerk::apply_batch(
                &mut reference,
                core::slice::from_ref(&decoded),
                &mut oracle,
                timestamp,
            );
            require(
                result.len() == 1
                    && result[0].status == EventStatus::Created
                    && result[0].timestamp == timestamp,
                "reference transfer was not accepted exactly",
            )?;
            transfers.record(timestamp, &[&bytes, &opening_bytes])?;
            // Only settled transfers with no range flags are generated. All
            // openings remain in the stream, not an unbounded live oracle map.
            oracle.openings.clear();
        }
        require(
            reference.accounts.len() == options.accounts as usize
                && reference.transfers.len() == options.transfers as usize
                && reference.external_ids.len() == options.transfers as usize
                && reference.journals.len() == 1
                && reference.voided.is_empty()
                && reference.pending_statuses.is_empty(),
            "retained reference counts differ from corpus",
        )?;
        require(
            signature_count_verified as usize
                == reference.accounts.len() + reference.transfers.len(),
            "verified signature count differs from retained signed records",
        )?;
        for account in reference.accounts.values() {
            let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(account)
                .map_err(|_| io::Error::other("encode reference account"))?;
            expected.record(account.timestamp, &[&bytes])?;
        }
        let roots = reference_roots(&reference)?;
        let manifest = Manifest {
            format: "VOS-CLERK-CORPUS-1".into(),
            smoke_only: options.accounts != DEFAULT_ACCOUNTS
                || options.transfers != DEFAULT_TRANSFERS,
            reference_only: true,
            public_replay_requires_actual_acceptance_context: true,
            reference_order: "creates_stream_then_transfers_stream_record_order".into(),
            account_reference_timestamp_start: ACCOUNT_REFERENCE_TIMESTAMP_START,
            transfer_reference_timestamp_start: TRANSFER_REFERENCE_TIMESTAMP_START,
            contains_private_business_keys: true,
            authority_authorizations_generated: false,
            journal_id: hex(&journal_id.0),
            registrar_public_key: hex(&registrar.public.0),
            journal_code: 1,
            account_count: reference.accounts.len() as u32,
            transfer_count: reference.transfers.len() as u32,
            external_id_count: reference.external_ids.len() as u32,
            voided_count: reference.voided.len() as u32,
            pending_count: reference.pending_statuses.len() as u32,
            signature_count_verified,
            roots,
            files: vec![
                creates.finish()?,
                transfers.finish()?,
                expected.finish()?,
                secrets.finish()?,
            ],
        };
        publish_manifest(&options.out, &directory, &manifest)?;
        Ok(manifest)
    }

    pub(super) fn run() -> Result<()> {
        let options = Options::parse();
        let manifest = generate(&options)?;
        println!(
            "Offline signed corpus: {} accounts, {} retained transfers; manifest: {}",
            manifest.account_count,
            manifest.transfer_count,
            options.out.join("manifest.toml").display()
        );
        println!(
            "Private business keys/openings retained; public execution and release qualification OPEN."
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Read as _;
        use zeroize::Zeroize as _;

        fn test_output() -> PathBuf {
            let base =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/clerk-corpus-tests");
            fs::create_dir_all(&base).unwrap();
            let parent = base.canonicalize().unwrap().join(format!(
                "smoke-{}-{}",
                std::process::id(),
                hex(&JournalId::random().0)
            ));
            // Only this freshly allocated directory is private; never chmod an
            // existing user/test directory or overwrite an earlier corpus.
            fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
            parent.join("corpus")
        }

        fn read_stream(path: &Path, magic: &[u8; 4]) -> Vec<(u64, Vec<Vec<u8>>)> {
            let mut file = File::open(path).unwrap();
            let mut header = [0u8; 8];
            file.read_exact(&mut header).unwrap();
            assert_eq!(&header[..4], magic);
            let count = u32::from_le_bytes(header[4..].try_into().unwrap());
            assert!(count <= DEFAULT_TRANSFERS + 1);
            let mut records = Vec::new();
            for _ in 0..count {
                let mut header = [0u8; 9];
                file.read_exact(&mut header).unwrap();
                let mut parts = Vec::new();
                assert!((1..=3).contains(&header[8]));
                for _ in 0..header[8] {
                    let mut length = [0u8; 4];
                    file.read_exact(&mut length).unwrap();
                    let length = u32::from_le_bytes(length) as usize;
                    assert!((1..=MAX_PART_BYTES).contains(&length));
                    let mut bytes = vec![0; length];
                    file.read_exact(&mut bytes).unwrap();
                    parts.push(bytes);
                }
                records.push((u64::from_le_bytes(header[..8].try_into().unwrap()), parts));
            }
            assert_eq!(file.read(&mut [0]).unwrap(), 0, "no trailing bytes");
            records
        }

        #[test]
        fn signed_corpus_small_stream_replays_signatures_counts_roots_and_private_modes() {
            let out = test_output();
            let options = Options {
                out: out.clone(),
                accounts: 4,
                transfers: 7,
            };
            let produced = generate(&options).unwrap();
            let parsed: Manifest =
                toml::from_str(&fs::read_to_string(out.join("manifest.toml")).unwrap()).unwrap();
            assert_eq!(
                (
                    parsed.account_count,
                    parsed.transfer_count,
                    parsed.external_id_count
                ),
                (4, 7, 7)
            );
            assert_eq!(parsed.signature_count_verified, 11);
            assert!(parsed.smoke_only && parsed.contains_private_business_keys);
            assert!(
                parsed.reference_only && parsed.public_replay_requires_actual_acceptance_context
            );
            assert_eq!(
                parsed.reference_order,
                "creates_stream_then_transfers_stream_record_order"
            );
            assert_eq!(parsed.account_reference_timestamp_start, 500_000);
            assert_eq!(parsed.transfer_reference_timestamp_start, 1_000_000);
            assert!(!parsed.authority_authorizations_generated);
            assert_eq!(fs::metadata(&out).unwrap().mode() & 0o777, 0o700);
            assert!(!out.join("manifest.next").exists());
            for report in &parsed.files {
                let mut bytes = fs::read(out.join(&report.file)).unwrap();
                assert_eq!(bytes.len() as u64, report.bytes);
                assert_eq!(
                    hex(blake2b_simd::Params::new()
                        .hash_length(32)
                        .hash(&bytes)
                        .as_bytes()),
                    report.blake2b_256
                );
                assert_eq!(
                    fs::metadata(out.join(&report.file)).unwrap().mode() & 0o777,
                    0o600
                );
                if report.file == "keys.private" {
                    bytes.as_mut_slice().zeroize();
                }
            }
            let mut keys = read_stream(&out.join("keys.private"), b"CCK1");
            assert_eq!(keys.len(), 5);
            assert_eq!(keys[0].1[0], AccountId::ZERO.0);
            let registrar = AuthKey(keys[0].1[1].as_slice().try_into().unwrap());
            for (_, parts) in &mut keys {
                assert_eq!(parts.len(), 3);
                assert_eq!(parts[0].len(), 16);
                let bytes = Zeroizing::new(parts[2].as_slice().try_into().unwrap());
                let secret = SecretKey::from_bytes(*bytes).unwrap();
                assert_eq!(secret.public_key().0.as_slice(), parts[1].as_slice());
                parts[2].as_mut_slice().zeroize();
            }
            let journal_id = JournalId(
                read_stream(&out.join("creates.corpus"), b"CCA1")
                    .first()
                    .map(|(_, parts)| {
                        vos::rkyv::from_bytes::<CreateAccount, vos::rkyv::rancor::Error>(&parts[0])
                            .unwrap()
                            .account
                            .journal_id
                            .0
                    })
                    .unwrap(),
            );
            let mut reference = MemLedger::new();
            let journal = Journal::new(journal_id, registrar, 1);
            reference
                .journals_smt
                .insert(journal_id.0, &journal_leaf_content(&journal));
            reference.journals.insert(journal_id.0, journal);
            let mut oracle = MemOracle::new();
            for (timestamp, parts) in read_stream(&out.join("creates.corpus"), b"CCA1") {
                assert_eq!(parts.len(), 1);
                let mut create =
                    vos::rkyv::from_bytes::<CreateAccount, vos::rkyv::rancor::Error>(&parts[0])
                        .unwrap();
                verify_create(&create, registrar).unwrap();
                assert_eq!(
                    cipher_clerk::apply_account_creations(
                        &mut reference,
                        core::slice::from_ref(&create),
                        &mut oracle,
                        timestamp
                    )[0]
                    .status,
                    EventStatus::Created
                );
                create.signature.s = [0; 32];
                assert!(verify_create(&create, registrar).is_err());
                create.signature = Signature::ZERO;
                assert!(verify_create(&create, registrar).is_err());
            }
            for (timestamp, parts) in read_stream(&out.join("transfers.corpus"), b"CCT1") {
                assert_eq!(parts.len(), 2);
                let mut transfer =
                    vos::rkyv::from_bytes::<Transfer, vos::rkyv::rancor::Error>(&parts[0]).unwrap();
                let openings =
                    vos::rkyv::from_bytes::<Vec<Opening>, vos::rkyv::rancor::Error>(&parts[1])
                        .unwrap();
                let debit = reference
                    .accounts
                    .get(&transfer.entries[0].account_id.0)
                    .unwrap()
                    .clone();
                verify_transfer(&transfer, &debit).unwrap();
                for opening in openings {
                    oracle.record(opening.amount, opening.value, opening.blinding);
                }
                assert_eq!(
                    cipher_clerk::apply_batch(
                        &mut reference,
                        core::slice::from_ref(&transfer),
                        &mut oracle,
                        timestamp
                    )[0]
                    .status,
                    EventStatus::Created
                );
                transfer.signatures[0].s = [0; 32];
                assert!(verify_transfer(&transfer, &debit).is_err());
                transfer.signatures[0] = Signature::ZERO;
                assert!(verify_transfer(&transfer, &debit).is_err());
            }
            assert_eq!(
                (
                    reference.accounts.len(),
                    reference.transfers.len(),
                    reference.external_ids.len()
                ),
                (4, 7, 7)
            );
            assert_eq!(parsed.roots.composite, hex(&reference.root()));
            assert_eq!(parsed.roots.composite, produced.roots.composite);
            let expected = read_stream(&out.join("accounts.reference"), b"CCR1");
            assert_eq!(expected.len(), 4);
            for (timestamp, parts) in expected {
                let account =
                    vos::rkyv::from_bytes::<Account, vos::rkyv::rancor::Error>(&parts[0]).unwrap();
                assert_eq!(account.timestamp, timestamp);
                assert_eq!(reference.accounts.get(&account.id.0), Some(&account));
            }
            let before = fs::read(out.join("manifest.toml")).unwrap();
            assert!(
                generate(&options).is_err(),
                "never replace a destination or its keys"
            );
            assert_eq!(fs::read(out.join("manifest.toml")).unwrap(), before);
            // All material stays under the disk test root for central evidence
            // retention/cleanup. No /tmp allocation or recursive deletion here.
        }

        #[test]
        fn signed_corpus_refuses_invalid_counts_and_relative_output_before_creation() {
            for (accounts, transfers) in [(0, 7), (3, 7), (1002, 7), (4, 0), (4, 100001)] {
                assert!(
                    validate_options(&Options {
                        out: "/absent-corpus-parent/run".into(),
                        accounts,
                        transfers
                    })
                    .is_err()
                );
            }
            assert!(
                validate_options(&Options {
                    out: "relative-output".into(),
                    accounts: 4,
                    transfers: 7
                })
                .is_err()
            );
            for (accounts, transfers) in [(4, 7), (DEFAULT_ACCOUNTS, DEFAULT_TRANSFERS)] {
                validate_options(&Options {
                    out: "/private-disk-parent/corpus".into(),
                    accounts,
                    transfers,
                })
                .unwrap();
            }
        }

        #[test]
        fn signed_corpus_refuses_oversize_or_incomplete_stream_without_manifest() {
            let out = test_output();
            let directory = prepare_output(&Options {
                out: out.clone(),
                accounts: 4,
                transfers: 7,
            })
            .unwrap();
            let mut stream = Stream::create(&out, "partial.corpus", b"CCT1", 1).unwrap();
            assert!(stream.record(1, &[&vec![0; MAX_PART_BYTES + 1]]).is_err());
            assert_eq!(stream.records, 0);
            assert_eq!(stream.bytes, 8);
            assert!(stream.finish().is_err());
            directory.sync_all().unwrap();
            assert!(!out.join("manifest.toml").exists());
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("clerk_corpus supports the approved Linux host only");
    std::process::exit(1);
}
