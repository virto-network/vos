//! Bounded public loading of an existing signed business corpus through vosx.
//!
//! Requires a released fixed-three Space and an installed, empty Shared Clerk.
//! All identity material already belongs to the explicitly supplied persona;
//! this tool never reads keys.private, generates credentials or decides Authority
//! policy. Exact private ATQ1 inputs and CLI protocol stores survive interruption.
//! --resume uses the same inputs, invocation IDs and business timestamp seeds.
//! The existing persona must already have the installed deployment's signed
//! Operator and Member roles. Role administration remains an explicit setup
//! prerequisite; this business loader never creates or resumes admin work.
//! A pass closes public six-map parity only; resources, backup, recovery, load
//! and hardware remain separate gates. Use --help for explicit artifact inputs.
//! Build with the existing host `std,http-ingress` features; qualification uses
//! `experimental-state-blocks,http-ingress,agent-runtime` with the locked host
//! toolchain. No new Cargo feature or production profile is introduced.

#[cfg(target_os = "linux")]
#[path = "support/clerk_public_corpus.rs"]
mod corpus;

#[cfg(target_os = "linux")]
mod linux {
    use super::corpus::*;
    use cipher_clerk::prelude::AuthKey;
    use clap::Parser;
    use serde::{Deserialize, Serialize};
    use serde_json::{Value as Json, json};
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::net::SocketAddr;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    use vos::agent::package_admission::admit_actor_package;
    use vos::agent::sdk::method_policy::{ActorMethodPolicyArtifact, AuthorizationPolicySelector};
    use vos::agent::sdk::wire::CanonicalWire;
    use vos::agent::sdk::{
        ActorId, AgentId, CredentialId, Hash, InvocationId, InvocationOrigin, InvocationRoleClaims,
        InvocationStatus, PrincipalId, RuntimeOutcome, SpaceId,
    };
    use vos::agent::supervisor::AgentRouteKey;
    use vos::agent::supervisor_adapters::{
        AgentInvocationIntent, AgentInvocationResponse, AgentTargetedPreparationRequest,
    };
    use vos::value::{Msg, Value};
    use vos::{Decode, Encode};

    const MAX_CLI_OUTPUT: u64 = 4 * 1024 * 1024;

    #[derive(Parser)]
    struct Options {
        /// Current portable main; its independently retained SHA256 is mandatory.
        #[arg(long)]
        vosx: PathBuf,
        #[arg(long)]
        vosx_sha256: String,
        #[arg(long)]
        clerk_package: PathBuf,
        #[arg(long)]
        clerk_blake2b_256: String,
        /// Existing private corpus; keys.private is never opened.
        #[arg(long)]
        corpus: PathBuf,
        /// Exact configured Space ID and Shared Agent, both full lowercase hex.
        #[arg(long)]
        space: String,
        #[arg(long)]
        agent: String,
        /// Existing operator public key, not a private key path.
        #[arg(long)]
        operator_public_key: String,
        /// Existing persona containing config/, data/ and cache/.
        #[arg(long)]
        persona: PathBuf,
        /// Exact existing Space directory, used to constrain retained CLI paths.
        #[arg(long)]
        space_dir: PathBuf,
        /// Three distinct loopback HTTP endpoints, one per member.
        #[arg(long, num_args = 3)]
        http: Vec<SocketAddr>,
        /// Fresh evidence under an existing private disk parent; reuse with --resume.
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        resume: bool,
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Inputs {
        format: u32,
        vosx_sha256: String,
        clerk_blake2b_256: String,
        corpus_manifest: String,
        creates: String,
        transfers: String,
        space: String,
        agent: String,
        operator_public_key: String,
        persona: PathBuf,
        space_dir: PathBuf,
        http: Vec<SocketAddr>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Run {
        inputs: Inputs,
        nonce: String,
        business_seed_start: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Accepted {
        format: u32,
        intent: String,
        request: String,
        response: String,
    }

    fn invocation_id(nonce: &str, ordinal: u64, salt: &[u8]) -> Result<InvocationId> {
        let nonce = id::<32>(nonce)?;
        require(nonce != [0; 32], "zero run nonce")?;
        Ok(InvocationId(
            Hash::digest(
                b"vos/tool/public-clerk-corpus/v1",
                &[&nonce, &ordinal.to_le_bytes(), salt],
            )
            .0,
        ))
    }

    fn verification_nonce(evidence: &Path) -> Result<[u8; 32]> {
        // Completed phases allow another fresh verification after reopen.
        // An unfinished phase keeps its original nonce and exact queries,
        // including a reservation whose first response was genuinely lost.
        let mut phase = 0u64;
        loop {
            let path = evidence.join(format!("verification-{phase}.json"));
            let nonce = if path.try_exists()? {
                let nonce: String = serde_json::from_slice(&bytes(&path, 1024)?)
                    .map_err(|_| io::Error::other("invalid retained verification nonce"))?;
                id::<32>(&nonce)?
            } else {
                let mut nonce = [0; 32];
                getrandom::getrandom(&mut nonce)
                    .map_err(|_| io::Error::other("verification nonce entropy"))?;
                require(nonce != [0; 32], "zero verification nonce")?;
                publish(&path, &serde_json::to_vec(&hex(nonce))?)?;
                nonce
            };
            require(nonce != [0; 32], "zero retained verification nonce")?;
            let completed = evidence.join(format!("parity-{}.json", hex(nonce)));
            if !completed.try_exists()? {
                return Ok(nonce);
            }
            // Enforce ordinary private evidence bounds before skipping a
            // completed phase; no cached result supplies a fresh observation.
            bytes(&completed, 64 * 1024)?;
            phase = phase
                .checked_add(1)
                .ok_or_else(|| io::Error::other("verification phase overflow"))?;
        }
    }

    fn arguments(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(|part| OsString::from(*part)).collect()
    }

    fn encoded(method: &str, fields: &[(&str, Value)]) -> Vec<u8> {
        let mut message = Msg::new(method);
        for (name, value) in fields {
            message = message.with(*name, value.clone());
        }
        let mut raw = vec![vos::value::TAG_DYNAMIC];
        raw.extend(message.encode());
        raw
    }

    fn private_file(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?)
    }

    fn freeze_binary(source: &Path, destination: &Path, expected: &str) -> Result<()> {
        if !destination.try_exists()? {
            let parent = destination
                .parent()
                .ok_or_else(|| io::Error::other("missing binary parent"))?;
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce)
                .map_err(|_| io::Error::other("binary nonce entropy"))?;
            let stage = parent.join(format!(".partial-binary-{}", hex(nonce)));
            let mut source = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(source)?;
            require(
                source.metadata()?.is_file() && source.metadata()?.len() <= 256 * 1024 * 1024,
                "portable binary exceeds tooling bound",
            )?;
            let mut file = private_file(&stage)?;
            io::copy(&mut source, &mut file)?;
            file.set_permissions(fs::Permissions::from_mode(0o700))?;
            file.sync_all()?;
            require(
                sha256(&stage)? == expected,
                "main binary changed while freezing",
            )?;
            fs::hard_link(&stage, destination)?;
            File::open(parent)?.sync_all()?;
            fs::remove_file(stage)?;
            File::open(parent)?.sync_all()?;
        }
        let metadata = fs::symlink_metadata(destination)?;
        require(
            destination.canonicalize()? == destination
                && metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o700
                && sha256(destination)? == expected,
            "frozen main binary differs",
        )
    }

    fn sha256(path: &Path) -> Result<String> {
        let output = Command::new("sha256sum").arg("--").arg(path).output()?;
        require(output.status.success(), "binary hash command failed")?;
        let digest = std::str::from_utf8(&output.stdout)?
            .split_whitespace()
            .next()
            .ok_or_else(|| io::Error::other("missing binary hash"))?
            .to_string();
        id::<32>(&digest)?;
        Ok(digest)
    }

    struct Driver<'a> {
        options: &'a Options,
        run: Run,
        binary: PathBuf,
        actor: ActorId,
        deployment: vos::agent::sdk::DeploymentId,
        policies: ActorMethodPolicyArtifact,
    }

    impl Driver<'_> {
        fn validate_policies(&self) -> Result<(vos::agent::sdk::RoleId, vos::agent::sdk::RoleId)> {
            use vos::agent::sdk::MethodMode;
            let operator = self.role("bootstrap")?;
            let member = self.role("state_root")?;
            require(
                operator != member,
                "required signed Clerk roles must be distinct",
            )?;
            for name in ["bootstrap", "create_account", "apply_transfer"] {
                let method = self
                    .policies
                    .method(name)
                    .ok_or_else(|| io::Error::other("required signed Clerk method absent"))?;
                require(
                    method.mode == MethodMode::Linear
                        && method.authorization_policy
                            == AuthorizationPolicySelector::ActorRole(operator),
                    "signed Clerk mutation policy differs",
                )?;
            }
            for name in ["state_root", "account_count", "transfer_count"] {
                let method = self
                    .policies
                    .method(name)
                    .ok_or_else(|| io::Error::other("required signed Clerk method absent"))?;
                require(
                    method.mode == MethodMode::LinearizableQuery
                        && method.authorization_policy
                            == AuthorizationPolicySelector::ActorRole(member),
                    "signed Clerk member policy differs",
                )?;
            }
            let method = self
                .policies
                .method("journal_id")
                .ok_or_else(|| io::Error::other("required signed Clerk method absent"))?;
            require(
                method.mode == MethodMode::LinearizableQuery
                    && method.authorization_policy == AuthorizationPolicySelector::Public,
                "signed Clerk public query policy differs",
            )?;
            Ok((operator, member))
        }

        fn cli(&self, directory: &Path, args: &[OsString]) -> Result<Json> {
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("log nonce entropy"))?;
            let prefix = directory.join(format!("attempt-{}", hex(nonce)));
            let stdout = prefix.with_extension("stdout");
            let stderr = prefix.with_extension("stderr");
            let status = Command::new("timeout")
                .args(["--signal=TERM", "--kill-after=10s", "180s"])
                .arg(&self.binary)
                .args(["--format", "json"])
                .args(args)
                .env("XDG_CONFIG_HOME", self.options.persona.join("config"))
                .env("XDG_DATA_HOME", self.options.persona.join("data"))
                .env("XDG_CACHE_HOME", self.options.persona.join("cache"))
                .env("TMPDIR", self.options.evidence.join("tmp"))
                .env("JUST_TEMPDIR", self.options.evidence.join("tmp"))
                .env("VOSX_DISABLE_MDNS", "1")
                .env("RUST_LOG", "warn")
                .stdin(Stdio::null())
                .stdout(private_file(&stdout)?)
                .stderr(private_file(&stderr)?)
                .status()?;
            require(
                status.success(),
                "public CLI operation failed; exact evidence retained, resume identical inputs",
            )?;
            Ok(serde_json::from_slice(&bytes(&stdout, MAX_CLI_OUTPUT)?)
                .map_err(|_| io::Error::other("invalid CLI JSON; private evidence retained"))?)
        }

        fn role(&self, method: &str) -> Result<vos::agent::sdk::RoleId> {
            let method = self
                .policies
                .method(method)
                .ok_or_else(|| io::Error::other("required signed Clerk method absent"))?;
            let AuthorizationPolicySelector::ActorRole(role) = method.authorization_policy else {
                return Err(io::Error::other("required signed Clerk actor role absent").into());
            };
            Ok(role)
        }

        fn call(
            &self,
            ordinal: u64,
            salt: &[u8],
            endpoint: SocketAddr,
            method_name: &str,
            message: Vec<u8>,
        ) -> Result<vos::agent::sdk::InvocationReply> {
            require(
                message.len() <= vos::agent::sdk::MAX_INVOCATION_MESSAGE_BYTES,
                "business message exceeds existing runtime limit",
            )?;
            let method = self
                .policies
                .method(method_name)
                .ok_or_else(|| io::Error::other("required Clerk method absent"))?;
            let roles = match method.authorization_policy {
                AuthorizationPolicySelector::Public => InvocationRoleClaims::none(),
                AuthorizationPolicySelector::ActorRole(role) => InvocationRoleClaims {
                    actor: Some(role),
                    space: None,
                },
                _ => return Err(io::Error::other("unsupported Clerk policy selector").into()),
            };
            let public = id::<32>(&self.options.operator_public_key)?;
            let invocation = invocation_id(&self.run.nonce, ordinal, salt)?;
            let intent = AgentTargetedPreparationRequest::new(
                AgentRouteKey::new(
                    SpaceId(id(&self.options.space)?),
                    AgentId(id(&self.options.agent)?),
                    self.actor,
                )
                .map_err(|_| io::Error::other("invalid route"))?,
                AgentInvocationIntent::new(
                    invocation,
                    method.mode,
                    InvocationOrigin {
                        principal: Some(PrincipalId::of_public_key(&public)),
                        credential: Some(CredentialId::of_public_key(&public)),
                        ..InvocationOrigin::anonymous()
                    },
                    roles,
                    message,
                    vos::agent::execution::MAX_EXECUTION_GAS,
                    false,
                )
                .map_err(|_| io::Error::other("invalid invocation intent"))?,
            )
            .map_err(|_| io::Error::other("invalid targeted intent"))?;
            let raw = intent
                .encode()
                .map_err(|_| io::Error::other("invalid canonical ATQ1"))?;
            let directory = self
                .options
                .evidence
                .join(format!("op-{ordinal}-{}", hex(salt)));
            if !directory.try_exists()? {
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
            }
            super::corpus::directory(&directory)?;
            let input = directory.join("intent.atq1");
            publish(&input, &raw)?;
            let completed = directory.join("accepted.json");
            let operation = self
                .options
                .space_dir
                .join("agent-client")
                .join("operations")
                .join(format!(
                    "{}-{}",
                    hex(CredentialId::of_public_key(&public).0),
                    hex(invocation.0)
                ));
            if !completed.try_exists()? {
                let output = self.cli(
                    &directory,
                    &[
                        arguments(&["space", "invoke-agent", &self.options.space, "--intent"])
                            .as_slice(),
                        &[input.into_os_string()],
                        arguments(&["--http", &endpoint.to_string()]).as_slice(),
                    ]
                    .concat(),
                )?;
                require(
                    output["decision"] == "issued"
                        && output["delivery_retired"] == true
                        && output["reservation_pending"] == false,
                    "public invocation did not retire successfully",
                )?;
                require(
                    output["request_dir"].as_str() == operation.join("request").to_str(),
                    "CLI retained path differs from exact operation",
                )?;
            }
            // Normal CLI reading verifies ASR1 against its original retained
            // ASQ1 even on resume. This tool's JSON is never its own evidence
            // oracle, and an already retained result causes no HTTP execution.
            let output = self.cli(
                &directory,
                &[
                    arguments(&["space", "submit-agent-invocation"]).as_slice(),
                    &[operation.join("application").into_os_string()],
                    arguments(&["--http", &endpoint.to_string()]).as_slice(),
                ]
                .concat(),
            )?;
            require(
                output["delivery_retained"] == true,
                "bound result was not retained",
            )?;
            let response = output["response"]
                .as_str()
                .ok_or_else(|| io::Error::other("retained response missing"))?
                .to_string();
            let request = output["request"]
                .as_str()
                .ok_or_else(|| io::Error::other("retained request commitment missing"))?
                .to_string();
            id::<32>(&request)?;
            let accepted = Accepted {
                format: 1,
                intent: digest(&raw),
                request,
                response,
            };
            self.reply(&accepted, &raw, invocation, method.mode)?;
            // Immutable publication compares exact old evidence on resume.
            // Ambiguity leaves the same ATQ1/native stores for exact retry.
            publish(&completed, &serde_json::to_vec(&accepted)?)?;
            self.reply(&accepted, &raw, invocation, method.mode)
        }

        fn reply(
            &self,
            accepted: &Accepted,
            intent: &[u8],
            invocation: InvocationId,
            mode: vos::agent::sdk::MethodMode,
        ) -> Result<vos::agent::sdk::InvocationReply> {
            require(
                accepted.format == 1 && accepted.intent == digest(intent),
                "accepted record differs from exact intent",
            )?;
            let raw = unhex(&accepted.response)
                .map_err(|_| io::Error::other("invalid retained response encoding"))?;
            let AgentInvocationResponse::Direct {
                request,
                outcome: RuntimeOutcome::Completed(Ok(reply)),
            } = AgentInvocationResponse::decode(&raw)
                .map_err(|_| io::Error::other("invalid canonical ASR1"))?
            else {
                return Err(io::Error::other("public invocation did not complete directly").into());
            };
            require(
                request.0 == id::<32>(&accepted.request)?,
                "result differs from original retained ASQ1",
            )?;
            require(
                reply.status == InvocationStatus::Done
                    && reply.invocation == invocation
                    && reply.actor == self.actor
                    && reply.deployment == self.deployment
                    && reply.mode == mode
                    && reply.observation.linear_revision.is_some(),
                "result differs from the selected Clerk invocation",
            )?;
            Ok(reply)
        }
    }

    fn value(reply: &vos::agent::sdk::InvocationReply) -> Result<Value> {
        Value::try_decode(&reply.reply)
            .ok_or_else(|| io::Error::other("invalid Clerk reply value").into())
    }

    fn success(
        reply: &vos::agent::sdk::InvocationReply,
        previous: &mut Option<(Hash, u64)>,
    ) -> Result<()> {
        require(
            value(reply)? == Value::Bytes(vec![0]),
            "Clerk business mutation refused",
        )?;
        let revision = reply
            .observation
            .linear_revision
            .ok_or_else(|| io::Error::other("missing accepted revision"))?;
        require(
            previous.is_none_or(|(incarnation, previous)| {
                reply.incarnation == incarnation && revision > previous
            }),
            "accepted incarnation or mutation order changed",
        )?;
        *previous = Some((reply.incarnation, revision));
        Ok(())
    }

    fn preflight(root: &Path, manifest: &Manifest) -> Result<()> {
        let mut reference = reference(manifest)?;
        let registrar = AuthKey(id(&manifest.registrar_public_key)?);
        let mut creates =
            manifest.stream(root, "creates.corpus", b"CCA1", manifest.account_count)?;
        let mut index = 0;
        while let Some(record) = creates.next(1)? {
            require(
                record.reference_timestamp == manifest.account_reference_timestamp_start + index,
                "account reference order differs",
            )?;
            require(
                encoded(
                    "create_account",
                    &[
                        (
                            "create_account_bytes",
                            Value::Bytes(record.parts[0].clone()),
                        ),
                        (
                            "batch_seed_timestamp",
                            Value::U64(record.reference_timestamp),
                        ),
                    ],
                )
                .len()
                    <= vos::agent::sdk::MAX_INVOCATION_MESSAGE_BYTES,
                "account message exceeds existing limit",
            )?;
            apply_create(
                &mut reference,
                &record.parts[0],
                record.reference_timestamp,
                registrar,
            )?;
            index += 1;
        }
        let mut transfers =
            manifest.stream(root, "transfers.corpus", b"CCT1", manifest.transfer_count)?;
        index = 0;
        while let Some(record) = transfers.next(2)? {
            require(
                record.reference_timestamp == manifest.transfer_reference_timestamp_start + index,
                "transfer reference order differs",
            )?;
            require(
                encoded(
                    "apply_transfer",
                    &[
                        ("transfer_bytes", Value::Bytes(record.parts[0].clone())),
                        ("openings_bytes", Value::Bytes(record.parts[1].clone())),
                        (
                            "batch_seed_timestamp",
                            Value::U64(record.reference_timestamp),
                        ),
                    ],
                )
                .len()
                    <= vos::agent::sdk::MAX_INVOCATION_MESSAGE_BYTES,
                "transfer message exceeds existing limit",
            )?;
            apply_transfer(
                &mut reference,
                &record.parts[0],
                &record.parts[1],
                record.reference_timestamp,
            )?;
            index += 1;
        }
        require(
            reference.accounts.len() == manifest.account_count as usize
                && reference.transfers.len() == manifest.transfer_count as usize
                && reference.external_ids.len() == manifest.external_id_count as usize
                && reference.voided.is_empty()
                && reference.pending_statuses.is_empty()
                && roots(&reference)? == manifest.roots,
            "offline corpus parity refused before mutation",
        )
    }

    pub fn run() -> Result<()> {
        let options = Options::parse();
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy();
            require(
                !name.contains("CANDIDATE")
                    && !name.starts_with("VOS_TEST_")
                    && !name.starts_with("VOSX_EXPERIMENTAL_")
                    && !name.starts_with("VOSX_QUALIFY_")
                    && name != "CLERK_AGENT_PACKAGE",
                "candidate/test override environment is forbidden",
            )?;
        }
        id::<32>(&options.vosx_sha256)?;
        id::<32>(&options.clerk_blake2b_256)?;
        let space = SpaceId(id(&options.space)?);
        let agent = AgentId(id(&options.agent)?);
        id::<32>(&options.operator_public_key)?;
        require(
            space != SpaceId::ZERO
                && agent != AgentId::ZERO
                && options.http.len() == 3
                && options
                    .http
                    .iter()
                    .all(|endpoint| endpoint.ip().is_loopback() && endpoint.port() != 0)
                && options
                    .http
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == 3,
            "require exact scope and three distinct loopback members",
        )?;
        directory(&options.persona)?;
        directory(&options.space_dir)?;
        for path in [
            options.persona.join("config"),
            options.persona.join("config/vosx"),
            options.persona.join("data"),
            options.persona.join("cache"),
        ] {
            directory(&path)?;
        }
        // Check existence/type only: all signing stays in the normal CLI.
        let identity = fs::symlink_metadata(options.persona.join("config/vosx/identity.key"))?;
        require(
            identity.is_file()
                && identity.uid() == unsafe { libc::geteuid() }
                && identity.mode() & 0o077 == 0,
            "require an existing private operator identity",
        )?;
        let binary_metadata = fs::symlink_metadata(&options.vosx)?;
        require(
            options.vosx.canonicalize()? == options.vosx
                && binary_metadata.is_file()
                && binary_metadata.mode() & 0o111 != 0
                && sha256(&options.vosx)? == options.vosx_sha256,
            "main binary provenance differs",
        )?;
        let package_raw = bytes(
            &options.clerk_package,
            vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES as u64,
        )?;
        require(
            digest(&package_raw) == options.clerk_blake2b_256,
            "Clerk package identity differs",
        )?;
        let package = admit_actor_package(&package_raw)
            .map_err(|_| io::Error::other("signed Clerk package admission refused"))?;
        require(
            package.manifest().name == "clerk-ledger",
            "package is not Clerk",
        )?;
        let policies = ActorMethodPolicyArtifact::decode(package.method_policy_bytes())
            .map_err(|_| io::Error::other("invalid signed Clerk policy"))?;
        let (manifest, manifest_hash) = Manifest::read(&options.corpus)?;
        let inputs = Inputs {
            format: 1,
            vosx_sha256: options.vosx_sha256.clone(),
            clerk_blake2b_256: options.clerk_blake2b_256.clone(),
            corpus_manifest: manifest_hash,
            creates: manifest
                .files
                .iter()
                .find(|file| file.file == "creates.corpus")
                .unwrap()
                .blake2b_256
                .clone(),
            transfers: manifest
                .files
                .iter()
                .find(|file| file.file == "transfers.corpus")
                .unwrap()
                .blake2b_256
                .clone(),
            space: options.space.clone(),
            agent: options.agent.clone(),
            operator_public_key: options.operator_public_key.clone(),
            persona: options.persona.clone(),
            space_dir: options.space_dir.clone(),
            http: options.http.clone(),
        };
        let run = if options.resume {
            directory(&options.evidence)?;
            let run: Run =
                serde_json::from_slice(&bytes(&options.evidence.join("inputs.json"), 64 * 1024)?)
                    .map_err(|_| io::Error::other("invalid retained run inputs"))?;
            require(
                run.inputs == inputs,
                "resume inputs differ from original run",
            )?;
            id::<32>(&run.nonce)?;
            run
        } else {
            directory(
                options
                    .evidence
                    .parent()
                    .ok_or_else(|| io::Error::other("missing evidence parent"))?,
            )?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&options.evidence)?;
            directory(&options.evidence)?;
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("run nonce entropy"))?;
            let run = Run {
                inputs,
                nonce: hex(nonce),
                business_seed_start: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_micros()
                    .try_into()?,
            };
            publish(
                &options.evidence.join("inputs.json"),
                &serde_json::to_vec(&run)?,
            )?;
            run
        };
        // Serialize this one credential's corpus driver. The daemon retains its
        // ordinary ownership locks; this lock grants no serving authority.
        require(
            run.business_seed_start != 0
                && run
                    .business_seed_start
                    .checked_add(1 + manifest.account_count as u64 + manifest.transfer_count as u64)
                    .is_some(),
            "retained business timestamp range exceeds bound",
        )?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(options.evidence.join("loader.lock"))?;
        let metadata = lock.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "loader lock differs from private regular file",
        )?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        if !options.evidence.join("tmp").try_exists()? {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(options.evidence.join("tmp"))?;
        }
        directory(&options.evidence.join("tmp"))?;
        let binary = options.evidence.join("vosx");
        freeze_binary(&options.vosx, &binary, &options.vosx_sha256)?;
        publish(&options.evidence.join("clerk-ledger.vos"), &package_raw)?;
        let frozen_corpus = options.evidence.join("business-corpus");
        if !frozen_corpus.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(&frozen_corpus)?;
        }
        directory(&frozen_corpus)?;
        let manifest_raw = bytes(&options.corpus.join("manifest.toml"), 16 * 1024)?;
        require(
            digest(&manifest_raw) == run.inputs.corpus_manifest,
            "corpus manifest changed before freezing",
        )?;
        publish(&frozen_corpus.join("manifest.toml"), &manifest_raw)?;
        for name in ["creates.corpus", "transfers.corpus"] {
            let report = manifest
                .files
                .iter()
                .find(|file| file.file == name)
                .ok_or_else(|| io::Error::other("missing corpus stream catalog"))?;
            freeze_stream(
                &options.corpus.join(name),
                &frozen_corpus.join(name),
                report.bytes,
                &report.blake2b_256,
            )?;
        }
        preflight(&frozen_corpus, &manifest)?;
        let driver = Driver {
            options: &options,
            run,
            binary,
            actor: ActorId::top_level(agent, "clerk-ledger"),
            deployment: package.deployment(),
            policies,
        };
        let (operator_role, member_role) = driver.validate_policies()?;
        let info = driver.cli(
            &options.evidence,
            &arguments(&["space", "info", &options.space]),
        )?;
        require(
            info["space_id"] == options.space
                && info["data_dir"].as_str() == options.space_dir.to_str()
                && info["daemon"]["state"] == "running",
            "selected existing Space directory or daemon differs",
        )?;
        let started = Instant::now();
        let mut previous = None;
        let journal = id::<16>(&manifest.journal_id)?;
        let registrar = AuthKey(id(&manifest.registrar_public_key)?);
        if !options.evidence.join("fresh-target.json").try_exists()? {
            let reply = driver.call(
                u64::MAX,
                b"fresh-target",
                options.http[0],
                "journal_id",
                encoded("journal_id", &[]),
            )?;
            require(
                value(&reply)? == Value::Bytes(vec![]),
                "target Clerk is already initialized; no corpus mutation issued",
            )?;
            let reply = driver.call(
                u64::MAX - 1,
                b"fresh-member",
                options.http[0],
                "state_root",
                encoded("state_root", &[]),
            )?;
            require(
                value(&reply)? == Value::Bytes(vec![]),
                "existing Member role or fresh empty state prerequisite refused",
            )?;
            publish(
                &options.evidence.join("fresh-target.json"),
                b"{\"format\":1}\n",
            )?;
        }
        success(
            &driver.call(
                0,
                b"corpus",
                options.http[0],
                "bootstrap",
                encoded(
                    "bootstrap",
                    &[
                        ("journal_id", Value::Bytes(journal.to_vec())),
                        ("registrar_pubkey", Value::Bytes(registrar.0.to_vec())),
                        ("code", Value::U32(manifest.journal_code as u32)),
                    ],
                ),
            )?,
            &mut previous,
        )?;
        let mut expected = reference(&manifest)?;
        let mut ordinal = 1;
        let mut creates = manifest.stream(
            &frozen_corpus,
            "creates.corpus",
            b"CCA1",
            manifest.account_count,
        )?;
        while let Some(record) = creates.next(1)? {
            let seed = driver
                .run
                .business_seed_start
                .checked_add(ordinal)
                .ok_or_else(|| io::Error::other("business seed overflow"))?;
            success(
                &driver.call(
                    ordinal,
                    b"corpus",
                    options.http[0],
                    "create_account",
                    encoded(
                        "create_account",
                        &[
                            (
                                "create_account_bytes",
                                Value::Bytes(record.parts[0].clone()),
                            ),
                            ("batch_seed_timestamp", Value::U64(seed)),
                        ],
                    ),
                )?,
                &mut previous,
            )?;
            apply_create(&mut expected, &record.parts[0], seed, registrar)?;
            ordinal += 1;
        }
        let mut transfers = manifest.stream(
            &frozen_corpus,
            "transfers.corpus",
            b"CCT1",
            manifest.transfer_count,
        )?;
        while let Some(record) = transfers.next(2)? {
            let seed = driver
                .run
                .business_seed_start
                .checked_add(ordinal)
                .ok_or_else(|| io::Error::other("business seed overflow"))?;
            success(
                &driver.call(
                    ordinal,
                    b"corpus",
                    options.http[0],
                    "apply_transfer",
                    encoded(
                        "apply_transfer",
                        &[
                            ("transfer_bytes", Value::Bytes(record.parts[0].clone())),
                            ("openings_bytes", Value::Bytes(record.parts[1].clone())),
                            ("batch_seed_timestamp", Value::U64(seed)),
                        ],
                    ),
                )?,
                &mut previous,
            )?;
            apply_transfer(&mut expected, &record.parts[0], &record.parts[1], seed)?;
            ordinal += 1;
            if (ordinal - 1 - manifest.account_count as u64) % 1_000 == 0 {
                eprintln!(
                    "Public corpus: {} transfers accepted and retired",
                    ordinal - 1 - manifest.account_count as u64
                );
            }
        }
        let expected_roots = roots(&expected)?;
        let verification = verification_nonce(&options.evidence)?;
        let mut observations = Vec::new();
        for (member, endpoint) in options.http.iter().enumerate() {
            for (method, desired) in [
                ("account_count", Value::U32(manifest.account_count)),
                ("transfer_count", Value::U32(manifest.transfer_count)),
                (
                    "state_root",
                    Value::Bytes(id::<32>(&expected_roots.composite)?.to_vec()),
                ),
            ] {
                let reply = driver.call(
                    ordinal,
                    &verification,
                    *endpoint,
                    method,
                    encoded(method, &[]),
                )?;
                require(
                    value(&reply)? == desired
                        && previous.is_some_and(|(incarnation, revision)| {
                            reply.incarnation == incarnation
                                && reply
                                    .observation
                                    .linear_revision
                                    .is_some_and(|current| current >= revision)
                        }),
                    "fresh member incarnation/counts/six-map composite parity refused",
                )?;
                observations.push(json!({"member": member, "method": method, "linear_revision": reply.observation.linear_revision}));
                ordinal += 1;
            }
        }
        // Revalidate immutable inputs after the complete public run.
        require(
            sha256(&driver.binary)? == options.vosx_sha256
                && digest(&bytes(
                    &options.evidence.join("clerk-ledger.vos"),
                    package_raw.len() as u64,
                )?) == options.clerk_blake2b_256
                && Manifest::read(&options.corpus)?.1 == driver.run.inputs.corpus_manifest,
            "input identity changed during loading",
        )?;
        manifest.stream(
            &frozen_corpus,
            "creates.corpus",
            b"CCA1",
            manifest.account_count,
        )?;
        manifest.stream(
            &frozen_corpus,
            "transfers.corpus",
            b"CCT1",
            manifest.transfer_count,
        )?;
        let (incarnation, last_revision) =
            previous.ok_or_else(|| io::Error::other("no accepted corpus context"))?;
        let summary = json!({"format": 1, "gate": "public-corpus-six-map-parity", "smoke_only": manifest.smoke_only, "accounts": expected.accounts.len(), "transfers": expected.transfers.len(), "external_ids": expected.external_ids.len(), "accepted_mutations": 1 + manifest.account_count as u64 + manifest.transfer_count as u64, "business_seed_start": driver.run.business_seed_start, "incarnation": hex(incarnation.0), "last_linear_revision": last_revision, "roots": expected_roots, "member_observations": observations, "operator_role": hex(operator_role.0), "member_role": hex(member_role.0), "elapsed_ms": started.elapsed().as_millis(), "vosx_sha256": options.vosx_sha256, "clerk_blake2b_256": options.clerk_blake2b_256, "open": ["signed storage/resource measurements", "full-data checkpoint/catch-up/recovery deadlines", "Agent backup/restore", "M1 rerun", "load/soak/hardware qualification"]});
        publish(
            &options
                .evidence
                .join(format!("parity-{}.json", hex(verification))),
            &serde_json::to_vec_pretty(&summary)?,
        )?;
        println!(
            "Public corpus parity passed: {} accounts, {} retained transfers; smoke_only={}; private evidence: {}",
            manifest.account_count,
            manifest.transfer_count,
            manifest.smoke_only,
            options.evidence.display()
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use vos::agent::sdk::{DeploymentId, InvocationObservation, MethodMode};

        fn test_directory() -> PathBuf {
            let parent = PathBuf::from(
                std::env::var_os("JUST_TEMPDIR").expect("disk-backed JUST_TEMPDIR is required"),
            )
            .canonicalize()
            .unwrap();
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let root = parent.join(format!("public-corpus-resume-{}", hex(nonce)));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            directory(&root).unwrap();
            root
        }

        #[test]
        fn unfinished_verification_retains_exact_ids_and_completed_phase_gets_fresh_ids() {
            let root = test_directory();
            let run_nonce = hex([7; 32]);
            let first = verification_nonce(&root).unwrap();
            let initial = invocation_id(&run_nonce, 1001, &first).unwrap();
            let resumed = verification_nonce(&root).unwrap();
            assert_eq!(first, resumed);
            assert_eq!(initial, invocation_id(&run_nonce, 1001, &resumed).unwrap());
            assert_ne!(initial, invocation_id(&run_nonce, 1002, &resumed).unwrap());
            assert_ne!(
                initial,
                invocation_id(&hex([8; 32]), 1001, &resumed).unwrap()
            );
            publish(
                &root.join(format!("parity-{}.json", hex(first))),
                b"{\"format\":1}",
            )
            .unwrap();
            let second = verification_nonce(&root).unwrap();
            assert_ne!(first, second);
            assert_ne!(initial, invocation_id(&run_nonce, 1001, &second).unwrap());
            assert_eq!(second, verification_nonce(&root).unwrap());
            assert!(invocation_id(&hex([0; 32]), 1001, &first).is_err());
        }

        #[test]
        fn exact_resume_refuses_a_changed_business_seed_before_any_cli_delivery() {
            let root = test_directory();
            let unchanged = encoded(
                "create_account",
                &[
                    ("create_account_bytes", Value::Bytes(vec![1, 2, 3])),
                    ("batch_seed_timestamp", Value::U64(500_001)),
                ],
            );
            let changed = encoded(
                "create_account",
                &[
                    ("create_account_bytes", Value::Bytes(vec![1, 2, 3])),
                    ("batch_seed_timestamp", Value::U64(500_002)),
                ],
            );
            let path = root.join("intent-message");
            publish(&path, &unchanged).unwrap();
            assert!(publish(&path, &changed).is_err());
            assert_eq!(bytes(&path, 16 * 1024).unwrap(), unchanged);
            assert_ne!(digest(&unchanged), digest(&changed));
        }

        #[test]
        fn accepted_context_refuses_reordered_results_reinstallation_and_business_denial() {
            let mut reply = vos::agent::sdk::InvocationReply {
                invocation: InvocationId([1; 32]),
                actor: ActorId([2; 32]),
                incarnation: Hash([3; 32]),
                deployment: DeploymentId([4; 32]),
                mode: MethodMode::Linear,
                lane: None,
                status: InvocationStatus::Done,
                reply: Value::Bytes(vec![0]).encode(),
                gas_remaining: 1,
                observation: InvocationObservation {
                    linear_revision: Some(10),
                    ..Default::default()
                },
            };
            let mut previous = None;
            success(&reply, &mut previous).unwrap();
            assert!(success(&reply, &mut previous).is_err());
            reply.observation.linear_revision = Some(9);
            assert!(success(&reply, &mut previous).is_err());
            reply.observation.linear_revision = Some(11);
            reply.incarnation = Hash([5; 32]);
            assert!(success(&reply, &mut previous).is_err());
            reply.incarnation = Hash([3; 32]);
            reply.reply = Value::Bytes(vec![4]).encode();
            assert!(success(&reply, &mut previous).is_err());
            reply.reply = Value::Bytes(vec![0]).encode();
            success(&reply, &mut previous).unwrap();
            assert_eq!(previous, Some((Hash([3; 32]), 11)));
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        // Error strings describe refusal phases only; never render input bytes.
        eprintln!("Public corpus loader stopped: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("clerk_corpus_public supports the approved Linux host only");
    std::process::exit(1);
}
