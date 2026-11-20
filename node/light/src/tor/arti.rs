//! arti's client, one a process: its state where the app keeps its private
//! files, plain bridges, a bounded bootstrap, dormancy; and the dialer it
//! makes, onion streams each on the circuit their isolation token names.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::{BridgeConfigBuilder, TorClientConfigBuilder};
use arti_client::status::BlockageKind;
use arti_client::{DormantMode, ErrorKind, HasKind, StreamPrefs, TorClient};
use tor_rtcompat::PreferredRuntime;

use super::dial::{Circuit, Dial, Dialing, Stream, Target, Unpublished};

/// The onion address's version byte (rend-spec-v3 §6).
const ONION_VERSION: u8 = 3;

/// The `.onion` address of the onion service whose ed25519 key is `key`:
/// `base32(key ‖ checksum ‖ 3)`, the checksum the first two bytes of
/// `SHA3-256(".onion checksum" ‖ key ‖ 3)`.
pub fn onion_address(key: &[u8; 32]) -> String {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(key);
    hasher.update([ONION_VERSION]);
    let checksum = hasher.finalize();
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&checksum[..2]);
    bytes.push(ONION_VERSION);
    let mut address = data_encoding::BASE32_NOPAD.encode(&bytes);
    address.make_ascii_lowercase();
    address + ".onion"
}

/// The ed25519 key an `.onion` address encodes, its version and checksum
/// checked: `None` for anything else.
pub fn onion_key(address: &str) -> Option<[u8; 32]> {
    let address = address.to_ascii_lowercase();
    let encoded = address.strip_suffix(".onion")?;
    let bytes = data_encoding::BASE32_NOPAD
        .decode(encoded.to_ascii_uppercase().as_bytes())
        .ok()?;
    let key: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
    (bytes.len() == 35 && onion_address(&key) == address).then_some(key)
}

/// Why a pasted bridge line was not taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// It names a pluggable transport (obfs4, Snowflake, WebTunnel), which
    /// this client does not run: plain bridges only.
    Transport(String),
    /// It is not a bridge line.
    Line(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::Transport(transport) => write!(
                f,
                "a {transport} bridge needs a pluggable transport; paste a plain bridge line"
            ),
            BridgeError::Line(problem) => write!(f, "not a bridge line: {problem}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// A plain bridge from a line as the Tor Project's distribution gives it
/// (`[bridge] <address:port> <fingerprint>`); one naming a transport is
/// refused.
pub fn bridge(line: &str) -> Result<BridgeConfigBuilder, BridgeError> {
    let line = line.trim();
    let line = match line.split_once(char::is_whitespace) {
        Some((first, rest)) if first.eq_ignore_ascii_case("bridge") => rest.trim(),
        _ => line,
    };
    // A line naming a transport leads with its name, its address second.
    let mut words = line.split_whitespace();
    if let (Some(first), Some(second)) = (words.next(), words.next())
        && first.parse::<std::net::SocketAddr>().is_err()
        && second.parse::<std::net::SocketAddr>().is_ok()
    {
        return Err(BridgeError::Transport(first.to_string()));
    }
    let bridge: BridgeConfigBuilder =
        line.parse()
            .map_err(|error: arti_client::config::BridgeParseError| {
                BridgeError::Line(error.to_string())
            })?;
    bridge
        .build()
        .map_err(|error| BridgeError::Line(error.to_string()))?;
    Ok(bridge)
}

/// Where arti keeps its state, and how it reaches the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorConfig {
    /// A directory in the app's private storage: arti's state (`state`)
    /// and its directory cache (`cache`) under it, so a later start skips
    /// the cold bootstrap. The app keeps it out of the operating system's
    /// backup.
    pub directory: PathBuf,
    /// Plain bridge lines the user pasted: none, the public relays.
    pub bridges: Vec<String>,
    /// How long a bootstrap may take: through an unreachable bridge arti
    /// waits without end (`light-node.md` §6.2).
    pub bootstrap: Duration,
}

impl TorConfig {
    /// arti's state and cache under `directory`, no bridge, a bootstrap
    /// bounded at two minutes: a cold one took up to 15 s on the phones.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            bridges: Vec::new(),
            bootstrap: Duration::from_secs(120),
        }
    }
}

/// Why Tor did not start, as the chrome names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// The device's clock is wrong: Tor refuses a directory outside its
    /// validity.
    Clock,
    /// No pasted bridge answered within the bootstrap's time.
    Bridge,
    /// A bridge line was not taken.
    BridgeLine(BridgeError),
    /// The network blocks Tor, or the device is offline: arti's word.
    Blocked(String),
    /// Tor's directory could not be fetched, and no blockage was named.
    Directory(String),
    /// arti's state directory is not private to the app, or cannot be
    /// made: arti checks its permissions, whatever the environment says.
    State(String),
    /// Any other failure, as arti reports it.
    Tor(String),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::Clock => f.write_str(
                "Tor cannot start: this device's clock is wrong. Set the date and time \
                 automatically, then try again.",
            ),
            BootstrapError::Bridge => f.write_str("this bridge does not answer"),
            BootstrapError::BridgeLine(error) => error.fmt(f),
            BootstrapError::Blocked(why) => write!(f, "this network blocks Tor: {why}"),
            BootstrapError::Directory(why) => write!(f, "Tor's directory: {why}"),
            BootstrapError::State(why) => write!(f, "Tor's state directory: {why}"),
            BootstrapError::Tor(why) => write!(f, "Tor: {why}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// The earliest time a right clock can show: the pinned arti's release,
/// 2026-10-01, in seconds since the epoch.
const RELEASED: u64 = 1_790_812_800;

/// What a failed bootstrap left to name it by.
#[derive(Clone, Debug, Default)]
struct Signals {
    /// arti's error's kind and text, if it ended with one rather than
    /// running out of time.
    error: Option<(ErrorKind, String)>,
    /// The blockage arti's status showed last.
    blockage: Option<(BlockageKind, String)>,
    /// arti's skew estimate was noteworthy (its status's text names the
    /// clock), or the device's clock is before the pinned arti's release.
    skewed: bool,
    /// The bootstrap went through bridges.
    bridges: bool,
}

/// Name a bootstrap's failure: the clock whenever any signal blames it;
/// a bootstrap through bridges that ran out of time, the bridge's; then
/// the blockage arti named, a directory that could not be fetched, or
/// arti's error.
fn named(signals: Signals) -> BootstrapError {
    let clock = signals.skewed
        || matches!(signals.error, Some((ErrorKind::ClockSkew, _)))
        || matches!(signals.blockage, Some((BlockageKind::ClockSkewed, _)));
    if clock {
        return BootstrapError::Clock;
    }
    if let Some((ErrorKind::FsPermissions, why)) = signals.error {
        return BootstrapError::State(why);
    }
    match (signals.error, signals.blockage) {
        (None, _) if signals.bridges => BootstrapError::Bridge,
        (_, Some((BlockageKind::CantBootstrap, why))) => BootstrapError::Directory(why),
        (_, Some((_, why))) => BootstrapError::Blocked(why),
        (Some((_, why)), None) => BootstrapError::Tor(why),
        (None, None) => BootstrapError::Blocked("no answer from the Tor network".into()),
    }
}

/// The process's arti client.
#[derive(Clone)]
pub struct Tor {
    client: Arc<TorClient<PreferredRuntime>>,
    deadline: Duration,
    bridges: bool,
}

impl Tor {
    /// arti's client over `config`'s directory, not yet bootstrapped, on
    /// the current tokio runtime. The directory is made private to the
    /// app if it is missing; arti refuses one that is not, its
    /// `ARTI_FS_DISABLE_PERMISSION_CHECKS` ignored.
    pub fn new(config: &TorConfig) -> Result<Self, BootstrapError> {
        // rustls's provider, ring's as russh's, before arti's first TLS:
        // an error is one installed already.
        let _ = rustls::crypto::ring::default_provider().install_default();
        if !config.directory.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&config.directory)
                .map_err(|error| BootstrapError::State(error.to_string()))?;
        }
        let mut builder = TorClientConfigBuilder::from_directories(
            config.directory.join("state"),
            config.directory.join("cache"),
        );
        builder.storage().permissions().ignore_environment();
        for line in &config.bridges {
            let bridge = bridge(line).map_err(BootstrapError::BridgeLine)?;
            builder.bridges().bridges().push(bridge);
        }
        let built = builder
            .build()
            .map_err(|error| BootstrapError::Tor(error.to_string()))?;
        let client = TorClient::builder()
            .config(built)
            .create_unbootstrapped()
            .map_err(|error| match error.kind() {
                ErrorKind::FsPermissions => BootstrapError::State(error.to_string()),
                _ => BootstrapError::Tor(error.to_string()),
            })?;
        Ok(Self {
            client,
            deadline: config.bootstrap,
            bridges: !config.bridges.is_empty(),
        })
    }

    /// Bootstrap, within the configured time: a failure named.
    pub async fn bootstrap(&self) -> Result<(), BootstrapError> {
        let ended = match tokio::time::timeout(self.deadline, self.client.bootstrap()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => Some((error.kind(), error.to_string())),
            Err(_) => None,
        };
        let status = self.client.bootstrap_status();
        let before_release = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(true, |now| now.as_secs() < RELEASED);
        Err(named(Signals {
            error: ended,
            blockage: status
                .blocked()
                .map(|blockage| (blockage.kind(), blockage.to_string())),
            skewed: status.to_string().contains("Clock is ") || before_release,
            bridges: self.bridges,
        }))
    }

    /// arti's client itself.
    pub fn client(&self) -> &Arc<TorClient<PreferredRuntime>> {
        &self.client
    }
}

impl Dial for Tor {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        match target.clone() {
            Target::Onion { address, port } => {
                let client = Arc::clone(&self.client);
                Box::pin(async move {
                    let mut prefs = StreamPrefs::new();
                    prefs.set_isolation(circuit.token());
                    let stream = client
                        .connect_with_prefs((address.as_str(), port), &prefs)
                        .await
                        .map_err(|error| match error.kind() {
                            ErrorKind::OnionServiceNotFound
                            | ErrorKind::OnionServiceNotRunning
                            | ErrorKind::OnionServiceConnectionFailed => {
                                Unpublished::error(error.to_string())
                            }
                            _ => io::Error::other(error),
                        })?;
                    Ok(Box::new(stream) as Stream)
                })
            }
            Target::Clearnet { host, port } => Box::pin(async move {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                Ok(Box::new(stream) as Stream)
            }),
        }
    }

    fn set_dormant(&self, dormant: bool) {
        self.client.set_dormant(if dormant {
            DormantMode::Soft
        } else {
            DormantMode::Normal
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Tor Project's onion: its key, from the address, gives the
    /// address back.
    #[test]
    fn an_onions_address_is_its_key_encoded() {
        let address = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        let decoded = data_encoding::BASE32_NOPAD
            .decode(address.trim_end_matches(".onion").to_uppercase().as_bytes())
            .unwrap();
        let key: [u8; 32] = decoded[..32].try_into().unwrap();
        assert_eq!(onion_address(&key), address);
        assert_eq!(onion_key(address), Some(key));
        let mut flipped = address.to_string().into_bytes();
        flipped[3] = if flipped[3] == b'a' { b'b' } else { b'a' };
        assert_eq!(onion_key(std::str::from_utf8(&flipped).unwrap()), None);
        assert_eq!(onion_key(address.trim_end_matches(".onion")), None);
        assert_eq!(onion_key(&address.to_uppercase()), Some(key));
        let mut other = key;
        other[0] ^= 1;
        assert_ne!(onion_address(&other)[52..56], address[52..56]);
    }

    /// A plain bridge line is taken, with or without its `Bridge` word; a
    /// transport's is refused, as is a line that is none.
    #[test]
    fn only_plain_bridges_are_taken() {
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";
        for line in [
            format!("192.0.2.1:443 {fingerprint}"),
            format!("Bridge 192.0.2.1:443 {fingerprint}"),
            format!("bridge 192.0.2.1:443 {fingerprint}"),
            format!("  [2001:db8::1]:9001 {fingerprint}\n"),
        ] {
            bridge(&line).unwrap();
        }
        let obfs4 = format!("obfs4 192.0.2.1:443 {fingerprint} cert=AAAA iat-mode=0");
        assert_eq!(
            bridge(&obfs4).err(),
            Some(BridgeError::Transport("obfs4".into()))
        );
        assert_eq!(
            bridge(&format!("Bridge {obfs4}")).err(),
            Some(BridgeError::Transport("obfs4".into()))
        );
        assert_eq!(
            bridge(&format!("snowflake 192.0.2.3:80 {fingerprint}")).err(),
            Some(BridgeError::Transport("snowflake".into()))
        );
        assert!(matches!(bridge("not a bridge"), Err(BridgeError::Line(_))));
        assert!(matches!(bridge(""), Err(BridgeError::Line(_))));
    }

    /// The clock is named whenever arti blamed it; a bootstrap through
    /// bridges that ran out of time is the bridge's; otherwise arti's
    /// blockage, or its error.
    #[test]
    fn a_bootstrap_failure_is_named() {
        let why = || "why".to_string();
        let named = |error: Option<ErrorKind>, blockage: Option<BlockageKind>, skewed, bridges| {
            named(Signals {
                error: error.map(|kind| (kind, why())),
                blockage: blockage.map(|kind| (kind, why())),
                skewed,
                bridges,
            })
        };
        use BlockageKind as B;
        use ErrorKind as K;
        let clock = BootstrapError::Clock;
        assert_eq!(named(Some(K::ClockSkew), None, false, false), clock);
        assert_eq!(named(None, Some(B::ClockSkewed), false, true), clock);
        assert_eq!(
            named(
                Some(K::TorNetworkTimeout),
                Some(B::CantBootstrap),
                true,
                false
            ),
            clock
        );
        assert_eq!(named(None, Some(B::CantBootstrap), true, true), clock);
        assert_eq!(named(None, None, false, true), BootstrapError::Bridge);
        assert_eq!(
            named(None, Some(B::Offline), false, true),
            BootstrapError::Bridge
        );
        assert_eq!(
            named(None, Some(B::Filtering), false, false),
            BootstrapError::Blocked(why())
        );
        assert_eq!(
            named(None, Some(B::CantBootstrap), false, false),
            BootstrapError::Directory(why())
        );
        assert_eq!(
            named(Some(K::FsPermissions), None, false, false),
            BootstrapError::State(why())
        );
        assert_eq!(
            named(Some(K::Internal), None, false, false),
            BootstrapError::Tor(why())
        );
        assert!(BootstrapError::Clock.to_string().contains("clock"));
    }
}
