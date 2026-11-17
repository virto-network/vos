//! The onion service in process (`light-node.md` §6.1, §6.6), on arti:
//! one `TorClient` with full vanguards, the service's key inserted once
//! into arti's keystore from the gateway's own key file, and the
//! service-side proof of work behind the `tor-pow` feature and the file's
//! `pow`. Each rendezvous takes a place among the onion's circuits (past
//! them it is not answered) and a number; its streams to port 22 go to the
//! onion's SSH server ([`crate::circuits`]), any other refused as an
//! unserved port is, with `DONE`. A circuit holding no
//! stream for [`IDLE`] is let go.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{HsNickname, RendRequest, RunningOnionService};
use tor_proto::stream::IncomingStreamRequest;

use crate::circuits::{CircuitPlace, Onion};
use crate::config;

/// The service's nickname in arti's keystore and state.
pub const NICKNAME: &str = "vos-gateway";
/// How long a circuit may hold no stream before it is let go.
pub const IDLE: Duration = Duration::from_secs(60);

/// The rendezvous requests arti hands the service.
type Requests = std::pin::Pin<Box<dyn futures::Stream<Item = RendRequest> + Send>>;

/// The onion, once launched: its address, and the service arti runs.
pub struct Hosted {
    /// Its `.onion` address.
    pub address: String,
    /// The onion's key, the ed25519 public key its address encodes.
    pub key: [u8; 32],
    pub service: Arc<RunningOnionService>,
    pub task: tokio::task::JoinHandle<()>,
}

/// arti's client, bootstrapped with full vanguards, its state and cache
/// where the file names, over the arti configuration it names.
async fn client(
    onion: &config::Onion,
) -> Result<Arc<TorClient<tor_rtcompat::PreferredRuntime>>, String> {
    // rustls's provider, ring's as the gateway's TLS uses, before arti's
    // first TLS: an error is one installed already.
    let _ = rustls::crypto::ring::default_provider().install_default();
    TorClient::create_bootstrapped(client_config(onion)?)
        .await
        .map_err(|error| format!("arti's bootstrap: {error}"))
}

/// arti's configuration: the file's arti configuration, if it names one,
/// its state and cache, and full vanguards.
fn client_config(onion: &config::Onion) -> Result<TorClientConfig, String> {
    use tor_config::ExplicitOrAuto;
    use tor_guardmgr::VanguardMode;
    let (Some(state), Some(cache)) = (&onion.state, &onion.cache) else {
        return Err("an onion in process needs its state and cache directories".into());
    };
    let mut builder = match &onion.arti {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            // A key arti does not recognize is refused, not ignored: a
            // mis-spelled authority or network section would otherwise
            // leave the compiled-in live-Tor directory in place.
            let mut unknown = Vec::new();
            let de = toml::Deserializer::parse(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let builder: TorClientConfigBuilder =
                serde_ignored::deserialize(de, |key| unknown.push(key.to_string()))
                    .map_err(|error| format!("{}: {error}", path.display()))?;
            if !unknown.is_empty() {
                return Err(format!(
                    "{}: keys arti does not know: {}",
                    path.display(),
                    unknown.join(", ")
                ));
            }
            builder
        }
        None => TorClientConfigBuilder::default(),
    };
    builder
        .storage()
        .state_dir(CfgPath::new_literal(state))
        .cache_dir(CfgPath::new_literal(cache));
    builder
        .vanguards()
        .mode(ExplicitOrAuto::Explicit(VanguardMode::Full));
    builder.build().map_err(|error| error.to_string())
}

/// Launch the onion the file names, its streams served by `front`, on the
/// runtime until it ends.
pub async fn launch(onion: &config::Onion, front: Arc<Onion>) -> Result<Hosted, String> {
    if onion.pow && !cfg!(feature = "tor-pow") {
        return Err("pow = true needs a gateway built with the tor-pow feature".into());
    }
    let path = onion
        .key
        .as_ref()
        .ok_or("an onion in process needs its key file")?;
    let seed = config::seed(path)?;
    let tor = client(onion).await?;
    let keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(&seed);
    let key = keypair.verifying_key().to_bytes();
    let hsid = tor_hscrypto::pk::HsIdKeypair::from(
        tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&keypair),
    );
    let expected = tor_hscrypto::pk::HsIdKey::from(&hsid).id();
    let nickname: HsNickname = NICKNAME.parse().expect("a nickname");
    let per = onion.per_circuit();
    let mut service = OnionServiceConfigBuilder::default();
    service
        .nickname(nickname)
        .max_concurrent_streams_per_circuit(per.streams as u32)
        .enable_pow(onion.pow);
    if let Some(points) = onion.intro_points {
        service.num_intro_points(points);
    }
    if let (Some(rate), Some(burst)) = (onion.intro_rate, onion.intro_burst) {
        service.rate_limit_at_intro(Some(tor_hsservice::config::TokenBucketConfig::new(
            rate, burst,
        )));
    }
    let service = service.build().map_err(|error| error.to_string())?;
    // The key goes into arti's keystore once; a restart finds it there,
    // and the keystore's key must be the file's.
    let launched: Option<(Arc<RunningOnionService>, Requests)> =
        match tor.launch_onion_service_with_hsid(service.clone(), hsid) {
            Ok(launched) => launched.map(|(service, requests)| (service, Box::pin(requests) as _)),
            Err(_) => tor
                .launch_onion_service(service)
                .map_err(|error| format!("the onion service: {error}"))?
                .map(|(service, requests)| (service, Box::pin(requests) as _)),
        };
    let (service, requests) = launched.ok_or("the onion service is disabled")?;
    if service.onion_address() != Some(expected) {
        return Err(format!(
            "arti's keystore holds another key for {NICKNAME} than {}",
            path.display()
        ));
    }
    let address = expected.display_unredacted().to_string();
    let task = tokio::spawn(serve(requests, front));
    Ok(Hosted {
        address,
        key,
        service,
        task,
    })
}

/// Answer the rendezvous `requests`, each a circuit of its own while the
/// onion holds fewer than its limit.
async fn serve(mut requests: Requests, front: Arc<Onion>) {
    let numbers = AtomicU32::new(0);
    while let Some(rendezvous) = requests.next().await {
        let Some(place) = front.circuits.circuit() else {
            let _ = rendezvous.reject().await;
            continue;
        };
        let circuit = numbers.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(circuit_streams(
            rendezvous,
            circuit,
            place,
            Arc::clone(&front),
        ));
    }
}

/// Serve one circuit's streams until it closes, or holds none for
/// [`IDLE`].
async fn circuit_streams(
    rendezvous: RendRequest,
    circuit: u32,
    _place: CircuitPlace,
    front: Arc<Onion>,
) {
    let Ok(mut streams) = rendezvous.accept().await else {
        return;
    };
    loop {
        let request = match tokio::time::timeout(IDLE, streams.next()).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(_) if front.circuits.streams(circuit) == 0 => return,
            Err(_) => continue,
        };
        let port = match request.request() {
            IncomingStreamRequest::Begin(begin) => begin.port(),
            _ => 0,
        };
        if !front.serves(port) {
            front.circuits.refused();
            let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
            continue;
        }
        let Ok(stream) = request.accept(Connected::new_empty()).await else {
            continue;
        };
        let front = Arc::clone(&front);
        tokio::spawn(async move { front.serve(stream, circuit, port).await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private network's authorities and fallback, as a test network's
    /// tooling writes them: they reach the built config, the file's own
    /// directories and weakened vanguards do not, and a key arti does not
    /// know is refused.
    #[test]
    fn an_arti_configuration_names_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("arti.toml");
        let network = r#"
[storage]
state_dir = "/elsewhere/state"

[vanguards]
mode = "lite"

[path_rules]
ipv4_subnet_family_prefix = 33

[address_filter]
allow_local_addrs = true

[[tor_network.fallback_caches]]
rsa_identity = "A13FF5397B8F66EB7A7BA85A753DB4E8C812D2F0"
ed_identity = "c3BCgjTnffMvOA2d1Ui1EtZgbDlOXAEoVoOU9m1bfFU"
orports = ["127.0.0.1:5100"]

[tor_network.authorities]
v3idents = ["705B85A1A414461D2BA13FBA815BEB322FE45594"]
uploads = [["127.0.0.1:7100"]]
downloads = [["127.0.0.1:7100"]]
votes = [["127.0.0.1:7100"]]
"#;
        std::fs::write(&path, network).unwrap();
        let mut onion = config::Onion {
            state: Some(dir.path().join("state")),
            cache: Some(dir.path().join("cache")),
            ..config::Onion::default()
        };
        let public = format!("{:?}", client_config(&onion).unwrap());
        onion.arti = Some(path.clone());
        let private = format!("{:?}", client_config(&onion).unwrap());
        assert!(private.contains("705b85a1a414461d2ba13fba815beb322fe45594"));
        assert!(private.contains("127.0.0.1:5100"));
        assert!(!public.contains("705b85a1a414461d2ba13fba815beb322fe45594"));
        let state = format!("{:?}", dir.path().join("state").display().to_string());
        assert!(private.contains(&state));
        assert!(
            !private.contains("/elsewhere"),
            "the file's directories apply"
        );
        assert!(
            private.contains("Full"),
            "full vanguards survive a file that asks for less"
        );
        // A key arti does not know is refused, not ignored.
        std::fs::write(&path, format!("[tor-network]\n{network}")).unwrap();
        assert!(client_config(&onion).unwrap_err().contains("does not know"));
        // A file that cannot be read is refused.
        onion.arti = Some(dir.path().join("none.toml"));
        assert!(client_config(&onion).is_err());
    }
}
