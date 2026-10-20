//! The space's venue: the node's client of it (`vos node run --venue`),
//! the node's account there (`vos node venue-account`), and the operator's
//! and controller's calls (`vos space venue`), each over the Kreivo
//! client's pinned calls. Built with the `kreivo` feature; a production
//! build refuses to select Kreivo until its spaces pallet meets the
//! conformance vectors.

use vos_node::{Space, VenueWithAccount};

use crate::args::VenueKind;

/// The client a node anchors through at `kind`'s node `url`, signing as
/// the node's own account there, for the space `space`.
pub fn anchoring(
    kind: VenueKind,
    url: &str,
    space: Option<&Space>,
) -> Result<VenueWithAccount, String> {
    let VenueKind::Kreivo = kind;
    vos_venue::kreivo::selectable(vos_venue::kreivo::Build::current())?;
    let space = space
        .filter(|space| space.genesis().is_some())
        .ok_or("a venue anchors a founded space: `--space`, its genesis beside it")?
        .id();
    kreivo::anchoring(url.to_string(), space)
}

#[cfg(not(feature = "kreivo"))]
mod kreivo {
    use vos_node::VenueWithAccount;
    use vos_wire::SpaceId;

    pub fn anchoring(_: String, _: SpaceId) -> Result<VenueWithAccount, String> {
        Err("this vos is built without the Kreivo client (the `kreivo` feature)".into())
    }
}

#[cfg(feature = "kreivo")]
pub use kreivo::{VenueCommand, account_of};

#[cfg(feature = "kreivo")]
mod kreivo {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use clap::Subcommand;
    use vos_node::VenueWithAccount;
    use vos_venue::VenueClient;
    use vos_venue::kreivo::calls::{self, Call, keys};
    use vos_venue::kreivo::chain::{self, ChainTransport};
    use vos_venue::kreivo::transport::{Sent, Transport};
    use vos_venue::kreivo::{AccountSeed, KreivoVenue, Options, Sender};
    use vos_wire::SpaceId;

    use crate::key_bytes;

    pub fn anchoring(url: String, space: SpaceId) -> Result<VenueWithAccount, String> {
        Ok(Box::new(move |seed: AccountSeed| {
            let signer = chain::keypair(seed.secret())?;
            let transport = ChainTransport::connect(&url, signer)
                .map_err(|lost| format!("{url}: {}", lost.0))?;
            let venue =
                KreivoVenue::connect(Arc::new(transport), &[space], space, Options::default())
                    .map_err(|lost| format!("{url}: {}", lost.0))?;
            Ok(Arc::new(venue) as Arc<dyn VenueClient>)
        }))
    }

    /// The account a node's account key signs as.
    pub fn account_of(seed: &AccountSeed) -> Result<[u8; 32], String> {
        Ok(chain::account(&chain::keypair(seed.secret())?))
    }

    /// Where the call goes, and who signs it.
    #[derive(clap::Args)]
    pub struct Signing {
        /// The Kreivo node: `ws://` or `wss://`.
        #[arg(long)]
        url: String,
        /// A file holding the signer's secret URI: a dev key (`//Alice`), a
        /// phrase, or a 32-byte mini secret in hex (`0x…`).
        #[arg(long)]
        signer_file: PathBuf,
    }

    impl Signing {
        fn transport(&self) -> Result<ChainTransport, String> {
            let uri =
                std::fs::read_to_string(&self.signer_file).map_err(crate::at(&self.signer_file))?;
            let signer = chain::keypair_from_uri(&uri)?;
            ChainTransport::connect(&self.url, signer).map_err(|lost| lost.0)
        }
    }

    #[derive(Subcommand)]
    pub enum VenueCommand {
        /// Register the space (call 0), its founder's signature over the
        /// registration made with a founding node's key. Fund its sovereign
        /// account, printed first, with the registration deposit before.
        Register {
            #[command(flatten)]
            signing: Signing,
            /// The space file, its genesis beside it.
            #[arg(long)]
            space: PathBuf,
            /// A founding node's data directory, its node stopped.
            #[arg(long)]
            data: PathBuf,
            /// The controller's account, in hex.
            #[arg(long)]
            controller: String,
            /// The first window anchored at the venue: the open one, by the
            /// venue's time, by default.
            #[arg(long)]
            start_window: Option<u64>,
        },
        /// The space's authorities, by its controller.
        Authority {
            #[command(subcommand)]
            command: AuthorityCommand,
        },
        /// Set the space's spend budget per window (call 10), by its
        /// controller.
        Budget {
            #[command(flatten)]
            signing: Signing,
            /// The space's id, in hex.
            #[arg(long)]
            space_id: String,
            /// The most the sovereign account spends in a window, in the
            /// chain's smallest unit.
            #[arg(long)]
            max: u128,
        },
    }

    #[derive(Subcommand)]
    pub enum AuthorityCommand {
        /// Add an authority, or update its paired anchor key (call 2).
        Add {
            #[command(flatten)]
            signing: Signing,
            #[arg(long)]
            space_id: String,
            /// The node's account (`vos node venue-account`), in hex.
            #[arg(long)]
            who: String,
            /// The node's anchor key it signs anchors with, in hex.
            #[arg(long)]
            anchor_key: Option<String>,
        },
        /// Remove an authority and its paired anchor key (call 3).
        Remove {
            #[command(flatten)]
            signing: Signing,
            #[arg(long)]
            space_id: String,
            #[arg(long)]
            who: String,
        },
    }

    /// Send `call` and report what the venue did with it.
    fn send(transport: ChainTransport, call: Call) -> Result<(), String> {
        let sender = Sender::new(Arc::new(transport), Duration::from_secs(1));
        match sender.call(&call.bytes()) {
            Ok(Sent::Included(outcome)) => {
                for event in &outcome.events {
                    println!("{event:?}");
                }
                match outcome.failure {
                    None => Ok(()),
                    Some(failure) => Err(match failure.pallet() {
                        Some(error) => format!("refused: {error:?}"),
                        None => format!("refused: {failure:?}"),
                    }),
                }
            }
            Ok(Sent::Landed) => {
                eprintln!("vos: it landed; its answer was lost: read the space to see its effect");
                Ok(())
            }
            Err(unsent) => Err(format!("not included: {unsent:?}")),
        }
    }

    impl VenueCommand {
        pub fn run(self) -> Result<(), String> {
            match self {
                VenueCommand::Register {
                    signing,
                    space,
                    data,
                    controller,
                    start_window,
                } => {
                    let genesis = vos_node::read_genesis(&space)?
                        .ok_or("the space has no genesis: `vos space up` founds it")?;
                    let space = vos_wire::vos_anchor::space_id(&genesis);
                    let controller = key_bytes(&controller)?;
                    let transport = signing.transport()?;
                    eprintln!(
                        "vos: the space's sovereign account, which holds its deposits and pays \
                         its authorities' fees: {}",
                        hex::encode(calls::sovereign(&space))
                    );
                    let venue =
                        vos_wire::vos_anchor::VenueId(transport.genesis().map_err(|lost| lost.0)?);
                    let start_window = match start_window {
                        Some(window) => window,
                        None => {
                            let now = transport
                                .storage(&keys::now())
                                .map_err(|lost| lost.0)?
                                .and_then(|bytes| calls::read::<u64>(&bytes))
                                .ok_or("the venue has no time")?;
                            genesis.clock.window(now).unwrap_or(0)
                        }
                    };
                    let digest = vos_wire::vos_anchor::register_digest(
                        &venue,
                        &space,
                        &controller,
                        start_window,
                    );
                    let (founder_key, founder_sig) = vos_node::sign_with_node_key(&data, &digest)?;
                    send(
                        transport,
                        Call::Register {
                            genesis: genesis.encode(),
                            controller,
                            start_window,
                            founder_key,
                            founder_sig,
                        },
                    )
                }
                VenueCommand::Authority {
                    command:
                        AuthorityCommand::Add {
                            signing,
                            space_id,
                            who,
                            anchor_key,
                        },
                } => send(
                    signing.transport()?,
                    Call::AddAuthority {
                        space: key_bytes(&space_id)?,
                        who: key_bytes(&who)?,
                        anchor_key: anchor_key.as_deref().map(key_bytes).transpose()?,
                    },
                ),
                VenueCommand::Authority {
                    command:
                        AuthorityCommand::Remove {
                            signing,
                            space_id,
                            who,
                        },
                } => send(
                    signing.transport()?,
                    Call::RemoveAuthority {
                        space: key_bytes(&space_id)?,
                        who: key_bytes(&who)?,
                    },
                ),
                VenueCommand::Budget {
                    signing,
                    space_id,
                    max,
                } => send(
                    signing.transport()?,
                    Call::SetBudget {
                        space: key_bytes(&space_id)?,
                        max_spend_per_window: max,
                    },
                ),
            }
        }
    }
}
