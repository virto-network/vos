//! The Tor policy (`light-node.md` §6.5, E22): which route a request may
//! take to a space, decided before a byte of it leaves the device.
//!
//! - **Tor is the default for every space:** each request goes through one
//!   of the space's pinned onions.
//! - **A per-space opt-out for key-signed calls** ([`Routes::opt_out`]):
//!   the member's own signed calls and queries, and s4's screens, may take
//!   the clearnet where the space offers it and the user accepted
//!   [`OPT_OUT_WARNING`].
//! - **No clearnet route at all** for anonymous requests (proven calls and
//!   the reads that prepare them: [`Purpose::anonymous`]) nor for the
//!   personal agent's and `Homes`' traffic, whatever the user or the space
//!   chose; nor for any request to a space that declares itself onion-only
//!   (the home is, E17). Such a request finding no onion is refused here
//!   ([`Refused`]), so nothing is sent.
//! - **A request's kind matches its purpose** ([`Purpose::admits`]): a
//!   proven call goes only as [`Purpose::Proven`], and that purpose
//!   carries nothing else, so a credentialed call never rides a key-signed
//!   connection that may be on the clearnet.

use vos_api::Kind;
use vos_wire::credentials::Onion;

/// The key the routes of the home whose handle is `handle` are kept under,
/// apart from every enrolled space's ([`space`]): a
/// space whose enrollment names a home's handle reaches none of the home's
/// routes, and the home's refresh none of its.
pub fn home(handle: &[u8; 32]) -> [u8; 32] {
    keyed(b"vos.light.home-routes", handle)
}

/// The key the routes of the space an enrollment names by `handle` are
/// kept under: of another domain than every home's ([`home`]), so no
/// handle a server names, a home's key included, reaches a home's routes.
pub fn space(handle: &[u8; 32]) -> [u8; 32] {
    keyed(b"vos.light.space-routes", handle)
}

fn keyed(domain: &[u8], handle: &[u8; 32]) -> [u8; 32] {
    crate::hash(domain, &[handle])
}

/// How a request reaches a space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Route {
    /// Through one of the space's onion services.
    Onion = 0,
    /// Over the clearnet, to the gateway's own SSH port.
    Clearnet = 1,
}

/// What a request is for: each purpose its own isolation group, so the
/// gateway cannot join two of them by circuit or by SSH key
/// (`light-node.md` §6.2, §8 H10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Purpose {
    /// A proven call: anonymous, each on a connection of its own, a spare
    /// built ahead.
    Proven = 0,
    /// A read that names nothing of the member's but must not link to it:
    /// the node's time, the onion set's refresh. Anonymous, each on a
    /// connection of its own, a spare built ahead; a timed fetch carries a
    /// `Time` and the one query it dates on one connection, opened for
    /// them alone.
    Fetch = 1,
    /// The credential tree's feed and the space's device window: anonymous,
    /// one long-lived connection, as every member reads the same.
    Feed = 2,
    /// The member's own key-signed calls and queries in the space: one
    /// connection a space.
    Member = 3,
    /// The personal agent's and `Homes`' traffic: onion only.
    Personal = 4,
    /// The personal agent's background schedule, apart from the
    /// foreground's: onion only.
    Background = 5,
    /// s4's screen session, whose SSH is s4's own, carried as bytes.
    Screens = 6,
}

impl Purpose {
    pub const ALL: [Purpose; 7] = [
        Purpose::Proven,
        Purpose::Fetch,
        Purpose::Feed,
        Purpose::Member,
        Purpose::Personal,
        Purpose::Background,
        Purpose::Screens,
    ];

    /// Whether its requests carry no identity of the member's: they never
    /// leave the device over the clearnet.
    pub fn anonymous(self) -> bool {
        matches!(self, Purpose::Proven | Purpose::Fetch | Purpose::Feed)
    }

    /// Whether it has no clearnet route in any space: the anonymous
    /// purposes, the personal agent's and `Homes`'.
    pub fn onion_only(self) -> bool {
        self.anonymous() || matches!(self, Purpose::Personal | Purpose::Background)
    }

    /// Whether each request takes a connection of its own, closed after its
    /// answer: a circuit and an SSH key each.
    pub fn one_shot(self) -> bool {
        matches!(self, Purpose::Proven | Purpose::Fetch)
    }

    /// Whether a request of `kind` may go under this purpose: a proven
    /// call only as [`Purpose::Proven`], which carries nothing else; the
    /// other anonymous purposes reads alone; a kind the gateway's
    /// subsystem does not relay never; s4's screens no node-API request at
    /// all.
    pub fn admits(self, kind: Kind) -> bool {
        match self {
            Purpose::Screens => false,
            Purpose::Proven => kind == Kind::Credentialed,
            // An anonymous purpose carries reads alone, so no key-signed
            // call joins its circuit.
            Purpose::Fetch | Purpose::Feed => matches!(
                kind,
                Kind::NodeKey
                    | Kind::Time
                    | Kind::AgentInfo
                    | Kind::Schema
                    | Kind::Devices
                    | Kind::Query
            ),
            _ => kind.relayed() && kind != Kind::Credentialed,
        }
    }
}

/// A gateway's clearnet SSH port, as enrollment pins it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clearnet {
    pub host: String,
    pub port: u16,
    /// The ed25519 SSH host key its port presents.
    pub ssh_host_key: [u8; 32],
}

/// What the chrome shows before a space's opt-out takes effect. The
/// space's screens are key-signed too (s4's session with its gateway), so
/// a sign-in or payment asked there is asked over the clearnet: its proof
/// still travels over Tor, but the operators can join the device's
/// address to it.
pub const OPT_OUT_WARNING: &str = "Without Tor, this space's operators see this device's network \
     address with every call it signs and on this space's screens, so they can tell which \
     sign-ins and payments asked there came from this device. Proofs still travel over Tor, \
     and your personal space stays on Tor.";

/// A registrar's onion set is usable: 1 to
/// [`MAX_ONIONS`](vos_wire::credentials::MAX_ONIONS) onions, no key twice.
pub(crate) fn usable_onions(onions: &[Onion]) -> bool {
    let repeated = onions
        .iter()
        .enumerate()
        .any(|(at, onion)| onions[..at].iter().any(|seen| seen.key == onion.key));
    !onions.is_empty() && onions.len() <= vos_wire::credentials::MAX_ONIONS && !repeated
}

/// A space's routes: the onions it pins, the clearnet port it may offer,
/// and the choices the space and the user made.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Routes {
    /// The space's onion set, as enrollment pinned it and a refresh keeps
    /// it.
    pub onions: Vec<Onion>,
    /// Its gateways' clearnet SSH port, if it offers one.
    pub clearnet: Option<Clearnet>,
    /// The space declared itself onion-only, or it is the home (E17).
    pub onion_only: bool,
    /// The user opted this space's key-signed calls out of Tor.
    opted_out: bool,
}

impl Routes {
    /// A space's routes as enrollment pins them: its onion set, its
    /// clearnet port if it offers one, whether it declared itself
    /// onion-only; Tor on for it.
    pub fn new(onions: Vec<Onion>, clearnet: Option<Clearnet>, onion_only: bool) -> Self {
        Self {
            onions,
            clearnet,
            onion_only,
            opted_out: false,
        }
    }

    /// A space reached through `onions` alone.
    pub fn onions(onions: Vec<Onion>) -> Self {
        Self::new(onions, None, false)
    }

    /// Opt this space's key-signed calls out of Tor, the chrome having
    /// shown [`OPT_OUT_WARNING`]. Refused where the space offers no
    /// clearnet port or is onion-only; anonymous calls and the personal
    /// agent's traffic stay on Tor whatever it says.
    pub fn opt_out(&mut self) -> Result<(), Refused> {
        if self.onion_only {
            return Err(Refused::OnionOnly);
        }
        if self.clearnet.is_none() {
            return Err(Refused::NoClearnet);
        }
        self.opted_out = true;
        Ok(())
    }

    /// Back on Tor for every call.
    pub fn opt_in(&mut self) {
        self.opted_out = false;
    }

    /// Whether the user opted this space's key-signed calls out of Tor.
    pub fn opted_out(&self) -> bool {
        self.opted_out
    }

    /// The route a request of `purpose` takes: the onion unless it is a
    /// key-signed one the user opted out for in a space that offers the
    /// clearnet. Refused, nothing sent, when that route does not exist.
    pub fn route(&self, purpose: Purpose) -> Result<Route, Refused> {
        let clearnet =
            self.opted_out && !purpose.onion_only() && !self.onion_only && self.clearnet.is_some();
        if clearnet {
            return Ok(Route::Clearnet);
        }
        if !self.onions.is_empty() {
            return Ok(Route::Onion);
        }
        Err(if purpose.anonymous() {
            Refused::Anonymous
        } else if purpose.onion_only() || self.onion_only {
            Refused::OnionOnly
        } else {
            Refused::NoOnion
        })
    }
}

/// Why the client sent nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// An anonymous request, and the space pins no onion: it never takes
    /// the clearnet.
    Anonymous,
    /// The personal agent's or `Homes`' traffic, or an onion-only space's,
    /// and no onion is pinned.
    OnionOnly,
    /// A key-signed request, no onion pinned, and the user has not opted
    /// the space out of Tor.
    NoOnion,
    /// An opt-out where the space offers no clearnet port.
    NoClearnet,
    /// A request whose kind its purpose does not carry.
    Kind,
    /// The space is not one the client knows.
    UnknownSpace,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refused::Anonymous => "an anonymous call leaves this device only through Tor",
            Refused::OnionOnly => "this traffic goes through the space's onion alone",
            Refused::NoOnion => "the space pins no onion, and Tor is on for it",
            Refused::NoClearnet => "the space offers no route but Tor",
            Refused::Kind => "this request does not go under its purpose",
            Refused::UnknownSpace => "no such space",
        })
    }
}

impl std::error::Error for Refused {}

#[cfg(test)]
mod tests {
    use super::*;

    fn onion(byte: u8) -> Onion {
        Onion {
            key: [byte; 32],
            ssh_host_key: [byte ^ 0xff; 32],
        }
    }

    fn clearnet() -> Clearnet {
        Clearnet {
            host: "gateway.example".into(),
            port: 2222,
            ssh_host_key: [7; 32],
        }
    }

    /// On a clearnet-only path (the space offers a clearnet port and pins
    /// no onion, and the user opted out), every anonymous request and the
    /// personal agent's traffic are refused; only key-signed ones go.
    #[test]
    fn anonymous_calls_are_refused_on_a_clearnet_only_path() {
        let mut routes = Routes {
            clearnet: Some(clearnet()),
            ..Routes::default()
        };
        routes.opt_out().unwrap();
        for purpose in Purpose::ALL {
            let route = routes.route(purpose);
            match purpose {
                Purpose::Proven | Purpose::Fetch | Purpose::Feed => {
                    assert_eq!(route, Err(Refused::Anonymous), "{purpose:?}")
                }
                Purpose::Personal | Purpose::Background => {
                    assert_eq!(route, Err(Refused::OnionOnly), "{purpose:?}")
                }
                Purpose::Member | Purpose::Screens => {
                    assert_eq!(route, Ok(Route::Clearnet), "{purpose:?}")
                }
            }
        }
    }

    /// With an onion pinned, the opt-out moves only key-signed requests to
    /// the clearnet; without the opt-out every request takes the onion.
    #[test]
    fn tor_is_the_default_and_the_opt_out_covers_key_signed_calls() {
        let mut routes = Routes {
            onions: vec![onion(1)],
            clearnet: Some(clearnet()),
            ..Routes::default()
        };
        for purpose in Purpose::ALL {
            assert_eq!(routes.route(purpose), Ok(Route::Onion));
        }
        routes.opt_out().unwrap();
        for purpose in Purpose::ALL {
            let expected = if purpose.onion_only() {
                Route::Onion
            } else {
                Route::Clearnet
            };
            assert_eq!(routes.route(purpose), Ok(expected), "{purpose:?}");
        }
        routes.opt_in();
        assert_eq!(routes.route(Purpose::Member), Ok(Route::Onion));
    }

    /// An onion-only space, the home among them, has no clearnet route and
    /// takes no opt-out; a space without a clearnet port takes none either;
    /// a key-signed request to a space pinning no onion waits for one.
    #[test]
    fn onion_only_spaces_take_no_opt_out() {
        let mut home = Routes {
            onions: vec![onion(2)],
            clearnet: Some(clearnet()),
            onion_only: true,
            ..Routes::default()
        };
        assert_eq!(home.opt_out(), Err(Refused::OnionOnly));
        assert!(!home.opted_out());
        for purpose in Purpose::ALL {
            assert_eq!(home.route(purpose), Ok(Route::Onion));
        }
        home.onions.clear();
        assert_eq!(home.route(Purpose::Member), Err(Refused::OnionOnly));
        let mut onions = Routes::onions(vec![onion(3)]);
        assert_eq!(onions.opt_out(), Err(Refused::NoClearnet));
        let unpinned = Routes {
            clearnet: Some(clearnet()),
            ..Routes::default()
        };
        assert_eq!(unpinned.route(Purpose::Member), Err(Refused::NoOnion));
    }

    /// A proven call goes only as `Proven`, which carries nothing else;
    /// the screens carry no node-API request; no purpose carries a kind
    /// the gateway does not relay.
    #[test]
    fn a_requests_kind_matches_its_purpose() {
        let carriers: Vec<Purpose> = Purpose::ALL
            .into_iter()
            .filter(|purpose| purpose.admits(Kind::Credentialed))
            .collect();
        assert_eq!(carriers, [Purpose::Proven]);
        for kind in Kind::ALL {
            assert!(!Purpose::Screens.admits(kind));
            assert_eq!(Purpose::Proven.admits(kind), kind == Kind::Credentialed);
            if !kind.relayed() {
                assert!(Purpose::ALL.iter().all(|purpose| !purpose.admits(kind)));
            }
        }
        for purpose in [Purpose::Fetch, Purpose::Member, Purpose::Personal] {
            assert!(purpose.admits(Kind::Query) && purpose.admits(Kind::Time));
        }
        for purpose in [Purpose::Fetch, Purpose::Feed] {
            assert!(!purpose.admits(Kind::Call), "{purpose:?}");
        }
        assert!(Purpose::Member.admits(Kind::Call) && Purpose::Personal.admits(Kind::Call));
        assert!(!Purpose::Member.admits(Kind::Install));
    }

    /// An opted-out space's screens take the clearnet with its key-signed
    /// calls, so the warning says what that hands its operators: the
    /// device's address beside the sign-ins its screens ask for.
    #[test]
    fn the_opt_out_moves_the_screens_and_its_warning_says_so() {
        let mut routes = Routes::new(vec![onion(1)], Some(clearnet()), false);
        assert_eq!(routes.route(Purpose::Screens), Ok(Route::Onion));
        routes.opt_out().unwrap();
        assert_eq!(routes.route(Purpose::Screens), Ok(Route::Clearnet));
        assert_eq!(routes.route(Purpose::Proven), Ok(Route::Onion));
        assert!(OPT_OUT_WARNING.contains("screens"));
        assert!(OPT_OUT_WARNING.contains("sign-ins"));
        assert!(!OPT_OUT_WARNING.contains("Sign-ins and other anonymous calls"));
    }

    /// A home's routes are kept under a key of their own, never a handle
    /// an enrollment could name.
    #[test]
    fn a_homes_routes_key_is_not_its_handle() {
        let handle = [9; 32];
        assert_ne!(home(&handle), handle);
        assert_ne!(home(&handle), home(&[8; 32]));
        // A server naming the home's key as its space's handle reaches
        // another key still.
        assert_ne!(space(&home(&handle)), home(&handle));
        assert_ne!(space(&handle), home(&handle));
    }
}
