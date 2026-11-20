//! An actor program's schema: its methods. The program carries it first in
//! its read-only data, so the agent reads it from a loaded machine and the
//! node from the blob, without running anything.

use alloc::vec::Vec;

use crate::abi::Kind;
use crate::defaults::{HANDLER_GAS, MAX_HANDLER_GAS};
use crate::ids::MethodId;
use crate::{Decode, Encode};

/// The section starts with these bytes, then the schema's length as four
/// little-endian bytes, then the schema: its methods, each without its
/// credential guard, then, only when the program is the credential actor,
/// a method has a guard or the actor asks an [`Admission`], the
/// [`Credentials`] that say which, then, only when it asks one, the
/// [`Admission`]. A program with none of them carries its methods alone.
pub const MAGIC: [u8; 4] = *b"VOSS";

/// The most a schema may hold: what a refine reads before installing.
pub const MAX_LEN: usize = 64 << 10;
pub const MAX_METHODS: usize = 1024;
pub const MAX_NAME: usize = 256;

/// The longest name a credential guard's scope takes.
pub const MAX_GUARD_NAME: usize = 64;

/// An installed record carries it whole; a program's section as
/// [`Schema::section`] writes it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Schema {
    pub methods: Vec<MethodSchema>,
    /// The program is its agent's credential actor (`#[actor(credentials)]`):
    /// its install records the row [`crate::keys::credentials`], whose ring
    /// the agent's auth guards read.
    pub credentials: bool,
    /// What ingress asks of its agent's requests
    /// (`#[actor(known_keys, onion_only)]`): its install records the row
    /// [`crate::keys::admission`], which ingress reads.
    pub admission: Admission,
}

/// What an agent's ingress asks of the requests it takes, as one actor of
/// the agent declares (`light-node.md` §3.3). Ingress reads it from the row
/// [`crate::keys::admission`] its install writes; the agent's refine does
/// not check it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Admission {
    /// A call that would create a session is refused unless its key is a
    /// row of the declaring actor's [`ADMITTED`] table, looked up before
    /// its signature is checked.
    pub known_keys: bool,
    /// A call, query, workflow read, credentialed call or schema read is
    /// refused unless the gateway marked it as received on its onion
    /// service; an unmarked one counts as clearnet.
    pub onion_only: bool,
}

impl Admission {
    /// Whether it asks anything.
    pub const fn asks(self) -> bool {
        self.known_keys || self.onion_only
    }
}

/// The table of the admitted keys an actor declaring
/// [`Admission::known_keys`] keeps: its rows' keys the ed25519 keys, any
/// value; ingress reads a row's presence ([`crate::keys::admitted`]).
pub const ADMITTED: &str = "admitted";

/// A method in a program's section: its schema but its guard.
#[derive(Encode, Decode)]
struct Plain {
    id: MethodId,
    name: Vec<u8>,
    kind: Kind,
    role: Option<Vec<u8>>,
    gas: Option<u64>,
    linearizable: bool,
}

/// What follows a section's methods when the program is the credential
/// actor, guards a method or asks an [`Admission`]: the mark, and each
/// guard by its method.
#[derive(Encode, Decode)]
pub struct Credentials {
    pub actor: bool,
    pub guards: Vec<(MethodId, CredentialGuard)>,
}

/// The device kernel a proven call's proof is of, for a method to run it
/// (`identity-and-authority.md` §5, `light-node.md` §4.3), from its
/// handler's attribute: one of the stock kernels of the agent's credential
/// actor, whose checks ingress runs, or a device kernel of the method's own
/// actor, whose claim its handler checks at apply.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum CredentialGuard {
    /// `#[msg(credential = Auth("name"))]`: the stock `auth` kernel, an
    /// `Anonymous` origin of the scope `name` gives, 1 to
    /// [`MAX_GUARD_NAME`] bytes, in this space, agent and instance; `once`
    /// admits each nullifier once in the scope: each device's secret gives
    /// it its own, so a member once a device.
    #[codec(index = 0)]
    Auth { name: Vec<u8>, once: bool },
    /// `#[msg(credential = Owner)]`: the stock
    /// `owner` kernel, an `Owner` origin, whose digest the handler compares
    /// with the row it debits.
    #[codec(index = 1)]
    Owner,
    /// `#[msg(proven = name)]`: the device kernel `name` of this actor, a
    /// `Kernel` origin naming its program; the handler takes the claim as
    /// its first argument and checks it.
    #[codec(index = 2)]
    Kernel { name: Vec<u8> },
}

/// The stock kernels' names: the device kernels of the credential actor.
pub mod stock {
    /// Auth's: a member's leaf under a root of the ring, and its nullifier
    /// in a scope.
    pub const AUTH: &str = "auth";
    /// Owner's: the secret behind an owner digest.
    pub const OWNER: &str = "owner";
}

impl CredentialGuard {
    /// Whether `caller` is an origin it admits: its kernel's.
    pub fn admits(&self, caller: &crate::ids::Principal) -> bool {
        use crate::ids::Principal;
        matches!(
            (self, caller),
            (CredentialGuard::Auth { .. }, Principal::Anonymous { .. })
                | (CredentialGuard::Owner, Principal::Owner(_))
                | (CredentialGuard::Kernel { .. }, Principal::Kernel { .. })
        )
    }

    /// The device kernel's method name, and whether it is a stock kernel of
    /// the credential actor rather than one of the method's own actor.
    pub fn kernel(&self) -> (&[u8], bool) {
        match self {
            CredentialGuard::Auth { .. } => (stock::AUTH.as_bytes(), true),
            CredentialGuard::Owner => (stock::OWNER.as_bytes(), true),
            CredentialGuard::Kernel { name } => (name, false),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct MethodSchema {
    /// [`crate::ids::derive_id`] of the method's name in `vos/method/`.
    pub id: MethodId,
    pub name: Vec<u8>,
    pub kind: Kind,
    /// The role a caller needs, by name; installing maps it to a role
    /// byte.
    pub role: Option<Vec<u8>>,
    /// The gas limit the handler requests; the agent caps it by policy.
    /// `None` takes the agent's default.
    pub gas: Option<u64>,
    /// A query that always reads after a read index, whatever consistency
    /// its client asks (`#[msg(linearizable)]`). It governs the query a
    /// client names: a method that query calls reads the caller's snapshot,
    /// marked or not.
    pub linearizable: bool,
    /// The device kernel a caller proves, if any: only a command takes one,
    /// with no role and not linearizable. A method with none refuses an
    /// `Anonymous`, `Owner` or `Kernel` caller, and one with a guard refuses
    /// every other caller. Boxed, so every method does not carry its size.
    pub credential: Option<alloc::boxed::Box<CredentialGuard>>,
}

impl MethodSchema {
    /// The gas limit a handler, or a workflow's step, runs with: the one it
    /// requests, or [`HANDLER_GAS`], capped at [`MAX_HANDLER_GAS`] by
    /// policy.
    pub fn gas_limit(&self) -> u64 {
        self.gas.unwrap_or(HANDLER_GAS).min(MAX_HANDLER_GAS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// The read-only data does not start with a schema section.
    Missing,
    /// The section is larger than [`MAX_LEN`] or ends early.
    Size,
    Undecodable,
    /// Too many methods, or a name too long.
    Limits,
    /// Method id 0, which is reserved.
    ReservedId,
    Duplicate(MethodId),
    /// A method marked linearizable that is not a query: what runs through
    /// the log reads its state as it applies.
    Linearizable(MethodId),
    /// A guard on a method that is not a command, or beside a role or
    /// `linearizable`, an auth guard's name empty or past
    /// [`MAX_GUARD_NAME`], or a kernel guard naming no device kernel of the
    /// program.
    Credential(MethodId),
}

impl Schema {
    /// The section's bytes.
    pub fn section(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let plain: Vec<Plain> = self
            .methods
            .iter()
            .map(|method| Plain {
                id: method.id,
                name: method.name.clone(),
                kind: method.kind,
                role: method.role.clone(),
                gas: method.gas,
                linearizable: method.linearizable,
            })
            .collect();
        plain.encode_to(&mut body);
        let guards: Vec<(MethodId, CredentialGuard)> = self
            .methods
            .iter()
            .filter_map(|method| Some((method.id, (**method.credential.as_ref()?).clone())))
            .collect();
        if self.credentials || !guards.is_empty() || self.admission.asks() {
            Credentials {
                actor: self.credentials,
                guards,
            }
            .encode_to(&mut body);
        }
        if self.admission.asks() {
            self.admission.encode_to(&mut body);
        }
        let mut section = Vec::with_capacity(8 + body.len());
        section.extend_from_slice(&MAGIC);
        section.extend_from_slice(&(body.len() as u32).to_le_bytes());
        section.extend_from_slice(&body);
        section
    }

    /// Read and validate the schema at the start of a program's read-only
    /// data.
    pub fn read(ro_data: &[u8]) -> Result<Self, SchemaError> {
        if ro_data.get(..4) != Some(&MAGIC[..]) {
            return Err(SchemaError::Missing);
        }
        let len = ro_data
            .get(4..8)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")) as usize)
            .ok_or(SchemaError::Size)?;
        if len > MAX_LEN {
            return Err(SchemaError::Size);
        }
        let body = ro_data.get(8..8 + len).ok_or(SchemaError::Size)?;
        let (plain, used) = <Vec<Plain>>::decode(body).map_err(|_| SchemaError::Undecodable)?;
        let mut schema = Schema {
            methods: plain
                .into_iter()
                .map(|method| MethodSchema {
                    id: method.id,
                    name: method.name,
                    kind: method.kind,
                    role: method.role,
                    gas: method.gas,
                    linearizable: method.linearizable,
                    credential: None,
                })
                .collect(),
            credentials: false,
            admission: Admission::default(),
        };
        if used != len {
            let (credentials, read) =
                Credentials::decode(&body[used..]).map_err(|_| SchemaError::Undecodable)?;
            let rest = &body[used + read..];
            if !rest.is_empty() {
                schema.admission = Admission::decode_exact(rest).ok_or(SchemaError::Undecodable)?;
                // An admission that asks nothing says nothing: the section
                // carries none.
                if !schema.admission.asks() {
                    return Err(SchemaError::Undecodable);
                }
            }
            // An empty mark says nothing, unless an admission follows it.
            if !credentials.actor && credentials.guards.is_empty() && !schema.admission.asks() {
                return Err(SchemaError::Undecodable);
            }
            schema.credentials = credentials.actor;
            for (id, guard) in credentials.guards {
                let method = schema
                    .methods
                    .iter_mut()
                    .find(|method| method.id == id)
                    .ok_or(SchemaError::Credential(id))?;
                if method.credential.is_some() {
                    return Err(SchemaError::Credential(id));
                }
                method.credential = Some(alloc::boxed::Box::new(guard));
            }
        }
        schema.validate()?;
        Ok(schema)
    }

    /// Unique, non-zero ids within the limits, and only queries marked
    /// linearizable.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.methods.len() > MAX_METHODS {
            return Err(SchemaError::Limits);
        }
        // The device kernels' names, sorted: a kernel guard's name is looked
        // up, not compared with every method's.
        let mut kernels: Vec<&[u8]> = self
            .methods
            .iter()
            .filter(|method| method.kind == Kind::Device)
            .map(|method| method.name.as_slice())
            .collect();
        kernels.sort_unstable();
        let mut ids: Vec<u32> = Vec::with_capacity(self.methods.len());
        for method in &self.methods {
            if method.name.len() > MAX_NAME
                || method
                    .role
                    .as_ref()
                    .is_some_and(|role| role.len() > MAX_NAME)
            {
                return Err(SchemaError::Limits);
            }
            if method.id.0 == 0 {
                return Err(SchemaError::ReservedId);
            }
            if method.linearizable && method.kind != Kind::Query {
                return Err(SchemaError::Linearizable(method.id));
            }
            if let Some(guard) = &method.credential
                && !guard_fits(method, guard, &kernels)
            {
                return Err(SchemaError::Credential(method.id));
            }
            ids.push(method.id.0);
        }
        // Sorted, a duplicate sits next to its twin: a refine validates a
        // schema of a thousand methods without comparing every pair.
        ids.sort_unstable();
        match ids.windows(2).find(|pair| pair[0] == pair[1]) {
            Some(pair) => Err(SchemaError::Duplicate(MethodId(pair[0]))),
            None => Ok(()),
        }
    }

    /// Whether a method's guard names a stock kernel, which needs the
    /// agent's credential actor.
    pub fn guards_stock(&self) -> bool {
        self.methods.iter().any(|method| {
            matches!(
                method.credential.as_deref(),
                Some(CredentialGuard::Auth { .. } | CredentialGuard::Owner)
            )
        })
    }

    pub fn method(&self, id: MethodId) -> Option<&MethodSchema> {
        self.methods.iter().find(|method| method.id == id)
    }

    /// The id of the method named `name`.
    pub fn method_id(&self, name: &str) -> Option<MethodId> {
        self.methods
            .iter()
            .find(|method| method.name == name.as_bytes())
            .map(|method| method.id)
    }
}

/// Whether `guard` may sit on `method`: a command's, with no role and not
/// linearizable; an auth guard's name within its bounds, a kernel guard's
/// one of `kernels`, the program's device kernels' names, sorted.
fn guard_fits(method: &MethodSchema, guard: &CredentialGuard, kernels: &[&[u8]]) -> bool {
    let named = match guard {
        CredentialGuard::Auth { name, .. } => (1..=MAX_GUARD_NAME).contains(&name.len()),
        CredentialGuard::Owner => true,
        CredentialGuard::Kernel { name } => kernels.binary_search(&name.as_slice()).is_ok(),
    };
    named && method.kind == Kind::Command && method.role.is_none() && !method.linearizable
}
