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
/// credential guard, then, only when the program is the credential actor
/// or a method has a guard, the [`Credentials`] that say which. A program
/// with neither carries the section it carried before guards were.
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
}

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
/// actor or guards a method: the mark, and each guard by its method.
#[derive(Encode, Decode)]
pub struct Credentials {
    pub actor: bool,
    pub guards: Vec<(MethodId, CredentialGuard)>,
}

/// What a credentialed call's origin must be for a method to run it
/// (`identity-and-authority.md` §5), from its handler's attribute. Its
/// index is the statement's kind.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum CredentialGuard {
    /// `#[msg(credential = Auth("name"))]`: an `Anonymous` origin of the
    /// scope `name` gives, 1 to [`MAX_GUARD_NAME`] bytes, in this space,
    /// agent and instance. `device` names the attestable kernel whose
    /// device proofs it also takes; `once` admits each nullifier once in
    /// the scope.
    #[codec(index = 0)]
    Auth {
        name: Vec<u8>,
        device: Option<Vec<u8>>,
        once: bool,
    },
    /// `#[msg(credential = Owner)]`: an `Owner` origin, whose digest the
    /// handler compares with the row it debits.
    #[codec(index = 1)]
    Owner,
}

impl CredentialGuard {
    /// The statement's kind it admits, its encoding's index.
    pub const fn kind(&self) -> u8 {
        match self {
            CredentialGuard::Auth { .. } => 0,
            CredentialGuard::Owner => 1,
        }
    }

    /// Whether `caller` is an origin it admits: its kind's.
    pub fn admits(&self, caller: &crate::ids::Principal) -> bool {
        use crate::ids::Principal;
        matches!(
            (self, caller),
            (CredentialGuard::Auth { .. }, Principal::Anonymous { .. })
                | (CredentialGuard::Owner, Principal::Owner(_))
        )
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
    /// The credential a caller proves, if any: only a command takes one,
    /// with no role and not linearizable. A method with none refuses an
    /// `Anonymous` or `Owner` caller, and one with a guard refuses every
    /// other caller. Boxed, so every method does not carry its size.
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
    /// A credential guard on a method that is not a command, or beside a
    /// role or `linearizable`, or an auth guard's name empty or past
    /// [`MAX_GUARD_NAME`], or its device kernel's past [`MAX_NAME`].
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
        if self.credentials || !guards.is_empty() {
            Credentials {
                actor: self.credentials,
                guards,
            }
            .encode_to(&mut body);
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
        };
        if used != len {
            let credentials =
                Credentials::decode_exact(&body[used..]).ok_or(SchemaError::Undecodable)?;
            // An empty mark says nothing: the section carries none.
            if !credentials.actor && credentials.guards.is_empty() {
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
                && !guard_fits(method, guard)
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

    /// Whether a method holds an auth guard, which needs the agent's
    /// credential actor.
    pub fn guards_auth(&self) -> bool {
        self.methods.iter().any(|method| {
            matches!(
                method.credential.as_deref(),
                Some(CredentialGuard::Auth { .. })
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
/// linearizable, an auth guard's names within their bounds.
fn guard_fits(method: &MethodSchema, guard: &CredentialGuard) -> bool {
    let names = match guard {
        CredentialGuard::Auth { name, device, .. } => {
            (1..=MAX_GUARD_NAME).contains(&name.len())
                && device
                    .as_ref()
                    .is_none_or(|device| device.len() <= MAX_NAME)
        }
        CredentialGuard::Owner => true,
    };
    names && method.kind == Kind::Command && method.role.is_none() && !method.linearizable
}
