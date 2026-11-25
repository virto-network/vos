//! The device group's proposal policy (`light-node.md` §3.4) and its
//! identities.
//!
//! - **Allowed:** Add and Remove, by value, in a commit with a path; a
//!   device's update is its own commit with a path and no proposals.
//!   Nothing else: no ReInit, no external commit or join, no PSK, no
//!   group-context change. Update proposals exist only by reference, which
//!   this build does not compile, and a commit never carries its own
//!   committer's Update by value.
//! - **The logged effect:** handshakes are encrypted, so only devices can
//!   check that a commit's proposals are the ones its log entry declares.
//!   A candidate is processed under [`Expected`]: its committer's
//!   credential, and the credentials it adds and removes, exactly; and the
//!   committer's renewed credential when the device set replaced its
//!   admin key, which its leaf must then take.
//! - **Identities:** a credential is a label, the device's sync key and
//!   admin key as bytes. Nothing binds a leaf's MLS keys to them: that a
//!   key package is the device's it names is the caller's to establish
//!   (where it took the key package from), and a committer that may add a
//!   device is trusted for the key package it adds.
//! - **Handshakes** are `PrivateMessage`s, padded (Padmé); a Welcome
//!   carries the ratchet tree, one for every new member.

use mls_rs::client_builder::PaddingMode;
use mls_rs::group::proposal::BorrowedProposal;
use mls_rs::group::{GroupContext, Roster};
use mls_rs::identity::{Credential, CredentialType, SigningIdentity};
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle, ProposalSource,
};
use mls_rs::time::MlsTime;
use mls_rs::{ExtensionList, MlsRules};
use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};

/// A device's credential: its sync key and its admin key, the leaf's
/// identity its sync key.
pub const CREDENTIAL_BYTES: usize = 64;

/// What the policy refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A proposal other than Add or Remove.
    Proposal,
    /// A proposal by reference.
    ByReference,
    /// An external commit.
    External,
    /// The committer is not the one the log names.
    Committer,
    /// The adds or the removals are not the ones the log declares.
    Effect,
    /// A credential that is not a device's.
    Credential,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refused::Proposal => "a proposal the device group does not allow",
            Refused::ByReference => "a proposal by reference",
            Refused::External => "an external commit",
            Refused::Committer => "a committer the log does not name",
            Refused::Effect => "proposals that are not the logged effect",
            Refused::Credential => "a credential that is not a device's",
        })
    }
}

impl std::error::Error for Refused {}

impl mls_rs_core::error::IntoAnyError for Refused {}

/// A commit's logged effect, which a received commit must be exactly: its
/// committer's credential, the credentials it adds and removes, and the
/// credential its committer's leaf takes, if another (`renewed`: the leaf
/// must take it; with none, the leaf keeps `committer`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expected {
    pub committer: Vec<u8>,
    pub adds: Vec<Vec<u8>>,
    pub removes: Vec<Vec<u8>>,
    pub renewed: Option<Vec<u8>>,
}

/// The device group's rules: the allow-list on what a device sends and
/// receives, and, for a candidate, its logged effect.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    pub(crate) expected: Option<Expected>,
}

impl Rules {
    /// The rules a candidate is processed under.
    pub fn expecting(expected: Expected) -> Self {
        Self {
            expected: Some(expected),
        }
    }
}

fn credential_of(identity: &SigningIdentity) -> Option<&[u8]> {
    match &identity.credential {
        Credential::Basic(basic) if basic.identifier.len() == CREDENTIAL_BYTES => {
            Some(&basic.identifier)
        }
        _ => None,
    }
}

/// `want` and `got` the same credentials, each as often.
fn same(want: &[Vec<u8>], mut got: Vec<Vec<u8>>) -> bool {
    let mut want = want.to_vec();
    want.sort();
    got.sort();
    want == got
}

impl MlsRules for Rules {
    type Error = Refused;

    fn filter_proposals(
        &self,
        direction: CommitDirection,
        source: CommitSource,
        roster: &Roster,
        _: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Refused> {
        let committer = match &source {
            CommitSource::ExistingMember(member) => member,
            CommitSource::NewMember(_) => return Err(Refused::External),
        };
        let mut adds = Vec::new();
        let mut removes = Vec::new();
        for info in proposals.iter_proposals() {
            if !matches!(info.source, ProposalSource::ByValue) {
                return Err(Refused::ByReference);
            }
            match info.proposal {
                BorrowedProposal::Add(add) => {
                    let credential =
                        credential_of(add.signing_identity()).ok_or(Refused::Credential)?;
                    adds.push(credential.to_vec());
                }
                BorrowedProposal::Remove(remove) => {
                    let member = roster
                        .member_with_index(remove.to_remove())
                        .map_err(|_| Refused::Effect)?;
                    let credential =
                        credential_of(&member.signing_identity).ok_or(Refused::Credential)?;
                    removes.push(credential.to_vec());
                }
                _ => return Err(Refused::Proposal),
            }
        }
        if let (CommitDirection::Receive, Some(expected)) = (direction, &self.expected) {
            if credential_of(&committer.signing_identity) != Some(&expected.committer[..]) {
                return Err(Refused::Committer);
            }
            if !same(&expected.adds, adds) || !same(&expected.removes, removes) {
                return Err(Refused::Effect);
            }
        }
        Ok(proposals)
    }

    fn commit_options(
        &self,
        _: &Roster,
        _: &GroupContext,
        _: &ProposalBundle,
    ) -> Result<CommitOptions, Refused> {
        Ok(CommitOptions::new()
            .with_path_required(true)
            .with_ratchet_tree_extension(true)
            .with_single_welcome_message(true)
            .with_allow_external_commit(false))
    }

    fn encryption_options(
        &self,
        _: &Roster,
        _: &GroupContext,
    ) -> Result<EncryptionOptions, Refused> {
        Ok(EncryptionOptions::new(true, PaddingMode::Padme))
    }
}

/// The device group's identities: a basic credential of a device's sync
/// key and admin key, the leaf's identity its sync key, a successor the
/// same credential, or the one renewal allowed: a leaf's device keys
/// change by its device's removal and a new add, and its admin key by the
/// renewal that follows a matured replacement. A leaf's signature key is
/// not compared here; [`crate::Mls::process`] requires a committer to
/// keep it. Every check against the device set is the caller's, through
/// [`Expected`].
#[derive(Clone, Debug, Default)]
pub struct Identity {
    renewal: Option<(Vec<u8>, Vec<u8>)>,
}

impl Identity {
    /// The identities allowing one leaf's credential `before` to be
    /// succeeded by `after`.
    pub fn renewing(before: Vec<u8>, after: Vec<u8>) -> Self {
        Self {
            renewal: Some((before, after)),
        }
    }
}

impl IdentityProvider for Identity {
    type Error = Refused;

    fn validate_member(
        &self,
        identity: &SigningIdentity,
        _: Option<MlsTime>,
        _: MemberValidationContext<'_>,
    ) -> Result<(), Refused> {
        credential_of(identity)
            .map(|_| ())
            .ok_or(Refused::Credential)
    }

    fn validate_external_sender(
        &self,
        _: &SigningIdentity,
        _: Option<MlsTime>,
        _: Option<&ExtensionList>,
    ) -> Result<(), Refused> {
        Err(Refused::External)
    }

    fn identity(&self, identity: &SigningIdentity, _: &ExtensionList) -> Result<Vec<u8>, Refused> {
        let credential = credential_of(identity).ok_or(Refused::Credential)?;
        Ok(credential[..32].to_vec())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<bool, Refused> {
        let (Some(before), Some(after)) = (credential_of(predecessor), credential_of(successor))
        else {
            return Err(Refused::Credential);
        };
        Ok(before == after
            || self
                .renewal
                .as_ref()
                .is_some_and(|(from, to)| from[..] == *before && to[..] == *after))
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}
