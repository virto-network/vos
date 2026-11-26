//! The group's proposal policy and its identities.
//!
//! - **Allowed:** Add and Remove, by value, in a commit with a path; a
//!   member's update is its own commit with a path and no proposals.
//!   Nothing else: no ReInit, no external commit or join, no PSK, no
//!   group-context change. Update proposals exist only by reference, which
//!   this build does not compile, and a commit never carries its own
//!   committer's Update by value.
//! - **The expected effect:** handshakes are encrypted, so only members
//!   can check that a commit's proposals are the ones its committer
//!   declared to the caller beside it. A candidate is processed under
//!   [`Expected`]: its committer's credential, and the credentials it adds
//!   and removes, exactly; and the committer's renewed credential when the
//!   caller expects a renewal, which its leaf must then take.
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

/// A member's credential: 64 bytes, the leaf's identity its first 32;
/// what the bytes are is the caller's.
pub(crate) const CREDENTIAL_BYTES: usize = 64;

/// What the policy refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A proposal other than Add or Remove.
    Proposal,
    /// A proposal by reference.
    ByReference,
    /// An external commit.
    External,
    /// The committer is not the one expected.
    Committer,
    /// The adds or the removals are not the ones expected.
    Effect,
    /// A credential that is not a 64-byte basic credential.
    Credential,
}

impl mls_rs_core::error::IntoAnyError for Refused {}

/// A commit's expected effect, which a received commit must be exactly: an
/// encrypted commit with a path by `committer`, adding and removing
/// exactly the credentials of `adds` and `removes`, its committer's leaf
/// taking `renewed` if one is expected and keeping `committer` otherwise,
/// and keeping its signature key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expected {
    pub committer: Vec<u8>,
    pub adds: Vec<Vec<u8>>,
    pub removes: Vec<Vec<u8>>,
    pub renewed: Option<Vec<u8>>,
}

/// The group's rules: the allow-list on what a member sends and receives,
/// and, for a candidate, its expected effect.
#[derive(Clone, Debug, Default)]
pub(crate) struct Rules {
    pub(crate) expected: Option<Expected>,
}

impl Rules {
    /// The rules a candidate is processed under.
    pub(crate) fn expecting(expected: Expected) -> Self {
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
        let CommitSource::ExistingMember(committer) = &source else {
            return Err(Refused::External);
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

/// The group's identities: a 64-byte basic credential, the leaf's identity
/// its first 32 bytes (what the bytes are is the caller's); a successor the
/// same credential, or the one renewal allowed. A leaf's signature key is
/// not compared here; [`crate::Mls::process`] requires a committer to keep
/// it. Every check of who may be a member is the caller's, through
/// [`Expected`]. A credential is a label: nothing binds a leaf's MLS keys
/// to the keys it names, so that a key package is the member's it names
/// is the caller's to establish, and a committer that may add a member is
/// trusted for the key package it adds.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    renewal: Option<(Vec<u8>, Vec<u8>)>,
}

impl Identity {
    /// The identities allowing one leaf's credential `before` to be
    /// succeeded by `after`.
    pub(crate) fn renewing(before: Vec<u8>, after: Vec<u8>) -> Self {
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
