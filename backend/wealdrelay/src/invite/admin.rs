// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The privileged half of the invite surface: issue, list, revoke, and "may I".
//!
//! `specs/backend/relay/invites.md`, "Admin controls" names four things an admin's
//! client has to be able to do, and until this module existed the store functions that
//! did them (`store::create`, `store::live_tokens`, `store::revoke`) had no call site
//! outside their own tests. This is the wire in front of them.
//!
//! ## What the relay is actually checking
//!
//! Not the `admit` capability. It cannot: capabilities live in the roster and the
//! roster is encrypted to the workspace group, so the relay holds no key that could
//! read one. What it can check is the access set, whose `authorizers` list is clear
//! device keys precisely so their signatures can be verified
//! (`specs/backend/relay/wire.md`, "The access set"). `identity.md` makes the authority
//! to rotate that set and the authority to admit the same power in practice, so the
//! authorizer list is the relay-visible form of "is an admin of this workspace".
//!
//! That is a narrower claim than the capability, and it is stated here rather than
//! implied, because a client that believed the relay was enforcing `admit` would be
//! believing something the relay is structurally unable to do. The record's own
//! `caps` list is signed by the issuer and validated by every client that reads it,
//! which is where the real capability rule lives.
//!
//! ## Why the answers here are not flat
//!
//! The redeem path answers `unavailable` to everything on purpose: it is reachable
//! without authentication, so any distinction it drew would confirm which tokens
//! exist. This path is the opposite. Its caller is an authenticated member of the
//! workspace who just uploaded a record, and telling them which rule they broke is
//! both safe and the difference between a fixable error and a mystery.

use sqlx::{PgPool, Row};

use super::store::{self, StoreError};
use super::{Invite, InviteError};
use crate::cbor::{self, CborError, Reader};

/// What an admin's client sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// "May this device issue invites here?"
    Authority,
    /// One signed record, whole.
    Create { record: Vec<u8> },
    /// Every invite this workspace has outstanding.
    List,
    /// End one, by token.
    Revoke { token: Vec<u8> },
    /// A freshly sealed `GroupInfo` for one scope of one live invite.
    ///
    /// `invites.md` requires a bundle refresh after a commit, because every commit
    /// makes the sealed candidate the record carries stale and a joiner that can
    /// only read a stale one parks until the invite expires. `store::refresh_bundle`
    /// has done this since it was written; until this arm existed, no frame reached
    /// it and the promise was code with no wire in front of it (BR-045).
    Refresh {
        token: Vec<u8>,
        group: Vec<u8>,
        epoch: u64,
        ct: Vec<u8>,
    },
}

/// What the relay answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Authority {
        may_issue: bool,
    },
    Created {
        token: Vec<u8>,
    },
    Live(Vec<Summary>),
    Revoked {
        token: Vec<u8>,
    },
    /// Whether the candidate was stored. `false` for a token this workspace does
    /// not own, a scope the record does not name, an invite that is no longer live,
    /// or ciphertext outside the bundle bound: one flat answer, because an admin has
    /// nothing to do differently about any of them and the alternative is a probe.
    Refreshed {
        accepted: bool,
    },
}

/// One live invite, as an admin's list shows it.
///
/// Deliberately thin. No code hash, because it is a credential's hash and this list is
/// a screen people share; no bundles, because they are large and the admin already has
/// them; no invitee identity, because the relay has never held one and this is not the
/// place to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub token: Vec<u8>,
    pub issued_at: u64,
    pub expires: u64,
    pub remaining: u8,
    pub seats: u8,
    pub scope_count: usize,
    pub state: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("the invite request is not canonical CBOR: {0}")]
    Encoding(#[from] CborError),
    #[error("invite request {0} is not one this relay knows")]
    UnknownRequest(u64),
    #[error("{0}")]
    Refused(#[from] InviteError),
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("this device is not an authorizer of this workspace")]
    NotAnAdmin,
}

impl AdminError {
    /// The wire code the caller is told.
    pub fn code(&self) -> crate::frame::ErrorCode {
        use crate::frame::ErrorCode;
        match self {
            Self::Encoding(_) => ErrorCode::NoncanonicalCbor,
            Self::UnknownRequest(_) => ErrorCode::MalformedHeader,
            Self::Refused(error) => error.code(),
            Self::Store(error) => error.code(),
            // The one refusal a client acts on differently: it hides the invite
            // control rather than showing an error, because the person is not an admin
            // and never will be by retrying.
            Self::NotAnAdmin => ErrorCode::WriterNotInAccessSet,
        }
    }
}

impl Request {
    /// The client's half of the wire, kept beside the relay's decoder.
    ///
    /// The same shape as `redeem::Request`, and for the same reason: a decoder
    /// proven only against bytes the test wrote by hand is a decoder proven
    /// against one author's reading of the spec. With both halves here the round
    /// trip is an assertion, and the encoder the relay's own tests drive is the
    /// one an implementer can read.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Authority => cbor::array(&[cbor::uint(0)]),
            Self::Create { record } => cbor::array(&[cbor::uint(1), cbor::bytes(record)]),
            Self::List => cbor::array(&[cbor::uint(2)]),
            Self::Revoke { token } => cbor::array(&[cbor::uint(3), cbor::bytes(token)]),
            Self::Refresh {
                token,
                group,
                epoch,
                ct,
            } => cbor::array(&[
                cbor::uint(4),
                cbor::bytes(token),
                cbor::bytes(group),
                cbor::uint(*epoch),
                cbor::bytes(ct),
            ]),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let fields = reader.array_header()?;
        let kind = reader.uint()?;
        let request = match (kind, fields) {
            (0, 1) => Self::Authority,
            (1, 2) => Self::Create {
                record: reader.bytes()?,
            },
            (2, 1) => Self::List,
            (3, 2) => Self::Revoke {
                token: reader.bytes()?,
            },
            (4, 5) => Self::Refresh {
                token: reader.bytes()?,
                group: reader.bytes()?,
                epoch: reader.uint()?,
                ct: reader.bytes()?,
            },
            _ => return Err(AdminError::UnknownRequest(kind)),
        };
        reader.finish()?;
        Ok(request)
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Authority { may_issue } => {
                cbor::array(&[cbor::uint(0), cbor::uint(u64::from(*may_issue))])
            }
            Self::Created { token } => cbor::array(&[cbor::uint(1), cbor::bytes(token)]),
            Self::Live(summaries) => {
                let encoded: Vec<Vec<u8>> = summaries.iter().map(Summary::encode).collect();
                cbor::array(&[cbor::uint(2), cbor::array(&encoded)])
            }
            Self::Revoked { token } => cbor::array(&[cbor::uint(3), cbor::bytes(token)]),
            Self::Refreshed { accepted } => {
                cbor::array(&[cbor::uint(4), cbor::uint(u64::from(*accepted))])
            }
        }
    }

    /// The client's half. See ``Request::encode`` for why both halves live here.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let fields = reader.array_header()?;
        let kind = reader.uint()?;
        let response = match (kind, fields) {
            (0, 2) => Self::Authority {
                may_issue: reader.uint()? != 0,
            },
            (1, 2) => Self::Created {
                token: reader.bytes()?,
            },
            (2, 2) => {
                let count = reader.array_header()?;
                let mut summaries = Vec::with_capacity(count);
                for _ in 0..count {
                    summaries.push(Summary::decode(&mut reader)?);
                }
                Self::Live(summaries)
            }
            (3, 2) => Self::Revoked {
                token: reader.bytes()?,
            },
            (4, 2) => Self::Refreshed {
                accepted: reader.uint()? != 0,
            },
            _ => return Err(AdminError::UnknownRequest(kind)),
        };
        reader.finish()?;
        Ok(response)
    }
}

impl Summary {
    pub fn encode(&self) -> Vec<u8> {
        cbor::array(&[
            cbor::bytes(&self.token),
            cbor::uint(self.issued_at),
            cbor::uint(self.expires),
            cbor::uint(u64::from(self.remaining)),
            cbor::uint(u64::from(self.seats)),
            cbor::uint(self.scope_count as u64),
            cbor::bytes(self.state.as_bytes()),
        ])
    }

    /// One summary, from a reader already positioned on it.
    fn decode(reader: &mut Reader) -> Result<Self, AdminError> {
        reader.array(7)?;
        Ok(Self {
            token: reader.bytes()?,
            issued_at: reader.uint()?,
            expires: reader.uint()?,
            // The wire carries these as unsigned integers and the type is a byte,
            // so a value out of range is a malformed field rather than something to
            // clamp: clamping would turn a corrupt list into a plausible one.
            remaining: u8::try_from(reader.uint()?).map_err(|_| CborError::OutOfRange(0))?,
            seats: u8::try_from(reader.uint()?).map_err(|_| CborError::OutOfRange(0))?,
            scope_count: reader.uint()? as usize,
            state: String::from_utf8(reader.bytes()?).map_err(|_| CborError::TypeMismatch {
                expected: "utf8 text",
            })?,
        })
    }
}

/// Whether this device may issue invites in this workspace.
///
/// One query, and no side channel in the answer: it is about the calling device and
/// says nothing about who else holds the authority or how many of them there are.
pub async fn may_issue(
    pool: &PgPool,
    workspace_id: &str,
    device_key: &[u8],
) -> Result<bool, StoreError> {
    let current = crate::access::store::current(pool, workspace_id)
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?;
    match current.prior {
        Some(prior) => Ok(prior.authorizers.iter().any(|key| key == device_key)),
        // No set at all. `wire.md` admits a device into `Bootstrapping` in exactly
        // this state and lets it publish the genesis set, so the honest answer is that
        // there is nobody to be an admin of yet: the first device to publish becomes
        // the sole authorizer, and until it does, nothing here can be issued because
        // there are no groups to scope an invite to either.
        None => Ok(false),
    }
}

/// Handle one request, for a session that has authenticated as `device_key` into
/// `workspace_id`.
///
/// Every arm other than ``Request::Authority`` re-checks authority rather than trusting
/// a check the caller made. Membership is re-read from the tables on every operation
/// everywhere else in this relay for the same reason: a session is long-lived and an
/// authority revoked mid-session must take effect on the next frame, not on the next
/// reconnect.
pub async fn handle(
    pool: &PgPool,
    workspace_id: &str,
    device_key: &[u8],
    request: Request,
    now_ms: i64,
) -> Result<Response, AdminError> {
    // `Authority` is the one request that is not gated on being an admin, because
    // its whole answer is whether the caller is one. Written as a guard on the gate
    // rather than as an early return with an `unreachable!` arm below it: that arm
    // was a line no test could ever execute, and an unreachable line in the
    // privileged path is a line nobody re-reads when the state machine changes.
    if !matches!(request, Request::Authority) && !may_issue(pool, workspace_id, device_key).await? {
        return Err(AdminError::NotAnAdmin);
    }

    match request {
        Request::Authority => Ok(Response::Authority {
            may_issue: may_issue(pool, workspace_id, device_key).await?,
        }),
        Request::Create { record } => {
            let invite = Invite::decode(&record)?;
            // The issuer is checked against the authenticated device, not merely
            // against the authorizer list. An admin may only issue invites signed by
            // its own key: without this, one authorizer could upload a record signed
            // by another authorizer's key if it ever obtained one, and the record's
            // own signature is what every client attributes the invite to.
            if invite.issuer != device_key {
                return Err(AdminError::NotAnAdmin);
            }
            // The declared workspace root and every scope must belong to the
            // workspace this session is authorized for. Without this the
            // `MissingWorkspaceRoot` check in `Invite::check` compares the record
            // with itself, so a record naming another workspace's group passes.
            // A group the relay has never seen is left to the redeem path: the
            // bootstrap invite is issued into an empty workspace whose root row
            // does not exist yet, and refusing it here would close that flow.
            for group in std::iter::once(&invite.workspace).chain(invite.scopes.iter()) {
                let owner = crate::access::store::workspace_of(pool, group)
                    .await
                    .map_err(|error| StoreError::Database(error.to_string()))?;
                if let Some(found) = owner {
                    if found != workspace_id {
                        return Err(AdminError::NotAnAdmin);
                    }
                }
            }
            let token = invite.token.clone();
            store::create(pool, workspace_id, &invite, now_ms).await?;
            Ok(Response::Created { token })
        }
        Request::List => Ok(Response::Live(summaries(pool, workspace_id).await?)),
        Request::Revoke { token } => {
            // The token is scoped to this workspace before anything is written, so an
            // admin of one workspace cannot revoke another workspace's invite by
            // presenting its token.
            let owned = store::belongs_to(pool, &token, workspace_id).await?;
            if owned {
                store::revoke(pool, &token).await?;
            }
            // The same answer either way. An admin pressing revoke twice should not
            // see an error, and an answer that distinguished "revoked" from "no such
            // token" would be a probe for tokens in other workspaces.
            Ok(Response::Revoked { token })
        }
        Request::Refresh {
            token,
            group,
            epoch,
            ct,
        } => {
            // Scoped to this workspace before anything is written, exactly as
            // `Revoke` is: an admin of one workspace must not be able to write a
            // candidate into another workspace's invite by presenting its token.
            // Everything else the upload has to satisfy (the invite still live, the
            // group actually one of its scopes, the ciphertext inside the bundle
            // bound) is `store::refresh_bundle`'s own gate, and it answers the same
            // `false` for all of them.
            if !store::belongs_to(pool, &token, workspace_id).await? {
                return Ok(Response::Refreshed { accepted: false });
            }
            let bundle = super::EncBundle { group, epoch, ct };
            let accepted = store::refresh_bundle(pool, &token, &bundle).await?;
            Ok(Response::Refreshed { accepted })
        }
    }
}

/// Every invite this workspace has outstanding, newest last.
pub async fn summaries(pool: &PgPool, workspace_id: &str) -> Result<Vec<Summary>, StoreError> {
    let rows = sqlx::query(
        "select i.token, \
                (extract(epoch from i.created_at) * 1000)::bigint as issued_at, \
                (extract(epoch from i.expires_at) * 1000)::bigint as expires, \
                i.remaining, i.uses, i.state, \
                (select count(*) from relay_invite_scope s where s.token = i.token) \
                    as scope_count \
         from relay_invite i \
         where i.workspace_id = $1 and i.bootstrap = false \
         order by i.created_at asc, i.token asc",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    .map_err(store::db_error)?;

    Ok(rows
        .iter()
        .map(|row| Summary {
            token: row.get::<Vec<u8>, _>("token"),
            issued_at: row.get::<i64, _>("issued_at").max(0) as u64,
            expires: row.get::<i64, _>("expires").max(0) as u64,
            // Both are byte-ranged by the schema's check constraints, so the clamp is
            // a total conversion rather than a fallback for a row that can exist.
            remaining: row.get::<i16, _>("remaining").clamp(0, 255) as u8,
            seats: row.get::<i16, _>("uses").clamp(0, 255) as u8,
            scope_count: row.get::<i64, _>("scope_count").max(0) as usize,
            state: row.get::<String, _>("state"),
        })
        .collect())
}
