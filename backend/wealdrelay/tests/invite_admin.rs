// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The privileged half of the invite surface: issue, list, revoke, and "may I".
//!
//! `specs/backend/relay/invites.md`, "Admin controls". The module landed with no
//! test of any kind, which step 20's coverage assertion is what found, and it is
//! the half of the invite surface where a mistake is expensive: the redeem path
//! answers `unavailable` to everything and therefore cannot leak much, while this
//! one is authenticated, tells the caller which rule it broke, and writes.
//!
//! What is worth proving, and what this file is organised around:
//!
//! - Authority is the access set's `authorizers` list and nothing else. A member
//!   who is not an authorizer is refused; a workspace with no set at all has no
//!   admins yet rather than everybody being one, which is the answer that stops the
//!   first `CONNECT` from being able to issue invites into an unfounded workspace.
//! - An admin may only issue an invite signed by its own key. Without that check an
//!   authorizer holding another authorizer's record could upload it, and the
//!   record's signature is what every client attributes the invite to.
//! - Revoking is scoped to the workspace before anything is written, and answers
//!   the same either way, so it cannot be used to probe for another workspace's
//!   tokens.
//! - Every request is re-checked against the tables. A session is long lived, and
//!   an authority revoked mid-session takes effect on the next frame.
//!
//! Nothing here is a double. The set is published by a real device over the real
//! store, the invite records carry real Argon2id code hashes and real signatures,
//! and the wire half runs over a real socket to a real relay.

mod support;

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use sqlx::PgPool;
use wealdrelay::access::{entry_hash, store as access_store, AccessSet};
use wealdrelay::cbor::Reader;
use wealdrelay::frame::{ErrorCode, Frame, PROTOCOL_VERSION};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::admin::{self, AdminError, Request, Response, Summary};
use wealdrelay::invite::code::Code;
use wealdrelay::invite::store::{self, State};
use wealdrelay::invite::{self, EncBundle, Invite};

use support::{config_for, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-invite-admin";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(signer: &SigningKey) -> Vec<u8> {
    signer.verifying_key().to_bytes().to_vec()
}

/// The workspace hash every set and record in this file is about.
fn root() -> Vec<u8> {
    vec![0x77; 32]
}

/// One invite, signed by `issuer`, with a real hash of a real code.
fn issue(issuer: &SigningKey, token_seed: u8, code: Code) -> Invite {
    let token = vec![token_seed; 16];
    let code_hash = invite::code::hash(code, &token).unwrap().to_vec();
    let mut record = Invite {
        token,
        workspace: root(),
        issuer: pk(issuer),
        issued_at: CLOCK,
        expires: CLOCK + invite::DEFAULT_EXPIRY_MS,
        uses: 2,
        code_hash,
        scopes: vec![root()],
        caps: vec![b"chat.read".to_vec()],
        update_pub: vec![0x33; 32],
        bundles: vec![EncBundle {
            group: root(),
            epoch: 1,
            ct: b"a GroupInfo sealed to the invite's update key".to_vec(),
        }],
        sig: vec![0u8; 64],
    };
    record.sig = issuer.sign(&record.digest_input()).to_bytes().to_vec();
    record
}

/// A relay with a database, and the pool behind it.
async fn prepared(label: &str) -> (Scratch, tempfile::TempDir, Running) {
    let scratch = Scratch::new(label).await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    (scratch, blobs, relay)
}

fn pool_of(state: &Arc<RelayState>) -> &PgPool {
    state.database.as_ref().expect("a database").pool()
}

/// Publish a genesis set naming `authorizers`, the way a trust root does.
async fn found(pool: &PgPool, signer: &SigningKey, members: &[&SigningKey]) -> AccessSet {
    // The workspace's one group, registered the way the provisioner registers one.
    // A `CONNECT` names groups and the relay resolves the workspace from them, so
    // without this row there is no workspace for an authenticated socket to be in.
    sqlx::query(
        "insert into relay_group (group_id, workspace_id) values ($1, $2) on conflict do nothing",
    )
    .bind(root())
    .bind(WORKSPACE)
    .execute(pool)
    .await
    .expect("the group is registered");
    let salt = access_store::salt(pool, WORKSPACE).await.expect("a salt");
    let mut entries: Vec<Vec<u8>> = members
        .iter()
        .map(|member| entry_hash(&member.verifying_key().to_bytes(), &salt))
        .collect();
    entries.push(entry_hash(&signer.verifying_key().to_bytes(), &salt));
    // The recovery principal is an entry too: `judge` refuses a set that names a
    // principal the entry list does not carry.
    entries.push(entry_hash(&key(0xee).verifying_key().to_bytes(), &salt));
    entries.sort();
    entries.dedup();
    let mut set = AccessSet {
        workspace: root(),
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: CLOCK,
        entries,
        authorizers: vec![pk(signer)],
        recovery: vec![pk(&key(0xee))],
        quorum: None,
        pending: Vec::new(),
        signer: pk(signer),
        sig: vec![0u8; 64],
    };
    set.sig = signer.sign(&set.digest_input()).to_bytes().to_vec();
    access_store::publish(pool, WORKSPACE, &set, &set.encode())
        .await
        .expect("the genesis set is accepted");
    set
}

// MARK: The wire, both halves

#[test]
fn every_request_and_every_response_round_trips_through_its_encoding() {
    // Both halves are here so the round trip is an assertion rather than one
    // author's reading of the spec twice.
    let requests = [
        Request::Authority,
        Request::Create {
            record: vec![0x01, 0x02, 0x03],
        },
        Request::List,
        Request::Revoke {
            token: vec![0x09; 16],
        },
        Request::Refresh {
            token: vec![0x0a; 16],
            group: vec![0x0b; 32],
            epoch: 7,
            ct: vec![0x0c; 8],
        },
    ];
    for request in requests {
        let encoded = request.encode();
        assert_eq!(
            Request::decode(&encoded).expect("a request this build wrote decodes"),
            request
        );
        // Deterministic: one request, one encoding.
        assert_eq!(
            Request::decode(&encoded).expect("decodes").encode(),
            encoded
        );
    }

    let responses = [
        Response::Authority { may_issue: true },
        Response::Authority { may_issue: false },
        Response::Created {
            token: vec![0x04; 16],
        },
        Response::Live(Vec::new()),
        Response::Live(vec![
            Summary {
                token: vec![0x05; 16],
                issued_at: CLOCK,
                expires: CLOCK + 1,
                remaining: 2,
                seats: 3,
                scope_count: 1,
                state: "live".to_string(),
            },
            Summary {
                token: vec![0x06; 16],
                issued_at: 0,
                expires: 0,
                remaining: 0,
                seats: 255,
                scope_count: 0,
                state: "revoked".to_string(),
            },
        ]),
        Response::Revoked {
            token: vec![0x07; 16],
        },
        Response::Refreshed { accepted: true },
        Response::Refreshed { accepted: false },
    ];
    for response in responses {
        let encoded = response.encode();
        assert_eq!(
            Response::decode(&encoded).expect("a response this build wrote decodes"),
            response
        );
        assert_eq!(
            Response::decode(&encoded).expect("decodes").encode(),
            encoded
        );
    }
}

#[test]
fn a_request_this_relay_does_not_know_is_named_rather_than_guessed_at() {
    use wealdrelay::cbor;

    // An unknown discriminant.
    let unknown = cbor::array(&[cbor::uint(9)]);
    match Request::decode(&unknown) {
        Err(AdminError::UnknownRequest(9)) => {}
        other => panic!("an unknown request was not named: {other:?}"),
    }
    // A known discriminant with the wrong field count. Same answer: the pair is
    // what identifies a request, so a `List` carrying a field is not a `List`.
    let miscounted = cbor::array(&[cbor::uint(2), cbor::bytes(&[1, 2, 3])]);
    assert!(matches!(
        Request::decode(&miscounted),
        Err(AdminError::UnknownRequest(2))
    ));
    // Bytes after the last field. Canonical encoding is the rule on this wire, and
    // a trailing byte is where a second request would hide.
    let mut trailing = Request::List.encode();
    trailing.push(0x00);
    assert!(matches!(
        Request::decode(&trailing),
        Err(AdminError::Encoding(_))
    ));
    // And not CBOR at all.
    assert!(matches!(
        Request::decode(&[0xff, 0xff]),
        Err(AdminError::Encoding(_))
    ));

    // The response decoder is held to the same rules, because a client reads it.
    let unknown = cbor::array(&[cbor::uint(9), cbor::uint(0)]);
    assert!(matches!(
        Response::decode(&unknown),
        Err(AdminError::UnknownRequest(9))
    ));
    let mut trailing = Response::Authority { may_issue: true }.encode();
    trailing.push(0x00);
    assert!(matches!(
        Response::decode(&trailing),
        Err(AdminError::Encoding(_))
    ));
    // A summary field out of its type's range is malformed rather than clamped: a
    // clamp would turn a corrupt list into a plausible one.
    let oversized = cbor::array(&[
        cbor::uint(2),
        cbor::array(&[cbor::array(&[
            cbor::bytes(&[0x05; 16]),
            cbor::uint(CLOCK),
            cbor::uint(CLOCK),
            cbor::uint(300),
            cbor::uint(1),
            cbor::uint(1),
            cbor::bytes(b"live"),
        ])]),
    ]);
    assert!(matches!(
        Response::decode(&oversized),
        Err(AdminError::Encoding(_))
    ));
    let not_utf8 = cbor::array(&[
        cbor::uint(2),
        cbor::array(&[cbor::array(&[
            cbor::bytes(&[0x05; 16]),
            cbor::uint(CLOCK),
            cbor::uint(CLOCK),
            cbor::uint(1),
            cbor::uint(1),
            cbor::uint(1),
            cbor::bytes(&[0xff, 0xfe]),
        ])]),
    ]);
    assert!(matches!(
        Response::decode(&not_utf8),
        Err(AdminError::Encoding(_))
    ));
    // A summary that is not a seven field array at all.
    let short = cbor::array(&[
        cbor::uint(2),
        cbor::array(&[cbor::array(&[cbor::bytes(&[0x05; 16])])]),
    ]);
    assert!(matches!(
        Response::decode(&short),
        Err(AdminError::Encoding(_))
    ));
}

#[test]
fn every_refusal_maps_to_the_code_the_client_acts_on() {
    use wealdrelay::cbor::CborError;
    use wealdrelay::invite::InviteError;

    assert_eq!(
        AdminError::Encoding(CborError::Truncated).code(),
        ErrorCode::NoncanonicalCbor
    );
    assert_eq!(
        AdminError::UnknownRequest(9).code(),
        ErrorCode::MalformedHeader
    );
    // The one refusal a client acts on differently: it hides the invite control
    // rather than showing an error.
    assert_eq!(
        AdminError::NotAnAdmin.code(),
        ErrorCode::WriterNotInAccessSet
    );
    // The two wrapped errors decide their own code, in one place, so this asserts
    // the delegation rather than a second copy of the table.
    let refused = InviteError::BadSignature;
    assert_eq!(
        AdminError::Refused(refused).code(),
        InviteError::BadSignature.code()
    );
    let store_error = wealdrelay::invite::store::StoreError::Database("gone".to_string());
    assert_eq!(
        AdminError::Store(store_error).code(),
        ErrorCode::Backpressure
    );
    // The messages are the operator's, so they say which rule was broken.
    assert!(AdminError::NotAnAdmin.to_string().contains("authorizer"));
    assert!(AdminError::UnknownRequest(9).to_string().contains("9"));
}

// MARK: Authority

#[tokio::test(flavor = "multi_thread")]
async fn a_workspace_with_no_access_set_has_no_admins_yet() {
    let (scratch, _blobs, relay) = prepared("invite_admin_unfounded").await;
    let pool = pool_of(&relay.state);

    // Not "everybody", which is what a permissive default would mean on a
    // workspace whose first device has not published yet.
    assert!(!admin::may_issue(pool, WORKSPACE, &pk(&key(0x21)))
        .await
        .expect("the query runs"));

    // And the request answers the same thing rather than erroring.
    let answer = admin::handle(
        pool,
        WORKSPACE,
        &pk(&key(0x21)),
        Request::Authority,
        CLOCK as i64,
    )
    .await
    .expect("authority is always answerable");
    assert_eq!(answer, Response::Authority { may_issue: false });

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn authority_is_the_authorizer_list_and_not_membership() {
    let (scratch, _blobs, relay) = prepared("invite_admin_authority").await;
    let pool = pool_of(&relay.state);
    let root_key = key(0x21);
    let member = key(0x22);
    found(pool, &root_key, &[&member]).await;

    assert!(admin::may_issue(pool, WORKSPACE, &pk(&root_key))
        .await
        .expect("the query runs"));
    // A member of the workspace who is not an authorizer. The difference between
    // the two lists is the whole check.
    assert!(!admin::may_issue(pool, WORKSPACE, &pk(&member))
        .await
        .expect("the query runs"));
    // And a device that is in no list at all.
    assert!(!admin::may_issue(pool, WORKSPACE, &pk(&key(0x23)))
        .await
        .expect("the query runs"));

    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&member),
            Request::Authority,
            CLOCK as i64
        )
        .await
        .expect("answered"),
        Response::Authority { may_issue: false }
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: Issue, list, revoke

#[tokio::test(flavor = "multi_thread")]
async fn only_an_authorizer_issues_and_only_with_a_record_it_signed_itself() {
    let (scratch, _blobs, relay) = prepared("invite_admin_issue").await;
    let pool = pool_of(&relay.state);
    let root_key = key(0x21);
    let member = key(0x22);
    found(pool, &root_key, &[&member]).await;

    // A member who is not an authorizer cannot issue, list or revoke.
    for request in [
        Request::Create {
            record: issue(&member, 0xa1, Code::from_bits(0x0123_4567_89ab_cdef)).encode(),
        },
        Request::List,
        Request::Revoke {
            token: vec![0xa1; 16],
        },
    ] {
        match admin::handle(pool, WORKSPACE, &pk(&member), request, CLOCK as i64).await {
            Err(AdminError::NotAnAdmin) => {}
            other => panic!("a non-authorizer was not refused: {other:?}"),
        }
    }

    // An authorizer uploading a record signed by somebody else. Refused, because
    // the signature is what every client attributes the invite to: without this an
    // authorizer holding another's record could issue in their name.
    let borrowed = issue(&member, 0xa2, Code::from_bits(0x0123_4567_89ab_cdef));
    match admin::handle(
        pool,
        WORKSPACE,
        &pk(&root_key),
        Request::Create {
            record: borrowed.encode(),
        },
        CLOCK as i64,
    )
    .await
    {
        Err(AdminError::NotAnAdmin) => {}
        other => panic!("a borrowed record was accepted: {other:?}"),
    }
    assert!(
        store::fetch(pool, &borrowed.token)
            .await
            .expect("the query runs")
            .is_none(),
        "a refused issue wrote a row"
    );

    // A record that is not a record. Refused as malformed, before anything is
    // written, and reported as the encoding failure it is rather than as an
    // authority one.
    match admin::handle(
        pool,
        WORKSPACE,
        &pk(&root_key),
        Request::Create {
            record: vec![0x00, 0x01],
        },
        CLOCK as i64,
    )
    .await
    {
        Err(AdminError::Refused(_)) | Err(AdminError::Encoding(_)) => {}
        other => panic!("a malformed record was accepted: {other:?}"),
    }

    // The authorizer's own record. Accepted, and the token comes back.
    let own = issue(&root_key, 0xa3, Code::from_bits(0x0123_4567_89ab_cdef));
    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            Request::Create {
                record: own.encode()
            },
            CLOCK as i64,
        )
        .await
        .expect("the issue is accepted"),
        Response::Created {
            token: own.token.clone()
        }
    );
    assert!(store::fetch(pool, &own.token)
        .await
        .expect("the query runs")
        .is_some());

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_list_is_this_workspace_s_invites_with_the_fields_an_admin_screen_shows() {
    let (scratch, _blobs, relay) = prepared("invite_admin_list").await;
    let pool = pool_of(&relay.state);
    let root_key = key(0x21);
    found(pool, &root_key, &[]).await;

    // Nothing yet.
    assert_eq!(
        admin::handle(pool, WORKSPACE, &pk(&root_key), Request::List, CLOCK as i64)
            .await
            .expect("answered"),
        Response::Live(Vec::new())
    );

    let first = issue(&root_key, 0xb1, Code::from_bits(0x0123_4567_89ab_cdef));
    let second = issue(&root_key, 0xb2, Code::from_bits(0x0fed_cba9_8765_4321));
    for record in [&first, &second] {
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            Request::Create {
                record: record.encode(),
            },
            CLOCK as i64,
        )
        .await
        .expect("issued");
    }
    // Another workspace's invite, which must not appear.
    let elsewhere = issue(&key(0x31), 0xb3, Code::from_bits(0x0123_4567_89ab_cdef));
    store::create(pool, "ws-somebody-else", &elsewhere, CLOCK as i64)
        .await
        .expect("stored");

    let Response::Live(summaries) =
        admin::handle(pool, WORKSPACE, &pk(&root_key), Request::List, CLOCK as i64)
            .await
            .expect("answered")
    else {
        panic!("the list answered with something else");
    };
    assert_eq!(summaries.len(), 2, "another workspace's invite was listed");
    assert_eq!(summaries[0].token, first.token);
    assert_eq!(summaries[1].token, second.token);
    // The fields an admin screen shows, and no more: no code hash, no bundles, no
    // invitee identity. `seats` is what was issued and `remaining` is what is left.
    assert_eq!(summaries[0].seats, 2);
    assert_eq!(summaries[0].remaining, 2);
    assert_eq!(summaries[0].scope_count, 1);
    assert_eq!(summaries[0].state, "live");
    // The two timestamps come from different clocks, deliberately. `issued_at` is
    // the row's own `created_at`, which is the database's, because a summary that
    // repeated the issuer's claimed field would let a backdated record present
    // itself as older than it is. `expires` is the record's, because that is the
    // value the redemption path actually enforces, and a list showing a different
    // deadline from the one that will be applied would be worse than showing none.
    // This fixture's clock is fixed in the past, so the two are far apart here in a
    // way they never are in production, which is exactly why the assertion names
    // the source of each rather than comparing them.
    assert!(summaries[0].issued_at > 0);
    assert_eq!(summaries[0].expires, first.expires);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_is_scoped_to_the_workspace_and_answers_the_same_either_way() {
    let (scratch, _blobs, relay) = prepared("invite_admin_revoke").await;
    let pool = pool_of(&relay.state);
    let root_key = key(0x21);
    found(pool, &root_key, &[]).await;

    let own = issue(&root_key, 0xc1, Code::from_bits(0x0123_4567_89ab_cdef));
    admin::handle(
        pool,
        WORKSPACE,
        &pk(&root_key),
        Request::Create {
            record: own.encode(),
        },
        CLOCK as i64,
    )
    .await
    .expect("issued");

    // Another workspace's invite, and this admin holds its token.
    let elsewhere = issue(&key(0x31), 0xc2, Code::from_bits(0x0123_4567_89ab_cdef));
    store::create(pool, "ws-somebody-else", &elsewhere, CLOCK as i64)
        .await
        .expect("stored");

    assert!(store::belongs_to(pool, &own.token, WORKSPACE)
        .await
        .expect("the query runs"));
    assert!(!store::belongs_to(pool, &elsewhere.token, WORKSPACE)
        .await
        .expect("the query runs"));
    // A token that exists nowhere is the same answer as one that belongs to
    // somebody else, deliberately.
    assert!(!store::belongs_to(pool, &[0xff; 16], WORKSPACE)
        .await
        .expect("the query runs"));

    // Ours: revoked.
    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            Request::Revoke {
                token: own.token.clone()
            },
            CLOCK as i64,
        )
        .await
        .expect("answered"),
        Response::Revoked {
            token: own.token.clone()
        }
    );
    let record = store::fetch(pool, &own.token)
        .await
        .expect("the query runs")
        .expect("the row survives");
    assert_eq!(record.state, State::Revoked);

    // Twice: the same answer, not an error. An admin pressing revoke twice has not
    // done anything wrong.
    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            Request::Revoke {
                token: own.token.clone()
            },
            CLOCK as i64,
        )
        .await
        .expect("answered"),
        Response::Revoked { token: own.token }
    );

    // Somebody else's, and one that does not exist: the same answer again, and
    // neither is touched. An answer that distinguished them would be a probe.
    for token in [elsewhere.token.clone(), vec![0xff; 16]] {
        assert_eq!(
            admin::handle(
                pool,
                WORKSPACE,
                &pk(&root_key),
                Request::Revoke {
                    token: token.clone()
                },
                CLOCK as i64,
            )
            .await
            .expect("answered"),
            Response::Revoked { token }
        );
    }
    let untouched = store::fetch(pool, &elsewhere.token)
        .await
        .expect("the query runs")
        .expect("the row survives");
    assert_eq!(
        untouched.state,
        State::Live,
        "another workspace's invite was revoked across the boundary"
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The same path, over a real socket

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_issues_lists_and_revokes_over_a_socket_and_a_member_cannot() {
    let (scratch, _blobs, relay) = prepared("invite_admin_socket").await;
    let pool = pool_of(&relay.state).clone();
    let root_key = key(0x21);
    let member = key(0x22);
    found(&pool, &root_key, &[&member]).await;

    let mut admin_client = Client::connect(relay.address).await;
    admin_client
        .handshake_as(&root_key, vec![root()], CLOCK)
        .await;

    // "May I?", over the wire, answered from the tables.
    admin_client
        .send_frame(&Frame::Invite {
            body: Request::Authority.encode(),
        })
        .await;
    match admin_client.recv_frame().await {
        Frame::Invite { body } => assert_eq!(
            Response::decode(&body).expect("a response"),
            Response::Authority { may_issue: true }
        ),
        other => panic!("the authority question was refused: {other:?}"),
    }

    // Issue.
    let record = issue(&root_key, 0xd1, Code::from_bits(0x0123_4567_89ab_cdef));
    admin_client
        .send_frame(&Frame::Invite {
            body: Request::Create {
                record: record.encode(),
            }
            .encode(),
        })
        .await;
    match admin_client.recv_frame().await {
        Frame::Invite { body } => assert_eq!(
            Response::decode(&body).expect("a response"),
            Response::Created {
                token: record.token.clone()
            }
        ),
        other => panic!("the issue was refused: {other:?}"),
    }

    // List.
    admin_client
        .send_frame(&Frame::Invite {
            body: Request::List.encode(),
        })
        .await;
    match admin_client.recv_frame().await {
        Frame::Invite { body } => {
            let Response::Live(summaries) = Response::decode(&body).expect("a response") else {
                panic!("the list answered with something else");
            };
            assert_eq!(summaries.len(), 1);
            assert_eq!(summaries[0].token, record.token);
        }
        other => panic!("the list was refused: {other:?}"),
    }

    // Revoke.
    admin_client
        .send_frame(&Frame::Invite {
            body: Request::Revoke {
                token: record.token.clone(),
            }
            .encode(),
        })
        .await;
    match admin_client.recv_frame().await {
        Frame::Invite { body } => assert_eq!(
            Response::decode(&body).expect("a response"),
            Response::Revoked {
                token: record.token.clone()
            }
        ),
        other => panic!("the revoke was refused: {other:?}"),
    }

    // A body that is not a request, over the same authenticated socket. An error
    // frame, and the socket stays open: a malformed admin request is not grounds to
    // drop a member's connection.
    admin_client
        .send_frame(&Frame::Invite {
            body: vec![0xff, 0xff],
        })
        .await;
    match admin_client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::NoncanonicalCbor),
        other => panic!("a malformed request was not refused: {other:?}"),
    }

    // And a member who is not an authorizer, over their own socket.
    let mut member_client = Client::connect(relay.address).await;
    member_client
        .handshake_as(&member, vec![root()], CLOCK)
        .await;
    member_client
        .send_frame(&Frame::Invite {
            body: Request::List.encode(),
        })
        .await;
    match member_client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("a member was allowed to list invites: {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authority_revoked_mid_session_takes_effect_on_the_next_frame() {
    // The reason every arm re-reads the tables. A session is long lived, and an
    // admin removed from the authorizer list must lose the power now, not at their
    // next reconnect.
    let (scratch, _blobs, relay) = prepared("invite_admin_midsession").await;
    let pool = pool_of(&relay.state).clone();
    let root_key = key(0x21);
    let deputy = key(0x22);

    // Both are authorizers to begin with.
    sqlx::query(
        "insert into relay_group (group_id, workspace_id) values ($1, $2) on conflict do nothing",
    )
    .bind(root())
    .bind(WORKSPACE)
    .execute(&pool)
    .await
    .expect("the group is registered");
    let salt = access_store::salt(&pool, WORKSPACE).await.expect("a salt");
    let mut entries = vec![
        entry_hash(&root_key.verifying_key().to_bytes(), &salt),
        entry_hash(&deputy.verifying_key().to_bytes(), &salt),
        entry_hash(&key(0xee).verifying_key().to_bytes(), &salt),
    ];
    entries.sort();
    let mut set = AccessSet {
        workspace: root(),
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: CLOCK,
        entries: entries.clone(),
        authorizers: {
            let mut both = vec![pk(&root_key), pk(&deputy)];
            both.sort();
            both
        },
        recovery: vec![pk(&key(0xee))],
        quorum: None,
        pending: Vec::new(),
        signer: pk(&root_key),
        sig: vec![0u8; 64],
    };
    set.sig = root_key.sign(&set.digest_input()).to_bytes().to_vec();
    access_store::publish(&pool, WORKSPACE, &set, &set.encode())
        .await
        .expect("the genesis set is accepted");

    let mut client = Client::connect(relay.address).await;
    client.handshake_as(&deputy, vec![root()], CLOCK).await;
    client
        .send_frame(&Frame::Invite {
            body: Request::Authority.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Invite { body } => assert_eq!(
            Response::decode(&body).expect("a response"),
            Response::Authority { may_issue: true }
        ),
        other => panic!("the deputy was refused while an authorizer: {other:?}"),
    }

    // The next version drops the deputy from the authorizer list, leaving them a
    // member. The socket is not touched.
    let mut next = AccessSet {
        workspace: root(),
        version: 1,
        prev_hash: set.digest().to_vec(),
        issued_at: CLOCK + 1,
        entries,
        authorizers: vec![pk(&root_key)],
        recovery: vec![pk(&key(0xee))],
        quorum: None,
        pending: Vec::new(),
        signer: pk(&root_key),
        sig: vec![0u8; 64],
    };
    next.sig = root_key.sign(&next.digest_input()).to_bytes().to_vec();
    access_store::publish(&pool, WORKSPACE, &next, &next.encode())
        .await
        .expect("the rotation is accepted");

    // The same socket, the next frame.
    client
        .send_frame(&Frame::Invite {
            body: Request::List.encode(),
        })
        .await;
    match client.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, ErrorCode::WriterNotInAccessSet),
        other => panic!("a revoked authority survived its own session: {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: What it answers when it cannot look

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_cannot_read_the_access_set_says_retry_rather_than_no() {
    use sqlx::Executor as _;

    // The difference that matters: `NotAnAdmin` is a client hiding its invite
    // control forever, and a relay that failed to read a table has not learned
    // that the caller is not an admin.
    let (scratch, _blobs, relay) = prepared("invite_admin_unreadable").await;
    let pool = pool_of(&relay.state).clone();
    let root_key = key(0x21);
    found(&pool, &root_key, &[]).await;

    pool.execute("drop table relay_access_set cascade")
        .await
        .expect("the table is dropped");

    match admin::handle(
        &pool,
        WORKSPACE,
        &pk(&root_key),
        Request::List,
        CLOCK as i64,
    )
    .await
    {
        Err(error) => assert_eq!(error.code(), ErrorCode::Backpressure),
        Ok(other) => panic!("an unreadable relay answered {other:?}"),
    }
    match admin::may_issue(&pool, WORKSPACE, &pk(&root_key)).await {
        Err(error) => assert_eq!(error.code(), ErrorCode::Backpressure),
        Ok(other) => panic!("an unreadable relay answered {other}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_cannot_read_the_invite_table_says_retry_on_the_list() {
    use sqlx::Executor as _;

    let (scratch, _blobs, relay) = prepared("invite_admin_unreadable_list").await;
    let pool = pool_of(&relay.state).clone();
    let root_key = key(0x21);
    found(&pool, &root_key, &[]).await;

    // The access set is still readable, so authority is established and the failure
    // is the summary query itself. That ordering is the point: a fault on the second
    // query is nothing the first query's fault has said anything about.
    pool.execute("drop table relay_invite_scope cascade")
        .await
        .expect("the table is dropped");
    pool.execute("drop table relay_invite cascade")
        .await
        .expect("the table is dropped");

    match admin::summaries(&pool, WORKSPACE).await {
        Err(error) => assert_eq!(error.code(), ErrorCode::Backpressure),
        Ok(other) => panic!("an unreadable relay listed {} invites", other.len()),
    }
    match admin::handle(
        &pool,
        WORKSPACE,
        &pk(&root_key),
        Request::Revoke {
            token: vec![0xff; 16],
        },
        CLOCK as i64,
    )
    .await
    {
        Err(error) => assert_eq!(error.code(), ErrorCode::Backpressure),
        Ok(other) => panic!("an unreadable relay answered {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: The redeem path's record step, which shares this file's fixtures

#[tokio::test(flavor = "multi_thread")]
async fn the_record_step_serves_the_issuer_s_own_bytes_and_an_empty_body_for_a_token_that_is_not_there(
) {
    use wealdrelay::invite::redeem::{Request as RedeemRequest, Response as RedeemResponse};

    // Step 6 of `invites.md`: a joiner asks for the record its token names. It is
    // the one redeem step that answers the same shape for a real token and an
    // imaginary one, which is what keeps this path from confirming that a token
    // exists.
    let (scratch, _blobs, relay) = prepared("invite_admin_record_step").await;
    let pool = pool_of(&relay.state).clone();
    let root_key = key(0x21);
    found(&pool, &root_key, &[]).await;
    let record = issue(&root_key, 0xe1, Code::from_bits(0x0123_4567_89ab_cdef));
    store::create(&pool, WORKSPACE, &record, CLOCK as i64)
        .await
        .expect("stored");

    let mut joiner = Client::connect(relay.address).await;
    joiner
        .send_frame(&Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![root()],
            sent_at: CLOCK,
        })
        .await;
    let _ = joiner.recv_frame().await;
    let _ = joiner.recv_frame().await;

    joiner
        .send_frame(&Frame::Join {
            body: RedeemRequest::Record {
                token: record.token.clone(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Join { body } => {
            let RedeemResponse::Record { body } =
                RedeemResponse::decode(&body).expect("a response")
            else {
                panic!("the record step answered with something else");
            };
            // The issuer's own bytes, never re-encoded: a client verifies the
            // signature over what the issuer signed.
            assert_eq!(body, record.encode());
            let mut reader = Reader::new(&body);
            reader.array_header().expect("a record is an array");
        }
        other => panic!("the record step was refused: {other:?}"),
    }

    // A token that does not exist, and a token that was revoked: byte-identical
    // empty answers, and neither is the refusal a live token would not have got
    // (WEALD-L152). An `UNAVAILABLE` here would confirm which guessed tokens are
    // real, before AUTH and against no attempt budget.
    let revoked = issue(&root_key, 0xe2, Code::from_bits(0x0f0f_0f0f_0f0f_0f0f));
    store::create(&pool, WORKSPACE, &revoked, CLOCK as i64)
        .await
        .expect("stored");
    store::revoke(&pool, &revoked.token).await.expect("revoked");

    let mut answers = Vec::new();
    for token in [vec![0xff; 16], revoked.token.clone()] {
        joiner
            .send_frame(&Frame::Join {
                body: RedeemRequest::Record { token }.encode(),
            })
            .await;
        match joiner.recv_frame().await {
            Frame::Join { body } => answers.push(body),
            other => panic!("the record step answered {other:?}"),
        }
    }
    assert_eq!(answers[0], answers[1]);
    let RedeemResponse::Record { body } = RedeemResponse::decode(&answers[0]).expect("a response")
    else {
        panic!("the record step answered with something else");
    };
    assert!(body.is_empty());

    relay.shutdown().await;
    scratch.drop_database().await;
}

// MARK: Refresh

/// BR-045: an admin's client can actually upload a fresh sealed `GroupInfo`.
///
/// `invites.md` requires a bundle refresh after a commit, and `store::refresh_bundle`
/// has implemented it since it was written, but until the `Refresh` arm existed no
/// frame reached it: every outstanding invite went stale on the next commit and its
/// parked joins waited for expiry. This is the wire in front of it, held to the same
/// workspace scoping every other privileged arm carries.
#[tokio::test(flavor = "multi_thread")]
async fn refreshing_a_bundle_is_scoped_and_reaches_the_store() {
    let (scratch, _blobs, relay) = prepared("invite_admin_refresh").await;
    let pool = pool_of(&relay.state);
    let root_key = key(0x21);
    let member = key(0x22);
    found(pool, &root_key, &[&member]).await;

    let own = issue(&root_key, 0xd1, Code::from_bits(0x0123_4567_89ab_cdef));
    admin::handle(
        pool,
        WORKSPACE,
        &pk(&root_key),
        Request::Create {
            record: own.encode(),
        },
        CLOCK as i64,
    )
    .await
    .expect("issued");

    let refresh = |token: Vec<u8>, group: Vec<u8>, epoch: u64| Request::Refresh {
        token,
        group,
        epoch,
        ct: b"a fresher GroupInfo sealed to the same update key".to_vec(),
    };

    // A member who is not an authorizer is refused before anything is written, as
    // every other privileged arm refuses them.
    assert!(matches!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&member),
            refresh(own.token.clone(), root(), 2),
            CLOCK as i64,
        )
        .await,
        Err(AdminError::NotAnAdmin)
    ));

    // The admin's own invite, its own scope: stored, and readable by the join path.
    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            refresh(own.token.clone(), root(), 2),
            CLOCK as i64,
        )
        .await
        .expect("answered"),
        Response::Refreshed { accepted: true }
    );
    let candidates = store::bundles_for(pool, &own.token, &root(), CLOCK as i64)
        .await
        .expect("the query runs");
    assert!(candidates.iter().any(|bundle| bundle.epoch == 2));
    // The candidate the issuer sealed into the record is still there: a refresh adds
    // to the choices rather than replacing the one every joiner can already read.
    assert!(candidates.iter().any(|bundle| bundle.epoch == 1));

    // A group the record does not scope is refused, and so is a token this workspace
    // does not own. One flat answer for both, because an admin has nothing to do
    // differently about either and a distinction would be a probe.
    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            refresh(own.token.clone(), vec![0x5c; 32], 2),
            CLOCK as i64,
        )
        .await
        .expect("answered"),
        Response::Refreshed { accepted: false }
    );

    let elsewhere = issue(&key(0x31), 0xd2, Code::from_bits(0x0123_4567_89ab_cdef));
    store::create(pool, "ws-somebody-else", &elsewhere, CLOCK as i64)
        .await
        .expect("stored");
    assert_eq!(
        admin::handle(
            pool,
            WORKSPACE,
            &pk(&root_key),
            refresh(elsewhere.token.clone(), root(), 2),
            CLOCK as i64,
        )
        .await
        .expect("answered"),
        Response::Refreshed { accepted: false }
    );
    // And nothing was written there.
    assert!(
        store::bundles_for(pool, &elsewhere.token, &root(), CLOCK as i64)
            .await
            .expect("the query runs")
            .iter()
            .all(|bundle| bundle.epoch != 2)
    );

    relay.shutdown().await;
    scratch.drop_database().await;
}
