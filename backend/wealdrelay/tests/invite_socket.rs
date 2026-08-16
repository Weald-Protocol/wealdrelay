// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Redeeming an invite over a real socket, by a device that is nobody yet.
//!
//! This is the path a workspace's first day runs on
//! (`specs/backend/relay/invites.md`, steps 4 to 7), and the thing that makes it
//! different from every other frame is that the joiner cannot authenticate: it has
//! no roster entry, no access-set membership and no group. It has a token, a code
//! that came by another channel, and a device key nobody has seen.
//!
//! So the claims worth proving are about what that opening buys, and mostly about
//! what it does not:
//!
//! - A correct token and code take exactly one seat and answer with its expiry.
//! - Every wrong thing gets the same answer, so the endpoint never confirms that a
//!   token exists.
//! - Five wrong codes cool the tuple down without burning the invite.
//! - The bundles the relay serves back are ciphertext it cannot open.
//! - Reserving does not make the joiner a member of anything: it is a seat, and the
//!   membership claim is the invite's signature, which every other client checks.

mod support;

use ed25519_dalek::{Signer as _, SigningKey};
use wealdrelay::frame::{Frame, PROTOCOL_VERSION};
use wealdrelay::health::{Clock, RelayState};
use wealdrelay::invite::code::Code;
use wealdrelay::invite::redeem::{Request, Response};
use wealdrelay::invite::store::{self, State};
use wealdrelay::invite::{self, EncBundle, Invite};

use support::{config_for, Client, Running, Scratch};

const CLOCK: u64 = 1_700_000_000_000;
const WORKSPACE: &str = "ws-invite-socket";

fn root() -> Vec<u8> {
    vec![0x11; 32]
}

/// One invite with a real Argon2id hash of a real code, one scope, one bundle.
fn issue(token_seed: u8, code: Code, uses: u8) -> Invite {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let token = vec![token_seed; 16];
    let code_hash = invite::code::hash(code, &token).unwrap().to_vec();
    let mut record = Invite {
        token,
        workspace: root(),
        issuer: issuer.verifying_key().to_bytes().to_vec(),
        issued_at: CLOCK,
        expires: CLOCK + invite::DEFAULT_EXPIRY_MS,
        uses,
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

/// A client that has connected and nothing more. No `AUTH`, because a joiner has
/// nothing to authenticate with, which is the whole point of this path.
async fn connected(relay: &Running) -> Client {
    let mut client = Client::connect(relay.address).await;
    client
        .send_frame(&Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![root()],
            sent_at: CLOCK,
        })
        .await;
    // The acknowledgement and the challenge. Both read and both ignored: this
    // client is never going to answer the challenge.
    let _ = client.recv_frame().await;
    let _ = client.recv_frame().await;
    client
}

async fn seed(state: &std::sync::Arc<RelayState>, record: &Invite) {
    let pool = state.database.as_ref().expect("a database").pool();
    store::create(pool, WORKSPACE, record, CLOCK as i64)
        .await
        .expect("the invite is stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_is_nobody_yet_takes_one_seat_and_enters() {
    let scratch = Scratch::new("invite_socket").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let code = Code::from_bits(0x0f0f0f);
    let record = issue(0xa1, code, 2);
    seed(&relay.state, &record).await;

    let mut joiner = connected(&relay).await;
    let device = vec![0x44; 32];
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x01; 16],
                device: device.clone(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Join { body } => match Response::decode(&body).expect("a response") {
            Response::Reserved { expires_at_ms } => assert!(
                expires_at_ms > CLOCK as i64,
                "the seat expires in the past: {expires_at_ms}"
            ),
            other => panic!("expected a reservation, got {other:?}"),
        },
        other => panic!("expected a Join answer, got {other:?}"),
    }

    // One seat, taken once. The reservation is idempotent for its nonce, so the
    // same request again is the same seat rather than a second one.
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x01; 16],
                device: device.clone(),
            }
            .encode(),
        })
        .await;
    assert!(matches!(joiner.recv_frame().await, Frame::Join { .. }));
    let pool = relay.state.database.as_ref().unwrap().pool();
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        1,
        "the idempotent retry took a second seat"
    );

    // The bundles, served back as the bytes the issuer sealed. The relay holds no
    // key for them: the private half of `update_pub` is derived by this joiner from
    // 32 bytes that travelled in a URL fragment and never reached here.
    joiner
        .send_frame(&Frame::Join {
            body: Request::Bundles {
                token: record.token.clone(),
                group: root(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Join { body } => match Response::decode(&body).expect("a response") {
            Response::Bundles(bundles) => {
                assert_eq!(bundles.len(), 1);
                assert_eq!(bundles[0].ct, record.bundles[0].ct);
                assert_eq!(bundles[0].epoch, 1);
            }
            other => panic!("expected bundles, got {other:?}"),
        },
        other => panic!("expected a Join answer, got {other:?}"),
    }

    // And the scope commit, which for a single-scope invite is the last one and
    // therefore spends the seat.
    joiner
        .send_frame(&Frame::Join {
            body: Request::Commit {
                token: record.token.clone(),
                nonce: vec![0x01; 16],
                device: device.clone(),
                group: root(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Join { body } => match Response::decode(&body).expect("a response") {
            Response::Committed { receipt } => assert_eq!(receipt.len(), 32),
            other => panic!("expected a receipt, got {other:?}"),
        },
        other => panic!("expected a Join answer, got {other:?}"),
    }
    let consumed: bool = sqlx::query_scalar(
        "select consumed_at is not null from relay_invite_reservation where token = $1",
    )
    .bind(&record.token)
    .fetch_one(pool)
    .await
    .expect("read the reservation");
    assert!(consumed, "the last scope commit did not consume the seat");

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_way_to_fail_gets_the_same_answer_and_none_of_them_burn_the_invite() {
    let scratch = Scratch::new("invite_socket_refusals").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let code = Code::from_bits(0x0a0a0a);
    let record = issue(0xb1, code, 4);
    seed(&relay.state, &record).await;

    let mut joiner = connected(&relay).await;
    let device = vec![0x55; 32];

    // A token nobody issued, a code nobody typed, a request that is not a request,
    // and a commit against a reservation that does not exist. One answer to all of
    // them, because the difference between them is exactly what an unauthenticated
    // endpoint must not confirm.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "a token nobody issued",
            Request::Reserve {
                token: vec![0xff; 16],
                code: code.grouped(),
                nonce: vec![0x02; 16],
                device: device.clone(),
            }
            .encode(),
        ),
        (
            "a wrong code",
            Request::Reserve {
                token: record.token.clone(),
                code: Code::from_bits(0x0b0b0b).grouped(),
                nonce: vec![0x03; 16],
                device: device.clone(),
            }
            .encode(),
        ),
        (
            "a code that is not even a code",
            Request::Reserve {
                token: record.token.clone(),
                code: "not-a-code".to_string(),
                nonce: vec![0x04; 16],
                device: device.clone(),
            }
            .encode(),
        ),
        (
            "a commit with no reservation",
            Request::Commit {
                token: record.token.clone(),
                nonce: vec![0x09; 16],
                device: device.clone(),
                group: root(),
            }
            .encode(),
        ),
        ("bytes that are not a request", vec![0xff, 0xff]),
        (
            "a step this relay does not have",
            wealdrelay::cbor::array(&[wealdrelay::cbor::uint(9), wealdrelay::cbor::bytes(&[1])]),
        ),
    ];
    for (what, body) in cases {
        joiner.send_frame(&Frame::Join { body }).await;
        match joiner.recv_frame().await {
            Frame::Error(error) => assert_eq!(
                error.code,
                invite::UNAVAILABLE,
                "{what} was answered with {:?}, which tells a prober something",
                error.code
            ),
            other => panic!("{what}: expected the generic refusal, got {other:?}"),
        }
    }

    // Nothing was burnt. Four seats, still live, still redeemable by somebody who
    // has the code.
    let pool = relay.state.database.as_ref().unwrap().pool();
    let stored = store::fetch(pool, &record.token).await.unwrap().unwrap();
    assert_eq!(stored.remaining, 4);
    assert_eq!(stored.state, State::Live);

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn five_wrong_codes_cool_the_tuple_down_and_the_right_one_still_answers_the_same() {
    let scratch = Scratch::new("invite_socket_cooldown").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::Fixed(CLOCK)).await;
    let code = Code::from_bits(0x0c0c0c);
    let record = issue(0xc1, code, 8);
    seed(&relay.state, &record).await;

    let mut joiner = connected(&relay).await;
    let device = vec![0x66; 32];
    let wrong = Code::from_bits(0x0d0d0d).grouped();
    for attempt in 0..5u8 {
        joiner
            .send_frame(&Frame::Join {
                body: Request::Reserve {
                    token: record.token.clone(),
                    code: wrong.clone(),
                    nonce: vec![attempt; 16],
                    device: device.clone(),
                }
                .encode(),
            })
            .await;
        assert!(matches!(joiner.recv_frame().await, Frame::Error(_)));
    }

    // The right code, from the cooled-down tuple, gets the same generic answer.
    // Telling this caller it was throttled would confirm the token exists, which is
    // the one thing five wrong guesses must not buy.
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x10; 16],
                device: device.clone(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, invite::UNAVAILABLE),
        other => panic!("expected the generic refusal, got {other:?}"),
    }

    // And the invite is untouched: nothing was burnt and no seat moved.
    let pool = relay.state.database.as_ref().unwrap().pool();
    assert_eq!(
        store::fetch(pool, &record.token)
            .await
            .unwrap()
            .unwrap()
            .remaining,
        8
    );
    // A second device from the same source is refused too. The cooldown is keyed
    // on the source precisely because the device value is whatever bytes the
    // caller typed into its frame: a fresh device string must not buy a fresh
    // five-guess allowance (WEALD-287).
    let mut other_device = connected(&relay).await;
    other_device
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x11; 16],
                device: vec![0x77; 32],
            }
            .encode(),
        })
        .await;
    match other_device.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, invite::UNAVAILABLE),
        other => panic!("expected the generic refusal, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test]
async fn a_request_and_a_response_round_trip_through_their_encodings() {
    for request in [
        Request::Reserve {
            token: vec![1; 16],
            code: "ABCD-EFGH-JKLM".to_string(),
            nonce: vec![2; 16],
            device: vec![3; 32],
        },
        Request::Bundles {
            token: vec![1; 16],
            group: vec![4; 32],
        },
        Request::Commit {
            token: vec![1; 16],
            nonce: vec![2; 16],
            device: vec![3; 32],
            group: vec![4; 32],
        },
    ] {
        assert_eq!(
            Request::decode(&request.encode()).expect("decodes"),
            request
        );
    }

    for response in [
        Response::Reserved {
            expires_at_ms: 1_700_000_600_000,
        },
        Response::Bundles(vec![EncBundle {
            group: vec![4; 32],
            epoch: 9,
            ct: b"opaque".to_vec(),
        }]),
        Response::Bundles(Vec::new()),
        Response::Committed {
            receipt: vec![5; 32],
        },
    ] {
        assert_eq!(
            Response::decode(&response.encode()).expect("decodes"),
            response
        );
    }

    // Every shape that is not one of those is refused, and refused the same way.
    use wealdrelay::invite::redeem::RedeemError;
    assert!(matches!(
        Request::decode(&[0xff]),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Request::decode(&wealdrelay::cbor::array(&[wealdrelay::cbor::uint(7)])),
        Err(RedeemError::UnknownStep(7))
    ));
    // A known step with the wrong number of fields, which is the shape a client one
    // version out of date would send.
    assert!(matches!(
        Request::decode(&wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(0),
            wealdrelay::cbor::bytes(&[1; 16]),
        ])),
        Err(RedeemError::Malformed(_))
    ));
    // A code that is not UTF-8 is not a code anybody typed.
    assert!(matches!(
        Request::decode(&wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(0),
            wealdrelay::cbor::bytes(&[1; 16]),
            wealdrelay::cbor::bytes(&[0xff, 0xfe]),
            wealdrelay::cbor::bytes(&[2; 16]),
            wealdrelay::cbor::bytes(&[3; 32]),
        ])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&[0xff]),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&wealdrelay::cbor::array(&[
            wealdrelay::cbor::uint(8),
            wealdrelay::cbor::uint(0),
        ])),
        Err(RedeemError::UnknownStep(8))
    ));
    assert_eq!(
        RedeemError::UnknownStep(8).code(),
        invite::UNAVAILABLE,
        "even a decoder failure answers the same word"
    );
    assert!(RedeemError::Malformed("why".into())
        .to_string()
        .contains("why"));
    assert!(RedeemError::UnknownStep(8).to_string().contains('8'));

    // A relay answering with more bundles than an invite may have scopes. Not a
    // shape a relay this build wrote can produce, which is the point: a client
    // decodes whatever arrives, and a bound it does not enforce is a relay that can
    // make it allocate.
    let flood = wealdrelay::cbor::array(&[
        wealdrelay::cbor::uint(1),
        wealdrelay::cbor::array(
            &(0..invite::MAX_SCOPES + 1)
                .map(|_| {
                    wealdrelay::cbor::array(&[
                        wealdrelay::cbor::bytes(&[4; 32]),
                        wealdrelay::cbor::uint(1),
                        wealdrelay::cbor::bytes(b"ct"),
                    ])
                })
                .collect::<Vec<_>>(),
        ),
    ]);
    assert!(matches!(
        Response::decode(&flood),
        Err(RedeemError::Malformed(_))
    ));

    // And the one mapping every refusal on this path goes through. A relay that
    // could not look says come back; everything else is the single generic answer.
    use wealdrelay::frame::ErrorCode;
    use wealdrelay::invite::store::StoreError;
    assert_eq!(
        StoreError::Database("gone".into()).code(),
        ErrorCode::Backpressure
    );
    assert_eq!(
        StoreError::Refused(invite::InviteError::Expired).code(),
        invite::UNAVAILABLE
    );
    assert_eq!(
        StoreError::Code(invite::code::CodeError::WrongLength(3)).code(),
        invite::UNAVAILABLE
    );
}

/// Every field of every step, given the wrong bytes.
///
/// A decoder that read the fields in another order would still pass a single
/// malformed case while interpreting a nonce as a device key. This is the same
/// per-position walk the invite record and the recovery wrap get, and it is worth
/// having here more than anywhere: these bytes arrive before authentication, from
/// anybody who can open a socket.
#[tokio::test]
async fn every_field_of_every_step_is_checked_at_its_own_position() {
    use wealdrelay::cbor;
    use wealdrelay::invite::redeem::RedeemError;

    let uint = cbor::uint(1);
    let bytes = cbor::bytes(&[1]);

    // Step 0, reserve: token, code, nonce, device. Each in turn given an integer
    // where a byte string belongs.
    for position in 1..5 {
        let mut fields = vec![
            cbor::uint(0),
            cbor::bytes(&[1; 16]),
            cbor::bytes(b"ABCD-EFGH-JKLM"),
            cbor::bytes(&[2; 16]),
            cbor::bytes(&[3; 32]),
        ];
        fields[position] = uint.clone();
        assert!(
            matches!(
                Request::decode(&cbor::array(&fields)),
                Err(RedeemError::Malformed(_))
            ),
            "reserve accepted an integer at position {position}"
        );
    }

    // Step 1, bundles: token and group.
    for position in 1..3 {
        let mut fields = vec![cbor::uint(1), cbor::bytes(&[1; 16]), cbor::bytes(&[4; 32])];
        fields[position] = uint.clone();
        assert!(
            matches!(
                Request::decode(&cbor::array(&fields)),
                Err(RedeemError::Malformed(_))
            ),
            "bundles accepted an integer at position {position}"
        );
    }

    // Step 2, commit: token, nonce, device, group.
    for position in 1..5 {
        let mut fields = vec![
            cbor::uint(2),
            cbor::bytes(&[1; 16]),
            cbor::bytes(&[2; 16]),
            cbor::bytes(&[3; 32]),
            cbor::bytes(&[4; 32]),
        ];
        fields[position] = uint.clone();
        assert!(
            matches!(
                Request::decode(&cbor::array(&fields)),
                Err(RedeemError::Malformed(_))
            ),
            "commit accepted an integer at position {position}"
        );
    }

    // The step number itself, and trailing bytes after a complete request.
    assert!(matches!(
        Request::decode(&cbor::array(&[bytes.clone(), cbor::bytes(&[1; 16])])),
        Err(RedeemError::Malformed(_))
    ));
    let mut trailing = Request::Bundles {
        token: vec![1; 16],
        group: vec![4; 32],
    }
    .encode();
    trailing.push(0x00);
    assert!(matches!(
        Request::decode(&trailing),
        Err(RedeemError::Malformed(_))
    ));

    // And the answers, the same way. A client decodes whatever a relay sends it.
    assert!(matches!(
        Response::decode(&cbor::array(&[bytes.clone(), uint.clone()])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[cbor::uint(0), bytes.clone()])),
        Err(RedeemError::Malformed(_))
    ));
    // An expiry past what a signed millisecond can hold.
    assert!(matches!(
        Response::decode(&cbor::array(&[cbor::uint(0), cbor::uint(u64::MAX)])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[cbor::uint(1), uint.clone()])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[
            cbor::uint(1),
            cbor::array(&[cbor::array(&[
                cbor::uint(1),
                cbor::uint(1),
                cbor::bytes(b"ct")
            ])]),
        ])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[
            cbor::uint(1),
            cbor::array(&[cbor::array(&[
                cbor::bytes(&[4; 32]),
                bytes.clone(),
                cbor::bytes(b"ct")
            ])]),
        ])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[
            cbor::uint(1),
            cbor::array(&[cbor::array(&[
                cbor::bytes(&[4; 32]),
                cbor::uint(1),
                uint.clone()
            ])]),
        ])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[
            cbor::uint(1),
            cbor::array(&[cbor::array(&[cbor::bytes(&[4; 32]), cbor::uint(1)])]),
        ])),
        Err(RedeemError::Malformed(_))
    ));
    assert!(matches!(
        Response::decode(&cbor::array(&[cbor::uint(2), uint])),
        Err(RedeemError::Malformed(_))
    ));
    let mut trailing = Response::Committed {
        receipt: vec![5; 32],
    }
    .encode();
    trailing.push(0x00);
    assert!(matches!(
        Response::decode(&trailing),
        Err(RedeemError::Malformed(_))
    ));
}

/// A workspace's first day, over sockets, end to end.
///
/// The relay mints a genesis key on first run; a device that is nobody redeems the
/// bootstrap invite; the same device publishes the genesis access set; the relay
/// destroys the private half of the key and writes entry zero of the transparency
/// log. Every step over a real socket against a real Postgres, because every step is
/// one the harness cannot do on the client's behalf: the code is Argon2-verified
/// against a hash of a value the relay never learns, and the set is signed by a
/// device key.
///
/// The awkward part, and the reason this is worth a test of its own: at every point
/// before the last one there are no groups. Groups are made by the trust root, and
/// the trust root is admitted by this publication. So the relay cannot resolve the
/// workspace the way it resolves it for everything else, which is from the groups a
/// connection names.
#[tokio::test(flavor = "multi_thread")]
async fn a_workspace_is_founded_by_a_device_that_was_nobody() {
    use ed25519_dalek::Signer as _;
    use wealdrelay::access::{entry_hash, AccessSet};
    use wealdrelay::invite::genesis::{self, Ensured};

    let scratch = Scratch::new("invite_socket_genesis").await;
    let blobs = tempfile::tempdir().unwrap();
    // The system clock, unlike every other test in this file. A reservation's
    // liveness is read against the database's `now()`, so a relay whose clock says
    // 2023 writes a seat that expired years ago and the founding lookup, which is a
    // query with `expires_at > now()` in it, correctly finds nothing. That is the
    // right behaviour and the wrong fixture.
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::System).await;
    let pool = relay.state.database.as_ref().expect("a database").pool();

    // First run: the relay's own genesis key, minted the way `serve::bootstrap`
    // mints it. The wall clock, because expiry is read against the database's.
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let Ensured::Minted(run) = genesis::ensure(pool, WORKSPACE, wall).await.expect("mints") else {
        panic!("a fresh relay mints");
    };

    // The joining device. Nobody: no roster entry, no access set, no group.
    let trust_root = SigningKey::from_bytes(&[0x21; 32]);
    let recovery = SigningKey::from_bytes(&[0x3f; 32]);
    let mut joiner = connected(&relay).await;
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: run.token.clone(),
                code: run.code.grouped(),
                nonce: vec![0x01; 16],
                device: trust_root.verifying_key().to_bytes().to_vec(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Join { .. } => {}
        other => panic!("the bootstrap seat was refused: {other:?}"),
    }

    // Now it can authenticate, because reserving wrote a provisional grant. It
    // reaches `Bootstrapping`, where the one frame it may send is `ACCESS`.
    let mut founder = Client::connect(relay.address).await;
    founder
        .handshake_as(&trust_root, vec![vec![0x77; 32]], CLOCK)
        .await;

    // The salt, asked for over the same socket. There is no group to resolve the
    // workspace from, so this is the query that has to work through the reservation.
    founder
        .send_frame(&Frame::Access { body: Vec::new() })
        .await;
    let salt = match founder.recv_frame().await {
        Frame::Access { body } => {
            // `[salt, null]`: a workspace with no accepted set has no head, and the
            // salt is what the entries of its first set are computed with.
            let mut reader = wealdrelay::cbor::Reader::new(&body);
            reader.array(2).expect("a two field answer");
            let salt = reader.bytes().expect("the salt");
            assert!(
                reader.optional_is_null().expect("a head or null"),
                "a workspace with no set answered with a head"
            );
            salt
        }
        other => panic!("the state query was refused: {other:?}"),
    };

    // And the genesis set, signed by the device that holds the seat.
    let mut set = AccessSet {
        workspace: vec![0x77; 32],
        version: 0,
        prev_hash: vec![0u8; 32],
        issued_at: CLOCK,
        entries: {
            let mut entries = vec![
                entry_hash(&trust_root.verifying_key().to_bytes(), &salt),
                entry_hash(&recovery.verifying_key().to_bytes(), &salt),
            ];
            entries.sort();
            entries
        },
        authorizers: vec![trust_root.verifying_key().to_bytes().to_vec()],
        recovery: vec![recovery.verifying_key().to_bytes().to_vec()],
        quorum: None,
        pending: Vec::new(),
        signer: trust_root.verifying_key().to_bytes().to_vec(),
        sig: vec![0u8; 64],
    };
    set.sig = trust_root.sign(&set.digest_input()).to_bytes().to_vec();
    founder
        .send_frame(&Frame::Access { body: set.encode() })
        .await;
    match founder.recv_frame().await {
        Frame::Access { body } => assert_eq!(body, set.digest().to_vec()),
        other => panic!("the genesis set was refused: {other:?}"),
    }

    // The key is gone, in the same transaction that accepted the set. There is no
    // configuration flag and no support call that puts it back.
    let held: bool = sqlx::query_scalar(
        "select secret_key is not null from relay_genesis where workspace_id = $1",
    )
    .bind(WORKSPACE)
    .fetch_one(pool)
    .await
    .expect("read the genesis row");
    assert!(!held, "the genesis key survived its own redemption");

    // And the log begins, at entry zero, with an all-zero predecessor. This is the
    // answer to "was this workspace founded by the device I think founded it",
    // available forever.
    let log = genesis::log(pool, WORKSPACE).await.expect("read the log");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].seq, 0);
    assert_eq!(log[0].prev_hash, vec![0u8; 32]);
    assert_eq!(log[0].kind, genesis::GENESIS_KIND);

    relay.shutdown().await;
    scratch.drop_database().await;
}

/// What the redeem path answers when the relay cannot look.
///
/// Every step of a redemption has a database behind it, and every one of them has
/// to tell a joiner the difference between "no" and "not now". `retry/backpressure`
/// with the socket open means come back; `quota/seats_exhausted` means this invite
/// is not going to work and the difference matters to somebody standing in front of
/// a setup screen.
///
/// The faults are real states of a real Postgres, injected one statement at a time,
/// because a redemption reaches four tables and a failure in the fourth says nothing
/// about the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_cannot_look_says_come_back_at_every_step() {
    let scratch = Scratch::new("invite_socket_faults").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::System).await;
    let code = Code::from_bits(0x0e0e0e);
    // Issued against the wall clock, because this relay runs on the system clock:
    // an invite whose expiry is this suite's fixed 2023 instant is expired before
    // the first request and every answer below would be `unavailable` for the
    // honest reason rather than the injected one.
    let mut record = issue(0xd1, code, 4);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    record.issued_at = wall;
    record.expires = wall + invite::DEFAULT_EXPIRY_MS;
    record.sig = SigningKey::from_bytes(&[1; 32])
        .sign(&record.digest_input())
        .to_bytes()
        .to_vec();
    let pool_for_seed = relay.state.database.as_ref().unwrap().pool();
    store::create(pool_for_seed, WORKSPACE, &record, wall as i64)
        .await
        .expect("the invite is stored");
    let pool = relay.state.database.as_ref().unwrap().pool();
    let device = vec![0x88; 32];

    async fn inject(pool: &sqlx::PgPool, statement: &str) {
        sqlx::query(statement)
            .execute(pool)
            .await
            .unwrap_or_else(|error| panic!("the injected state must land: {statement}: {error}"));
    }

    let mut joiner = connected(&relay).await;

    // The reservation, against a table that refuses writes. The invite is fine and
    // the code is right; the relay is not, and a joiner told `quota` here would
    // throw away an invitation that still works.
    inject(
        pool,
        "create or replace function weald_injected_refusal() returns trigger \
         language plpgsql as $$ begin raise exception 'injected'; end $$",
    )
    .await;
    inject(
        pool,
        "create trigger weald_injected before insert on relay_invite_reservation \
         for each statement execute function weald_injected_refusal()",
    )
    .await;
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x21; 16],
                device: device.clone(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, wealdrelay::frame::ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    inject(
        pool,
        "drop trigger weald_injected on relay_invite_reservation",
    )
    .await;

    // The bundle fetch, against a table that is not there.
    inject(
        pool,
        "alter table relay_invite_bundle rename to weald_parked",
    )
    .await;
    joiner
        .send_frame(&Frame::Join {
            body: Request::Bundles {
                token: record.token.clone(),
                group: root(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, wealdrelay::frame::ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    inject(
        pool,
        "alter table weald_parked rename to relay_invite_bundle",
    )
    .await;

    // A real seat, so the commit below is refused by the fault rather than by the
    // absence of a reservation.
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x22; 16],
                device: device.clone(),
            }
            .encode(),
        })
        .await;
    assert!(matches!(joiner.recv_frame().await, Frame::Join { .. }));

    inject(
        pool,
        "alter table relay_invite_scope rename to weald_parked",
    )
    .await;
    joiner
        .send_frame(&Frame::Join {
            body: Request::Commit {
                token: record.token.clone(),
                nonce: vec![0x22; 16],
                device: device.clone(),
                group: root(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, wealdrelay::frame::ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    inject(
        pool,
        "alter table weald_parked rename to relay_invite_scope",
    )
    .await;

    // And the salt read, which is what stands between a token and a device hash.
    // Renamed rather than dropped, so the workspace still exists and only the read
    // fails: the answer must still be come back rather than a refusal that reads as
    // "this invite is dead".
    inject(pool, "alter table relay_workspace rename to weald_parked").await;
    joiner
        .send_frame(&Frame::Join {
            body: Request::Reserve {
                token: record.token.clone(),
                code: code.grouped(),
                nonce: vec![0x23; 16],
                device: device.clone(),
            }
            .encode(),
        })
        .await;
    match joiner.recv_frame().await {
        Frame::Error(error) => assert_eq!(error.code, wealdrelay::frame::ErrorCode::Backpressure),
        other => panic!("expected backpressure, got {other:?}"),
    }
    inject(pool, "alter table weald_parked rename to relay_workspace").await;

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_with_no_database_at_all_says_come_back_rather_than_refusing_the_invite() {
    // The other shape of the same answer, and the one a client meets during a
    // failover: the relay is up, the socket is open, and there is nothing behind it.
    let scratch = Scratch::new("invite_socket_nodb").await;
    let blobs = tempfile::tempdir().unwrap();
    let relay = Running::start(config_for(&scratch, blobs.path()), Clock::System).await;
    let state = std::sync::Arc::new(wealdrelay::health::RelayState::new(
        relay.state.config.clone(),
        None,
        None,
    ));
    let (sender, mut receiver) = wealdrelay::ws::outbound_channel();
    let mut session = wealdrelay::session::Session::new(&state.config);
    assert!(
        wealdrelay::ws::perform(
            &sender,
            &state,
            &mut session,
            state.hub.connect(),
            wealdrelay::session::Work::Redeem {
                body: Request::Reserve {
                    token: vec![0x01; 16],
                    code: "AAAA-BBBB-CCCC".to_string(),
                    nonce: vec![0x02; 16],
                    device: vec![0x03; 32],
                }
                .encode(),
            },
            0,
        )
        .await,
        "a relay with no database must not drop the connection"
    );
    match receiver.try_recv() {
        Ok(wealdrelay::ws::Outbound::Frame(Frame::Error(error))) => {
            assert_eq!(error.code, wealdrelay::frame::ErrorCode::Backpressure);
        }
        other => panic!("expected backpressure, got {other:?}"),
    }

    relay.shutdown().await;
    scratch.drop_database().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_state_query_whose_genesis_lookup_fails_is_a_retry_and_not_a_refusal() {
    // The state query has two ways to resolve a workspace and this is what happens
    // when the second one cannot run. A device asking for the salt is told to come
    // back, not told its workspace is unknown: the difference is whether it waits
    // or gives up on an enrolment that is perfectly valid.
    //
    // **Which session reaches the genesis lookup changed, and the test moved with
    // it.** This used to drive a founding device on an enforcing relay, on the
    // reasoning that a trust root has no groups and so must be resolved from its
    // bootstrap reservation. Two things have since made that unreachable, both
    // deliberately. A successful `reserve` now writes a provisional grant in the
    // same transaction as the seat (`invite/reserve.rs`), so the founder is
    // admitted as an ordinary member and its session carries a workspace; and
    // `ws.rs report_access_state` answers from that admitted workspace and from
    // nothing else, because resolving from the groups a client names is a
    // cross-tenant oracle (BR-013). `store::state_of` cannot answer `None` for a
    // workspace, so a bound session never falls through to genesis at all.
    //
    // What is left is the session that carries no workspace claim, which is
    // `WEALD_RELAY_ACCESS_SET=off`, the one ci diagnostic mode `environments.md`
    // permits. There the group-resolved form is still the first attempt, a group
    // this relay does not know resolves nothing, and the genesis lookup is the
    // second. That is the branch under test, and parking the table is still the
    // only honest way to make it fail rather than answer.
    let scratch = Scratch::new("invite_socket_statefault").await;
    let blobs = tempfile::tempdir().unwrap();
    let mut config = config_for(&scratch, blobs.path());
    config.access_set = wealdrelay::config::AccessSetMode::Off;
    let relay = Running::start(config, Clock::System).await;
    let pool = relay.state.database.as_ref().unwrap().pool();

    let trust_root = SigningKey::from_bytes(&[0x31; 32]);
    let mut founder = Client::connect(relay.address).await;
    founder
        .handshake_as(&trust_root, vec![vec![0x77; 32]], CLOCK)
        .await;

    sqlx::query("alter table relay_genesis rename to weald_parked")
        .execute(pool)
        .await
        .expect("park the genesis table");
    founder
        .send_frame(&Frame::Access { body: Vec::new() })
        .await;
    match founder.recv_frame().await {
        Frame::Error(error) => assert_eq!(
            error.code,
            wealdrelay::frame::ErrorCode::Backpressure,
            "a lookup that could not run must not read as an unknown workspace"
        ),
        other => panic!("expected backpressure, got {other:?}"),
    }
    sqlx::query("alter table weald_parked rename to relay_genesis")
        .execute(pool)
        .await
        .expect("restore the genesis table");

    relay.shutdown().await;
    scratch.drop_database().await;
}
