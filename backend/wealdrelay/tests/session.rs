// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The session state machine, without a socket and without a database.
//!
//! That absence is the point. `src/session.rs` was split out of the socket so
//! that the ordering rule (`CONNECT`, then `AUTH`, then content) could be proved
//! by walking every frame against every state rather than argued by reading the
//! frame handler top to bottom. A relay that answered `SEND` before `AUTH` would
//! be a relay any unauthenticated peer could write through, so the walk below is
//! the test that matters most in this file, and it builds its frame list from
//! `FrameTag::ALL` so that a frame added later without a rule fails here.

use proptest::prelude::*;
use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, FrameError, FrameTag, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, CLOCK_SKEW_LIMIT_MS, MAX_GROUPS_PER_CONNECTION,
};

/// The relay's clock in every test that does not care about skew. A fixed value,
/// because `handle` takes the clock as an argument precisely so that no test
/// reads a wall clock.
const NOW: u64 = 1_700_000_000_000;

/// Payloads the frame samples carry. Named once, so the expected `Work` and the
/// frame that produces it cannot drift apart.
const DEVICE_KEY: [u8; 32] = [7; 32];
const SIGNATURE: [u8; 64] = [9; 64];
const ENVELOPE: &[u8] = &[6, 6, 6];
const ACCESS_BODY: &[u8] = &[1, 2, 3];
const RECON_PAYLOAD: &[u8] = &[4, 5];
const BLOB_PAYLOAD: &[u8] = &[8];
const DROP_PAYLOAD: &[u8] = &[10];
const WRAP_BODY: &[u8] = &[9];
const HANDSHAKE_MESSAGE: &[u8] = &[10, 11];
const JOIN_BODY: &[u8] = &[12];
const FROM_SEQ: u64 = 5;

/// Every state, so a table-driven test walks them rather than remembering them.
const STATES: [State; 5] = [
    State::Fresh,
    State::Challenged,
    State::Ready,
    State::Bootstrapping,
    State::Closed,
];

/// A group id. Thirty-two bytes, the width the frame decoder enforces, so the
/// values here are the shape the session sees in production.
fn group(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// The three required keys and nothing else, then whatever one test changes.
/// Starting from the minimum means a failure names one variable.
fn config(extra: &[(&'static str, &'static str)]) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ];
    pairs.extend_from_slice(extra);
    Config::resolve(&Values::from_pairs(pairs)).expect("configuration resolves")
}

fn full() -> Config {
    config(&[])
}

fn read_only() -> Config {
    config(&[(keys::WRITE_MODE, "read_only")])
}

/// A `CONNECT` that will be accepted: the version this build speaks, one group,
/// and a client clock equal to the relay's.
fn connect() -> Frame {
    Frame::Connect {
        version: PROTOCOL_VERSION,
        groups: vec![group(1)],
        sent_at: NOW,
    }
}

/// A session driven to the given state by the frames that legitimately reach it.
/// Constructing the state by driving the machine rather than by reaching into it
/// means the fixture itself exercises the transitions it depends on.
fn session_in(state: State, config: &Config) -> Session {
    let mut session = Session::new(config);
    match state {
        State::Fresh => {}
        State::Challenged => {
            session.handle(connect(), NOW);
        }
        State::Ready => {
            session.handle(connect(), NOW);
            session.authenticated(0);
        }
        State::Bootstrapping => {
            session.handle(connect(), NOW);
            session.bootstrapping(0);
        }
        State::Closed => {
            session.handle(connect(), NOW);
            session.handle(Frame::Bye { reason: Vec::new() }, NOW);
        }
    }
    assert_eq!(session.state(), state, "fixture reached the wrong state");
    session
}

/// One frame per tag, so the walk covers the frame set by construction. The match
/// has no wildcard arm: a tag added to `FrameTag` stops this file compiling, which
/// is the mechanism that keeps the ordering table exhaustive.
fn sample(tag: FrameTag) -> Frame {
    match tag {
        FrameTag::Connect => connect(),
        FrameTag::ConnectAck => Frame::ConnectAck {
            version: PROTOCOL_VERSION,
            server_time: NOW,
            min_enc: 0,
        },
        FrameTag::AuthChallenge => Frame::AuthChallenge {
            challenge: vec![0; 32],
        },
        FrameTag::Auth => Frame::Auth {
            device_key: DEVICE_KEY.to_vec(),
            signature: SIGNATURE.to_vec(),
        },
        FrameTag::AuthAck => Frame::AuthAck {
            key_packages_remaining: 3,
            write_mode: 0,
            build_digest: b"sha256:test".to_vec(),
            access_set: 1,
            min_enc: 1,
        },
        FrameTag::Access => Frame::Access {
            body: ACCESS_BODY.to_vec(),
        },
        FrameTag::Sub => Frame::Sub {
            group: group(2),
            from_seq: FROM_SEQ,
        },
        FrameTag::SubAck => Frame::SubAck {
            group: group(2),
            head_seq: FROM_SEQ,
        },
        FrameTag::Recon => Frame::Recon {
            group: group(3),
            payload: RECON_PAYLOAD.to_vec(),
        },
        FrameTag::Push => Frame::Push {
            envelope: ENVELOPE.to_vec(),
        },
        FrameTag::Send => Frame::Send {
            envelope: ENVELOPE.to_vec(),
        },
        FrameTag::SendAck => Frame::SendAck {
            hash: vec![0; 32],
            seq: 1,
        },
        FrameTag::Blob => Frame::Blob {
            payload: BLOB_PAYLOAD.to_vec(),
        },
        FrameTag::Drop => Frame::Drop {
            payload: DROP_PAYLOAD.to_vec(),
        },
        FrameTag::Bye => Frame::Bye {
            reason: b"done".to_vec(),
        },
        FrameTag::Error => Frame::Error(FrameError::new(ErrorCode::Backpressure)),
        FrameTag::Wrap => Frame::Wrap {
            body: WRAP_BODY.to_vec(),
        },
        FrameTag::Join => Frame::Join {
            body: JOIN_BODY.to_vec(),
        },
        FrameTag::Handshake => Frame::Handshake {
            group: group(4),
            seq: 0,
            message: HANDSHAKE_MESSAGE.to_vec(),
        },
    }
}

/// What the documented rule says should happen to one frame in one state.
#[derive(Debug)]
enum Expected {
    /// The handshake opens: an acknowledgement and a challenge, and the session
    /// moves on to `Challenged`.
    Handshake,
    /// The state machine has decided the frame is allowed and handed the work to
    /// the socket layer.
    Deferred(Work),
    /// `AUTH`, whose work carries a challenge only the session knows.
    DeferredAuth,
    /// A clean close, in any live state.
    Farewell,
    /// The frame is not one this state accepts. Refused, and the connection ends.
    WrongState,
}

/// The ordering rule from `src/session.rs`, written out independently of the
/// implementation: only `CONNECT` in `Fresh`, only `AUTH` in `Challenged`, only
/// the five content frames in `Ready`, `BYE` in any live state, nothing at all
/// once closed.
fn expected(tag: FrameTag, state: State) -> Expected {
    match (state, tag) {
        (State::Fresh, FrameTag::Connect) => Expected::Handshake,
        // The challenge is not asserted here: it is derived from the relay's clock
        // and the requested groups, so the harness cannot name it in a table. The
        // handshake test below checks that the work carries exactly the challenge
        // this connection issued, which is the property that matters.
        (State::Challenged, FrameTag::Auth) => Expected::DeferredAuth,
        (State::Ready, FrameTag::Send) => Expected::Deferred(Work::Accept {
            envelope: ENVELOPE.to_vec(),
        }),
        (State::Ready, FrameTag::Sub) => Expected::Deferred(Work::Subscribe {
            group: group(2),
            from_seq: FROM_SEQ,
        }),
        (State::Ready, FrameTag::Recon) => Expected::Deferred(Work::Reconcile {
            group: group(3),
            payload: RECON_PAYLOAD.to_vec(),
        }),
        // `ACCESS` is the one frame a bootstrapping session may send, which is how a
        // workspace publishes the genesis set that admits everybody else.
        (State::Ready | State::Bootstrapping, FrameTag::Access) => {
            Expected::Deferred(Work::RotateAccessSet {
                body: ACCESS_BODY.to_vec(),
            })
        }
        // Ready only. A bootstrapping session holds no group whose epoch secret
        // could have derived a tag, so a wrap from one is a wrong-state frame.
        (State::Ready, FrameTag::Wrap) => Expected::Deferred(Work::PublishWrap {
            body: WRAP_BODY.to_vec(),
        }),
        // The only frame accepted before authentication, and the reason is in
        // `session.rs`: a device redeeming an invite has no membership to
        // authenticate with yet.
        (
            State::Fresh | State::Challenged | State::Ready | State::Bootstrapping,
            FrameTag::Join,
        ) => Expected::Deferred(Work::Redeem {
            body: JOIN_BODY.to_vec(),
        }),
        (State::Ready, FrameTag::Handshake) => Expected::Deferred(Work::PublishHandshake {
            group: group(4),
            message: HANDSHAKE_MESSAGE.to_vec(),
        }),
        (State::Ready, FrameTag::Blob) => Expected::Deferred(Work::BlobTicket {
            payload: BLOB_PAYLOAD.to_vec(),
        }),
        (State::Ready, FrameTag::Drop) => Expected::Deferred(Work::DropBefore {
            payload: DROP_PAYLOAD.to_vec(),
        }),
        (State::Fresh | State::Challenged | State::Ready | State::Bootstrapping, FrameTag::Bye) => {
            Expected::Farewell
        }
        _ => Expected::WrongState,
    }
}

/// The single error a wrong-state frame is answered with.
fn malformed_header() -> Reaction {
    Reaction::ReplyAndClose(vec![Frame::Error(FrameError::new(
        ErrorCode::MalformedHeader,
    ))])
}

/// The one error frame in a reaction, for the tests that check a code.
fn error_of(reaction: &Reaction) -> &FrameError {
    let frames = match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => frames,
        Reaction::Defer(work) => panic!("expected a reply, got deferred work: {work:?}"),
    };
    assert_eq!(frames.len(), 1, "expected exactly one frame: {frames:?}");
    match &frames[0] {
        Frame::Error(error) => error,
        other => panic!("expected an error frame, got {other:?}"),
    }
}

// MARK: The handshake

#[test]
fn the_handshake_runs_connect_then_auth_then_content() {
    // The happy path end to end, in one test, because the ordering rule is only
    // meaningful if the order it enforces is the order that works. Everything
    // else in this file is a way for this sequence to go wrong.
    let config = full();
    let mut session = Session::new(&config);
    assert_eq!(session.state(), State::Fresh);
    assert!(session.challenge().is_none());
    assert!(session.subscribed().is_empty());
    assert!(session.requested().is_empty());

    let reaction = session.handle(connect(), NOW);
    let Reaction::Reply(frames) = reaction else {
        panic!("CONNECT should be answered, not deferred or closed");
    };
    assert_eq!(frames.len(), 2, "an acknowledgement and a challenge");
    assert_eq!(
        frames[0],
        Frame::ConnectAck {
            version: PROTOCOL_VERSION,
            server_time: NOW,
            min_enc: 0,
        }
    );
    let Frame::AuthChallenge { challenge } = frames[1].clone() else {
        panic!("the second frame is the challenge");
    };
    assert_eq!(session.state(), State::Challenged);
    assert_eq!(session.requested(), &[group(1)]);
    assert_eq!(session.challenge(), Some(challenge.as_slice()));

    // `AUTH` is deferred: verifying a signature against the access set is the
    // socket layer's work, and keeping it out of here is what makes this file
    // free of a database.
    let reaction = session.handle(
        Frame::Auth {
            device_key: DEVICE_KEY.to_vec(),
            signature: SIGNATURE.to_vec(),
        },
        NOW,
    );
    assert_eq!(
        reaction,
        Reaction::Defer(Work::Authenticate {
            device_key: DEVICE_KEY.to_vec(),
            signature: SIGNATURE.to_vec(),
            // Exactly the bytes this connection issued. A signature captured from
            // another session verifies against another challenge and is refused by
            // the socket layer, which is the whole reason the challenge travels
            // with the work rather than being looked up later.
            challenge: challenge.clone(),
        })
    );
    // Spent. A second `AUTH` on this connection has nothing to verify against.
    assert!(session.challenge().is_none());
    assert_eq!(
        session.state(),
        State::Challenged,
        "the session is not ready until the caller says the signature checked out"
    );

    assert_eq!(session.authenticated(11), auth_ack(11, 0));
    assert_eq!(session.state(), State::Ready);

    // Every content frame is now allowed, and every one of them is work for
    // somebody else.
    for (frame, work) in [
        (
            Frame::Send {
                envelope: ENVELOPE.to_vec(),
            },
            Work::Accept {
                envelope: ENVELOPE.to_vec(),
            },
        ),
        (
            Frame::Sub {
                group: group(2),
                from_seq: FROM_SEQ,
            },
            Work::Subscribe {
                group: group(2),
                from_seq: FROM_SEQ,
            },
        ),
        (
            Frame::Recon {
                group: group(3),
                payload: RECON_PAYLOAD.to_vec(),
            },
            Work::Reconcile {
                group: group(3),
                payload: RECON_PAYLOAD.to_vec(),
            },
        ),
        (
            Frame::Access {
                body: ACCESS_BODY.to_vec(),
            },
            Work::RotateAccessSet {
                body: ACCESS_BODY.to_vec(),
            },
        ),
        (
            Frame::Blob {
                payload: BLOB_PAYLOAD.to_vec(),
            },
            Work::BlobTicket {
                payload: BLOB_PAYLOAD.to_vec(),
            },
        ),
        (
            Frame::Drop {
                payload: DROP_PAYLOAD.to_vec(),
            },
            Work::DropBefore {
                payload: DROP_PAYLOAD.to_vec(),
            },
        ),
    ] {
        assert_eq!(session.handle(frame, NOW), Reaction::Defer(work));
        assert_eq!(session.state(), State::Ready);
    }
}

// MARK: The ordering table

#[test]
fn every_frame_in_every_state_follows_the_documented_rule() {
    // This is the test that turns "a relay cannot answer SEND before AUTH" into a
    // proof rather than a reading of the code. The frame list comes from
    // `FrameTag::ALL` and the expectation comes from `expected`, so a frame with
    // no rule is a compile error and a frame with the wrong rule is a failure
    // that names the pair.
    let config = full();
    let mut permitted = 0;
    let mut refused = 0;
    for &tag in FrameTag::ALL {
        for state in STATES {
            let mut session = session_in(state, &config);
            let reaction = session.handle(sample(tag), NOW);
            let rule = expected(tag, state);
            let context = format!("{tag:?} in {state:?} gave {reaction:?}");
            match rule {
                Expected::Handshake => {
                    permitted += 1;
                    let Reaction::Reply(frames) = &reaction else {
                        panic!("{context}");
                    };
                    assert!(
                        matches!(frames[0], Frame::ConnectAck { .. })
                            && matches!(frames[1], Frame::AuthChallenge { .. }),
                        "{context}"
                    );
                    assert_eq!(session.state(), State::Challenged, "{context}");
                }
                Expected::Deferred(work) => {
                    permitted += 1;
                    assert_eq!(reaction, Reaction::Defer(work), "{context}");
                    assert_eq!(
                        session.state(),
                        state,
                        "deferring work does not move the session: {context}"
                    );
                }
                Expected::DeferredAuth => {
                    permitted += 1;
                    let Reaction::Defer(Work::Authenticate {
                        device_key,
                        signature,
                        challenge,
                    }) = &reaction
                    else {
                        panic!("{context}");
                    };
                    assert_eq!(device_key, &DEVICE_KEY.to_vec(), "{context}");
                    assert_eq!(signature, &SIGNATURE.to_vec(), "{context}");
                    assert!(!challenge.is_empty(), "{context}");
                    assert_eq!(
                        session.state(),
                        state,
                        "deferring work does not move the session: {context}"
                    );
                }
                Expected::Farewell => {
                    permitted += 1;
                    assert_eq!(
                        reaction,
                        Reaction::ReplyAndClose(vec![Frame::Bye { reason: Vec::new() }]),
                        "{context}"
                    );
                    assert_eq!(session.state(), State::Closed, "{context}");
                }
                Expected::WrongState => {
                    refused += 1;
                    assert_eq!(reaction, malformed_header(), "{context}");
                    assert_eq!(
                        error_of(&reaction).code.qualified(),
                        "reject/malformed_header",
                        "a frame in the wrong state is the client being wrong about \
                         the protocol: {context}"
                    );
                    assert_eq!(
                        session.state(),
                        State::Closed,
                        "a wrong-state frame ends the connection: {context}"
                    );
                }
            }
        }
    }

    // The counts are asserted so that a rule table which accidentally permitted
    // nothing, or permitted everything, could not pass the walk above.
    // Nineteen: CONNECT, AUTH, the eight content frames in `Ready`, BYE in each of
    // the four live states, and `ACCESS` again in `Bootstrapping`. That last one is
    // the whole of the bootstrap hole, and counting it here is what stops it
    // widening: a second frame permitted in that state moves this number and fails.
    // The count went from twelve to eighteen in step 8: `WRAP` and `HANDSHAKE`
    // became the sixth and seventh content frames in `Ready`, and `JOIN` is
    // accepted in all four live states because a device redeeming an invite has no
    // membership to authenticate with yet. Step 10 makes it nineteen: `DROP`, the
    // compaction instruction, is the eighth content frame and is `Ready` only,
    // because it names a group and a group is checked against an authenticated
    // workspace.
    //
    // The bootstrap hole is what this number is really guarding, and it is now two
    // frames wide rather than one: `ACCESS`, which publishes the genesis set, and
    // `JOIN`, which reserves the seat that set is published by. Both are steps of
    // the same enrolment and neither reads anything. A third would move this number
    // and fail here, which is the point.
    assert_eq!(
        permitted, 19,
        "CONNECT, AUTH, the eight content frames, BYE and JOIN in four live states, ACCESS while bootstrapping"
    );
    assert_eq!(refused, FrameTag::ALL.len() * STATES.len() - 19);
}

#[test]
fn a_closed_session_accepts_nothing_at_all() {
    // Stated separately from the walk because it is the property an operator
    // cares about: a connection the relay has finished with cannot be revived by
    // sending it more frames, not even another CONNECT.
    let config = full();
    for &tag in FrameTag::ALL {
        let mut session = session_in(State::Closed, &config);
        assert_eq!(session.handle(sample(tag), NOW), malformed_header());
        assert_eq!(session.state(), State::Closed);
    }
}

// MARK: CONNECT

#[test]
fn a_connect_with_another_version_aborts_the_connection() {
    // `operations.md`: a version failure aborts the connection and never silently
    // continues. Both directions are offered, because a client one version behind
    // and a client one version ahead are both wrong here and a comparison written
    // as a `<` would only catch one of them.
    let config = full();
    for version in [0, PROTOCOL_VERSION + 1, u16::MAX] {
        let mut session = Session::new(&config);
        let reaction = session.handle(
            Frame::Connect {
                version,
                groups: Vec::new(),
                sent_at: NOW,
            },
            NOW,
        );
        assert!(matches!(reaction, Reaction::ReplyAndClose(_)));
        let error = error_of(&reaction);
        assert_eq!(error.code.qualified(), "version/protocol_unsupported");
        assert_eq!(
            error.detail.as_deref(),
            Some(PROTOCOL_VERSION.to_be_bytes().as_slice()),
            "the error carries the version this build does speak"
        );
        assert_eq!(session.state(), State::Closed);
        assert!(
            session.challenge().is_none(),
            "a refused CONNECT issues no challenge"
        );
    }
}

#[test]
fn connect_accepts_the_group_limit_and_refuses_one_more() {
    // The boundary is tested from both sides, because a limit checked with the
    // wrong comparison is off by exactly one group and no test that only tries a
    // large number would notice.
    let config = full();
    let groups = |count: usize| -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let mut id = vec![0; 32];
                id[..8].copy_from_slice(&(index as u64).to_be_bytes());
                id
            })
            .collect()
    };

    let mut at_limit = Session::new(&config);
    let reaction = at_limit.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: groups(MAX_GROUPS_PER_CONNECTION),
            sent_at: NOW,
        },
        NOW,
    );
    assert!(matches!(reaction, Reaction::Reply(_)));
    assert_eq!(at_limit.state(), State::Challenged);
    assert_eq!(at_limit.requested().len(), MAX_GROUPS_PER_CONNECTION);

    let mut over = Session::new(&config);
    let reaction = over.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: groups(MAX_GROUPS_PER_CONNECTION + 1),
            sent_at: NOW,
        },
        NOW,
    );
    let error = error_of(&reaction);
    assert_eq!(error.code.qualified(), "quota/rate_limited");
    assert_eq!(
        error.detail.as_deref(),
        Some((MAX_GROUPS_PER_CONNECTION as u64).to_be_bytes().as_slice()),
        "the client is told the limit rather than left to guess it"
    );
    assert_eq!(over.state(), State::Closed);
    assert!(over.requested().is_empty());
}

#[test]
fn min_enc_in_connect_ack_is_the_configured_floor() {
    // A client that would be refused learns the floor in the acknowledgement
    // rather than on its first write, so the byte has to come from configuration
    // and not from a constant.
    for (value, expected_byte) in [("none", 0), ("mls", 1)] {
        let config = config(&[(keys::MIN_ENC, value)]);
        let mut session = Session::new(&config);
        let Reaction::Reply(frames) = session.handle(connect(), NOW) else {
            panic!("CONNECT is answered");
        };
        assert_eq!(
            frames[0],
            Frame::ConnectAck {
                version: PROTOCOL_VERSION,
                server_time: NOW,
                min_enc: expected_byte,
            },
            "min_enc for {value}"
        );
    }
}

// MARK: Clock skew

/// The skew a `CONNECT` at `sent_at` reports against a relay clock of `NOW`.
fn skew_for(sent_at: u64, relay_ms: u64) -> Option<i64> {
    let config = full();
    let mut session = Session::new(&config);
    session.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: Vec::new(),
            sent_at,
        },
        relay_ms,
    );
    session.skew_ms()
}

#[test]
fn skew_is_reported_only_past_the_limit_and_with_the_right_sign() {
    // The limit is a tolerance, so the interesting values are at it and either
    // side of it. The sign matters as much as the magnitude: the client uses it to
    // decide whether its own invite-expiry arithmetic can be trusted, and a
    // magnitude with no direction would not tell it which way to correct.
    assert_eq!(skew_for(NOW, NOW), None, "agreeing clocks say nothing");
    assert_eq!(
        skew_for(NOW + CLOCK_SKEW_LIMIT_MS, NOW),
        None,
        "exactly at the limit is still inside the tolerance"
    );
    assert_eq!(
        skew_for(NOW - CLOCK_SKEW_LIMIT_MS, NOW),
        None,
        "and the same in the other direction"
    );

    let ahead = CLOCK_SKEW_LIMIT_MS + 1;
    assert_eq!(
        skew_for(NOW + ahead, NOW),
        Some(i64::try_from(ahead).unwrap()),
        "a client ahead of the relay reports a positive skew"
    );
    assert_eq!(
        skew_for(NOW - ahead, NOW),
        Some(-i64::try_from(ahead).unwrap()),
        "a client behind the relay reports a negative skew"
    );

    // An hour out is the misconfigured container the limit exists to catch.
    assert_eq!(skew_for(NOW + 3_600_000, NOW), Some(3_600_000));
}

#[test]
fn an_absurd_clock_saturates_rather_than_overflowing() {
    // A `u64` millisecond clock can hold values no `i64` difference can express.
    // A peer can put any number it likes in `sent_at`, so the arithmetic has to
    // saturate rather than wrap or panic: this test exists because the alternative
    // is a peer choosing a number that aborts the relay's thread.
    assert_eq!(
        skew_for(u64::MAX, NOW),
        Some(i64::MAX - i64::try_from(NOW).unwrap())
    );
    assert_eq!(
        skew_for(NOW, u64::MAX),
        Some(i64::try_from(NOW).unwrap() - i64::MAX)
    );
    assert_eq!(
        skew_for(u64::MAX, u64::MAX),
        None,
        "two clocks that saturate to the same value do not disagree"
    );
}

#[test]
fn the_relay_never_adjusts_its_own_clock_to_the_clients() {
    // `operations.md`: the relay evaluates every expiry it owns against its own
    // observed time. So a skewed client is told and not trusted, and
    // `server_time` is the clock that was passed in whatever the client claimed.
    let config = full();
    for sent_at in [0, NOW, NOW + 3_600_000, u64::MAX] {
        let mut session = Session::new(&config);
        let Reaction::Reply(frames) = session.handle(
            Frame::Connect {
                version: PROTOCOL_VERSION,
                groups: Vec::new(),
                sent_at,
            },
            NOW,
        ) else {
            panic!("CONNECT is answered");
        };
        assert_eq!(
            frames[0],
            Frame::ConnectAck {
                version: PROTOCOL_VERSION,
                server_time: NOW,
                min_enc: 0,
            },
            "server_time for a client claiming {sent_at}"
        );
    }
}

// MARK: The challenge

#[test]
fn the_challenge_is_thirty_two_bytes_and_unique_per_session() {
    // The challenge is what stops a signature captured from one session being
    // replayed into another, which it can only do if two sessions never issue the
    // same bytes.
    let config = full();
    let issue = |now_ms: u64, groups: Vec<Vec<u8>>| -> Vec<u8> {
        let mut session = Session::new(&config);
        let Reaction::Reply(frames) = session.handle(
            Frame::Connect {
                version: PROTOCOL_VERSION,
                groups,
                sent_at: now_ms,
            },
            now_ms,
        ) else {
            panic!("CONNECT is answered");
        };
        let Frame::AuthChallenge { challenge } = frames[1].clone() else {
            panic!("the second frame is the challenge");
        };
        challenge
    };

    let first = issue(NOW, vec![group(1)]);
    // Same relay time and same requested groups is the replay collision that
    // matters: two sockets can begin in one millisecond. Their challenges must
    // still differ because the per-session nonce is part of the derivation.
    let second = issue(NOW, vec![group(1)]);
    assert_eq!(first.len(), 32, "a full BLAKE3 output");
    assert_eq!(second.len(), 32);
    assert_ne!(
        first, second,
        "two otherwise identical sessions must not share a challenge"
    );
    assert_ne!(
        first,
        issue(NOW, vec![group(2)]),
        "the requested groups are in the derivation too"
    );
    assert_ne!(
        first,
        vec![0; 32],
        "an all-zero challenge would mean the derivation ran on nothing"
    );
}

#[test]
fn the_challenge_is_spent_once_authentication_succeeds() {
    // Held so that `AUTH` is verified against the bytes this connection sent, and
    // cleared afterwards so a second `AUTH` cannot reuse it. The frame table
    // refuses a second `AUTH` as well, and both belong here: this one is the belt
    // and the walk above is the braces.
    let config = full();
    let mut session = Session::new(&config);
    session.handle(connect(), NOW);
    assert_eq!(session.challenge().map(<[u8]>::len), Some(32));
    session.authenticated(0);
    assert!(session.challenge().is_none());
}

// MARK: Write mode

#[test]
fn read_only_refuses_send_locally_and_still_serves_readers() {
    // The whole point of the mode: a relay in maintenance refuses durable writes
    // without a database round trip per refusal, while subscription and
    // reconciliation keep working. A `SEND` that deferred here would mean
    // maintenance still touched the database on every rejected write.
    let config = read_only();
    let mut session = session_in(State::Ready, &config);

    let reaction = session.handle(
        Frame::Send {
            envelope: ENVELOPE.to_vec(),
        },
        NOW,
    );
    assert_eq!(
        reaction,
        Reaction::Reply(vec![Frame::Error(FrameError::new(
            ErrorCode::ServiceReadOnly
        ))]),
        "answered here, not deferred"
    );
    assert_eq!(
        error_of(&reaction).code.qualified(),
        "denied/service_read_only"
    );
    assert_eq!(
        session.state(),
        State::Ready,
        "a refused write does not end the connection"
    );

    assert_eq!(
        session.handle(
            Frame::Sub {
                group: group(2),
                from_seq: FROM_SEQ
            },
            NOW
        ),
        Reaction::Defer(Work::Subscribe {
            group: group(2),
            from_seq: FROM_SEQ
        }),
        "readers are unaffected"
    );
    assert_eq!(
        session.handle(
            Frame::Recon {
                group: group(3),
                payload: RECON_PAYLOAD.to_vec()
            },
            NOW
        ),
        Reaction::Defer(Work::Reconcile {
            group: group(3),
            payload: RECON_PAYLOAD.to_vec()
        }),
        "and so is reconciliation"
    );
}

#[test]
fn auth_ack_tells_the_client_which_write_mode_it_reached() {
    // A client that learned the mode only from a refused `SEND` would have to
    // attempt a write to discover it could not write.
    assert_eq!(Session::new(&full()).authenticated(4), auth_ack(4, 0));
    assert_eq!(Session::new(&read_only()).authenticated(4), auth_ack(4, 1));
}

// MARK: Subscription limits

#[test]
fn resubscribing_does_not_count_twice_against_the_group_limit() {
    // A client that re-subscribes to catch up from a new cursor is doing something
    // ordinary. If each `SUB` consumed a slot, a long-lived connection would be
    // rate limited for reading the same group repeatedly, which is the opposite of
    // what the limit is for.
    let config = full();
    let mut session = session_in(State::Ready, &config);
    for from_seq in 0..10 {
        assert_eq!(
            session.handle(
                Frame::Sub {
                    group: group(1),
                    from_seq
                },
                NOW
            ),
            Reaction::Defer(Work::Subscribe {
                group: group(1),
                from_seq
            })
        );
    }
    assert_eq!(session.subscribed(), &[group(1)]);
}

#[test]
fn the_group_limit_refuses_a_new_group_but_never_a_known_one() {
    // At the limit the distinction matters: refusing a group the connection is
    // already serving would break a client that was inside the limit the whole
    // time.
    let config = full();
    let mut session = session_in(State::Ready, &config);
    for index in 0..MAX_GROUPS_PER_CONNECTION {
        let mut id = vec![0; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        assert!(matches!(
            session.handle(
                Frame::Sub {
                    group: id,
                    from_seq: 0
                },
                NOW
            ),
            Reaction::Defer(_)
        ));
    }
    assert_eq!(session.subscribed().len(), MAX_GROUPS_PER_CONNECTION);

    let reaction = session.handle(
        Frame::Sub {
            group: group(0xff),
            from_seq: 0,
        },
        NOW,
    );
    let error = error_of(&reaction);
    assert_eq!(error.code.qualified(), "quota/rate_limited");
    assert_eq!(
        error.detail.as_deref(),
        Some((MAX_GROUPS_PER_CONNECTION as u64).to_be_bytes().as_slice())
    );
    assert_eq!(
        session.state(),
        State::Ready,
        "over a subscription limit is not a reason to drop the connection"
    );
    assert_eq!(session.subscribed().len(), MAX_GROUPS_PER_CONNECTION);

    // The first group again, at the limit, still works.
    let mut known = vec![0; 32];
    known[..8].copy_from_slice(&0u64.to_be_bytes());
    assert!(matches!(
        session.handle(
            Frame::Sub {
                group: known,
                from_seq: 7
            },
            NOW
        ),
        Reaction::Defer(_)
    ));
}

// MARK: Rejection

#[test]
fn rejection_closes_the_session_and_names_the_reason() {
    // A peer that cannot prove a key has nothing else to say, and leaving the
    // socket open would let it keep guessing. More than one code is checked so the
    // reason is carried rather than replaced by a fixed one.
    let config = full();
    for code in [
        ErrorCode::WriterNotInAccessSet,
        ErrorCode::MalformedHeader,
        ErrorCode::SeatsExhausted,
    ] {
        let mut session = session_in(State::Challenged, &config);
        // The frames to send on the way out, and not a `Reaction`: a refusal always
        // closes, so the caller in `ws::refuse` has nothing to match on.
        let frames = session.rejected(code);
        assert_eq!(frames, vec![Frame::Error(FrameError::new(code))]);
        assert_eq!(session.state(), State::Closed);
        // And the closed session is as closed as any other.
        assert_eq!(session.handle(connect(), NOW), malformed_header());
    }
}

// MARK: Properties

/// An arbitrary frame, including the relay-to-client ones a client has no
/// business sending. The point of the property is that the session survives
/// anything a peer can put on the wire, so the generator does not exclude the
/// frames a well-behaved client would never send.
fn any_frame() -> impl Strategy<Value = Frame> {
    let bytes = || prop::collection::vec(any::<u8>(), 0..40);
    prop_oneof![
        (
            any::<u16>(),
            prop::collection::vec(bytes(), 0..4),
            any::<u64>()
        )
            .prop_map(|(version, groups, sent_at)| Frame::Connect {
                version,
                groups,
                sent_at
            }),
        (any::<u16>(), any::<u64>(), any::<u8>()).prop_map(|(version, server_time, min_enc)| {
            Frame::ConnectAck {
                version,
                server_time,
                min_enc,
            }
        }),
        bytes().prop_map(|challenge| Frame::AuthChallenge { challenge }),
        (bytes(), bytes()).prop_map(|(device_key, signature)| Frame::Auth {
            device_key,
            signature
        }),
        (any::<u32>(), any::<u8>(), bytes(), any::<u8>(), any::<u8>()).prop_map(
            |(key_packages_remaining, write_mode, build_digest, access_set, min_enc)| {
                Frame::AuthAck {
                    key_packages_remaining,
                    write_mode,
                    build_digest,
                    access_set,
                    min_enc,
                }
            }
        ),
        bytes().prop_map(|body| Frame::Access { body }),
        (bytes(), any::<u64>()).prop_map(|(group, from_seq)| Frame::Sub { group, from_seq }),
        (bytes(), any::<u64>()).prop_map(|(group, head_seq)| Frame::SubAck { group, head_seq }),
        (bytes(), bytes()).prop_map(|(group, payload)| Frame::Recon { group, payload }),
        bytes().prop_map(|envelope| Frame::Push { envelope }),
        bytes().prop_map(|envelope| Frame::Send { envelope }),
        (bytes(), any::<u64>()).prop_map(|(hash, seq)| Frame::SendAck { hash, seq }),
        bytes().prop_map(|payload| Frame::Blob { payload }),
        bytes().prop_map(|reason| Frame::Bye { reason }),
        Just(Frame::Error(FrameError::new(ErrorCode::Backpressure))),
    ]
}

/// Case count comes from the environment so ci can run reduced counts on push
/// and full counts on a pull request, per `specs/backend/build/testing.md`.
fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    /// Any sequence of frames, in any order, with any clock, and the session
    /// neither panics nor comes back from the dead. Written as a property rather
    /// than as cases because the reachable (frame, state) pairs are the product of
    /// the frame set and the state set, and a peer chooses which of them it sends.
    #[test]
    fn no_sequence_of_frames_panics_or_reopens_a_closed_session(
        frames in prop::collection::vec((any_frame(), any::<u64>()), 0..=6),
    ) {
        let config = full();
        let mut session = Session::new(&config);
        let mut closed = false;
        for (frame, now_ms) in frames {
            let reaction = session.handle(frame, now_ms);
            if closed {
                // Every frame after the close is refused identically, so there is
                // no frame that resurrects a connection the relay has finished
                // with.
                prop_assert_eq!(&reaction, &malformed_header());
            }
            if matches!(reaction, Reaction::ReplyAndClose(_)) {
                closed = true;
            }
            prop_assert_eq!(session.state() == State::Closed, closed);
        }
    }
}

/// What `AUTH_ACK` looks like for a session built from the test configuration.
///
/// The digest is whatever `RunningDigest::resolve` found for the test binary,
/// which is an `exe-blake3:` self-hash: no image build baked one in. Asserting
/// on the resolved value rather than pinning a literal is deliberate, because
/// pinning one would make every rebuild of the test binary fail this assertion.
///
/// `min_enc` is zero because the configuration these tests build sets no
/// encryption floor. That it is reported truthfully rather than defaulted to the
/// safe-looking answer is the point: a relay accepting plaintext has to say so.
fn auth_ack(key_packages_remaining: u32, write_mode: u8) -> Frame {
    Frame::AuthAck {
        key_packages_remaining,
        write_mode,
        build_digest: wealdrelay::RunningDigest::resolve().line().into_bytes(),
        access_set: 1,
        min_enc: 0,
    }
}

// MARK: The running digest (step 12, verification.md proof 1)

#[test]
fn a_baked_image_digest_is_reported_verbatim_and_is_comparable() {
    let digest =
        wealdrelay::RunningDigest::resolve_with(Some("  sha256:abc123  ".to_string()), None);
    assert_eq!(
        digest,
        wealdrelay::RunningDigest::Image("sha256:abc123".to_string())
    );
    assert_eq!(digest.line(), "sha256:abc123");
    assert!(digest.is_comparable());
}

#[test]
fn without_a_baked_digest_the_binary_hashes_itself_and_says_so() {
    let exe = std::env::current_exe().expect("a test binary has a path");
    let digest = wealdrelay::RunningDigest::resolve_with(None, Some(exe.clone()));
    match &digest {
        wealdrelay::RunningDigest::Executable(hex) => assert_eq!(hex.len(), 64),
        other => panic!("expected a self-hash, got {other:?}"),
    }
    // Labelled, and therefore never comparable against a published release. A
    // self-hash formatted like an image digest would read as a permanent
    // mismatch and train somebody to ignore the banner.
    assert!(digest.line().starts_with("exe-blake3:"));
    assert!(!digest.is_comparable());
    // Same binary, same answer: the digest is a fact about the file, not about
    // when it was asked.
    assert_eq!(
        digest,
        wealdrelay::RunningDigest::resolve_with(None, Some(exe))
    );
}

#[test]
fn an_empty_baked_value_falls_through_rather_than_reporting_nothing() {
    let exe = std::env::current_exe().expect("a test binary has a path");
    let digest = wealdrelay::RunningDigest::resolve_with(Some("   ".to_string()), Some(exe));
    assert!(matches!(digest, wealdrelay::RunningDigest::Executable(_)));
}

#[test]
fn a_binary_that_cannot_be_read_reports_unknown_rather_than_empty() {
    let digest = wealdrelay::RunningDigest::resolve_with(
        None,
        Some(std::path::PathBuf::from("/nonexistent/wealdrelay")),
    );
    assert_eq!(digest, wealdrelay::RunningDigest::Unknown);
    assert_eq!(digest.line(), "unknown");
    assert!(!digest.is_comparable());
    // And the resolver reached for neither input, which is the desktop case.
    assert_eq!(
        wealdrelay::RunningDigest::resolve_with(None, None),
        wealdrelay::RunningDigest::Unknown
    );
}

#[test]
fn the_process_resolves_a_digest_without_being_told_one() {
    // The default path, exercised so `resolve` itself is covered: this test
    // binary has no baked digest, so it hashes itself.
    assert!(wealdrelay::RunningDigest::resolve()
        .line()
        .starts_with("exe-blake3:"));
}
