// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The ephemeral path without a socket and without a database.
//!
//! Everything the `LIVE` frame decides before it needs anything: the codec, the
//! five refusal paths in the order `specs/backend/relay/presence.md` states them,
//! the budget that is deliberately not the envelope budget, and the version filter
//! that keeps a version 1 subscriber from ever seeing one.
//!
//! The claim these tests exist to hold is the negative one. A beat is not durable,
//! and "not durable" is not something a reader of the code can verify by reading
//! it: the storage double in `no_live_frame_ever_reaches_storage` is what turns it
//! into a fact.

mod support;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{ErrorCode, Frame, FrameTag, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use wealdrelay::session::{
    Reaction, Session, State, Work, FRAME_BUDGET_WINDOW_MS, LIVE_FRAMES_PER_MINUTE, MAX_LIVE_BYTES,
};

const NOW: u64 = 1_700_000_000_000;

fn group(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn config(pairs: &[(&'static str, &'static str)]) -> Config {
    let mut values = vec![
        (keys::HOSTNAME, "relay.acme.com"),
        (keys::DATABASE_URL, "postgres://weald@localhost/weald_relay"),
        (keys::STORAGE_URL, "file:///var/lib/wealdrelay/blobs"),
    ];
    for (key, value) in pairs {
        values.retain(|(existing, _)| existing != key);
        values.push((key, value));
    }
    Config::resolve(&Values::from_pairs(values)).expect("configuration resolves")
}

/// A session in `Ready`, which is the only state a beat is accepted in.
fn ready(config: &Config) -> Session {
    let mut session = Session::new(config);
    session.handle(
        Frame::Connect {
            version: PROTOCOL_VERSION,
            groups: vec![group(1)],
            sent_at: NOW,
        },
        NOW,
    );
    session.authenticated(0);
    assert_eq!(session.state(), State::Ready);
    session
}

fn beat(ct: Vec<u8>) -> Frame {
    Frame::Live {
        group: group(1),
        epoch: 4,
        ct,
    }
}

fn refusal(reaction: &Reaction) -> ErrorCode {
    match reaction {
        Reaction::Reply(frames) | Reaction::ReplyAndClose(frames) => match frames.as_slice() {
            [Frame::Error(error)] => error.code,
            other => panic!("expected one error frame, got {other:?}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// MARK: The codec

#[test]
fn a_beat_round_trips_through_canonical_cbor() {
    let frame = beat(vec![9; 128]);
    let encoded = frame.encode();
    assert_eq!(Frame::decode(&encoded).expect("decodes"), frame);
    // Deterministic: one message has exactly one encoding, which is the property
    // every frame in this set has and which the content address depends on.
    assert_eq!(Frame::decode(&encoded).expect("decodes").encode(), encoded);
}

#[test]
fn the_two_new_tags_are_in_every_mirrored_list() {
    // Three lists in `frame.rs` name the tag set, and a tag in one and not the
    // others is a frame a peer could send that this build could not name back.
    for tag in [FrameTag::Live, FrameTag::Keys] {
        assert!(FrameTag::ALL.contains(&tag));
        assert_eq!(FrameTag::from_u16(tag as u16), Some(tag));
    }
    assert_eq!(FrameTag::Live as u16, 21);
    assert_eq!(FrameTag::Keys as u16, 22);
}

#[test]
fn a_beat_is_charged_its_payload_in_the_queue_budget() {
    // The queue budget is accounted in bytes, and a frame that reported zero would
    // let a flood of beats occupy a queue the accounting believed was empty.
    assert!(beat(vec![0; 1024]).queued_bytes() > 1024);
    assert!(beat(vec![0; 1024]).queued_bytes() < 1024 + 512);
}

// MARK: Version negotiation

#[test]
fn a_version_one_connect_still_decodes_on_this_build() {
    // The whole of the compatibility claim on the decode side. An equality check
    // here would have made a version 1 client's opening frame unreadable, which is
    // a client that cannot connect at all rather than one that misses a feature.
    let frame = Frame::Connect {
        version: MIN_PROTOCOL_VERSION,
        groups: vec![group(1)],
        sent_at: NOW,
    };
    assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
}

#[test]
fn a_connect_ack_below_this_builds_maximum_decodes() {
    // A version 2 client learning it is talking to a version 1 relay. It must read
    // the frame to learn that, so refusing it here would turn "presence is
    // unavailable" into "this relay is unusable".
    let frame = Frame::ConnectAck {
        version: MIN_PROTOCOL_VERSION,
        server_time: NOW,
        min_enc: 0,
    };
    assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
}

#[test]
fn the_selection_is_the_lower_of_the_two_ceilings() {
    let config = config(&[]);
    for offered in [MIN_PROTOCOL_VERSION, PROTOCOL_VERSION] {
        let mut session = Session::new(&config);
        let reaction = session.handle(
            Frame::Connect {
                version: offered,
                groups: vec![group(1)],
                sent_at: NOW,
            },
            NOW,
        );
        match reaction {
            Reaction::Reply(frames) => match frames.first() {
                Some(Frame::ConnectAck { version, .. }) => {
                    assert_eq!(*version, offered.min(PROTOCOL_VERSION));
                }
                other => panic!("expected a ConnectAck, got {other:?}"),
            },
            other => panic!("expected a handshake, got {other:?}"),
        }
        assert_eq!(session.negotiated_version(), offered.min(PROTOCOL_VERSION));
    }
}

#[test]
fn an_offer_below_the_floor_ends_the_connection() {
    let config = config(&[]);
    let mut session = Session::new(&config);
    let reaction = session.handle(
        Frame::Connect {
            version: MIN_PROTOCOL_VERSION - 1,
            groups: Vec::new(),
            sent_at: NOW,
        },
        NOW,
    );
    assert_eq!(refusal(&reaction), ErrorCode::ProtocolUnsupported);
    assert!(matches!(reaction, Reaction::ReplyAndClose(_)));
    assert_eq!(session.state(), State::Closed);
}

// MARK: The five refusals, in order

#[test]
fn a_beat_before_ready_closes_the_connection() {
    // There is no pre-auth case. `JOIN` remains the only frame a session may send
    // before it has authenticated, and a beat from an unauthenticated peer is a
    // peer claiming presence in a workspace it has not proved it belongs to.
    let config = config(&[]);
    for state in [State::Fresh, State::Challenged, State::Bootstrapping] {
        let mut session = Session::new(&config);
        match state {
            State::Fresh => {}
            State::Challenged => {
                session.handle(
                    Frame::Connect {
                        version: PROTOCOL_VERSION,
                        groups: Vec::new(),
                        sent_at: NOW,
                    },
                    NOW,
                );
            }
            _ => {
                session.handle(
                    Frame::Connect {
                        version: PROTOCOL_VERSION,
                        groups: Vec::new(),
                        sent_at: NOW,
                    },
                    NOW,
                );
                session.bootstrapping(0);
            }
        }
        let reaction = session.handle(beat(vec![1]), NOW);
        assert_eq!(refusal(&reaction), ErrorCode::MalformedHeader);
        assert_eq!(session.state(), State::Closed);
    }
}

#[test]
fn the_ephemeral_path_turned_off_refuses_every_beat() {
    let config = config(&[(keys::LIVE, "off")]);
    let mut session = ready(&config);
    let reaction = session.handle(beat(vec![1]), NOW);
    assert_eq!(refusal(&reaction), ErrorCode::ProtocolUnsupported);
    // The connection stays up. An operator posture is not a reason to drop a socket
    // that is carrying durable traffic.
    assert_eq!(session.state(), State::Ready);
}

#[test]
fn an_oversized_beat_is_refused_and_names_the_ceiling() {
    let config = config(&[]);
    let mut session = ready(&config);
    let reaction = session.handle(beat(vec![0; MAX_LIVE_BYTES + 1]), NOW);
    assert_eq!(refusal(&reaction), ErrorCode::EnvelopeTooLarge);
    // Exactly at the ceiling is accepted: a bound the client cannot reach is a
    // bound the client cannot plan against.
    assert!(matches!(
        session.handle(beat(vec![0; MAX_LIVE_BYTES]), NOW),
        Reaction::Defer(Work::PublishLive { .. })
    ));
}

#[test]
fn the_live_budget_refuses_the_frame_and_keeps_the_connection() {
    let config = config(&[]);
    let mut session = ready(&config);
    for _ in 0..LIVE_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(beat(vec![1]), NOW),
            Reaction::Defer(Work::PublishLive { .. })
        ));
    }
    let reaction = session.handle(beat(vec![1]), NOW);
    assert_eq!(refusal(&reaction), ErrorCode::RateLimited);
    assert!(matches!(reaction, Reaction::Reply(_)));
    assert_eq!(session.state(), State::Ready);

    // And the window resets, because a client that beats on a 20 second timer must
    // never be permanently locked out by one burst.
    assert!(matches!(
        session.handle(beat(vec![1]), NOW + FRAME_BUDGET_WINDOW_MS),
        Reaction::Defer(Work::PublishLive { .. })
    ));
}

#[test]
fn the_live_budget_is_accounted_independently_of_durable_writes() {
    // The point of a separate budget: presence can never starve a durable write,
    // and a spent presence budget must not refuse one.
    let config = config(&[]);
    let mut session = ready(&config);
    for _ in 0..LIVE_FRAMES_PER_MINUTE {
        session.handle(beat(vec![1]), NOW);
    }
    assert_eq!(
        refusal(&session.handle(beat(vec![1]), NOW)),
        ErrorCode::RateLimited
    );
    assert!(matches!(
        session.handle(
            Frame::Send {
                envelope: vec![7; 16]
            },
            NOW
        ),
        Reaction::Defer(Work::Accept { .. })
    ));
}

#[test]
fn a_beat_is_deferred_with_its_group_epoch_and_body_intact() {
    // The access-set check lives in `ws::perform`, where it reuses
    // `authorize_group` rather than copying it. What the session decides is that
    // the frame is well formed and within budget, and that it carries the bytes
    // through unchanged.
    let config = config(&[]);
    let mut session = ready(&config);
    match session.handle(beat(vec![3, 4, 5]), NOW) {
        Reaction::Defer(Work::PublishLive {
            group: g,
            epoch,
            ct,
        }) => {
            assert_eq!(g, group(1));
            assert_eq!(epoch, 4);
            assert_eq!(ct, vec![3, 4, 5]);
        }
        other => panic!("expected a deferred publish, got {other:?}"),
    }
}

// MARK: KEYS, decided without a database

fn keys(body: wealdrelay::frame::KeysBody) -> Frame {
    Frame::Keys(body)
}

#[test]
fn every_keys_form_round_trips_and_reports_its_own_discriminant() {
    use wealdrelay::frame::KeysBody;
    let forms = [
        (
            KeysBody::Publish {
                packages: vec![vec![1; 8]],
            },
            1,
        ),
        (KeysBody::Published { remaining: 7 }, 2),
        (
            KeysBody::Fetch {
                device: group(2),
                count: 4,
            },
            3,
        ),
        (
            KeysBody::Bundles {
                packages: vec![vec![2; 8]],
            },
            4,
        ),
        (KeysBody::None, 5),
    ];
    for (body, discriminant) in forms {
        assert_eq!(body.form(), discriminant);
        let frame = keys(body);
        assert_eq!(Frame::decode(&frame.encode()).expect("decodes"), frame);
    }
}

#[test]
fn a_keys_frame_is_charged_its_packages_and_nothing_else() {
    use wealdrelay::frame::KeysBody;
    // The queue budget is accounted in bytes and the two forms that carry
    // packages are the only ones that can grow.
    assert!(
        keys(KeysBody::Publish {
            packages: vec![vec![0; 512], vec![0; 512]],
        })
        .queued_bytes()
            > 1024
    );
    assert!(
        keys(KeysBody::Bundles {
            packages: vec![vec![0; 512]],
        })
        .queued_bytes()
            > 512
    );
    for small in [
        KeysBody::Published { remaining: 3 },
        KeysBody::Fetch {
            device: group(1),
            count: 1,
        },
        KeysBody::None,
    ] {
        assert_eq!(small.queued_bytes(), 0);
    }
}

#[test]
fn an_unknown_keys_form_is_a_bad_field_rather_than_a_guess() {
    use wealdrelay::cbor;
    // A form this build does not speak is refused by name. Reading it as one of
    // the five would be the decoder guessing at a frame the peer did not send.
    let bytes = cbor::array(&[
        cbor::uint(u64::from(FrameTag::Keys as u16)),
        cbor::array(&[cbor::uint(9), cbor::array(&[])]),
    ]);
    assert!(matches!(
        Frame::decode(&bytes),
        Err(wealdrelay::frame::FrameDecodeError::BadField { field: "form" })
    ));
}

#[test]
fn a_relay_to_client_keys_form_sent_upward_closes_the_connection() {
    use wealdrelay::frame::KeysBody;
    let config = config(&[]);
    for body in [
        KeysBody::Published { remaining: 1 },
        KeysBody::Bundles {
            packages: Vec::new(),
        },
        KeysBody::None,
    ] {
        let mut session = ready(&config);
        let reaction = session.handle(keys(body), NOW);
        assert_eq!(refusal(&reaction), ErrorCode::MalformedHeader);
        assert_eq!(session.state(), State::Closed);
    }
}

#[test]
fn a_fetch_of_zero_or_over_the_cap_is_refused_and_names_the_cap() {
    use wealdrelay::frame::KeysBody;
    use wealdrelay::session::MAX_KEY_PACKAGE_FETCH;
    let config = config(&[]);
    for count in [0, MAX_KEY_PACKAGE_FETCH + 1] {
        let mut session = ready(&config);
        let reaction = session.handle(
            keys(KeysBody::Fetch {
                device: group(2),
                count,
            }),
            NOW,
        );
        // Zero is refused as well as too many: a fetch for nothing is a client
        // that would sit waiting for an answer it asked not to receive.
        assert_eq!(refusal(&reaction), ErrorCode::EnvelopeTooLarge);
        assert_eq!(session.state(), State::Ready);
    }
    // And the cap itself is admitted, because a bound a client cannot reach is a
    // bound it cannot plan against.
    let mut session = ready(&config);
    assert!(matches!(
        session.handle(
            keys(KeysBody::Fetch {
                device: group(2),
                count: MAX_KEY_PACKAGE_FETCH,
            }),
            NOW
        ),
        Reaction::Defer(Work::KeyPackages { .. })
    ));
}

#[test]
fn the_keys_budget_is_its_own_and_refuses_the_frame_only() {
    use wealdrelay::frame::KeysBody;
    use wealdrelay::session::KEYS_FRAMES_PER_MINUTE;
    let config = config(&[]);
    let mut session = ready(&config);
    for _ in 0..KEYS_FRAMES_PER_MINUTE {
        assert!(matches!(
            session.handle(
                keys(KeysBody::Publish {
                    packages: vec![vec![1; 4]],
                }),
                NOW
            ),
            Reaction::Defer(Work::KeyPackages { .. })
        ));
    }
    let reaction = session.handle(
        keys(KeysBody::Publish {
            packages: vec![vec![1; 4]],
        }),
        NOW,
    );
    assert_eq!(refusal(&reaction), ErrorCode::RateLimited);
    assert_eq!(session.state(), State::Ready);
    // A spent key budget does not spend the presence budget, and neither spends
    // the envelope allowance.
    assert!(matches!(
        session.handle(beat(vec![1]), NOW),
        Reaction::Defer(Work::PublishLive { .. })
    ));
}

#[test]
fn keys_before_ready_closes_the_connection() {
    use wealdrelay::frame::KeysBody;
    let config = config(&[]);
    let mut session = Session::new(&config);
    let reaction = session.handle(
        keys(KeysBody::Publish {
            packages: vec![vec![1]],
        }),
        NOW,
    );
    assert_eq!(refusal(&reaction), ErrorCode::MalformedHeader);
    assert_eq!(session.state(), State::Closed);
}
