// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The `WAKE` codec, the coalescing state machine and the bounded queue, in process.
//!
//! Everything here is decided without a database, a socket or a clock the test does
//! not own, which is the point: the rules in `specs/backend/relay/push.md` sections 3
//! and 4 about which bytes are legal and which wakes are sent are pure functions of
//! their inputs, so they are proved as pure functions and the integration suites are
//! left to prove the parts that genuinely need Postgres and a WebSocket.
//!
//! No handle is ever printed by an assertion message in this file. That is not
//! decoration: `WakeBody`'s `Debug` redacts, and a test that formatted a handle to
//! make its failure readable would have written the leak the negative proof forbids.

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::frame::{
    ErrorClass, ErrorCode, Frame, FrameDecodeError, FrameTag, WakeBody, MAX_WAKE_BYTES,
    PROTOCOL_VERSION,
};
use wealdrelay::push::queue::{Admit, Queue};
use wealdrelay::push::{
    Category, Health, Push, Settings, ALL_CATEGORIES, DEFAULT_COALESCE_MS, DEFAULT_QUEUE,
    HANDLE_BYTES, MAX_REGISTER_URL_BYTES,
};

const NOW: u64 = 1_700_000_000_000;
const EXPIRES: u64 = NOW + 604_800_000;

fn handle(seed: u8) -> Vec<u8> {
    vec![seed; HANDLE_BYTES]
}

/// Every form, once, so a walk over them is a walk over the table in section 3.
fn all_forms() -> Vec<WakeBody> {
    vec![
        WakeBody::Register {
            handle: handle(0xA1),
            categories: ALL_CATEGORIES,
            expires_at: EXPIRES,
        },
        WakeBody::Registered {
            expires_at: EXPIRES,
        },
        WakeBody::Clear,
        WakeBody::Cleared,
        WakeBody::Query,
        WakeBody::Capability {
            enabled: true,
            register_url: "https://ringer.example/v1/handles".to_string(),
        },
    ]
}

// MARK: The codec

#[test]
fn every_form_round_trips_through_its_own_bytes() {
    for (index, body) in all_forms().into_iter().enumerate() {
        let form = u8::try_from(index + 1).expect("six forms fit a byte");
        assert_eq!(body.form(), form, "the forms are numbered in table order");
        let frame = Frame::Wake(body.clone());
        assert_eq!(frame.tag(), FrameTag::Wake);
        let encoded = frame.encode();
        assert_eq!(
            Frame::decode(&encoded),
            Ok(Frame::Wake(body)),
            "form {form} does not survive its own encoding"
        );
    }
}

#[test]
fn the_frame_is_a_tag_and_a_form_and_nothing_else() {
    // The shape `KEYS` uses: `[tag, [form, fields]]`. Asserted on the bytes rather
    // than through the decoder, because the CDDL another implementation is written
    // against says this and a decoder that agreed with a different encoder would
    // still pass a round trip.
    let encoded = Frame::Wake(WakeBody::Clear).encode();
    assert_eq!(
        encoded,
        vec![0x82, 0x18, 25, 0x82, 0x03, 0x80],
        "an array of two: tag 25, then an array of two holding form 3 and no fields"
    );
}

#[test]
fn a_capability_carries_a_real_boolean_and_a_real_text_string() {
    // `enabled` is `bool` and `register_url` is `tstr` in the pinned CDDL. An integer
    // in either position is a different wire format, so the bytes are checked.
    let encoded = Frame::Wake(WakeBody::Capability {
        enabled: false,
        register_url: "https://a".to_string(),
    })
    .encode();
    assert!(
        encoded.contains(&0xf4),
        "false is major 7 value 20, not an integer"
    );
    assert!(
        encoded.windows(2).any(|pair| pair == [0x69, b'h']),
        "the url is a text string of nine bytes, not a byte string"
    );
    let enabled = Frame::Wake(WakeBody::Capability {
        enabled: true,
        register_url: String::new(),
    })
    .encode();
    assert!(enabled.contains(&0xf5), "true is major 7 value 21");
    assert_eq!(
        Frame::decode(&enabled),
        Ok(Frame::Wake(WakeBody::Capability {
            enabled: true,
            register_url: String::new(),
        })),
        "an empty url is legal: `tstr .size (0..512)` includes zero"
    );
}

/// One `WAKE` frame's bytes, built without the encoder, so a test can be wrong about
/// a field in exactly the way a hostile peer would be.
fn wake_bytes(form: u8, fields: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![0x82, 0x18, 25];
    let mut inner = vec![0x82];
    inner.extend_from_slice(&cbor_uint(u64::from(form)));
    inner.extend_from_slice(&cbor_array(fields));
    out.extend_from_slice(&inner);
    out
}

fn cbor_uint(value: u64) -> Vec<u8> {
    if value < 24 {
        return vec![u8::try_from(value).expect("under 24")];
    }
    if value <= u64::from(u8::MAX) {
        return vec![0x18, u8::try_from(value).expect("a byte")];
    }
    if value <= u64::from(u16::MAX) {
        let mut out = vec![0x19];
        out.extend_from_slice(&u16::try_from(value).expect("under 65536").to_be_bytes());
        return out;
    }
    // Shortest form at every width, because a test that encoded 256 in eight bytes
    // would be testing the canonicity rule rather than the field it meant to.
    let mut out = vec![0x1b];
    out.extend_from_slice(&value.to_be_bytes());
    out
}

fn cbor_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn cbor_text(value: &[u8]) -> Vec<u8> {
    let mut out = head(3, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn cbor_array(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(&item);
    }
    out
}

fn head(major: u8, value: u64) -> Vec<u8> {
    let tag = major << 5;
    if value < 24 {
        return vec![tag | u8::try_from(value).expect("under 24")];
    }
    if value <= u64::from(u8::MAX) {
        return vec![tag | 24, u8::try_from(value).expect("a byte")];
    }
    let mut out = vec![tag | 25];
    out.extend_from_slice(&u16::try_from(value).expect("under 65536").to_be_bytes());
    out
}

#[test]
fn a_handle_of_the_wrong_length_is_its_own_reject() {
    // Fifteen, seventeen and zero. Each is `reject/push_handle_malformed` and names
    // the field, because a client told `malformed_header` would go looking at its
    // framing rather than at the handle it was given.
    for length in [0usize, 15, 17, 32] {
        let bytes = wake_bytes(
            1,
            vec![
                cbor_bytes(&vec![0x11; length]),
                cbor_uint(1),
                cbor_uint(EXPIRES),
            ],
        );
        let error = Frame::decode(&bytes).expect_err("a wrong-length handle is refused");
        assert_eq!(error, FrameDecodeError::BadWakeField { field: "handle" });
        assert_eq!(error.code(), ErrorCode::PushHandleMalformed);
        assert_eq!(error.code().class(), ErrorClass::Reject);
    }
}

#[test]
fn a_bitmask_with_no_bits_or_an_undefined_bit_is_a_reject() {
    // Zero is refused rather than read as "wake me for nothing": a device that wants
    // no wakes sends `Clear`. Anything at or above 8 is a category this version does
    // not have, and masking it off silently would store a registration whose meaning
    // the two ends disagree about.
    for mask in [0u8, 8, 9, 0x80, 0xff] {
        let bytes = wake_bytes(
            1,
            vec![
                cbor_bytes(&handle(1)),
                cbor_uint(u64::from(mask)),
                cbor_uint(EXPIRES),
            ],
        );
        assert_eq!(
            Frame::decode(&bytes),
            Err(FrameDecodeError::BadWakeField {
                field: "categories"
            }),
            "mask {mask} is not one this version defines"
        );
    }
    // And every mask that is a non-empty subset of the three bits is accepted.
    for mask in 1..=ALL_CATEGORIES {
        let bytes = wake_bytes(
            1,
            vec![
                cbor_bytes(&handle(2)),
                cbor_uint(u64::from(mask)),
                cbor_uint(EXPIRES),
            ],
        );
        assert!(
            Frame::decode(&bytes).is_ok(),
            "mask {mask} is a legal subset"
        );
    }
}

#[test]
fn a_categories_field_wider_than_a_byte_is_refused_by_the_codec() {
    // `categories = uint .size 1`. A larger integer is out of range for the field
    // rather than an undefined bit, so it is the codec's refusal and not the push
    // registry's, and the two are told apart on purpose.
    let bytes = wake_bytes(
        1,
        vec![cbor_bytes(&handle(3)), cbor_uint(256), cbor_uint(EXPIRES)],
    );
    assert_eq!(
        Frame::decode(&bytes),
        Err(FrameDecodeError::BadField {
            field: "categories"
        }),
        "a field that is the wrong shape is `malformed_header`, and only a canonicity \
         violation is `noncanonical_cbor`"
    );
}

#[test]
fn a_register_url_over_the_ceiling_is_a_reject_and_one_at_it_is_not() {
    // Padded inside the path of a real https url, because the codec applies the same
    // scheme rule the configuration does: a url a client would refuse is one this
    // decoder refuses too, rather than one the relay states and the device ignores.
    let prefix = b"https://r.example/";
    let at_the_bound = {
        let mut url = prefix.to_vec();
        url.resize(MAX_REGISTER_URL_BYTES, b'x');
        url
    };
    let over = {
        let mut url = prefix.to_vec();
        url.resize(MAX_REGISTER_URL_BYTES + 1, b'x');
        url
    };
    assert!(Frame::decode(&wake_bytes(6, vec![vec![0xf5], cbor_text(&at_the_bound)])).is_ok());
    assert_eq!(
        Frame::decode(&wake_bytes(6, vec![vec![0xf5], cbor_text(&over)])),
        Err(FrameDecodeError::BadWakeField {
            field: "register_url"
        })
    );
}

#[test]
fn a_register_url_that_is_not_utf8_is_refused_rather_than_replaced() {
    // A lossy conversion would give two different inputs one decoded value, which is
    // the same determinism hole as a non-canonical integer.
    let bytes = wake_bytes(6, vec![vec![0xf5], cbor_text(&[0xff, 0xfe])]);
    assert_eq!(
        Frame::decode(&bytes),
        Err(FrameDecodeError::BadField {
            field: "register_url"
        })
    );
}

#[test]
fn a_register_url_sent_as_a_byte_string_is_refused() {
    // The CDDL says `tstr`. A byte string of the same bytes is a different wire
    // format, and accepting both would mean two encodings of one frame.
    let bytes = wake_bytes(6, vec![vec![0xf5], cbor_bytes(b"https://a")]);
    assert_eq!(
        Frame::decode(&bytes),
        Err(FrameDecodeError::BadField {
            field: "register_url"
        })
    );
}

#[test]
fn an_enabled_field_that_is_not_a_boolean_is_refused() {
    // `1` is not `true`. A decoder that accepted it would be a decoder with an
    // opinion about `2`.
    for encoded_enabled in [cbor_uint(1), cbor_uint(0), vec![0xf6]] {
        let bytes = wake_bytes(6, vec![encoded_enabled, cbor_text(b"https://a")]);
        assert_eq!(
            Frame::decode(&bytes),
            Err(FrameDecodeError::BadField { field: "enabled" })
        );
    }
}

#[test]
fn an_unknown_form_is_a_reject_naming_the_form() {
    // `malformed_header`, which is the answer `KEYS` gives an unknown form of its own:
    // a peer that disagrees about the frame set rather than one whose registration is
    // wrong.
    for form in [0u8, 7, 8, 255] {
        assert_eq!(
            Frame::decode(&wake_bytes(form, Vec::new())),
            Err(FrameDecodeError::BadField { field: "form" }),
            "form {form} is not one of the six"
        );
    }
}

#[test]
fn a_form_with_the_wrong_number_of_fields_is_refused() {
    // Every form's field count is fixed, and a peer sending a `Clear` with a field in
    // it is a peer this build must not read past.
    let cases = vec![
        (1u8, vec![cbor_bytes(&handle(4)), cbor_uint(1)]),
        (2, Vec::new()),
        (3, vec![cbor_uint(0)]),
        (4, vec![cbor_uint(0)]),
        (5, vec![cbor_uint(0)]),
        (6, vec![vec![0xf5]]),
    ];
    for (form, fields) in cases {
        assert!(
            matches!(
                Frame::decode(&wake_bytes(form, fields)),
                Err(FrameDecodeError::BadField { .. })
            ),
            "form {form} accepted the wrong field count"
        );
    }
}

#[test]
fn a_wake_frame_over_a_kibibyte_is_refused_before_it_is_parsed() {
    // Its own bound, far below `MAX_FRAME_BYTES`, and checked before any field is
    // read: the point is not to reject a large registration but to refuse to read one.
    let huge = vec![b'x'; 4096];
    let bytes = wake_bytes(6, vec![vec![0xf5], cbor_text(&huge)]);
    assert!(bytes.len() > MAX_WAKE_BYTES);
    let error = Frame::decode(&bytes).expect_err("over the ceiling");
    assert_eq!(error, FrameDecodeError::TooLargeWake(bytes.len()));
    // The code every other over-size frame is answered with, because that is what it
    // is: the refusal is about the size rather than about the registration.
    assert_eq!(error.code(), ErrorCode::EnvelopeTooLarge);
    assert!(error.to_string().contains("over the"));
}

#[test]
fn trailing_bytes_after_a_wake_frame_are_refused() {
    let mut bytes = Frame::Wake(WakeBody::Query).encode();
    bytes.push(0x00);
    assert!(matches!(
        Frame::decode(&bytes),
        Err(FrameDecodeError::Cbor(_))
    ));
}

#[test]
fn the_tag_is_twenty_five_and_the_version_is_four() {
    assert_eq!(FrameTag::Wake as u16, 25);
    assert_eq!(FrameTag::from_u16(25), Some(FrameTag::Wake));
    assert!(FrameTag::ALL.contains(&FrameTag::Wake));
    // The version bump the frame requires. A version 3 relay and a version 4 client
    // cannot agree on tag 25, which is what makes this breaking-class.
    assert_eq!(PROTOCOL_VERSION, 4);
}

#[test]
fn the_queue_budget_counts_the_two_variable_fields() {
    // Not `encode().len()`, and not zero either: a url can be half a kibibyte and the
    // frame's fixed allowance is a header estimate.
    assert_eq!(
        WakeBody::Register {
            handle: handle(5),
            categories: 1,
            expires_at: EXPIRES,
        }
        .queued_bytes(),
        HANDLE_BYTES
    );
    assert_eq!(
        WakeBody::Capability {
            enabled: true,
            register_url: "abcd".to_string(),
        }
        .queued_bytes(),
        4
    );
    for body in [
        WakeBody::Registered { expires_at: 0 },
        WakeBody::Clear,
        WakeBody::Cleared,
        WakeBody::Query,
    ] {
        assert_eq!(body.queued_bytes(), 0, "the small forms are all header");
    }
    // And the frame's own accounting includes it.
    assert!(
        Frame::Wake(WakeBody::Register {
            handle: handle(6),
            categories: 1,
            expires_at: EXPIRES,
        })
        .queued_bytes()
            > HANDLE_BYTES
    );
}

#[test]
fn a_body_never_prints_its_handle() {
    // The mechanism behind the first of section 2's three absences. A derived `Debug`
    // would put a live wake capability in every formatted frame, and "nobody formats a
    // frame" is a rule a reviewer enforces rather than the compiler.
    for body in all_forms() {
        let rendered = format!("{body:?}");
        assert!(
            rendered.contains("[redacted]"),
            "the body did not redact: {rendered}"
        );
        assert!(
            !rendered.contains("a1a1"),
            "a handle reached a Debug rendering"
        );
        assert!(
            !rendered.contains("161") && !rendered.contains("ringer.example"),
            "a field reached a Debug rendering: {rendered}"
        );
    }
    // The form is still there, because the form is not a secret and an operator
    // debugging a registration needs to know which one arrived.
    assert!(format!("{:?}", WakeBody::Clear).contains("Clear"));
}

// MARK: The four error codes

#[test]
fn the_four_codes_are_in_the_registry_with_the_classes_the_spec_names() {
    let expected = [
        (
            ErrorCode::PushHandleMalformed,
            ErrorClass::Reject,
            "push_handle_malformed",
        ),
        (
            ErrorCode::PushNotConfigured,
            ErrorClass::Denied,
            "push_not_configured",
        ),
        (
            ErrorCode::PushRegistrationRate,
            ErrorClass::Quota,
            "push_registration_rate",
        ),
        (
            ErrorCode::PushBackpressure,
            ErrorClass::Retry,
            "push_backpressure",
        ),
    ];
    for (code, class, name) in expected {
        assert_eq!(code.class(), class);
        assert_eq!(code.as_str(), name);
        assert_eq!(code.qualified(), format!("{}/{name}", class.as_str()));
        assert!(
            ErrorCode::ALL.contains(&code),
            "{name} is missing from the walkable registry"
        );
        // And the code survives an `ERROR` frame, which is how a client reads it.
        let frame = Frame::Error(wealdrelay::frame::FrameError::new(code));
        assert_eq!(Frame::decode(&frame.encode()), Ok(frame));
    }
    // Only `retry` and `quota` are retryable, so a denial is not retried blind.
    assert!(!ErrorCode::PushNotConfigured.class().is_retryable());
    assert!(!ErrorCode::PushHandleMalformed.class().is_retryable());
    assert!(ErrorCode::PushRegistrationRate.class().is_retryable());
    assert!(ErrorCode::PushBackpressure.class().is_retryable());
}

// MARK: Categories

#[test]
fn a_category_is_a_bit_a_name_and_an_urgency_and_nothing_more() {
    assert_eq!(Category::Message.bit(), 1);
    assert_eq!(Category::Call.bit(), 2);
    assert_eq!(Category::Handshake.bit(), 4);
    assert_eq!(Category::Message.as_str(), "message");
    assert_eq!(Category::Call.as_str(), "call");
    assert_eq!(Category::Handshake.as_str(), "handshake");
    // Only a call jumps the window: a ring two seconds late is a missed call.
    assert!(Category::Call.is_urgent());
    assert!(!Category::Message.is_urgent());
    assert!(!Category::Handshake.is_urgent());
    assert_eq!(Category::ALL.len(), 3);
    assert_eq!(
        Category::ALL.iter().fold(0u8, |mask, c| mask | c.bit()),
        ALL_CATEGORIES
    );
}

#[test]
fn masking_admits_exactly_the_bits_a_device_registered() {
    for category in Category::ALL.iter().copied() {
        assert!(category.admitted_by(category.bit()));
        assert!(category.admitted_by(ALL_CATEGORIES));
        assert!(!category.admitted_by(ALL_CATEGORIES ^ category.bit()));
        assert!(!category.admitted_by(0));
    }
    // A device that wants calls only is not woken for a message.
    assert!(!Category::Message.admitted_by(Category::Call.bit()));
    assert!(Category::Call.admitted_by(Category::Call.bit()));
}

#[test]
fn a_valid_mask_is_non_empty_and_defined() {
    assert!(!wealdrelay::push::is_valid_mask(0));
    for mask in 1..=ALL_CATEGORIES {
        assert!(wealdrelay::push::is_valid_mask(mask));
    }
    for mask in [8u8, 16, 128, 255] {
        assert!(!wealdrelay::push::is_valid_mask(mask));
    }
}

// MARK: The coalescing state machine

#[test]
fn a_burst_into_one_group_is_one_wake() {
    let mut queue = Queue::new(16);
    assert!(queue.is_empty());
    assert_eq!(
        queue.admit(handle(1), Category::Message, NOW, 2000),
        Admit::Queued
    );
    for step in 1..20 {
        assert_eq!(
            queue.admit(handle(1), Category::Message, NOW + step, 2000),
            Admit::Coalesced,
            "a second envelope inside the window is not a second wake"
        );
    }
    assert_eq!(queue.len(), 1);
    // And it leaves at the deadline the first one set, not the last.
    assert_eq!(queue.next_deadline(), Some(NOW + 2000));
    assert!(queue.take_due(NOW + 1999).is_empty());
    assert_eq!(
        queue.take_due(NOW + 2000),
        vec![(handle(1), Category::Message)]
    );
    assert!(queue.is_empty());
    assert_eq!(queue.next_deadline(), None);
}

#[test]
fn a_call_is_due_immediately_and_supersedes_a_pending_message() {
    let mut queue = Queue::new(16);
    assert_eq!(
        queue.admit(handle(2), Category::Message, NOW, 2000),
        Admit::Queued
    );
    assert_eq!(
        queue.admit(handle(2), Category::Call, NOW + 5, 2000),
        Admit::Superseded,
        "a ring takes over the window a message opened"
    );
    assert_eq!(queue.next_deadline(), Some(NOW + 5));
    assert_eq!(
        queue.take_due(NOW + 5),
        vec![(handle(2), Category::Call)],
        "one wake, and it is the ring"
    );
}

#[test]
fn a_message_behind_a_pending_call_is_redundant() {
    let mut queue = Queue::new(16);
    assert_eq!(
        queue.admit(handle(3), Category::Call, NOW, 2000),
        Admit::Queued
    );
    assert_eq!(
        queue.admit(handle(3), Category::Message, NOW, 2000),
        Admit::Redundant
    );
    assert_eq!(
        queue.admit(handle(3), Category::Handshake, NOW, 2000),
        Admit::Redundant
    );
    // A second ring for the same device is one ring.
    assert_eq!(
        queue.admit(handle(3), Category::Call, NOW, 2000),
        Admit::Coalesced
    );
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.take_due(NOW), vec![(handle(3), Category::Call)]);
}

#[test]
fn a_handshake_and_a_message_for_one_handle_share_a_window() {
    let mut queue = Queue::new(16);
    assert_eq!(
        queue.admit(handle(4), Category::Handshake, NOW, 2000),
        Admit::Queued
    );
    assert_eq!(
        queue.admit(handle(4), Category::Message, NOW, 2000),
        Admit::Coalesced
    );
    // The first category is kept. The payload says nothing beyond the category and
    // the client's next act is to read the log either way.
    assert_eq!(
        queue.take_due(NOW + 2000),
        vec![(handle(4), Category::Handshake)]
    );
}

#[test]
fn two_handles_do_not_coalesce_into_each_other() {
    let mut queue = Queue::new(16);
    assert_eq!(
        queue.admit(handle(5), Category::Message, NOW, 2000),
        Admit::Queued
    );
    assert_eq!(
        queue.admit(handle(6), Category::Message, NOW, 2000),
        Admit::Queued
    );
    assert_eq!(queue.len(), 2);
    let due = queue.take_due(NOW + 2000);
    assert_eq!(
        due,
        vec![
            (handle(5), Category::Message),
            (handle(6), Category::Message)
        ],
        "insertion order, so a recorded batch is reproducible"
    );
}

#[test]
fn a_zero_window_means_no_coalescing_at_all() {
    // Legal, and a posture rather than a mistake: an operator who wants every wake
    // sent as it arrives says so.
    let mut queue = Queue::new(16);
    queue.admit(handle(7), Category::Message, NOW, 0);
    assert_eq!(queue.next_deadline(), Some(NOW));
    assert_eq!(
        queue.take_due(NOW),
        vec![(handle(7), Category::Message)],
        "due the instant it arrives"
    );
}

#[test]
fn a_window_that_would_overflow_the_clock_saturates() {
    // Not a real deployment, and it is here because the alternative to saturating is
    // a panic on a wrapping add in the one function every wake goes through.
    let mut queue = Queue::new(4);
    queue.admit(handle(8), Category::Message, u64::MAX - 1, 1000);
    assert_eq!(queue.next_deadline(), Some(u64::MAX));
}

// MARK: The bound

#[test]
fn at_the_bound_the_oldest_wake_goes() {
    // A wake is a hint that something happened, and the newest hint is the one whose
    // notification is still worth delivering. Shedding the newest would make a relay
    // under load stop waking anybody while still holding a full queue.
    let mut queue = Queue::new(2);
    assert_eq!(queue.bound(), 2);
    assert_eq!(
        queue.admit(handle(10), Category::Message, NOW, 0),
        Admit::Queued
    );
    assert_eq!(
        queue.admit(handle(11), Category::Message, NOW, 0),
        Admit::Queued
    );
    assert_eq!(
        queue.admit(handle(12), Category::Message, NOW, 0),
        Admit::Dropped
    );
    assert_eq!(queue.len(), 2);
    assert_eq!(
        queue.take_due(NOW),
        vec![
            (handle(11), Category::Message),
            (handle(12), Category::Message)
        ],
        "the first handle was the one dropped"
    );
}

#[test]
fn a_queue_cannot_be_built_with_no_room() {
    // `Config` refuses a zero bound on the way in, and clamping here means this type
    // has no state in which `admit` would have to answer for a capacity nobody chose.
    let mut queue = Queue::new(0);
    assert_eq!(queue.bound(), 1);
    assert_eq!(
        queue.admit(handle(13), Category::Message, NOW, 0),
        Admit::Queued
    );
}

#[tokio::test]
async fn the_drop_counter_counts_exactly_the_wakes_the_bound_shed() {
    let push = Push::new(Settings {
        wake_url: Some("https://ringer.example/v1/wake".to_string()),
        token: None,
        register_url: "https://ringer.example/v1/handles".to_string(),
        coalesce_ms: 0,
        queue_bound: 4,
    });
    for seed in 0..4 {
        assert_eq!(
            push.enqueue(handle(seed), Category::Message, NOW).await,
            Admit::Queued
        );
    }
    assert_eq!(push.dropped(), 0);
    for seed in 4..7 {
        assert_eq!(
            push.enqueue(handle(seed), Category::Message, NOW).await,
            Admit::Dropped
        );
    }
    assert_eq!(push.dropped(), 3, "one per shed wake, and no label on it");
    assert_eq!(push.queued().await, 4);
    // A coalesced wake is not a dropped one, which is why the outcomes are not a
    // boolean.
    assert_eq!(
        push.enqueue(handle(6), Category::Message, NOW).await,
        Admit::Coalesced
    );
    assert_eq!(push.dropped(), 3);
    assert_eq!(push.take_due(NOW).await.len(), 4);
    assert_eq!(push.queued().await, 0);
}

// MARK: Settings, health and the shape of the state

fn config_with(extra: &[(&'static str, &'static str)]) -> Config {
    let mut pairs = vec![
        (keys::HOSTNAME, "relay.example".to_string()),
        (
            keys::DATABASE_URL,
            "postgres://weald:weald@127.0.0.1:5432/weald".to_string(),
        ),
        (keys::STORAGE_URL, "file:///tmp/weald-push-unit".to_string()),
    ];
    for (key, value) in extra {
        pairs.push((*key, (*value).to_string()));
    }
    Config::resolve(&Values::from_pairs(pairs)).expect("the configuration resolves")
}

#[test]
fn push_is_off_by_default_and_off_is_a_posture() {
    let config = config_with(&[]);
    let settings = Settings::from_config(&config);
    assert!(!settings.enabled());
    assert_eq!(settings.wake_url, None);
    assert_eq!(settings.register_url, "");
    assert_eq!(settings.coalesce_ms, DEFAULT_COALESCE_MS);
    assert_eq!(
        settings.queue_bound,
        usize::try_from(DEFAULT_QUEUE).expect("the default fits")
    );
    let push = Push::from_config(&config);
    assert!(!push.enabled());
    assert_eq!(push.health(), Health::Off);
    assert_eq!(push.health().as_str(), "off");
    // And the capability a `Query` is answered with says exactly that.
    assert_eq!(
        push.capability(),
        WakeBody::Capability {
            enabled: false,
            register_url: String::new(),
        }
    );
}

#[test]
fn the_registration_url_is_derived_from_the_wake_url_when_it_is_not_set() {
    // The device must not guess a ringer, because guessing ours would mean a
    // self-hoster's users registering with a party their operator did not choose. So
    // the relay states it, and it states the reference ringer's own path.
    let config = config_with(&[
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
    ]);
    let settings = Settings::from_config(&config);
    assert_eq!(
        settings.register_url,
        format!(
            "https://ringer.example/v1/wake{}",
            wealdrelay::push::RINGER_REGISTER_PATH
        )
    );
    // A trailing slash does not produce a doubled one.
    let trailing = config_with(&[(keys::PUSH, "on"), (keys::PUSH_URL, "https://r.example/")]);
    assert_eq!(
        Settings::from_config(&trailing).register_url,
        format!(
            "https://r.example{}",
            wealdrelay::push::RINGER_REGISTER_PATH
        )
    );
    // And an explicit value wins, which is how an operator points registration at a
    // different host from the wake leg.
    let explicit = config_with(&[
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
        (keys::PUSH_REGISTER_URL, "https://register.example/handles"),
    ]);
    assert_eq!(
        Settings::from_config(&explicit).register_url,
        "https://register.example/handles"
    );
}

#[test]
fn a_configured_relay_reports_configured_until_a_wake_fails_to_reach_the_ringer() {
    let push = Push::from_config(&config_with(&[
        (keys::PUSH, "on"),
        (keys::PUSH_URL, "https://ringer.example/v1/wake"),
    ]));
    assert!(push.enabled());
    // Seeded reachable: a relay that has not tried has not failed.
    assert_eq!(push.health(), Health::Configured);
    assert_eq!(
        push.capability(),
        WakeBody::Capability {
            enabled: true,
            register_url: format!(
                "https://ringer.example/v1/wake{}",
                wealdrelay::push::RINGER_REGISTER_PATH
            ),
        }
    );

    use wealdrelay::push::ringer::Outcome;
    push.record(Outcome::Accepted);
    assert_eq!(push.sent(), 1);
    assert_eq!(push.health(), Health::Configured);

    push.record(Outcome::Unreachable);
    assert_eq!(push.failed(), 1);
    assert_eq!(push.health(), Health::Unreachable);
    assert_eq!(push.health().as_str(), "unreachable");

    // A ringer that answers is reachable, whatever it says: `404` and `429` are facts
    // about one handle rather than about the deployment.
    push.record(Outcome::Unknown);
    assert_eq!(push.health(), Health::Configured);
    push.record(Outcome::Unreachable);
    push.record(Outcome::Refused);
    assert_eq!(push.health(), Health::Configured);
    // Every answer that was not a `2xx` is counted: one unreachable, one unknown, one
    // unreachable again, one refused.
    assert_eq!(push.failed(), 4);
    push.record(Outcome::Unreachable);
    push.record(Outcome::Paused { seconds: 1 });
    assert_eq!(
        push.health(),
        Health::Configured,
        "a rate limit is not an outage"
    );
    assert_eq!(push.pauses(), 0, "the worker counts a pause, not `record`");
    push.note_pause();
    assert_eq!(push.pauses(), 1);
}

#[tokio::test]
async fn waiting_for_work_returns_when_the_earliest_window_closes() {
    // The worker sleeps rather than polls, and it wakes on the earlier of "something
    // was enqueued" and "the next deadline passed". Both arms are exercised here
    // because the alternative to a covered timeout arm is a relay that spins.
    let push = Push::new(Settings {
        wake_url: Some("https://ringer.example/v1/wake".to_string()),
        token: None,
        register_url: String::new(),
        coalesce_ms: 20,
        queue_bound: 8,
    });
    let now = 1_000;
    push.enqueue(handle(20), Category::Message, now).await;
    // The deadline is 20 ms out in the queue's own clock, and the wait is bounded by
    // it, so this returns rather than hanging.
    tokio::time::timeout(std::time::Duration::from_secs(2), push.wait_for_work(now))
        .await
        .expect("the wait is bounded by the next deadline");
    // With an empty queue the wait is unbounded, so it returns only when something is
    // enqueued.
    assert_eq!(push.take_due(now + 20).await.len(), 1);
    let notified = push.wait_for_work(now);
    let enqueue = push.enqueue(handle(21), Category::Call, now);
    let (_, admitted) = tokio::join!(notified, enqueue);
    assert_eq!(admitted, Admit::Queued);
}
