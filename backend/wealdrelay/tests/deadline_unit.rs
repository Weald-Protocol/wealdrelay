// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The two connection deadlines, as arithmetic.
//!
//! `crate::deadline` is deliberately a pure function of time in and decisions
//! out, so these are the tests that pin the *rules*: when a stranger runs out of
//! handshake, when a quiet member is asked whether it is there, and when an
//! unanswered question becomes a closed socket. The socket suite beside this one
//! proves the same rules through a real relay and a real client; what it cannot
//! do is assert on the instant a deadline falls without waiting for it, which is
//! why both exist.
//!
//! Nothing here reads a clock, per `specs/backend/build/testing.md`.

use std::time::Duration;

use wealdrelay::config::{keys, Config, Values};
use wealdrelay::deadline::{
    Deadlines, Expiry, Next, DEFAULT_HANDSHAKE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS,
    LIVENESS_PROBE_WINDOW,
};

const HANDSHAKE: Duration = Duration::from_millis(10_000);
const IDLE: Duration = Duration::from_millis(300_000);

fn fresh() -> Deadlines {
    Deadlines::from_parts(HANDSHAKE, IDLE, 0)
}

/// Authenticated at `at_ms`, which is the state every idle test starts from.
fn ready(at_ms: u64) -> Deadlines {
    let mut deadlines = fresh();
    deadlines.authenticated(at_ms);
    deadlines
}

// MARK: The handshake deadline

#[test]
fn a_connection_that_has_not_authenticated_waits_out_its_handshake_and_is_then_expired() {
    let deadlines = fresh();

    // At the upgrade: the whole window is ahead.
    assert_eq!(deadlines.next(0), Next::Wait(HANDSHAKE));
    // One millisecond short of it, the connection is still fine, and the wait
    // returned is what is left rather than the whole window. That matters: a
    // caller that waited the full window on every turn would grant an
    // unauthenticated peer a fresh deadline for every byte it sent.
    assert_eq!(
        deadlines.next(9_999),
        Next::Wait(Duration::from_millis(1)),
        "just inside the deadline the connection lives"
    );
    // On it, and past it.
    assert_eq!(deadlines.next(10_000), Next::Expired(Expiry::Handshake));
    assert_eq!(deadlines.next(10_001), Next::Expired(Expiry::Handshake));
}

#[test]
fn traffic_before_auth_ack_does_not_extend_the_handshake_deadline() {
    let mut deadlines = fresh();
    // A peer sending frames it is not authenticated to send, forever. This is the
    // attack the deadline exists to stop, and it is the one a naive "reset the
    // timer on every message" implementation would let through: the whole point
    // is that the window runs from the upgrade rather than from the last byte.
    for at in [1_000, 5_000, 9_000, 9_999] {
        deadlines.saw_message(at);
    }

    assert_eq!(deadlines.next(10_000), Next::Expired(Expiry::Handshake));
}

#[test]
fn authentication_ends_the_handshake_deadline_and_starts_the_idle_one() {
    let mut deadlines = fresh();
    deadlines.authenticated(9_000);

    // Past the handshake window, and not expired: it no longer applies.
    assert_eq!(
        deadlines.next(10_001),
        Next::Wait(Duration::from_millis(298_999))
    );
    // Stated the other way round, plainly: the idle window runs from the
    // `AUTH_ACK` rather than from the upgrade.
    assert_eq!(deadlines.next(9_000), Next::Wait(IDLE));
}

#[test]
fn a_second_authentication_cannot_extend_the_idle_window() {
    let mut deadlines = ready(0);
    // The caller checks the session state after every message, so this is called
    // repeatedly on an already-authenticated connection. If it were not
    // idempotent, a peer could hold a connection open indefinitely by sending
    // frames the session ignores.
    deadlines.authenticated(200_000);

    assert_eq!(deadlines.next(300_000), Next::Probe(LIVENESS_PROBE_WINDOW));
}

// MARK: The idle deadline and its liveness exchange

#[test]
fn a_quiet_authenticated_connection_is_probed_rather_than_closed() {
    let deadlines = ready(0);

    assert_eq!(
        deadlines.next(299_999),
        Next::Wait(Duration::from_millis(1))
    );
    // The interval elapsing is a question, not a verdict. A connection that was
    // closed here would be a member dropped for working quietly.
    assert_eq!(deadlines.next(300_000), Next::Probe(LIVENESS_PROBE_WINDOW));
    // And asking is not enough on its own: until `probed` records it, the state
    // is unchanged, so a caller that failed between deciding and sending does not
    // silently convert the probe into a close.
    assert!(!deadlines.probing());
}

#[test]
fn an_unanswered_probe_closes_the_connection_when_its_window_runs_out() {
    let mut deadlines = ready(0);
    deadlines.probed(300_000);
    assert!(deadlines.probing());

    assert_eq!(
        deadlines.next(309_999),
        Next::Wait(Duration::from_millis(1)),
        "inside the probe window the peer still has time to answer"
    );
    assert_eq!(deadlines.next(310_000), Next::Expired(Expiry::Idle));
}

#[test]
fn any_answer_at_all_clears_the_probe_and_restarts_the_interval() {
    let mut deadlines = ready(0);
    deadlines.probed(300_000);
    // A pong, a frame, a ping of the peer's own: the deadline asks whether
    // somebody is there and every one of those answers it. The caller does not
    // distinguish them and neither does this.
    deadlines.saw_message(300_100);

    assert!(!deadlines.probing());
    assert_eq!(
        deadlines.next(310_000),
        Next::Wait(Duration::from_millis(290_100))
    );
    assert_eq!(deadlines.next(600_100), Next::Probe(LIVENESS_PROBE_WINDOW));
}

#[test]
fn the_probe_window_never_outlasts_the_interval_it_guards() {
    // A deliberately tiny idle interval, which the socket suite uses. If the
    // probe window were the flat ten seconds, the guard would be dominated by a
    // constant nobody configured and a one-second idle deadline would take eleven
    // seconds to fire.
    let mut deadlines = Deadlines::from_parts(HANDSHAKE, Duration::from_millis(400), 0);
    deadlines.authenticated(0);

    assert_eq!(deadlines.next(400), Next::Probe(Duration::from_millis(400)));
    deadlines.probed(400);
    assert_eq!(deadlines.next(800), Next::Expired(Expiry::Idle));
}

#[test]
fn time_that_appears_to_run_backwards_is_due_rather_than_wrapped() {
    // Monotonic time forbids this; unsigned arithmetic makes the cost of being
    // wrong about it a deadline 584 million years away rather than a deadline
    // that fires. `remaining` saturates in the safe direction and this is the
    // assertion that says which direction that is.
    let mut deadlines = ready(10_000);
    deadlines.probed(10_000);

    assert_eq!(deadlines.next(0), Next::Wait(LIVENESS_PROBE_WINDOW));
    assert_eq!(deadlines.next(20_000), Next::Expired(Expiry::Idle));
}

#[test]
fn each_deadline_has_its_own_word_for_the_operator_surface() {
    // The counters are the only way to tell a deadline from a crash, so the two
    // must never collapse into one label.
    assert_eq!(Expiry::Handshake.as_str(), "handshake_deadline");
    assert_eq!(Expiry::Idle.as_str(), "idle_deadline");
    assert_ne!(Expiry::Handshake.as_str(), Expiry::Idle.as_str());
}

// MARK: The configuration behind them

fn resolve(pairs: Vec<(&'static str, String)>) -> Result<Config, wealdrelay::config::ConfigError> {
    let mut all = vec![
        (keys::HOSTNAME, "localhost".to_string()),
        (keys::DATABASE_URL, "postgres://localhost/weald".to_string()),
        (keys::STORAGE_URL, "file:///tmp/weald".to_string()),
    ];
    all.extend(pairs);
    Config::resolve(&Values::from_pairs(all))
}

#[test]
fn both_deadlines_have_a_default_an_operator_never_has_to_set() {
    let config = resolve(vec![]).expect("the default configuration resolves");

    assert_eq!(config.handshake_timeout_ms, DEFAULT_HANDSHAKE_TIMEOUT_MS);
    assert_eq!(config.idle_timeout_ms, DEFAULT_IDLE_TIMEOUT_MS);
    // And the default is a bound rather than the absence of one, which is the
    // whole point: the behaviour being replaced was unlimited, so a default that
    // meant unlimited would be the old behaviour under a new name.
    assert_eq!(
        Deadlines::new(&config, 0).next(DEFAULT_HANDSHAKE_TIMEOUT_MS),
        Next::Expired(Expiry::Handshake)
    );
}

#[test]
fn an_operator_can_set_either_deadline() {
    let config = resolve(vec![
        (keys::HANDSHAKE_TIMEOUT_MS, "2500".to_string()),
        (keys::IDLE_TIMEOUT_MS, "60000".to_string()),
    ])
    .expect("an explicit configuration resolves");

    assert_eq!(config.handshake_timeout_ms, 2_500);
    assert_eq!(config.idle_timeout_ms, 60_000);
    assert_eq!(
        Deadlines::new(&config, 0).next(2_500),
        Next::Expired(Expiry::Handshake)
    );
}

#[test]
fn zero_is_refused_at_startup_rather_than_resolved_into_a_relay_that_serves_nobody() {
    // The same refusal `WEALD_RELAY_MAX_CONNECTIONS=0` gets, and for the same
    // reason: zero is not a smaller limit, it is a service that does not run.
    // Naming the key matters, because the operator's next action is to edit it.
    for key in [keys::HANDSHAKE_TIMEOUT_MS, keys::IDLE_TIMEOUT_MS] {
        let error = resolve(vec![(key, "0".to_string())]).expect_err("zero is refused");
        assert!(
            error.to_string().contains(key),
            "the refusal names the key the operator must edit: {error}"
        );
    }
}

#[test]
fn a_deadline_that_is_not_a_number_is_refused_rather_than_defaulted() {
    for key in [keys::HANDSHAKE_TIMEOUT_MS, keys::IDLE_TIMEOUT_MS] {
        // Including the shapes an operator plausibly types. A relay that silently
        // fell back to the default here would be a relay whose deadline an
        // operator has read back from their own environment file and believed.
        for value in ["30s", "", "-1", "10_000"] {
            assert!(
                resolve(vec![(key, value.to_string())]).is_err(),
                "{key}={value:?} is refused"
            );
        }
    }
}

#[test]
fn both_keys_are_in_the_set_the_config_file_reader_accepts() {
    // `relay.toml` refuses a key outside `keys::ALL` rather than ignoring it, so
    // a variable absent from that list is one an operator can set in a file and
    // watch do nothing.
    assert!(keys::ALL.contains(&keys::HANDSHAKE_TIMEOUT_MS));
    assert!(keys::ALL.contains(&keys::IDLE_TIMEOUT_MS));
}
