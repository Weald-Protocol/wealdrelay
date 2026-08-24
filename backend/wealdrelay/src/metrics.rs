// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Prometheus text exposition over the readiness document.
//!
//! The relay already counts everything an incident needs: sockets open, sockets
//! refused at the cap, sockets closed on the handshake deadline and on the idle
//! deadline, media shed and denied, call table refusals, oversized outbound
//! frames, and the three pool numbers. All of it is on `/readyz`, behind the
//! operator bearer, as JSON.
//!
//! What did not exist was a way to *watch* any of it over time. A JSON document
//! answers "what is true now" to whoever is already looking, which is the same
//! shape of failure the control plane's alert board had: during an incident the
//! question is almost never what the counter is, it is when it started moving and
//! what moved with it. So this renders the same snapshot in the one format every
//! scraper and every hosted metrics backend reads for free.
//!
//! Three rules it inherits from the document it renders:
//!
//! - **No new counters.** Everything here already exists on `/readyz` and is
//!   already covered. A metrics endpoint that computed its own numbers would be a
//!   second source of truth about the same process, and the two would disagree
//!   during exactly the incident they were both built for.
//! - **Capacity, never identity.** Not one series has a group, principal, call or
//!   handle label. `crate::hub` refuses to hold that metadata and a labelled
//!   series here would reintroduce it through the back door, permanently, in a
//!   time series database somebody else operates. The only labels in this file
//!   are static build strings on `weald_relay_build_info`, which is the
//!   conventional way to carry a version without putting it in a metric name.
//! - **Private listener, operator bearer.** Same reasoning as `/readyz`'s
//!   detailed body, written out on `health::private_router`: the private listener
//!   is a network boundary and a network boundary is not an authentication
//!   boundary, because every co-tenant service in a provider environment can
//!   reach the port. Refusal counters and pool saturation are exactly what an
//!   attacker probing for a relay under load would want.
//!
//! `specs/backend/relay/operations.md` owns the counter list; this file owns only
//! its shape on the wire.

use crate::health::Readiness;

/// The exposition content type. Version 0.0.4 is what every scraper accepts.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// One metric, rendered with its help and type lines.
///
/// A small helper rather than a macro because there are two dozen of these and a
/// macro would make the list harder to read than the repetition it saved.
fn metric(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Escape a label value: backslash, quote and newline, per the exposition format.
///
/// Only the build strings go through this, and they are ours, but a version
/// string that broke the parse would take the whole scrape down rather than one
/// series, and "it is ours" is the assumption that fails after somebody adds a
/// git description with a quote in it.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render one readiness snapshot as Prometheus text.
///
/// Deliberately a pure function of the snapshot: the handler gathers, this
/// formats, and the test does not need a listener to prove the output.
pub fn render(readiness: &Readiness) -> String {
    let stats = &readiness.call_stats;
    let pool = &readiness.db_pool;
    let mut out = String::with_capacity(2_048);

    out.push_str("# HELP weald_relay_build_info The running build, as labels. Always 1.\n");
    out.push_str("# TYPE weald_relay_build_info gauge\n");
    out.push_str(&format!(
        "weald_relay_build_info{{version=\"{}\",build=\"{}\"}} 1\n",
        escape(&readiness.version),
        escape(&readiness.build),
    ));

    // The verdict, as a number, so an alert can be written against readiness
    // itself rather than against the scrape's HTTP status. A relay that is up
    // enough to be scraped and not ready enough to write is the state worth
    // alerting on, and it is invisible to anything watching only whether the
    // scrape succeeded.
    metric(
        &mut out,
        "weald_relay_ready",
        "1 when this relay would accept a durable write right now, 0 otherwise.",
        "gauge",
        u64::from(readiness.ready),
    );

    metric(
        &mut out,
        "weald_relay_connections",
        "Client sockets open on this process right now.",
        "gauge",
        stats.connections,
    );
    // The rate-limit refusal counter the launch review asked for by name. It was
    // already counted (`health::RelayState::connections_refused`) and already
    // read by the control plane's `relay_connections_refused_rate` rule; what it
    // lacked was a series an operator could put on a graph beside everything
    // else during an incident.
    metric(
        &mut out,
        "weald_relay_connections_refused_total",
        "Connections refused at the connection cap since start.",
        "counter",
        stats.connections_refused,
    );
    metric(
        &mut out,
        "weald_relay_connections_closed_handshake_deadline_total",
        "Connections closed for never authenticating inside the handshake timeout, since start.",
        "counter",
        stats.connections_closed_handshake_deadline,
    );
    metric(
        &mut out,
        "weald_relay_connections_closed_idle_deadline_total",
        "Connections closed for going silent past the idle timeout, since start.",
        "counter",
        stats.connections_closed_idle_deadline,
    );
    metric(
        &mut out,
        "weald_relay_oversized_outbound_frames_total",
        "Outbound frames refused at the wire cap since start. Any non-zero value is a relay bug.",
        "counter",
        stats.oversized_outbound_frames,
    );

    metric(
        &mut out,
        "weald_relay_calls_open",
        "Calls open on this process right now.",
        "gauge",
        stats.open,
    );
    metric(
        &mut out,
        "weald_relay_call_media_shed_total",
        "Media frames dropped because a recipient's queue was full, since start.",
        "counter",
        stats.media_shed,
    );
    metric(
        &mut out,
        "weald_relay_call_media_denied_total",
        "Media frames refused because the sender was not in the call it named, since start.",
        "counter",
        stats.media_denied,
    );
    metric(
        &mut out,
        "weald_relay_calls_share_refused_total",
        "Calls refused because one connection already held its share of the call table, since start.",
        "counter",
        stats.calls_share_refused,
    );

    metric(
        &mut out,
        "weald_relay_db_pool_size",
        "The configured Postgres pool ceiling.",
        "gauge",
        u64::from(pool.size),
    );
    metric(
        &mut out,
        "weald_relay_db_pool_connections",
        "Postgres connections the pool holds right now, busy or idle.",
        "gauge",
        u64::from(pool.connections),
    );
    // The one to alert on: equal to the ceiling means every further caller is
    // waiting on `acquire_timeout`, which looks like a relay defect from every
    // other vantage point.
    metric(
        &mut out,
        "weald_relay_db_pool_in_use",
        "Postgres connections checked out to a query at this instant.",
        "gauge",
        u64::from(pool.in_use),
    );

    metric(
        &mut out,
        "weald_relay_frozen_groups",
        "Groups whose retention control chain is contested. A count, never the ids.",
        "gauge",
        readiness.frozen_groups.len() as u64,
    );

    out
}
