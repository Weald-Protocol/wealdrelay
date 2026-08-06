// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Structured JSON logs, and the scrubbing layer over them.
//!
//! Two rules from `specs/backend/relay/operations.md`, and they are not the same
//! rule:
//!
//! - **Envelope bytes never appear at any level.** Not header, not body. The
//!   relay's whole claim is that it cannot read content, and a log line carrying
//!   `ct` would put content somewhere a log shipper takes it.
//! - **Group ids appear at debug level only.** A group id is opaque, but it is
//!   still a correlation handle, and an info-level log carrying one lets whoever
//!   reads logs build a picture of which groups are busy.
//!
//! On top of that, `specs/backend/cloud/control-plane.md` asks for "a scrubbing
//! layer that drops anything resembling a token". That is what ``scrub`` is, and
//! it is deliberately a text-level pass rather than a field allowlist. A field
//! allowlist protects the fields somebody remembered; a text pass also catches the
//! token that arrived inside an error message from a library nobody audited, which
//! is where credentials actually leak.
//!
//! The step 3 negative proof is that a planted token does not survive this.

use std::fmt;

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// What replaces a redacted run of characters. Fixed text, and long enough to be
/// greppable in a log aggregator.
pub const REDACTED: &str = "[redacted]";

/// The shortest run this treats as a secret.
///
/// Twenty is chosen against the things the relay actually handles: a base64
/// 32-byte key is 43 characters, a Postgres password in a URL is usually longer
/// than twenty, an AWS secret key is 40, and a JWT is far longer. Below twenty the
/// pass starts eating hex-encoded group id prefixes and version strings, which
/// would make debug logs useless without protecting anything.
const MINIMUM_SECRET_LENGTH: usize = 20;

/// Keys whose value is dropped whatever it looks like.
///
/// The text pass catches most things; this catches the short ones. A four
/// character token is not distinguishable from a word by shape, so the only way to
/// protect it is by the name it travels under.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "session",
    "cookie",
    "private_key",
    "credential",
    // A push wake handle. Sixteen bytes of hex is thirty two characters and, unlike a
    // key, it can be all lowercase letters, so `scrub_long_runs` would not claim it:
    // that pass needs a digit or an uppercase letter to avoid eating every long word.
    // Nothing in this crate ever formats a handle (`crate::push`), so this is the
    // second line of defence rather than the first, and it is here because the failure
    // mode is a handle arriving inside an error message from a library nobody audited.
    "handle",
    "push_handle",
];

/// Remove anything that looks like a credential from one line of text.
///
/// Four passes, in this order, because each can expose the next:
///
/// 1. URL userinfo: `postgres://user:password@host` becomes
///    `postgres://user:[redacted]@host`. The database URL reaches logs through
///    connection error messages, and it is the single most likely secret in a
///    relay's output.
/// 2. `Bearer <anything>`, because the token after it is a token by definition.
/// 3. `key=value` and `key: value` where the key is one of ``SENSITIVE_KEYS``.
/// 4. Any remaining long run of base64, base64url or hex characters.
///
/// Bearer runs before the labelled pass and not after it. `Authorization: Bearer
/// abc123` is claimed by both, and with the labelled pass first the value it drops
/// is the word `Bearer` itself, which removes the marker the bearer pass looks for
/// and leaves a short opaque token standing in the log.
pub fn scrub(line: &str) -> String {
    let mut out = scrub_url_userinfo(line);
    out = scrub_bearer(&out);
    out = scrub_labelled_values(&out);
    scrub_long_runs(&out)
}

/// `scheme://user:secret@host` keeps the user and loses the password. The user is
/// kept deliberately: an operator debugging a connection failure needs to know
/// which role failed, and the role name is not the credential.
fn scrub_url_userinfo(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes: Vec<char> = line.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        // Find `://`, then the authority up to the next `/`, whitespace or quote.
        if bytes[index] == ':'
            && bytes.get(index + 1) == Some(&'/')
            && bytes.get(index + 2) == Some(&'/')
        {
            out.push_str("://");
            index += 3;
            let start = index;
            while index < bytes.len()
                && !matches!(bytes[index], '/' | ' ' | '"' | '\'' | ',' | ')' | '\n')
            {
                index += 1;
            }
            let authority: String = bytes[start..index].iter().collect();
            match authority.rsplit_once('@') {
                Some((userinfo, host)) => {
                    let user = userinfo.split_once(':').map_or(userinfo, |(user, _)| user);
                    out.push_str(user);
                    out.push(':');
                    out.push_str(REDACTED);
                    out.push('@');
                    out.push_str(host);
                }
                None => out.push_str(&authority),
            }
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// `token=abc`, `"secret": "abc"`, `password: abc`.
fn scrub_labelled_values(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    let mut redactions: Vec<(usize, usize)> = Vec::new();
    for key in SENSITIVE_KEYS {
        let mut from = 0;
        while let Some(found) = lowered[from..].find(key) {
            let key_start = from + found;
            let mut cursor = key_start + key.len();
            from = cursor;
            // Optional closing quote after the key, then a separator.
            let bytes = line.as_bytes();
            while cursor < bytes.len() && matches!(bytes[cursor], b'"' | b'\'' | b' ') {
                cursor += 1;
            }
            if cursor >= bytes.len() || !matches!(bytes[cursor], b'=' | b':') {
                continue;
            }
            cursor += 1;
            while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'"' | b'\'') {
                cursor += 1;
            }
            let value_start = cursor;
            while cursor < bytes.len()
                && !matches!(
                    bytes[cursor],
                    b'"' | b'\'' | b' ' | b',' | b'}' | b'\n' | b'&'
                )
            {
                cursor += 1;
            }
            if cursor > value_start {
                redactions.push((value_start, cursor));
            }
        }
    }
    redact_ranges(line, redactions)
}

fn scrub_bearer(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    let mut redactions = Vec::new();
    let mut from = 0;
    while let Some(found) = lowered[from..].find("bearer ") {
        let start = from + found + "bearer ".len();
        let bytes = line.as_bytes();
        let mut cursor = start;
        while cursor < bytes.len() && !matches!(bytes[cursor], b'"' | b' ' | b',' | b'}' | b'\n') {
            cursor += 1;
        }
        if cursor > start {
            redactions.push((start, cursor));
        }
        from = start.max(from + 1);
    }
    redact_ranges(line, redactions)
}

/// Any run of at least ``MINIMUM_SECRET_LENGTH`` characters drawn only from the
/// base64, base64url and hex alphabets.
///
/// The run must contain at least one digit or one uppercase letter. Without that
/// condition an ordinary long lowercase word, or a snake_case identifier, is a
/// base64 string by shape, and the pass would redact half of every message.
fn scrub_long_runs(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut redactions = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_secret_char(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_secret_char(bytes[index]) {
            index += 1;
        }
        let run = &line[start..index];
        if run.len() >= MINIMUM_SECRET_LENGTH
            && run
                .chars()
                .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        {
            redactions.push((start, index));
        }
    }
    redact_ranges(line, redactions)
}

fn is_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// Replace every range with ``REDACTED``, right to left so earlier offsets stay
/// valid. Overlapping ranges are merged, because two passes can both claim the
/// same span and replacing twice would produce `[red[redacted]acted]`.
///
/// Public, and taking the ranges rather than finding them, for the same reason
/// `crate::storage::object_name` is shaped that way. Every pass above hands it
/// offsets it took from runs of ASCII, so no input to ``scrub`` can produce a
/// range that starts or ends inside a multi-byte character. The handling of one
/// that does is still the difference between a redacted secret and a leaked one,
/// and as a function over the ranges it can be given the case the passes cannot
/// produce, and tested rather than reasoned about.
pub fn redact_ranges(line: &str, mut ranges: Vec<(usize, usize)>) -> String {
    if ranges.is_empty() {
        return line.to_string();
    }
    // Every range is widened outward to the nearest character boundary before it
    // is merged or replaced. The offsets come from byte scans over ASCII runs and
    // the text around them can be anything, so a range can in principle start or
    // end inside a multi-byte character. Widening rather than skipping is the
    // decision that matters: skipping would leave the run in the string, and a
    // scrubber that silently declines to redact is a scrubber that leaks. Taking
    // one more byte of a character than was asked for is the safe direction to be
    // wrong in, and it cannot fail, so there is no arm here that only theory can
    // reach.
    let bytes = line.as_bytes();
    ranges = ranges
        .into_iter()
        .map(|(start, end)| (to_boundary(bytes, start, -1), to_boundary(bytes, end, 1)))
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = line.to_string();
    for (start, end) in merged.into_iter().rev() {
        out.replace_range(start..end, REDACTED);
    }
    out
}

/// Walk `index` in the direction of `step` until it sits on a character boundary.
///
/// `str::floor_char_boundary` and `str::ceil_char_boundary` are unstable, so the
/// arithmetic is written here. One function rather than two so the loop that does
/// the work is one piece of code with one set of outcomes: a continuation byte
/// moves the index on, anything else and the end of the string stop it.
///
/// Called with `-1` for the start of a range and `1` for the end, which widens the
/// range outward. Termination is guaranteed by UTF-8 itself: the first byte of a
/// `str` is never a continuation byte, so walking down always stops, and the walk
/// up stops at the end of the slice.
fn to_boundary(bytes: &[u8], mut index: usize, step: isize) -> usize {
    while bytes.get(index).is_some_and(|byte| is_continuation(*byte)) {
        index = index.wrapping_add_signed(step);
    }
    index
}

/// A byte in the middle of a multi-byte character, which is to say `10xxxxxx`.
fn is_continuation(byte: u8) -> bool {
    byte & 0b1100_0000 == 0b1000_0000
}

/// Whether a value may be logged at this level. Group ids are debug-only; envelope
/// bytes are never loggable at all, which is why there is no level that admits
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Safe at any level: counts, durations, error classes, configuration values
    /// that are not credentials.
    Operational,
    /// A group id. Debug and below.
    Correlatable,
    /// Envelope bytes, header or body. Never.
    Content,
}

impl Sensitivity {
    /// The rule, in one place, so a new log site cannot invent its own.
    ///
    /// The comparison runs the way it does because `tracing::Level` orders by
    /// verbosity and not by severity: `ERROR` is the smallest level and `TRACE` the
    /// largest, so "debug and below" in the operator's sense is `>= DEBUG` here.
    /// Written the other way round it reads correctly and admits a group id at
    /// info, warn and error while refusing it at trace, which is the leak inverted.
    pub fn permitted_at(self, level: tracing::Level) -> bool {
        match self {
            Self::Operational => true,
            Self::Correlatable => level >= tracing::Level::DEBUG,
            Self::Content => false,
        }
    }
}

/// A group id rendered for a log line, at a level that permits it.
///
/// Returns `None` when the level does not permit it, so a caller cannot get the
/// value out by asking at the wrong level. This is the mechanism behind the
/// debug-only rule: it is enforced by the type rather than remembered at each of
/// the places a group id is in scope.
pub fn group_for_log(group_id: &[u8], level: tracing::Level) -> Option<String> {
    if !Sensitivity::Correlatable.permitted_at(level) {
        return None;
    }
    Some(hex_prefix(group_id))
}

/// First twelve hex characters. Enough to correlate two lines, short of the whole
/// id, and the same prefix length the client's alarms use so an operator and a
/// user comparing notes are looking at the same string.
pub fn hex_prefix(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(12);
    for byte in bytes.iter().take(6) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Install the JSON subscriber with the scrubbing writer.
///
/// Returns `Err` if a subscriber is already installed, which is what happens when
/// a test installs one twice, and is a caller error rather than something to
/// panic over.
pub fn install(filter: &str) -> Result<(), String> {
    let env_filter = tracing_subscriber::EnvFilter::try_new(filter).map_err(|e| e.to_string())?;
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(ScrubbingWriter),
        )
        .try_init()
        .map_err(|error| error.to_string())
}

/// The writer that every log line passes through on its way out.
///
/// A writer and not a formatter, deliberately. A formatting layer only sees the
/// fields it was given; the writer sees the finished line, including whatever a
/// dependency's `Display` implementation put in an error message. That is where a
/// credential actually escapes.
#[derive(Debug, Clone, Copy)]
pub struct ScrubbingWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ScrubbingWriter {
    type Writer = ScrubbingSink;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubbingSink
    }
}

/// Scrubs, then writes to stdout. Logs go to stdout rather than a file because the
/// relay ships as a container and a distroless image has nowhere to rotate a file
/// to.
pub struct ScrubbingSink;

impl std::io::Write for ScrubbingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let scrubbed = scrub(&text);
        std::io::Write::write_all(&mut std::io::stdout(), scrubbed.as_bytes())?;
        // The original length, because the caller is reporting how much of *its*
        // buffer was consumed and a redaction changes the byte count.
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut std::io::stdout())
    }
}

/// A value that refuses to render. For a field that must never reach a log, so
/// the compiler carries the rule instead of a reviewer.
pub struct NeverLogged;

impl fmt::Debug for NeverLogged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REDACTED}")
    }
}

impl fmt::Display for NeverLogged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REDACTED}")
    }
}
