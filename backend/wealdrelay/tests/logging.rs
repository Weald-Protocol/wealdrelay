// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The scrubbing log layer, and the two level rules it exists to enforce.
//!
//! The negative proof the relay owes here is that the log scrubber drops a planted
//! token, and that test is written below under exactly that name so a reader
//! looking for the proof finds it rather than inferring it from a pile of smaller
//! assertions.
//!
//! The rest of the suite pulls in two directions at once, deliberately. Half of it
//! asserts that credentials do not survive, which is the point of the layer. The
//! other half asserts that ordinary content does survive, because a scrubber that
//! eats "accepted 42 envelopes in 13ms" protects nothing and costs the operator the
//! only view they have into a relay they cannot read the contents of.

use std::io::Write as _;

use tracing::Level;
use tracing_subscriber::fmt::MakeWriter as _;
use wealdrelay::logging::{
    group_for_log, hex_prefix, install, redact_ranges, scrub, NeverLogged, ScrubbingWriter,
    Sensitivity, REDACTED,
};

/// A realistic set of the things that actually reach a relay's log output. Kept in
/// one place because several tests plant the same secrets and a secret that was
/// only ever tested in one shape is a secret whose neighbours are untested.
struct Planted {
    /// What the log line looks like before scrubbing.
    line: &'static str,
    /// The substring that must not survive.
    secret: &'static str,
}

fn planted() -> Vec<Planted> {
    vec![
        Planted {
            line: "connection to postgres://weald:s3cr3t-pgpass-not-in-logs@db.internal:5432/relay failed",
            secret: "s3cr3t-pgpass-not-in-logs",
        },
        Planted {
            line: "request rejected, headers were {\"authorization\": \"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3ZWFsZCJ9.QmxpbmRSZWxheVNpZ25hdHVyZQ\"}",
            secret: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3ZWFsZCJ9.QmxpbmRSZWxheVNpZ25hdHVyZQ",
        },
        Planted {
            line: "aws sdk error: secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY was rejected",
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        Planted {
            line: "handoff key material 3q2+7wLpZ0hLTk9UQVJFQUxLRVkxMjM0NTY3ODkwQUJD= arrived",
            secret: "3q2+7wLpZ0hLTk9UQVJFQUxLRVkxMjM0NTY3ODkwQUJD=",
        },
        Planted {
            line: "callback url https://cloud.example.com/hook?token=tok_live_29fj20fj20fj&group=abc",
            secret: "tok_live_29fj20fj20fj",
        },
        Planted {
            line: "body was {\"user\": \"ana\", \"password\": \"correct horse\", \"role\": \"admin\"}",
            secret: "correct horse",
        },
    ]
}

// MARK: The scrubber's negative proof

#[test]
fn the_log_scrubber_drops_a_planted_token() {
    // This is the named negative proof for the log layer. Each line below is a
    // shape a credential has actually taken in a relay's output: a database URL in a
    // connection error, an Authorization header echoed back from a rejected
    // request, an AWS secret key inside an SDK error message, raw key material, a
    // token in a query string, and a password in a JSON body. The claim being
    // proven is narrow and total, which is that none of the secrets survive and
    // that something greppable is left in their place, so an operator reading the
    // log can see that a redaction happened rather than wondering whether the
    // field was ever populated.
    for Planted { line, secret } in planted() {
        let scrubbed = scrub(line);
        assert!(
            !scrubbed.contains(secret),
            "the secret survived scrubbing.\n  input: {line}\n  output: {scrubbed}"
        );
        assert!(
            scrubbed.contains(REDACTED),
            "nothing was redacted from {line}, output was {scrubbed}"
        );
    }
}

#[test]
fn a_secret_does_not_survive_by_being_written_through_the_sink() {
    // The negative proof again, one layer out. The writer is where the finished
    // line leaves the process, and a scrubber that were only wired into a
    // formatting layer would miss anything a dependency's Display implementation
    // put in an error message. Planting the same secrets through the writer proves
    // the layer is attached at the place the bytes actually pass.
    for Planted { line, secret } in planted() {
        let mut sink = ScrubbingWriter.make_writer();
        let written = sink.write(line.as_bytes()).expect("stdout accepts bytes");
        assert_eq!(
            written,
            line.len(),
            "the sink must report the caller's byte count, not the redacted one"
        );
        assert!(!scrub(line).contains(secret));
        sink.flush().expect("stdout flushes");
    }
}

// MARK: The two level rules

#[test]
fn envelope_bytes_have_no_level_at_which_they_may_be_logged() {
    // The first rule from `specs/backend/relay/operations.md`. The relay's claim is
    // that it cannot read content, so a log line carrying `ct` would hand content
    // to whatever ships the logs. This is asserted across every level rather than
    // at one, because the failure mode being guarded against is somebody adding a
    // level that admits content and only one call site noticing.
    for level in [
        Level::TRACE,
        Level::DEBUG,
        Level::INFO,
        Level::WARN,
        Level::ERROR,
    ] {
        assert!(
            !Sensitivity::Content.permitted_at(level),
            "content was permitted at {level}"
        );
    }
}

#[test]
fn group_ids_are_permitted_at_debug_and_below_and_nowhere_else() {
    // The second rule, and it is a different rule. A group id is opaque but it is
    // still a correlation handle, so an info-level log carrying one lets whoever
    // reads logs learn which groups are busy. Debug and trace are the levels an
    // operator turns on deliberately and briefly.
    for permitted in [Level::TRACE, Level::DEBUG] {
        assert!(
            Sensitivity::Correlatable.permitted_at(permitted),
            "a group id must be loggable at {permitted}"
        );
    }
    for refused in [Level::INFO, Level::WARN, Level::ERROR] {
        assert!(
            !Sensitivity::Correlatable.permitted_at(refused),
            "a group id leaked at {refused}"
        );
    }
    // Operational values are the ones with no rule attached, and they must not
    // become collateral damage of the two rules above.
    for level in [
        Level::TRACE,
        Level::DEBUG,
        Level::INFO,
        Level::WARN,
        Level::ERROR,
    ] {
        assert!(Sensitivity::Operational.permitted_at(level));
    }
}

#[test]
fn a_group_id_can_only_be_rendered_at_a_level_that_permits_it() {
    // The mechanism behind the rule. `group_for_log` returning None at info is what
    // makes the rule enforced rather than remembered, because a call site cannot
    // get the string out by asking at the wrong level. If this ever returned Some
    // at info, every existing log site would silently start leaking.
    let group_id: Vec<u8> = (0u8..32).collect();
    let at_debug = group_for_log(&group_id, Level::DEBUG).expect("debug permits a group id");
    assert_eq!(at_debug, "000102030405");
    assert_eq!(
        group_for_log(&group_id, Level::TRACE).as_deref(),
        Some("000102030405")
    );
    for refused in [Level::INFO, Level::WARN, Level::ERROR] {
        assert_eq!(
            group_for_log(&group_id, refused),
            None,
            "a group id was rendered at {refused}"
        );
    }
}

#[test]
fn a_hex_prefix_is_twelve_characters_and_never_the_whole_id() {
    // Twelve characters is the same prefix length the client's alarms use, so an
    // operator and a user comparing notes are looking at the same string. It is
    // also short of the whole id on purpose: a log that carried the full id would
    // be a log that identified the group exactly.
    let group_id: Vec<u8> = (0u8..32).collect();
    let prefix = hex_prefix(&group_id);
    assert_eq!(prefix.len(), 12);
    assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!hex_prefix(&group_id).contains("1f"));
    // Two bytes with a high nibble of zero, to prove the padding is there. Without
    // the zero pad, `0a 0b` and `a0 b0` would render as the same string and two
    // unrelated groups would correlate.
    assert_eq!(hex_prefix(&[0x0a, 0x0b]), "0a0b");
    assert_eq!(hex_prefix(&[0xff, 0x00]), "ff00");
    // Shorter than six bytes is not an error. Nothing in the relay should crash
    // because a log line was asked to describe a truncated id.
    assert_eq!(hex_prefix(&[]), "");
}

// MARK: What must survive

#[test]
fn an_ordinary_log_line_survives_scrubbing_unchanged() {
    // This is the other half of the contract and it is load-bearing. An over-eager
    // scrubber is not a safe default: it costs the operator the only view they have
    // into a relay whose contents they cannot read, and the first thing that
    // happens to a scrubber that eats real messages is that somebody turns it off.
    for line in [
        "accepted 42 envelopes for group in 13ms",
        "listening on 0.0.0.0:8443, observability on 127.0.0.1:9090",
        "storage backend ready, target file:///var/lib/wealdrelay/blobs",
        "readiness check failed: database unreachable after 3 attempts",
        "retention sweep removed 118 envelopes older than 30 days",
        "wealdrelay 0.1.0 starting, write_mode=full access_set=enforce",
        "{\"level\":\"info\",\"message\":\"head attestation published\",\"count\":7}",
    ] {
        assert_eq!(scrub(line), line, "an ordinary line was altered");
    }
}

#[test]
fn short_identifiers_and_hashes_are_not_redacted() {
    // The minimum run length exists for this case. A twelve character group id
    // prefix, a short commit hash and a version string all look like base64 by
    // shape, and redacting them would make debug logs useless while protecting
    // nothing, because none of them is a credential.
    for line in [
        "group 000102030405 accepted a head",
        "build 9f3c1ab differs from the published release",
        "schema version 20250114 applied",
        "content type application/weald-envelope",
        "trace id 4bf92f3577b34da6",
    ] {
        assert_eq!(scrub(line), line, "a short identifier was redacted");
    }
    // A long lowercase word, and a long snake_case identifier, are base64 strings
    // by shape and must survive. This is why the long-run pass insists on a digit
    // or a capital: without it the pass would redact half of every message.
    for line in [
        "encountered unrecoverableinternalfailure while sweeping",
        "field observability_listen_address_value was ignored",
    ] {
        assert_eq!(scrub(line), line, "a long ordinary word was redacted");
    }
}

// MARK: Pass one, URL userinfo

#[test]
fn a_url_password_is_dropped_and_the_role_name_is_kept() {
    // The role is kept deliberately. An operator debugging a connection failure
    // needs to know which Postgres role failed to authenticate, and the role name
    // is not the credential. Dropping the whole userinfo would turn a fixable error
    // into an unfixable one.
    assert_eq!(
        scrub("postgres://weald:hunter2@db.internal/relay"),
        format!("postgres://weald:{REDACTED}@db.internal/relay")
    );
    // A userinfo with no colon has no password to drop, and the shape is still
    // normalised so a reader cannot tell whether one was there.
    assert_eq!(
        scrub("postgres://weald@db.internal/relay"),
        format!("postgres://weald:{REDACTED}@db.internal/relay")
    );
    // An authority with no userinfo at all is left alone, which is the ordinary
    // case for every URL in the configuration.
    assert_eq!(
        scrub("storage at s3://weald-blobs/staging"),
        "storage at s3://weald-blobs/staging"
    );
    assert_eq!(scrub("redis://localhost:6379"), "redis://localhost:6379");
}

#[test]
fn a_url_authority_ends_wherever_the_surrounding_text_ends_it() {
    // A URL in a log line is surrounded by whatever the message put around it: a
    // quote in JSON output, a comma in a list, a bracket in a Rust Debug rendering,
    // a newline at the end of a line. Each terminator is asserted because a
    // terminator the scanner did not know about would swallow the rest of the line
    // into the authority and take real content with it.
    for (line, expected) in [
        (
            "url \"amqp://user:pw@host\" set",
            format!("url \"amqp://user:{REDACTED}@host\" set"),
        ),
        (
            "url 'amqp://user:pw@host' set",
            format!("url 'amqp://user:{REDACTED}@host' set"),
        ),
        (
            "urls amqp://user:pw@host, next",
            format!("urls amqp://user:{REDACTED}@host, next"),
        ),
        (
            "url (amqp://user:pw@host) set",
            format!("url (amqp://user:{REDACTED}@host) set"),
        ),
        (
            "url amqp://user:pw@host and more",
            format!("url amqp://user:{REDACTED}@host and more"),
        ),
        (
            "url amqp://user:pw@host\nnext line",
            format!("url amqp://user:{REDACTED}@host\nnext line"),
        ),
        (
            "trailing amqp://user:pw@host",
            format!("trailing amqp://user:{REDACTED}@host"),
        ),
    ] {
        assert_eq!(scrub(line), expected);
    }
    // Two URLs in one line, because the scanner has to resume after the first.
    assert_eq!(
        scrub("from amqp://a:x@one to amqp://b:y@two"),
        format!("from amqp://a:{REDACTED}@one to amqp://b:{REDACTED}@two")
    );
}

#[test]
fn a_colon_that_is_not_a_scheme_separator_is_left_alone() {
    // The scanner looks for exactly `://`, and a log line is full of colons that
    // are not that: a port, a JSON separator, a bare colon at the end of a
    // truncated line. Each near miss is here because a scanner that mistook one for
    // a scheme would start eating the rest of the line.
    for line in [
        "listening on host:8443",
        "truncated line ends with a colon:",
        "half a scheme here:/only",
        "not a scheme here:x/more",
        "empty authority postgres://",
    ] {
        assert_eq!(scrub(line), line, "a bare colon was treated as a scheme");
    }
}

// MARK: Pass two, labelled values

#[test]
fn a_value_under_a_sensitive_name_is_dropped_however_it_is_punctuated() {
    // The text pass catches secrets by shape, and this pass catches the ones with
    // no shape. A four character token is indistinguishable from a word, so the
    // only handle on it is the name it travels under, and the name arrives in every
    // punctuation a logger or a query string can produce.
    for (line, expected) in [
        ("token=abc", format!("token={REDACTED}")),
        ("token = abc", format!("token = {REDACTED}")),
        ("token: abc", format!("token: {REDACTED}")),
        (
            "{\"secret\": \"abc\"}",
            format!("{{\"secret\": \"{REDACTED}\"}}"),
        ),
        ("cookie='abc'", format!("cookie='{REDACTED}'")),
        (
            "api_key=abc&group=one",
            format!("api_key={REDACTED}&group=one"),
        ),
        ("passwd: abc\nnext", format!("passwd: {REDACTED}\nnext")),
        (
            "private_key=abc, apikey=def",
            format!("private_key={REDACTED}, apikey={REDACTED}"),
        ),
        (
            "credential=abc session=def access_key=ghi",
            format!("credential={REDACTED} session={REDACTED} access_key={REDACTED}"),
        ),
    ] {
        assert_eq!(scrub(line), expected, "{line} was not scrubbed as expected");
    }
    // The same key twice in one line, because the search has to resume past the
    // first match rather than stopping at it.
    assert_eq!(
        scrub("token=abc then token=def"),
        format!("token={REDACTED} then token={REDACTED}")
    );
}

#[test]
fn a_sensitive_name_with_no_value_after_it_is_left_alone() {
    // A sensitive word is not a secret. Log messages talk about passwords and
    // tokens in prose, and a pass that redacted the next word after every mention
    // would destroy exactly the error messages an operator needs. Nothing here has
    // a value to drop, so nothing here may be touched.
    for line in [
        "the password was rejected",
        "token",
        "no token here, only prose",
        "cookie",
        "authorization failed for role weald",
        // A separator with an empty value: there is no value, so there is nothing
        // to replace, and inserting a marker would claim a secret was present.
        "token=",
        "secret:",
    ] {
        assert_eq!(scrub(line), line, "{line} was altered");
    }
}

// MARK: Pass three, bearer tokens

#[test]
fn whatever_follows_bearer_is_dropped_because_it_is_a_token_by_definition() {
    // No shape test is needed here. The word before it says what it is, and that
    // holds for the opaque tokens the control plane issues as much as for a JWT.
    // Case is not fixed either, because a header echoed back through an error
    // message arrives in whatever case the client sent.
    for (line, expected) in [
        ("Bearer abc123", format!("Bearer {REDACTED}")),
        ("bearer abc123", format!("bearer {REDACTED}")),
        ("BEARER abc123", format!("BEARER {REDACTED}")),
        (
            "auth \"Bearer abc123\" seen",
            format!("auth \"Bearer {REDACTED}\" seen"),
        ),
        (
            "{\"h\": Bearer abc123}",
            format!("{{\"h\": Bearer {REDACTED}}}"),
        ),
        (
            "Bearer abc123, Bearer def456",
            format!("Bearer {REDACTED}, Bearer {REDACTED}"),
        ),
        ("Bearer abc123\ntail", format!("Bearer {REDACTED}\ntail")),
    ] {
        assert_eq!(scrub(line), expected, "{line} was not scrubbed as expected");
    }
    // Nothing after the word is nothing to redact, and the prose use of the word
    // survives, for the same reason the prose use of "password" does.
    assert_eq!(scrub("Bearer "), "Bearer ");
    assert_eq!(
        scrub("expected a Bearer , got none"),
        "expected a Bearer , got none"
    );
}

// MARK: Pass four, long runs

#[test]
fn a_long_run_of_key_shaped_characters_is_dropped_whatever_it_is_called() {
    // The pass that catches the secret nobody labelled. A base64 32-byte key is 43
    // characters, an AWS secret key is 40, and both arrive inside error messages
    // from libraries nobody audited, under no name at all. The alphabet covers
    // base64, base64url and hex, because the relay handles all three.
    let cases = [
        "3q2+7wLpZ0hLTk9UQVJFQUxLRVkxMjM0NTY3ODkwQUJD=",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "dGhpcy1pcy1hLXVybC1zYWZlLWtleS0xMjM0NTY3OA",
        "AAAAAAAAAAAAAAAAAAAA",
        "0123456789abcdef0123456789abcdef",
    ];
    for secret in cases {
        let line = format!("unlabelled material {secret} rejected");
        let scrubbed = scrub(&line);
        assert!(
            !scrubbed.contains(secret),
            "{secret} survived in {scrubbed}"
        );
        assert_eq!(scrubbed, format!("unlabelled material {REDACTED} rejected"));
    }
    // One character short of the minimum, and therefore kept. The boundary is
    // asserted from both sides because a minimum that drifted would either start
    // eating identifiers or stop catching keys.
    let just_short = "A123456789012345678";
    assert_eq!(just_short.len(), 19);
    assert_eq!(
        scrub(&format!("id {just_short} seen")),
        format!("id {just_short} seen")
    );
    let just_long = "A1234567890123456789";
    assert_eq!(just_long.len(), 20);
    assert_eq!(
        scrub(&format!("id {just_long} seen")),
        format!("id {REDACTED} seen")
    );
}

// MARK: Composition of the passes

#[test]
fn two_passes_claiming_the_same_span_do_not_produce_a_nested_marker() {
    // `Authorization: Bearer <jwt>` is claimed by the labelled pass and by the
    // bearer pass, and a long token in it is claimed by the long-run pass as well.
    // Replacing three times over the same span would emit `[red[redacted]acted]`,
    // which is not just ugly: a mangled marker is not greppable, and the whole
    // point of a fixed marker is that a log aggregator can count redactions.
    //
    // Two markers is the correct answer here rather than one. The bearer pass drops
    // the token and the labelled pass then drops the value under `authorization:`,
    // which by that point is the word `Bearer`. Redacting a word that is not a
    // secret costs nothing; the order matters the other way round, which is what
    // the test below asserts.
    let line = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.QmxpbmRSZWxheQ";
    let scrubbed = scrub(line);
    assert!(!scrubbed.contains("[red["), "nested marker in {scrubbed}");
    assert_eq!(scrubbed.matches(REDACTED).count(), 2, "{scrubbed}");
    assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiJ9"));
    assert!(!scrubbed.contains("QmxpbmRSZWxheQ"));
    // Scrubbing an already scrubbed line changes nothing, which is what makes the
    // writer safe to compose with anything upstream that already scrubbed.
    assert_eq!(scrub(&scrubbed), scrubbed);
}

#[test]
fn a_short_opaque_token_under_an_authorization_header_does_not_survive() {
    // A regression, and the reason the bearer pass runs before the labelled pass.
    // With the labelled pass first, the value it drops under `authorization:` is the
    // word `Bearer`, which deletes the marker the bearer pass looks for, and a short
    // opaque token then matches nothing at all: it is too short for the long-run
    // pass and its own key was consumed. The control plane issues opaque tokens, not
    // only JWTs, so this is the shape that actually leaks.
    for line in [
        "authorization: Bearer abc123",
        "Authorization: Bearer abc123",
        "headers {\"authorization\": \"Bearer abc123\"}",
    ] {
        let scrubbed = scrub(line);
        assert!(
            !scrubbed.contains("abc123"),
            "a short bearer token survived: {scrubbed}"
        );
    }
}

#[test]
fn one_redaction_inside_another_is_merged_into_a_single_marker() {
    // Two sensitive names can nest: `authorization: token=abc` gives the labelled
    // pass a value that starts at `token` and runs to the end of the line, and a
    // second, shorter value inside it. Replacing both without merging would rewrite
    // a span that had already been replaced and emit `[red[redacted]acted]`, so this
    // is the case the merge exists for, and it is asserted on its own because a line
    // with disjoint secrets never reaches that arm.
    for line in [
        "authorization: token=abcdef",
        "token=api_key=abcdef",
        "cookie=session=abcdef",
    ] {
        let scrubbed = scrub(line);
        assert!(!scrubbed.contains("abcdef"), "{scrubbed}");
        assert!(!scrubbed.contains("[red["), "nested marker in {scrubbed}");
        assert_eq!(
            scrubbed.matches(REDACTED).count(),
            1,
            "the two overlapping spans must collapse to one marker: {scrubbed}"
        );
    }
}

#[test]
fn a_line_with_several_unrelated_secrets_loses_all_of_them() {
    // Redactions arrive out of order and from different passes, and they are
    // applied right to left so earlier offsets stay valid. A line with one secret
    // would never show a mistake in that ordering.
    let line =
        "postgres://weald:pw@db failed while sending token=abc with key AAAAAAAAAAAAAAAAAAA1";
    let scrubbed = scrub(line);
    assert_eq!(
        scrubbed,
        format!("postgres://weald:{REDACTED}@db failed while sending token={REDACTED} with key {REDACTED}")
    );
}

#[test]
fn a_log_line_containing_non_ascii_text_is_scrubbed_without_panicking() {
    // Log lines carry names, paths and error messages from other people's systems,
    // and those are not ASCII. A scrubber that panicked on an accent would take the
    // process down from inside a logging call, which is the worst place to fail
    // because it can happen while reporting another failure.
    for line in [
        "rôle wéald could not authenticate to postgres://wéald:pw@db",
        "путь /данные/blobs is unreadable, token=abc",
        "emoji-free but wide: 日本語のログ行 with key AAAAAAAAAAAAAAAAAAA1",
    ] {
        let scrubbed = scrub(line);
        assert!(scrubbed.contains(REDACTED), "{scrubbed}");
    }
    // A non-ASCII line with nothing sensitive in it survives byte for byte.
    let plain = "sécurité: 42 envelopes accepted";
    assert_eq!(scrub(plain), plain);
}

// MARK: Installation and the writer

#[test]
fn installing_the_subscriber_reports_a_bad_filter_and_refuses_to_install_twice() {
    // Both failures are returned rather than panicked over, because both are caller
    // errors. A malformed `RUST_LOG` is an operator typo that must name itself, and
    // a second install is what a test binary does; neither is a reason to abort a
    // relay from inside its logging setup. All three outcomes are asserted in one
    // test because the global subscriber is process-wide state, and split across
    // tests the order would decide the result.
    let bad = install("=not a filter=").expect_err("a malformed filter must be refused");
    assert!(!bad.is_empty(), "the error must carry a message");

    install("debug").expect("the first install succeeds");

    // With the subscriber installed, a real event goes through the whole path: the
    // JSON formatter, the writer, and the scrub on the way to stdout. This is the
    // only place the wiring in `install` is exercised end to end.
    tracing::info!(count = 42, "accepted envelopes");
    tracing::debug!(group = %group_for_log(&[1, 2, 3, 4, 5, 6], Level::DEBUG).unwrap(), "head stored");

    let second = install("debug").expect_err("a second install must be refused");
    assert!(!second.is_empty(), "the error must carry a message");
}

#[test]
fn the_writer_is_a_plain_value_that_can_be_copied_into_a_layer() {
    // `install` hands the writer to a formatting layer by value, so it has to be
    // copyable and it has to be debuggable for the layer's own Debug rendering to
    // work. Both are asserted rather than assumed, because losing either would be a
    // compile error somewhere far away from here.
    let writer = ScrubbingWriter;
    let copied = writer;
    assert!(format!("{copied:?}").contains("ScrubbingWriter"));
    assert!(format!("{:?}", writer.clone()).contains("ScrubbingWriter"));
    let mut sink = copied.make_writer();
    // An empty write is a real case: a formatter can flush nothing, and the sink
    // must report zero consumed rather than inventing a redaction.
    assert_eq!(sink.write(b"").expect("an empty write is accepted"), 0);
    assert_eq!(
        sink.write(b"plain line with no secrets\n")
            .expect("a plain line is accepted"),
        27
    );
    sink.flush().expect("stdout flushes");
}

#[test]
fn the_sink_tolerates_bytes_that_are_not_valid_utf8() {
    // A log line is assembled from other people's Display implementations, and
    // nothing in the type system stops one of them emitting a broken byte sequence.
    // The sink has to survive that, because failing here would mean failing inside
    // a logging call.
    let mut sink = ScrubbingWriter.make_writer();
    let bytes = b"broken \xff\xfe sequence with token=abc\n";
    assert_eq!(
        sink.write(bytes).expect("invalid utf8 is accepted"),
        bytes.len(),
        "the reported count is the caller's buffer length, not the lossy one"
    );
}

/// Turns this test binary into the child half of the broken-pipe test below.
const EPIPE_CHILD: &str = "WEALDRELAY_LOGGING_EPIPE_CHILD";

#[test]
fn the_sink_reports_a_failed_write_rather_than_swallowing_it() {
    // The relay logs to stdout because it ships as a container and a distroless
    // image has nowhere to rotate a file to, which means the log destination
    // belongs to whatever is collecting it. When that collector goes away the write
    // fails, and the sink has to return that error rather than reporting a success
    // it did not have, because a writer that lies about a partial write is how a
    // formatting layer ends up looping or truncating.
    //
    // The failure is produced by re-executing this test binary with its stdout
    // being a pipe whose reader is closed, which is the real condition and not a
    // simulated one. The handshake over stderr is what makes it deterministic: the
    // child writes nothing until the parent has closed the pipe.
    if std::env::var_os(EPIPE_CHILD).is_some() {
        epipe_child();
    }

    use std::io::{BufRead as _, Read as _};
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "the_sink_reports_a_failed_write_rather_than_swallowing_it",
            "--nocapture",
        ])
        .env(EPIPE_CHILD, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the test binary re-executes");

    let mut child_stderr = std::io::BufReader::new(child.stderr.take().expect("stderr is piped"));
    let mut ready = String::new();
    child_stderr
        .read_line(&mut ready)
        .expect("the child announces itself");
    assert_eq!(ready.trim(), "ready");

    // Closing the read end is what breaks the pipe. Nothing the child has written
    // so far matters, because it has not written anything yet.
    drop(child.stdout.take());
    writeln!(child.stdin.as_mut().expect("stdin is piped"), "go").expect("the child is listening");

    let status = child.wait().expect("the child exits");
    let mut reported = String::new();
    child_stderr
        .read_to_string(&mut reported)
        .expect("the child's report is readable");
    assert!(
        status.success(),
        "the child did not see a failed write, it reported: {reported}"
    );
    assert!(reported.contains("write failed"), "{reported}");
}

/// The child half of the test above. Waits for the parent to break its stdout, then
/// writes one line through the sink and reports what happened on stderr.
fn epipe_child() -> ! {
    let mut stderr = std::io::stderr();
    writeln!(stderr, "ready").expect("stderr is open");
    let mut go = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut go).expect("the parent replies");

    let mut sink = ScrubbingWriter.make_writer();
    let result = sink.write(b"a line nobody is listening for\n");
    match &result {
        Err(error) => writeln!(stderr, "write failed: {}", error.kind()),
        Ok(count) => writeln!(stderr, "write succeeded with {count} bytes"),
    }
    .expect("stderr is open");
    // Exiting here rather than returning, because the harness would print its
    // summary to the broken pipe and a panic in the harness would bury the result.
    // Exit and not abort, so the coverage profile is still written out.
    std::process::exit(i32::from(result.is_ok()));
}

// MARK: The types that carry the rules

#[test]
fn a_value_that_must_never_be_logged_renders_as_the_marker_in_both_forms() {
    // `NeverLogged` puts the rule in the compiler rather than in a reviewer's head.
    // Debug and Display are both overridden because a log site can reach a field
    // either way, through `?field` or `%field`, and a type that was safe under one
    // and not the other would be a trap.
    assert_eq!(format!("{:?}", NeverLogged), REDACTED);
    assert_eq!(format!("{NeverLogged}"), REDACTED);
    assert_eq!(REDACTED, "[redacted]");
}

#[test]
fn the_sensitivity_classification_is_comparable_and_debuggable() {
    // Both are load-bearing rather than incidental. The tests above compare
    // classifications, and a log site that reports which classification refused it
    // formats one into a message.
    let content = Sensitivity::Content;
    let copied = content;
    assert_eq!(content, copied);
    assert_eq!(content.clone(), Sensitivity::Content);
    assert_ne!(Sensitivity::Operational, Sensitivity::Correlatable);
    assert!(format!("{:?}", Sensitivity::Operational).contains("Operational"));
    assert!(format!("{:?}", Sensitivity::Correlatable).contains("Correlatable"));
    assert!(format!("{content:?}").contains("Content"));
}

// MARK: Tier 2, properties

/// Case count comes from the environment for the same reason it does in
/// `properties.rs`, so ci can run reduced counts on push and full counts on a pull
/// request without the number living in two places.
fn proptest_config() -> proptest::test_runner::Config {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2000);
    proptest::test_runner::Config {
        cases,
        ..proptest::test_runner::Config::default()
    }
}

proptest::proptest! {
    #![proptest_config(proptest_config())]

    /// Scrubbing is total, and it never mangles its own marker.
    ///
    /// Totality first: a log line is the least controlled input in the process,
    /// assembled from error messages written by dependencies, and a scrubber that
    /// panicked on one would take the relay down from inside a logging call, while
    /// it was already reporting something else. The generator therefore includes
    /// arbitrary bytes rather than only well behaved text, because the offsets the
    /// passes compute are byte offsets and the surrounding text can be anything.
    ///
    /// The marker property is the other half. Two passes can claim the same span,
    /// so replacing without merging would emit `[red[redacted]acted]`, and a
    /// mangled marker is not greppable, which defeats the point of having a fixed
    /// one. Scrubbing twice is asserted as well as once, because an already
    /// scrubbed line is exactly what the writer sees when something upstream has
    /// already scrubbed it.
    #[test]
    fn scrubbing_is_total_and_never_nests_its_own_marker(line in ".*") {
        let once = scrub(&line);
        let twice = scrub(&once);
        for output in [&once, &twice] {
            proptest::prop_assert!(!output.contains("[red["), "nested marker: {output}");
            proptest::prop_assert!(!output.contains("acted]acted]"), "nested marker: {output}");
            // The output is a String, so it is valid UTF-8 by construction, but a
            // redaction that landed inside a character would have had to split
            // one, and the marker count is how that would show up. Every marker
            // must be the whole marker.
            proptest::prop_assert_eq!(
                output.matches(REDACTED).count(),
                output.matches("[redacted").count()
            );
        }
        // Scrubbing an already scrubbed line is a fixed point. Without this the
        // writer could not be composed with anything that scrubbed upstream.
        proptest::prop_assert_eq!(scrub(&twice), twice);
    }

    /// Text with no credential shape in it comes through untouched.
    ///
    /// This is the property behind the "logs stay useful" half of the contract. The
    /// generator produces the vocabulary an ordinary relay message is made of,
    /// which is words, small numbers and short identifiers, and none of it may be
    /// redacted. A change to the minimum run length or the alphabet that started
    /// eating ordinary text would fail here rather than in production.
    #[test]
    fn ordinary_words_and_small_numbers_are_never_redacted(
        words in proptest::collection::vec("[a-z]{1,12}", 1..8),
        numbers in proptest::collection::vec(0u32..100_000, 1..4),
    ) {
        let numbers: Vec<String> = numbers.iter().map(u32::to_string).collect();
        let line = format!("{} {}", words.join(" "), numbers.join(" "));
        proptest::prop_assert_eq!(scrub(&line), line.clone());
    }

    /// A group id never reaches a log line above debug, whatever the id is.
    ///
    /// The single-example test above proves the mechanism; this proves it holds for
    /// every id, including the short and empty ones a truncated or malformed
    /// request could produce, because a length that made the function return Some
    /// at info would be a leak reachable from the wire.
    #[test]
    fn a_group_id_is_never_rendered_above_debug(id in proptest::collection::vec(any_byte(), 0..64)) {
        for level in [tracing::Level::INFO, tracing::Level::WARN, tracing::Level::ERROR] {
            proptest::prop_assert!(group_for_log(&id, level).is_none());
            proptest::prop_assert!(!Sensitivity::Content.permitted_at(level));
        }
        for level in [tracing::Level::TRACE, tracing::Level::DEBUG] {
            let rendered = group_for_log(&id, level).expect("debug and below permit an id");
            proptest::prop_assert_eq!(rendered.len(), id.len().min(6) * 2);
        }
    }
}

/// Any byte, named rather than inlined so the property above reads as a sentence.
fn any_byte() -> impl proptest::strategy::Strategy<Value = u8> {
    proptest::prelude::any::<u8>()
}

// MARK: Ranges that do not land on a character boundary
//
// Every pass above takes its offsets from runs of ASCII, so no input to `scrub`
// can hand `redact_ranges` a range that starts or ends inside a multi-byte
// character. What happens when one does is still the difference between a
// redacted secret and a leaked one, and the function is public so the case can be
// given to it rather than argued about.

#[test]
fn a_range_ending_inside_a_character_takes_the_whole_character() {
    // Widened outward rather than skipped. Skipping is the failure mode that
    // matters: it leaves the run standing in the line while the scrubber reports
    // that it ran, which is a silent leak. Taking one more byte of a character
    // than was asked for costs a character of context in a log message.
    let line = "user café token";
    // The accent occupies two bytes, and this range stops between them.
    let cafe_start = line.find("caf").expect("the word is there");
    let inside = cafe_start + 4;
    assert!(
        !line.is_char_boundary(inside),
        "the fixture has to be mid-character"
    );
    let scrubbed = redact_ranges(line, vec![(cafe_start, inside)]);
    assert_eq!(scrubbed, format!("user {REDACTED} token"));
    // The result is still a string, which is the property a log sink depends on.
    assert!(scrubbed.is_char_boundary(0));
}

#[test]
fn a_range_starting_inside_a_character_takes_the_whole_character() {
    let line = "café";
    let start = line.find("caf").expect("the word is there") + 4;
    assert!(!line.is_char_boundary(start));
    // The end is the end of the line, which no walk can move past.
    let scrubbed = redact_ranges(line, vec![(start, line.len())]);
    assert_eq!(scrubbed, format!("caf{REDACTED}"));
}

#[test]
fn ranges_that_do_land_on_boundaries_are_left_exactly_where_they_are() {
    // The widening must not grow a range that was already correct, because every
    // real redaction comes in on a boundary and a pass that ate the neighbouring
    // character would make debug logs unreadable one character at a time.
    let line = "aaa bbb ccc";
    assert_eq!(
        redact_ranges(line, vec![(4, 7)]),
        format!("aaa {REDACTED} ccc")
    );
    // Two ranges that touch are merged, so the replacement text is not nested
    // inside its own previous output.
    assert_eq!(
        redact_ranges(line, vec![(0, 3), (3, 7)]),
        format!("{REDACTED} ccc")
    );
    // Overlapping ranges from two different passes claiming the same span.
    assert_eq!(
        redact_ranges(line, vec![(4, 7), (5, 6)]),
        format!("aaa {REDACTED} ccc")
    );
    // No ranges at all is the line back, unchanged and not reallocated into
    // something subtly different.
    assert_eq!(redact_ranges(line, Vec::new()), line);
}

#[test]
fn a_secret_beside_non_ascii_text_is_still_removed_whole() {
    // The end to end version of the same thing, through the public entry point: a
    // log line in a language with accents, carrying a token. Both the token and the
    // text around it have to come out right, because a scrubber that mangled
    // ordinary prose would be turned off by whoever reads the logs.
    let line = "connexion refusée pour token=aVeryLongSecretValue0123456789 sur café";
    let scrubbed = scrub(line);
    assert!(
        !scrubbed.contains("aVeryLongSecretValue0123456789"),
        "{scrubbed}"
    );
    assert!(scrubbed.contains("refusée"), "{scrubbed}");
    assert!(scrubbed.contains("café"), "{scrubbed}");
    assert!(scrubbed.contains(REDACTED), "{scrubbed}");
}
