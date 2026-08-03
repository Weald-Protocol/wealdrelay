// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The fuzz corpus, replayed by `cargo test` with no nightly and no sanitizer.
//!
//! `specs/backend/relay/mls-binding.md` requires fuzzing of `weald_mls_process` "with
//! malformed and hostile messages", and the corpus has to be carried forward rather than
//! rediscovered. A libFuzzer target satisfies the first and only half of the second: it
//! explores, but it explores in a nightly build with a sanitizer,
//! on a schedule, and nobody notices for a week when it stops being run.
//!
//! So the seeds are checked in under `fuzz/corpus/process/` and this file replays every
//! one of them through the same function on every ordinary `cargo test`. A regression that
//! the fuzzer found once is then found again immediately, by the suite everybody runs,
//! rather than by the suite somebody remembers to run.
//!
//! The seeds are generated rather than hand-written, because hand-written MLS messages are
//! not MLS messages: half the interesting surface is behind a signature check, and bytes
//! that fail deserialisation never reach it. Real ones are produced here from a real group
//! and then damaged in the ways a network damages things.
//!
//! Regenerate with `WEALD_MLS_WRITE_CORPUS=1 cargo test -p weald-mls --test fuzz_corpus`.
//! The seeds are not byte-reproducible (MLS messages carry fresh randomness), which is
//! fine: they are starting points for a fuzzer, not fixtures with expected values.

use std::path::{Path, PathBuf};

use weald_mls::session::{Config, Device, Processed};
use weald_mls::status::Status;

/// Where the checked-in corpus lives. The same directory `cargo fuzz run process` reads,
/// so the two halves cannot drift apart.
fn corpus_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("process")
}

fn device(identity: &str) -> Device {
    Device::open(&Config {
        database: ":memory:".to_string(),
        identity: identity.as_bytes().to_vec(),
    })
    .expect("a device")
}

/// Real messages of every kind the seam produces, from a real group.
///
/// One of each thing `process` can be handed: the two it accepts (a commit, a proposal),
/// the one it is for (an application message), and the ones a confused or hostile caller
/// will hand it anyway (a key package, a welcome, a group info, a ratchet tree). The last
/// group matters more than it looks: they are well-formed MLS objects of the wrong kind,
/// which is the input most likely to reach a code path a random byte string never will.
fn real_messages() -> Vec<(String, Vec<u8>)> {
    let ada_device = device("ada");
    let mut ada = ada_device
        .create_group(b"weald-corpus-group")
        .expect("a group");
    let bo_device = device("bo");
    let cy_device = device("cy");

    let key_package = bo_device.key_package().expect("a key package");
    let (commit, welcome) = ada.add(&key_package).expect("an add");
    ada.merge_pending().expect("merged");
    let mut bo = bo_device.join_welcome(&welcome).expect("bo joined");

    let application = ada.encrypt(b"a line of the document").expect("ciphertext");
    let proposal = bo
        .propose_add(&cy_device.key_package().expect("a key package"))
        .expect("a proposal");
    let group_info = ada.group_info().expect("a group info");
    let ratchet_tree = ada.ratchet_tree().expect("a ratchet tree");

    vec![
        ("commit".to_string(), commit),
        ("welcome".to_string(), welcome),
        ("key_package".to_string(), key_package),
        ("application".to_string(), application),
        ("proposal".to_string(), proposal),
        ("group_info".to_string(), group_info),
        ("ratchet_tree".to_string(), ratchet_tree),
    ]
}

/// The damage a network, a bug or an attacker does to a well-formed message.
///
/// Deterministic mutations rather than random ones, because these are seeds: the fuzzer
/// supplies the randomness, and a seed set that changed on every regeneration would make
/// the checked-in corpus meaningless as a regression suite.
fn mutations(name: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if bytes.is_empty() {
        return out;
    }

    // Truncated: the shape a message cut short by a closed socket has, and the one that
    // finds a length field read past the end of a buffer.
    out.push((
        format!("{name}.truncated"),
        bytes[..bytes.len() / 2].to_vec(),
    ));
    out.push((format!("{name}.head"), bytes[..1.min(bytes.len())].to_vec()));

    // A flipped bit in the middle. Usually a signature failure, which is the path a
    // tampered message takes and the one that must fail closed.
    let mut flipped = bytes.to_vec();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0b1000_0000;
    out.push((format!("{name}.flipped"), flipped));

    // A flipped bit in the header, where the version, the wire format and the content type
    // live. The parser's own decisions come from these bytes.
    let mut header = bytes.to_vec();
    header[0] ^= 0xff;
    out.push((format!("{name}.header"), header));

    // Trailing garbage. `tls_deserialize_exact` must refuse a message with bytes after it
    // rather than parse the prefix and ignore the rest, or two peers would disagree about
    // what they received while both believing they succeeded.
    let mut trailing = bytes.to_vec();
    trailing.extend_from_slice(&[0xff; 32]);
    out.push((format!("{name}.trailing"), trailing));

    // The same message twice end to end, which is the concatenation a framing bug makes.
    let mut doubled = bytes.to_vec();
    doubled.extend_from_slice(bytes);
    out.push((format!("{name}.doubled"), doubled));

    out
}

/// The degenerate inputs, which are not mutations of anything.
fn degenerate() -> Vec<(String, Vec<u8>)> {
    vec![
        ("empty".to_string(), Vec::new()),
        ("zero".to_string(), vec![0x00]),
        ("ones".to_string(), vec![0xff; 16]),
        (
            "text".to_string(),
            b"not a tls encoded message at all".to_vec(),
        ),
        // A plausible header followed by a length that claims far more than follows: the
        // classic allocation-from-untrusted-length shape.
        (
            "giant_length".to_string(),
            vec![0x00, 0x01, 0xff, 0xff, 0xff, 0xff],
        ),
        // Long enough to be worth an allocation and structured enough to get past a length
        // check, which is the input a naive parser reads past the end of.
        ("long_zeroes".to_string(), vec![0x00; 4096]),
    ]
}

fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut all = degenerate();
    for (name, bytes) in real_messages() {
        all.extend(mutations(&name, &bytes));
        all.push((name, bytes));
    }
    all
}

#[test]
fn the_seed_corpus_is_written_when_asked_and_carried_forward_otherwise() {
    if std::env::var("WEALD_MLS_WRITE_CORPUS").as_deref() != Ok("1") {
        // Not regenerating. The corpus still has to be there: a fuzz gate whose corpus
        // directory went missing would run and report nothing wrong.
        let directory = corpus_directory();
        let count = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("no corpus at {}: {error}", directory.display()))
            .count();
        assert!(
            count >= 40,
            "the checked-in corpus has {count} files, which is fewer than the seeds this \
             file generates. Something removed the corpus that the spec requires to be \
             carried forward."
        );
        return;
    }

    let directory = corpus_directory();
    std::fs::create_dir_all(&directory).expect("the corpus directory");
    for (name, bytes) in seeds() {
        std::fs::write(directory.join(&name), &bytes).expect("a seed");
    }
}

#[test]
fn every_corpus_file_is_answered_with_a_typed_status_rather_than_a_panic() {
    let directory = corpus_directory();
    let entries = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("no corpus at {}: {error}", directory.display()));

    let ada_device = device("ada");
    let mut ada = ada_device
        .create_group(b"weald-replay-group")
        .expect("a group");

    let mut replayed = 0_usize;
    for entry in entries {
        let path = entry.expect("a corpus entry").path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).expect("a corpus file");
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .to_string();

        // The property, and it is the whole property: an answer, of a kind the caller can
        // switch over. Not a panic, not an abort, not an unwind into Swift.
        match ada.process(&bytes) {
            Ok(Processed::Application { .. } | Processed::Commit { .. } | Processed::Proposal) => {}
            Err(error) => {
                assert!(
                    matches!(
                        error.status(),
                        Status::Malformed
                            | Status::Protocol
                            | Status::InvalidArgument
                            | Status::Storage
                    ),
                    "{name} was answered with {:?}, which is not an answer process is \
                     allowed to give",
                    error.status()
                );
            }
        }

        // The group survived it. A corpus entry that left the session unusable would be a
        // denial of service reachable by anybody who can put bytes on the relay.
        assert_eq!(ada.epoch(), 0, "{name} moved the epoch");
        assert!(
            ada.encrypt(b"still working").is_ok(),
            "{name} left the group unusable"
        );
        replayed += 1;
    }

    assert!(
        replayed >= 40,
        "only {replayed} corpus files were replayed, so the corpus is not what it should be"
    );
}
