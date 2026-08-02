// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Membership churn: the property the Phase 3 gate is actually about.
//!
//! `specs/backend/relay/mls-binding.md`, "Testing": "Random interleavings of add, remove,
//! update and concurrent application messages, asserting that every remaining member
//! converges to the same document state, and that every removed member fails to decrypt
//! everything after the removing epoch. Ten thousand cases in CI, a longer soak nightly."
//! `specs/backend/build/phases-relay.md` step 7 repeats it as a gate item, so this file is
//! the thing that either passes or blocks the step.
//!
//! What is modelled here is a relay and a set of devices, not a set of devices talking
//! directly. That distinction is the whole reason the suite is interesting. The relay in
//! `specs/backend/relay/wire.md` accepts one write at a time and hands out a single order,
//! and MLS accepts one commit per epoch, so two members who commit against the same epoch
//! produce one winner and one loser. The loser is not a hypothetical: it happens whenever
//! two people press a button at the same second, and a client that did not recover from it
//! would wedge. So the model runs that case on purpose and asserts the recovery, rather
//! than serialising the operations and quietly never reaching it.
//!
//! Three properties are asserted on every case.
//!
//! 1. Every remaining member holds the same epoch, the same `epoch_authenticator()` and
//!    the same `members()`. The authenticator is the value RFC 9420 defines for exactly
//!    this comparison, so two members that agree on it agree about the whole epoch's
//!    state and not just about a number that happens to match.
//! 2. Every remaining member's document is the same: the plaintexts it decrypted, in
//!    order, from the point it joined. The suffix matters. MLS hands a joiner no history,
//!    so a test that compared whole documents would be asserting something the protocol
//!    never promised and would fail on a correct implementation.
//! 3. Every removed member fails, with `Status::Protocol` and never with a panic, on
//!    every message the group produces after the epoch that removed it, and its own epoch
//!    never moves past that epoch again.
//!
//! Two honest consequences of real MLS are asserted rather than avoided.
//!
//! - An application message encrypted at epoch N and ordered by the relay after a commit
//!   that closed epoch N is readable by nobody. `join_config` in `src/session.rs` keeps
//!   OpenMLS's default of zero past epochs, which is the forward-secrecy setting we want,
//!   and the consequence is that a raced application message is lost and has to be
//!   resent. The property that matters is that it is lost *uniformly*: every member
//!   refuses it, so no two members end up disagreeing about whether it was ever said.
//! - The losing commit of a race is refused by anybody it reaches, again with
//!   `Status::Protocol`. If it were ever accepted, the group would fork.
//!
//! Case count comes from `WEALD_MLS_CASES` and defaults to a number a developer will
//! tolerate on every `cargo test`. The gate script sets it to 10000. A failing case is
//! written by proptest itself to `proptest-regressions/churn.txt`, which is a checked-in
//! file on purpose: `phases-relay.md` says failing seeds are pinned forever, and pinning
//! them means committing that file rather than reading a seed out of a CI log that will
//! be rotated away.
//!
//! Real OpenMLS against real SQLite, like everything else in this crate. There is no test
//! double anywhere here, by the spec's own rule.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use weald_mls::session::{Config, Device, Processed, Session};
use weald_mls::status::Status;

/// The group every case runs in.
const GROUP: &[u8] = b"weald-churn-group";

/// How many members a case may reach.
///
/// Five, and the number is a runtime decision rather than a modelling one. Every extra
/// member costs a SQLite database, a key generation and a delivery on every single
/// message, and the interesting interleavings (a race, an eviction, a message that
/// crosses an epoch boundary) all appear at three. Ten thousand cases has to finish, so
/// the size is spent where it buys new behaviour.
const MAX_MEMBERS: usize = 5;

/// How long a script may be. Same reasoning as ``MAX_MEMBERS``.
const MAX_OPERATIONS: usize = 10;

/// How many cases to run, from the environment.
///
/// The default is small so that `cargo test` stays a thing people run. The gate runs
/// `WEALD_MLS_CASES=10000`, which is the number in the spec.
fn cases() -> u32 {
    std::env::var("WEALD_MLS_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64)
}

/// Where a failing case is written down.
///
/// Named explicitly rather than left to proptest's default. The default walks up looking
/// for `lib.rs` or `main.rs` beside the test and, for an integration test in `tests/`,
/// gives up and drops the file next to the source as `tests/churn.proptest-regressions`.
/// A path under `proptest-regressions/` is the one people expect to see in a diff, and
/// `phases-relay.md` asks for failing seeds pinned forever, which means checked in.
/// The path is relative to the package root, which is where cargo runs a test binary.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "proptest-regressions/churn.txt",
        ))),
        ..ProptestConfig::default()
    }
}

/// One device, opened against its own in-memory database.
///
/// In-memory for the reason `store.rs` gives: ten thousand cases against a file would be
/// measuring the disk rather than the protocol. It is the same provider and the same SQL.
fn device(identity: &str) -> Device {
    Device::open(&Config {
        database: ":memory:".to_string(),
        identity: identity.as_bytes().to_vec(),
    })
    .expect("a device")
}

/// One member of the group, as the model tracks it.
struct Live {
    /// What it signs as, so a failure names a device rather than an index.
    name: String,
    session: Session,
    /// Where in the transcript this member's history begins. A joiner gets nothing that
    /// was said before its welcome, so convergence is only ever asserted from here on.
    joined_at: usize,
    /// The plaintexts this member holds: what it actually decrypted, plus what it wrote
    /// itself. Built from decrypted bytes rather than from the payload the model sent, or
    /// the comparison at the end of the case would be comparing the model with itself.
    document: Vec<Vec<u8>>,
}

/// One member that was removed, kept alive so it can go on being refused.
///
/// The session is retained deliberately. A removed device in the real product does not
/// vanish; it is a laptop that is still running, still holding a database, and still
/// receiving whatever the relay was willing to hand it. Everything this suite claims
/// about removal is claimed about that device, which is why it stays in the model.
struct Evicted {
    name: String,
    session: Session,
    /// The epoch the removing commit landed on. Its epoch must never exceed this again.
    frozen_at: u64,
}

/// The group, the relay's ordering, and everything the model asserts about them.
struct Churn {
    live: Vec<Live>,
    evicted: Vec<Evicted>,
    /// Every plaintext that was successfully said, in relay order. A message that no
    /// member could read never reaches this, because a message no member could read is
    /// not part of anybody's document.
    transcript: Vec<Vec<u8>>,
    /// How many devices have been minted, so identities stay distinct within a case.
    minted: usize,
}

impl Churn {
    /// A group of one, which is where every case starts.
    fn start() -> Self {
        let founder = device("device-0");
        let session = founder.create_group(GROUP).expect("a group");
        Self {
            live: vec![Live {
                name: "device-0".to_string(),
                session,
                joined_at: 0,
                document: Vec::new(),
            }],
            evicted: Vec::new(),
            transcript: Vec::new(),
            minted: 1,
        }
    }

    // MARK: Delivery

    /// One commit, from the member that produced it, to everybody else.
    ///
    /// The producer merges last and only here. That is the reserve-send-advance ordering
    /// `mls-binding.md` requires of this seam: a member that merged before the relay
    /// accepted the write would be an epoch ahead of a group that never saw the commit,
    /// unable to read what the group is still sending and unable to say why.
    fn hand_out(&mut self, producer: usize, commit: &[u8]) {
        for index in 0..self.live.len() {
            if index == producer {
                continue;
            }
            let processed = self.live[index]
                .session
                .process(commit)
                .unwrap_or_else(|error| {
                    panic!("{} refused a group commit: {error}", self.live[index].name)
                });
            assert!(
                matches!(processed, Processed::Commit { .. }),
                "{} read a commit as something other than a commit",
                self.live[index].name
            );
        }
        self.live[producer]
            .session
            .merge_pending()
            .expect("merged once the relay accepted the write");
        self.shut_out_the_evicted(commit);
    }

    /// A commit, delivered, with the group asserted to agree afterwards.
    fn deliver_commit(&mut self, producer: usize, commit: &[u8]) {
        self.hand_out(producer, commit);
        self.assert_the_group_agrees();
    }

    /// Every removed device is handed the same bytes the group got, and must refuse them.
    ///
    /// This is property three, applied to every single message rather than once at the
    /// end. A removed device that could read one message in the middle of a long script
    /// and none of the others would pass an end-of-case check and would still be a total
    /// failure of the product's central claim.
    fn shut_out_the_evicted(&mut self, message: &[u8]) {
        for gone in &mut self.evicted {
            let refused = gone.session.process(message).err().unwrap_or_else(|| {
                panic!("{} read a message sent after it was removed", gone.name)
            });
            assert_eq!(
                refused.status(),
                Status::Protocol,
                "{} was refused for the wrong reason: {refused}",
                gone.name
            );
            assert_eq!(
                gone.session.epoch(),
                gone.frozen_at,
                "{} moved past the epoch that removed it",
                gone.name
            );
        }
    }

    // MARK: Operations

    /// Somebody invites a new device, which joins by welcome.
    fn add(&mut self, committer: usize) {
        let name = format!("device-{}", self.minted);
        self.minted += 1;
        let joiner = device(&name);
        let key_package = joiner.key_package().expect("a key package");
        let (commit, welcome) = self.live[committer]
            .session
            .add(&key_package)
            .expect("an add");
        self.deliver_commit(committer, &commit);

        let session = joiner.join_welcome(&welcome).expect("joined by welcome");
        // The joiner arrives already in the epoch the commit created, and agreeing with
        // the group about it. If it did not, the welcome and the commit would describe
        // two different groups and the divergence would only surface on the next message.
        assert_eq!(session.epoch(), self.live[committer].session.epoch());
        assert_eq!(
            session.epoch_authenticator(),
            self.live[committer].session.epoch_authenticator()
        );
        let joined_at = self.transcript.len();
        self.live.push(Live {
            name,
            session,
            joined_at,
            document: Vec::new(),
        });
        self.assert_the_group_agrees();
    }

    /// Somebody removes somebody else.
    ///
    /// The victim is handed the removing commit along with everybody else, because that is
    /// how a real device learns it is gone: nobody sends it a private notice.
    fn remove(&mut self, committer: usize, victim: usize) {
        let leaf = self.live[victim].session.own_leaf();
        let commit = self.live[committer]
            .session
            .remove(&[leaf])
            .expect("a removal");
        self.hand_out(committer, &commit);

        let gone = self.live.remove(victim);
        let frozen_at = gone.session.epoch();
        self.evicted.push(Evicted {
            name: gone.name,
            session: gone.session,
            frozen_at,
        });
        // The leaf is gone from the roster every remaining member holds, right now.
        // Asserted about the specific leaf rather than about the size of the roster,
        // because a removal that evicted the wrong member would keep the count right.
        //
        // Only right now, though. A leaf index is a position in the ratchet tree and MLS
        // reuses a blanked position for the next member who joins, so this same index
        // legitimately reappears in the roster later wearing somebody else's credential.
        // The lasting claim about a removed device is that it cannot read, which is what
        // `shut_out_the_evicted` asserts on every message from here to the end of the
        // case, and not that its old seat stays empty.
        for member in &self.live {
            assert!(
                !member.session.members().contains(&leaf),
                "{} still lists the leaf that was removed",
                member.name
            );
        }
        self.assert_the_group_agrees();
    }

    /// Somebody commits nothing, which is a self-update: a new epoch and fresh key
    /// material with no membership change.
    fn update(&mut self, committer: usize) {
        let commit = self.live[committer]
            .session
            .commit_pending()
            .expect("an empty commit");
        self.deliver_commit(committer, &commit);
    }

    /// Somebody sends an application message and everybody reads it.
    fn say(&mut self, sender: usize, payload: &[u8]) {
        let leaf = self.live[sender].session.own_leaf();
        let ciphertext = self.live[sender]
            .session
            .encrypt(payload)
            .expect("ciphertext");
        for index in 0..self.live.len() {
            if index == sender {
                continue;
            }
            let (plaintext, from) = self.live[index]
                .session
                .decrypt(&ciphertext)
                .unwrap_or_else(|error| {
                    panic!(
                        "{} could not read a message: {error}",
                        self.live[index].name
                    )
                });
            // The sender's leaf, not just the bytes. A binding that returned the right
            // plaintext under the wrong sender would let the layer above attribute a
            // message to the wrong person, which is a security bug wearing a UI bug's
            // clothes.
            assert_eq!(
                from, leaf,
                "{} attributed a message to the wrong leaf",
                self.live[index].name
            );
            self.live[index].document.push(plaintext);
        }
        // The author holds what it wrote. It cannot decrypt its own ciphertext (that is
        // asserted in `tests/session.rs`) and does not need to.
        self.live[sender].document.push(payload.to_vec());
        self.shut_out_the_evicted(&ciphertext);
        self.transcript.push(payload.to_vec());
    }

    /// Somebody speaks at the same moment somebody else commits, and the relay orders the
    /// commit first.
    ///
    /// The concurrent application message across an epoch boundary. With zero past epochs
    /// kept, which is the forward-secrecy setting `session.rs` chose, the message is
    /// readable by nobody once the epoch has closed. That is the correct outcome and the
    /// client above resends. What is asserted is that the loss is uniform and typed: every
    /// member refuses it, with `Protocol` rather than with a panic or a wrong plaintext,
    /// so no two members can disagree about whether the message was ever said.
    fn say_across_the_boundary(&mut self, sender: usize, committer: usize, payload: &[u8]) {
        let stale = self.live[sender]
            .session
            .encrypt(payload)
            .expect("ciphertext");
        let commit = self.live[committer]
            .session
            .commit_pending()
            .expect("an empty commit");
        self.deliver_commit(committer, &commit);

        for index in 0..self.live.len() {
            if index == sender {
                continue;
            }
            let refused = self.live[index]
                .session
                .decrypt(&stale)
                .expect_err("a message from an epoch that has closed");
            assert_eq!(
                refused.status(),
                Status::Protocol,
                "{} refused a stale message for the wrong reason: {refused}",
                self.live[index].name
            );
        }
        self.shut_out_the_evicted(&stale);
        // Nothing enters the transcript. A message nobody could read is not part of the
        // group's document state, and the client that sent it has to send it again.
        self.assert_the_group_agrees();
    }

    /// Two members commit against the same epoch. One wins, and the loser has to recover.
    ///
    /// The relay accepts one write per epoch (`wire.md`) and MLS accepts one commit per
    /// epoch, so this is not an exotic case: it is what happens when two people act at
    /// the same second. The loser never merges its own commit. It recovers by processing
    /// the winner's, which is what `merge_staged_commit` clearing a pending commit is
    /// for, and it must land in exactly the same place as everybody else.
    fn race(&mut self, winner: usize, loser: usize) {
        let epoch = self.live[winner].session.epoch();
        let winning = self.live[winner]
            .session
            .commit_pending()
            .expect("a commit from the winner");
        let losing = self.live[loser]
            .session
            .commit_pending()
            .expect("a commit from the loser");

        self.deliver_commit(winner, &winning);
        assert_eq!(
            self.live[loser].session.epoch(),
            epoch + 1,
            "{} did not recover from losing a commit race",
            self.live[loser].name
        );

        // And if the losing commit reaches anybody anyway, it is refused. This is the
        // assertion that stands between a lost race and a forked group: two accepted
        // commits on one epoch is exactly what a fork is.
        let refused = self.live[winner]
            .session
            .process(&losing)
            .expect_err("a commit for an epoch that has closed");
        assert_eq!(refused.status(), Status::Protocol);
        self.shut_out_the_evicted(&losing);
        self.assert_the_group_agrees();
    }

    // MARK: Properties

    /// Property one: everybody still in the group holds the same group.
    fn assert_the_group_agrees(&self) {
        let Some((first, rest)) = self.live.split_first() else {
            return;
        };
        let epoch = first.session.epoch();
        let authenticator = first.session.epoch_authenticator();
        let roster = first.session.members();
        for member in rest {
            assert_eq!(
                member.session.epoch(),
                epoch,
                "{} is at a different epoch from {}",
                member.name,
                first.name
            );
            assert_eq!(
                member.session.epoch_authenticator(),
                authenticator,
                "{} and {} are at epoch {epoch} and do not agree about it",
                member.name,
                first.name
            );
            assert_eq!(
                member.session.members(),
                roster,
                "{} and {} disagree about who is in the group",
                member.name,
                first.name
            );
        }
    }

    /// Property two: everybody still in the group holds the same document, from the point
    /// they joined.
    fn assert_the_documents_agree(&self) {
        for member in &self.live {
            let expected = &self.transcript[member.joined_at..];
            assert_eq!(
                member.document.len(),
                expected.len(),
                "{} holds {} messages where the group said {}",
                member.name,
                member.document.len(),
                expected.len()
            );
            assert_eq!(
                member.document, expected,
                "{}'s document is not the group's",
                member.name
            );
        }
    }

    /// Property three, once more at the end of the case, against a message minted after
    /// the script finished.
    ///
    /// The per-message check in ``shut_out_the_evicted`` already covers everything the
    /// script produced. This covers the case where the last operation was a removal and
    /// nothing was said afterwards, so the removed device was never actually asked.
    fn assert_the_removed_are_still_out(&mut self) {
        if self.evicted.is_empty() || self.live.is_empty() {
            return;
        }
        let farewell = self.live[0]
            .session
            .encrypt(b"after everything")
            .expect("ciphertext");
        self.shut_out_the_evicted(&farewell);
        // The farewell was read by nobody but the model, so it is deliberately not
        // recorded in any document: the remaining members were never handed it.
    }
}

/// One operation in a script.
///
/// Indices are generated freely and resolved against the live membership when the
/// operation runs, because proptest cannot know how many members exist at that point in
/// the script and a strategy that tried to track it would be a second implementation of
/// the model.
#[derive(Debug, Clone)]
enum Operation {
    Add { committer: usize },
    Remove { committer: usize, victim: usize },
    Update { committer: usize },
    Say { sender: usize, payload: Vec<u8> },
    Race { winner: usize, loser: usize },
    SayAcrossTheBoundary { sender: usize, committer: usize },
}

/// The distribution over operations.
///
/// Weighted towards saying things and adding people, because those are what a real
/// workspace does most of, and a distribution that spent half its cases on removals would
/// be testing a group that never gets large enough to be interesting.
fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        3 => (0usize..16).prop_map(|committer| Operation::Add { committer }),
        2 => (0usize..16, 0usize..16)
            .prop_map(|(committer, victim)| Operation::Remove { committer, victim }),
        2 => (0usize..16).prop_map(|committer| Operation::Update { committer }),
        4 => (0usize..16, prop::collection::vec(any::<u8>(), 1..24))
            .prop_map(|(sender, payload)| Operation::Say { sender, payload }),
        2 => (0usize..16, 0usize..16).prop_map(|(winner, loser)| Operation::Race { winner, loser }),
        2 => (0usize..16, 0usize..16)
            .prop_map(|(sender, committer)| Operation::SayAcrossTheBoundary { sender, committer }),
    ]
}

/// A second index, distinct from the first, over a group of `size` members.
fn another(first: usize, offset: usize, size: usize) -> usize {
    (first + 1 + offset % (size - 1)) % size
}

/// Run one script against one group.
///
/// Operations that cannot happen at this size are turned into a self-update rather than
/// skipped. Skipping would silently shorten the script and make the case count mean less
/// than it says; a self-update is a real operation that is always legal.
fn run(script: &[Operation]) {
    let mut churn = Churn::start();
    for operation in script {
        let size = churn.live.len();
        match operation.clone() {
            Operation::Add { committer } if size < MAX_MEMBERS => churn.add(committer % size),
            Operation::Remove { committer, victim } if size > 1 => {
                let committer = committer % size;
                churn.remove(committer, another(committer, victim, size));
            }
            Operation::Say { sender, payload } => churn.say(sender % size, &payload),
            Operation::Race { winner, loser } if size > 1 => {
                let winner = winner % size;
                churn.race(winner, another(winner, loser, size));
            }
            Operation::SayAcrossTheBoundary { sender, committer } if size > 1 => {
                let sender = sender % size;
                churn.say_across_the_boundary(sender, committer % size, b"raced with a commit");
            }
            Operation::Update { committer } => churn.update(committer % size),
            Operation::Add { committer }
            | Operation::Remove { committer, .. }
            | Operation::Race {
                winner: committer, ..
            }
            | Operation::SayAcrossTheBoundary {
                sender: committer, ..
            } => churn.update(committer % size),
        }
    }
    churn.assert_the_group_agrees();
    churn.assert_the_documents_agree();
    churn.assert_the_removed_are_still_out();
}

proptest! {
    #![proptest_config(config())]

    /// The gate's property, in one case at a time.
    #[test]
    fn any_interleaving_of_churn_leaves_one_group_that_agrees_and_no_reader_who_should_not_be(
        script in prop::collection::vec(operation(), 1..=MAX_OPERATIONS)
    ) {
        run(&script);
    }
}

/// The interleavings the random suite is allowed to miss, pinned so they are always run.
///
/// A property suite with a case count is a statement about the average script, not about
/// any particular one. These three are the ones the design turns on, so they are also
/// asserted directly: a change that made them unreachable from the strategy would still
/// be caught here rather than showing up as a quietly weaker suite.
#[test]
fn the_three_interleavings_the_design_turns_on_are_run_every_time() {
    run(&[
        Operation::Add { committer: 0 },
        Operation::Add { committer: 0 },
        Operation::Say {
            sender: 1,
            payload: b"before anything happened".to_vec(),
        },
        // Two members commit against one epoch.
        Operation::Race {
            winner: 0,
            loser: 1,
        },
        // A message that crosses the epoch boundary the wrong way.
        Operation::SayAcrossTheBoundary {
            sender: 2,
            committer: 0,
        },
        // And an eviction, with the group going on talking afterwards.
        Operation::Remove {
            committer: 0,
            victim: 1,
        },
        Operation::Say {
            sender: 0,
            payload: b"after the removal".to_vec(),
        },
    ]);
}
