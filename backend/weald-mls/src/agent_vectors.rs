// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The shared vector corpus, run by the Rust codec.
//!
//! # What this module is
//!
//! Nothing but tests. `agent_corpus` loads the corpus and `agent_card` decodes a
//! card; this is the file where the two meet, and it is the only place the
//! cross-language claim is actually made. Without it, `agent_corpus` proves a loader
//! and `agent_card` proves a codec against cards it built itself, and the corpus sits
//! on disk being read by one language.
//!
//! The Swift half is `Tests/AgentGoldenVectorsTests.swift` and
//! `Tests/AgentAdversarialTests.swift`, over the same files, asserting the same
//! reason codes. `scripts/agents-gate.sh` runs both in the same gate part, because
//! either one passing alone is the thing this programme is trying not to do.
//!
//! # Why the reason code is asserted and not just the refusal
//!
//! A corpus that checked accept-or-reject would call it agreement when Swift refused
//! a card for an out-of-order key and Rust refused the same bytes for a bad length.
//! Both refused; neither read the card the same way; the next payload built on that
//! shared understanding would diverge silently. So every `reject` row names a code
//! and both codecs must produce that code.
//!
//! # The corpus is generated, and this asserts nothing about that
//!
//! `scripts/agents-vectors.py --check` is what proves the checked-in bytes are the
//! bytes the generator produces. It is a gate part of its own rather than a test
//! here, because it needs Python and a working tree, and a Rust test that shelled
//! out to it would fail in the published mirror, where neither the corpus nor the
//! script exists.

#[cfg(test)]
mod tests {
    use crate::agent_card::{self, CardError};
    use crate::agent_corpus::{self, Corpus, Expectation, Stage, Vector};
    use crate::agent_invoke::{self, AdmissionContext, InvokeError, PROTOCOL_VERSION};
    use crate::agent_lifecycle;

    /// The one context every `admit`-stage invoke vector is evaluated in.
    ///
    /// Stated in `scripts/agents-vectors.py` beside the bytes and in
    /// `specs/agents/networked/testing.md`, and asserted identically by the Swift
    /// half. An `admit` vector is only meaningful next to its context: a
    /// cross-workspace `scope` with no stated carrying group would be a refusal
    /// nobody could reproduce, and a passed deadline with no stated clock would be a
    /// number.
    fn admission_context() -> AdmissionContext {
        AdmissionContext {
            envelope_group: vec![0x5c; 32],
            now: 1_800_000_000,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    /// Whether this checkout is a tree the corpus does not travel to.
    ///
    /// The vectors live under `Tests/`, beside the client's own suite, and the
    /// published mirror carries neither: `agent_corpus::check_tree` states that as
    /// a rule and proves it from both sides. This module is published anyway,
    /// because it is `weald-mls` source and `lib.rs` declares it, so without this
    /// guard a stranger who clones the tag and runs the tests, which is the exact
    /// thing the published repository exists for, gets eleven failures about a
    /// directory that is deliberately absent.
    ///
    /// A skip that says so on stderr rather than a silent pass. What is being
    /// skipped is a codec proof over bytes a second implementation cannot see, and
    /// a run that quietly reported eleven more green tests than it performed would
    /// be the same lie in the other direction.
    fn corpus_absent() -> bool {
        let root = agent_corpus::repository_root();
        let absent = agent_corpus::tree_kind(&root) == agent_corpus::TreeKind::PublishedMirror;
        if absent {
            eprintln!(
                "skipped: the agent vector corpus lives at Tests/Fixtures/agents in the \
                 monorepo and is not published; the codecs it exercises carry their own tests"
            );
        }
        absent
    }

    fn golden() -> Corpus {
        agent_corpus::load(&agent_corpus::golden_root()).expect("the golden corpus loads")
    }

    fn adversarial() -> Corpus {
        agent_corpus::load(&agent_corpus::adversarial_root()).expect("the adversarial corpus loads")
    }

    /// One vector, against the rule its manifest row states.
    ///
    /// Accept means: decodes, verifies, and re-encodes to the same bytes. The
    /// re-encode is what makes this a codec proof rather than a decoder proof. A
    /// decoder that dropped a field would pass a decode assertion and fail here, and
    /// so would an encoder whose canonical form differs from the generator's by one
    /// head byte.
    /// One vector, dispatched on the kind its manifest row names.
    ///
    /// A kind this file does not know is a panic and not a skip. That direction
    /// matters: a vector for a payload nobody wired up yet would otherwise report the
    /// same green as before while proving nothing, which is the exact failure the
    /// orphan check in `agent_corpus` exists to prevent one level down.
    fn run(vector: &Vector) {
        match vector.kind.as_str() {
            "agent.card" => run_card(vector),
            "agent.invoke" => run_invoke(vector),
            "agent.lifecycle" => run_lifecycle(vector),
            "agent.lease" => run_lease(vector),
            other => panic!(
                "{} names kind '{other}', which no codec in this crate claims",
                vector.name
            ),
        }
    }

    /// An `agent.invoke`, at the layer its `stage` names.
    ///
    /// `decode` means the bytes are refused by the codec, with a `codec.` reason.
    /// `admit` means the bytes **must decode and verify** and then be refused by
    /// admission, with a lifecycle reason. Conflating the two is what this split
    /// prevents: an implementation that failed an expired invoke at decode would pass
    /// a corpus that only asked "was it refused", while being unable to tell "these
    /// bytes are not an invoke" from "this invoke arrived too late".
    fn run_invoke(vector: &Vector) {
        let context = admission_context();
        match (&vector.expectation, vector.stage) {
            (Expectation::Accept, _) => {
                let invoke = agent_invoke::decode_verified(&vector.bytes).unwrap_or_else(|e| {
                    panic!("{} must decode, and was refused: {e}", vector.name)
                });
                assert_eq!(
                    agent_invoke::encode(&invoke),
                    vector.bytes,
                    "{} does not re-encode to its own bytes",
                    vector.name
                );
                assert_eq!(
                    agent_invoke::admission_refusal(&invoke, &context),
                    None,
                    "{} is an accepted vector and admission refused it",
                    vector.name
                );
            }
            (Expectation::Reject(reason), Stage::Decode) => {
                match agent_invoke::decode_verified(&vector.bytes) {
                    Ok(invoke) => panic!(
                        "{} decoded and must be refused with {reason}. Got invocation {:02x?}",
                        vector.name,
                        &invoke.invocation_id[..4]
                    ),
                    Err(error) => assert_eq!(
                        error.reason(),
                        reason.as_str(),
                        "{} was refused as {} and the corpus requires {reason}: {error}",
                        vector.name,
                        error.reason()
                    ),
                }
            }
            (Expectation::Reject(reason), Stage::Admit) => {
                let invoke = agent_invoke::decode_verified(&vector.bytes).unwrap_or_else(|e| {
                    panic!(
                        "{} is an admit-stage vector, so it must decode and verify: {e}",
                        vector.name
                    )
                });
                assert_eq!(
                    agent_invoke::admission_refusal(&invoke, &context),
                    Some(reason.as_str()),
                    "{} must be refused by admission as {reason}",
                    vector.name
                );
            }
        }
    }

    /// An `agent.lifecycle` record. `decode`-stage only, and that is a claim: the
    /// interesting refusals (a terminal from a host that never accepted, a second
    /// `accepted`) are statements about a set and belong to the fold, which is the Swift
    /// side's because its proof is two app instances rather than two codecs.
    fn run_lifecycle(vector: &Vector) {
        match &vector.expectation {
            Expectation::Accept => {
                let record = agent_lifecycle::decode_verified(&vector.bytes).unwrap_or_else(|e| {
                    panic!("{} must decode, and was refused: {e}", vector.name)
                });
                assert_eq!(
                    agent_lifecycle::encode(&record),
                    vector.bytes,
                    "{} does not re-encode to its own bytes",
                    vector.name
                );
            }
            Expectation::Reject(reason) => match agent_lifecycle::decode_verified(&vector.bytes) {
                Ok(record) => panic!(
                    "{} decoded as {} and must be refused with {reason}",
                    vector.name, record.state
                ),
                Err(error) => assert_eq!(
                    error.reason(),
                    reason.as_str(),
                    "{} was refused as {} and the corpus requires {reason}: {error}",
                    vector.name,
                    error.reason()
                ),
            },
        }
    }

    fn run_lease(vector: &Vector) {
        match &vector.expectation {
            Expectation::Accept => {
                let lease =
                    agent_lifecycle::lease_decode_verified(&vector.bytes).unwrap_or_else(|e| {
                        panic!("{} must decode, and was refused: {e}", vector.name)
                    });
                assert_eq!(
                    agent_lifecycle::lease_encode(&lease),
                    vector.bytes,
                    "{} does not re-encode to its own bytes",
                    vector.name
                );
            }
            Expectation::Reject(reason) => {
                match agent_lifecycle::lease_decode_verified(&vector.bytes) {
                    Ok(lease) => panic!(
                        "{} decoded at epoch {} and must be refused with {reason}",
                        vector.name, lease.epoch
                    ),
                    Err(error) => assert_eq!(
                        error.reason(),
                        reason.as_str(),
                        "{} was refused as {} and the corpus requires {reason}: {error}",
                        vector.name,
                        error.reason()
                    ),
                }
            }
        }
    }

    fn run_card(vector: &Vector) {
        match &vector.expectation {
            Expectation::Accept => {
                let card = agent_card::decode_verified(&vector.bytes).unwrap_or_else(|e| {
                    panic!("{} must decode, and was refused: {e}", vector.name)
                });
                assert_eq!(
                    agent_card::encode(&card),
                    vector.bytes,
                    "{} does not re-encode to its own bytes",
                    vector.name
                );
            }
            Expectation::Reject(reason) => match agent_card::decode_verified(&vector.bytes) {
                Ok(card) => panic!(
                    "{} decoded and must be refused with {reason}. Got agent {:02x?}",
                    vector.name,
                    &card.agent_id[..4]
                ),
                Err(error) => assert_eq!(
                    error.reason(),
                    reason.as_str(),
                    "{} was refused as {} and the corpus requires {reason}: {error}",
                    vector.name,
                    error.reason()
                ),
            },
        }
    }

    #[test]
    fn the_golden_corpus_is_populated() {
        if corpus_absent() {
            return;
        }
        let corpus = golden();
        assert!(!corpus.is_empty());
        // The kinds this crate claims. An assertion rather than a filter, so a kind
        // added to the corpus without a codec here fails loudly instead of being
        // quietly excluded from every run.
        let claimed = [
            "agent.card",
            "agent.invoke",
            "agent.lifecycle",
            "agent.lease",
        ];
        assert!(corpus
            .vectors
            .iter()
            .all(|v| claimed.contains(&v.kind.as_str())));
        for kind in claimed {
            assert!(
                corpus.vectors.iter().any(|v| v.kind == kind),
                "the golden corpus has no {kind} vector"
            );
        }
    }

    /// The forged invoke decodes structurally and fails only on its signature, and it
    /// really claims player 1 as its requester.
    ///
    /// This is the invoke half of the claim the card's forgery test makes, and it is
    /// the one the whole invocation story rests on: without it, anybody who can write
    /// to the workspace can ask an agent to work in somebody else's name.
    #[test]
    fn the_forged_invoke_is_structurally_valid_and_fails_only_verification() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        let forged = corpus
            .vector("invoke.forged.requester")
            .expect("invoke.forged.requester");
        let genuine = corpus
            .vector("invoke.forged.target")
            .expect("invoke.forged.target");

        let structural = agent_invoke::decode(&forged.bytes).expect("structurally valid");
        assert_eq!(
            agent_invoke::decode_verified(&forged.bytes).unwrap_err(),
            InvokeError::SignatureInvalid
        );

        let real = agent_invoke::decode_verified(&genuine.bytes).expect("the genuine invoke");
        assert_eq!(structural.requester, real.requester);
        assert_eq!(structural.invocation_id, real.invocation_id);
        assert_ne!(structural.sig, real.sig);
    }

    /// The three admit-stage invokes are valid bytes, and that is the claim.
    ///
    /// Asserted separately from `run_invoke` because the interesting half is the
    /// positive one: each of these decodes and verifies cleanly. A codec that refused
    /// any of them would be a codec that had taken over admission's job, and the
    /// product would lose the ability to tell a person their request arrived too late.
    #[test]
    fn every_admit_stage_invoke_decodes_and_verifies() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        let admit: Vec<&Vector> = corpus
            .vectors
            .iter()
            .filter(|v| v.kind == "agent.invoke" && v.stage == Stage::Admit)
            .collect();
        assert_eq!(admit.len(), 3, "the three cases step 2's gate names");
        for vector in admit {
            agent_invoke::decode_verified(&vector.bytes)
                .unwrap_or_else(|e| panic!("{} must be valid invoke bytes: {e}", vector.name));
        }
    }

    /// The one context, and the boundary either side of it.
    ///
    /// `invoke.deadline.withinskew` is one second inside the five minute bound and
    /// accepted; `invoke.deadline.passed` is one second outside it and refused. The
    /// pair is what makes the refusal a boundary test rather than an assertion that a
    /// small number is smaller than a large one.
    #[test]
    fn the_skew_boundary_is_proven_from_both_sides() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        let context = admission_context();
        let inside = agent_invoke::decode_verified(
            &corpus
                .vector("invoke.deadline.withinskew")
                .expect("withinskew")
                .bytes,
        )
        .expect("inside");
        let outside = agent_invoke::decode_verified(
            &corpus
                .vector("invoke.deadline.passed")
                .expect("passed")
                .bytes,
        )
        .expect("outside");

        assert_eq!(outside.deadline + 1, inside.deadline);
        assert_eq!(agent_invoke::admission_refusal(&inside, &context), None);
        assert_eq!(
            agent_invoke::admission_refusal(&outside, &context),
            Some("deadline.passed")
        );
    }

    #[test]
    fn every_golden_vector_behaves_as_the_corpus_states() {
        if corpus_absent() {
            return;
        }
        for vector in &golden().vectors {
            run(vector);
        }
    }

    #[test]
    fn every_adversarial_vector_behaves_as_the_corpus_states() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        assert!(!corpus.is_empty());
        for vector in &corpus.vectors {
            run(vector);
        }
    }

    /// This language's verdict on every vector, as a line per vector.
    ///
    /// Step 4's gate asks for the corpus run through both implementations with the
    /// reason codes compared **pairwise**, and that comparison cannot be made from two
    /// suites that each assert against the manifest and print nothing. Both would go
    /// green while disagreeing about a vector the manifest happens to describe loosely,
    /// and "zero divergence" would be an inference rather than a measurement.
    ///
    /// So each language writes what it actually produced, and
    /// `scripts/agents-verdicts.py` joins the two files on the vector name. The row is
    /// the verdict, not the expectation: writing the manifest back out would make the
    /// two files agree by construction and prove nothing.
    ///
    /// Not gated on an environment variable. A file that appears only when somebody
    /// remembers to ask for it is a file the gate will one day compare from a previous
    /// run, and stale evidence is worse than none.
    #[test]
    fn verdicts_are_recorded_for_every_vector() {
        use std::fmt::Write as _;

        let mut rows = String::new();
        let mut count = 0usize;
        if corpus_absent() {
            return;
        }
        for (corpus, tree) in [(golden(), "golden"), (adversarial(), "adversarial")] {
            for vector in &corpus.vectors {
                writeln!(
                    rows,
                    "{}\t{}\t{}\t{}",
                    tree,
                    vector.name,
                    vector.kind,
                    verdict(vector)
                )
                .expect("a String never fails to write");
                count += 1;
            }
        }
        assert!(count > 0, "no vectors, so nothing was compared");

        let path = agent_corpus::repository_root().join("build/agent-verdicts-rust.tsv");
        std::fs::create_dir_all(path.parent().expect("build/")).expect("the build directory");
        std::fs::write(&path, rows).expect("the verdict ledger is writable");
    }

    /// What this crate's codecs actually do with one vector's bytes.
    ///
    /// Deliberately non-panicking and deliberately not consulting the expectation. It
    /// is the measurement the pairwise comparison joins on, and a measurement that
    /// read the answer first would be a copy of the answer.
    ///
    /// The invoke `admit:` prefix is not cosmetic. A refusal by admission and a refusal
    /// by the codec are different layers reaching different conclusions about the same
    /// bytes, and a comparison that flattened them would call it agreement when one
    /// language refused an expired invoke at decode and the other admitted it and
    /// declined it, which is exactly the confusion `Stage` exists to prevent.
    fn verdict(vector: &Vector) -> String {
        match vector.kind.as_str() {
            "agent.card" => match agent_card::decode_verified(&vector.bytes) {
                Ok(_) => "accept".to_string(),
                Err(e) => format!("reject:{}", e.reason()),
            },
            "agent.lifecycle" => match agent_lifecycle::decode_verified(&vector.bytes) {
                Ok(_) => "accept".to_string(),
                Err(e) => format!("reject:{}", e.reason()),
            },
            "agent.lease" => match agent_lifecycle::lease_decode_verified(&vector.bytes) {
                Ok(_) => "accept".to_string(),
                Err(e) => format!("reject:{}", e.reason()),
            },
            "agent.invoke" => match agent_invoke::decode_verified(&vector.bytes) {
                Err(e) => format!("reject:{}", e.reason()),
                Ok(invoke) => {
                    match agent_invoke::admission_refusal(&invoke, &admission_context()) {
                        Some(reason) => format!("admit:{reason}"),
                        None => "accept".to_string(),
                    }
                }
            },
            other => format!("unknown-kind:{other}"),
        }
    }

    /// The forged card decodes structurally and fails only on its signature. If it
    /// were refused for any other reason the forgery would be untested, because the
    /// vector would be proving that other rule.
    #[test]
    fn the_forged_card_is_structurally_valid_and_fails_only_verification() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        let forged = corpus
            .vector("card.forged.owner")
            .expect("card.forged.owner");
        let genuine = corpus
            .vector("card.forged.target")
            .expect("card.forged.target");

        let structural = agent_card::decode(&forged.bytes).expect("structurally valid");
        assert_eq!(
            agent_card::decode_verified(&forged.bytes).unwrap_err(),
            CardError::SignatureInvalid
        );

        // It really claims the genuine owner: same principal, same agent, different
        // signature. Without this the vector could be a stranger's own valid card
        // that happened not to verify.
        let real = agent_card::decode_verified(&genuine.bytes).expect("the genuine card");
        assert_eq!(structural.owner_principal, real.owner_principal);
        assert_eq!(structural.agent_id, real.agent_id);
        assert_ne!(structural.sig, real.sig);
    }

    /// A stranger's same-slug card is valid and not confusable with player 1's.
    ///
    /// The refusal cannot live in a codec: the stranger signed their own card and
    /// every rule holds. What is provable here, and what step 14's resolution rests
    /// on, is that the two differ in everything authority is keyed on.
    #[test]
    fn a_strangers_same_slug_card_is_valid_and_distinct() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        let mine = agent_card::decode_verified(
            &corpus.vector("card.forged.target").expect("target").bytes,
        )
        .expect("mine");
        let theirs = agent_card::decode_verified(
            &corpus
                .vector("card.stranger.sameslug")
                .expect("sameslug")
                .bytes,
        )
        .expect("theirs");

        // The collision is real, which is what makes the case a case.
        assert_eq!(mine.aliases, theirs.aliases);
        assert_eq!(mine.display_name, theirs.display_name);
        // And nothing authority rests on is shared.
        assert_ne!(mine.agent_id, theirs.agent_id);
        assert_ne!(mine.owner_principal, theirs.owner_principal);
        assert_ne!(agent_card::card_hash(&mine), agent_card::card_hash(&theirs));

        // Swapping the owner does not make one card the other's.
        let mut swapped = theirs.clone();
        swapped.owner_principal = mine.owner_principal.clone();
        assert_eq!(
            agent_card::verify(&swapped).unwrap_err(),
            CardError::SignatureInvalid
        );
    }

    /// The smuggled prompt really is in the bytes and really is refused. Asserting
    /// the payload is present is what stops this from passing against an empty
    /// extra key.
    #[test]
    fn a_prompt_smuggled_into_a_spare_slot_is_refused() {
        if corpus_absent() {
            return;
        }
        let corpus = adversarial();
        let vector = corpus
            .vector("card.key.smuggled.prompt")
            .expect("card.key.smuggled.prompt");
        let needle = b"helpful assistant";
        assert!(vector
            .bytes
            .windows(needle.len())
            .any(|window| window == needle));
        assert_eq!(
            agent_card::decode(&vector.bytes).unwrap_err().reason(),
            "codec.key.unknown"
        );
    }

    /// Both corpora together cover every reason a card can be refused with.
    ///
    /// A reason with no vector is a refusal nothing cross-checks: each language could
    /// emit it for different bytes forever, because no file makes them meet. The
    /// four excluded are unreachable from an `agent.card` and are named rather than
    /// silently dropped, so the next payload's step has to revisit the list.
    #[test]
    fn every_card_reachable_reason_has_a_vector() {
        let mut named: Vec<&str> = Vec::new();
        if corpus_absent() {
            return;
        }
        for corpus in [golden(), adversarial()] {
            for vector in &corpus.vectors {
                if let Expectation::Reject(reason) = &vector.expectation {
                    named.push(Box::leak(reason.clone().into_boxed_str()));
                }
            }
        }
        let required = [
            "codec.state.unknown",
            "codec.reason.unknown",
            "codec.reason.mismatch",
            "codec.result.mismatch",
            "codec.detail.toolong",
            "codec.lease.window",
            "codec.truncated",
            "codec.trailing",
            "codec.noncanonical.int",
            "codec.type.mismatch",
            "codec.length.wrong",
            "codec.arraycount.wrong",
            "codec.utf8.invalid",
            "codec.mapkeys.order",
            "codec.key.unknown",
            "codec.key.missing",
            "codec.depth",
            "codec.capability.unknown",
            "codec.hostkind.unknown",
            "codec.availability.unknown",
            "codec.org.mismatch",
            "codec.cardhash.mismatch",
            "codec.list.order",
            "codec.alias.empty",
            "codec.alias.case",
            "codec.signature.invalid",
        ];
        for reason in required {
            assert!(
                named.contains(&reason),
                "no vector in either corpus produces {reason}"
            );
        }
    }
}
