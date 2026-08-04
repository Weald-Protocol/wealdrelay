// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The shared agent vector corpus, as Rust reads it.
//!
//! # One corpus, two languages
//!
//! `specs/agents/networked/protocol.md` requires every rule in it to be enforced
//! by both the Swift codec and this one, **against one corpus**. Two corpora that
//! happen to agree today is exactly the failure that makes a cross-language
//! protocol rot, so the bytes live once, at `Tests/Fixtures/agents/`, and
//! `Tests/AgentCorpus.swift` reads the same files.
//!
//! The two loaders are written to the same rules on purpose. A manifest one
//! accepts and the other rejects is itself a caught bug, and that only works if
//! neither is more forgiving than the other.
//!
//! # Why the loader is strict about things that are not bytes
//!
//! - A manifest entry naming a missing file is an error, never a skip. A skipped
//!   vector is a vector that has silently stopped proving anything.
//! - A `.cbor` file that no manifest entry names is an error too, and that is the
//!   direction people get wrong: somebody writes a hostile vector, forgets the
//!   manifest row, and the corpus reports the same green while the case they wrote
//!   never runs.
//! - A `reject` entry must name a reason and an `accept` entry must not, because
//!   `protocol.md` closes the reason vocabulary.
//!
//! An empty corpus is legal and loads to zero vectors. Step 0 ships exactly that:
//! the loader is proven before there is anything to load, which is the only order
//! in which the loader can be proven at all.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// What a conforming codec must do with a vector's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expectation {
    Accept,
    /// The closed reason code from `protocol.md` this rejection must produce.
    Reject(String),
}

/// One vector, with its bytes read eagerly. A corpus small enough to check in is
/// small enough to hold, and a lazy read would let a deleted file survive as far
/// as an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub expectation: Expectation,
    pub bytes: Vec<u8>,
}

/// A loaded corpus. Vectors are ordered by name so both languages iterate in the
/// same sequence and a pairwise comparison table has stable rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corpus {
    pub root: PathBuf,
    pub vectors: Vec<Vector>,
}

impl Corpus {
    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    pub fn vector(&self, name: &str) -> Option<&Vector> {
        self.vectors.iter().find(|v| v.name == name)
    }
}

/// The repository root, found by walking up from this crate.
///
/// `CARGO_MANIFEST_DIR` is `<root>/backend/weald-mls`, so the root is two levels
/// up. Computed rather than hard-coded as a relative path because the working
/// directory of a test process is not something this crate gets to assume.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("CARGO_MANIFEST_DIR is <root>/backend/weald-mls")
        .to_path_buf()
}

/// `Tests/Fixtures/agents`, the golden corpus.
pub fn golden_root() -> PathBuf {
    repository_root().join("Tests/Fixtures/agents")
}

/// `Tests/Fixtures/agents/adversarial`, the hand-constructed hostile events.
pub fn adversarial_root() -> PathBuf {
    golden_root().join("adversarial")
}

/// Read a corpus rooted at `root`.
///
/// A root with no `manifest.json` is an error rather than an empty corpus. The
/// two are different: one is "nothing to prove yet", spelled by a manifest with an
/// empty `vectors` array, and the other is "the corpus is missing", which is what
/// a wrong path or a bad checkout looks like. Collapsing them would let a typo in
/// a gate script report a clean run.
pub fn load(root: &Path) -> Result<Corpus, CorpusError> {
    let manifest_path = root.join("manifest.json");
    if !manifest_path.is_file() {
        return Err(CorpusError::MissingManifest(manifest_path));
    }

    let raw = std::fs::read(&manifest_path)
        .map_err(|e| CorpusError::UnreadableManifest(manifest_path.clone(), e.to_string()))?;
    let manifest: Manifest = serde_json::from_slice(&raw)
        .map_err(|e| CorpusError::UnreadableManifest(manifest_path.clone(), e.to_string()))?;

    let _ = manifest.corpus;
    let _ = manifest.protocol_version;

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut named: BTreeSet<PathBuf> = BTreeSet::new();
    let mut vectors: Vec<Vector> = Vec::new();

    for entry in manifest.vectors {
        if !seen.insert(entry.name.clone()) {
            return Err(CorpusError::DuplicateName(entry.name));
        }

        let expectation = match (entry.expect.as_str(), entry.reason.as_deref()) {
            ("accept", None) => Expectation::Accept,
            ("accept", Some(reason)) => {
                return Err(CorpusError::AcceptCarriesReason(
                    entry.name,
                    reason.to_string(),
                ))
            }
            ("reject", Some(reason)) if !reason.is_empty() => {
                Expectation::Reject(reason.to_string())
            }
            ("reject", _) => return Err(CorpusError::RejectMissingReason(entry.name)),
            (other, _) => {
                return Err(CorpusError::UnknownExpectation(
                    entry.name,
                    other.to_string(),
                ))
            }
        };

        let file_path = root.join(&entry.file);
        let bytes = std::fs::read(&file_path)
            .map_err(|_| CorpusError::MissingVectorFile(entry.name.clone(), file_path.clone()))?;
        named.insert(normalize(&file_path));

        vectors.push(Vector {
            name: entry.name,
            kind: entry.kind,
            file: entry.file,
            expectation,
            bytes,
        });
    }

    assert_no_orphans(root, &named)?;

    vectors.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Corpus {
        root: root.to_path_buf(),
        vectors,
    })
}

/// `std::fs::canonicalize` would fail on a path that does not exist, and every
/// path compared here has already been read, but canonicalize also resolves
/// symlinks, which would make a corpus reachable through two names compare
/// unequal to itself. Component-wise cleanup is enough and is total.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Every `.cbor` under `root` must be named by the manifest.
///
/// The adversarial corpus is a corpus in its own right with its own manifest, so
/// walking into it from the golden root would report every hostile vector as an
/// orphan. It is skipped by name for that reason, not because nested directories
/// are uninteresting.
fn assert_no_orphans(root: &Path, named: &BTreeSet<PathBuf>) -> Result<(), CorpusError> {
    let mut orphans: Vec<String> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|_| CorpusError::Unwalkable(dir.clone()))?;
        for entry in entries {
            let entry = entry.map_err(|_| CorpusError::Unwalkable(dir.clone()))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                if name == "adversarial" {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) == Some("cbor")
                && !named.contains(&normalize(&path))
            {
                orphans.push(name.to_string());
            }
        }
    }

    if orphans.is_empty() {
        Ok(())
    } else {
        orphans.sort();
        Err(CorpusError::OrphanedVectors(orphans))
    }
}

#[derive(Deserialize)]
struct Manifest {
    corpus: String,
    #[serde(rename = "protocolVersion")]
    protocol_version: u32,
    vectors: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    kind: String,
    file: String,
    expect: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusError {
    MissingManifest(PathBuf),
    UnreadableManifest(PathBuf, String),
    DuplicateName(String),
    UnknownExpectation(String, String),
    RejectMissingReason(String),
    AcceptCarriesReason(String, String),
    MissingVectorFile(String, PathBuf),
    OrphanedVectors(Vec<String>),
    Unwalkable(PathBuf),
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorpusError::MissingManifest(p) => write!(
                f,
                "no corpus manifest at {}. An absent corpus is not an empty one.",
                p.display()
            ),
            CorpusError::UnreadableManifest(p, why) => {
                write!(
                    f,
                    "corpus manifest at {} is not readable: {why}",
                    p.display()
                )
            }
            CorpusError::DuplicateName(name) => write!(
                f,
                "two vectors named '{name}'. Names identify a case across both languages."
            ),
            CorpusError::UnknownExpectation(name, expect) => write!(
                f,
                "vector '{name}' expects '{expect}'. Only 'accept' and 'reject' exist."
            ),
            CorpusError::RejectMissingReason(name) => write!(
                f,
                "vector '{name}' rejects with no reason code. protocol.md closes that vocabulary."
            ),
            CorpusError::AcceptCarriesReason(name, reason) => {
                write!(f, "vector '{name}' accepts but names reason '{reason}'.")
            }
            CorpusError::MissingVectorFile(name, p) => write!(
                f,
                "vector '{name}' names {}, which is not there.",
                p.display()
            ),
            CorpusError::OrphanedVectors(files) => write!(
                f,
                "{} vector file(s) no manifest entry names: {}. \
                 An unlisted vector runs against nothing and proves nothing.",
                files.len(),
                files.join(", ")
            ),
            CorpusError::Unwalkable(p) => {
                write!(f, "cannot enumerate the corpus at {}.", p.display())
            }
        }
    }
}

impl std::error::Error for CorpusError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// A corpus in a temp directory. Every test builds the exact shape it is
    /// asserting on rather than sharing a fixture, because a shared fixture is one
    /// more thing that can drift away from what the assertion believes.
    struct Scratch {
        dir: tempfile::TempDir,
    }

    impl Scratch {
        fn new() -> Self {
            Scratch {
                dir: tempfile::tempdir().expect("tempdir"),
            }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().to_path_buf()
        }

        fn manifest(&self, body: &str) -> &Self {
            fs::write(self.root().join("manifest.json"), body).expect("write manifest");
            self
        }

        fn vector(&self, rel: &str, bytes: &[u8]) -> &Self {
            let path = self.root().join(rel);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, bytes).expect("write vector");
            self
        }
    }

    fn manifest_with(vectors: &str) -> String {
        format!(r#"{{"corpus":"golden","protocolVersion":1,"vectors":[{vectors}]}}"#)
    }

    // ---------------------------------------------------------------- happy path

    #[test]
    fn empty_corpus_loads_to_zero_vectors() {
        let s = Scratch::new();
        s.manifest(&manifest_with(""));
        let corpus = load(&s.root()).expect("empty corpus is legal");
        assert!(corpus.is_empty());
        assert_eq!(corpus.root, s.root());
        assert_eq!(corpus.vector("nothing"), None);
    }

    #[test]
    fn one_vector_corpus_reads_its_bytes() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"card.minimal","kind":"agent.card","file":"vectors/a.cbor","expect":"accept"}"#,
        ))
        .vector("vectors/a.cbor", &[0xa1, 0x01, 0x02]);

        let corpus = load(&s.root()).expect("load");
        assert!(!corpus.is_empty());
        let v = corpus.vector("card.minimal").expect("named vector");
        assert_eq!(v.kind, "agent.card");
        assert_eq!(v.file, "vectors/a.cbor");
        assert_eq!(v.expectation, Expectation::Accept);
        assert_eq!(v.bytes, vec![0xa1, 0x01, 0x02]);
    }

    #[test]
    fn reject_entry_carries_its_reason() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"v","kind":"agent.invoke","file":"vectors/v.cbor","expect":"reject","reason":"deadline.passed"}"#,
        ))
        .vector("vectors/v.cbor", b"x");

        let corpus = load(&s.root()).expect("load");
        assert_eq!(
            corpus.vectors[0].expectation,
            Expectation::Reject("deadline.passed".into())
        );
    }

    #[test]
    fn vectors_are_sorted_by_name() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"b","kind":"k","file":"vectors/b.cbor","expect":"accept"},
               {"name":"a","kind":"k","file":"vectors/a.cbor","expect":"accept"}"#,
        ))
        .vector("vectors/a.cbor", b"a")
        .vector("vectors/b.cbor", b"b");

        let corpus = load(&s.root()).expect("load");
        let names: Vec<_> = corpus.vectors.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn hidden_files_and_non_cbor_files_are_not_orphans() {
        let s = Scratch::new();
        s.manifest(&manifest_with(""))
            .vector("vectors/.gitkeep", b"")
            .vector("README.md", b"notes")
            .vector(".hidden/x.cbor", b"ignored");
        load(&s.root()).expect("only .cbor files count, and hidden ones do not");
    }

    #[test]
    fn a_nested_adversarial_corpus_is_not_walked() {
        let s = Scratch::new();
        s.manifest(&manifest_with(""))
            .vector("adversarial/vectors/hostile.cbor", b"hostile");
        load(&s.root()).expect("the adversarial corpus owns its own manifest");
    }

    // ------------------------------------------------------------------ refusals

    #[test]
    fn a_missing_manifest_is_not_an_empty_corpus() {
        let s = Scratch::new();
        let err = load(&s.root()).expect_err("must refuse");
        assert!(matches!(err, CorpusError::MissingManifest(_)));
    }

    #[test]
    fn unparseable_manifest_is_refused() {
        let s = Scratch::new();
        s.manifest("{not json");
        let err = load(&s.root()).expect_err("must refuse");
        assert!(matches!(err, CorpusError::UnreadableManifest(_, _)));
    }

    #[test]
    fn an_unreadable_manifest_file_is_refused() {
        let s = Scratch::new();
        // A directory named manifest.json is a file for `is_file`'s purposes only
        // when it is one; here it is not, so this exercises the read error rather
        // than the parse error.
        fs::create_dir(s.root().join("vectors")).expect("mkdir");
        s.manifest(&manifest_with(""));
        let path = s.root().join("manifest.json");
        fs::set_permissions(
            &path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o000),
        )
        .expect("chmod");
        let err = load(&s.root()).expect_err("must refuse");
        fs::set_permissions(
            &path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644),
        )
        .expect("restore");
        assert!(matches!(err, CorpusError::UnreadableManifest(_, _)));
    }

    #[test]
    fn duplicate_names_are_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"a","kind":"k","file":"vectors/a.cbor","expect":"accept"},
               {"name":"a","kind":"k","file":"vectors/b.cbor","expect":"accept"}"#,
        ))
        .vector("vectors/a.cbor", b"a")
        .vector("vectors/b.cbor", b"b");
        assert_eq!(
            load(&s.root()).expect_err("must refuse"),
            CorpusError::DuplicateName("a".into())
        );
    }

    #[test]
    fn accept_with_a_reason_is_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"a","kind":"k","file":"vectors/a.cbor","expect":"accept","reason":"budget.rate"}"#,
        ))
        .vector("vectors/a.cbor", b"a");
        assert_eq!(
            load(&s.root()).expect_err("must refuse"),
            CorpusError::AcceptCarriesReason("a".into(), "budget.rate".into())
        );
    }

    #[test]
    fn reject_without_a_reason_is_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"a","kind":"k","file":"vectors/a.cbor","expect":"reject"}"#,
        ))
        .vector("vectors/a.cbor", b"a");
        assert_eq!(
            load(&s.root()).expect_err("must refuse"),
            CorpusError::RejectMissingReason("a".into())
        );
    }

    #[test]
    fn reject_with_an_empty_reason_is_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"a","kind":"k","file":"vectors/a.cbor","expect":"reject","reason":""}"#,
        ))
        .vector("vectors/a.cbor", b"a");
        assert_eq!(
            load(&s.root()).expect_err("must refuse"),
            CorpusError::RejectMissingReason("a".into())
        );
    }

    #[test]
    fn an_unknown_expectation_is_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"a","kind":"k","file":"vectors/a.cbor","expect":"maybe"}"#,
        ))
        .vector("vectors/a.cbor", b"a");
        assert_eq!(
            load(&s.root()).expect_err("must refuse"),
            CorpusError::UnknownExpectation("a".into(), "maybe".into())
        );
    }

    #[test]
    fn a_manifest_entry_naming_a_missing_file_is_refused_not_skipped() {
        let s = Scratch::new();
        s.manifest(&manifest_with(
            r#"{"name":"a","kind":"k","file":"vectors/gone.cbor","expect":"accept"}"#,
        ));
        let err = load(&s.root()).expect_err("must refuse");
        assert!(matches!(err, CorpusError::MissingVectorFile(name, _) if name == "a"));
    }

    #[test]
    fn an_unlisted_vector_file_is_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(""))
            .vector("vectors/orphan.cbor", b"nobody names me");
        assert_eq!(
            load(&s.root()).expect_err("must refuse"),
            CorpusError::OrphanedVectors(vec!["orphan.cbor".into()])
        );
    }

    #[test]
    fn an_unreadable_subdirectory_is_refused() {
        let s = Scratch::new();
        s.manifest(&manifest_with(""));
        let locked = s.root().join("locked");
        fs::create_dir(&locked).expect("mkdir");
        fs::set_permissions(
            &locked,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o000),
        )
        .expect("chmod");
        let err = load(&s.root()).expect_err("must refuse");
        fs::set_permissions(
            &locked,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .expect("restore");
        assert!(matches!(err, CorpusError::Unwalkable(_)));
    }

    // -------------------------------------------------------------------- paths

    /// Two trees, and both are asserted rather than one of them skipped.
    ///
    /// This crate is published byte for byte to
    /// `github.com/Weald-Protocol/wealdrelay`
    /// (`specs/backend/build/relay-publication.md`) and the corpus is not: it is
    /// checked in beside the client's tests, under `Tests/`, which that tree does
    /// not carry. So the monorepo asserts the corpus is present and loads, and the
    /// published tree asserts it is consistently absent. A tree that carries the
    /// client and no corpus, or a corpus and no client, fails either way, which is
    /// the fact worth holding: what must never happen is a loader pointed
    /// somewhere nothing is and a test that shrugged.
    #[test]
    fn the_repository_root_holds_the_checked_in_corpus() {
        let root = repository_root();
        assert_eq!(golden_root(), root.join("Tests/Fixtures/agents"));
        assert_eq!(adversarial_root(), golden_root().join("adversarial"));
        if root.join("Weald.xcodeproj").exists() {
            assert!(golden_root().join("manifest.json").is_file());
            assert!(adversarial_root().join("manifest.json").is_file());
        } else {
            assert!(
                !golden_root().exists(),
                "a tree with no client carries no corpus"
            );
        }
    }

    #[test]
    fn the_checked_in_corpora_load() {
        if !repository_root().join("Weald.xcodeproj").exists() {
            return; // The published tree, asserted above to carry no corpus.
        }
        load(&golden_root()).expect("golden corpus loads");
        load(&adversarial_root()).expect("adversarial corpus loads");
    }

    #[test]
    fn normalize_drops_curdir_and_resolves_parentdir() {
        assert_eq!(
            normalize(Path::new("/a/./b/../c/d.cbor")),
            PathBuf::from("/a/c/d.cbor")
        );
    }

    // ------------------------------------------------------------------ messages

    #[test]
    fn every_error_says_what_went_wrong() {
        let p = PathBuf::from("/tmp/x");
        let messages = [
            CorpusError::MissingManifest(p.clone()).to_string(),
            CorpusError::UnreadableManifest(p.clone(), "bad".into()).to_string(),
            CorpusError::DuplicateName("a".into()).to_string(),
            CorpusError::UnknownExpectation("a".into(), "maybe".into()).to_string(),
            CorpusError::RejectMissingReason("a".into()).to_string(),
            CorpusError::AcceptCarriesReason("a".into(), "r".into()).to_string(),
            CorpusError::MissingVectorFile("a".into(), p.clone()).to_string(),
            CorpusError::OrphanedVectors(vec!["a.cbor".into()]).to_string(),
            CorpusError::Unwalkable(p).to_string(),
        ];
        for message in messages {
            assert!(!message.is_empty());
        }
    }
}
