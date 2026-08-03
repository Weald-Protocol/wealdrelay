#!/usr/bin/env python3
"""Refuse a release whose builds did not agree.

    scripts/repro-compare.py DIR            every manifest.json under DIR
    scripts/repro-compare.py DIR --expect sha256:...    and it must be this one
    scripts/repro-compare.py --selftest     the comparison's own suite

specs/backend/relay/verification.md proof 1, and step 13's gate: two independent
ci runners must produce byte-identical artifacts, and a third build from a clean
clone at the tag must match the published digest. This is the thing that says no.

It exits non-zero on disagreement, and the `image` job in
.github/workflows/backend-release.yml is downstream of the job that runs it, so
a non-zero exit here means nothing is published. That ordering is the point:
publishing first and verifying afterwards would put an unverified digest in
front of a customer.

Three findings are refusals, and they are distinguished because the fix differs:

- **The inputs differed.** Two builds of two different trees. Not a
  reproducibility failure at all; somebody built the wrong commit, or built
  dirty. The context digest in each manifest says so.
- **The outputs differed from the same inputs.** The real failure. Something in
  the build reads the clock, the path, the host or the network.
- **Fewer than two builds.** A comparison of one build is not a comparison, and
  reporting it as a pass would be the most damaging thing this script could do.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


class Disagreement(Exception):
    """A refusal, with the reason an operator needs to act on."""


def load(directory: str) -> list[dict]:
    """Every `manifest.json` under a directory, in a stable order.

    CI downloads each runner's artifact into its own subdirectory, so the layout
    is `repro/repro-a/manifest.json`, `repro/repro-b/manifest.json`. Sorted by
    label so a failure message reads the same way twice.
    """
    found = []
    for root, _, files in os.walk(directory):
        for name in files:
            if name == "manifest.json":
                with open(os.path.join(root, name), encoding="utf-8") as handle:
                    found.append(json.load(handle))
    return sorted(found, key=lambda m: (m.get("label", ""), m.get("artifact_digest", "")))


def inputs_of(manifest: dict) -> tuple:
    source = manifest.get("source", {})
    return (source.get("context_digest"), manifest.get("source_date_epoch"))


def outputs_of(manifest: dict) -> tuple:
    """Everything two builds of one tree must produce identically.

    **Not the index digest.** An OCI index covers the per-platform manifests and
    also the SLSA provenance attestation, and a provenance attestation records
    which machine ran the build, when, and from where. Provenance that matched
    between two independent builders would not be provenance. Comparing the index
    would therefore report every honest release as irreproducible, which is worse
    than not comparing at all: a check that always fails gets turned off.

    What is compared is the per-platform image manifest digest, which is the
    thing a runtime actually pulls and runs, plus the SHA-256 of each binary. The
    binaries are compared as well as the manifests because a manifest covers a
    compressed layer, and comparing the uncompressed artifact closes the reading
    where two layers agree by coincidence of packaging.
    """
    return (
        tuple(sorted((manifest.get("platform_digests") or {}).items())),
        tuple(sorted((manifest.get("binaries") or {}).items())),
    )


def describe(manifest: dict) -> str:
    source = manifest.get("source", {})
    dirty = " DIRTY" if source.get("dirty") else ""
    return "%s  commit %s%s  context %s  artifact %s" % (
        manifest.get("label", "?"),
        (source.get("commit") or "?")[:12],
        dirty,
        (source.get("context_digest") or "?")[:19],
        (manifest.get("artifact_digest") or "?")[:19],
    )


def compare(manifests: list[dict], expect: str | None = None, allow_dirty: bool = False) -> str:
    """The agreed digest, or raise.

    Returns the digest so the caller can record it. A comparison that returned
    nothing would leave the release pipeline with no number to publish, and a
    pipeline that recomputes the number it just verified is a pipeline that can
    publish something it did not verify.
    """
    if len(manifests) < 2:
        raise Disagreement(
            "found %d build manifest(s). A reproducible build is a claim about "
            "two independent builds, so one is not a pass." % len(manifests)
        )

    # `--allow-dirty` exists for one case: proving the build reproducible during
    # development, before the work is committed and long before there is a tag.
    # The release pipeline never passes it, because a release built from a dirty
    # tree is a release nobody outside this machine can rebuild.
    if not allow_dirty and any(m.get("source", {}).get("dirty") for m in manifests):
        raise Disagreement(
            "at least one build was made from a dirty tree, so nothing here is "
            "reproducible from a tag:\n  " + "\n  ".join(describe(m) for m in manifests)
        )

    distinct_inputs = {inputs_of(m) for m in manifests}
    if len(distinct_inputs) != 1:
        raise Disagreement(
            "the builds did not share their inputs, so this is not a "
            "reproducibility failure but a mistake about what was built:\n  "
            + "\n  ".join(describe(m) for m in manifests)
        )

    distinct_outputs = {outputs_of(m) for m in manifests}
    if len(distinct_outputs) != 1:
        raise Disagreement(
            "identical inputs produced different artifacts. Something in the "
            "build reads the clock, the path, the host or the network:\n  "
            + "\n  ".join(describe(m) for m in manifests)
        )

    digest = manifests[0].get("artifact_digest")
    if not digest:
        raise Disagreement("the manifests carry no artifact digest to compare.")

    if expect is not None and digest != expect:
        raise Disagreement(
            "the builds agree with each other but not with the published "
            "digest.\n  rebuilt:   %s\n  published: %s" % (digest, expect)
        )
    return digest


# --- the comparison's own suite ---------------------------------------------
# specs/backend/build/testing.md: the thing that enforces a gate is itself
# tested, because a comparison that always returns zero is indistinguishable
# from a reproducible build right up until it matters.


def _manifest(label, context="sha256:ctx", epoch=1000, image="sha256:img", binary="sha256:bin",
              dirty=False, index="sha256:index", artifact=None):
    # `is None` and not `or`: a case that wants an empty digest means empty.
    return {
        "label": label,
        "source": {"commit": "c" * 40, "context_digest": context, "dirty": dirty},
        "source_date_epoch": epoch,
        "index_digest": index,
        "platform_digests": {"linux/amd64": image},
        "binaries": {"linux/amd64": binary},
        # In a real manifest this is a hash over the two above. The suite sets it
        # from `image` so a case that changes one changes the other, which is the
        # relationship relay-reproduce.sh guarantees.
        "artifact_digest": ("sha256:artifact-" + image + "-" + binary)
        if artifact is None
        else artifact,
    }


def selftest() -> int:
    cases = []

    def case(name, fn):
        cases.append((name, fn))

    def expect_refusal(fragment, manifests, expect=None, allow_dirty=False):
        try:
            compare(manifests, expect, allow_dirty)
        except Disagreement as error:
            assert fragment in str(error), "wanted %r in %r" % (fragment, str(error))
            return
        raise AssertionError("expected a refusal for: " + fragment)

    case(
        "two agreeing builds pass and the digest is returned",
        lambda: (
            _assert_eq(
                compare([_manifest("a"), _manifest("b")]),
                _manifest("a")["artifact_digest"],
            )
        ),
    )
    case(
        "one build is never a pass",
        lambda: expect_refusal("so one is not a pass", [_manifest("a")]),
    )
    case(
        "zero builds is never a pass",
        lambda: expect_refusal("found 0 build manifest", []),
    )
    case(
        "a dirty tree is refused before anything is compared",
        lambda: expect_refusal("dirty tree", [_manifest("a", dirty=True), _manifest("b")]),
    )
    case(
        "different inputs are named as a mistake, not a reproducibility failure",
        lambda: expect_refusal(
            "did not share their inputs",
            [_manifest("a", context="sha256:one"), _manifest("b", context="sha256:two")],
        ),
    )
    case(
        "a different SOURCE_DATE_EPOCH is an input difference",
        lambda: expect_refusal(
            "did not share their inputs",
            [_manifest("a", epoch=1), _manifest("b", epoch=2)],
        ),
    )
    case(
        "same inputs, different image digest, is the real failure",
        lambda: expect_refusal(
            "identical inputs produced different artifacts",
            [_manifest("a", image="sha256:one"), _manifest("b", image="sha256:two")],
        ),
    )
    case(
        "same inputs, same image, different binary, is also refused",
        lambda: expect_refusal(
            "identical inputs produced different artifacts",
            [_manifest("a", binary="sha256:one"), _manifest("b", binary="sha256:two")],
        ),
    )
    case(
        "agreeing builds with no digest at all are refused",
        lambda: expect_refusal(
            "no artifact digest",
            [_manifest("a", artifact=""), _manifest("b", artifact="")],
        ),
    )
    case(
        "a differing index digest alone is not a failure, because provenance differs",
        lambda: _assert_eq(
            compare([_manifest("a", index="sha256:one"), _manifest("b", index="sha256:two")]),
            _manifest("a")["artifact_digest"],
        ),
    )
    case(
        "a third build that does not match the published digest is refused",
        lambda: expect_refusal(
            "not with the published digest",
            [_manifest("a"), _manifest("b")],
            "sha256:published",
        ),
    )
    case(
        "a third build that does match the published digest passes",
        lambda: _assert_eq(
            compare([_manifest("a"), _manifest("b")], _manifest("a")["artifact_digest"]),
            _manifest("a")["artifact_digest"],
        ),
    )
    case(
        "describe names the label, the commit and the dirty flag",
        lambda: _assert_in("DIRTY", describe(_manifest("a", dirty=True))),
    )
    case(
        "--allow-dirty lets a development proof through, and only that check",
        lambda: _assert_eq(
            compare([_manifest("a", dirty=True), _manifest("b", dirty=True)], allow_dirty=True),
            _manifest("a")["artifact_digest"],
        ),
    )
    case(
        "--allow-dirty does not weaken the output comparison",
        lambda: expect_refusal(
            "identical inputs produced different artifacts",
            [
                _manifest("a", image="sha256:one", dirty=True),
                _manifest("b", image="sha256:two", dirty=True),
            ],
            allow_dirty=True,
        ),
    )

    failures = 0
    for name, fn in cases:
        try:
            fn()
            print("  pass  %s" % name)
        except AssertionError as error:
            failures += 1
            print("  FAIL  %s: %s" % (name, error))
    print("\n%d/%d comparison cases pass" % (len(cases) - failures, len(cases)))
    return 1 if failures else 0


def _assert_eq(got, want):
    assert got == want, "got %r, wanted %r" % (got, want)


def _assert_in(fragment, text):
    assert fragment in text, "wanted %r in %r" % (fragment, text)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", help="a directory holding build manifests")
    parser.add_argument("--expect", help="the published digest the builds must match")
    parser.add_argument("--selftest", action="store_true", help="run the comparison's own suite")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="permit builds from an uncommitted tree. Development only; the "
        "release pipeline never passes this.",
    )
    parser.add_argument("--out", help="write the agreed digest here")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.directory:
        parser.error("a directory is required unless --selftest is given")

    manifests = load(args.directory)
    for manifest in manifests:
        print("  " + describe(manifest))
    try:
        digest = compare(manifests, args.expect, args.allow_dirty)
    except Disagreement as error:
        print("\nREFUSED: %s" % error, file=sys.stderr)
        return 1
    print("\nthe builds agree: %s" % digest)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(digest + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - the entry point itself
    sys.exit(main(sys.argv[1:]))
