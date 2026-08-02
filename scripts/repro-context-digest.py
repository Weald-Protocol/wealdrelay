#!/usr/bin/env python3
"""A digest over exactly the files the relay's Docker build can see.

    scripts/repro-context-digest.py --root .

Why this exists: when two builds disagree on the image digest, the first
question is whether their *inputs* disagreed. Without this number the answer is
a guess, and "the build is not reproducible" and "the two trees were not the
same" are very different findings with very different fixes.

It is also what makes step 13's negative proof legible. A tampered source tree
must produce a different image digest; the context digest shows that the tamper
reached the build at all, so a passing negative proof cannot be a build that
silently ignored the edit.

The rules are `.dockerignore` at the repository root, reimplemented here rather
than shelled out to, because there is no command that prints a build context's
contents. Path, mode bit and content are all hashed: a file that becomes
executable changes the image even when its bytes do not.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import sys


def load_patterns(root: str) -> list[tuple[bool, str]]:
    """`.dockerignore`, as (negated, pattern) pairs in file order."""
    path = os.path.join(root, ".dockerignore")
    patterns: list[tuple[bool, str]] = []
    if not os.path.exists(path):
        return patterns
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            patterns.append((negated, line[1:] if negated else line))
    return patterns


def matches(pattern: str, relative: str) -> bool:
    """One `.dockerignore` pattern against one relative path.

    Docker's matcher is Go's `filepath.Match` extended with `**`. The subset
    used here is the subset the repository's own `.dockerignore` uses, and an
    unsupported construct is better refused than silently mismatched, so
    anything not covered simply does not match and the file stays in the
    context. A file wrongly kept changes the digest and is caught; a file
    wrongly dropped would hide a real difference.
    """
    if pattern.startswith("**/"):
        tail = pattern[3:]
        parts = relative.split("/")
        return any(fnmatch.fnmatch("/".join(parts[i:]), tail) for i in range(len(parts)))
    if fnmatch.fnmatch(relative, pattern):
        return True
    # A directory pattern excludes everything beneath it.
    return relative.startswith(pattern.rstrip("/") + "/")


def ignored(patterns: list[tuple[bool, str]], relative: str) -> bool:
    """Last matching pattern wins, which is Docker's rule."""
    verdict = False
    for negated, pattern in patterns:
        if matches(pattern, relative):
            verdict = not negated
    return verdict


def walk(root: str, patterns: list[tuple[bool, str]]) -> list[str]:
    kept = []
    for directory, subdirectories, files in os.walk(root):
        relative_dir = os.path.relpath(directory, root)
        relative_dir = "" if relative_dir == "." else relative_dir
        # Prune ignored directories rather than descending into them. `target`
        # alone is hundreds of thousands of files.
        subdirectories[:] = [
            name
            for name in subdirectories
            if not ignored(patterns, os.path.join(relative_dir, name) if relative_dir else name)
        ]
        subdirectories.sort()
        for name in sorted(files):
            relative = os.path.join(relative_dir, name) if relative_dir else name
            if ignored(patterns, relative):
                continue
            kept.append(relative)
    return sorted(kept)


def digest(root: str) -> tuple[str, list[str]]:
    patterns = load_patterns(root)
    kept = walk(root, patterns)
    outer = hashlib.sha256()
    for relative in kept:
        absolute = os.path.join(root, relative)
        if os.path.islink(absolute):
            # The target, not the contents. A symlink may dangle, and following
            # it would make the digest depend on something outside the context.
            payload = os.readlink(absolute).encode("utf-8")
            kind = b"link"
        else:
            with open(absolute, "rb") as handle:
                payload = handle.read()
            kind = b"file"
        # lstat, for the same reason: a dangling symlink has no target to stat.
        executable = b"1" if os.lstat(absolute).st_mode & 0o111 else b"0"
        outer.update(relative.encode("utf-8"))
        outer.update(b"\0")
        outer.update(kind)
        outer.update(executable)
        outer.update(hashlib.sha256(payload).digest())
    return "sha256:" + outer.hexdigest(), kept


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="the build context root")
    parser.add_argument(
        "--list", action="store_true", help="print every file in the context, one per line"
    )
    args = parser.parse_args(argv)

    value, kept = digest(os.path.abspath(args.root))
    if args.list:
        for relative in kept:
            print(relative)
    print(value)
    return 0


if __name__ == "__main__":  # pragma: no cover - the entry point itself
    sys.exit(main(sys.argv[1:]))
