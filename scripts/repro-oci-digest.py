#!/usr/bin/env python3
"""The image digest, read out of an OCI layout tar.

    scripts/repro-oci-digest.py image.tar

specs/backend/relay/verification.md proof 1 turns on comparing what two machines
produced. The number that matters is the digest of the image *index*, because
that is what a registry stores under the tag and what `cosign verify` is run
against.

Read from the exported layout rather than from `docker images --digests`,
deliberately. The local image store's ids are host state: they depend on what
was already pulled and how the daemon happened to lay the layers down. The
layout is the artifact, and hashing the artifact is the only reading of
"byte-identical" that a third party could repeat.

`--full` also prints the per-platform manifest digests, which is what tells an
operator *which* architecture diverged when a comparison fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile


def _read(tar: tarfile.TarFile, name: str) -> bytes:
    member = tar.extractfile(name)
    if member is None:  # pragma: no cover - a directory where a blob belongs
        raise SystemExit(f"{name}: not a file inside the layout")
    return member.read()


def image_digest(tar_path: str) -> tuple[str, dict]:
    """The digest a registry would store under the tag, and the index it names.

    Not the hash of `index.json`. BuildKit writes that outer file with an
    `org.opencontainers.image.created` annotation taken from the wall clock, so
    hashing it would report every build as irreproducible for a reason that has
    nothing to do with the image. The number that matters is the digest of the
    *inner* index the outer file points at: that is what is pushed, what a tag
    resolves to, and what `cosign verify` is run against.

    Verified rather than trusted. The descriptor's digest is recomputed from the
    blob's own bytes, because a layout whose descriptor disagreed with its
    content would otherwise be reported as a perfectly reproducible build.
    """
    with tarfile.open(tar_path, "r") as tar:
        outer = json.loads(_read(tar, "index.json"))
        manifests = outer.get("manifests") or []
        if len(manifests) != 1:
            raise SystemExit(
                f"{tar_path}: expected one top-level descriptor, found {len(manifests)}"
            )
        claimed = manifests[0]["digest"]
        algorithm, _, _ = claimed.partition(":")
        if algorithm != "sha256":
            raise SystemExit(f"{tar_path}: unsupported digest algorithm {algorithm}")
        hexdigest = claimed.partition(":")[2]
        raw = _read(tar, f"blobs/sha256/{hexdigest}")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != hexdigest:
            raise SystemExit(
                f"{tar_path}: the layout is inconsistent. index.json names "
                f"sha256:{hexdigest} but that blob hashes to sha256:{actual}"
            )
        return claimed, json.loads(raw)


def per_platform(index: dict) -> dict:
    """Manifest digest per platform, from the index's descriptors."""
    out = {}
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform") or {}
        os_name = platform.get("os")
        arch = platform.get("architecture")
        if not os_name or not arch:
            continue
        # BuildKit attaches attestation manifests under the unknown/unknown
        # platform. They are part of the image and covered by the index digest;
        # naming them as a platform would just be noise in the report.
        if os_name == "unknown" or arch == "unknown":
            continue
        variant = platform.get("variant")
        key = f"{os_name}/{arch}" + (f"/{variant}" if variant else "")
        out[key] = descriptor.get("digest", "")
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tar", help="an OCI layout tar, as written by buildx")
    parser.add_argument(
        "--full",
        action="store_true",
        help="also print the per-platform manifest digests, as JSON",
    )
    args = parser.parse_args(argv)

    digest, index = image_digest(args.tar)
    if args.full:
        print(
            json.dumps(
                {"index": digest, "platforms": per_platform(index)},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(digest)
    return 0


if __name__ == "__main__":  # pragma: no cover - the entry point itself
    sys.exit(main(sys.argv[1:]))
