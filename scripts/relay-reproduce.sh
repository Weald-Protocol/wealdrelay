#!/usr/bin/env bash
# One deterministic build of the relay, and a manifest of what came out.
#
#   scripts/relay-reproduce.sh --out DIR [--label NAME] [--source-dir DIR]
#
# specs/backend/relay/verification.md proof 1: the published container digest is
# byte-reproducible from the tagged source, so a third party can rebuild and
# compare. This script is the half that produces one build's numbers.
# scripts/repro-compare.py is the half that refuses when two of them differ.
#
# Two rules decide everything here.
#
# **Nothing may come from the clock.** SOURCE_DATE_EPOCH is the tagged commit's
# own timestamp, and the OCI export is written with rewrite-timestamp=true so
# BuildKit stamps layers with it rather than with now. A build that reads the
# clock is a build that can never be reproduced, which would make the audit
# claim in server.md unverifiable rather than merely unverified.
#
# **Nothing may come from the machine.** The image digest is read out of the OCI
# layout the build produced, not out of the local image store, because the local
# store's ids are host state. RUSTFLAGS remaps the build directory and the cargo
# home out of the binary in the Dockerfile for the same reason.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT=""
LABEL="${WEALD_REPRO_LABEL:-local}"
SOURCE_DIR="$ROOT"
PLATFORMS="${WEALD_REPRO_PLATFORMS:-linux/amd64,linux/arm64}"

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --source-dir) SOURCE_DIR="$(cd "$2" && pwd)"; shift 2 ;;
    --platforms) PLATFORMS="$2"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "relay-reproduce: unknown argument: $1" >&2; exit 64 ;;
  esac
done

[ -n "$OUT" ] || { echo "relay-reproduce: --out DIR is required" >&2; exit 64; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

cd "$SOURCE_DIR"

command -v docker >/dev/null 2>&1 || {
  echo "relay-reproduce: docker is required" >&2; exit 69; }
docker buildx version >/dev/null 2>&1 || {
  echo "relay-reproduce: docker buildx is required" >&2; exit 69; }

# The source identity this build claims to be of. `git` is the authority: a
# manifest that named a commit without saying whether the tree was dirty would
# let an uncommitted edit hide inside a matching commit id.
#
# A second build is only evidence when it happened somewhere else, so this
# script must also run against a tree that is a copy of the context rather than
# a checkout. When there is no git directory the identity is passed in, and the
# comparison still has a real number to work with because the context digest
# below is computed from the files rather than claimed.
if git rev-parse --git-dir >/dev/null 2>&1; then
  COMMIT="${WEALD_REPRO_COMMIT:-$(git rev-parse HEAD)}"
  TREE="${WEALD_REPRO_TREE:-$(git rev-parse 'HEAD^{tree}')}"
  if [ -n "$(git status --porcelain)" ]; then DIRTY=true; else DIRTY=false; fi
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
else
  COMMIT="${WEALD_REPRO_COMMIT:?not a git checkout, so WEALD_REPRO_COMMIT must be set}"
  TREE="${WEALD_REPRO_TREE:-$COMMIT}"
  DIRTY="${WEALD_REPRO_DIRTY:-true}"
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?not a git checkout, so SOURCE_DATE_EPOCH must be set}"
fi

# The OCI provenance labels are part of the image config, so they are part of the
# digest: a build that stamps a different revision or version produces different
# bytes. Both therefore have to come from the source tree the same way the
# release workflow derives them (VCS_REF from the commit, VERSION from the tag),
# or the clean-clone rebuild would disagree with the published digest for a
# reason that has nothing to do with the code. Away from a tag both fall back to
# the Dockerfile's own defaults, so a local build is reproducible against another
# local build rather than accidentally claiming to be a release.
VCS_REF="${WEALD_REPRO_COMMIT:-${COMMIT:-unknown}}"
if [ -n "${WEALD_REPRO_VERSION:-}" ]; then
  VERSION="$WEALD_REPRO_VERSION"
elif git rev-parse --git-dir >/dev/null 2>&1 \
  && VERSION="$(git describe --tags --exact-match HEAD 2>/dev/null)"; then
  :
else
  VERSION="0.0.0-dev"
fi

# A build context digest, computed over exactly the files the Dockerfile can
# see. This is what makes the tampered-tree negative proof legible: when two
# builds disagree, the manifest says whether their inputs disagreed too.
CONTEXT_DIGEST="$(
  python3 "$ROOT/scripts/repro-context-digest.py" --root "$SOURCE_DIR"
)"

echo "relay-reproduce: label=$LABEL commit=${COMMIT:0:12} dirty=$DIRTY epoch=$SOURCE_DATE_EPOCH"
echo "relay-reproduce: context=$CONTEXT_DIGEST"
echo "relay-reproduce: vcs_ref=${VCS_REF:0:12} version=$VERSION"

layout="$OUT/oci"
rm -rf "$layout"
mkdir -p "$layout"

# A dedicated builder instance, so the result does not depend on whatever
# happens to be configured on this machine.
BUILDER="weald-repro"
docker buildx inspect "$BUILDER" >/dev/null 2>&1 \
  || docker buildx create --name "$BUILDER" --driver docker-container >/dev/null

start="$(date +%s)"
docker buildx build \
  --builder "$BUILDER" \
  --file backend/wealdrelay/Dockerfile \
  --platform "$PLATFORMS" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --build-arg "VCS_REF=$VCS_REF" \
  --build-arg "VERSION=$VERSION" \
  --output "type=oci,dest=$OUT/image.tar,rewrite-timestamp=true,tar=true,name=weald-relay" \
  --metadata-file "$OUT/buildx-metadata.json" \
  --progress plain \
  . 2>"$OUT/build.log"
elapsed=$(( $(date +%s) - start ))

# The digest, read out of the OCI layout the build just wrote rather than out of
# the local image store. The store's ids are host state; this is the number that
# would be pushed.
FULL="$(python3 "$ROOT/scripts/repro-oci-digest.py" "$OUT/image.tar" --full)"
IMAGE_DIGEST="$(printf '%s' "$FULL" | python3 -c "import json,sys;print(json.load(sys.stdin)['index'])")"
# And the per-platform manifests underneath it. These are what is compared;
# the index above is recorded and deliberately not, because the index also
# covers the provenance attestation, and provenance that did not differ
# between two builders would not be provenance. See scripts/repro-compare.py.
PLATFORM_DIGESTS="$(printf '%s' "$FULL" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['platforms'],sort_keys=True))")"

# The binary itself, per platform, exported from the `artifact` stage. This is
# the SHA-256 that goes in the release notes
# (specs/backend/relay/verification.md proof 2), and exporting it from the same
# Dockerfile is what makes it the binary that is genuinely inside the image.
binaries="$OUT/binaries"
rm -rf "$binaries"
mkdir -p "$binaries"
bin_json="{}"
IFS=',' read -r -a platform_list <<< "$PLATFORMS"
for platform in "${platform_list[@]}"; do
  slug="${platform//\//-}"
  dest="$binaries/$slug"
  mkdir -p "$dest"
  docker buildx build \
    --builder "$BUILDER" \
    --file backend/wealdrelay/Dockerfile \
    --target artifact \
    --platform "$platform" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --output "type=local,dest=$dest" \
    --progress plain \
    . 2>>"$OUT/build.log"
  sum="$(python3 -c '
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print("sha256:" + h.hexdigest())
' "$dest/wealdrelay")"
  bin_json="$(python3 -c '
import json, sys
d = json.loads(sys.argv[1]); d[sys.argv[2]] = sys.argv[3]; print(json.dumps(d))
' "$bin_json" "$platform" "$sum")"
done

python3 - "$OUT/manifest.json" <<PY
import hashlib, json, platform, subprocess, sys

def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return "unknown"

manifest = {
    "label": "$LABEL",
    "source": {
        "commit": "$COMMIT",
        "tree": "$TREE",
        # Shell booleans are strings, and `true` is not a Python literal.
        "dirty": "$DIRTY" == "true",
        "context_digest": "$CONTEXT_DIGEST",
    },
    "source_date_epoch": int("$SOURCE_DATE_EPOCH"),
    # Stamped into the image config as OCI labels, so they are digest inputs.
    # Recorded here because a digest mismatch whose only cause is a version
    # string should be readable as such rather than investigated as a
    # non-deterministic build.
    "labels": {"vcs_ref": "$VCS_REF", "version": "$VERSION"},
    "platforms": "$PLATFORMS".split(","),
    # Recorded, never compared: the index covers the provenance attestation,
    # and provenance that matched between two builders would not be provenance.
    "index_digest": "$IMAGE_DIGEST",
    "platform_digests": json.loads(r'''$PLATFORM_DIGESTS'''),
    "binaries": json.loads(r'''$bin_json'''),
    # Recorded, never compared. Two builds that agree are only interesting when
    # the machines that made them differ, so the differences go in the manifest
    # and repro-compare.py ignores this whole object.
    "builder": {
        "host_platform": platform.platform(),
        "host_machine": platform.machine(),
        "docker": run("docker", "version", "--format", "{{.Server.Version}}"),
        "buildx": run("docker", "buildx", "version"),
    },
    "elapsed_seconds": $elapsed,
}
# One number over everything that is supposed to be identical, so a release note
# and a ledger entry have something short to carry.
payload = json.dumps(
    {"platform_digests": manifest["platform_digests"], "binaries": manifest["binaries"]},
    sort_keys=True,
).encode("utf-8")
manifest["artifact_digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()

json.dump(manifest, open(sys.argv[1], "w"), indent=2, sort_keys=True)
open(sys.argv[1], "a").write("\n")
print(json.dumps(
    {k: manifest[k] for k in ("label", "artifact_digest", "platform_digests", "binaries")},
    indent=2,
))
PY

echo "relay-reproduce: wrote $OUT/manifest.json in ${elapsed}s"
