#!/usr/bin/env bash
# Rewrite the Homebrew formula from a published release, and nothing else.
#
#   scripts/release-homebrew.sh wealdrelay-v0.1.0
#   scripts/release-homebrew.sh wealdrelay-v0.1.0 --out /path/to/homebrew-tap/Formula
#
# The formula points at the release's own signed tarballs rather than at a bottle,
# so that what Homebrew installs is byte-identical to what the release notes name
# (`specs/backend/relay/verification.md`, proof 2). A bottle would be one more
# artifact nobody verified.
#
# The version, the URLs and the checksums are therefore not editable by hand: they
# are read from the release's published `.sha256` files, which is the only source
# that cannot disagree with the artifact. Editing them by hand is how a tap and a
# release stop agreeing, and the person who finds out is a customer whose
# `brew install` fails a checksum.
#
# Needs `gh` and network access to the release. Writes the rewritten formula to
# stdout unless `--out` is given.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORMULA="$ROOT/backend/wealdrelay/deploy/homebrew/wealdrelay.rb"
REPO="${WEALD_RELAY_REPO:-hunterh37/WealdRelay}"

TAG="${1:-}"
OUT=""
shift || true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-}"; [ -n "$OUT" ] || { printf 'release-homebrew: --out needs a directory\n' >&2; exit 2; }; shift 2 ;;
    *) printf 'release-homebrew: unknown option %s\n' "$1" >&2; exit 2 ;;
  esac
done

if [ -z "$TAG" ]; then
  printf 'usage: scripts/release-homebrew.sh TAG [--out DIR]\n' >&2
  exit 2
fi

command -v gh >/dev/null 2>&1 \
  || { printf 'release-homebrew: the gh CLI is required.\n' >&2; exit 1; }
[ -f "$FORMULA" ] || { printf 'release-homebrew: no formula at %s\n' "$FORMULA" >&2; exit 1; }

# The version Homebrew shows, and the string the formula's own smoke test asserts
# `wealdrelay --version` prints. The tag carries a `wealdrelay-v` prefix that a
# version string does not.
VERSION="${TAG#wealdrelay-v}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Only the three targets the formula serves. A missing checksum is a hard failure:
# a formula with a stale sha256 for one platform is worse than no formula, because
# it fails for exactly one group of people and looks fine to everybody else.
TARGETS="aarch64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

for target in $TARGETS; do
  asset="wealdrelay-${target}.tar.gz.sha256"
  gh release download "$TAG" --repo "$REPO" --pattern "$asset" --dir "$work" \
    || { printf 'release-homebrew: %s is not published for %s.\n' "$asset" "$TAG" >&2; exit 1; }
done

sha_for() {
  cut -d' ' -f1 < "$work/wealdrelay-${1}.tar.gz.sha256"
}

DARWIN_ARM="$(sha_for aarch64-apple-darwin)"
LINUX_ARM="$(sha_for aarch64-unknown-linux-musl)"
LINUX_X86="$(sha_for x86_64-unknown-linux-musl)"

for value in "$DARWIN_ARM" "$LINUX_ARM" "$LINUX_X86"; do
  printf '%s' "$value" | grep -Eq '^[0-9a-f]{64}$' \
    || { printf 'release-homebrew: %s is not a sha256.\n' "$value" >&2; exit 1; }
done

# Substituted rather than templated, so the formula in the repository stays a
# valid, readable Ruby file that a reviewer can diff against the tap.
rendered="$work/wealdrelay.rb"
sed \
  -e "s|^  version \".*\"$|  version \"${VERSION}\"|" \
  -e "s|/releases/download/wealdrelay-v[^/]*/|/releases/download/${TAG}/|g" \
  -e "s|hunterh37/WealdRelay|${REPO}|g" \
  "$FORMULA" > "$rendered"

# One checksum per url, in file order, matched to the target named in the url
# above it rather than to a line number.
python3 - "$rendered" "$DARWIN_ARM" "$LINUX_ARM" "$LINUX_X86" << 'PY'
import re, sys
path, darwin_arm, linux_arm, linux_x86 = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
by_target = {
    "aarch64-apple-darwin": darwin_arm,
    "aarch64-unknown-linux-musl": linux_arm,
    "x86_64-unknown-linux-musl": linux_x86,
}
lines = open(path).read().splitlines(keepends=True)
current = None
seen = set()
for index, line in enumerate(lines):
    match = re.search(r"wealdrelay-([a-z0-9_]+-[a-z0-9-]+)\.tar\.gz", line)
    if match:
        current = match.group(1)
        continue
    if re.match(r'\s*sha256 "', line):
        if current is None or current not in by_target:
            raise SystemExit(f"a sha256 line at {index + 1} follows no known target url")
        lines[index] = re.sub(r'"[0-9a-f]{64}"', f'"{by_target[current]}"', line)
        seen.add(current)
        current = None
missing = set(by_target) - seen
if missing:
    raise SystemExit(f"no sha256 line was rewritten for: {', '.join(sorted(missing))}")
open(path, "w").writelines(lines)
PY

if grep -q '0000000000000000' "$rendered"; then
  printf 'release-homebrew: a placeholder checksum survived the rewrite.\n' >&2
  exit 1
fi

if [ -n "$OUT" ]; then
  mkdir -p "$OUT"
  cp "$rendered" "$OUT/wealdrelay.rb"
  printf 'release-homebrew: wrote %s/wealdrelay.rb for %s\n' "$OUT" "$TAG"
else
  cat "$rendered"
fi
