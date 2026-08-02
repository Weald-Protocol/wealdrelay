#!/usr/bin/env bash
# Public-repository spec check. The full 30-step gate lives in Weald's private
# build repository; this is the subset that is meaningful here and that an
# outside contributor can run.
#
#   1. every relay error code has a conformance vector
#   2. wire.cddl compiles
#   3. every spec cross-reference resolves
#   4. the licence boundary holds
#   5. house style
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0; SKIP=0
red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
ylw() { printf '\033[33m%s\033[0m\n' "$*"; }
pass() { grn "ok    $*"; }
fail() { red "FAIL  $*"; FAIL=1; }
skip() { ylw "skip  $*"; SKIP=1; }

C="$ROOT/specs/backend/contracts"

# 1. Every relay error code has a vector. A code nobody can produce a failing
#    case for is a code no implementer can test against.
CODES="$C/registries/error-codes.md"
VECTORS="$C/wire/vectors"
if [ -f "$CODES" ] && [ -d "$VECTORS" ]; then
  MISSING=""
  for code in $(grep -oE '^\| `[a-z_]+`' "$CODES" | tr -d '|` ' | sort -u); do
    grep -rq "$code" "$VECTORS" || MISSING="$MISSING $code"
  done
  if [ -n "$MISSING" ]; then fail "error codes with no vector:$MISSING"
  else pass "every relay error code has a vector"; fi
fi

# 2. The formal wire schema compiles.
if command -v cddl >/dev/null 2>&1; then
  if cddl compile-cddl --cddl "$C/wire/wire.cddl" >/dev/null 2>&1; then
    pass "wire.cddl compiles"
  else fail "wire.cddl does not compile"; fi
else
  skip "wire.cddl not compiled (install the cddl crate: cargo install cddl)"
fi

# 3. Every spec cross-reference resolves. This is the check that catches a file
#    left behind when specifications move between repositories.
DANGLING=""
while IFS= read -r ref; do
  [ -e "$ROOT/$ref" ] || DANGLING="$DANGLING $ref"
done < <(grep -rhoE '`specs/backend/[a-zA-Z0-9/._-]+`' "$ROOT/specs" | tr -d '`' | sort -u)
if [ -n "$DANGLING" ]; then
  fail "spec references that resolve to nothing:"
  for d in $DANGLING; do echo "      $d"; done
else pass "every spec reference resolves"; fi

# 4. The licence boundary. This repository is wholly Apache 2.0, so every crate
#    carries the licence and every source file says so.
LIC_FAIL=""
for crate in backend/wealdrelay backend/weald-mls; do
  [ -f "$ROOT/$crate/LICENSE" ] || LIC_FAIL="$LIC_FAIL $crate/LICENSE"
  [ -f "$ROOT/$crate/NOTICE" ]  || LIC_FAIL="$LIC_FAIL $crate/NOTICE"
done
[ -f "$ROOT/LICENSE" ] || LIC_FAIL="$LIC_FAIL LICENSE"
grep -q '^license = "Apache-2.0"' "$ROOT/Cargo.toml" \
  || LIC_FAIL="$LIC_FAIL Cargo.toml:workspace.package.license"
MISSING_SPDX=$(find "$ROOT/backend" -name '*.rs' -not -path '*/target/*' -print0 2>/dev/null \
  | xargs -0 grep -L 'SPDX-License-Identifier: Apache-2.0' 2>/dev/null | sed "s|$ROOT/||")
if [ -n "$LIC_FAIL" ]; then fail "the licence boundary is missing files:$LIC_FAIL"
elif [ -n "$MISSING_SPDX" ]; then
  fail "Rust sources with no SPDX header:"; echo "$MISSING_SPDX" | sed 's/^/      /'
else pass "Apache 2.0, NOTICE and SPDX headers all present"; fi

# 5. House style.
EM=$(grep -rln $'—' "$ROOT/specs" 2>/dev/null)
if [ -n "$EM" ]; then fail "em dash found in:"; echo "$EM" | sed "s|$ROOT/||; s/^/      /"
else pass "no em dashes"; fi

echo
if [ "$FAIL" -ne 0 ]; then red "spec-check FAILED"; exit 1; fi
[ "$SKIP" -ne 0 ] && ylw "spec-check passed with skipped checks"
grn "spec-check passed"
