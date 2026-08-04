#!/usr/bin/env bash
# Enforce the contracts in specs/backend/contracts/.
#
# Wired into the same gate the backend-build skill runs. A contract nobody can
# violate accidentally is worth more than a document everybody agrees with.
#
# External tools. Each check skips loudly if its tool is missing:
#   spectral   npm i -g @stoplight/spectral-cli
#   cddl       cargo install cddl
#   mmdc       npm i -g @mermaid-js/mermaid-cli
#   yq         pip3 install yq --break-system-packages
#   jq
#
#   scripts/spec-check.sh --strict    a skipped check is a failure
#
# `--strict` exists because of what happened the first time these four were
# actually installed: three checks that had been skipping for the life of the
# project went red immediately. `wire.cddl` had never been compiled, two mermaid
# diagrams had never been parsed (one used `FK UK` where the grammar wants
# `FK,UK`, the other put a `;` in a sequence Note, which is a statement separator),
# and the OpenAPI document had nine operations with no description and no ruleset
# to check them against. None of that was a hard problem. All of it survived
# because a yellow skip line reads, to anyone scanning output, exactly like a
# green pass. CI runs this with --strict so that the tools are not optional
# anywhere it matters, and a laptop missing one still gets a useful run.

set -uo pipefail

STRICT=0
for arg in "$@"; do
  case "$arg" in
    --strict) STRICT=1 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "spec-check: unknown argument: $arg" >&2; exit 64 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C="$ROOT/specs/backend/contracts"
FAIL=0
SKIP=0

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
fail() { red "FAIL  $*"; FAIL=1; }
pass() { grn "ok    $*"; }
skip() { ylw "skip  $*"; SKIP=1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Which tree is this. `github.com/Weald-Protocol/wealdrelay` runs this same file
# byte for byte over a subset of this one (specs/backend/build/relay-publication.md),
# so three of the checks below are about files that subset deliberately excludes:
# the hosted control plane's OpenAPI document, every citation that points into an
# unpublished specification, and the proprietary client's licence note. None of
# those is a defect there, and asserting them there is what has kept that
# repository's ci red on every push since the mirror became a byte-exact copy.
#
# They are not weakened, they are located. Every published file is byte-identical
# to a file in this tree, so a check that holds here holds for the whole published
# subset too, and the published tree gets a counted note rather than a failure.
# `specs/backend/build/` is never published, which is how the two are told apart.
PUBLISHED_TREE=0
[ -d "$ROOT/specs/backend/build" ] || PUBLISHED_TREE=1
note() { ylw "note  $*"; }

echo "spec-check: $C"
[ "$PUBLISHED_TREE" -eq 1 ] && echo "spec-check: the published tree; three checks are the monorepo's to make"
echo

# --------------------------------------------------------------------------
# 1. OpenAPI lints clean
# --------------------------------------------------------------------------
OAS="$C/api/openapi.yaml"
if [ ! -f "$OAS" ] && [ "$PUBLISHED_TREE" -eq 1 ]; then
  # The document describes the hosted control plane's HTTP surface, which is not
  # part of the protocol and is not published.
  note "openapi.yaml is not published; the monorepo lints it"
elif [ ! -f "$OAS" ]; then
  fail "openapi.yaml missing"
elif have spectral; then
  # The ruleset is named explicitly rather than discovered. Spectral searches from
  # the process working directory, not from the document, so discovery would make
  # this check pass or fail depending on where it was invoked from, which is worse
  # than not having it.
  if spectral lint "$OAS" --ruleset "$C/api/.spectral.yaml" --fail-severity=warn >/tmp/spectral.out 2>&1; then
    pass "openapi lints clean"
  else
    fail "openapi lint"; sed 's/^/      /' /tmp/spectral.out
  fi
elif have yq; then
  if yq -e '.openapi' "$OAS" >/dev/null 2>&1; then
    pass "openapi parses (install spectral for a real lint)"
  else
    fail "openapi does not parse"
  fi
else
  skip "openapi lint (no spectral, no yq)"
fi

# --------------------------------------------------------------------------
# 2. Every problem type declared in the OpenAPI exists in the registry,
#    and every registry code is referenced by at least one operation.
# --------------------------------------------------------------------------
REG="$C/registries/error-codes.md"
if [ -f "$OAS" ] && [ -f "$REG" ]; then
  DECLARED=$(grep -o 'x-problem-types: \[[^]]*\]' "$OAS" \
    | sed 's/x-problem-types: \[//; s/\]//' | tr ',' '\n' | tr -d ' ' | sort -u | grep -v '^$')
  REGISTERED=$(grep -oE '^\| `[a-z_]+` \| [0-9]{3} \|' "$REG" \
    | sed 's/^| `//; s/` .*//' | sort -u)

  MISSING=$(comm -23 <(echo "$DECLARED") <(echo "$REGISTERED"))
  if [ -n "$MISSING" ]; then
    fail "problem types declared in openapi but absent from the registry:"
    echo "$MISSING" | sed 's/^/      /'
  else
    pass "every declared problem type is registered"
  fi

  ORPHAN=$(comm -13 <(echo "$DECLARED") <(echo "$REGISTERED"))
  if [ -n "$ORPHAN" ]; then
    fail "registered problem types no operation declares:"
    echo "$ORPHAN" | sed 's/^/      /'
  else
    pass "every registered problem type is reachable"
  fi
fi

# --------------------------------------------------------------------------
# 3. Every relay frame error code has a negative vector
# --------------------------------------------------------------------------
MAN="$C/wire/vectors/manifest.json"
if [ -f "$MAN" ] && [ -f "$REG" ]; then
  CODES=$(grep -oE '^\| `(retry|reject|denied|quota|version)/[a-z_]+`' "$REG" \
    | sed 's/^| `//; s/`$//' | sort -u)
  if have jq; then
    COVERED=$(jq -r '.vectors[].expect' "$MAN" | sort -u)
  else
    COVERED=$(grep -oE '"expect": "[^"]+"' "$MAN" | sed 's/"expect": "//; s/"//' | sort -u)
  fi
  UNCOVERED=$(comm -23 <(echo "$CODES") <(echo "$COVERED"))
  if [ -n "$UNCOVERED" ]; then
    fail "relay error codes with no negative vector in the corpus:"
    echo "$UNCOVERED" | sed 's/^/      /'
  else
    pass "every relay error code has a vector"
  fi

  # The silence-is-normal vectors are load-bearing. Losing one turns the
  # split-view detector into a false-positive generator.
  for v in attest-device-absent-quietly-is-normal attest-agent-proxied-is-normal \
           attest-agent-issuer-offline-is-normal clock-skew-under-bound-is-silent; do
    grep -q "\"$v\"" "$MAN" || fail "required silence-is-normal vector removed: $v"
  done
  pass "silence-is-normal vectors present"
fi

# --------------------------------------------------------------------------
# 4. CDDL is valid, and every event kind in wire.md appears in it
# --------------------------------------------------------------------------
CDDL="$C/wire/wire.cddl"
if [ ! -f "$CDDL" ]; then
  fail "wire.cddl missing"
elif have cddl; then
  if cddl compile-cddl --cddl "$CDDL" >/tmp/cddl.out 2>&1; then
    pass "wire.cddl compiles"
  else
    fail "wire.cddl"; sed 's/^/      /' /tmp/cddl.out
  fi
else
  skip "cddl compile (cargo install cddl)"
fi

WIRE="$ROOT/specs/backend/relay/wire.md"
if [ -f "$WIRE" ] && [ -f "$CDDL" ]; then
  MISSINGKIND=""
  while read -r hexk; do
    dec=$((16#${hexk#0x}))
    grep -qE "= *$dec\b" "$CDDL" || MISSINGKIND="$MISSINGKIND $hexk"
  done < <(grep -oE '`0x[0-9A-F]{4}`' "$WIRE" | tr -d '`' | sort -u)
  if [ -n "$MISSINGKIND" ]; then
    fail "event kinds in wire.md missing from wire.cddl:$MISSINGKIND"
  else
    pass "every event kind is in the CDDL"
  fi
fi

# --------------------------------------------------------------------------
# 5. Every mermaid diagram parses
# --------------------------------------------------------------------------
if have mmdc; then
  BAD=""
  # mmdc drives headless Chrome. On a CI runner the default sandbox cannot be
  # entered, and every diagram then "fails to parse" for a reason that has
  # nothing to do with the diagram. The flags are passed everywhere so local and
  # ci run the same command, and the last error is kept so a real syntax break
  # is still diagnosable instead of being swallowed with the launch failure.
  PUPPETEER_CFG="$(mktemp -t puppeteer-XXXXXX)"
  printf '{"args":["--no-sandbox","--disable-setuid-sandbox","--disable-dev-shm-usage"]}\n' >"$PUPPETEER_CFG"
  MMDC_LOG="$(mktemp -t mmdc-XXXXXX)"
  for f in "$C"/diagrams/*.mmd; do
    mmdc -p "$PUPPETEER_CFG" -i "$f" -o "/tmp/$(basename "$f").svg" >"$MMDC_LOG" 2>&1 ||
      BAD="$BAD $(basename "$f")"
  done
  if [ -n "$BAD" ]; then
    fail "mermaid parse:$BAD"
    sed 's/^/      /' "$MMDC_LOG" >&2
  else
    pass "every diagram parses"
  fi
  rm -f "$PUPPETEER_CFG" "$MMDC_LOG"
else
  skip "mermaid parse (npm i -g @mermaid-js/mermaid-cli)"
fi

# --------------------------------------------------------------------------
# 6. Every relative link across specs/backend resolves
# --------------------------------------------------------------------------
BROKEN=0
UNPUBLISHED=0
while IFS= read -r f; do
  d="$(dirname "$f")"
  while read -r link; do
    [ -z "$link" ] && continue
    case "$link" in http*|mailto:*|\#*) continue;; esac
    tgt="${link%%#*}"
    if [ -e "$d/$tgt" ] || [ -e "$ROOT/$tgt" ]; then continue; fi
    fail "broken link in ${f#$ROOT/}: $tgt"; BROKEN=1
  done < <(grep -oE '\]\([^)]+\)' "$f" | sed 's/](//; s/)$//')
  # Backtick-quoted spec paths are the dominant convention in this tree.
  while read -r p; do
    [ -e "$ROOT/$p" ] && continue
    if [ "$PUBLISHED_TREE" -eq 1 ]; then UNPUBLISHED=$((UNPUBLISHED + 1)); continue; fi
    fail "dangling spec reference in ${f#$ROOT/}: $p"; BROKEN=1
  done < <(grep -oE '`specs/[A-Za-z0-9._/-]+\.(md|yaml|cddl|json|mmd)`' "$f" | tr -d '`' | sort -u)
done < <(find "$ROOT/specs/backend" -name '*.md')
if [ "$PUBLISHED_TREE" -eq 1 ]; then
  # A citation into an unpublished document is copied rather than rewritten, on
  # purpose: relay-publication.md records both alternatives being tried and being
  # worse, and specs/backend/hosted-service.md tells a reader who follows one why
  # it goes nowhere. A broken link between two published files is still a failure.
  [ "$BROKEN" -eq 0 ] && pass "every link between published specs resolves"
  note "$UNPUBLISHED citation(s) into specifications this repository does not publish"
elif [ "$BROKEN" -eq 0 ]; then
  pass "every spec reference resolves"
fi

# --------------------------------------------------------------------------
# 7. State machine tables: every `To` state is a declared state
# --------------------------------------------------------------------------
SM="$C/state-machines/instance-lifecycle.md"
if [ -f "$SM" ]; then
  STATES=$(awk '/^## States/,/^## Transitions/' "$SM" \
    | grep -oE '^\| `[a-z_]+`' | sed 's/^| `//; s/`//' | sort -u)
  TARGETS=$(awk '/^## Transitions/,/^## Illegal/' "$SM" \
    | grep -oE '\| `[a-z_]+` \| [A-Z]' | sed 's/^| `//; s/`.*//' | sort -u)
  UNDEF=$(comm -13 <(echo "$STATES") <(echo "$TARGETS"))
  if [ -n "$UNDEF" ]; then
    fail "transition targets that are not declared states:"; echo "$UNDEF" | sed 's/^/      /'
  else
    pass "no undefined transition targets"
  fi
  for s in $STATES; do
    grep -q "\`$s\`" <<<"$(awk '/^## Transitions/,0' "$SM")" \
      || fail "unreachable state, no transition mentions it: $s"
  done
fi

# --------------------------------------------------------------------------
# 8. Every control plane column is classified
# --------------------------------------------------------------------------
CP="$ROOT/specs/backend/cloud/control-plane.md"
DC="$C/registries/data-classification.md"
if [ -f "$CP" ] && [ -f "$DC" ]; then
  # `see below` and `unique` are prose inside the schema fence, not columns.
  NOISE='^(see|below|unique|and|the|for|with)$'
  UNCLASSIFIED=""
  for col in $(awk '/^```$/{f=0} f{print} /^accounts /{f=1}' "$CP" \
      | grep -oE '[a-z_]{3,}' | grep -vE "$NOISE" | sort -u); do
    grep -q "$col" "$DC" || UNCLASSIFIED="$UNCLASSIFIED $col"
  done
  if [ -n "$UNCLASSIFIED" ]; then
    fail "schema fields with no data-classification row:$UNCLASSIFIED"
  else
    pass "every schema field is classified"
  fi
fi

# --------------------------------------------------------------------------
# 9. The open source boundary holds
#
# The relay is Apache 2.0 and the client is not, which is a claim the website,
# the self-host guide and the protocol specification all make on our behalf.
# A crate that loses its LICENSE, a source file that ships without an SPDX
# header, or a workspace that quietly reverts to a different license would make
# every one of those documents wrong, and nobody would notice from the outside
# until someone tried to fork us.
# --------------------------------------------------------------------------
LICENSE_FAIL=""
for crate in backend/wealdrelay backend/weald-mls; do
  [ -f "$ROOT/$crate/LICENSE" ] || LICENSE_FAIL="$LICENSE_FAIL $crate/LICENSE"
  [ -f "$ROOT/$crate/NOTICE" ] || LICENSE_FAIL="$LICENSE_FAIL $crate/NOTICE"
done
# The root licence file differs by tree and both are load bearing. Here it is
# `LICENSE.md`, the note saying the macOS client is proprietary and outside this
# workspace. There it is `LICENSE`, the Apache 2.0 text itself, because that
# repository is the licensed artifact rather than a note about one.
if [ "$PUBLISHED_TREE" -eq 1 ]; then
  [ -f "$ROOT/LICENSE" ] || LICENSE_FAIL="$LICENSE_FAIL LICENSE"
else
  [ -f "$ROOT/LICENSE.md" ] || LICENSE_FAIL="$LICENSE_FAIL LICENSE.md"
fi
grep -q '^license = "Apache-2.0"' "$ROOT/Cargo.toml" \
  || LICENSE_FAIL="$LICENSE_FAIL Cargo.toml:workspace.package.license"

MISSING_SPDX=$(find "$ROOT/backend/wealdrelay" "$ROOT/backend/weald-mls" \
  -name '*.rs' -not -path '*/target/*' -print0 2>/dev/null \
  | xargs -0 grep -L 'SPDX-License-Identifier: Apache-2.0' 2>/dev/null \
  | sed "s|$ROOT/||")

if [ -n "$LICENSE_FAIL" ]; then
  fail "the open source boundary is missing files:$LICENSE_FAIL"
elif [ -n "$MISSING_SPDX" ]; then
  fail "Rust sources with no SPDX header:"
  echo "$MISSING_SPDX" | sed 's/^/      /'
else
  pass "relay and MLS binding carry Apache 2.0, NOTICE and SPDX headers"
fi

# --------------------------------------------------------------------------
# 10. House style. These are project rules, not preferences.
# --------------------------------------------------------------------------
EM=$(grep -rln $'—' "$ROOT/specs/backend" 2>/dev/null)
if [ -n "$EM" ]; then fail "em dash found in:"; echo "$EM" | sed "s|$ROOT/||; s/^/      /"; else pass "no em dashes"; fi

# --------------------------------------------------------------------------
echo
if [ "$FAIL" -ne 0 ]; then red "spec-check FAILED"; exit 1; fi
if [ "$SKIP" -ne 0 ]; then
  if [ "$STRICT" -eq 1 ]; then
    red "spec-check FAILED: a check was skipped and --strict was asked for."
    red "Install the tool named beside the skip. Every skip above has one."
    exit 1
  fi
  ylw "spec-check passed with skipped checks"
fi
grn "spec-check passed"
