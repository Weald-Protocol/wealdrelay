#!/usr/bin/env bash
# The `sha256/...` pin for a live host, per RFC 7469.
#
#   scripts/relay-pin.sh relay.example.com
#   scripts/relay-pin.sh relay.example.com 8443
#
# The digest is over the DER `SubjectPublicKeyInfo`, not over the certificate, so
# renewing with the same key pair keeps the pin valid. A relay behind a 90-day
# ACME certificate would otherwise warn its operator four times a year and teach
# them to click through, which is worse than not pinning
# (`specs/backend/relay/transport-security.md`).
#
# The operational rule that goes with the output: a client build carries the key
# in service *and* the next one. A build that ships only the key in service
# bricks every client the moment that key is replaced.
#
# Nothing here is Weald-specific. Point it at any TLS host, including your own
# reverse proxy before it fronts a relay, which is the check worth doing first.
set -euo pipefail

HOST="${1:-}"
PORT="${2:-443}"

if [ -z "$HOST" ]; then
  printf 'usage: scripts/relay-pin.sh HOST [PORT]\n' >&2
  exit 2
fi

command -v openssl >/dev/null 2>&1 \
  || { printf 'relay-pin: openssl is required and is not installed.\n' >&2; exit 1; }

# `-servername` so a host behind SNI-based routing answers with its own
# certificate rather than the terminator's default one, which is the mistake that
# makes a pin look wrong when it is the fetch that was wrong.
chain="$(printf '' | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" 2>/dev/null || true)"

if ! printf '%s' "$chain" | grep -q 'BEGIN CERTIFICATE'; then
  printf 'relay-pin: no certificate from %s:%s. Wrong port, no TLS, or unreachable.\n' \
    "$HOST" "$PORT" >&2
  exit 1
fi

pin="$(printf '%s' "$chain" \
  | openssl x509 -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform der 2>/dev/null \
  | openssl dgst -sha256 -binary \
  | openssl base64)"

[ -n "$pin" ] || { printf 'relay-pin: could not read a public key from the leaf certificate.\n' >&2; exit 1; }

printf 'sha256/%s\n' "$pin"

# The leaf's own identity, so an operator can see which certificate produced the
# pin they are about to publish for other people's machines.
printf '%s' "$chain" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/# /'
