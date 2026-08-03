#!/usr/bin/env bash
#
# Print the SPKI pin for a live host, in the form RelayKnownHosts wants.
#
#   ./scripts/relay-pin.sh api.weald.team
#   ./scripts/relay-pin.sh some-slug.weald.team 443
#
# The digest is SHA-256 over the DER SubjectPublicKeyInfo, base64, which is what
# RFC 7469 pins and what RelaySPKI computes on the client. Pinning the key rather
# than the certificate is what lets an ACME renewal keep the same pin, provided
# the renewal reuses the key pair.
#
# Print both the serving key and the standby key, and ship both, before rotating.
# A build that ships only the key in service is a build that bricks every client
# the moment that key is replaced. See specs/backend/relay/transport-security.md.
set -euo pipefail

host="${1:-}"
port="${2:-443}"

if [[ -z "$host" ]]; then
    echo "usage: $0 <host> [port]" >&2
    exit 2
fi

for tool in openssl base64; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "$0: $tool is required" >&2
        exit 1
    }
done

# The leaf, as served. `-servername` so a host behind SNI answers with its own
# certificate rather than the terminator's default, which is the mistake that
# produces a pin that refuses the host it was taken from.
leaf="$(
    openssl s_client -connect "${host}:${port}" -servername "$host" \
        </dev/null 2>/dev/null |
        openssl x509 -outform der 2>/dev/null | base64
)"

if [[ -z "$leaf" ]]; then
    echo "$0: no certificate from ${host}:${port}" >&2
    exit 1
fi

digest="$(
    printf '%s' "$leaf" | base64 --decode |
        openssl x509 -inform der -pubkey -noout |
        openssl pkey -pubin -outform der |
        openssl dgst -sha256 -binary | base64
)"

negotiated="$(
    openssl s_client -connect "${host}:${port}" -servername "$host" \
        </dev/null 2>/dev/null | awk '/^ *Protocol *:/ { print $3; exit }'
)"

expiry="$(
    printf '%s' "$leaf" | base64 --decode |
        openssl x509 -inform der -noout -enddate | cut -d= -f2
)"

echo "host:       ${host}:${port}"
echo "protocol:   ${negotiated:-unknown}"
echo "expires:    ${expiry}"
echo
echo "Paste into RelayKnownHosts.entries, alongside the standby key:"
echo
echo "    RelayPin(wireValue: \"sha256/${digest}\")!,"
