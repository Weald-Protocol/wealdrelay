#!/bin/sh
# The compose bundle installer.
#
# It is attached to every release and shipped inside the bundle it fetches, so
# there are two ways to have it: download it from the release page for the tag
# you want, or take it from a clone of the repository. There is no install
# one-liner piped from a domain, and there will not be one: an installer you
# cannot read before it runs is an installer you cannot check.
#
#   sh install.sh                                  the newest release
#   WEALD_RELAY_VERSION=wealdrelay-v0.1.0 sh install.sh    a specific tag
#
# specs/backend/relay/server.md distribution channel 2. It fetches the compose
# bundle for a release, verifies its checksum, generates the two passwords, and
# stops. It does not run `docker compose up`, because a script that starts a
# service the moment it is run has taken a decision that belongs to the
# operator.
#
# POSIX sh on purpose. This runs on whatever a fresh VPS happens to have.
set -eu

REPO="${WEALD_RELAY_REPO:-Weald-Protocol/wealdrelay}"
VERSION="${WEALD_RELAY_VERSION:-latest}"
DIR="${WEALD_RELAY_DIR:-weald-relay}"

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required and is not installed. $2"
}

need curl "Install curl, then run this again."
need tar "Install tar, then run this again."

if ! command -v docker >/dev/null 2>&1; then
  die "docker is required. See https://docs.docker.com/engine/install/ and run this again."
fi
if ! docker compose version >/dev/null 2>&1; then
  die "the docker compose plugin is required. Install docker-compose-plugin and run this again."
fi

[ -e "$DIR" ] && die "$DIR already exists. Move it aside, or set WEALD_RELAY_DIR."

if [ "$VERSION" = latest ]; then
  url="https://github.com/${REPO}/releases/latest/download/weald-relay-compose.tar.gz"
else
  url="https://github.com/${REPO}/releases/download/${VERSION}/weald-relay-compose.tar.gz"
fi

say "Fetching the compose bundle from ${url}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/bundle.tar.gz" \
  || die "could not download the bundle. Check the version and your network."

# Every release publishes the bundle's SHA-256 beside it. Verified when it is
# reachable; a missing checksum file is a hard failure rather than a shrug,
# because an unverified download is the one step of this install with real
# consequences.
curl -fsSL "${url}.sha256" -o "$tmp/bundle.sha256" \
  || die "the bundle checksum is missing from the release. Refusing to install unverified."

expected="$(cut -d' ' -f1 < "$tmp/bundle.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/bundle.tar.gz" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/bundle.tar.gz" | cut -d' ' -f1)"
else
  die "neither sha256sum nor shasum is installed, so the bundle cannot be verified."
fi
[ "$expected" = "$actual" ] || die "checksum mismatch. Expected $expected, got $actual."
say "Checksum verified."

mkdir -p "$DIR"
tar -xzf "$tmp/bundle.tar.gz" -C "$DIR" --strip-components=1

# Passwords, generated here so nobody ships the example values. These guard
# ciphertext: the relay is blind and cannot read what they protect.
random() {
  if [ -r /dev/urandom ]; then
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 40
  else
    die "no /dev/urandom, so no passwords can be generated. Edit .env by hand."
  fi
}

if [ ! -f "$DIR/.env" ]; then
  cp "$DIR/.env.example" "$DIR/.env"
  pg="$(random)"
  mo="$(random)"
  # A temporary file and a move, so an interrupted edit cannot leave a
  # half-written .env that compose would read.
  sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pg}|" \
      -e "s|^MINIO_ROOT_PASSWORD=.*|MINIO_ROOT_PASSWORD=${mo}|" \
      "$DIR/.env" > "$DIR/.env.tmp"
  mv "$DIR/.env.tmp" "$DIR/.env"
  chmod 600 "$DIR/.env"
fi

say ""
say "Installed into ./${DIR}"
say ""
say "Both passwords in .env are generated. Do not copy .env.example over it."
say ""
say "Two things left:"
say "  1. cd ${DIR} && \$EDITOR .env      set WEALD_RELAY_HOSTNAME to your hostname"
say "  2. docker compose up -d"
say ""
say "Then read the one-time enrollment URL and code out of the log:"
say "  docker compose logs relay"
say ""
say "It expires in 24 hours or on first use, and the first device to open it"
say "becomes the workspace trust root. The link is reprinted on every start while"
say "the workspace is unenrolled. The code is not: the relay keeps only its hash."
