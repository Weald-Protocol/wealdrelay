# The relay image, per specs/backend/relay/server.md section 1: multi-arch amd64
# and arm64, distroless base, non-root, no shell.
#
# Base images are pinned by digest and never by tag, per
# specs/backend/build/environments.md. A digest change is a deliberate commit.
#
# The build cross-compiles from the native BUILDPLATFORM rather than running an
# emulated toolchain on TARGETPLATFORM. Emulated Rust builds of this crate take
# tens of minutes on arm64 under QEMU, and a release pipeline nobody waits for is
# a release pipeline nobody runs.

# rust:1.97.1-bookworm, matching rust-toolchain.toml. glibc/bookworm so the
# artifact matches the distroless cc-debian12 runtime below.
FROM --platform=$BUILDPLATFORM rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder

ARG TARGETARCH
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Reproducibility inputs. SOURCE_DATE_EPOCH is passed by the release workflow
# from the tagged commit's timestamp; the default keeps a local build honest
# rather than stamping "now".
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# blake3 and ring compile C, so a C cross-compiler is required for the target,
# not just the Rust std for it. Installed only when the target differs from the
# build host, and in whichever direction that happens to be: CI builds amd64
# natively and cross-builds arm64, a developer on an Apple machine does the
# reverse, and neither should be the only one that works.
RUN set -eux; \
    build="$(dpkg --print-architecture)"; \
    if [ "${build}" != "${TARGETARCH}" ]; then \
      case "${TARGETARCH}" in \
        arm64) pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
        amd64) pkgs="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
      esac; \
      apt-get update; \
      apt-get install -y --no-install-recommends ${pkgs}; \
      rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /src

# Dependency layer first: copy only the manifests so a source-only change does
# not re-resolve and re-download the whole graph.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backend/wealdrelay/Cargo.toml backend/wealdrelay/Cargo.toml
COPY backend/weald-mls/Cargo.toml backend/weald-mls/Cargo.toml

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "${target}" > /tmp/target; \
    rustup target add "${target}"

# Stub sources, so the dependency graph builds and caches without the crate.
RUN set -eux; \
    mkdir -p backend/wealdrelay/src backend/weald-mls/src; \
    echo 'fn main() {}' > backend/wealdrelay/src/main.rs; \
    touch backend/wealdrelay/src/lib.rs backend/weald-mls/src/lib.rs; \
    target="$(cat /tmp/target)"; \
    cargo build --release --locked --target "${target}" -p wealdrelay || true; \
    rm -rf backend/wealdrelay/src backend/weald-mls/src

COPY . .

# --locked so the lockfile is the contract; --remap-path-prefix so the build
# directory does not end up inside the binary, which is one of the things that
# stops two machines producing the same bytes.
RUN set -eux; \
    target="$(cat /tmp/target)"; \
    build="$(dpkg --print-architecture)"; \
    if [ "${build}" != "${TARGETARCH}" ]; then \
      case "${target}" in \
        aarch64-unknown-linux-gnu) \
          export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
          export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc; \
          ;; \
        x86_64-unknown-linux-gnu) \
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc; \
          export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc; \
          ;; \
      esac; \
    fi; \
    export RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=${CARGO_HOME:-/usr/local/cargo}=/cargo"; \
    cargo build --release --locked --target "${target}" -p wealdrelay; \
    install -D "target/${target}/release/wealdrelay" /out/wealdrelay; \
    touch -d "@${SOURCE_DATE_EPOCH}" /out/wealdrelay

# The binary on its own, for the release manifest and for
# `specs/backend/relay/verification.md` proof 2: every release publishes the
# binary's SHA-256, and the number it publishes has to be the number of the
# binary that is actually inside the image rather than of a second build that
# merely came from the same source.
#
#   docker buildx build --target artifact --platform linux/amd64 \
#     --output type=local,dest=out .
#
# `scratch` so the export is one file and its hash is the binary's hash.
FROM scratch AS artifact
COPY --from=builder /out/wealdrelay /wealdrelay

# gcr.io/distroless/cc-debian12:nonroot. cc rather than static, because the
# binary links glibc; nonroot rather than latest, because the process must not
# be uid 0. No shell is present in this image by construction, which is the
# point: a relay that cannot be shelled into is a relay whose operator cannot be
# talked into reading an envelope.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e

COPY --from=builder /out/wealdrelay /usr/local/bin/wealdrelay

# Apache 2.0 section 4 obliges a redistribution to carry the license and, where
# the work has one, the NOTICE. The image is a redistribution, so both travel
# inside it rather than only in the repository.
COPY backend/wealdrelay/LICENSE backend/wealdrelay/NOTICE /usr/local/share/wealdrelay/

# Provenance, as OCI annotations rather than prose. `revision` and `version` are
# passed by the release workflow from the tagged commit; the defaults keep a
# local build from claiming to be a release.
ARG VCS_REF=unknown
ARG VERSION=0.0.0-dev

LABEL org.opencontainers.image.title="wealdrelay" \
      org.opencontainers.image.description="The Weald blind relay. Stores and forwards envelopes it cannot read." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Dicyanin Labs" \
      org.opencontainers.image.source="https://github.com/hunterh37/WealdRelay" \
      org.opencontainers.image.documentation="https://github.com/hunterh37/WealdRelay/blob/main/backend/wealdrelay/deploy/README.md" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}"

# 65532 is distroless's `nonroot`. Stated explicitly rather than inherited, so a
# base image change cannot silently promote the process to root.
USER 65532:65532

# The public listener (WEALD_RELAY_LISTEN) and the private observability
# listener (WEALD_RELAY_OBSERVABILITY_LISTEN). Documentation only: EXPOSE
# publishes nothing on its own, and the observability port must stay on
# provider-private networking per specs/backend/relay/server.md.
EXPOSE 8443
EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/wealdrelay"]
