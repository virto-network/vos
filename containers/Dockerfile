# vosx slim runtime image.
#
# Multi-stage build per `project_container_packaging_plan`:
#
#   builder  → rust:1-bookworm + workspace src + cargo build --release
#   runtime  → debian:12-slim with vosx + .so extensions + entrypoint
#
# What's NOT shipped:
#   - the riscv64em-javm Rust toolchain (the `dev` extension's
#     compile path would need it; the slim image is for ai/admin
#     workflows and falls back to the bundled `vosx/blobs/*.elf`
#     for the bootstrap actors).
#   - http-gateway — D2 (release-LTO hang) blocks release builds.
#     Re-add `-p http-gateway` to the cargo line once that clears.
#   - dev-extension — needs cargo/rustc at runtime to compile
#     guest actors. A `vosx:dev` variant will add it; the slim
#     image targets ai + admin use cases.
#
# Build (from workspace root):
#   docker build -f containers/Dockerfile -t vosx:slim .
#
# Run (single-process exemplar; see containers/ai-daemon.yml
# for a compose flow):
#   docker run --rm -it \
#       -v vosx-data:/var/lib/vosx \
#       -v vosx-config:/etc/vosx \
#       -v vosx-cache:/var/cache/vosx \
#       -p 4001:4001 \
#       -e VOSX_SPACE=demo \
#       vosx:slim

# ── 1. Builder image ─────────────────────────────────────────────
# Pinned nightly matches workspace's rust-toolchain.toml.
# Bookworm-flavoured base because we ship debian-slim runtime —
# matched glibc keeps the binary portable across the boundary.
FROM rust:1-bookworm AS builder

# rustup + nightly channel matching the workspace pin. The
# rust-toolchain.toml in the workspace root tells rustup which
# nightly to install on first `cargo` invocation.
RUN rustup toolchain install nightly --profile minimal --component rustfmt clippy

# pkg-config + build essentials. vos itself has zero native C
# deps (rustls, ureq); the build tools are for transitive
# dev-deps (e.g. wasm runtimes pulled in by some optional
# features) and cost ~50MB in the builder.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Layer 1: dependency cache via a stub. Copy only Cargo manifests
# first so `cargo fetch` can populate the registry cache before
# any source changes invalidate it.
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
# Workspace member manifests + dummy lib.rs files for each
# member would normally go here, but the workspace shape is
# large and the cache savings drop off quickly. Skip the
# stubbing dance; rely on Docker's RUN-step caching for the
# full source.

# Full source copy. .dockerignore keeps target/, .git/, and the
# examples/ build artifacts out.
COPY . .

# Build vosx + ai-extension. dev-extension is omitted from the
# slim image (it needs cargo+rustc at runtime). http-gateway is
# blocked on D2. Release profile because the daemon is the long-
# running process; +nightly is implied by rust-toolchain.toml.
ENV CARGO_TERM_COLOR=always
RUN cargo build --release -p vosx -p ai-extension

# ── 2. Runtime image ────────────────────────────────────────────
FROM debian:12-slim AS runtime

# Runtime deps: ca-certificates for outbound HTTPS (hf-hub
# fetches GGUF + tokenizer over HTTPS). tini reaps zombies +
# forwards signals — vosx already handles SIGTERM directly
# (Sprint 1 commit C), but tini's PID-1 hardening costs ~20KB.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# XDG-mapped volumes — the entrypoint sets the env vars so
# vosx finds them automatically.
RUN mkdir -p /var/lib/vosx /etc/vosx /var/cache/vosx

ENV XDG_DATA_HOME=/var/lib/vosx
ENV XDG_CONFIG_HOME=/etc/vosx
ENV XDG_CACHE_HOME=/var/cache/vosx

# Copy artifacts from the builder. The .so libs go beside the
# binary so `vosx` finds them on the default RUST_LIB / library
# search path; the manifest path arg points at them explicitly.
COPY --from=builder /workspace/target/release/vosx /usr/local/bin/vosx
COPY --from=builder /workspace/target/release/libai_extension.so \
        /usr/local/lib/vosx/libai_extension.so

# Entrypoint script — see containers/entrypoint.sh for the
# rationale (signal handling, log streaming).
COPY containers/entrypoint.sh /usr/local/bin/vosx-entrypoint
RUN chmod +x /usr/local/bin/vosx-entrypoint

# Default manifest shipped in /etc/vosx/manifest.toml is a
# common shape (ai extension on port 4001). Operators bind-
# mount their own to override.
COPY containers/manifest.example.toml /etc/vosx/manifest.toml

# libp2p TCP + QUIC.
EXPOSE 4001/tcp 4001/udp

VOLUME ["/var/lib/vosx", "/etc/vosx", "/var/cache/vosx"]

# `tini -- ...` so signals propagate to the vosx process even
# under `docker run` without `--init`.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vosx-entrypoint"]
