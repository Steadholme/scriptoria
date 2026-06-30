# syntax=docker/dockerfile:1
#
# Multi-stage build for Scriptoria (blog/forum/wiki/comments/paste/drive vhost demux over six
# vendored library crates).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# The surfaces embed their templates + static CSS via include_str! at COMPILE time, so the runtime
# image carries only the single statically-templated binary — no assets to ship. sqlx and Aperture's
# Cairn S3 client (object_store -> reqwest) both use rustls (ring), and the only FFI is glibc, so
# there is NO OpenSSL. ca-certificates is present so the S3 client can verify TLS to Cairn if it is
# fronted by HTTPS. The HEALTHCHECK uses the built-in `scriptoria healthcheck` subcommand, so the
# image needs no curl.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Bring the whole self-contained crate (the binary + the three vendored surface crates under
# crates/) and build the release binary. The surfaces' static/ + templates/ are needed at build
# time for their include_str! embeds.
COPY Cargo.toml ./
COPY src ./src
COPY crates ./crates
RUN cargo build --release --bin scriptoria \
    && strip target/release/scriptoria

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home scriptoria
COPY --from=builder /build/target/release/scriptoria /usr/local/bin/scriptoria

USER scriptoria
ENV BIND_ADDR=0.0.0.0:8700
EXPOSE 8700

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["scriptoria", "healthcheck"]

CMD ["scriptoria"]
