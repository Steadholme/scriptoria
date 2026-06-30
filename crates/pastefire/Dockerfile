# syntax=docker/dockerfile:1
#
# Multi-stage build for Pastefire (enterprise pastebin / snippet host).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Pastefire links NO OpenSSL: sqlx uses `rustls`, so the binary depends only on glibc — no
# libssl in either stage. The container HEALTHCHECK uses the built-in `pastefire healthcheck`
# subcommand, so no extra HTTP tool is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin pastefire \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they
# must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin pastefire \
    && strip target/release/pastefire

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home pastefire
COPY --from=builder /build/target/release/pastefire /usr/local/bin/pastefire

USER pastefire
# Default in-container bind; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:8730
EXPOSE 8730

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["pastefire", "healthcheck"]

ENTRYPOINT ["pastefire"]
