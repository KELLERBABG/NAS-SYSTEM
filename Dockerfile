# ──────────────────────────────────────────────────────────────────────────
#  GHOST NAS Docker Image
#  Multi-stage build: Rust compiler → Distroless runtime
#  For TrueNAS SCALE App Catalog deployment
# ──────────────────────────────────────────────────────────────────────────

# ── Build Stage ──
FROM rust:1.77-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for layer caching
COPY Cargo.toml ./
COPY src/ ./src/

# Build with optimizations
RUN cargo build --release --locked

# ── Runtime Stage ──
FROM gcr.io/distroless/cc-debian12:latest

# Copy GHOST NAS binary
COPY --from=builder /build/target/release/ghost-nas /usr/local/bin/ghost-nas

# Create required directories
RUN mkdir -p /mnt/ghost-vault /mnt/ghost-config /run/ghost /usr/share/ghost-nas/webui

# Copy default web UI (can be extended with a React/Vue dashboard)
# COPY webui/ /usr/share/ghost-nas/webui/

# Expose ports
#   UDP: 0-65535 (ephemeral for P2P)
#   TCP: 9001 (bulk transfer)
#   HTTP: 9443 (TrueNAS middleware API)
EXPOSE 9001/tcp 9443/tcp

# Labels for TrueNAS SCALE Catalog
LABEL \
    org.opencontainers.image.title="GHOST NAS" \
    org.opencontainers.image.description="GHOST NAS — Encrypted, distributed storage vault for TrueNAS SCALE" \
    org.opencontainers.image.version="0.1.0" \
    org.opencontainers.image.source="https://github.com/ghost-nas/ghost-nas" \
    trueos.scale.category="Storage" \
    trueos.scale.icon="https://ghost-nas.org/icon.png"

# Volume mount points
VOLUME ["/mnt/ghost-config", "/mnt/ghost-vault", "/run/ghost"]

ENTRYPOINT ["/usr/local/bin/ghost-nas"]
CMD ["--init-vault"]