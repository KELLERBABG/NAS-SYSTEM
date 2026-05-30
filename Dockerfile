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

# Ordnerstruktur bereits in der Builder-Stage vorbereiten
RUN mkdir -p ./dist/mnt/ghost-vault ./dist/mnt/ghost-config ./dist/run/ghost ./dist/usr/share/ghost-nas/webui

# Copy manifests first for layer caching
COPY Cargo.toml ./
COPY src/ ./src/

# Build with optimizations
RUN cargo build --release --locked

# ── Runtime Stage ──
FROM gcr.io/distroless/cc-debian12:latest

# Die vorbereitete Ordnerstruktur aus dem Builder kopieren (umgeht das fehlende mkdir)
COPY --from=builder /build/dist /

# Copy GHOST NAS binary
COPY --from=builder /build/target/release/ghost-nas /usr/local/bin/ghost-nas

# Expose ports
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
