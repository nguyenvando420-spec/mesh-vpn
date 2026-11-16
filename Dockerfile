# Multi-stage production and NAT-lab Dockerfile for Mesh VPN (Rust 1.94.1).
# Targets:
#   - mesh-server : Minimal unprivileged Control + Blind Relay + STUN server (runs as UID `mesh`)
#   - mesh-node   : Ubuntu LTS Linux lab node (minimal NET_ADMIN + /dev/net/tun, non-privileged)
#   - lab-router  : Linux NAT/chaos router (EIM, APDM, UDP-block, 443-only, MTU-1400, tc netem, MITM)
#   - vps-proxy   : Optional TLS Reverse Proxy (Nginx) for `tls_mode = "reverse_proxy"` lab topology

ARG RUST_IMAGE=rust:1.94.1-slim-bookworm
ARG SERVER_BASE_IMAGE=debian:bookworm-slim
ARG LAB_BASE_IMAGE=ubuntu:24.04

# ---------------------------------------------------------------------------
# Stage 1: Dependency fetch & release compilation (Rust 1.94.1)
# ---------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS builder

ARG CARGO_TARGET=""

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    libc6-dev \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN if [ -n "${CARGO_TARGET}" ]; then rustup target add "${CARGO_TARGET}"; fi

WORKDIR /workspace

# Copy workspace manifests first for deterministic dependency caching.
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml deny.toml ./
COPY crates/mesh-core/Cargo.toml crates/mesh-core/Cargo.toml
COPY crates/mesh-sys/Cargo.toml crates/mesh-sys/Cargo.toml
COPY crates/mesh-crypto/Cargo.toml crates/mesh-crypto/Cargo.toml
COPY crates/mesh-proto/Cargo.toml crates/mesh-proto/Cargo.toml
COPY crates/mesh-net/Cargo.toml crates/mesh-net/Cargo.toml
COPY crates/mesh-store/Cargo.toml crates/mesh-store/Cargo.toml
COPY crates/mesh-datapath/Cargo.toml crates/mesh-datapath/Cargo.toml
COPY crates/mesh-server/Cargo.toml crates/mesh-server/Cargo.toml
COPY crates/meshd/Cargo.toml crates/meshd/Cargo.toml
COPY crates/mesh/Cargo.toml crates/mesh/Cargo.toml
COPY crates/mesh-client/Cargo.toml crates/mesh-client/Cargo.toml
COPY crates/mesh-mobile-ffi/Cargo.toml crates/mesh-mobile-ffi/Cargo.toml
COPY tools/uniffi-bindgen/Cargo.toml tools/uniffi-bindgen/Cargo.toml

# Create minimal placeholder entrypoints so `cargo fetch --locked` caches all crates
# cleanly before copying real source trees.
RUN mkdir -p \
      crates/mesh-core/src crates/mesh-sys/src crates/mesh-crypto/src \
      crates/mesh-proto/src crates/mesh-net/src crates/mesh-store/src \
      crates/mesh-datapath/src crates/mesh-server/src crates/meshd/src crates/mesh/src \
      crates/mesh-client/src crates/mesh-mobile-ffi/src tools/uniffi-bindgen/src && \
    for lib in mesh-core mesh-sys mesh-crypto mesh-proto mesh-net mesh-store mesh-datapath mesh-client mesh-mobile-ffi; do \
      touch "crates/${lib}/src/lib.rs"; \
    done && \
    for bin in mesh-server meshd mesh; do \
      printf 'fn main() {}\n' > "crates/${bin}/src/main.rs"; \
    done && \
    printf 'fn main() {}\n' > tools/uniffi-bindgen/src/main.rs && \
    if [ -n "${CARGO_TARGET}" ]; then \
      cargo fetch --locked --target "${CARGO_TARGET}"; \
    else \
      cargo fetch --locked; \
    fi && \
    rm -rf crates/*/src tools/uniffi-bindgen/src

# Copy full workspace sources and build release binaries offline against Cargo.lock.
COPY crates ./crates
COPY tools ./tools

RUN mkdir -p /out && \
    if [ -n "${CARGO_TARGET}" ]; then \
      cargo build --release --locked --offline --target "${CARGO_TARGET}" --bin mesh-server --bin meshd --bin mesh && \
      cp "target/${CARGO_TARGET}/release/mesh-server" \
         "target/${CARGO_TARGET}/release/meshd" \
         "target/${CARGO_TARGET}/release/mesh" /out/; \
    else \
      cargo build --release --locked --offline --bin mesh-server --bin meshd --bin mesh && \
      cp target/release/mesh-server target/release/meshd target/release/mesh /out/; \
    fi

# ---------------------------------------------------------------------------
# Stage 2: Minimal unprivileged Control + Blind Relay + STUN runtime
# ---------------------------------------------------------------------------
FROM ${SERVER_BASE_IMAGE} AS mesh-server

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system mesh-admin && \
    groupadd --system mesh && \
    useradd --system --gid mesh --groups mesh-admin --no-create-home --shell /usr/sbin/nologin mesh && \
    install -d -m 0750 -o root -g mesh /etc/mesh && \
    install -d -m 0700 -o mesh -g mesh /var/lib/mesh && \
    install -d -m 0750 -o mesh -g mesh /var/log/mesh && \
    install -d -m 0750 -o mesh -g mesh-admin /run/mesh-server

COPY --from=builder /out/mesh-server /usr/local/bin/mesh-server
COPY --from=builder /out/mesh /usr/local/bin/mesh
COPY --chown=root:mesh --chmod=0755 lab/vps/entrypoint.sh /usr/local/bin/mesh-server-entrypoint.sh

# Allow unprivileged `mesh` user to bind TCP 443 when NET_BIND_SERVICE is permitted.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/mesh-server

# Specify username only (without `:mesh`) so OCI runtime preserves supplementary group `mesh-admin`.
USER mesh

EXPOSE 443/tcp 3478/udp

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:9091/readyz >/dev/null || exit 1

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/mesh-server-entrypoint.sh"]

# ---------------------------------------------------------------------------
# Stage 3: Linux Lab Client Node (requires only NET_ADMIN + /dev/net/tun)
# ---------------------------------------------------------------------------
FROM ${LAB_BASE_IMAGE} AS mesh-node

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    faketime \
    iperf3 \
    iproute2 \
    iptables \
    iputils-ping \
    jq \
    netcat-openbsd \
    nftables \
    openssl \
    procps \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN install -d -m 0700 -o root -g root /var/lib/meshd && \
    install -d -m 0755 -o root -g root /var/run/meshd && \
    install -d -m 0750 -o root -g root /var/log/meshd && \
    install -d -m 0755 -o root -g root /etc/mesh

COPY --from=builder /out/meshd /usr/local/bin/meshd
COPY --from=builder /out/mesh /usr/local/bin/mesh
COPY --chmod=0755 lab/node/entrypoint.sh /usr/local/bin/mesh-node-entrypoint.sh

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/mesh-node-entrypoint.sh"]

# ---------------------------------------------------------------------------
# Stage 4: Linux NAT / Firewall / Chaos Lab Router
# ---------------------------------------------------------------------------
FROM ${LAB_BASE_IMAGE} AS lab-router

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    conntrack \
    curl \
    iperf3 \
    iproute2 \
    iptables \
    iputils-ping \
    jq \
    nftables \
    openssl \
    procps \
    socat \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 lab/router/entrypoint.sh /usr/local/bin/router-entrypoint.sh

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/router-entrypoint.sh"]

# ---------------------------------------------------------------------------
# Stage 5: Optional Nginx TLS Reverse Proxy for Reverse-Proxy Lab Mode
# ---------------------------------------------------------------------------
FROM ${SERVER_BASE_IMAGE} AS vps-proxy

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nginx \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 lab/vps/proxy-entrypoint.sh /usr/local/bin/proxy-entrypoint.sh

EXPOSE 443/tcp

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/proxy-entrypoint.sh"]
