# SPDX-License-Identifier: AGPL-3.0-only
ARG NODE_IMAGE=node:26.10.0-bookworm@sha256:abbacf6ecd105ed33c408bdca7701c8a54f50e317eabfb3ed31733d4e6951db5
ARG RUST_IMAGE=rust:1.98.1-bookworm@sha256:c49256cbe5ea0188bc658a689500d70c41eb51f009a7a7be209caf60a944f3ec
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
FROM ${NODE_IMAGE} AS ui
ARG BUILDKIT_SBOM_SCAN_STAGE=true
WORKDIR /source
COPY . .
RUN npm ci && npm run build \
    && node scripts/release/controller-notices.mjs /source/node_modules /source/controller-notices/npm

FROM ${RUST_IMAGE} AS binaries
ARG BUILDKIT_SBOM_SCAN_STAGE=true
RUN apt-get update && apt-get install -y --no-install-recommends libsystemd-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY scripts/release/controller-notices.mjs ./scripts/release/controller-notices.mjs
COPY --from=ui /usr/local/bin/node /usr/local/bin/node
COPY --from=ui /source/packages/console/dist /source/packages/console/dist
COPY --from=ui /source/packages/browser-ui/dist-embedded /source/packages/browser-ui/dist-embedded
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo build --release --locked -p blindpass-controller -p blindpass-cli \
    && target/release/blindpass-controller --build-info && target/release/blindpass --version \
    && node scripts/release/controller-notices.mjs /usr/local/cargo/registry/src /source/controller-notices/rust

FROM ${RUNTIME_IMAGE} AS runtime
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="BlindPass controller" \
    org.opencontainers.image.source="https://github.com/atas-tech/blindpass" \
    org.opencontainers.image.licenses="AGPL-3.0-only" \
    org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$REVISION
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 blindpass \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin blindpass \
    && install -d -m 0700 -o 10001 -g 10001 /data /keys /run/blindpass-controller \
    && install -d -m 0755 /usr/share/doc/blindpass
COPY --from=binaries /source/target/release/blindpass-controller /source/target/release/blindpass /usr/local/bin/
COPY --chmod=0755 deploy/controller/entrypoint.sh /usr/local/bin/blindpass-entrypoint
COPY Cargo.lock LICENSES.md /usr/share/doc/blindpass/
COPY packages/console/LICENSE /usr/share/doc/blindpass/LICENSE
COPY packages/browser-ui/LICENSE /usr/share/doc/blindpass/browser-ui-LICENSE
COPY assets/ui/ASSETS.md assets/ui/LICENSE /usr/share/doc/blindpass/assets/
COPY assets/ui/fonts/OFL.txt /usr/share/doc/blindpass/assets/Inter-OFL.txt
COPY --from=ui /source/controller-notices/npm /usr/share/doc/blindpass/third-party/npm
COPY --from=binaries /source/controller-notices/rust /usr/share/doc/blindpass/third-party/rust
ENV BLINDPASS_LISTEN=0.0.0.0:3200 BLINDPASS_KEYS_DIR=/keys BLINDPASS_DATA_DIR=/data \
    BLINDPASS_ADMIN_SOCKET_PATH=/run/blindpass-controller/admin.sock BLINDPASS_LOG_FORMAT=json \
    BLINDPASS_PROXY_REQUIRED=1
EXPOSE 3200
VOLUME ["/data", "/keys"]
USER 10001:10001
HEALTHCHECK --interval=5s --timeout=4s --start-period=10s --retries=3 CMD ["/usr/local/bin/blindpass-controller", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/blindpass-entrypoint"]
CMD ["serve"]
