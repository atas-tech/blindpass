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
# The default build images are x86-64 digests. Refuse a build whose requested platform
# differs, otherwise the runtime stage would carry binaries of the wrong architecture.
ARG TARGETARCH
RUN case "${TARGETARCH:-amd64}:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; \
      *) echo "builder image architecture $(uname -m) does not match target ${TARGETARCH}; pass the reviewed NODE_IMAGE/RUST_IMAGE digests for that architecture" >&2; exit 1 ;; esac
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

# ADR 0011: the signed PostgreSQL repository key is fetched and fingerprint-checked
# in a throwaway stage; no downloader or key tooling reaches the runtime image.
FROM ${RUNTIME_IMAGE} AS pgdg
ARG PGDG_KEY_FINGERPRINT=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl --fail --silent --show-error --location https://www.postgresql.org/media/keys/ACCC4CF8.asc --output /pgdg.asc \
    && test "$(gpg --show-keys --with-colons /pgdg.asc | awk -F: '/^fpr:/ {print $10; exit}')" = "$PGDG_KEY_FINGERPRINT" \
    && gpg --dearmor --output /pgdg.gpg /pgdg.asc

# Test-only: runs the PostgreSQL toolkit integration tests (ADR 0011) as an unprivileged
# user against the exact pinned toolkit. Never the default or a published target.
FROM binaries AS pgtest
COPY --from=pgdg /pgdg.gpg /usr/share/keyrings/pgdg.gpg
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && install -d /etc/postgresql-common \
    && printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf \
    && echo 'deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main' > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        postgresql-16=16.15-1.pgdg12+2 postgresql-client-16=16.15-1.pgdg12+2 \
        postgresql-common=293.pgdg12+1 postgresql-client-common=293.pgdg12+1 libpq5=18.6-1.pgdg12+2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home tester \
    && cp -a /usr/local/cargo /home/tester/.cargo && chown -R 10001:10001 /home/tester/.cargo /source
USER 10001:10001
ENV CARGO_HOME=/home/tester/.cargo CARGO_TARGET_DIR=/home/tester/target HOME=/home/tester
WORKDIR /source
# Compile once at image build so each run starts immediately.
RUN cargo test -p blindpass-controller --test backup_postgres_toolkit --test restore_postgres --test production_ownership --no-run --locked --offline
CMD ["cargo", "test", "-p", "blindpass-controller", "--test", "backup_postgres_toolkit", "--locked", "--offline", "--", "--ignored", "--test-threads=1"]

FROM ${RUNTIME_IMAGE} AS runtime
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="BlindPass controller" \
    org.opencontainers.image.source="https://github.com/atas-tech/blindpass" \
    org.opencontainers.image.licenses="AGPL-3.0-only" \
    org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$REVISION
COPY --from=pgdg /pgdg.gpg /usr/share/keyrings/pgdg.gpg
# Exact reviewed toolkit (ADR 0011). No cluster is ever created, and the repository
# configuration does not remain in the image. postgresql-common depends on ssl-cert,
# whose postinst generates a private snakeoil key shared by every container of the
# image; it is removed in the same layer so no layer retains it (O01 scans all layers).
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && install -d /etc/postgresql-common \
    && printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf \
    && echo 'deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main' > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        postgresql-16=16.15-1.pgdg12+2 postgresql-client-16=16.15-1.pgdg12+2 \
        postgresql-common=293.pgdg12+1 postgresql-client-common=293.pgdg12+1 libpq5=18.6-1.pgdg12+2 \
    && rm -f /etc/apt/sources.list.d/pgdg.list /usr/share/keyrings/pgdg.gpg \
    && rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem \
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
