# SPDX-License-Identifier: AGPL-3.0-only
# The image is a build environment, never a supported broker/container profile.
# CI overrides the pinned per-architecture image digests on its native runners.
ARG NODE_IMAGE=node:26.10.0-bookworm@sha256:abbacf6ecd105ed33c408bdca7701c8a54f50e317eabfb3ed31733d4e6951db5
ARG RUST_IMAGE=rust:1.98.1-bookworm@sha256:c49256cbe5ea0188bc658a689500d70c41eb51f009a7a7be209caf60a944f3ec
FROM ${NODE_IMAGE} AS ui
WORKDIR /source
COPY . .
RUN npm ci && npm run build

FROM ${RUST_IMAGE} AS binaries
RUN apt-get update && apt-get install -y --no-install-recommends libsystemd-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY --from=ui /source/packages/console/dist /source/packages/console/dist
COPY --from=ui /source/packages/browser-ui/dist-embedded /source/packages/browser-ui/dist-embedded
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo build --release --locked -p blindpass-controller -p blindpass-cli -p blindpass-node \
    -p blindpass-broker --bin blindpass-controller --bin blindpass --bin blindpass-node \
    --bin blindpass-broker --bin blindpass-provision --bin blindpass-credential-loader --bin blindpass-consumer \
    --bin blindpass-backup-probe --bin blindpass-workload-client
RUN target/release/blindpass-controller --build-info && target/release/blindpass --version \
    && target/release/blindpass-node --version && target/release/blindpass-broker --version
RUN mkdir /out && cp target/release/blindpass-controller target/release/blindpass \
    target/release/blindpass-node target/release/blindpass-broker target/release/blindpass-provision \
    target/release/blindpass-credential-loader target/release/blindpass-consumer \
    target/release/blindpass-backup-probe target/release/blindpass-workload-client /out/
FROM scratch AS export
COPY --from=binaries /out/ /
