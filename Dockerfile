FROM --platform=$BUILDPLATFORM rust:1-bookworm AS vendor

ENV USER=root

WORKDIR /code

RUN cargo init --bin --name inapt /code

COPY Cargo.lock /code/Cargo.lock
COPY Cargo.toml /code/Cargo.toml

# https://docs.docker.com/engine/reference/builder/#run---mounttypecache
RUN --mount=type=cache,target=$CARGO_HOME/git,sharing=locked \
    --mount=type=cache,target=$CARGO_HOME/registry,sharing=locked \
    mkdir -p /code/.cargo \
    && cargo vendor >> /code/.cargo/config.toml

FROM rust:1-bookworm AS base

ENV USER=root

WORKDIR /code

COPY Cargo.toml /code/Cargo.toml
COPY Cargo.lock /code/Cargo.lock
COPY migrations /code/migrations
COPY src /code/src
COPY --from=vendor /code/.cargo /code/.cargo
COPY --from=vendor /code/vendor /code/vendor

FROM base AS builder

# https://docs.docker.com/engine/reference/builder/#run---mounttypecache
RUN --mount=type=cache,target=$CARGO_HOME/git,sharing=locked \
    --mount=type=cache,target=$CARGO_HOME/registry,sharing=locked \
    --mount=type=cache,target=/core/target/release/.fingerprint,sharing=locked \
    --mount=type=cache,target=/core/target/release/build,sharing=locked \
    --mount=type=cache,target=/core/target/release/deps,sharing=locked \
    --mount=type=cache,target=/core/target/release/examples,sharing=locked \
    --mount=type=cache,target=/core/target/release/incremental,sharing=locked \
    cargo build --release --package inapt --offline

FROM debian

RUN apt-get update \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

ENV ADDRESS=0.0.0.0
ENV PORT=3000

COPY --from=builder /code/target/release/inapt /usr/local/bin/inapt

ENTRYPOINT ["/usr/local/bin/inapt"]
