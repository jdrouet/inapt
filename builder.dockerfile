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

# https://docs.docker.com/engine/reference/builder/#run---mounttypecache
RUN --mount=type=cache,target=$CARGO_HOME/git,sharing=locked \
    --mount=type=cache,target=$CARGO_HOME/registry,sharing=locked \
    cargo install cargo-deb

ENV USER=root

WORKDIR /code

COPY Cargo.toml /code/Cargo.toml
COPY Cargo.lock /code/Cargo.lock
COPY package /code/package
COPY src /code/src
COPY readme.md /code/readme.md
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
    cargo deb

FROM scratch

COPY --from=builder /code/target/debian /
