FROM rust:1-bookworm AS builder

ENV USER=root

WORKDIR /code

COPY Cargo.toml /code/Cargo.toml
COPY Cargo.lock /code/Cargo.lock
COPY migrations /code/migrations
COPY src /code/src

RUN cargo build --release --package inapt

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

ENV ADDRESS=0.0.0.0
ENV PORT=3000

COPY --from=builder /code/target/release/inapt /usr/local/bin/inapt

ENTRYPOINT ["/usr/local/bin/inapt"]
