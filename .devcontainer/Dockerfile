FROM rust:1

RUN rustup component add rustfmt
RUN rustup component add clippy
RUN cargo install cargo-audit --locked --features=fix
