#!/bin/bash

set -xe

rustup component add rustfmt
rustup component add clippy
cargo install cargo-audit --locked --features=fix
