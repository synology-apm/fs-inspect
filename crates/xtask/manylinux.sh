#!/bin/sh
# Puts the toolchain of rust-toolchain.toml into a manylinux_2_28 container, which has no Rust,
# for `cargo xtask dist` (crates/xtask/src/dist.rs). dist's own container and release.yml's Linux
# legs both run it, so both build with the same toolchain. Run from the workspace root.
set -eu
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
if [ ! -x "$cargo_home/bin/rustup" ]; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain none --no-modify-path
fi
PATH="$cargo_home/bin:$PATH"
rustup toolchain install
# A GitHub job's later steps find cargo only through GITHUB_PATH.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$cargo_home/bin" >> "$GITHUB_PATH"
fi
