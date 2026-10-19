#!/bin/sh
# Synthetic three-UID proof. The build may download public Rust crates; the
# test phase has no network and never loads a real SIWC credential.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_image='rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663'
if [ -n "${SIWC_BUILD_DIR:-}" ]; then
  build_dir=$SIWC_BUILD_DIR
  mkdir -p "$build_dir"
  cleanup() { :; }
else
  build_dir=$(mktemp -d)
  cleanup() { rm -rf "$build_dir"; }
fi
trap cleanup EXIT INT TERM

if ! docker run --rm \
  --mount "type=bind,source=$repo_dir,target=/src,readonly" \
  --mount "type=bind,source=$build_dir,target=/out" \
  --env CARGO_TARGET_DIR=/out/target \
  --env CARGO_HOME=/out/cargo \
  --env CARGO_BUILD_JOBS=2 \
  --env CARGO_INCREMENTAL=0 \
  --env CARGO_PROFILE_TEST_DEBUG=0 \
  --workdir /src "$fixture_image" \
  cargo test --locked --lib --no-run >"$build_dir/build.log" 2>&1; then
  tail -n 80 "$build_dir/build.log"
  exit 1
fi
tail -n 3 "$build_dir/build.log"

fixture=$(find "$build_dir/target/debug/deps" -maxdepth 1 -type f \
  -name 'siwc_isolated_broker-*' -perm -111 -print -quit)
test -n "$fixture"
fixture_name=$(basename "$fixture")

docker run --rm --network none --cap-drop ALL \
  --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add KILL --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges \
  --mount "type=bind,source=$build_dir/target/debug/deps,target=/fixture,readonly" \
  "$fixture_image" \
  "/fixture/$fixture_name" --exact linux_uid_boundary::three_real_uid_socket_boundary --ignored --nocapture
