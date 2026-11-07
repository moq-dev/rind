#!/usr/bin/env bash
# Stage rind-dart's Dart package as pub.dev receives it: the crate as `cargo
# package` normalizes it, depending on rind from crates.io at the version its
# manifest requires, pinned by the lockfile cargo writes, and as a workspace of
# its own so no enclosing Cargo workspace claims it. Its build hook builds
# with --locked against that lockfile.
#
# Usage: sh/dart-package.sh OUT_DIR
set -euo pipefail

out=${1:?usage: sh/dart-package.sh OUT_DIR}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 --locked |
    jq -r '.packages[] | select(.name == "rind-dart") | .version')

cargo package --manifest-path "$root/Cargo.toml" -p rind-dart --no-verify --locked
rm -rf "$out"
mkdir -p "$out"
tar -xzf "$root/target/package/rind-dart-$version.crate" -C "$out" --strip-components 1
rm "$out/Cargo.toml.orig" "$out/.cargo_vcs_info.json"
printf '\n[workspace]\n' >>"$out/Cargo.toml"
