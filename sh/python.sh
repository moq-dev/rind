#!/usr/bin/env bash
# Build pyrind's wheel and run its tests, or its benchmarks, against it.
#
# Usage: sh/python.sh test|bench [ARGS...]
# The tests need pyca/cryptography, the differential oracle, mypy, and the
# Wycheproof submodule; the benchmarks compare against cryptography,
# hashlib, and hmac. ARGS go to unittest or the benchmark script.
set -euo pipefail

usage="usage: sh/python.sh test|bench [ARGS...]"
action=${1:?$usage}
shift

cd "$(git rev-parse --show-toplevel)"

out=$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/pyrind
rm -rf "$out"
maturin build --release --quiet --manifest-path rind-python/Cargo.toml --out "$out/wheel"
# A wheel is a zip of the installed package, so unpacking it is installing it
# without pip.
python3 -m zipfile -e "$out"/wheel/pyrind-*.whl "$out/site"

case "$action" in
    test)
        PYTHONPATH="$out/site" python3 -m unittest discover --start-directory rind-python/tests "$@"
        # Checks the type stubs against the built module.
        (cd "$out/site" && python3 -m mypy.stubtest pyrind)
        ;;
    bench) PYTHONPATH="$out/site" python3 rind-python/bench/bench.py "$@" ;;
    *)
        echo "$usage" >&2
        exit 2
        ;;
esac
