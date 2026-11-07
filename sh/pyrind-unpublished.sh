#!/usr/bin/env bash
# Print the tag of pyrind's current version if release-plz has released it
# and PyPI does not have all of it yet, or nothing.
#
# Usage: sh/pyrind-unpublished.sh
# release-plz tags rind-python when a release PR lands, since it never goes
# to crates.io; this lets release.yml publish that tag to PyPI, and retry on a
# later push if publishing failed.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

version=$(cargo metadata --format-version 1 --no-deps --locked |
    jq -r '.packages[] | select(.name == "rind-python") | .version')
tag="rind-python-v$version"

# Exit status 2 means no such tag: this version is unreleased.
status=0
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null || status=$?
case "$status" in
    0) ;;
    2) exit 0 ;;
    *) exit "$status" ;;
esac

# twine uploads the wheels before the sdist, so a version whose sdist is on
# PyPI is complete; one without it may be partly uploaded, and release.yml
# skips the files already there.
json=$(mktemp)
trap 'rm -f "$json"' EXIT
status=$(curl --silent --output "$json" --write-out '%{http_code}' "https://pypi.org/pypi/pyrind/$version/json")
case "$status" in
    200)
        if ! jq -e '.urls | any(.packagetype == "sdist")' "$json" >/dev/null; then
            echo "$tag"
        fi
        ;;
    404) echo "$tag" ;;
    *)
        echo "error: PyPI answered $status for pyrind $version" >&2
        exit 1
        ;;
esac
