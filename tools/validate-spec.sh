#!/usr/bin/env bash
# Validates SDK-produced sample payloads against spec/schema.json.
#
# Wraps tools/validate-spec.py so that the Python dependency is set up on demand:
# `zig build spec` should work from a clean checkout without a separate install
# step. The virtualenv lives in .venv-spec/ and is gitignored.
set -euo pipefail

samples="${1:?usage: validate-spec.sh <samples.ndjson>}"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

venv=".venv-spec"
python="$venv/bin/python"

if [[ ! -x "$python" ]]; then
    echo "creating $venv for the schema validator"
    python3 -m venv "$venv"
fi

if ! "$python" -c "import jsonschema" 2>/dev/null; then
    echo "installing jsonschema into $venv"
    "$venv/bin/pip" install --quiet jsonschema
fi

exec "$python" tools/validate-spec.py <"$samples"
