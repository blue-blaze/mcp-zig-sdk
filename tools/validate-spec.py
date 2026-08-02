#!/usr/bin/env python3
"""Validate SDK-produced payloads against the published MCP schema.

Reads the NDJSON stream written by `tools/spec_samples.zig` on stdin, where each
record is `{"def": "<schema $def>", "value": <payload>}`, and checks every payload
against that definition in `spec/schema.json`.

This is the only check that can catch a divergence between the Zig types and the
specification itself; the Zig unit tests pin the bytes the SDK emits, but they
cannot know whether those bytes are what the schema asks for.

Exits non-zero on the first failure, listing every problem found.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit(
        "jsonschema is not installed.\n"
        "  python3 -m venv .venv-spec && ./.venv-spec/bin/pip install jsonschema"
    )

REPO = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "spec" / "schema.json"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    defs = schema["$defs"]

    records = []
    for line_number, line in enumerate(sys.stdin, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append((line_number, json.loads(line)))
        except json.JSONDecodeError as exc:
            print(f"line {line_number}: sample stream is not valid JSON: {exc}")
            return 1

    if not records:
        print("no samples on stdin; did the emitter run?")
        return 1

    failures = []
    checked = set()

    for line_number, record in records:
        name = record["def"]
        if name not in defs:
            failures.append(f"line {line_number}: no such definition '{name}' in schema.json")
            continue

        # Resolve $ref against the whole document, not just the fragment.
        validator = Draft202012Validator({"$ref": f"#/$defs/{name}", **schema})
        errors = sorted(validator.iter_errors(record["value"]), key=lambda e: e.path)
        if errors:
            for error in errors:
                location = "/".join(str(p) for p in error.absolute_path) or "<root>"
                failures.append(f"{name} at {location}: {error.message}")
        checked.add(name)

    print(f"validated {len(records)} samples across {len(checked)} definitions")

    if failures:
        print(f"\n{len(failures)} failure(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("all samples conform to spec/schema.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
