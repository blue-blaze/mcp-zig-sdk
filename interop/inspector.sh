#!/usr/bin/env bash
# The MCP Inspector, the reference debugging client, against this SDK's servers.
#
# A third independent implementation on the other end of the wire — and the one a person
# reaches for first when a server misbehaves, so it is worth knowing it works.
#
# The Inspector defaults to the 2025 protocol, so `interop/inspector.json` sets
# `"protocolEra": "modern"` per server. Without it the very first `tools/list` arrives
# with no `_meta` envelope and this SDK correctly refuses it — which reads like a bug and
# is not one.
#
# Usage: interop/inspector.sh

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Built here rather than assumed: this script was only ever run after `run.sh`, which
# builds as a side effect, so the dependency was real but invisible. Running it alone —
# which is the whole point of it being a separate script — would have used a stale binary
# or none at all.
zig build examples || exit 1

inspector="./interop/node_modules/.bin/mcp-inspector"
if [ ! -x "$inspector" ]; then
    echo "inspector: not installed — run 'npm install' in interop/" >&2
    exit 2
fi

# Loopback must bypass any configured proxy. The Inspector's fetch honours these, and
# without them a proxy in the environment turns "server is right here" into
# "fetch failed" — a failure that looks like a protocol problem and is not one.
export NO_PROXY="127.0.0.1,localhost"
export no_proxy="$NO_PROXY"

failures=0
declare -a results=()

invoke() {
    local server="$1"
    shift
    $inspector --cli --format json --config interop/inspector.json --server "$server" "$@" 2>&1
}

run() {
    local name="$1" server="$2"
    shift 2
    local output
    output="$(invoke "$server" "$@")"
    if printf '%s' "$output" | grep -q '"result"'; then
        results+=("PASS  $name")
        printf '  ok   %s\n' "$name"
    else
        results+=("FAIL  $name")
        failures=$((failures + 1))
        printf '  FAIL %s — %s\n' "$name" "$(printf '%s' "$output" | head -c 200)"
    fi
}

# For cases where the specified outcome is a refusal. `needle` is text the refusal must
# contain, so that "rejected" cannot pass for the wrong reason.
run_expect_refusal() {
    local name="$1" server="$2" needle="$3"
    shift 3
    local output
    output="$(invoke "$server" "$@")"
    if printf '%s' "$output" | grep -q '"result"'; then
        results+=("FAIL  $name")
        failures=$((failures + 1))
        printf '  FAIL %s — accepted, but the specification requires a refusal\n' "$name"
    elif printf '%s' "$output" | grep -q "$needle"; then
        results+=("PASS  $name")
        printf '  ok   %s\n' "$name"
    else
        results+=("FAIL  $name")
        failures=$((failures + 1))
        printf '  FAIL %s — refused for the wrong reason: %s\n' "$name" "$(printf '%s' "$output" | head -c 200)"
    fi
}

echo "MCP Inspector -> this SDK's stdio server"
run "stdio tools/list" zig-stdio --method tools/list
run "stdio tools/call" zig-stdio --method tools/call --tool-name add --tool-arg a=2 b=40
run "stdio resources/list" zig-stdio --method resources/list
run "stdio resources/read" zig-stdio --method resources/read --uri file:///readme.md
run "stdio resources/templates/list" zig-stdio --method resources/templates/list
run "stdio resources/read via template" zig-stdio --method resources/read --uri greeting://Ada
run "stdio prompts/list" zig-stdio --method prompts/list
run "stdio prompts/get" zig-stdio --method prompts/get --prompt-name review_code --prompt-args language=zig

echo
echo "MCP Inspector -> this SDK's HTTP server"
pkill -f 'zig-out/bin/http-server' >/dev/null 2>&1
sleep 1
./zig-out/bin/http-server >/tmp/interop-inspector-http.log 2>&1 &
http_pid=$!
sleep 1
run "http tools/list" zig-http --method tools/list
# The Inspector does not mirror `x-mcp-header`-annotated arguments into `Mcp-Param-*`, so
# the specified outcome here is a refusal, and that is what is asserted.
#
# The Streamable HTTP binding's table is unambiguous: "Client omits header but value is in
# body | Non-conforming client | Server MUST reject the request", with `-32020`. So this
# is a gap in the Inspector rather than a disagreement, and a server that accepted the
# call would be the non-conforming one — which is why this is a positive conformance check
# and not a skipped test.
#
# The mirroring path itself is covered where a client does implement it: the TypeScript SDK
# leg in `run.sh`, and this SDK's own client in `interop-check`.
run_expect_refusal "http tools/call refuses a missing Mcp-Param-*" zig-http "Mcp-Param-Region" \
    --method tools/call --tool-name execute_sql --tool-arg region=eu-west-1 query="select 1"
run "http tools/call streaming" zig-http --method tools/call --tool-name count --tool-arg to=3
run "http resources/read" zig-http --method resources/read --uri file:///readme.md
kill -INT "$http_pid" 2>/dev/null
wait "$http_pid" 2>/dev/null

if grep -q leaked /tmp/interop-inspector-http.log; then
    results+=("FAIL  HTTP server leak check")
    failures=$((failures + 1))
else
    results+=("PASS  HTTP server leak check")
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "all ${#results[@]} Inspector checks passed"
else
    echo "$failures of ${#results[@]} Inspector checks failed"
fi
exit $((failures == 0 ? 0 : 1))
