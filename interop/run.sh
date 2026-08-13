#!/usr/bin/env bash
# Runs the full interoperability matrix against the official TypeScript SDK.
#
# Five legs, because a bug on either side of the wire shows up in only one direction:
#
#   1. TS client   -> this SDK's server   over Streamable HTTP
#   2. TS client   -> this SDK's server   over stdio
#   3. this client -> TS SDK's server     over Streamable HTTP
#   4. this client -> TS SDK's server     over stdio
#   5. this client -> TS SDK's *2025* server, over stdio
#
# Legs 1-4 run the TS servers with `legacy: 'reject'` and pin both TS clients to
# 2026-07-28, so none of them can pass by quietly falling back to the older protocol.
# Leg 5 is the opposite experiment and needs both halves to mean anything: a server that
# speaks only 2025, and a client that was told it may negotiate. Same `buildServer` as
# the others, so any difference in the results is the protocol era and nothing else.
#
# Usage: interop/run.sh          (from the repository root or anywhere)

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Loopback must bypass any configured proxy, or a proxy in the environment turns
# "the server is on this machine" into "fetch failed" — a failure that reads like a
# protocol problem and is not one.
export NO_PROXY="127.0.0.1,localhost"
export no_proxy="$NO_PROXY"

if [ ! -d interop/node_modules ]; then
    echo "interop: dependencies missing — run 'npm install' in interop/" >&2
    exit 2
fi

zig build examples interop || exit 1

http_port=8787
ts_port=8792
failures=0
declare -a results=()

# Waits for a line in a log rather than sleeping: a slow start must not read as a
# protocol failure.
wait_for() {
    local file="$1" needle="$2" tries=60
    while [ $tries -gt 0 ]; do
        grep -q "$needle" "$file" 2>/dev/null && return 0
        sleep 0.5
        tries=$((tries - 1))
    done
    return 1
}

record() {
    local name="$1" status="$2"
    if [ "$status" -eq 0 ]; then
        results+=("PASS  $name")
    else
        results+=("FAIL  $name")
        failures=$((failures + 1))
    fi
}

echo "=============================================================="
echo "leg 1: TypeScript client -> this SDK's server (Streamable HTTP)"
echo "=============================================================="
pkill -f 'zig-out/bin/http-server' >/dev/null 2>&1
sleep 1
./zig-out/bin/http-server >/tmp/interop-zig-http.log 2>&1 &
zig_http_pid=$!
sleep 1
(cd interop && node ts-client.mjs "http://127.0.0.1:$http_port/mcp")
record "TS client -> Zig server (HTTP)" $?
kill -INT "$zig_http_pid" 2>/dev/null
wait "$zig_http_pid" 2>/dev/null
# The server runs under a leak-checking allocator, so its own report is part of the result.
if grep -q "leaked" /tmp/interop-zig-http.log; then
    echo "FAIL: the Zig server reported a leak"
    results+=("FAIL  Zig HTTP server leak check")
    failures=$((failures + 1))
else
    results+=("PASS  Zig HTTP server leak check")
fi

echo
echo "=============================================================="
echo "leg 2: TypeScript client -> this SDK's server (stdio)"
echo "=============================================================="
(cd interop && node ts-client-stdio.mjs ../zig-out/bin/stdio-server)
record "TS client -> Zig server (stdio)" $?

echo
echo "=============================================================="
echo "leg 3: this SDK's client -> TypeScript server (Streamable HTTP)"
echo "=============================================================="
pkill -f ts-server-http.mjs >/dev/null 2>&1
sleep 1
(cd interop && node ts-server-http.mjs "$ts_port" >/tmp/interop-ts-http.log 2>&1) &
if wait_for /tmp/interop-ts-http.log listening; then
    ./zig-out/bin/interop-check http "http://127.0.0.1:$ts_port/mcp"
    record "Zig client -> TS server (HTTP)" $?
else
    echo "FAIL: the TypeScript server never came up"
    record "Zig client -> TS server (HTTP)" 1
fi
pkill -f ts-server-http.mjs >/dev/null 2>&1

echo
echo "=============================================================="
echo "leg 4: this SDK's client -> TypeScript server (stdio)"
echo "=============================================================="
./zig-out/bin/interop-check stdio node interop/ts-server-stdio.mjs
record "Zig client -> TS server (stdio)" $?

echo
echo "=============================================================="
echo "leg 5: this SDK's client -> TypeScript 2025 server (stdio)"
echo "=============================================================="
./zig-out/bin/interop-check legacy node interop/legacy-server-stdio.mjs
record "Zig client -> TS 2025 server (stdio, negotiated)" $?

echo
echo "=============================================================="
echo "matrix"
echo "=============================================================="
for line in "${results[@]}"; do echo "  $line"; done
echo
if [ "$failures" -eq 0 ]; then
    echo "all ${#results[@]} legs passed"
else
    echo "$failures of ${#results[@]} legs failed"
fi
exit $((failures == 0 ? 0 : 1))
