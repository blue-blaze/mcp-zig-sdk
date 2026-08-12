# mcp-zig-sdk

A Zig implementation of the [Model Context Protocol][mcp], revision
**2026-07-28** ("MCP 2.0") — server and client, stdio and Streamable HTTP.

Requires Zig **0.16.0**. One dependency, [Velo][velo], for the HTTP server and client;
`zig build` fetches it.

## Use it

```sh
zig fetch --save git+https://github.com/blue-blaze/mcp-zig-sdk.git
```

```zig
const mcp_dep = b.dependency("mcp", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("mcp", mcp_dep.module("mcp"));
// `oauth` is usable on its own, with or without `mcp`.
exe.root_module.addImport("oauth", mcp_dep.module("oauth"));
```

## Modules

| Module  | Purpose |
|---|---|
| `mcp`   | The protocol SDK: server dispatch, client, transports |
| `oauth` | OAuth 2.1 client + resource server. No MCP dependency; usable standalone |

Everything in `oauth` except its `http` module is pure, so the security-relevant
behaviour — algorithm confusion, issuer mismatch, audience binding, scope escalation —
is covered by unit tests rather than by a mock server. `zig build run-oauth-flow` then
exercises the whole flow against a real socket: discovery, PKCE, a real ES256-signed
token, and that token validated by the resource-server half.

## Status

Complete: the protocol over both transports on both ends, authorization, and a passing
interoperability matrix against the official TypeScript SDK and the MCP Inspector.

| Area | State |
|---|---|
| JSON-RPC, protocol types, comptime schema generation | done |
| Server dispatch, all nine methods, pagination, cache hints | done |
| Progress, per-request logging, cancellation | done |
| Multi-round-trip requests and elicitation | done |
| `subscriptions/listen`, both transports | done |
| stdio transport, server and client | done |
| Streamable HTTP transport, server and client | done |
| OAuth 2.1 resource server: PRM, challenges, JWT/JWKS verification | done |
| OAuth 2.1 client: discovery, PKCE, `iss` validation, refresh, step-up | done |
| OAuth 2.1 client: `client_credentials`, for a service authorizing as itself | done |
| Authorization on the HTTP transport: 401/403/503, PRM endpoint, per-tool scopes | done |
| Interoperability: official TypeScript SDK, both directions, both transports | done |
| Interoperability: MCP Inspector, both transports | done |

`https://` on the client transport requires `-Dtls`, which this build forwards to
Velo; without it an `https` URL is refused rather than silently downgraded.

That option did not exist until the path was checked. The `if (velo.tls_enabled)`
branches were therefore never analyzed, and when the option was added they did not
compile: the TLS session was declared as `velo.tls.ClientSession`, a name Velo does not
export. Zig's lazy analysis is why a wrong name inside an unreachable branch stayed
invisible, and deriving the reader and writer types with `@TypeOf` off that same name
meant nothing else contradicted it. Both now name Velo's own `Session`,
`SessionReader` and `SessionWriter`.

`zig build -Dtls test` runs an https round trip: `tools/list` and a `tools/call`
against a real TLS server (Velo's `serveTls`, on its own OS thread because OpenSSL's
session calls block the thread they run on). It skips without `cert.pem`/`key.pem`, and
a separate test forces the session type to be analyzed even then, so a fresh clone
still type-checks the path it cannot run. The round trip was negative-verified by
making the client *verify* the self-signed certificate: it then fails, which is what
proves a TLS handshake is happening rather than a plaintext connection succeeding.

## Tool arguments

A tool's `inputSchema` is derived from its handler's argument type at compile time, so the
schema and the code that decodes against it cannot disagree — and where they could, the
build stops rather than the call:

```zig
const ForecastArgs = struct {
    city: []const u8,
    days: u8 = 3,
    units: ?enum { metric, imperial } = null,   // `= null` is required, see below

    pub const schema_docs = .{ .city = "The city to look up" };
};
```

Two rules follow from `std.json` being the decoder, both enforced by `schema_gen`:

- **An optional field must be written `?T = null`.** Without the default, the schema leaves
  the field out of `required` while `std.json` still demands it be present, so the tool
  advertises a field as omittable and then rejects every call that omits it. That is a
  compile error naming the field and the fix.
- **An integer carries its Zig type's own bounds.** A `u8` is `minimum: 0, maximum: 255`,
  not just `{"type":"integer"}`, because a model that sent `300` to a bare integer schema
  was obeying the contract and getting `InvalidParams` for it.

## Authorization

An HTTP server becomes a protected resource by handing the transport a guard, and a
tool states what it needs beside the handler that needs it:

```zig
mcp.tool("append_note", appendNote, .{ .scopes = "notes:write" }),

var state: mcp.velo_http.State = .init(gpa, &server, .{
    .authorization = .{ .resource_server = &protected, .baseline = "mcp:use" },
});
state.metadata = protected.metadata(&.{issuer}, &.{ "mcp:use", "notes:write" });
try mcp.velo_http.mount(&app, "/mcp");
try mcp.velo_http.mountMetadata(&app, metadata_url);
```

Credentials are checked before the body is parsed, so a client with no token gets the
`401` and the `resource_metadata` pointer that is its only way in — rather than a `400`
about its JSON. The per-tool requirement is then applied to the grant already
established, which is why widening a scope never revalidates a token.

On the client side a refusal surfaces as `error.Unauthorized`, and the transport records
what the server said:

```zig
client.listTools(arena, .{}) catch |err| switch (err) {
    error.Unauthorized => {
        const challenge = (try transport.copyChallenge(arena)).?;
        switch (try mcp.authorization.recoveryFor(arena, challenge.status, challenge.header)) {
            .authorize => |c| { ... },   // discover, PKCE, exchange
            .step_up => |c| { ... },     // union the scopes, reauthorize
            .give_up => return err,
        }
    },
    else => return err,
};
```

`zig build run-http-auth` runs all of it against real sockets: a mock authorization
server, a protected MCP server, and a client that starts with nothing and works its way
through a `401` and a `403`.

stdio is deliberately **not** covered. The specification says a stdio server SHOULD NOT
use OAuth — the client started the process and can pass credentials directly — and
`src/mcp/stdio.zig` records why in full.

Every wire payload this SDK emits is validated against `spec/schema.json` by
`zig build spec` — 103 samples across 79 schema definitions, produced by running
the real server, client, and subscription broker rather than written by hand.

## Subscriptions and the response-write bound

A `subscriptions/listen` stream is one HTTP response that never ends, and that collides
with a defence Velo applies by default: `timeouts.write_ms` bounds how long writing one
response may take, so that a peer which stops reading cannot pin a connection. The bound
is armed once around the whole response, so its 30-second default was a hard cap on how
long any subscription could live. `mcp.velo_http.listen` now lifts it for a server that
serves subscriptions, and `WriteBound` documents what that gives up and how to keep it.

Keep-alives do not help, which is the part that misleads: they are writes that *succeed*,
and the bound is on elapsed write time rather than on idleness. Nothing in this repository
could have noticed — the unit tests, all four interoperability legs, and the Inspector run
finish well inside 30 seconds. It took holding a subscription open and waiting, and it was
reported from use rather than found by the suite.

A server built with `mount` on its own Velo app has to set `write_ms = 0` itself; the
doc comment on `mount` says so, because the failure is a stream that works perfectly for
thirty seconds and then closes with no reply.

## Bounding a hung server

The mirror image, on the client: a server that accepts the POST and then says nothing.
`http_client.Options.receive_timeout_ms` bounds the wait and surfaces expiry as
`error.Timeout`.

```zig
var transport: mcp.http_client.Transport = .init(gpa, io, url, .{
    .receive_timeout_ms = 30_000,
});
```

It is a gap between bytes rather than a deadline on the exchange, which is what lets a
`subscriptions/listen` stream — a response that never ends — live under it. Abandoning the
call it belonged to is safe: request ids are never reused and `receive` skips any response
whose id it is not awaiting, so a late reply is discarded rather than mistaken for the
next one. That is a documented guarantee, and a caller building its own deadline with
`io.async` may rely on it.

There is deliberately no equivalent on `Client.Options`. A deadline needs an `Io` to wait
on and a clock to measure with, and `Client` holds neither — which is what lets the same
client drive a socket, a pipe, or an in-memory pair in a test. The knob belongs to
whichever transport owns the wait.

Two gaps stated rather than left to be found: it is not enforced on `https`, where the
socket belongs to Velo's TLS session and the read happens inside OpenSSL (the transport
writes a diagnostic when both are configured), and it does not cover connecting, since
`std.Io.net` exposes no deadline there. `SO_RCVTIMEO` is not the missing piece — on a
blocking socket it fails a read with `EAGAIN`, which `std.Io.Threaded` treats as a caller
bug and aborts on, so the socket option would turn a slow server into a crash.

## Memory

Request memory is an arena the transport owns. A handler allocates from
`context.arena` and never frees: the arena is released once the reply has been written,
so there are no `defer free`s in handler code and no way for a handler to outlive its own
allocations. Long-lived state — the registry, the subscription broker, the transport
itself — takes a general allocator from the application and is torn down by it.

Everything with a per-peer cost is a fixed-size table rather than a growing container, so
a peer cannot enlarge the server: 4096 registry entries, 256 subscribers, 64 subscribed
URIs each, 64 queued notifications each (identical ones coalesce), 1024 cancellable
in-flight requests. Exceeding one is a refusal, not an allocation.

Which allocator backs `context.arena` depends on the transport, and the difference is
large enough to matter when choosing what a tool returns:

| | Backing | Behaviour |
|---|---|---|
| Streamable HTTP, `stream_responses = true` (default) | fresh arena over the application's allocator | grows on the heap, freed when the request ends |
| Streamable HTTP, `stream_responses = false` | Velo's per-request scratch arena | **fixed 128 KiB**; exceeding it fails the request |
| stdio | one arena reused per message, `retain_capacity` | grows to the high-water mark and **keeps** it |

Three consequences worth knowing before they are discovered:

- On the default HTTP path nothing bounds a reply, so a tool whose output scales with its
  arguments lets the caller choose how much the server allocates. Clamp such arguments in
  the handler; `@min(args.limit, ceiling)` is the whole fix.
- A stdio server's memory settles at the largest message it has ever handled, because the
  arena retains capacity between messages. That is not a leak, and it is why one oversized
  response raises resident memory for the life of the process.
- Notifications are encoded into the request arena and are not freed until the request
  ends, so a handler that reports progress per row accumulates every one of those messages.
  Report per batch.

On the client side of Streamable HTTP the bound on a response is applied while it
arrives, not after. Only a declared `Content-Length` can be refused up front; a
`Transfer-Encoding: chunked` body and a `Connection: close` body with no length have
nothing to check, and those two were bounded by nothing but the server's willingness to
stop. The number of lines in a response head is bounded for the same reason.

Request bodies over HTTP are bounded by what Velo can buffer rather than by the protocol's
16 MiB ceiling, and the effective limit is lower still — the body and its parsed form share
one 128 KiB arena, so roughly 50 KB of arguments is the practical ceiling. Past it the
reply is a JSON-RPC error rather than a bare status. Larger inputs belong in a resource
the tool reads, not in its arguments.

### Returning a lot of data

The protocol has no chunked tool result: a result is one object, and progress
notifications cannot carry pieces of it. So a tool that could return a million rows has to
be designed not to, and the SDK's pagination (`page_size`, cursors) covers `tools/list`
and its siblings — not tool output. For a database server that means, in order of
preference: page in the tool's own arguments and clamp the page size; return a
`resource_link` and let the client read what it wants; report progress per batch rather
than per row; and check `context.checkCancelled()` at batch boundaries, since on HTTP a
client that closes the stream has already stopped caring about the rest.

### Handler state

Comptime-registered handlers take only a `*Context`, so application state arrives on the
context rather than through a global:

```zig
const Application = struct { broker: *mcp.subscriptions.Broker };

const server: mcp.Server = .init(&registry, info, .{ .user = &application });

fn touchReadme(context: *mcp.Context, _: struct {}) mcp.Error!mcp.types.CallToolResult {
    context.userAs(*Application).broker.publishResourcesListChanged();
    return context.textResult("announced");
}
```

It is set once on the server rather than per handler, because a server's handlers all
serve one application — per-handler pointers would let two of them disagree about which.

## Interoperability

Checked against two independent implementations. The harness is not vendored — it
installs from `interop/package.json`, which pins the versions:

```sh
cd interop && npm install
./interop/run.sh        # official TypeScript SDK, 4 legs
./interop/inspector.sh  # MCP Inspector, both transports
```

`run.sh` runs all four directions, because a bug on either side of the wire shows up in
only one of them:

| | Streamable HTTP | stdio |
|---|---|---|
| TypeScript SDK client → this server | pass | pass |
| this client → TypeScript SDK server | pass | pass |

Both TypeScript servers run with `legacy: 'reject'` and both clients pin `2026-07-28`, so
no leg can pass by quietly falling back to the 2025 protocol. What the legs cover beyond
the method surface: comptime-generated JSON Schema consumed by another SDK's validator,
`x-mcp-header` mirrored into `Mcp-Param-*` and validated against the body in both
directions, per-request progress and `logLevel` (both opt-in, so they prove the `_meta`
envelope was understood), cache hints, a failing tool arriving as `isError` rather than a
protocol error, and a multi-round-trip call driven by the official SDK's own
auto-fulfilment.

Two findings worth recording, both about the other end:

- **The Inspector does not mirror `x-mcp-header` arguments.** The Streamable HTTP binding
  is explicit — "Client omits header but value is in body | Non-conforming client | Server
  MUST reject the request" — so `interop/inspector.sh` asserts the `-32020` refusal as a
  conformance check. A server that accepted the call would be the broken one.
- **The TypeScript client drops progress notifications over stdio.** It delivers an
  arbitrary subset to `onprogress` (0 to 3 of 3, varying per run). Waiting does not change
  it, so they are dropped rather than late. Not a fault on this side: piping the identical
  request into the server shows all three on the wire ahead of the result, this SDK's
  client receives all three on both transports, and the same TypeScript client receives
  all three over HTTP — where each notification is its own SSE event rather than one of
  four messages in a single pipe read. So the exact count is asserted in the HTTP leg,
  where it is observable, and reported in the stdio leg.

## Platforms

Linux, macOS, and Windows are all built and tested in CI: the unit tests, the format
check, and the example builds run on all three. The jobs that need a shell and a network
namespace — running the example programs end to end, schema conformance, fuzzing, and the
interoperability matrix — are Linux-only.

Windows was broken until this was checked, in three places, and each one is the kind that
only shows up on the platform itself:

- `src/mcp/velo_http.zig`'s shutdown watchdog slept with `std.posix.poll`, which does not
  exist there. It now owns a private `std.Io.Threaded`, which is portable and keeps the
  property the separate thread exists for — not sharing the server's scheduler, since
  being unscheduled while idle is what it is there to notice.
- Three programs iterated argv with `Args.iterate`, a compile error on Windows, where
  argv must be decoded into a buffer the iterator owns.
- `zig fmt --check` rejected every `.zig` file, because Windows runners ship
  `core.autocrlf=true` and there was no `.gitattributes`. That one reads like a formatting
  problem in the code and is not one; see the comment in `.gitattributes`.

## Testing

```sh
zig build test      # unit tests, including the fuzz corpora
zig build spec      # every emitted payload against spec/schema.json
zig build fmt
zig build examples
```

## Fuzzing

```sh
zig build fuzz                  # 20k iterations per target, seed 0
zig build fuzz -- 500000 7      # iterations, seed
```

17 targets, covering the parsers that read bytes chosen by a peer: JSON-RPC framing, the
client-side result decoders, SSE, HTTP response and chunk framing, `requestState`
envelopes, and in `oauth` the JWT, JWKS, scope, challenge, URL, form, and metadata readers.
Inputs are mostly mutations of valid documents — bit flips, truncation, structural
injection, span duplication — because random bytes die at the first branch. A minority of
iterations are the pristine seed, without which nothing behind a signature, an HMAC, or an
exact string match is ever reached.

Each target reports what fraction of its inputs the parser **accepted**. That number is the
point: it distinguishes a target that is exercising a parser from one whose every input is
rejected immediately. Five targets read 0% when this was first written — the seeds were the
wrong shape, or were always mutated past their own integrity checks — and that was only
visible because the rate is printed.

Every iteration runs under a leak-checking allocator. Most parsers here take a
request-scoped arena, where allocating and walking away is not a leak, so one target drives
the allocator-owning entry point (`jsonrpc.parse`, which returns memory the caller must
release) to give that check something real to catch. Both the crash and leak paths are
negative-verified: introducing a leak makes the run fail, and removing it makes the run
pass.

`zig build test` also contains `std.testing.fuzz` harnesses, but treat those as smoke
tests, not fuzzing. Guided fuzzing through the test runner does not build on Zig 0.16.0 —
the compiler's own `compiler/test_runner.zig` fails in fuzz mode with a `writeStackTrace`
type mismatch, reproducible with a nine-line project containing one trivial fuzz test — and
outside fuzz mode the runner executes each harness over its declared corpus plus one empty
input. Every corpus here is empty, so each of those tests runs exactly one zero-length
input. `zig build fuzz` exists because of that, and is where the real coverage is.

## Licence

[Apache-2.0](LICENSE). Chosen over MIT for two reasons specific to this repository: it
redistributes `spec/schema.json`, which is Apache-2.0, so the whole tree is under one set
of terms rather than a mix; and the explicit patent grant matters for `oauth`, which is
authentication code other people will embed.

Third-party attribution is in [NOTICE](NOTICE).

[mcp]: https://modelcontextprotocol.io/specification/2026-07-28
[velo]: https://github.com/blue-blaze/velo
