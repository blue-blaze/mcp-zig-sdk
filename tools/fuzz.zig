//! A standalone fuzzer for the parsers that read bytes chosen by a peer.
//!
//! ## Why this exists rather than `zig build test --fuzz`
//!
//! Guided fuzzing through the test runner does not work on Zig 0.16.0: the compiler's own
//! `compiler/test_runner.zig` fails to build in fuzz mode with a `writeStackTrace` type
//! mismatch, which reproduces with a nine-line project containing one trivial
//! `std.testing.fuzz` test.
//!
//! Worse, the fallback is not the safety net it looks like. Outside fuzz mode the runner
//! runs each `std.testing.fuzz` test over its declared corpus and then once more with an
//! empty input — and every corpus in this repository is empty. So each of those tests was
//! executing exactly one zero-length input: a smoke test that the harness compiles and
//! returns, not a search for inputs that break it. Measured, not assumed.
//!
//! This is an ordinary executable, so none of that applies to it. It is coverage-blind —
//! it cannot steer toward new paths the way libFuzzer does — but it does the thing that
//! actually finds defects in byte-level parsers: take a valid input, corrupt it, and see
//! whether the parser survives. Every iteration runs under its own leak-checking
//! allocator, so a parser that returns an error while holding memory fails here too.
//!
//! ## Usage
//!
//! ```sh
//! zig build fuzz                    # 20k iterations, seed 0
//! zig build fuzz -- 200000 12345    # iterations, seed
//! ```
//!
//! A failure prints the target, the seed, and the iteration, which is enough to reproduce
//! it: the input is a pure function of seed and iteration.

const std = @import("std");
const mcp = @import("mcp");
const oauth = @import("oauth");

/// Upper bound on a generated input. Large enough to hold a realistic seed plus growth,
/// small enough that a failing case is readable when printed.
const input_bytes_max = 4096;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var args = init.minimal.args.iterate();
    _ = args.skip();
    const iterations = if (args.next()) |raw|
        try std.fmt.parseInt(usize, raw, 10)
    else
        20_000;
    const seed = if (args.next()) |raw| try std.fmt.parseInt(u64, raw, 10) else 0;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout.interface;

    // Seeds live for the whole run, so an arena that outlives every target.
    var seed_arena: std.heap.ArenaAllocator = .init(gpa);
    defer seed_arena.deinit();
    const targets = try buildTargets(seed_arena.allocator());

    try out.print("fuzzing {d} targets, {d} iterations each, seed {d}\n\n", .{
        targets.len,
        iterations,
        seed,
    });
    try out.flush();

    var failures: usize = 0;
    for (targets) |target| {
        const failed = try run(gpa, out, target, iterations, seed);
        failures += failed;
    }

    try out.print("\n{d} of {d} targets failed\n", .{ failures, targets.len });
    try out.flush();
    if (failures != 0) std.process.exit(1);
}

/// One fuzz target: a name, the seeds to mutate, and the parser to drive.
const Target = struct {
    name: []const u8,
    /// Valid — or near-valid — inputs to corrupt. Mutating a real document reaches far
    /// deeper into a parser than random bytes, which almost always die at the first byte.
    seeds: []const []const u8,
    /// Must not crash, whatever it is given. Rejecting malformed input is a pass, so the
    /// return value is not pass/fail — it reports whether the input was *accepted*, which
    /// is how this tells apart a fuzzer that is exercising a parser from one whose every
    /// input dies at the first byte.
    ///
    /// `arena` is released after the call, so allocating into it and walking away is not a
    /// leak — that is what an arena is for, and most parsers here take one by design.
    /// `gpa` is leak-checked per iteration: a target uses it for an API that hands back
    /// memory the caller must free, which is the only kind of leak this can detect.
    run: *const fn (gpa: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool,
};

fn run(
    gpa: std.mem.Allocator,
    out: *std.Io.Writer,
    target: Target,
    iterations: usize,
    seed: u64,
) !usize {
    // Derived per target so that adding a target does not shift every other target's
    // inputs, which would discard whatever confidence previous runs built up.
    var hasher = std.hash.Wyhash.init(seed);
    hasher.update(target.name);
    var prng: std.Random.DefaultPrng = .init(hasher.final());
    const random = prng.random();

    var buffer: [input_bytes_max]u8 = undefined;
    var accepted: usize = 0;

    for (0..iterations) |iteration| {
        const input = generate(random, &buffer, target.seeds);

        // A fresh leak-checking allocator per iteration: a parser that errors out while
        // still holding memory is a defect, and one shared arena would hide it.
        var debug: std.heap.DebugAllocator(.{}) = .init;
        var arena_state: std.heap.ArenaAllocator = .init(debug.allocator());
        if (target.run(debug.allocator(), arena_state.allocator(), input)) accepted += 1;
        arena_state.deinit();

        if (debug.deinit() == .leak) {
            try out.print("FAIL {s} — leaked at iteration {d} (seed {d})\n", .{
                target.name,
                iteration,
                seed,
            });
            try out.flush();
            return 1;
        }
    }

    // Reported rather than asserted: the right rate differs per target — a signed JWT
    // almost never survives mutation, while a scope string usually does. A rate of zero is
    // the one that means this target is testing nothing, and it is visible here.
    const percent = if (iterations == 0) 0 else accepted * 100 / iterations;
    try out.print("ok   {s: <36} {d}% of inputs accepted\n", .{ target.name, percent });
    try out.flush();
    _ = gpa;
    return 0;
}

/// Builds one input: sometimes pure noise, usually a corrupted seed.
fn generate(
    random: std.Random,
    buffer: *[input_bytes_max]u8,
    seeds: []const []const u8,
) []const u8 {
    // A minority of pure noise, because a parser can also be wrong about inputs that look
    // nothing like the format — but the majority is mutation, which is what gets past the
    // first branch.
    if (seeds.len == 0 or random.uintLessThan(u8, 10) == 0) {
        const length = random.uintLessThan(usize, 256);
        random.bytes(buffer[0..length]);
        return buffer[0..length];
    }

    const seed = seeds[random.uintLessThan(usize, seeds.len)];
    const length = @min(seed.len, buffer.len);
    @memcpy(buffer[0..length], seed[0..length]);
    var slice = buffer[0..length];

    // A minority of iterations use the seed untouched. Without this, targets whose input
    // is protected by a signature, an HMAC, or an exact string match never see a single
    // acceptable input — any edit invalidates it — so everything past verification stays
    // unexecuted. Measured: four targets sat at 0% accepted until this existed.
    if (random.uintLessThan(u8, 8) == 0) return slice;

    // One to four edits. A single edit usually still parses; too many and the result is
    // noise again, which the branch above already covers.
    const edits = 1 + random.uintLessThan(usize, 4);
    for (0..edits) |_| {
        if (slice.len == 0) break;
        switch (random.uintLessThan(u8, 6)) {
            // Flip a bit: finds off-by-one and sign confusion in length fields.
            0 => slice[random.uintLessThan(usize, slice.len)] ^= @as(u8, 1) << random.int(u3),
            // Replace a byte with an arbitrary one.
            1 => slice[random.uintLessThan(usize, slice.len)] = random.int(u8),
            // Truncate: the case a parser reaching past its input gets wrong.
            2 => slice = slice[0..random.uintLessThan(usize, slice.len)],
            // Insert a structural character, which is how nesting and quoting break.
            3 => {
                const structural = "{}[]\",:\\ \r\n\t=?";
                slice[random.uintLessThan(usize, slice.len)] =
                    structural[random.uintLessThan(usize, structural.len)];
            },
            // Duplicate a span: produces repeated keys and doubled separators.
            4 => {
                const at = random.uintLessThan(usize, slice.len);
                const span = @min(slice.len - at, 1 + random.uintLessThan(usize, 16));
                const end = @min(buffer.len, slice.len + span);
                if (end > slice.len) {
                    std.mem.copyBackwards(u8, buffer[slice.len..end], slice[at..][0..(end - slice.len)]);
                    slice = buffer[0..end];
                }
            },
            // Zero a span: NUL bytes inside otherwise valid text.
            else => {
                const at = random.uintLessThan(usize, slice.len);
                const span = @min(slice.len - at, 1 + random.uintLessThan(usize, 8));
                @memset(slice[at..][0..span], 0);
            },
        }
    }
    return slice;
}

// ---------------------------------------------------------------------------
// Seeds
// ---------------------------------------------------------------------------

// Seeds that have to be *valid* are generated rather than written out, because a
// hand-written one that is subtly wrong is rejected at the first check and the target
// silently tests nothing. The acceptance rate this program reports is what makes that
// visible; these four targets read 0% until the seeds became real.
var generated_jwks: []const u8 = "";
var generated_jwt: []const u8 = "";
var generated_state: []const u8 = "";

const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const fuzz_key_seed: [Scheme.KeyPair.seed_length]u8 = @splat(0x31);

/// Builds a real key set, a real signature over it, and a real sealed `requestState`.
fn generateSeeds(arena: std.mem.Allocator) !void {
    const pair = try Scheme.KeyPair.generateDeterministic(fuzz_key_seed);
    const sec1 = pair.public_key.toUncompressedSec1();

    generated_jwks = try std.fmt.allocPrint(
        arena,
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"use\":\"sig\"," ++
            "\"alg\":\"ES256\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}",
        .{
            try oauth.base64url.encode(arena, sec1[1..33]),
            try oauth.base64url.encode(arena, sec1[33..65]),
        },
    );

    const header = try oauth.base64url.encode(arena, "{\"alg\":\"ES256\",\"kid\":\"k1\",\"typ\":\"at+jwt\"}");
    const claims = try std.fmt.allocPrint(
        arena,
        "{{\"iss\":\"https://as.example.com\",\"aud\":\"https://mcp.example.com\"," ++
            "\"sub\":\"u1\",\"scope\":\"mcp:use\",\"iat\":{d},\"exp\":{d}}}",
        .{ fuzz_now - 60, fuzz_now + 600 },
    );
    const payload = try oauth.base64url.encode(arena, claims);
    const signing_input = try std.fmt.allocPrint(arena, "{s}.{s}", .{ header, payload });
    const signature = try pair.sign(signing_input, null);
    generated_jwt = try std.fmt.allocPrint(arena, "{s}.{s}", .{
        signing_input,
        try oauth.base64url.encode(arena, &signature.toBytes()),
    });

    const sealer: mcp.request_state.Sealer = .init("fuzz-secret");
    generated_state = try sealer.seal(arena, .{
        .principal = "user-1",
        .method = "tools/call",
        .state = "{\"step\":1}",
        .expires_at = fuzz_now + 300,
        .params_digest = @splat(0),
    });
}

/// One fixed instant, so an expiry check is a property of the seed rather than of when the
/// fuzzer happens to run.
const fuzz_now: i64 = 1_800_000_000;

const request_meta =
    "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientCapabilities\":{}}";

const jsonrpc_seeds = [_][]const u8{
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++ request_meta ++ "}}",
    "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"tools/call\",\"params\":{" ++ request_meta ++
        ",\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":7}}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"bad\"}}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"tools\":[]}}",
};

/// Result *objects*, which is what the decoders take — the envelope is `jsonrpc`'s job.
/// Seeding these with envelopes is what held this target at 0% accepted.
const result_seeds = [_][]const u8{
    "{\"resultType\":\"complete\",\"ttlMs\":0,\"cacheScope\":\"private\",\"tools\":[" ++
        "{\"name\":\"add\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]}",
    "{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"isError\":false}",
    "{\"resultType\":\"complete\",\"ttlMs\":300000,\"cacheScope\":\"public\",\"contents\":[" ++
        "{\"uri\":\"file:///a\",\"text\":\"x\",\"mimeType\":\"text/plain\"}]}",
    "{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{}}",
    "{\"resultType\":\"input_required\",\"requestState\":\"abc\"}",
    "{\"resultType\":\"complete\",\"messages\":[{\"role\":\"user\"," ++
        "\"content\":{\"type\":\"text\",\"text\":\"q\"}}]}",
    "{\"resultType\":\"complete\",\"completion\":{\"values\":[\"a\"],\"hasMore\":false}}",
};

const sse_seeds = [_][]const u8{
    "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n",
    ":\r\n\r\ndata: {\"a\":1}\r\n\r\n",
    "event: message\r\nid: 4\r\ndata: {\"a\":1}\r\ndata: {\"b\":2}\r\n\r\n",
    "retry: 100\ndata: x\n\n",
};

const http_response_seeds = [_][]const u8{
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "1a\r\ndata: {\"jsonrpc\":\"2.0\"}\r\n\r\n0\r\n\r\n",
    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer resource_metadata=\"https://a.example/m\"\r\n" ++
        "Content-Length: 0\r\n\r\n",
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 60\r\n\r\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32020,\"message\":\"x\"}}",
};

const challenge_seeds = [_][]const u8{
    "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
    "Bearer error=\"insufficient_scope\", scope=\"mcp:use files:write\", realm=\"mcp\"",
    "Bearer error=\"invalid_token\", error_description=\"expired\"",
    "Negotiate, Bearer scope=\"a b\"",
};

const scope_seeds = [_][]const u8{
    "mcp:use",
    "mcp:use files:read files:write offline_access",
    "a b  c\td",
};

const url_seeds = [_][]const u8{
    "https://as.example.com/tenant1",
    "http://127.0.0.1:8790/token",
    "https://[::1]:443/x?a=b#c",
};

const jwks_seeds = [_][]const u8{
    "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"use\":\"sig\",\"alg\":\"ES256\"," ++
        "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," ++
        "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]}",
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"r1\",\"alg\":\"RS256\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}",
    "{\"keys\":[]}",
};

const prm_seeds = [_][]const u8{
    "{\"resource\":\"https://mcp.example.com/mcp\"," ++
        "\"authorization_servers\":[\"https://as.example.com\"]," ++
        "\"scopes_supported\":[\"mcp:use\"],\"bearer_methods_supported\":[\"header\"]}",
};

const as_metadata_seeds = [_][]const u8{
    "{\"issuer\":\"https://as.example.com\"," ++
        "\"authorization_endpoint\":\"https://as.example.com/authorize\"," ++
        "\"token_endpoint\":\"https://as.example.com/token\"," ++
        "\"jwks_uri\":\"https://as.example.com/jwks\"," ++
        "\"code_challenge_methods_supported\":[\"S256\"]}",
};

const token_seeds = [_][]const u8{
    "{\"access_token\":\"abc.def.ghi\",\"token_type\":\"Bearer\",\"expires_in\":300," ++
        "\"scope\":\"mcp:use\",\"refresh_token\":\"r\"}",
    "{\"error\":\"invalid_grant\",\"error_description\":\"code already used\"}",
};

const cimd_seeds = [_][]const u8{
    "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"App\"," ++
        "\"redirect_uris\":[\"http://127.0.0.1:3000/callback\"]}",
};

const jwt_seeds = [_][]const u8{
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIn0.AAAA",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.",
};

const form_seeds = [_][]const u8{
    "code=abc&state=xyz&iss=https%3A%2F%2Fas.example.com",
    "error=access_denied&error_description=user+said+no&state=xyz",
};

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

fn buildTargets(arena: std.mem.Allocator) ![]const Target {
    try generateSeeds(arena);

    const jwks = try arena.dupe([]const u8, &.{generated_jwks});
    const jwt = try arena.dupe([]const u8, &.{ generated_jwt, jwt_seeds[0], jwt_seeds[1] });
    const state = try arena.dupe([]const u8, &.{generated_state});

    const dynamic = [_]Target{
        .{ .name = "oauth.jwk.KeySet.parse", .seeds = jwks, .run = fuzzJwks },
        .{ .name = "oauth.jwt.verify", .seeds = jwt, .run = fuzzJwt },
        .{ .name = "request_state.verify", .seeds = state, .run = fuzzRequestState },
    };

    const all = try arena.alloc(Target, static_targets.len + dynamic.len);
    @memcpy(all[0..static_targets.len], &static_targets);
    @memcpy(all[static_targets.len..], &dynamic);
    return all;
}

const static_targets = [_]Target{
    .{ .name = "jsonrpc.parseLeaky", .seeds = &jsonrpc_seeds, .run = fuzzJsonRpc },
    .{ .name = "jsonrpc.parse (owned arena)", .seeds = &jsonrpc_seeds, .run = fuzzJsonRpcOwned },
    .{ .name = "types result decoders", .seeds = &result_seeds, .run = fuzzDecoders },
    .{ .name = "sse.Decoder", .seeds = &sse_seeds, .run = fuzzSse },
    .{ .name = "http_client.Response", .seeds = &http_response_seeds, .run = fuzzHttpResponse },
    .{ .name = "oauth.bearer.parseChallenge", .seeds = &challenge_seeds, .run = fuzzChallenge },
    .{ .name = "mcp.authorization.recoveryFor", .seeds = &challenge_seeds, .run = fuzzRecovery },
    .{ .name = "oauth.scope.Set.parse", .seeds = &scope_seeds, .run = fuzzScope },
    .{ .name = "oauth.url.parse", .seeds = &url_seeds, .run = fuzzUrl },
    .{ .name = "oauth.url.FormIterator", .seeds = &form_seeds, .run = fuzzForm },
    .{ .name = "oauth.prm.parse", .seeds = &prm_seeds, .run = fuzzPrm },
    .{ .name = "oauth.as_metadata.parse", .seeds = &as_metadata_seeds, .run = fuzzAsMetadata },
    .{ .name = "oauth.token response", .seeds = &token_seeds, .run = fuzzToken },
    .{ .name = "oauth.cimd.parse", .seeds = &cimd_seeds, .run = fuzzCimd },
};

fn fuzzJsonRpc(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    _ = mcp.jsonrpc.parseLeaky(arena, input) catch return false;
    return true;
}

/// The allocator-owning entry point: `parse` returns a `Parsed` carrying its own arena,
/// which the caller must release. Driven from the leak-checked allocator, so a failure path
/// inside `parse` that forgets to unwind its own allocation is visible here.
fn fuzzJsonRpcOwned(gpa: std.mem.Allocator, _: std.mem.Allocator, input: []const u8) bool {
    var parsed = mcp.jsonrpc.parse(gpa, input) catch return false;
    parsed.deinit();
    return true;
}

fn fuzzDecoders(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, input, .{}) catch return false;
    var any = false;
    inline for (.{
        mcp.types.DiscoverResult,
        mcp.types.ListToolsResult,
        mcp.types.ReadResourceResult,
        mcp.types.CallToolResult,
        mcp.types.GetPromptResult,
        mcp.types.CompleteResult,
    }) |Result| {
        if (mcp.types.decode(Result, arena, value)) |_| any = true else |_| {}
    }
    return any;
}

fn fuzzSse(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    var reader: std.Io.Reader = .fixed(input);
    var decoder: mcp.sse.Decoder = .{ .reader = &reader };
    var events: usize = 0;
    while (events < 64) {
        const message = decoder.next(arena) catch return events != 0;
        if (message == null) break;
        events += 1;
    }
    return events != 0;
}

fn fuzzHttpResponse(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    var reader: std.Io.Reader = .fixed(input);
    var response = mcp.http_client.Response.read(&reader, arena, input_bytes_max) catch return false;
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        const message = response.next(arena, input_bytes_max) catch break;
        if (message == null) break;
    }
    // The head parsed; body framing may still have been rejected, which is its own pass.
    return true;
}

fn fuzzRequestState(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    const sealer: mcp.request_state.Sealer = .init("fuzz-secret");
    _ = sealer.verify(arena, input, .{
        .principal = "user-1",
        .method = "tools/call",
        .params_digest = @splat(0),
        .now = 1_800_000_000,
    }) catch return false;
    return true;
}

fn fuzzChallenge(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    const parsed = oauth.bearer.parseChallenge(arena, input) catch return false;
    return parsed != null;
}

fn fuzzRecovery(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    var actionable = false;
    for ([_]u16{ 401, 403, 503 }) |status| {
        const recovery = mcp.authorization.recoveryFor(arena, status, input) catch return false;
        if (recovery != .give_up) actionable = true;
    }
    return actionable;
}

fn fuzzScope(_: std.mem.Allocator, _: std.mem.Allocator, input: []const u8) bool {
    const set = oauth.scope.Set.parse(input) catch return false;
    _ = set.contains("mcp:use");
    _ = oauth.scope.Set.unionOf(set.value(), "files:write") catch return false;
    return true;
}

fn fuzzUrl(_: std.mem.Allocator, _: std.mem.Allocator, input: []const u8) bool {
    const parts = oauth.url.parse(input) catch return false;
    var buffer: [512]u8 = undefined;
    if (parts.host.len + 8 < buffer.len) _ = parts.authority(&buffer);
    _ = parts.pathComponent();
    return true;
}

fn fuzzForm(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    var iterator: oauth.url.FormIterator = .init(input);
    var pairs: usize = 0;
    while (pairs < 64) {
        const pair = iterator.next(arena) catch return pairs != 0;
        if (pair == null) break;
        pairs += 1;
    }
    return pairs != 0;
}

fn fuzzJwks(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    const set = oauth.jwk.KeySet.parse(arena, input) catch return false;
    var usable = false;
    for (set.keys) |key| {
        inline for (comptime std.enums.values(oauth.jwk.Algorithm)) |algorithm| {
            if (key.permits(algorithm)) {
                if (key.publicKey(algorithm)) |_| usable = true else |_| {}
            }
        }
    }
    return usable;
}

fn fuzzJwt(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    // A real key set, so the fuzzer reaches signature verification rather than stopping at
    // "no key for this kid".
    const set = oauth.jwk.KeySet.parse(arena, generated_jwks) catch return false;
    var keys = set;
    _ = oauth.jwt.verify(arena, input, &keys, .{
        .issuer = "https://as.example.com",
        .audience = "https://mcp.example.com",
        .now = fuzz_now,
    }) catch return false;
    return true;
}

fn fuzzPrm(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    _ = oauth.prm.parse(arena, input) catch return false;
    return true;
}

fn fuzzAsMetadata(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    _ = oauth.as_metadata.parse(arena, input, "https://as.example.com") catch return false;
    return true;
}

fn fuzzToken(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    // The failure out-parameter is part of the contract: an error response is parsed into
    // it rather than thrown away, so a fuzzer that passed null would skip that path.
    var failure: ?oauth.token.Failure = null;
    const context: oauth.token.ParseContext = .{
        .issuer = "https://as.example.com",
        .resource = "https://mcp.example.com/mcp",
        .now = 1_800_000_000,
    };
    _ = oauth.token.parseResponse(arena, input, context, &failure) catch return failure != null;
    return true;
}

fn fuzzCimd(_: std.mem.Allocator, arena: std.mem.Allocator, input: []const u8) bool {
    _ = oauth.cimd.parse(
        arena,
        input,
        "https://app.example.com/oauth/client.json",
    ) catch return false;
    return true;
}
