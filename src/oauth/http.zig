//! The only part of this module that performs I/O.
//!
//! Everything else here is pure: it builds strings and validates documents that
//! somebody else fetched. That split is deliberate — it makes the security-relevant
//! logic testable without a network — but a caller still needs the fetching done,
//! and doing it wrong has security consequences of its own.
//!
//! ## Why this is a buffered client
//!
//! Unlike the MCP transport, nothing here streams. Metadata documents, key sets, and
//! token responses are single small JSON objects with a known upper bound, so Velo's
//! buffered client is exactly the right tool and this file stays short.
//!
//! ## HTTPS is enforced here
//!
//! "All authorization server endpoints **MUST** be served over HTTPS" is a
//! requirement that can only be enforced at the moment of the request. A discovery
//! document naming an `http://` token endpoint would otherwise be honored, and every
//! validation performed on it would be validation of whatever an on-path attacker
//! chose to send. Loopback is exempt so that local development works without a
//! certificate.

const std = @import("std");
const velo = @import("velo");
const assert_mod = @import("assert");

const jwk = @import("jwk.zig");
const resource_server = @import("resource_server.zig");
const url = @import("url.zig");

const assert = assert_mod.assert;

/// Default cap on a fetched document.
pub const response_bytes_max_default: usize = 256 * 1024;

/// Default lifetime of a cached key set, in milliseconds.
///
/// Long enough that key fetching is not on the hot path, short enough that a
/// rotation is picked up without operator action. A `kid` miss triggers an immediate
/// refresh regardless, so this bound only governs how stale an *unused* key set gets.
pub const key_cache_ttl_ms_default: i64 = 5 * 60 * 1000;

/// Minimum interval between forced refreshes, in milliseconds.
///
/// Without it, a stream of tokens naming a nonexistent `kid` becomes a stream of
/// requests to the authorization server — an amplification an unauthenticated peer
/// could trigger.
pub const refresh_interval_ms_min: i64 = 10 * 1000;

pub const Error = error{
    /// The URL was not absolute, or not `http`/`https`.
    InvalidUrl,
    /// The endpoint is not HTTPS and is not loopback.
    InsecureTransport,
    /// The request could not be completed.
    RequestFailed,
    /// The response exceeded the configured cap.
    ResponseTooLarge,
    /// `https` was requested but Velo was built without TLS. Refused rather than
    /// downgraded: silently using `http` for a token request would leak the token.
    TlsNotSupported,
    OutOfMemory,
};

pub const Response = struct {
    status: u16,
    body: []const u8,
    content_type: ?[]const u8,

    pub fn isSuccess(response: *const Response) bool {
        return response.status >= 200 and response.status < 300;
    }
};

pub const Options = struct {
    response_bytes_max: usize = response_bytes_max_default,
    /// Skip TLS verification. Insecure; for self-signed certificates in tests.
    tls_insecure: bool = false,
    /// Permit plain `http` to non-loopback hosts. Off by default, and turning it on
    /// forfeits the confidentiality and integrity every check in this module assumes.
    allow_insecure_http: bool = false,
    diagnostics: ?*std.Io.Writer = null,
};

/// Performs the HTTP requests the OAuth flows need.
pub const Fetcher = struct {
    io: velo.Io,
    options: Options = .{},

    pub fn init(io: velo.Io, options: Options) Fetcher {
        return .{ .io = io, .options = options };
    }

    /// Fetches a document.
    pub fn get(
        fetcher: *const Fetcher,
        arena: std.mem.Allocator,
        target: []const u8,
    ) Error!Response {
        try fetcher.checkTransport(target);
        return fetcher.send(arena, target, .{
            .max_response_bytes = fetcher.options.response_bytes_max,
            .tls_insecure = fetcher.options.tls_insecure,
        });
    }

    /// Posts an `application/x-www-form-urlencoded` body, as the token,
    /// registration, and revocation endpoints all expect.
    pub fn postForm(
        fetcher: *const Fetcher,
        arena: std.mem.Allocator,
        target: []const u8,
        body: []const u8,
        extra_headers: []const [2][]const u8,
    ) Error!Response {
        try fetcher.checkTransport(target);

        var headers: std.ArrayListUnmanaged([2][]const u8) = .empty;
        headers.append(arena, .{ "Content-Type", "application/x-www-form-urlencoded" }) catch
            return error.OutOfMemory;
        headers.append(arena, .{ "Accept", "application/json" }) catch return error.OutOfMemory;
        for (extra_headers) |header| {
            headers.append(arena, header) catch return error.OutOfMemory;
        }

        return fetcher.send(arena, target, .{
            .method = "POST",
            .headers = headers.items,
            .body = body,
            .max_response_bytes = fetcher.options.response_bytes_max,
            .tls_insecure = fetcher.options.tls_insecure,
        });
    }

    fn send(
        fetcher: *const Fetcher,
        arena: std.mem.Allocator,
        target: []const u8,
        options: velo.http.client.Options,
    ) Error!Response {
        const response = velo.http.client.request(fetcher.io, arena, target, options) catch |err| {
            fetcher.report("oauth: request to {s} failed: {s}\n", .{ target, @errorName(err) });
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.TlsNotSupported => error.TlsNotSupported,
                error.UnsupportedScheme, error.InvalidUrl => error.InvalidUrl,
                // Velo reports an over-cap body as its own error; everything else is
                // a connection or protocol failure, which are the same to a caller
                // that can only retry.
                error.ResponseTooLarge, error.StreamTooLong => error.ResponseTooLarge,
                else => error.RequestFailed,
            };
        };

        return .{
            .status = response.status,
            .body = response.body,
            .content_type = response.header("content-type"),
        };
    }

    /// Enforces the communication-security requirement.
    fn checkTransport(fetcher: *const Fetcher, target: []const u8) Error!void {
        const parts = url.parse(target) catch return error.InvalidUrl;
        if (parts.isHttps()) return;
        if (parts.isLoopback()) return;
        if (fetcher.options.allow_insecure_http) return;
        fetcher.report("oauth: refusing plain http endpoint {s}\n", .{target});
        return error.InsecureTransport;
    }

    fn report(fetcher: *const Fetcher, comptime format: []const u8, args: anytype) void {
        const writer = fetcher.options.diagnostics orelse return;
        // Best effort: a diagnostic must never change an outcome.
        writer.print(format, args) catch return;
        writer.flush() catch {};
    }
};

/// A `KeyProvider` that fetches a JWKS and caches it.
///
/// ## Concurrency
///
/// The lock is held only to read or replace the cached bytes, never across the
/// fetch. Holding it across I/O would serialize every request behind one slow
/// authorization server, and a spin lock across a network round trip is a stall
/// rather than a wait. Two threads that miss simultaneously both fetch; a duplicated
/// idempotent GET is a better outcome than a convoy.
///
/// The cache stores the raw document and reparses it into the request arena on each
/// call. Parsing a few kilobytes of JSON per request costs less than the lifetime
/// bugs that come from handing out a `KeySet` whose strings point into memory another
/// thread may be about to free.
pub const JwksProvider = struct {
    gpa: std.mem.Allocator,
    fetcher: *const Fetcher,
    jwks_uri: []const u8,
    ttl_ms: i64 = key_cache_ttl_ms_default,

    document: ?[]u8 = null,
    fetched_at_ms: i64 = 0,
    last_refresh_ms: i64 = 0,
    lock: std.atomic.Mutex = .unlocked,

    pub fn init(
        gpa: std.mem.Allocator,
        fetcher: *const Fetcher,
        jwks_uri: []const u8,
    ) JwksProvider {
        assert(jwks_uri.len > 0);
        return .{ .gpa = gpa, .fetcher = fetcher, .jwks_uri = jwks_uri };
    }

    pub fn deinit(provider: *JwksProvider) void {
        if (provider.document) |document| provider.gpa.free(document);
        provider.document = null;
    }

    pub fn keyProvider(provider: *JwksProvider) resource_server.KeyProvider {
        return .{ .ptr = provider, .vtable = &vtable };
    }

    const vtable: resource_server.KeyProvider.VTable = .{
        .keys = keys,
        .invalidate = invalidate,
    };

    fn keys(ptr: *anyopaque, arena: std.mem.Allocator) resource_server.Error!jwk.KeySet {
        const provider: *JwksProvider = @ptrCast(@alignCast(ptr));
        const now = provider.nowMs();

        // Fast path: a fresh document, copied out under the lock so that a
        // concurrent refresh cannot free it mid-parse.
        if (provider.cachedCopy(arena, now)) |copy| {
            return jwk.KeySet.parse(arena, copy) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                // A cached document that no longer parses means the cache is the
                // problem; drop it so the next request refetches.
                else => {
                    provider.forget();
                    return error.Unavailable;
                },
            };
        }

        const fetched = try provider.fetch(arena);
        return jwk.KeySet.parse(arena, fetched) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unavailable,
        };
    }

    /// Discards the cache so that the next request refetches.
    ///
    /// Called when a token names a `kid` the cached set does not contain, which is
    /// what happens for the first token signed with a newly rotated key. Rate
    /// limited by `refresh_interval_ms_min`, because the trigger is an
    /// unauthenticated request.
    fn invalidate(ptr: *anyopaque) void {
        const provider: *JwksProvider = @ptrCast(@alignCast(ptr));
        const now = provider.nowMs();

        provider.acquire();
        defer provider.release();

        if (now - provider.last_refresh_ms < refresh_interval_ms_min) return;
        provider.last_refresh_ms = now;
        if (provider.document) |document| provider.gpa.free(document);
        provider.document = null;
        provider.fetched_at_ms = 0;
    }

    fn cachedCopy(provider: *JwksProvider, arena: std.mem.Allocator, now: i64) ?[]u8 {
        provider.acquire();
        defer provider.release();

        const document = provider.document orelse return null;
        if (now - provider.fetched_at_ms > provider.ttl_ms) return null;
        return arena.dupe(u8, document) catch null;
    }

    fn fetch(provider: *JwksProvider, arena: std.mem.Allocator) resource_server.Error![]const u8 {
        // Outside the lock, deliberately.
        const response = provider.fetcher.get(arena, provider.jwks_uri) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Unavailable,
        };
        if (!response.isSuccess()) return error.Unavailable;

        const owned = provider.gpa.dupe(u8, response.body) catch return error.OutOfMemory;

        provider.acquire();
        defer provider.release();
        if (provider.document) |old| provider.gpa.free(old);
        provider.document = owned;
        provider.fetched_at_ms = provider.nowMs();
        return response.body;
    }

    fn forget(provider: *JwksProvider) void {
        provider.acquire();
        defer provider.release();
        if (provider.document) |document| provider.gpa.free(document);
        provider.document = null;
        provider.fetched_at_ms = 0;
    }

    /// Monotonic milliseconds.
    ///
    /// `.awake` rather than `.real`: a cache lifetime must not be shortened or
    /// extended by someone setting the system clock, and it is a duration rather
    /// than a point in time.
    fn nowMs(provider: *const JwksProvider) i64 {
        return std.Io.Clock.awake.now(provider.fetcher.io).toMilliseconds();
    }

    fn acquire(provider: *JwksProvider) void {
        // A spin lock: every critical section here is a pointer swap or a copy, with
        // no syscall and no I/O, so there is nothing to wait on for long.
        while (!provider.lock.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(provider: *JwksProvider) void {
        provider.lock.unlock();
    }
};

test "checkTransport enforces https outside loopback" {
    const fetcher: Fetcher = .{ .io = undefined };

    try fetcher.checkTransport("https://auth.example.com/jwks");
    try fetcher.checkTransport("http://localhost:9000/jwks");
    try fetcher.checkTransport("http://127.0.0.1:9000/jwks");
    try fetcher.checkTransport("http://[::1]:9000/jwks");

    try std.testing.expectError(
        error.InsecureTransport,
        fetcher.checkTransport("http://auth.example.com/jwks"),
    );
    try std.testing.expectError(error.InvalidUrl, fetcher.checkTransport("auth.example.com"));
    try std.testing.expectError(error.InvalidUrl, fetcher.checkTransport("ftp://auth.example.com"));
}

test "allow_insecure_http opts out explicitly" {
    const fetcher: Fetcher = .{ .io = undefined, .options = .{ .allow_insecure_http = true } };
    try fetcher.checkTransport("http://auth.example.com/jwks");
}

test "Response reports success by status class" {
    const ok: Response = .{ .status = 200, .body = "", .content_type = null };
    try std.testing.expect(ok.isSuccess());

    const created: Response = .{ .status = 201, .body = "", .content_type = null };
    try std.testing.expect(created.isSuccess());

    const not_found: Response = .{ .status = 404, .body = "", .content_type = null };
    try std.testing.expect(!not_found.isSuccess());

    const redirect: Response = .{ .status = 302, .body = "", .content_type = null };
    try std.testing.expect(!redirect.isSuccess());
}

test "JwksProvider caches, expires, and can be invalidated" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const fetcher: Fetcher = .{ .io = io };
    var provider: JwksProvider = .init(std.testing.allocator, &fetcher, "https://auth.example.com/jwks");
    defer provider.deinit();
    const now = provider.nowMs();

    // Seed the cache directly: the fetching path needs a server, which the
    // integration test in the example covers.
    provider.document = try std.testing.allocator.dupe(
        u8,
        "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a\",\"n\":\"AA\",\"e\":\"AQAB\"}]}",
    );
    provider.fetched_at_ms = now;

    const set = try JwksProvider.keys(&provider, arena.allocator());
    try std.testing.expectEqual(@as(usize, 1), set.keys.len);
    try std.testing.expectEqualStrings("a", set.keys[0].kid.?);

    // An expired cache is not served.
    provider.fetched_at_ms = now - provider.ttl_ms - 1;
    try std.testing.expectEqual(@as(?[]u8, null), provider.cachedCopy(arena.allocator(), now));

    // Invalidation drops it and is then rate limited against repetition.
    provider.fetched_at_ms = now;
    JwksProvider.invalidate(&provider);
    try std.testing.expectEqual(@as(?[]u8, null), provider.document);

    provider.document = try std.testing.allocator.dupe(u8, "{\"keys\":[]}");
    provider.fetched_at_ms = provider.nowMs();
    // Immediately again: refused, so a stream of bogus kids cannot become a stream
    // of upstream requests.
    JwksProvider.invalidate(&provider);
    try std.testing.expect(provider.document != null);
}

test "JwksProvider drops a cached document that stops parsing" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();

    const fetcher: Fetcher = .{ .io = threaded.io() };
    var provider: JwksProvider = .init(std.testing.allocator, &fetcher, "https://auth.example.com/jwks");
    defer provider.deinit();

    provider.document = try std.testing.allocator.dupe(u8, "not json");
    provider.fetched_at_ms = provider.nowMs();

    try std.testing.expectError(
        error.Unavailable,
        JwksProvider.keys(&provider, arena.allocator()),
    );
    try std.testing.expectEqual(@as(?[]u8, null), provider.document);
}
