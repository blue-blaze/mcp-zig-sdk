//! Authorization for MCP transports: the MCP-shaped view of the `oauth` module.
//!
//! An MCP server that accepts HTTP is an OAuth 2.1 resource server. The `oauth`
//! module already decides what one request establishes; what it cannot know is
//! *when* to ask, and what the operation being requested requires. That is what this
//! file adds:
//!
//! 1. A baseline requirement that applies to every request, checked before the body
//!    is parsed.
//! 2. A per-operation requirement, read from the registry, checked after.
//!
//! ## Why authentication happens before the body is parsed
//!
//! The scopes an operation needs are only knowable once the body has been read — the
//! tool name is in it. It would be simpler to parse first and make a single
//! authorization decision with the full requirement in hand.
//!
//! But a client with no credentials at all must learn that from a `401` carrying
//! `resource_metadata`; that is the entire discovery mechanism the specification
//! defines. If a malformed body were answered with `400` before the missing token was
//! noticed, such a client would be told its JSON was bad and would never find out
//! that the resource is protected, nor where to go to get in. So credentials are
//! checked first, against the baseline, and the operation's requirement is applied
//! afterwards to the grant that check produced.
//!
//! Authentication still happens exactly once. `Guard.authenticate` validates the
//! token; `Guard.authorizeOperation` is a pure function of the resulting grant and
//! can only ever produce `403`. The 401-versus-403 decision therefore still has a
//! single home, inside `oauth`.
//!
//! ## Why a rejection carries no JSON-RPC body
//!
//! Every other failure this transport produces is a JSON-RPC error, because every
//! other failure is about the request. These are not: the request was never looked
//! at. There is no reserved error code for "you need a token", and borrowing one that
//! means something else would tell the client something untrue. RFC 6750 already
//! defines the response for this case, and it is the `WWW-Authenticate` header.
//!
//! ## stdio
//!
//! This does not apply to stdio, and deliberately so. The specification says a
//! stdio server SHOULD NOT use OAuth: the client launched the process, so it is
//! already in a position to hand over credentials directly, and there is no origin to
//! defend against. Such a server reads credentials from its environment — see
//! `bearerHeader` and the note on it.

const std = @import("std");
const assert_mod = @import("assert");
const oauth = @import("oauth");

const assert = assert_mod.assert;

/// A refusal to serve a request, ready to become an HTTP response.
///
/// Kept independent of any particular transport's response type so that this file
/// does not depend on a transport, and a transport does not have to reach into
/// `oauth` to build one.
pub const Rejection = struct {
    /// 401 when credentials are missing or invalid, 403 when they are insufficient,
    /// 503 when validation could not be performed.
    status: u16,
    /// The `WWW-Authenticate` value. Absent on 503: there is nothing for the client
    /// to fix, and offering a challenge would invite it to discard a working token
    /// and reauthorize, which is the one reaction that cannot help.
    challenge: ?[]const u8 = null,
};

/// What the guard decided about one request.
pub const Decision = union(enum) {
    granted: oauth.Grant,
    reject: Rejection,
};

/// Applies a resource server and a baseline scope requirement to MCP requests.
pub const Guard = struct {
    resource_server: *const oauth.ResourceServer,

    /// Scopes every request must carry, whatever it asks for.
    ///
    /// Null means authentication alone suffices for operations that declare no scopes
    /// of their own. That is a real deployment: a server whose whole surface is
    /// equally sensitive has nothing to express here.
    baseline: ?[]const u8 = null,

    /// Step one: check the credentials, before the body has been parsed.
    ///
    /// `authorization` is the raw `Authorization` header value, or null when absent.
    pub fn authenticate(
        guard: *const Guard,
        arena: std.mem.Allocator,
        authorization: ?[]const u8,
        now: i64,
    ) error{OutOfMemory}!Decision {
        const outcome = try guard.resource_server.authorize(
            arena,
            authorization,
            guard.baseline,
            now,
        );
        return switch (outcome) {
            .granted => |grant| .{ .granted = grant },
            .challenge => |challenge| .{ .reject = .{
                .status = challenge.status,
                .challenge = challenge.header,
            } },
            // No challenge: see `Rejection.challenge`.
            .unavailable => .{ .reject = .{ .status = 503, .challenge = null } },
        };
    }

    /// Step two: check the grant against what this particular operation requires.
    ///
    /// `required` is what the operation declares, or null when it declares nothing.
    /// Returns null when the request may proceed.
    ///
    /// The two requirements are unioned rather than one replacing the other: an
    /// operation naming its own scopes is saying what it needs *in addition*, and a
    /// baseline that a specific operation could switch off would not be a baseline.
    pub fn authorizeOperation(
        guard: *const Guard,
        arena: std.mem.Allocator,
        grant: *const oauth.Grant,
        required: ?[]const u8,
    ) error{OutOfMemory}!?Rejection {
        const operation = required orelse return null;

        // The baseline was already enforced in step one, so when there is none the
        // operation's own requirement is the whole of it and no union is needed.
        const baseline = guard.baseline orelse {
            const challenge = try guard.resource_server.checkScopes(arena, grant, operation) orelse
                return null;
            return .{ .status = challenge.status, .challenge = challenge.header };
        };

        const combined = oauth.ScopeSet.unionOf(baseline, operation) catch {
            // A requirement this deployment cannot even represent is a configuration
            // fault, not a client fault. Refusing is the only safe reading: treating
            // an unrepresentable requirement as satisfied would grant the operation.
            return .{ .status = 403, .challenge = null };
        };

        const challenge = try guard.resource_server.checkScopes(
            arena,
            grant,
            combined.value(),
        ) orelse return null;
        return .{ .status = challenge.status, .challenge = challenge.header };
    }
};

/// What a client should do about a refusal.
pub const Recovery = union(enum) {
    /// Obtain a token. Either none was sent or the one that was is not acceptable, so
    /// discovery starts from `resource_metadata` and runs the whole authorization flow.
    authorize: oauth.ParsedChallenge,
    /// Widen the token already held: it authenticated, but the operation needs scopes
    /// it does not carry. The challenge names all of them, and a client must ask for
    /// the union of these and what it asked for before — asking for only these would
    /// silently drop the access it already had.
    step_up: oauth.ParsedChallenge,
    /// Nothing to act on: no challenge, no `Bearer` challenge in it, or one that names
    /// no metadata document to start from. Retrying cannot help.
    give_up,
};

/// Reads a refusal and says what to do about it.
///
/// Takes the status and the raw header rather than a transport's own type, so that this
/// stays independent of any particular transport — and so that a caller holding a
/// challenge from anywhere can use it.
///
/// The status decides between the two recoveries, not the `error` parameter. A 403 is
/// the only status the specification uses for insufficient scope, and a server that
/// sent `insufficient_scope` with a 401 is telling a client to reauthorize; obeying the
/// status is the reading that cannot loop.
pub fn recoveryFor(
    arena: std.mem.Allocator,
    status: u16,
    challenge_header: ?[]const u8,
) error{OutOfMemory}!Recovery {
    const raw = challenge_header orelse return .give_up;
    const parsed = oauth.bearer.parseChallenge(arena, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // A challenge that cannot be read is a challenge that cannot be followed.
        // Guessing at a metadata URL from a malformed header would mean starting
        // discovery from something the server did not say.
        error.ChallengeTooLong, error.Malformed => return .give_up,
    } orelse return .give_up;

    if (status == 403) {
        // Step-up needs the scopes; without them there is nothing to widen towards.
        if (parsed.scope == null) return .give_up;
        return .{ .step_up = parsed };
    }
    if (status == 401) {
        // Discovery has to start somewhere the server named.
        if (parsed.resource_metadata == null) return .give_up;
        return .{ .authorize = parsed };
    }
    return .give_up;
}

/// Renders an `Authorization` header value for a bearer token.
///
/// Useful on the client side of both transports. Over stdio it is how a server's
/// environment-supplied credential reaches an upstream API — note that it must be a
/// credential of the server's own, never the one the server was handed: forwarding a
/// received token is exactly the confused-deputy pattern the audience restriction
/// exists to prevent.
pub fn bearerHeader(arena: std.mem.Allocator, token: []const u8) error{OutOfMemory}![]const u8 {
    assert(token.len > 0);
    return std.fmt.allocPrint(arena, oauth.bearer.scheme ++ " {s}", .{token});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A verifier that accepts one token and reports fixed scopes.
const StubVerifier = struct {
    token: []const u8,
    scopes: []const u8,
    fail: ?oauth.resource_server.Error = null,

    fn verify(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        token: []const u8,
        now: i64,
    ) oauth.resource_server.Error!oauth.Grant {
        _ = arena;
        _ = now;
        const stub: *StubVerifier = @ptrCast(@alignCast(ptr));
        if (stub.fail) |err| return err;
        if (!std.mem.eql(u8, token, stub.token)) return error.InvalidToken;
        return .{
            .issuer = "https://as.example.com",
            .audience = "https://mcp.example.com",
            .subject = "user-1",
            .scopes = stub.scopes,
        };
    }

    fn verifier(stub: *StubVerifier) oauth.Verifier {
        return .{
            .ptr = stub,
            .vtable = &.{ .verify = StubVerifier.verify },
        };
    }
};

const Fixture = struct {
    stub: StubVerifier,
    server: oauth.ResourceServer,

    fn init(scopes: []const u8) Fixture {
        return .{
            .stub = .{ .token = "good", .scopes = scopes },
            .server = undefined,
        };
    }

    fn guard(fixture: *Fixture, baseline: ?[]const u8) Guard {
        fixture.server = .init(fixture.stub.verifier(), .{
            .resource = "https://mcp.example.com",
            .metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource",
            .scopes_supported = "mcp:use",
        });
        return .{ .resource_server = &fixture.server, .baseline = baseline };
    }
};

test "a request with no credentials is a 401 naming the metadata document" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use");
    const guard = fixture.guard("mcp:use");

    const decision = try guard.authenticate(arena, null, 0);
    try testing.expect(decision == .reject);
    try testing.expectEqual(@as(u16, 401), decision.reject.status);
    const challenge = decision.reject.challenge.?;
    try testing.expect(std.mem.indexOf(u8, challenge, "resource_metadata=") != null);
    // The scope hint has to be there, or the client's first authorization request
    // asks for nothing and comes back just as unauthorized.
    try testing.expect(std.mem.indexOf(u8, challenge, "mcp:use") != null);
}

test "validation being impossible is a 503 with no challenge" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use");
    fixture.stub.fail = error.Unavailable;
    const guard = fixture.guard(null);

    const decision = try guard.authenticate(arena, "Bearer good", 0);
    try testing.expect(decision == .reject);
    try testing.expectEqual(@as(u16, 503), decision.reject.status);
    try testing.expectEqual(@as(?[]const u8, null), decision.reject.challenge);
}

test "a valid token satisfying the baseline is granted" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use files:read");
    const guard = fixture.guard("mcp:use");

    const decision = try guard.authenticate(arena, "Bearer good", 0);
    try testing.expect(decision == .granted);
    try testing.expectEqualStrings("user-1", decision.granted.subject.?);
}

test "an operation scope the grant lacks is a 403 naming baseline and operation" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use");
    const guard = fixture.guard("mcp:use");

    const decision = try guard.authenticate(arena, "Bearer good", 0);
    try testing.expect(decision == .granted);

    const rejection = (try guard.authorizeOperation(
        arena,
        &decision.granted,
        "files:write",
    )).?;
    try testing.expectEqual(@as(u16, 403), rejection.status);
    const challenge = rejection.challenge.?;
    try testing.expect(std.mem.indexOf(u8, challenge, "insufficient_scope") != null);
    // Both, at once: a challenge that named only the missing one would cost the user
    // an interaction now and another one on the next operation.
    try testing.expect(std.mem.indexOf(u8, challenge, "mcp:use") != null);
    try testing.expect(std.mem.indexOf(u8, challenge, "files:write") != null);
}

test "an operation declaring no scopes rides on the baseline alone" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use");
    const guard = fixture.guard("mcp:use");

    const decision = try guard.authenticate(arena, "Bearer good", 0);
    try testing.expectEqual(
        @as(?Rejection, null),
        try guard.authorizeOperation(arena, &decision.granted, null),
    );
}

test "an operation scope the grant holds passes" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use files:write");
    const guard = fixture.guard("mcp:use");

    const decision = try guard.authenticate(arena, "Bearer good", 0);
    try testing.expectEqual(
        @as(?Rejection, null),
        try guard.authorizeOperation(arena, &decision.granted, "files:write"),
    );
}

test "with no baseline an operation requirement still applies" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use");
    const guard = fixture.guard(null);

    const decision = try guard.authenticate(arena, "Bearer good", 0);
    try testing.expect(decision == .granted);

    const rejection = (try guard.authorizeOperation(
        arena,
        &decision.granted,
        "files:write",
    )).?;
    try testing.expectEqual(@as(u16, 403), rejection.status);
}

test "an invalid token is a 401 rather than a 403" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fixture: Fixture = .init("mcp:use");
    const guard = fixture.guard("mcp:use");

    const decision = try guard.authenticate(arena, "Bearer wrong", 0);
    try testing.expect(decision == .reject);
    // 403 would tell the client to ask for more scopes, which cannot fix a token that
    // does not validate.
    try testing.expectEqual(@as(u16, 401), decision.reject.status);
}

test "a 401 naming a metadata document means authorize" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();

    const recovery = try recoveryFor(
        arena_state.allocator(),
        401,
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:use\"",
    );
    try testing.expect(recovery == .authorize);
    try testing.expectEqualStrings(
        "https://mcp.example.com/.well-known/oauth-protected-resource",
        recovery.authorize.resource_metadata.?,
    );
}

test "a 403 naming scopes means step up" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();

    const recovery = try recoveryFor(
        arena_state.allocator(),
        403,
        "Bearer error=\"insufficient_scope\", scope=\"mcp:use files:write\"",
    );
    try testing.expect(recovery == .step_up);
    try testing.expectEqualStrings("mcp:use files:write", recovery.step_up.scope.?);
}

test "the status decides, not the error parameter" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();

    // `insufficient_scope` on a 401 is a server that wants reauthorization. Treating it
    // as a step-up would widen a token the server has already refused, and try again.
    const recovery = try recoveryFor(
        arena_state.allocator(),
        401,
        "Bearer error=\"insufficient_scope\", scope=\"files:write\", " ++
            "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
    );
    try testing.expect(recovery == .authorize);
}

test "a refusal with nothing actionable is not retried" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No header at all.
    try testing.expect(try recoveryFor(arena, 401, null) == .give_up);
    // A scheme this client cannot speak.
    try testing.expect(try recoveryFor(arena, 401, "Negotiate") == .give_up);
    // A 401 with no metadata document: discovery would have no starting point.
    try testing.expect(try recoveryFor(arena, 401, "Bearer realm=\"mcp\"") == .give_up);
    // A 403 with no scopes: nothing to widen towards.
    try testing.expect(
        try recoveryFor(arena, 403, "Bearer error=\"insufficient_scope\"") == .give_up,
    );
    // 503 is not an authorization failure at all.
    try testing.expect(try recoveryFor(arena, 503, "Bearer") == .give_up);
}

test "bearerHeader renders the scheme the specification allows" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();

    try testing.expectEqualStrings(
        "Bearer abc.def.ghi",
        try bearerHeader(arena_state.allocator(), "abc.def.ghi"),
    );
}

test "fuzz recoveryFor against arbitrary challenge headers" {
    // The header is written by whoever refused the request, and what this returns decides
    // whether the client starts an authorization flow. A crash here would be reachable by
    // any server a client is pointed at; a `give_up` never is a problem, so the property
    // is that every input produces one of the three answers.
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [1024]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            for ([_]u16{ 401, 403, 503, 200 }) |status| {
                const recovery = recoveryFor(arena, status, buffer[0..length]) catch continue;
                switch (recovery) {
                    // A recovery must carry what the next step needs, or it is not a
                    // recovery: discovery with no starting point and widening with no
                    // target are both loops.
                    .authorize => |challenge| {
                        try std.testing.expectEqual(@as(u16, 401), status);
                        try std.testing.expect(challenge.resource_metadata != null);
                    },
                    .step_up => |challenge| {
                        try std.testing.expectEqual(@as(u16, 403), status);
                        try std.testing.expect(challenge.scope != null);
                    },
                    .give_up => {},
                }
            }
        }
    }.run, .{});
}
