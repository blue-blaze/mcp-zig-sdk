//! The token endpoint: exchanging an authorization code, refreshing, and reading
//! what came back.
//!
//! ## `resource` goes in the token request too
//!
//! RFC 8707 requires the `resource` parameter in **both** the authorization request
//! and the token request. Sending it only in the first is a common mistake with a
//! quiet consequence: the authorization server has no way to know which resource the
//! token being minted is for, so it issues one whose audience is unconstrained — and
//! an unconstrained token is exactly what a compromised MCP server needs in order to
//! replay it somewhere else.
//!
//! ## Refresh tokens are confidential and not guaranteed
//!
//! A refresh token is longer-lived than the access token it replaces, so it is the
//! more valuable secret. The authorization server decides whether to issue one at
//! all; a client that assumes it has one and stores nothing else will silently
//! require a full re-authorization the first time the assumption is wrong. `TokenSet`
//! therefore makes it optional and records what was actually granted.

const std = @import("std");
const assert_mod = @import("assert");

const prm = @import("prm.zig");
const scope = @import("scope.zig");
const url = @import("url.zig");

const assert = assert_mod.assert;

/// The only token type this stack can present.
///
/// Compared case-insensitively per RFC 6749 Section 7.1.
pub const token_type_bearer = "Bearer";

/// Upper bound on a token endpoint response.
pub const response_bytes_max = 128 * 1024;

/// Default leeway when deciding whether an access token is still usable, in seconds.
///
/// A token that expires while in flight produces a 401 the client then has to
/// recover from; treating the last few seconds as already expired turns that into a
/// refresh it was going to do anyway.
pub const expiry_leeway_seconds_default: i64 = 30;

/// How a client authenticates to the token endpoint.
///
/// `private_key_jwt` is deliberately absent. The specification permits it, but it
/// requires the client to sign an assertion, and `std.crypto` has RSA verification
/// without RSA signing — so the only algorithms available would be EC, which not all
/// authorization servers accept. Offering a partial implementation of client
/// authentication would be worse than requiring the caller to supply one.
pub const ClientAuth = union(enum) {
    /// A public client. Correct for a client that cannot keep a secret, which is most
    /// MCP clients, and safe precisely because PKCE is mandatory.
    none,
    /// The secret in the form body.
    secret_post: []const u8,
    /// The secret in an `Authorization: Basic` header. Preferred by RFC 6749 where a
    /// secret exists at all.
    secret_basic: []const u8,

    pub fn method(auth: ClientAuth) []const u8 {
        return switch (auth) {
            .none => "none",
            .secret_post => "client_secret_post",
            .secret_basic => "client_secret_basic",
        };
    }
};

pub const BuildError = error{
    InvalidResource,
    OutOfMemory,
};

/// A request ready to POST: the form body and any extra headers it needs.
pub const Request = struct {
    body: []const u8,
    /// Headers beyond `Content-Type`, which the transport supplies. Non-empty only
    /// for `client_secret_basic`.
    headers: []const [2][]const u8,
};

pub const CodeExchange = struct {
    code: []const u8,
    /// Must be byte-identical to the one in the authorization request.
    redirect_uri: []const u8,
    client_id: []const u8,
    /// The PKCE secret. This is what proves the client that redeems the code is the
    /// one that requested it.
    code_verifier: []const u8,
    /// The canonical URI of the MCP server (RFC 8707).
    resource: []const u8,
    auth: ClientAuth = .none,
};

/// Builds an authorization code exchange request.
pub fn buildCodeExchange(
    arena: std.mem.Allocator,
    exchange: CodeExchange,
) BuildError!Request {
    assert(exchange.code.len > 0);
    assert(exchange.code_verifier.len > 0);
    prm.validateResourceIdentifier(exchange.resource) catch return error.InvalidResource;

    var form: Form = .init(arena);
    try form.add("grant_type", "authorization_code");
    try form.add("code", exchange.code);
    try form.add("redirect_uri", exchange.redirect_uri);
    try form.add("client_id", exchange.client_id);
    try form.add("code_verifier", exchange.code_verifier);
    // Both requests, not just the authorization one.
    try form.add("resource", exchange.resource);
    return form.finish(exchange.auth, exchange.client_id);
}

pub const Refresh = struct {
    refresh_token: []const u8,
    client_id: []const u8,
    resource: []const u8,
    /// Narrower scopes than originally granted, if the client wants to downscope.
    /// Omitted means "the same as before"; a refresh **cannot** be used to widen
    /// scope, so a step-up needs a new authorization flow rather than this.
    scopes: ?[]const u8 = null,
    auth: ClientAuth = .none,
};

/// Builds a refresh request.
pub fn buildRefresh(arena: std.mem.Allocator, refresh: Refresh) BuildError!Request {
    assert(refresh.refresh_token.len > 0);
    prm.validateResourceIdentifier(refresh.resource) catch return error.InvalidResource;

    var form: Form = .init(arena);
    try form.add("grant_type", "refresh_token");
    try form.add("refresh_token", refresh.refresh_token);
    try form.add("client_id", refresh.client_id);
    try form.add("resource", refresh.resource);
    if (refresh.scopes) |scopes| {
        if (scopes.len > 0) try form.add("scope", scopes);
    }
    return form.finish(refresh.auth, refresh.client_id);
}

/// Accumulates an `application/x-www-form-urlencoded` body.
const Form = struct {
    allocating: std.Io.Writer.Allocating,
    arena: std.mem.Allocator,
    count: usize = 0,

    fn init(arena: std.mem.Allocator) Form {
        return .{ .allocating = .init(arena), .arena = arena };
    }

    fn add(form: *Form, name: []const u8, value: []const u8) error{OutOfMemory}!void {
        const writer = &form.allocating.writer;
        if (form.count > 0) writer.writeByte('&') catch return error.OutOfMemory;
        form.count += 1;
        url.encodeComponent(writer, name) catch return error.OutOfMemory;
        writer.writeByte('=') catch return error.OutOfMemory;
        url.encodeComponent(writer, value) catch return error.OutOfMemory;
    }

    fn finish(
        form: *Form,
        auth: ClientAuth,
        client_id: []const u8,
    ) error{OutOfMemory}!Request {
        switch (auth) {
            .none => {},
            .secret_post => |secret| try form.add("client_secret", secret),
            .secret_basic => {},
        }

        const body = form.allocating.toOwnedSlice() catch return error.OutOfMemory;
        const headers: []const [2][]const u8 = switch (auth) {
            .none, .secret_post => &.{},
            .secret_basic => |secret| blk: {
                const header = try basicAuthorization(form.arena, client_id, secret);
                const list = form.arena.alloc([2][]const u8, 1) catch return error.OutOfMemory;
                list[0] = .{ "Authorization", header };
                break :blk list;
            },
        };
        return .{ .body = body, .headers = headers };
    }
};

/// Builds an `Authorization: Basic` value per RFC 6749 Section 2.3.1.
///
/// The client id and secret are form-urlencoded *before* base64, which is the step
/// implementations skip and then fail against any secret containing a `+` or `:`.
fn basicAuthorization(
    arena: std.mem.Allocator,
    client_id: []const u8,
    secret: []const u8,
) error{OutOfMemory}![]u8 {
    var credentials: std.Io.Writer.Allocating = .init(arena);
    defer credentials.deinit();
    url.encodeComponent(&credentials.writer, client_id) catch return error.OutOfMemory;
    credentials.writer.writeByte(':') catch return error.OutOfMemory;
    url.encodeComponent(&credentials.writer, secret) catch return error.OutOfMemory;

    const raw = credentials.written();
    const encoder = std.base64.standard.Encoder;
    const encoded = arena.alloc(u8, encoder.calcSize(raw.len)) catch return error.OutOfMemory;
    _ = encoder.encode(encoded, raw);

    return std.fmt.allocPrint(arena, "Basic {s}", .{encoded}) catch error.OutOfMemory;
}

pub const ParseError = error{
    /// The body exceeded `response_bytes_max`.
    ResponseTooLarge,
    /// Not a JSON object, or a field had the wrong type.
    Malformed,
    /// `access_token` was absent or empty.
    MissingAccessToken,
    /// `token_type` was absent, or was not `Bearer`. A token of another type must not
    /// be presented in an `Authorization: Bearer` header — it would either be
    /// rejected or, worse, accepted by a server that does not check.
    UnsupportedTokenType,
    /// The endpoint returned an OAuth error response.
    TokenRequestFailed,
    OutOfMemory,
};

/// An RFC 6749 Section 5.2 error response.
pub const Failure = struct {
    /// One of `invalid_request`, `invalid_client`, `invalid_grant`,
    /// `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, or an
    /// extension value.
    code: []const u8,
    description: ?[]const u8 = null,
    uri: ?[]const u8 = null,

    /// True when re-running the authorization flow is the appropriate response.
    ///
    /// `invalid_grant` means the code or refresh token was already used, expired, or
    /// revoked — a state no amount of retrying the same request escapes.
    pub fn needsReauthorization(failure: *const Failure) bool {
        return std.mem.eql(u8, failure.code, "invalid_grant");
    }

    /// True when the client asked for scopes it may not have.
    pub fn isScopeProblem(failure: *const Failure) bool {
        return std.mem.eql(u8, failure.code, "invalid_scope");
    }
};

/// The token endpoint response, as it appears on the wire.
const Wire = struct {
    access_token: ?[]const u8 = null,
    token_type: ?[]const u8 = null,
    expires_in: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    /// The scopes actually granted. Present when they differ from what was
    /// requested, and authoritative when present.
    scope: ?[]const u8 = null,
    id_token: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
    error_description: ?[]const u8 = null,
    error_uri: ?[]const u8 = null,
};

/// Tokens held for one resource at one issuer.
///
/// `issuer` and `resource` travel with the tokens because credentials are bound to
/// the authorization server that issued them: a token obtained from one issuer must
/// never be presented after protected resource metadata starts naming a different
/// one.
pub const TokenSet = struct {
    access_token: []const u8,
    /// Absent when the authorization server chose not to issue one, which it is
    /// entitled to do.
    refresh_token: ?[]const u8 = null,
    /// Unix seconds, or null when the response carried no `expires_in`.
    expires_at: ?i64 = null,
    /// What was granted. May be narrower than what was requested.
    scopes: []const u8 = "",
    issuer: []const u8,
    resource: []const u8,
    id_token: ?[]const u8 = null,

    /// True when the access token should be refreshed before use.
    ///
    /// A set with no expiry is never considered expired: the server did not say, and
    /// guessing would either refresh needlessly or refuse a valid token.
    pub fn isExpired(
        tokens: *const TokenSet,
        now: i64,
        leeway_seconds: i64,
    ) bool {
        const expires_at = tokens.expires_at orelse return false;
        // Saturating so that a set whose `expires_at` saturated on the way in stays
        // readable here rather than trapping on the comparison's other side.
        return now +| leeway_seconds >= expires_at;
    }

    pub fn hasScope(tokens: *const TokenSet, token: []const u8) bool {
        return scope.contains(tokens.scopes, token);
    }

    pub fn hasAllScopes(tokens: *const TokenSet, required: []const u8) bool {
        return scope.containsAll(tokens.scopes, required);
    }

    /// True when this set may be used against `issuer`.
    ///
    /// Checked before presenting a token, not just when storing one: protected
    /// resource metadata can change between requests, and continuing to send an old
    /// issuer's token to a server that has moved is how a token reaches a party it
    /// was not issued for.
    pub fn boundTo(tokens: *const TokenSet, issuer: []const u8, resource: []const u8) bool {
        return std.mem.eql(u8, tokens.issuer, issuer) and
            std.mem.eql(u8, tokens.resource, resource);
    }

    /// The `Authorization` header value.
    pub fn authorizationHeader(
        tokens: *const TokenSet,
        arena: std.mem.Allocator,
    ) error{OutOfMemory}![]u8 {
        return std.fmt.allocPrint(arena, "Bearer {s}", .{tokens.access_token}) catch
            error.OutOfMemory;
    }
};

/// What the caller knows that the response body does not say.
pub const ParseContext = struct {
    /// The issuer the tokens are being bound to.
    issuer: []const u8,
    /// The resource they were requested for.
    resource: []const u8,
    /// Supplies the granted scopes when the response omits `scope`, which RFC 6749
    /// permits when they are identical to what was asked for.
    requested_scopes: []const u8 = "",
    /// Turns the relative `expires_in` into an absolute instant. A duration is only
    /// meaningful at the moment it was received.
    now: i64,
};

/// Parses a token endpoint response.
pub fn parseResponse(
    arena: std.mem.Allocator,
    body: []const u8,
    context: ParseContext,
    failure: *?Failure,
) ParseError!TokenSet {
    if (body.len > response_bytes_max) return error.ResponseTooLarge;

    const wire = std.json.parseFromSliceLeaky(Wire, arena, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };

    // The error response is checked first: a body carrying `error` is not a token
    // response, and looking for `access_token` in it would report the wrong problem.
    if (wire.@"error") |code| {
        failure.* = .{
            .code = code,
            .description = wire.error_description,
            .uri = wire.error_uri,
        };
        return error.TokenRequestFailed;
    }

    const access_token = wire.access_token orelse return error.MissingAccessToken;
    if (access_token.len == 0) return error.MissingAccessToken;

    const token_type = wire.token_type orelse return error.UnsupportedTokenType;
    if (!std.ascii.eqlIgnoreCase(token_type, token_type_bearer)) {
        return error.UnsupportedTokenType;
    }

    const granted = wire.scope orelse context.requested_scopes;

    return .{
        .access_token = access_token,
        .refresh_token = wire.refresh_token,
        // Saturating, because `expires_in` is a number chosen by the peer and this is
        // the only place it is arithmetic: `now + maxInt(i64)` traps, which turns a
        // token response into a crashed process. Saturating reads an absurd lifetime
        // as "effectively never", which costs at most a 401 the client already knows
        // how to recover from — the same trade this file makes for a string
        // `expires_in`. Rejecting the response instead would discard a working token
        // over a field that only decides when to refresh.
        .expires_at = if (wire.expires_in) |seconds| context.now +| seconds else null,
        .scopes = granted,
        .issuer = context.issuer,
        .resource = context.resource,
        .id_token = wire.id_token,
    };
}

const test_issuer = "https://auth.example.com";
const test_resource = "https://mcp.example.com/mcp";
const test_now: i64 = 1_700_000_000;

test "buildCodeExchange emits every required parameter including resource" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try buildCodeExchange(arena.allocator(), .{
        .code = "authcode",
        .redirect_uri = "http://127.0.0.1:3000/callback",
        .client_id = "https://app.example.com/client.json",
        .code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        .resource = test_resource,
    });

    try std.testing.expect(std.mem.indexOf(u8, request.body, "grant_type=authorization_code") != null);
    try std.testing.expect(std.mem.indexOf(u8, request.body, "code=authcode") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, request.body, "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != null,
    );
    // The parameter that binds the token to this server, in the request that mints it.
    try std.testing.expect(
        std.mem.indexOf(u8, request.body, "resource=https%3A%2F%2Fmcp.example.com%2Fmcp") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, request.body, "redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback") != null,
    );
    // A public client sends no credential and needs no extra header.
    try std.testing.expectEqual(@as(usize, 0), request.headers.len);
    try std.testing.expect(std.mem.indexOf(u8, request.body, "client_secret") == null);
}

test "buildRefresh asks for the same resource and does not widen scope" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try buildRefresh(arena.allocator(), .{
        .refresh_token = "rt-1",
        .client_id = "c",
        .resource = test_resource,
    });
    try std.testing.expect(std.mem.indexOf(u8, request.body, "grant_type=refresh_token") != null);
    try std.testing.expect(std.mem.indexOf(u8, request.body, "refresh_token=rt-1") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, request.body, "resource=https%3A%2F%2Fmcp.example.com%2Fmcp") != null,
    );
    // No scope requested means "as before".
    try std.testing.expect(std.mem.indexOf(u8, request.body, "scope=") == null);
}

test "buildRefresh can downscope" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try buildRefresh(arena.allocator(), .{
        .refresh_token = "rt-1",
        .client_id = "c",
        .resource = test_resource,
        .scopes = "files:read",
    });
    try std.testing.expect(std.mem.indexOf(u8, request.body, "scope=files%3Aread") != null);
}

test "client_secret_post puts the secret in the body" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try buildCodeExchange(arena.allocator(), .{
        .code = "c",
        .redirect_uri = "https://app.example.com/cb",
        .client_id = "client-1",
        .code_verifier = "v" ** 43,
        .resource = test_resource,
        .auth = .{ .secret_post = "s3cr3t" },
    });
    try std.testing.expect(std.mem.indexOf(u8, request.body, "client_secret=s3cr3t") != null);
    try std.testing.expectEqual(@as(usize, 0), request.headers.len);
}

test "client_secret_basic encodes credentials before base64" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try buildCodeExchange(arena.allocator(), .{
        .code = "c",
        .redirect_uri = "https://app.example.com/cb",
        .client_id = "client-1",
        .code_verifier = "v" ** 43,
        .resource = test_resource,
        .auth = .{ .secret_basic = "s3cr3t" },
    });
    // The secret must not appear in the body when it travels in the header.
    try std.testing.expect(std.mem.indexOf(u8, request.body, "client_secret") == null);
    try std.testing.expectEqual(@as(usize, 1), request.headers.len);
    try std.testing.expectEqualStrings("Authorization", request.headers[0][0]);
    try std.testing.expectEqualStrings("Basic Y2xpZW50LTE6czNjcjN0", request.headers[0][1]);
}

test "client_secret_basic form-encodes a secret with reserved characters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // A `:` in the secret would make the credentials ambiguous if not encoded first,
    // which is the step that gets skipped.
    const header = try basicAuthorization(arena.allocator(), "id:with:colons", "a+b:c");
    const encoded = header["Basic ".len..];
    const decoder = std.base64.standard.Decoder;
    const length = try decoder.calcSizeForSlice(encoded);
    const decoded = try arena.allocator().alloc(u8, length);
    try decoder.decode(decoded, encoded);
    try std.testing.expectEqualStrings("id%3Awith%3Acolons:a%2Bb%3Ac", decoded);
}

test "build refuses a resource that is not canonical" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.InvalidResource, buildCodeExchange(arena.allocator(), .{
        .code = "c",
        .redirect_uri = "https://app.example.com/cb",
        .client_id = "c",
        .code_verifier = "v" ** 43,
        .resource = "https://mcp.example.com/mcp#frag",
    }));
    try std.testing.expectError(error.InvalidResource, buildRefresh(arena.allocator(), .{
        .refresh_token = "rt",
        .client_id = "c",
        .resource = "mcp.example.com",
    }));
}

test "parseResponse reads a token response" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failure: ?Failure = null;
    const tokens = try parseResponse(
        arena.allocator(),
        \\{"access_token":"at-1","token_type":"Bearer","expires_in":3600,
        \\ "refresh_token":"rt-1","scope":"files:read"}
    ,
        .{
            .issuer = test_issuer,
            .resource = test_resource,
            .requested_scopes = "files:read files:write",
            .now = test_now,
        },
        &failure,
    );

    try std.testing.expectEqualStrings("at-1", tokens.access_token);
    try std.testing.expectEqualStrings("rt-1", tokens.refresh_token.?);
    try std.testing.expectEqual(test_now + 3600, tokens.expires_at.?);
    // The response's `scope` is authoritative: the server granted less than was asked
    // for, and pretending otherwise would produce 403s the client cannot explain.
    try std.testing.expectEqualStrings("files:read", tokens.scopes);
    try std.testing.expect(!tokens.hasScope("files:write"));
}

test "parseResponse falls back to the requested scopes when the response omits them" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failure: ?Failure = null;
    const tokens = try parseResponse(
        arena.allocator(),
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}",
        .{
            .issuer = test_issuer,
            .resource = test_resource,
            .requested_scopes = "files:read",
            .now = test_now,
        },
        &failure,
    );
    // RFC 6749 permits omitting `scope` when it is identical to the request.
    try std.testing.expectEqualStrings("files:read", tokens.scopes);
    try std.testing.expectEqual(@as(?i64, null), tokens.expires_at);
    try std.testing.expectEqual(@as(?[]const u8, null), tokens.refresh_token);
}

test "parseResponse accepts any capitalization of Bearer and rejects other types" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var failure: ?Failure = null;
    const context: ParseContext = .{ .issuer = test_issuer, .resource = test_resource, .now = test_now };

    _ = try parseResponse(
        allocator,
        "{\"access_token\":\"at\",\"token_type\":\"bearer\"}",
        context,
        &failure,
    );

    // A DPoP or MAC token presented as a Bearer would be either rejected or, on a
    // server that does not check, accepted without its binding.
    try std.testing.expectError(error.UnsupportedTokenType, parseResponse(
        allocator,
        "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}",
        context,
        &failure,
    ));
    try std.testing.expectError(error.UnsupportedTokenType, parseResponse(
        allocator,
        "{\"access_token\":\"at\"}",
        context,
        &failure,
    ));
}

test "parseResponse requires a non-empty access token" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var failure: ?Failure = null;
    const context: ParseContext = .{ .issuer = test_issuer, .resource = test_resource, .now = test_now };

    try std.testing.expectError(error.MissingAccessToken, parseResponse(
        arena.allocator(),
        "{\"token_type\":\"Bearer\"}",
        context,
        &failure,
    ));
    try std.testing.expectError(error.MissingAccessToken, parseResponse(
        arena.allocator(),
        "{\"access_token\":\"\",\"token_type\":\"Bearer\"}",
        context,
        &failure,
    ));
}

test "parseResponse reports an OAuth error response" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failure: ?Failure = null;
    try std.testing.expectError(error.TokenRequestFailed, parseResponse(
        arena.allocator(),
        \\{"error":"invalid_grant","error_description":"code already used",
        \\ "error_uri":"https://auth.example.com/errors/invalid_grant"}
    ,
        .{ .issuer = test_issuer, .resource = test_resource, .now = test_now },
        &failure,
    ));
    try std.testing.expectEqualStrings("invalid_grant", failure.?.code);
    try std.testing.expectEqualStrings("code already used", failure.?.description.?);
    // `invalid_grant` is not retryable: the code is spent.
    try std.testing.expect(failure.?.needsReauthorization());
    try std.testing.expect(!failure.?.isScopeProblem());
}

test "parseResponse classifies a scope error" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failure: ?Failure = null;
    try std.testing.expectError(error.TokenRequestFailed, parseResponse(
        arena.allocator(),
        "{\"error\":\"invalid_scope\"}",
        .{ .issuer = test_issuer, .resource = test_resource, .now = test_now },
        &failure,
    ));
    try std.testing.expect(failure.?.isScopeProblem());
    try std.testing.expect(!failure.?.needsReauthorization());
}

test "parseResponse prefers the error over a stray access_token" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failure: ?Failure = null;
    // A body carrying both is malformed; treating it as a success would adopt a token
    // the server was in the middle of refusing to issue.
    try std.testing.expectError(error.TokenRequestFailed, parseResponse(
        arena.allocator(),
        "{\"error\":\"invalid_client\",\"access_token\":\"at\",\"token_type\":\"Bearer\"}",
        .{ .issuer = test_issuer, .resource = test_resource, .now = test_now },
        &failure,
    ));
    try std.testing.expectEqualStrings("invalid_client", failure.?.code);
}

test "parseResponse rejects malformed and oversized bodies" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var failure: ?Failure = null;
    const context: ParseContext = .{ .issuer = test_issuer, .resource = test_resource, .now = test_now };

    try std.testing.expectError(
        error.Malformed,
        parseResponse(allocator, "[]", context, &failure),
    );
    try std.testing.expectError(
        error.Malformed,
        parseResponse(allocator, "{\"access_token\":123,\"token_type\":\"Bearer\"}", context, &failure),
    );
    try std.testing.expectError(
        error.Malformed,
        parseResponse(allocator, "not json", context, &failure),
    );

    const big = try allocator.alloc(u8, response_bytes_max + 1);
    @memset(big, ' ');
    try std.testing.expectError(
        error.ResponseTooLarge,
        parseResponse(allocator, big, context, &failure),
    );
}

test "a stringly-typed expires_in is accepted rather than discarding the token" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failure: ?Failure = null;
    const tokens = try parseResponse(
        arena.allocator(),
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":\"3600\"}",
        .{ .issuer = test_issuer, .resource = test_resource, .now = test_now },
        &failure,
    );
    try std.testing.expectEqual(test_now + 3600, tokens.expires_at.?);

    // This is deliberately more permissive than `jwt.decodeClaims`, which rejects a
    // string `exp`. The two differ because the consequences differ: misreading a JWT
    // expiry means honoring a token that should be dead, while misreading `expires_in`
    // only means refreshing at the wrong moment. Some authorization servers really do
    // emit it as a string, and rejecting the whole response over it would throw away
    // a perfectly good access token.
}

test "an expires_in that would overflow the clock does not crash the process" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var failure: ?Failure = null;
    const context: ParseContext = .{ .issuer = test_issuer, .resource = test_resource, .now = test_now };

    // A token endpoint reachable before any of its answers are trusted, so this is a
    // remote crash with no prerequisite beyond being pointed at a hostile server.
    const huge = try parseResponse(
        allocator,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":9223372036854775807}",
        context,
        &failure,
    );
    try std.testing.expectEqual(std.math.maxInt(i64), huge.expires_at.?);
    // Saturated means "effectively never", and asking that question must not trap either.
    try std.testing.expect(!huge.isExpired(test_now, expiry_leeway_seconds_default));
    // At a clock that has reached the saturated instant, the leeway saturates too and
    // the answer is "expired" — which is the honest one, and reached without trapping.
    try std.testing.expect(huge.isExpired(std.math.maxInt(i64) - 1, expiry_leeway_seconds_default));

    // The other end of the range: a negative lifetime is honest about being spent
    // rather than wrapping into the far future.
    const negative = try parseResponse(
        allocator,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":-9223372036854775808}",
        context,
        &failure,
    );
    try std.testing.expectEqual(test_now +| std.math.minInt(i64), negative.expires_at.?);
    try std.testing.expect(negative.isExpired(test_now, 0));
}

test "TokenSet expiry accounts for leeway and for an absent expiry" {
    const with_expiry: TokenSet = .{
        .access_token = "at",
        .expires_at = test_now + 60,
        .issuer = test_issuer,
        .resource = test_resource,
    };
    try std.testing.expect(!with_expiry.isExpired(test_now, expiry_leeway_seconds_default));
    // Within the leeway window it is treated as expired, so the refresh happens before
    // a request fails rather than after.
    try std.testing.expect(with_expiry.isExpired(test_now + 31, expiry_leeway_seconds_default));
    try std.testing.expect(with_expiry.isExpired(test_now + 3600, 0));

    const no_expiry: TokenSet = .{
        .access_token = "at",
        .issuer = test_issuer,
        .resource = test_resource,
    };
    // The server did not say, so guessing would either refresh needlessly or refuse a
    // token that is still good.
    try std.testing.expect(!no_expiry.isExpired(test_now + 1_000_000, 0));
}

test "TokenSet is bound to its issuer and resource" {
    const tokens: TokenSet = .{
        .access_token = "at",
        .issuer = test_issuer,
        .resource = test_resource,
    };
    try std.testing.expect(tokens.boundTo(test_issuer, test_resource));

    // An authorization server change must invalidate the binding, not be ignored.
    try std.testing.expect(!tokens.boundTo("https://other-auth.example", test_resource));
    try std.testing.expect(!tokens.boundTo(test_issuer, "https://other-mcp.example/mcp"));
}

test "TokenSet renders an Authorization header" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const tokens: TokenSet = .{
        .access_token = "at-1",
        .issuer = test_issuer,
        .resource = test_resource,
    };
    try std.testing.expectEqualStrings(
        "Bearer at-1",
        try tokens.authorizationHeader(arena.allocator()),
    );
}

test "ClientAuth reports the metadata method name" {
    try std.testing.expectEqualStrings("none", (ClientAuth{ .none = {} }).method());
    try std.testing.expectEqualStrings("client_secret_post", (ClientAuth{ .secret_post = "s" }).method());
    try std.testing.expectEqualStrings("client_secret_basic", (ClientAuth{ .secret_basic = "s" }).method());
}

test "fuzz parseResponse" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            var failure: ?Failure = null;
            const tokens = parseResponse(
                arena.allocator(),
                buffer[0..length],
                .{ .issuer = test_issuer, .resource = test_resource, .now = test_now },
                &failure,
            ) catch return;
            // Anything accepted carries a usable token bound to this resource.
            try std.testing.expect(tokens.access_token.len > 0);
            try std.testing.expectEqualStrings(test_resource, tokens.resource);
        }
    }.run, .{});
}
