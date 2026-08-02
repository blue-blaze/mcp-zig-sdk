//! The resource server half: turn an `Authorization` header into a decision.
//!
//! An MCP server acts as an OAuth 2.1 resource server, and its obligations are
//! narrow enough to state completely:
//!
//!   * validate the token, including that it was issued *for this server*
//!   * answer 401 with a `WWW-Authenticate` challenge naming the metadata document
//!   * answer 403 when the token is valid but lacks the scopes the operation needs
//!   * publish protected resource metadata
//!
//! `ResourceServer.authorize` produces all of those as one `Outcome`, so a transport
//! has a single call to make and no room to answer 401 where it meant 403.
//!
//! ## Why the verifier is an interface
//!
//! How a token is validated is deployment policy. A JWT with a JWKS, an RFC 7662
//! introspection call, an opaque token in a shared database, and a test double are
//! all legitimate, and none of them belongs in this module. `Verifier` is the seam;
//! `JwtVerifier` is the implementation most deployments want.
//!
//! ## What this module refuses to do
//!
//! It never returns token contents in a challenge, and it does not distinguish
//! "expired" from "wrong signature" to the caller: `invalid_token` is the whole
//! answer an unauthenticated peer gets. Anything finer is a probing oracle.

const std = @import("std");
const assert_mod = @import("assert");

const bearer = @import("bearer.zig");
const jwk = @import("jwk.zig");
const jwt = @import("jwt.zig");
const prm = @import("prm.zig");
const scope = @import("scope.zig");

const assert = assert_mod.assert;

pub const Error = error{
    /// The token is absent, malformed, expired, for another audience, or otherwise
    /// not acceptable. Deliberately coarse: the difference is useful in a server log
    /// and is an oracle in a response.
    InvalidToken,
    /// The presented credentials were not a well-formed Bearer token.
    InvalidRequest,
    /// Validation could not be performed — the key set could not be fetched, an
    /// introspection endpoint was down. This is a 503, not a 401: telling a client
    /// its token is bad when the truth is that the server cannot check is how a
    /// working client gets driven into a reauthorization loop.
    Unavailable,
    OutOfMemory,
};

/// What a validated token establishes.
///
/// Scope checking is not done here. A verifier authenticates; whether the scopes
/// suffice depends on the operation, which the verifier does not know.
pub const Grant = struct {
    /// The `iss` the token was validated against.
    issuer: []const u8,
    /// The resource identifier found in the audience.
    audience: []const u8,
    /// End-user identifier, absent for a client-credentials token.
    subject: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    /// Granted scopes, space-delimited.
    scopes: []const u8 = "",
    expires_at: ?i64 = null,

    pub fn hasScope(grant: *const Grant, token: []const u8) bool {
        return scope.contains(grant.scopes, token);
    }

    pub fn hasAllScopes(grant: *const Grant, required: []const u8) bool {
        return scope.containsAll(grant.scopes, required);
    }
};

/// How a token is validated.
pub const Verifier = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Validates `token` and reports what it grants.
        ///
        /// `arena` lives for the request. `now` is passed rather than read from a
        /// clock so that expiry is testable and so that one request cannot see two
        /// different times.
        verify: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            token: []const u8,
            now: i64,
        ) Error!Grant,
    };

    pub fn verify(
        verifier: Verifier,
        arena: std.mem.Allocator,
        token: []const u8,
        now: i64,
    ) Error!Grant {
        return verifier.vtable.verify(verifier.ptr, arena, token, now);
    }
};

/// A challenge to return, already rendered.
pub const Challenge = struct {
    status: u16,
    /// The `WWW-Authenticate` header value.
    header: []const u8,
};

/// The decision for one request.
pub const Outcome = union(enum) {
    granted: Grant,
    challenge: Challenge,
    /// Validation could not be performed. The transport should answer 503; no
    /// challenge is offered, because there is nothing for the client to fix.
    unavailable,
};

pub const Options = struct {
    /// This server's canonical resource URI. Also the audience a token must carry.
    resource: []const u8,
    /// URL of this server's protected resource metadata document, advertised in
    /// every challenge. Without it a 401 tells the client nothing it can act on.
    metadata_url: []const u8,
    /// Scopes advertised as the minimum for basic functionality. Used as the `scope`
    /// hint on an unauthenticated 401 when the operation names none.
    scopes_supported: ?[]const u8 = null,
    realm: ?[]const u8 = null,
    /// Include `error_description` in challenges. On by default because the
    /// descriptions this module emits name only the class of failure, never token
    /// contents; turn it off to say strictly nothing.
    describe_errors: bool = true,
};

/// Applies a `Verifier` and the challenge rules to incoming requests.
pub const ResourceServer = struct {
    verifier: Verifier,
    options: Options,

    pub fn init(verifier: Verifier, options: Options) ResourceServer {
        assert(options.resource.len > 0);
        assert(options.metadata_url.len > 0);
        return .{ .verifier = verifier, .options = options };
    }

    /// Decides one request.
    ///
    /// `authorization` is the raw header value, or null when absent.
    /// `required_scopes` is what *this* operation needs; null means authentication
    /// alone is enough.
    ///
    /// The order is fixed: credentials must be present and well-formed, then valid,
    /// and only then are scopes considered. Checking scopes against an unvalidated
    /// token would be reading attacker-supplied claims.
    pub fn authorize(
        server: *const ResourceServer,
        arena: std.mem.Allocator,
        authorization: ?[]const u8,
        required_scopes: ?[]const u8,
        now: i64,
    ) error{OutOfMemory}!Outcome {
        const token = bearer.extract(authorization) catch |err| switch (err) {
            // No credentials at all: the bare challenge, carrying the scope hint so
            // the client's first authorization request asks for the right thing.
            error.Missing => return server.challengeFor(arena, .{
                .code = null,
                .scope = required_scopes orelse server.options.scopes_supported,
                .description = null,
            }),
            // A different scheme, or a token this server will not read.
            error.UnsupportedScheme, error.Malformed, error.TokenTooLong => {
                return server.challengeFor(arena, .{
                    .code = .invalid_request,
                    .scope = required_scopes orelse server.options.scopes_supported,
                    .description = "malformed Authorization header",
                });
            },
        };

        const grant = server.verifier.verify(arena, token, now) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unavailable => return .unavailable,
            error.InvalidRequest => return server.challengeFor(arena, .{
                .code = .invalid_request,
                .scope = required_scopes orelse server.options.scopes_supported,
                .description = "malformed credentials",
            }),
            error.InvalidToken => return server.challengeFor(arena, .{
                .code = .invalid_token,
                .scope = required_scopes orelse server.options.scopes_supported,
                .description = "the access token is not valid for this resource",
            }),
        };

        if (required_scopes) |required| {
            if (!grant.hasAllScopes(required)) {
                // 403 with the scopes needed for this operation, all of them at once.
                // Challenging for one missing scope at a time costs the user a
                // round trip per scope.
                return server.challengeFor(arena, .{
                    .code = .insufficient_scope,
                    .scope = required,
                    .description = "additional scopes are required for this operation",
                });
            }
        }

        return .{ .granted = grant };
    }

    /// Re-checks an already-validated grant against a stricter requirement.
    ///
    /// Returns null when the grant suffices, or the `403` to send.
    ///
    /// This exists because what an operation requires is not always knowable when the
    /// credentials are checked: a transport that authenticates before parsing a body
    /// cannot yet know which tool the body names. Authentication happens once, in
    /// `authorize`; this is a pure function of an existing grant and can only ever
    /// produce `insufficient_scope`, so the 401-versus-403 decision still has a single
    /// home.
    ///
    /// `required` must be everything the operation needs, not the difference: the spec
    /// requires a challenge to name the full set, because a client that is told about
    /// one missing scope at a time costs its user an interaction per scope.
    pub fn checkScopes(
        server: *const ResourceServer,
        arena: std.mem.Allocator,
        grant: *const Grant,
        required: []const u8,
    ) error{OutOfMemory}!?Challenge {
        if (grant.hasAllScopes(required)) return null;
        const outcome = try server.challengeFor(arena, .{
            .code = .insufficient_scope,
            .scope = required,
            .description = "additional scopes are required for this operation",
        });
        return outcome.challenge;
    }

    const ChallengeSpec = struct {
        code: ?bearer.ErrorCode,
        scope: ?[]const u8,
        description: ?[]const u8,
    };

    fn challengeFor(
        server: *const ResourceServer,
        arena: std.mem.Allocator,
        spec: ChallengeSpec,
    ) error{OutOfMemory}!Outcome {
        const challenge: bearer.Challenge = .{
            .code = spec.code,
            .description = if (server.options.describe_errors) spec.description else null,
            .scope = spec.scope,
            .resource_metadata = server.options.metadata_url,
            .realm = server.options.realm,
        };
        const header = challenge.render(arena) catch return error.OutOfMemory;
        return .{ .challenge = .{ .status = challenge.status(), .header = header } };
    }

    /// The protected resource metadata document to publish, given the authorization
    /// servers this deployment trusts.
    ///
    /// Built here rather than by the caller so that `resource` cannot disagree with
    /// the audience this server validates — a mismatch a client experiences as
    /// tokens that are always rejected.
    pub fn metadata(
        server: *const ResourceServer,
        authorization_servers: []const []const u8,
        scopes_supported: ?[]const []const u8,
    ) prm.ResourceMetadata {
        return .{
            .resource = server.options.resource,
            .authorization_servers = authorization_servers,
            .scopes_supported = scopes_supported,
            // MCP allows only the Authorization header.
            .bearer_methods_supported = &.{"header"},
        };
    }
};

/// Where a `JwtVerifier` gets its keys.
///
/// An interface rather than a stored key set because a JWKS rotates: an
/// authorization server publishes a new key before it starts signing with it, and a
/// verifier holding a snapshot from startup rejects every token afterwards. A
/// provider can cache, refresh on a `kid` miss, or return a fixed set in tests.
pub const KeyProvider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        keys: *const fn (ptr: *anyopaque, arena: std.mem.Allocator) Error!jwk.KeySet,
        /// Discard any cached keys, so the next `keys` call refetches.
        ///
        /// Called when a token names a `kid` the current set does not contain, which
        /// is exactly what the first token signed with a newly rotated key looks
        /// like. Without this hook, rotation means every token is rejected until a
        /// cache expires on its own — an outage whose cause is invisible from either
        /// end. Optional, because a fixed key set has nothing to discard.
        invalidate: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn keys(provider: KeyProvider, arena: std.mem.Allocator) Error!jwk.KeySet {
        return provider.vtable.keys(provider.ptr, arena);
    }

    /// Returns true if there was a cache to discard, so a caller knows whether
    /// retrying could possibly produce a different answer.
    pub fn invalidate(provider: KeyProvider) bool {
        const hook = provider.vtable.invalidate orelse return false;
        hook(provider.ptr);
        return true;
    }
};

/// A fixed key set, for tests and for deployments that pin keys by configuration.
pub const StaticKeys = struct {
    set: jwk.KeySet,

    pub fn provider(static: *StaticKeys) KeyProvider {
        return .{ .ptr = static, .vtable = &vtable };
    }

    const vtable: KeyProvider.VTable = .{ .keys = keys };

    fn keys(ptr: *anyopaque, arena: std.mem.Allocator) Error!jwk.KeySet {
        _ = arena;
        const static: *StaticKeys = @ptrCast(@alignCast(ptr));
        return static.set;
    }
};

/// Validates JWT access tokens against a key set.
pub const JwtVerifier = struct {
    provider: KeyProvider,
    config: Config,

    pub const Config = struct {
        /// Expected `iss`, compared byte-exactly.
        issuer: []const u8,
        /// Required audience: this server's canonical resource URI. This is the
        /// RFC 8707 check, and the reason a stolen token for another service is
        /// useless here.
        audience: []const u8,
        leeway_seconds: i64 = jwt.leeway_seconds_default,
        require_expiry: bool = true,
        require_typ: ?[]const u8 = null,
        /// Where to report why a token was rejected. Nothing else does: the client
        /// is told only `invalid_token`, so without this the reason is lost.
        diagnostics: ?*std.Io.Writer = null,
    };

    pub fn init(provider: KeyProvider, config: Config) JwtVerifier {
        assert(config.issuer.len > 0);
        assert(config.audience.len > 0);
        return .{ .provider = provider, .config = config };
    }

    pub fn verifier(self: *JwtVerifier) Verifier {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Verifier.VTable = .{ .verify = verifyToken };

    fn verifyToken(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        token: []const u8,
        now: i64,
    ) Error!Grant {
        const self: *JwtVerifier = @ptrCast(@alignCast(ptr));

        const verified = attempt: {
            break :attempt self.attempt(arena, token, now) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Unavailable => return error.Unavailable,
                // A `kid` the current set does not carry is the signature of key
                // rotation, not of a bad token. Refetch once and try again; if the
                // provider had nothing to discard, there is no second answer to get.
                error.KeyNotFound => {
                    if (!self.provider.invalidate()) {
                        self.report("KeyNotFound");
                        return error.InvalidToken;
                    }
                    break :attempt self.attempt(arena, token, now) catch |retry| switch (retry) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Unavailable => return error.Unavailable,
                        else => {
                            self.report(@errorName(retry));
                            return error.InvalidToken;
                        },
                    };
                },
                else => {
                    self.report(@errorName(err));
                    return error.InvalidToken;
                },
            };
        };

        return self.grantOf(arena, &verified);
    }

    const AttemptError = Error || jwt.Error;

    fn attempt(
        self: *JwtVerifier,
        arena: std.mem.Allocator,
        token: []const u8,
        now: i64,
    ) AttemptError!jwt.Verified {
        const keys = try self.provider.keys(arena);
        return jwt.verify(arena, token, &keys, .{
            .issuer = self.config.issuer,
            .audience = self.config.audience,
            .now = now,
            // Scope checking belongs to the resource server, which knows the
            // operation; doing it here would collapse 403 into 401.
            .required_scopes = null,
            .leeway_seconds = self.config.leeway_seconds,
            .require_expiry = self.config.require_expiry,
            .require_typ = self.config.require_typ,
        });
    }

    fn grantOf(
        self: *const JwtVerifier,
        arena: std.mem.Allocator,
        verified: *const jwt.Verified,
    ) Error!Grant {
        return .{
            .issuer = self.config.issuer,
            .audience = self.config.audience,
            .subject = verified.claims.sub,
            .client_id = verified.claims.client_id,
            .scopes = try grantedScopes(arena, &verified.claims),
            .expires_at = verified.claims.exp,
        };
    }

    /// Records why a token was rejected. Nothing else does: the client is told only
    /// `invalid_token`, so without this the reason is lost.
    fn report(self: *const JwtVerifier, reason: []const u8) void {
        const writer = self.config.diagnostics orelse return;
        // Best-effort: a diagnostic that fails to write must not change the
        // authorization outcome.
        writer.print("oauth: rejected token: {s}\n", .{reason}) catch return;
        writer.flush() catch {};
    }

    /// Collects granted scopes from whichever claim the issuer used.
    fn grantedScopes(arena: std.mem.Allocator, claims: *const jwt.Claims) Error![]const u8 {
        if (claims.scope) |value| return value;

        // `scp` as an array is not standard but is widely emitted; joining it here
        // means the rest of this module only has to know about one representation.
        if (claims.all == .object) {
            if (claims.all.object.get("scp")) |value| switch (value) {
                .string => |text| return text,
                .array => |items| {
                    var set: scope.Set = .{};
                    for (items.items) |item| {
                        if (item != .string) continue;
                        set.add(item.string) catch break;
                    }
                    return arena.dupe(u8, set.value()) catch error.OutOfMemory;
                },
                else => {},
            };
        }
        return "";
    }
};

// -- Tests --------------------------------------------------------------------

const test_resource = "https://mcp.example.com/mcp";
const test_metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
const test_issuer = "https://auth.example.com";
const test_now: i64 = 1_700_000_000;

/// A verifier whose answer is dictated by the test.
const ScriptedVerifier = struct {
    result: Error!Grant,
    seen: ?[]const u8 = null,

    fn verifier(self: *ScriptedVerifier) Verifier {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Verifier.VTable = .{ .verify = verify };

    fn verify(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        token: []const u8,
        now: i64,
    ) Error!Grant {
        _ = .{ arena, now };
        const self: *ScriptedVerifier = @ptrCast(@alignCast(ptr));
        self.seen = token;
        return self.result;
    }
};

fn testServer(verifier: Verifier) ResourceServer {
    return .init(verifier, .{
        .resource = test_resource,
        .metadata_url = test_metadata_url,
        .scopes_supported = "files:read",
    });
}

test "a missing Authorization header yields a bare 401 naming the metadata document" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = error.InvalidToken };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(arena.allocator(), null, null, test_now);
    const challenge = outcome.challenge;
    try std.testing.expectEqual(@as(u16, 401), challenge.status);
    // No `error` parameter: nothing was presented, so nothing was invalid.
    try std.testing.expect(std.mem.indexOf(u8, challenge.header, "error=") == null);
    try std.testing.expect(std.mem.indexOf(u8, challenge.header, test_metadata_url) != null);
    // The scope hint tells the client what to ask for on its first attempt.
    try std.testing.expect(std.mem.indexOf(u8, challenge.header, "scope=\"files:read\"") != null);
    // The verifier was never consulted.
    try std.testing.expectEqual(@as(?[]const u8, null), scripted.seen);
}

test "a wrong scheme is a 400, not a 401" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = error.InvalidToken };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(arena.allocator(), "Basic dXNlcjpwYXNz", null, test_now);
    try std.testing.expectEqual(@as(u16, 400), outcome.challenge.status);
    try std.testing.expect(std.mem.indexOf(u8, outcome.challenge.header, "invalid_request") != null);
}

test "an invalid token yields 401 invalid_token and reveals nothing else" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = error.InvalidToken };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(arena.allocator(), "Bearer abc.def.ghi", null, test_now);
    try std.testing.expectEqual(@as(u16, 401), outcome.challenge.status);
    try std.testing.expect(std.mem.indexOf(u8, outcome.challenge.header, "invalid_token") != null);
    // The token must not be echoed back.
    try std.testing.expect(std.mem.indexOf(u8, outcome.challenge.header, "abc.def.ghi") == null);
    try std.testing.expectEqualStrings("abc.def.ghi", scripted.seen.?);
}

test "a valid token is granted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = Grant{
        .issuer = test_issuer,
        .audience = test_resource,
        .subject = "user-1",
        .scopes = "files:read files:write",
    } };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(arena.allocator(), "Bearer good", "files:read", test_now);
    try std.testing.expectEqualStrings("user-1", outcome.granted.subject.?);
    try std.testing.expect(outcome.granted.hasScope("files:write"));
}

test "insufficient scope is 403 and names every scope the operation needs" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = Grant{
        .issuer = test_issuer,
        .audience = test_resource,
        .scopes = "files:read",
    } };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(
        arena.allocator(),
        "Bearer good",
        "files:read files:write mail:send",
        test_now,
    );
    const challenge = outcome.challenge;
    try std.testing.expectEqual(@as(u16, 403), challenge.status);
    try std.testing.expect(std.mem.indexOf(u8, challenge.header, "insufficient_scope") != null);
    // All of them, in one challenge: one per round trip would be one user prompt per
    // scope.
    try std.testing.expect(
        std.mem.indexOf(u8, challenge.header, "scope=\"files:read files:write mail:send\"") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, challenge.header, test_metadata_url) != null);
}

test "an unavailable verifier does not become an authorization failure" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = error.Unavailable };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(arena.allocator(), "Bearer good", null, test_now);
    // Not a challenge: the client's token may be perfectly good.
    try std.testing.expectEqual(Outcome.unavailable, outcome);
}

test "describe_errors off removes the description but keeps the actionable parts" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = error.InvalidToken };
    var server = testServer(scripted.verifier());
    server.options.describe_errors = false;

    const outcome = try server.authorize(arena.allocator(), "Bearer bad", null, test_now);
    const header = outcome.challenge.header;
    try std.testing.expect(std.mem.indexOf(u8, header, "error_description") == null);
    try std.testing.expect(std.mem.indexOf(u8, header, "invalid_token") != null);
    try std.testing.expect(std.mem.indexOf(u8, header, test_metadata_url) != null);
}

test "metadata declares the resource this server actually validates" {
    var scripted: ScriptedVerifier = .{ .result = error.InvalidToken };
    const server = testServer(scripted.verifier());

    const metadata = server.metadata(&.{test_issuer}, &.{ "files:read", "files:write" });
    try metadata.validate();
    try std.testing.expectEqualStrings(test_resource, metadata.resource);
    try std.testing.expectEqualStrings("header", metadata.bearer_methods_supported.?[0]);
}

test "the challenge a resource server emits is one a client can parse" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var scripted: ScriptedVerifier = .{ .result = Grant{
        .issuer = test_issuer,
        .audience = test_resource,
        .scopes = "files:read",
    } };
    const server = testServer(scripted.verifier());

    const outcome = try server.authorize(
        arena.allocator(),
        "Bearer good",
        "files:write",
        test_now,
    );
    // Round-trip through the client-side parser: the two halves must agree.
    const parsed = (try bearer.parseChallenge(arena.allocator(), outcome.challenge.header)).?;
    try std.testing.expectEqual(bearer.ErrorCode.insufficient_scope, parsed.code.?);
    try std.testing.expectEqualStrings("files:write", parsed.scope.?);
    try std.testing.expectEqualStrings(test_metadata_url, parsed.resource_metadata.?);
}

// -- JwtVerifier tests --------------------------------------------------------

const TestSigner = struct {
    const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const base64url = @import("base64url.zig");

    pair: Scheme.KeyPair,

    fn init(seed: u8) !TestSigner {
        var bytes: [Scheme.KeyPair.seed_length]u8 = undefined;
        @memset(&bytes, seed);
        return .{ .pair = try Scheme.KeyPair.generateDeterministic(bytes) };
    }

    fn keySet(signer: *const TestSigner, arena: std.mem.Allocator) !jwk.KeySet {
        const sec1 = signer.pair.public_key.toUncompressedSec1();
        const document = try std.fmt.allocPrint(
            arena,
            "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"use\":\"sig\"," ++
                "\"x\":\"{s}\",\"y\":\"{s}\"}}]}}",
            .{
                try base64url.encode(arena, sec1[1..33]),
                try base64url.encode(arena, sec1[33..65]),
            },
        );
        return jwk.KeySet.parse(arena, document);
    }

    fn token(signer: *const TestSigner, arena: std.mem.Allocator, claims: []const u8) ![]u8 {
        const header = try base64url.encode(arena, "{\"alg\":\"ES256\",\"kid\":\"k1\"}");
        const payload = try base64url.encode(arena, claims);
        const signing_input = try std.fmt.allocPrint(arena, "{s}.{s}", .{ header, payload });
        const signature = try signer.pair.sign(signing_input, null);
        return std.fmt.allocPrint(arena, "{s}.{s}", .{
            signing_input,
            try base64url.encode(arena, &signature.toBytes()),
        });
    }
};

test "JwtVerifier grants a real token end to end" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(31);
    var static: StaticKeys = .{ .set = try signer.keySet(allocator) };
    var verifier: JwtVerifier = .init(static.provider(), .{
        .issuer = test_issuer,
        .audience = test_resource,
    });
    const server = testServer(verifier.verifier());

    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":{d},\"sub\":\"u1\"," ++
            "\"client_id\":\"c1\",\"scope\":\"files:read files:write\"}}",
        .{ test_issuer, test_resource, test_now + 300 },
    );
    const header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{try signer.token(allocator, claims)},
    );

    const outcome = try server.authorize(allocator, header, "files:write", test_now);
    const grant = outcome.granted;
    try std.testing.expectEqualStrings("u1", grant.subject.?);
    try std.testing.expectEqualStrings("c1", grant.client_id.?);
    try std.testing.expectEqualStrings("files:read files:write", grant.scopes);
    try std.testing.expectEqual(test_now + 300, grant.expires_at.?);
}

test "JwtVerifier rejects a token minted for another resource" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(32);
    var static: StaticKeys = .{ .set = try signer.keySet(allocator) };
    var verifier: JwtVerifier = .init(static.provider(), .{
        .issuer = test_issuer,
        .audience = test_resource,
    });
    const server = testServer(verifier.verifier());

    // Correctly signed by the right issuer, but for a different audience — the
    // token-passthrough case the specification forbids honoring.
    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"https://other.example/api\",\"exp\":{d}}}",
        .{ test_issuer, test_now + 300 },
    );
    const header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{try signer.token(allocator, claims)},
    );

    const outcome = try server.authorize(allocator, header, null, test_now);
    try std.testing.expectEqual(@as(u16, 401), outcome.challenge.status);
    try std.testing.expect(std.mem.indexOf(u8, outcome.challenge.header, "invalid_token") != null);
}

test "JwtVerifier reports the reason to diagnostics but not to the client" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var log: std.Io.Writer.Allocating = .init(allocator);
    const signer = try TestSigner.init(33);
    var static: StaticKeys = .{ .set = try signer.keySet(allocator) };
    var verifier: JwtVerifier = .init(static.provider(), .{
        .issuer = test_issuer,
        .audience = test_resource,
        .diagnostics = &log.writer,
    });
    const server = testServer(verifier.verifier());

    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":{d}}}",
        .{ test_issuer, test_resource, test_now - 10_000 },
    );
    const header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{try signer.token(allocator, claims)},
    );

    const outcome = try server.authorize(allocator, header, null, test_now);
    try std.testing.expectEqual(@as(u16, 401), outcome.challenge.status);
    // The operator learns it expired; the client learns only that it was invalid.
    try std.testing.expect(std.mem.indexOf(u8, log.written(), "Expired") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.challenge.header, "Expired") == null);
}

test "JwtVerifier collects scopes from an scp array" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(34);
    var static: StaticKeys = .{ .set = try signer.keySet(allocator) };
    var verifier: JwtVerifier = .init(static.provider(), .{
        .issuer = test_issuer,
        .audience = test_resource,
    });
    const server = testServer(verifier.verifier());

    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":{d},\"scp\":[\"files:read\",\"mail:send\"]}}",
        .{ test_issuer, test_resource, test_now + 300 },
    );
    const header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{try signer.token(allocator, claims)},
    );

    const outcome = try server.authorize(allocator, header, "mail:send", test_now);
    try std.testing.expectEqualStrings("files:read mail:send", outcome.granted.scopes);
}

/// A provider that always fails, standing in for an unreachable JWKS endpoint.
const FailingKeys = struct {
    fn provider(self: *FailingKeys) KeyProvider {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable: KeyProvider.VTable = .{ .keys = keys };
    fn keys(ptr: *anyopaque, arena: std.mem.Allocator) Error!jwk.KeySet {
        _ = .{ ptr, arena };
        return error.Unavailable;
    }
};

test "an unreachable key source is 503, not 401" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var failing: FailingKeys = .{};
    var verifier: JwtVerifier = .init(failing.provider(), .{
        .issuer = test_issuer,
        .audience = test_resource,
    });
    const server = testServer(verifier.verifier());

    const outcome = try server.authorize(arena.allocator(), "Bearer a.b.c", null, test_now);
    try std.testing.expectEqual(Outcome.unavailable, outcome);
}
