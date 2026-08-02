//! JWT access token validation (RFC 7519, RFC 9068) for a resource server.
//!
//! ## Order is the security property
//!
//! `verify` does its work in one order and it is not incidental:
//!
//!   1. split the compact serialization into three segments
//!   2. read the header and resolve `alg` to an `Algorithm` this module implements
//!   3. select the key from the key set
//!   4. **verify the signature**
//!   5. only then decode the payload and check the claims
//!
//! Everything before step 4 is attacker-controlled data being used to pick a
//! verification procedure, which is why steps 2 and 3 are constrained to choices
//! that are safe for any input: `alg` can only resolve to a public-key signature
//! algorithm, and key selection cannot be steered onto the wrong key. No claim is
//! read for any decision before the signature holds — a verifier that checks `exp`
//! or `iss` first is not checking anything, because unsigned claims say whatever the
//! sender wants.
//!
//! ## Audience validation is the point
//!
//! MCP requires a server to reject tokens that were not issued for it, and this is
//! the check that does it: `aud` must contain the resource identifier. It is also
//! what stops token passthrough (an MCP server forwarding a client's token to an
//! upstream API, or accepting a token minted for some other service) and what stops
//! an OIDC ID token — whose `aud` is a client id — from being used as an access
//! token. `Expectations.audience` has no default for that reason.

const std = @import("std");
const assert_mod = @import("assert");

const base64url = @import("base64url.zig");
const jwk = @import("jwk.zig");
const scope = @import("scope.zig");

const assert = assert_mod.assert;

/// Upper bound on a token this module will look at.
///
/// Tokens arrive in a header, so `bearer.token_bytes_max` bounds them first; this is
/// the same number, restated where the parsing happens.
pub const token_bytes_max = 8 * 1024;

/// Upper bound on the decoded header and payload.
pub const segment_bytes_max = 6 * 1024;

/// Default tolerance for clock skew between the issuer and this server, in seconds.
///
/// Some skew is unavoidable and rejecting a token because two machines disagree by a
/// second is a worse failure than honoring one for a moment past its expiry.
pub const leeway_seconds_default: i64 = 60;

/// How far in the future an `iat` may be before the token is considered nonsense.
///
/// Beyond skew, a token issued in the future is either a badly configured issuer or
/// a forgery attempt, and neither should be honored.
pub const issued_at_future_seconds_max: i64 = 300;

pub const Error = error{
    /// Not three dot-separated segments, or a segment was not valid base64url.
    Malformed,
    /// Longer than `token_bytes_max`, or a segment longer than `segment_bytes_max`.
    TokenTooLarge,
    /// The header named an algorithm this module does not implement. `none` and
    /// every HMAC algorithm land here, which is the algorithm-confusion guard.
    UnsupportedAlgorithm,
    /// The header carried a `crit` member naming an extension this module does not
    /// understand. RFC 7515 requires rejecting the token rather than ignoring it.
    UnsupportedCriticalHeader,
    /// No key in the set can verify this token.
    KeyNotFound,
    /// The key material was unusable.
    InvalidKey,
    /// The signature did not verify.
    InvalidSignature,
    /// `iss` was absent or is not the expected issuer.
    InvalidIssuer,
    /// `aud` was absent or does not include this resource. The token was not issued
    /// for this server.
    InvalidAudience,
    /// `exp` has passed, or was absent while required.
    Expired,
    /// `nbf` is in the future, or `iat` is implausibly so.
    NotYetValid,
    /// The token is valid but lacks a required scope. Distinct from the rest because
    /// it is the only one that means 403 rather than 401: re-authenticating will not
    /// help, but asking for more scopes will.
    InsufficientScope,
    OutOfMemory,
};

/// The JOSE header members this module acts on.
pub const Header = struct {
    alg: []const u8,
    kid: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    crit: ?[]const []const u8 = null,
};

/// The registered and OAuth claims a resource server uses.
///
/// `aud` is normalized to a list, because RFC 7519 allows either a string or an
/// array and code that handles only one of them fails against half of all issuers.
pub const Claims = struct {
    iss: ?[]const u8 = null,
    sub: ?[]const u8 = null,
    aud: []const []const u8 = &.{},
    exp: ?i64 = null,
    nbf: ?i64 = null,
    iat: ?i64 = null,
    jti: ?[]const u8 = null,
    /// The `scope` claim (RFC 8693), a space-delimited string.
    scope: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    /// Every claim as parsed, for callers that need one this struct does not name.
    all: std.json.Value = .null,

    /// True if the token carries `token_scope`.
    ///
    /// Reads both `scope` and `scp`: RFC 8693 registers `scope` as a string, but
    /// several widely deployed authorization servers emit `scp` as an array instead.
    pub fn hasScope(claims: *const Claims, token_scope: []const u8) bool {
        if (claims.scope) |value| {
            if (scope.contains(value, token_scope)) return true;
        }
        if (claims.all == .object) {
            if (claims.all.object.get("scp")) |value| switch (value) {
                .array => |items| for (items.items) |item| {
                    if (item == .string and std.mem.eql(u8, item.string, token_scope)) return true;
                },
                .string => |text| if (scope.contains(text, token_scope)) return true,
                else => {},
            };
        }
        return false;
    }

    /// True if the token carries every token in `required`.
    pub fn hasAllScopes(claims: *const Claims, required: []const u8) bool {
        var iterator: scope.Iterator = .init(required);
        while (iterator.next()) |token| {
            if (!claims.hasScope(token)) return false;
        }
        return true;
    }

    pub fn hasAudience(claims: *const Claims, audience: []const u8) bool {
        for (claims.aud) |entry| {
            if (std.mem.eql(u8, entry, audience)) return true;
        }
        return false;
    }
};

/// What a resource server requires of a token.
///
/// `issuer` and `audience` have no defaults. A verifier that could be constructed
/// without them would be a verifier that could be *used* without them, and either
/// omission turns validation into decoration.
pub const Expectations = struct {
    /// The authorization server's issuer identifier, compared byte-exactly.
    issuer: []const u8,
    /// This server's canonical resource URI, which must appear in `aud`.
    audience: []const u8,
    /// Current time as a Unix timestamp in seconds.
    now: i64,
    /// Scopes the operation requires. A token missing any of them is
    /// `error.InsufficientScope`, which is a 403.
    required_scopes: ?[]const u8 = null,
    leeway_seconds: i64 = leeway_seconds_default,
    /// Whether a token without `exp` is rejected. On by default: a token that never
    /// expires cannot be revoked by waiting, and an issuer that omits `exp` is
    /// almost certainly not issuing access tokens.
    require_expiry: bool = true,
    /// When set, `typ` must equal this value. Off by default because issuers
    /// disagree — RFC 9068 says `at+jwt`, plenty emit `JWT` — and the audience check
    /// is what actually prevents using an ID token here.
    require_typ: ?[]const u8 = null,
};

/// A token that passed every check.
pub const Verified = struct {
    header: Header,
    claims: Claims,
    algorithm: jwk.Algorithm,
    /// The key that verified it, for logging key rotation.
    kid: ?[]const u8,
};

/// The three segments of a compact JWS, plus the bytes that were signed.
pub const Parts = struct {
    /// `header.payload` exactly as received. Signature verification is over these
    /// bytes; re-encoding the decoded values produces different bytes.
    signing_input: []const u8,
    header_segment: []const u8,
    payload_segment: []const u8,
    signature_segment: []const u8,

    /// Splits the compact serialization without decoding anything.
    pub fn split(token: []const u8) Error!Parts {
        if (token.len > token_bytes_max) return error.TokenTooLarge;

        const first = std.mem.indexOfScalar(u8, token, '.') orelse return error.Malformed;
        const second = std.mem.indexOfScalarPos(u8, token, first + 1, '.') orelse
            return error.Malformed;
        // A fourth segment means JWE (five segments) or a corrupted token. Either
        // way it is not something to verify as a JWS.
        if (std.mem.indexOfScalarPos(u8, token, second + 1, '.') != null) return error.Malformed;

        const header_segment = token[0..first];
        const payload_segment = token[first + 1 .. second];
        const signature_segment = token[second + 1 ..];
        if (header_segment.len == 0) return error.Malformed;
        if (payload_segment.len == 0) return error.Malformed;
        // An empty signature is the `alg: none` token in disguise.
        if (signature_segment.len == 0) return error.Malformed;

        assert(second > first);
        return .{
            .signing_input = token[0..second],
            .header_segment = header_segment,
            .payload_segment = payload_segment,
            .signature_segment = signature_segment,
        };
    }
};

/// Decodes the JOSE header.
pub fn decodeHeader(arena: std.mem.Allocator, segment: []const u8) Error!Header {
    const bytes = try decodeSegment(arena, segment);
    return std.json.parseFromSliceLeaky(Header, arena, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
}

/// Decodes the payload into claims.
///
/// Claim types are checked rather than coerced: a `exp` that arrived as a string is
/// a malformed token, and reading it as one anyway would let an issuer bug or an
/// attacker turn an expiry into an absent one.
pub fn decodeClaims(arena: std.mem.Allocator, segment: []const u8) Error!Claims {
    const bytes = try decodeSegment(arena, segment);
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    if (parsed != .object) return error.Malformed;
    const object = parsed.object;

    var claims: Claims = .{ .all = parsed };
    claims.iss = try stringClaim(object, "iss");
    claims.sub = try stringClaim(object, "sub");
    claims.jti = try stringClaim(object, "jti");
    claims.scope = try stringClaim(object, "scope");
    claims.client_id = try stringClaim(object, "client_id");
    claims.exp = try dateClaim(object, "exp");
    claims.nbf = try dateClaim(object, "nbf");
    claims.iat = try dateClaim(object, "iat");

    if (object.get("aud")) |value| switch (value) {
        .string => |single| {
            const list = arena.alloc([]const u8, 1) catch return error.OutOfMemory;
            list[0] = single;
            claims.aud = list;
        },
        .array => |items| {
            const list = arena.alloc([]const u8, items.items.len) catch return error.OutOfMemory;
            for (items.items, 0..) |item, index| {
                if (item != .string) return error.Malformed;
                list[index] = item.string;
            }
            claims.aud = list;
        },
        else => return error.Malformed,
    };

    return claims;
}

fn decodeSegment(arena: std.mem.Allocator, segment: []const u8) Error![]u8 {
    const length = base64url.decodedLength(segment) catch return error.Malformed;
    if (length > segment_bytes_max) return error.TokenTooLarge;
    return base64url.decode(arena, segment) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidEncoding => error.Malformed,
    };
}

fn stringClaim(object: std.json.ObjectMap, name: []const u8) Error!?[]const u8 {
    const value = object.get(name) orelse return null;
    if (value != .string) return error.Malformed;
    return value.string;
}

/// Reads a NumericDate claim.
///
/// RFC 7519 defines NumericDate as a JSON number, so an integer is the expected
/// form. A float is accepted when it is integral, because a few issuers serialize
/// seconds as `1735689600.0`; a fractional value is truncated toward negative
/// infinity, which keeps `exp` conservative.
fn dateClaim(object: std.json.ObjectMap, name: []const u8) Error!?i64 {
    const value = object.get(name) orelse return null;
    switch (value) {
        .integer => |number| return number,
        .float => |number| {
            if (!std.math.isFinite(number)) return error.Malformed;
            if (number > @as(f64, @floatFromInt(std.math.maxInt(i64)))) return error.Malformed;
            if (number < @as(f64, @floatFromInt(std.math.minInt(i64)))) return error.Malformed;
            return @intFromFloat(@floor(number));
        },
        .number_string => |text| return std.fmt.parseInt(i64, text, 10) catch error.Malformed,
        else => return error.Malformed,
    }
}

/// Validates a JWT access token against a key set.
///
/// The steps run in the order documented at the top of this file. On success the
/// caller has a token whose signature holds, whose issuer is the expected one, and
/// whose audience includes this server.
pub fn verify(
    arena: std.mem.Allocator,
    token: []const u8,
    keys: *const jwk.KeySet,
    expectations: Expectations,
) Error!Verified {
    assert(expectations.issuer.len > 0);
    assert(expectations.audience.len > 0);

    const parts = try Parts.split(token);
    const header = try decodeHeader(arena, parts.header_segment);

    // `crit` names extensions the verifier must understand. This module implements
    // none, so any value is a refusal — the alternative is honoring a token while
    // ignoring the constraint that was declared essential to it.
    if (header.crit) |critical| {
        if (critical.len > 0) return error.UnsupportedCriticalHeader;
    }
    if (expectations.require_typ) |required| {
        const declared = header.typ orelse return error.Malformed;
        if (!std.ascii.eqlIgnoreCase(declared, required)) return error.Malformed;
    }

    // `none` and every HMAC algorithm fail here, before any key is chosen.
    const algorithm = jwk.Algorithm.fromText(header.alg) orelse return error.UnsupportedAlgorithm;

    const selected = keys.find(header.kid, algorithm) orelse return error.KeyNotFound;
    const key = selected.publicKey(algorithm) catch return error.InvalidKey;

    const signature = base64url.decode(arena, parts.signature_segment) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidEncoding => return error.Malformed,
    };
    key.verify(algorithm, parts.signing_input, signature) catch |err| switch (err) {
        error.InvalidSignature => return error.InvalidSignature,
        error.MalformedSignature => return error.Malformed,
        // Unreachable in practice: `find` already established that the key permits
        // this algorithm. Mapped rather than asserted so that a future key selection
        // change fails closed.
        error.AlgorithmMismatch => return error.InvalidSignature,
    };

    // Past this line the claims are authenticated and may be acted on.
    const claims = try decodeClaims(arena, parts.payload_segment);
    try checkClaims(&claims, expectations);

    return .{
        .header = header,
        .claims = claims,
        .algorithm = algorithm,
        .kid = selected.kid,
    };
}

/// Checks the claims of an already-verified token.
///
/// Separated from `verify` so it can be reused by a verifier that obtained claims
/// some other way — from an RFC 7662 introspection response, for instance — and so
/// that each rule is testable on its own.
pub fn checkClaims(claims: *const Claims, expectations: Expectations) Error!void {
    const issuer = claims.iss orelse return error.InvalidIssuer;
    // Simple string comparison, per RFC 8414. Normalizing first would let
    // `https://as.example.com:443` pass as `https://as.example.com` and, worse,
    // establish a precedent for normalizing the other comparisons in this stack.
    if (!std.mem.eql(u8, issuer, expectations.issuer)) return error.InvalidIssuer;

    if (claims.aud.len == 0) return error.InvalidAudience;
    if (!claims.hasAudience(expectations.audience)) return error.InvalidAudience;

    const leeway = expectations.leeway_seconds;
    assert(leeway >= 0);

    if (claims.exp) |exp| {
        if (expectations.now - leeway >= exp) return error.Expired;
    } else if (expectations.require_expiry) {
        return error.Expired;
    }

    if (claims.nbf) |nbf| {
        if (expectations.now + leeway < nbf) return error.NotYetValid;
    }
    if (claims.iat) |iat| {
        if (iat - expectations.now > issued_at_future_seconds_max) return error.NotYetValid;
    }

    // Last, because a token that is expired or for another audience should report
    // that rather than a scope problem: the first two are 401 and mean "get a new
    // token", while this one is 403 and means "get more scopes".
    if (expectations.required_scopes) |required| {
        if (!claims.hasAllScopes(required)) return error.InsufficientScope;
    }
}

// -- Test helpers -------------------------------------------------------------
//
// std.crypto can verify RSA but not sign it, so the round-trip tests use ES256 with
// a deterministic key. That is real signing and real verification over the real
// signing input, which is the property worth testing; the RSA paths are covered by
// structural and negative tests.

const TestSigner = struct {
    const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    pair: Scheme.KeyPair,

    fn init(seed: u8) !TestSigner {
        var bytes: [Scheme.KeyPair.seed_length]u8 = undefined;
        @memset(&bytes, seed);
        return .{ .pair = try Scheme.KeyPair.generateDeterministic(bytes) };
    }

    fn jwkJson(signer: *const TestSigner, arena: std.mem.Allocator, kid: []const u8) ![]u8 {
        const sec1 = signer.pair.public_key.toUncompressedSec1();
        const x = try base64url.encode(arena, sec1[1..33]);
        const y = try base64url.encode(arena, sec1[33..65]);
        return std.fmt.allocPrint(
            arena,
            "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"{s}\",\"use\":\"sig\"," ++
                "\"x\":\"{s}\",\"y\":\"{s}\"}}]}}",
            .{ kid, x, y },
        );
    }

    fn token(
        signer: *const TestSigner,
        arena: std.mem.Allocator,
        header_json: []const u8,
        claims_json: []const u8,
    ) ![]u8 {
        const header = try base64url.encode(arena, header_json);
        const payload = try base64url.encode(arena, claims_json);
        const signing_input = try std.fmt.allocPrint(arena, "{s}.{s}", .{ header, payload });
        const signature = try signer.pair.sign(signing_input, null);
        const encoded = try base64url.encode(arena, &signature.toBytes());
        return std.fmt.allocPrint(arena, "{s}.{s}", .{ signing_input, encoded });
    }
};

const test_issuer = "https://auth.example.com";
const test_audience = "https://mcp.example.com/mcp";
const test_now: i64 = 1_700_000_000;

fn testClaims(arena: std.mem.Allocator, overrides: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"exp\":{d},\"iat\":{d}{s}}}",
        .{ test_issuer, test_audience, test_now + 300, test_now - 10, overrides },
    );
}

fn testExpectations() Expectations {
    return .{ .issuer = test_issuer, .audience = test_audience, .now = test_now };
}

test "Parts.split isolates the segments and the signing input" {
    const parts = try Parts.split("aaa.bbb.ccc");
    try std.testing.expectEqualStrings("aaa", parts.header_segment);
    try std.testing.expectEqualStrings("bbb", parts.payload_segment);
    try std.testing.expectEqualStrings("ccc", parts.signature_segment);
    try std.testing.expectEqualStrings("aaa.bbb", parts.signing_input);
}

test "Parts.split rejects shapes that are not a compact JWS" {
    try std.testing.expectError(error.Malformed, Parts.split(""));
    try std.testing.expectError(error.Malformed, Parts.split("aaa"));
    try std.testing.expectError(error.Malformed, Parts.split("aaa.bbb"));
    // Five segments is a JWE, not something to verify as a signed token.
    try std.testing.expectError(error.Malformed, Parts.split("a.b.c.d.e"));
    try std.testing.expectError(error.Malformed, Parts.split(".bbb.ccc"));
    try std.testing.expectError(error.Malformed, Parts.split("aaa..ccc"));
    // The `alg: none` shape, which has an empty signature.
    try std.testing.expectError(error.Malformed, Parts.split("aaa.bbb."));
    try std.testing.expectError(error.TokenTooLarge, Parts.split("a" ** (token_bytes_max + 1)));
}

test "a genuinely signed ES256 token verifies" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(7);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const token = try signer.token(
        allocator,
        "{\"alg\":\"ES256\",\"kid\":\"k1\",\"typ\":\"at+jwt\"}",
        try testClaims(allocator, ",\"sub\":\"user-1\",\"scope\":\"files:read files:write\""),
    );

    const verified = try verify(allocator, token, &keys, testExpectations());
    try std.testing.expectEqual(jwk.Algorithm.ES256, verified.algorithm);
    try std.testing.expectEqualStrings("k1", verified.kid.?);
    try std.testing.expectEqualStrings("user-1", verified.claims.sub.?);
    try std.testing.expect(verified.claims.hasScope("files:read"));
    try std.testing.expect(!verified.claims.hasScope("files:delete"));
}

test "a tampered payload fails the signature" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(11);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const token = try signer.token(
        allocator,
        "{\"alg\":\"ES256\",\"kid\":\"k1\"}",
        try testClaims(allocator, ",\"scope\":\"files:read\""),
    );

    // Re-encode the claims with an extra scope, keeping the original signature.
    const parts = try Parts.split(token);
    const forged_claims = try testClaims(allocator, ",\"scope\":\"files:read admin\"");
    const forged = try std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{
        parts.header_segment,
        try base64url.encode(allocator, forged_claims),
        parts.signature_segment,
    });
    try std.testing.expectError(
        error.InvalidSignature,
        verify(allocator, forged, &keys, testExpectations()),
    );
}

test "a token signed by a different key fails" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const honest = try TestSigner.init(3);
    const attacker = try TestSigner.init(4);
    const keys = try jwk.KeySet.parse(allocator, try honest.jwkJson(allocator, "k1"));
    const token = try attacker.token(
        allocator,
        "{\"alg\":\"ES256\",\"kid\":\"k1\"}",
        try testClaims(allocator, ""),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "alg none is refused before any key is chosen" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(5);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));

    const header = try base64url.encode(allocator, "{\"alg\":\"none\",\"kid\":\"k1\"}");
    const payload = try base64url.encode(allocator, try testClaims(allocator, ""));
    // A signature segment is present so that this fails on the algorithm rather
    // than on the structural check for an empty one.
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}.AA", .{ header, payload });

    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "an HMAC algorithm is refused rather than attempted with the public key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(6);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));

    // The classic confusion attack: keep the key set, change the algorithm to one
    // whose "key" is a shared secret the attacker also has.
    const header = try base64url.encode(allocator, "{\"alg\":\"HS256\",\"kid\":\"k1\"}");
    const payload = try base64url.encode(allocator, try testClaims(allocator, ""));
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}.AA", .{ header, payload });

    try std.testing.expectError(
        error.UnsupportedAlgorithm,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "an EC key is not used for an RSA algorithm" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(8);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));

    const header = try base64url.encode(allocator, "{\"alg\":\"RS256\",\"kid\":\"k1\"}");
    const payload = try base64url.encode(allocator, try testClaims(allocator, ""));
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}.AA", .{ header, payload });

    // Key selection refuses before verification is even attempted.
    try std.testing.expectError(
        error.KeyNotFound,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "a token naming an unknown kid is not verified against another key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(9);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const token = try signer.token(
        allocator,
        "{\"alg\":\"ES256\",\"kid\":\"does-not-exist\"}",
        try testClaims(allocator, ""),
    );
    try std.testing.expectError(
        error.KeyNotFound,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "a crit header is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(10);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const token = try signer.token(
        allocator,
        "{\"alg\":\"ES256\",\"kid\":\"k1\",\"crit\":[\"exp-ext\"],\"exp-ext\":1}",
        try testClaims(allocator, ""),
    );
    try std.testing.expectError(
        error.UnsupportedCriticalHeader,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "require_typ is enforced when set and ignored when not" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(12);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const token = try signer.token(
        allocator,
        "{\"alg\":\"ES256\",\"kid\":\"k1\",\"typ\":\"JWT\"}",
        try testClaims(allocator, ""),
    );

    _ = try verify(allocator, token, &keys, testExpectations());

    var strict = testExpectations();
    strict.require_typ = "at+jwt";
    try std.testing.expectError(error.Malformed, verify(allocator, token, &keys, strict));

    strict.require_typ = "jwt";
    _ = try verify(allocator, token, &keys, strict);
}

test "a token for another audience is rejected" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(13);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":\"https://other.example/api\",\"exp\":{d}}}",
        .{ test_issuer, test_now + 300 },
    );
    const token = try signer.token(allocator, "{\"alg\":\"ES256\",\"kid\":\"k1\"}", claims);

    try std.testing.expectError(
        error.InvalidAudience,
        verify(allocator, token, &keys, testExpectations()),
    );
}

test "an audience array containing this resource is accepted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const signer = try TestSigner.init(14);
    const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));
    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"iss\":\"{s}\",\"aud\":[\"https://other.example\",\"{s}\"],\"exp\":{d}}}",
        .{ test_issuer, test_audience, test_now + 300 },
    );
    const token = try signer.token(allocator, "{\"alg\":\"ES256\",\"kid\":\"k1\"}", claims);

    const verified = try verify(allocator, token, &keys, testExpectations());
    try std.testing.expectEqual(@as(usize, 2), verified.claims.aud.len);
}

test "checkClaims enforces issuer byte-exactly" {
    var claims: Claims = .{
        .iss = "https://auth.example.com",
        .aud = &.{test_audience},
        .exp = test_now + 300,
    };
    try checkClaims(&claims, testExpectations());

    // Differing only by a trailing slash, or by a normalization the spec forbids
    // applying, must still be a mismatch.
    claims.iss = "https://auth.example.com/";
    try std.testing.expectError(error.InvalidIssuer, checkClaims(&claims, testExpectations()));
    claims.iss = "https://auth.example.com:443";
    try std.testing.expectError(error.InvalidIssuer, checkClaims(&claims, testExpectations()));
    claims.iss = "https://AUTH.example.com";
    try std.testing.expectError(error.InvalidIssuer, checkClaims(&claims, testExpectations()));
    claims.iss = null;
    try std.testing.expectError(error.InvalidIssuer, checkClaims(&claims, testExpectations()));
}

test "checkClaims applies expiry with leeway" {
    var claims: Claims = .{
        .iss = test_issuer,
        .aud = &.{test_audience},
        .exp = test_now,
    };
    // Exactly at expiry, with the default leeway, is still honored.
    try checkClaims(&claims, testExpectations());

    var strict = testExpectations();
    strict.leeway_seconds = 0;
    try std.testing.expectError(error.Expired, checkClaims(&claims, strict));

    claims.exp = test_now - leeway_seconds_default - 1;
    try std.testing.expectError(error.Expired, checkClaims(&claims, testExpectations()));
}

test "checkClaims requires an expiry by default" {
    var claims: Claims = .{ .iss = test_issuer, .aud = &.{test_audience} };
    try std.testing.expectError(error.Expired, checkClaims(&claims, testExpectations()));

    var permissive = testExpectations();
    permissive.require_expiry = false;
    try checkClaims(&claims, permissive);
}

test "checkClaims honors nbf and rejects an implausible iat" {
    var claims: Claims = .{
        .iss = test_issuer,
        .aud = &.{test_audience},
        .exp = test_now + 300,
        .nbf = test_now + leeway_seconds_default + 1,
    };
    try std.testing.expectError(error.NotYetValid, checkClaims(&claims, testExpectations()));

    claims.nbf = test_now + leeway_seconds_default;
    try checkClaims(&claims, testExpectations());

    claims.nbf = null;
    claims.iat = test_now + issued_at_future_seconds_max + 1;
    try std.testing.expectError(error.NotYetValid, checkClaims(&claims, testExpectations()));
}

test "checkClaims reports insufficient scope distinctly and last" {
    var claims: Claims = .{
        .iss = test_issuer,
        .aud = &.{test_audience},
        .exp = test_now + 300,
        .scope = "files:read",
    };
    var expectations = testExpectations();
    expectations.required_scopes = "files:read";
    try checkClaims(&claims, expectations);

    expectations.required_scopes = "files:read files:write";
    try std.testing.expectError(error.InsufficientScope, checkClaims(&claims, expectations));

    // An expired token reports expiry, not a scope problem: the client needs to know
    // that a new token would help.
    claims.exp = test_now - 10_000;
    try std.testing.expectError(error.Expired, checkClaims(&claims, expectations));
}

test "hasScope reads both the scope string and the scp array" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        "{\"scp\":[\"files:read\",\"mail:send\"]}",
        .{},
    );
    const claims: Claims = .{ .all = parsed };
    try std.testing.expect(claims.hasScope("files:read"));
    try std.testing.expect(claims.hasScope("mail:send"));
    try std.testing.expect(!claims.hasScope("files:write"));
    try std.testing.expect(claims.hasAllScopes("files:read mail:send"));
    try std.testing.expect(!claims.hasAllScopes("files:read admin"));
}

test "decodeClaims rejects wrongly typed claims instead of coercing them" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const cases = [_][]const u8{
        "{\"iss\":123}",
        "{\"exp\":\"soon\"}",
        "{\"aud\":123}",
        "{\"aud\":[\"ok\",123]}",
        "{\"scope\":[\"a\"]}",
        "[]",
    };
    for (cases) |case| {
        const segment = try base64url.encode(allocator, case);
        try std.testing.expectError(error.Malformed, decodeClaims(allocator, segment));
    }
}

test "decodeClaims accepts an integral float NumericDate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const segment = try base64url.encode(allocator, "{\"exp\":1700000300.0}");
    const claims = try decodeClaims(allocator, segment);
    try std.testing.expectEqual(@as(i64, 1_700_000_300), claims.exp.?);
}

test "decodeClaims bounds the segment size" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const big = try allocator.alloc(u8, segment_bytes_max + 1);
    @memset(big, 'a');
    const segment = try base64url.encode(allocator, big);
    try std.testing.expectError(error.TokenTooLarge, decodeClaims(allocator, segment));
}

test "fuzz verify" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            const signer = try TestSigner.init(21);
            const keys = try jwk.KeySet.parse(allocator, try signer.jwkJson(allocator, "k1"));

            // No arbitrary input may ever verify: it would have to forge a signature.
            const result = verify(allocator, buffer[0..length], &keys, testExpectations());
            try std.testing.expect(std.meta.isError(result));
        }
    }.run, .{});
}
