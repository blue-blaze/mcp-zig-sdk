//! The authorization code flow with PKCE: building the request, and validating the
//! response.
//!
//! ## PKCE is mandatory, and `S256` is the method
//!
//! An attacker who intercepts an authorization code can redeem it, unless the token
//! request must also present a secret only the original requester knows. That is
//! PKCE. OAuth 2.1 requires `S256` when the client is technically capable, and a Zig
//! program always is, so `plain` is not implemented here — offering it would only
//! create a way to weaken a flow by configuration.
//!
//! ## The `iss` check is the mix-up defense
//!
//! An attacker who controls one authorization server a client talks to can try to
//! make the client send it a code issued by a different, honest one. RFC 9207 adds
//! `iss` to the authorization response so the client can tell. The rule is a table,
//! and all four rows matter:
//!
//! | metadata advertises `iss` | `iss` present | action |
//! |---|---|---|
//! | true  | yes | compare to the recorded issuer |
//! | true  | no  | **reject** |
//! | false | yes | compare to the recorded issuer |
//! | false | no  | proceed |
//!
//! Row three is the local-policy provision: MCP compares a present `iss` regardless
//! of what the metadata claimed, so that a server emitting `iss` before updating its
//! metadata is still checked. `validateResponse` implements the whole table, because
//! implementing three rows of it is the same as implementing none.
//!
//! ## What must be recorded per request
//!
//! `Request` holds it: the code verifier, the state, and **the issuer taken from the
//! validated metadata document**. The `iss` comparison is worthless if the expected
//! issuer came from an unvalidated source, so it is stored alongside the verifier
//! rather than looked up later.

const std = @import("std");
const assert_mod = @import("assert");

const base64url = @import("base64url.zig");
const prm = @import("prm.zig");
const scope = @import("scope.zig");
const url = @import("url.zig");

const assert = assert_mod.assert;

/// The only code challenge method this module implements.
pub const challenge_method = "S256";

/// Length of a generated code verifier, in bytes before encoding.
///
/// 32 random bytes become 43 base64url characters, which is the minimum RFC 7636
/// allows and 256 bits of entropy. The maximum is 128 characters; more than 256 bits
/// buys nothing.
pub const verifier_entropy_bytes = 32;

/// Encoded length of a generated verifier.
pub const verifier_length = base64url.encodedLength(verifier_entropy_bytes);

/// Bounds from RFC 7636 Section 4.1.
pub const verifier_length_min = 43;
pub const verifier_length_max = 128;

/// Length of a generated `state` value, in bytes before encoding.
pub const state_entropy_bytes = 16;
pub const state_length = base64url.encodedLength(state_entropy_bytes);

/// Upper bound on an authorization response query string.
pub const response_bytes_max = 8 * 1024;

pub const PkceError = error{
    /// The verifier is outside the RFC 7636 length bounds, or contains a character
    /// outside its `unreserved` alphabet.
    InvalidVerifier,
};

/// A PKCE code verifier and the challenge derived from it.
pub const Pkce = struct {
    /// The secret. Sent only in the token request, never in the authorization
    /// request, and never logged.
    verifier: [verifier_length]u8,
    /// `BASE64URL(SHA256(verifier))`, sent in the authorization request.
    challenge: [base64url.encodedLength(32)]u8,

    /// Generates a verifier from a cryptographically secure source.
    ///
    /// `io.randomSecure` rather than a userspace PRNG: this value is the only thing
    /// standing between an intercepted authorization code and a token. A failure to
    /// obtain entropy is an error rather than a fallback, because the only fallback
    /// would be a verifier an attacker can predict.
    pub fn generate(io: std.Io) std.Io.RandomSecureError!Pkce {
        var entropy: [verifier_entropy_bytes]u8 = undefined;
        try io.randomSecure(&entropy);

        var pkce: Pkce = .{ .verifier = undefined, .challenge = undefined };
        _ = base64url.encodeInto(&pkce.verifier, &entropy);
        pkce.deriveChallenge();
        return pkce;
    }

    /// Adopts an existing verifier, for a caller that persists one across a process
    /// restart while the user is at the authorization server.
    pub fn fromVerifier(verifier: []const u8) PkceError!Pkce {
        if (!validVerifier(verifier)) return error.InvalidVerifier;
        // A verifier of another length cannot be stored in the fixed buffer, and
        // supporting variable lengths would mean carrying a length everywhere for the
        // benefit of a value this module also generates.
        if (verifier.len != verifier_length) return error.InvalidVerifier;

        var pkce: Pkce = .{ .verifier = undefined, .challenge = undefined };
        @memcpy(&pkce.verifier, verifier);
        pkce.deriveChallenge();
        return pkce;
    }

    fn deriveChallenge(pkce: *Pkce) void {
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&pkce.verifier, &digest, .{});
        _ = base64url.encodeInto(&pkce.challenge, &digest);
        assert(pkce.challenge.len == 43);
    }
};

/// True if `verifier` is a valid `code_verifier` per RFC 7636 Section 4.1:
/// 43–128 characters of `unreserved` = ALPHA / DIGIT / `-` / `.` / `_` / `~`.
pub fn validVerifier(verifier: []const u8) bool {
    if (verifier.len < verifier_length_min) return false;
    if (verifier.len > verifier_length_max) return false;
    for (verifier) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or
            byte == '-' or byte == '.' or byte == '_' or byte == '~';
        if (!ok) return false;
    }
    return true;
}

/// Generates an opaque `state` value.
///
/// State is a CSRF defense: the client discards any authorization response whose
/// state it did not issue. It carries no information, so it is random rather than
/// encoded application data — encoding data there is how state stops being a
/// nonce.
pub fn generateState(io: std.Io) std.Io.RandomSecureError![state_length]u8 {
    var entropy: [state_entropy_bytes]u8 = undefined;
    try io.randomSecure(&entropy);
    var state: [state_length]u8 = undefined;
    _ = base64url.encodeInto(&state, &entropy);
    return state;
}

pub const BuildError = error{
    /// The redirect URI is neither loopback nor HTTPS.
    InsecureRedirectUri,
    /// The redirect URI is not a valid absolute URL, or carries a fragment.
    InvalidRedirectUri,
    /// The resource is not a valid canonical resource URI.
    InvalidResource,
    /// The authorization endpoint is not a valid URL.
    InvalidEndpoint,
    OutOfMemory,
};

/// Everything that must be remembered between sending a user to the authorization
/// server and receiving the response.
///
/// Kept as one value so that none of it can be forgotten: the verifier without the
/// issuer gives no mix-up protection, and the issuer without the verifier gives no
/// code-injection protection.
pub const Request = struct {
    /// The URL to send the user agent to.
    url: []const u8,
    /// The PKCE pair. Only `verifier` is needed later.
    pkce: Pkce,
    /// The `state` sent, to be compared with what comes back.
    state: []const u8,
    /// The issuer from the *validated* metadata document. The `iss` comparison is
    /// only meaningful against a value obtained this way.
    issuer: []const u8,
    /// The redirect URI sent, which must be repeated in the token request.
    redirect_uri: []const u8,
    /// The resource the token is for (RFC 8707), repeated in the token request.
    resource: []const u8,
    /// The scopes asked for. Recorded because a later step-up must request the union
    /// of these and whatever a challenge names.
    scopes: ?[]const u8,
};

pub const Parameters = struct {
    client_id: []const u8,
    /// Where the authorization response is delivered. Must be loopback or HTTPS, and
    /// must be registered with the authorization server.
    redirect_uri: []const u8,
    /// The canonical URI of the MCP server. Sent in both the authorization and token
    /// requests, and what binds the resulting token to this server.
    resource: []const u8,
    scopes: ?[]const u8 = null,
    /// Extra parameters, for authorization server features this module does not
    /// model. Names are used as given.
    extra: []const [2][]const u8 = &.{},
};

/// Builds an authorization request.
///
/// `issuer` must come from a metadata document that was validated against the issuer
/// used to fetch it.
pub fn buildRequest(
    arena: std.mem.Allocator,
    authorization_endpoint: []const u8,
    issuer: []const u8,
    pkce: Pkce,
    state: []const u8,
    parameters: Parameters,
) BuildError!Request {
    assert(issuer.len > 0);
    assert(state.len > 0);

    const endpoint = url.parse(authorization_endpoint) catch return error.InvalidEndpoint;
    _ = endpoint;
    try validateRedirectUri(parameters.redirect_uri);
    prm.validateResourceIdentifier(parameters.resource) catch return error.InvalidResource;

    var allocating: std.Io.Writer.Allocating = .init(arena);
    errdefer allocating.deinit();
    const writer = &allocating.writer;

    writer.writeAll(authorization_endpoint) catch return error.OutOfMemory;
    // The endpoint may already carry query parameters; RFC 6749 requires preserving
    // them and appending.
    const separator: u8 = if (std.mem.indexOfScalar(u8, authorization_endpoint, '?') == null)
        '?'
    else
        '&';
    writer.writeByte(separator) catch return error.OutOfMemory;

    writeParam(writer, "response_type", "code") catch return error.OutOfMemory;
    writeParam(writer, "client_id", parameters.client_id) catch return error.OutOfMemory;
    writeParam(writer, "redirect_uri", parameters.redirect_uri) catch return error.OutOfMemory;
    writeParam(writer, "state", state) catch return error.OutOfMemory;
    writeParam(writer, "code_challenge", &pkce.challenge) catch return error.OutOfMemory;
    writeParam(writer, "code_challenge_method", challenge_method) catch return error.OutOfMemory;
    // RFC 8707. Sent whether or not the server advertises support, because a server
    // that ignores it costs nothing and a server that honors it binds the token.
    writeParam(writer, "resource", parameters.resource) catch return error.OutOfMemory;
    if (parameters.scopes) |scopes| {
        if (scopes.len > 0) writeParam(writer, "scope", scopes) catch return error.OutOfMemory;
    }
    for (parameters.extra) |pair| {
        writeParam(writer, pair[0], pair[1]) catch return error.OutOfMemory;
    }

    return .{
        .url = allocating.toOwnedSlice() catch return error.OutOfMemory,
        .pkce = pkce,
        .state = arena.dupe(u8, state) catch return error.OutOfMemory,
        .issuer = arena.dupe(u8, issuer) catch return error.OutOfMemory,
        .redirect_uri = arena.dupe(u8, parameters.redirect_uri) catch return error.OutOfMemory,
        .resource = arena.dupe(u8, parameters.resource) catch return error.OutOfMemory,
        .scopes = if (parameters.scopes) |scopes|
            arena.dupe(u8, scopes) catch return error.OutOfMemory
        else
            null,
    };
}

fn writeParam(
    writer: *std.Io.Writer,
    name: []const u8,
    value: []const u8,
) std.Io.Writer.Error!void {
    // Every parameter after the first is preceded by `&`. The caller has already
    // written `?` or `&`, so check what the buffer ends with.
    const written = writer.buffered();
    if (written.len > 0 and written[written.len - 1] != '?' and written[written.len - 1] != '&') {
        try writer.writeByte('&');
    }
    try url.encodeComponent(writer, name);
    try writer.writeByte('=');
    try url.encodeComponent(writer, value);
}

/// Checks a redirect URI.
///
/// It must be loopback or HTTPS — an `http` redirect to a remote host would deliver
/// the authorization code in the clear. A fragment is rejected because the
/// authorization server appends the response to the URI and a fragment would make
/// the result ambiguous.
pub fn validateRedirectUri(redirect_uri: []const u8) BuildError!void {
    const parts = url.parse(redirect_uri) catch return error.InvalidRedirectUri;
    if (parts.fragment != null) return error.InvalidRedirectUri;
    if (parts.isHttps()) return;
    if (parts.isLoopback()) return;
    return error.InsecureRedirectUri;
}

pub const ResponseError = error{
    /// The response could not be read as a form-encoded query string.
    Malformed,
    /// Longer than `response_bytes_max`.
    ResponseTooLarge,
    /// `state` was absent or is not the one that was sent. The response belongs to
    /// some other flow, or to none.
    StateMismatch,
    /// `iss` does not match the recorded issuer. A mix-up attempt, or a
    /// misconfigured server; either way the code must not be redeemed.
    IssuerMismatch,
    /// The metadata advertised `iss` and the response did not carry it.
    MissingIssuer,
    /// The response carried neither `code` nor `error`.
    Malformed_MissingCode,
    /// The authorization server returned an error. The details are in
    /// `AuthorizationError`.
    AuthorizationFailed,
    OutOfMemory,
};

/// An `error` response from the authorization endpoint.
pub const AuthorizationError = struct {
    code: []const u8,
    description: ?[]const u8 = null,
    uri: ?[]const u8 = null,
};

/// A validated authorization response.
pub const Response = struct {
    code: []const u8,
    /// The `iss` that was present and checked, if any.
    issuer: ?[]const u8,
};

/// Validates an authorization response and extracts the code.
///
/// `query` is the response parameters — the query string of the redirect, without the
/// leading `?`. `iss_advertised` is
/// `authorization_response_iss_parameter_supported` from the validated metadata.
///
/// On an error response, `failure` is filled in and `error.AuthorizationFailed` is
/// returned — but only after the `iss` check, because the specification requires not
/// acting on or displaying `error`, `error_description`, or `error_uri` when `iss`
/// does not match. An attacker-supplied error message shown to a user is a phishing
/// surface.
pub fn validateResponse(
    arena: std.mem.Allocator,
    query: []const u8,
    request: *const Request,
    iss_advertised: bool,
    failure: *?AuthorizationError,
) ResponseError!Response {
    if (query.len > response_bytes_max) return error.ResponseTooLarge;

    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var iss: ?[]const u8 = null;
    var error_code: ?[]const u8 = null;
    var error_description: ?[]const u8 = null;
    var error_uri: ?[]const u8 = null;

    var iterator: url.FormIterator = .init(query);
    while (iterator.next(arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidEncoding => return error.Malformed,
    }) |pair| {
        // First occurrence wins. A duplicated parameter is a malformed response, and
        // taking the later one would let an appended copy override the real value.
        if (std.mem.eql(u8, pair.name, "code")) {
            if (code == null) code = pair.value;
        } else if (std.mem.eql(u8, pair.name, "state")) {
            if (state == null) state = pair.value;
        } else if (std.mem.eql(u8, pair.name, "iss")) {
            if (iss == null) iss = pair.value;
        } else if (std.mem.eql(u8, pair.name, "error")) {
            if (error_code == null) error_code = pair.value;
        } else if (std.mem.eql(u8, pair.name, "error_description")) {
            if (error_description == null) error_description = pair.value;
        } else if (std.mem.eql(u8, pair.name, "error_uri")) {
            if (error_uri == null) error_uri = pair.value;
        }
    }

    // State first: a response for a flow this client did not start should not be
    // examined further, and the comparison needs no other information.
    const returned_state = state orelse return error.StateMismatch;
    if (!constantTimeEql(returned_state, request.state)) return error.StateMismatch;

    // Then the RFC 9207 table, in full.
    if (iss) |value| {
        // Rows one and three: a present `iss` is always compared, whether or not the
        // metadata advertised it.
        if (!std.mem.eql(u8, value, request.issuer)) return error.IssuerMismatch;
    } else if (iss_advertised) {
        // Row two.
        return error.MissingIssuer;
    }
    // Row four: absent and unadvertised, proceed.

    if (error_code) |value| {
        failure.* = .{
            .code = value,
            .description = error_description,
            .uri = error_uri,
        };
        return error.AuthorizationFailed;
    }

    const returned_code = code orelse return error.Malformed_MissingCode;
    if (returned_code.len == 0) return error.Malformed_MissingCode;

    return .{ .code = returned_code, .issuer = iss };
}

/// Constant-time equality, for the state comparison.
///
/// `std.mem.eql` returns early on the first differing byte, which leaks a prefix
/// length. State is not a high-value secret, but it is compared against a value an
/// attacker supplies, and the cost of doing this right is nothing.
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |x, y| difference |= x ^ y;
    return difference == 0;
}

test "generate produces a verifier and matching challenge" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pkce: Pkce = try .generate(io);
    try std.testing.expectEqual(@as(usize, 43), pkce.verifier.len);
    try std.testing.expect(validVerifier(&pkce.verifier));

    // The challenge must be BASE64URL(SHA256(verifier)), recomputed independently.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&pkce.verifier, &digest, .{});
    var expected: [43]u8 = undefined;
    _ = base64url.encodeInto(&expected, &digest);
    try std.testing.expectEqualStrings(&expected, &pkce.challenge);
}

test "generate does not repeat itself" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const first: Pkce = try .generate(io);
    const second: Pkce = try .generate(io);
    try std.testing.expect(!std.mem.eql(u8, &first.verifier, &second.verifier));
}

test "PKCE matches the RFC 7636 Appendix B vector" {
    // The known-answer test from the specification, which catches an encoder that
    // pads or uses the wrong alphabet.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const pkce = try Pkce.fromVerifier(verifier);
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &pkce.challenge);
}

test "validVerifier enforces the RFC 7636 alphabet and bounds" {
    try std.testing.expect(validVerifier("a" ** verifier_length_min));
    try std.testing.expect(validVerifier("a" ** verifier_length_max));
    try std.testing.expect(validVerifier(("aA0-._~" ** 7)[0..43]));

    try std.testing.expect(!validVerifier("a" ** (verifier_length_min - 1)));
    try std.testing.expect(!validVerifier("a" ** (verifier_length_max + 1)));
    try std.testing.expect(!validVerifier(("a" ** 42) ++ "!"));
    try std.testing.expect(!validVerifier(("a" ** 42) ++ "+"));
    try std.testing.expect(!validVerifier(""));
}

test "fromVerifier refuses a verifier it cannot represent" {
    try std.testing.expectError(error.InvalidVerifier, Pkce.fromVerifier("too-short"));
    try std.testing.expectError(error.InvalidVerifier, Pkce.fromVerifier("a" ** 64));
    try std.testing.expectError(error.InvalidVerifier, Pkce.fromVerifier(("a" ** 42) ++ "!"));
}

test "generateState produces distinct opaque values" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const first = try generateState(io);
    const second = try generateState(io);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expect(std.mem.indexOfScalar(u8, &first, '=') == null);
}

fn testRequest(arena: std.mem.Allocator) !Request {
    const pkce = try Pkce.fromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    return buildRequest(
        arena,
        "https://auth.example.com/authorize",
        "https://auth.example.com",
        pkce,
        "state-123",
        .{
            .client_id = "https://app.example.com/client.json",
            .redirect_uri = "http://127.0.0.1:3000/callback",
            .resource = "https://mcp.example.com/mcp",
            .scopes = "files:read files:write",
        },
    );
}

test "buildRequest emits every mandatory parameter" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try testRequest(arena.allocator());
    const target = request.url;

    try std.testing.expect(std.mem.startsWith(u8, target, "https://auth.example.com/authorize?"));
    try std.testing.expect(std.mem.indexOf(u8, target, "response_type=code") != null);
    try std.testing.expect(std.mem.indexOf(u8, target, "code_challenge_method=S256") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, target, "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, target, "state=state-123") != null);
    // RFC 8707: the resource is percent-encoded and always present.
    try std.testing.expect(
        std.mem.indexOf(u8, target, "resource=https%3A%2F%2Fmcp.example.com%2Fmcp") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, target, "scope=files%3Aread%20files%3Awrite") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, target, "redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback") != null,
    );
}

test "buildRequest never puts the verifier in the URL" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try testRequest(arena.allocator());
    // The verifier is the secret. If it travelled with the challenge, PKCE would
    // protect nothing.
    try std.testing.expect(std.mem.indexOf(u8, request.url, &request.pkce.verifier) == null);
}

test "buildRequest records what the response validation needs" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try testRequest(arena.allocator());
    try std.testing.expectEqualStrings("https://auth.example.com", request.issuer);
    try std.testing.expectEqualStrings("state-123", request.state);
    try std.testing.expectEqualStrings("https://mcp.example.com/mcp", request.resource);
    try std.testing.expectEqualStrings("files:read files:write", request.scopes.?);
}

test "buildRequest preserves an endpoint's existing query" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const pkce = try Pkce.fromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    const request = try buildRequest(
        arena.allocator(),
        "https://auth.example.com/authorize?tenant=acme",
        "https://auth.example.com",
        pkce,
        "s",
        .{
            .client_id = "c",
            .redirect_uri = "https://app.example.com/cb",
            .resource = "https://mcp.example.com",
        },
    );
    try std.testing.expect(std.mem.indexOf(u8, request.url, "?tenant=acme&response_type=code") != null);
}

test "buildRequest omits scope when there is nothing to ask for" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const pkce = try Pkce.fromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    const request = try buildRequest(
        arena.allocator(),
        "https://auth.example.com/authorize",
        "https://auth.example.com",
        pkce,
        "s",
        .{
            .client_id = "c",
            .redirect_uri = "https://app.example.com/cb",
            .resource = "https://mcp.example.com",
            .scopes = "",
        },
    );
    // An empty `scope=` is not the same as an absent one, and some servers reject it.
    try std.testing.expect(std.mem.indexOf(u8, request.url, "scope=") == null);
}

test "buildRequest carries extra parameters through" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const pkce = try Pkce.fromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    const request = try buildRequest(
        arena.allocator(),
        "https://auth.example.com/authorize",
        "https://auth.example.com",
        pkce,
        "s",
        .{
            .client_id = "c",
            .redirect_uri = "https://app.example.com/cb",
            .resource = "https://mcp.example.com",
            .extra = &.{.{ "prompt", "consent" }},
        },
    );
    try std.testing.expect(std.mem.indexOf(u8, request.url, "prompt=consent") != null);
}

test "validateRedirectUri accepts loopback and https only" {
    try validateRedirectUri("http://127.0.0.1:3000/callback");
    try validateRedirectUri("http://localhost:3000/callback");
    try validateRedirectUri("http://[::1]:3000/callback");
    try validateRedirectUri("https://app.example.com/callback");

    try std.testing.expectError(
        error.InsecureRedirectUri,
        validateRedirectUri("http://app.example.com/callback"),
    );
    try std.testing.expectError(
        error.InvalidRedirectUri,
        validateRedirectUri("https://app.example.com/cb#frag"),
    );
    try std.testing.expectError(error.InvalidRedirectUri, validateRedirectUri("app.example.com/cb"));
}

test "buildRequest refuses an insecure redirect or a bad resource" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const pkce = try Pkce.fromVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    try std.testing.expectError(error.InsecureRedirectUri, buildRequest(
        arena.allocator(),
        "https://auth.example.com/authorize",
        "https://auth.example.com",
        pkce,
        "s",
        .{
            .client_id = "c",
            .redirect_uri = "http://app.example.com/cb",
            .resource = "https://mcp.example.com",
        },
    ));
    try std.testing.expectError(error.InvalidResource, buildRequest(
        arena.allocator(),
        "https://auth.example.com/authorize",
        "https://auth.example.com",
        pkce,
        "s",
        .{
            .client_id = "c",
            .redirect_uri = "https://app.example.com/cb",
            .resource = "https://mcp.example.com#frag",
        },
    ));
}

test "validateResponse accepts a matching response" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request = try testRequest(arena.allocator());
    var failure: ?AuthorizationError = null;
    const response = try validateResponse(
        arena.allocator(),
        "code=authcode&state=state-123&iss=https%3A%2F%2Fauth.example.com",
        &request,
        true,
        &failure,
    );
    try std.testing.expectEqualStrings("authcode", response.code);
    try std.testing.expectEqualStrings("https://auth.example.com", response.issuer.?);
    try std.testing.expectEqual(@as(?AuthorizationError, null), failure);
}

test "validateResponse implements all four rows of the RFC 9207 table" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    // Row 1: advertised, present, matching.
    _ = try validateResponse(
        allocator,
        "code=c&state=state-123&iss=https%3A%2F%2Fauth.example.com",
        &request,
        true,
        &failure,
    );

    // Row 2: advertised, absent — reject.
    try std.testing.expectError(error.MissingIssuer, validateResponse(
        allocator,
        "code=c&state=state-123",
        &request,
        true,
        &failure,
    ));

    // Row 3: not advertised, present — still compared. This is the row that keeps a
    // server which emits `iss` ahead of its metadata honest.
    _ = try validateResponse(
        allocator,
        "code=c&state=state-123&iss=https%3A%2F%2Fauth.example.com",
        &request,
        false,
        &failure,
    );
    try std.testing.expectError(error.IssuerMismatch, validateResponse(
        allocator,
        "code=c&state=state-123&iss=https%3A%2F%2Fattacker.example",
        &request,
        false,
        &failure,
    ));

    // Row 4: not advertised, absent — proceed.
    const proceeded = try validateResponse(
        allocator,
        "code=c&state=state-123",
        &request,
        false,
        &failure,
    );
    try std.testing.expectEqual(@as(?[]const u8, null), proceeded.issuer);
}

test "validateResponse rejects an iss that differs only by normalization" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    const cases = [_][]const u8{
        "code=c&state=state-123&iss=https%3A%2F%2Fauth.example.com%2F",
        "code=c&state=state-123&iss=https%3A%2F%2Fauth.example.com%3A443",
        "code=c&state=state-123&iss=https%3A%2F%2FAUTH.example.com",
    };
    for (cases) |case| {
        try std.testing.expectError(
            error.IssuerMismatch,
            validateResponse(allocator, case, &request, true, &failure),
        );
    }
}

test "validateResponse rejects a wrong or missing state" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    try std.testing.expectError(error.StateMismatch, validateResponse(
        allocator,
        "code=c&state=someone-elses",
        &request,
        false,
        &failure,
    ));
    try std.testing.expectError(error.StateMismatch, validateResponse(
        allocator,
        "code=c",
        &request,
        false,
        &failure,
    ));
}

test "validateResponse surfaces an authorization error only after the iss check" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    try std.testing.expectError(error.AuthorizationFailed, validateResponse(
        allocator,
        "error=access_denied&error_description=User%20said%20no&state=state-123" ++
            "&iss=https%3A%2F%2Fauth.example.com",
        &request,
        true,
        &failure,
    ));
    try std.testing.expectEqualStrings("access_denied", failure.?.code);
    try std.testing.expectEqualStrings("User said no", failure.?.description.?);

    // An error response whose `iss` does not match must not be acted on or displayed:
    // the description is attacker-controlled text destined for a user's screen.
    failure = null;
    try std.testing.expectError(error.IssuerMismatch, validateResponse(
        allocator,
        "error=access_denied&error_description=Click%20here%20to%20fix&state=state-123" ++
            "&iss=https%3A%2F%2Fattacker.example",
        &request,
        true,
        &failure,
    ));
    try std.testing.expectEqual(@as(?AuthorizationError, null), failure);
}

test "validateResponse requires a code when there is no error" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    try std.testing.expectError(error.Malformed_MissingCode, validateResponse(
        allocator,
        "state=state-123",
        &request,
        false,
        &failure,
    ));
    try std.testing.expectError(error.Malformed_MissingCode, validateResponse(
        allocator,
        "code=&state=state-123",
        &request,
        false,
        &failure,
    ));
}

test "validateResponse keeps the first of duplicated parameters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    // An appended copy must not override the real value.
    const response = try validateResponse(
        allocator,
        "code=real&state=state-123&code=injected",
        &request,
        false,
        &failure,
    );
    try std.testing.expectEqualStrings("real", response.code);
}

test "validateResponse bounds its input" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try testRequest(allocator);
    var failure: ?AuthorizationError = null;

    const long = try allocator.alloc(u8, response_bytes_max + 1);
    @memset(long, 'a');
    try std.testing.expectError(
        error.ResponseTooLarge,
        validateResponse(allocator, long, &request, false, &failure),
    );
}

test "fuzz validateResponse" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            const request = try testRequest(allocator);
            var failure: ?AuthorizationError = null;
            const response = validateResponse(
                allocator,
                buffer[0..length],
                &request,
                true,
                &failure,
            ) catch return;
            // Anything accepted must have carried a code and, since `iss` was
            // advertised, a matching issuer.
            try std.testing.expect(response.code.len > 0);
            try std.testing.expectEqualStrings(request.issuer, response.issuer.?);
        }
    }.run, .{});
}
