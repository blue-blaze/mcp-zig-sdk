//! Authorization server metadata (RFC 8414) and OpenID Connect Discovery 1.0.
//!
//! A client **MUST** support both, because MCP requires an authorization server to
//! provide only one of them and does not say which. That is why discovery is a list
//! of candidate URLs rather than one: the two specifications disagree about where
//! the document lives, and a client that guessed wrong finds nothing.
//!
//! ## The issuer check is the whole point
//!
//! After fetching, the document's `issuer` **MUST** be identical to the issuer used
//! to build the URL, or the document **MUST NOT** be used. Without it, a document
//! fetched from `https://attacker.example/.well-known/oauth-authorization-server`
//! that says `"issuer": "https://honest.example"` would be adopted, and every
//! endpoint the client then trusts — authorization, token — would be the attacker's.
//! `Metadata.validate` performs the comparison and there is no way to obtain a
//! `Metadata` from this module without it.
//!
//! ## PKCE support is not optional
//!
//! Neither OAuth 2.1 nor PKCE defines a way to probe for PKCE support, so metadata
//! is the only signal. If `code_challenge_methods_supported` is absent, the client
//! **MUST** refuse to proceed — including against OpenID providers, where the field
//! is not part of the OIDC metadata specification but is required here anyway.
//! `requirePkce` is that refusal.

const std = @import("std");
const assert_mod = @import("assert");

const prm = @import("prm.zig");
const scope = @import("scope.zig");
const url = @import("url.zig");

const assert = assert_mod.assert;

/// RFC 8414 well-known suffix. MCP does not define an application-specific one.
pub const oauth_suffix = "oauth-authorization-server";

/// OpenID Connect Discovery 1.0 well-known suffix.
pub const oidc_suffix = "openid-configuration";

/// The PKCE method a client must use when technically capable, which it always is.
pub const pkce_method_required = "S256";

/// Upper bound on a metadata document.
pub const document_bytes_max = 512 * 1024;

/// Upper bound on entries in a list-valued field.
pub const list_max = 64;

/// The most candidate URLs discovery will produce.
pub const candidates_max = 3;

pub const ValidateError = error{
    /// `issuer` was absent, or is not a valid issuer identifier.
    InvalidIssuer,
    /// `issuer` is not the issuer this document was fetched for. RFC 8414
    /// Section 3.3 and OpenID Connect Discovery Section 4.3 both require rejecting
    /// the document in this case.
    IssuerMismatch,
    /// A required endpoint was absent or not a valid URL.
    InvalidEndpoint,
    /// An endpoint is not served over HTTPS.
    InsecureEndpoint,
    /// A list-valued field exceeded `list_max`.
    TooManyEntries,
};

pub const ParseError = ValidateError || error{
    DocumentTooLarge,
    Malformed,
    OutOfMemory,
};

pub const PkceError = error{
    /// `code_challenge_methods_supported` was absent. The authorization server does
    /// not advertise PKCE, so the client must not proceed.
    PkceNotSupported,
    /// The server advertises PKCE but not `S256`.
    S256NotSupported,
};

/// An authorization server metadata document.
///
/// Field names are the wire names. Only the members this stack acts on are declared;
/// the rest are ignored on parse, because both registries grow.
pub const Metadata = struct {
    /// The issuer identifier. Compared byte-exactly against the issuer used to build
    /// the discovery URL.
    issuer: []const u8,
    authorization_endpoint: ?[]const u8 = null,
    token_endpoint: ?[]const u8 = null,
    registration_endpoint: ?[]const u8 = null,
    revocation_endpoint: ?[]const u8 = null,
    introspection_endpoint: ?[]const u8 = null,
    jwks_uri: ?[]const u8 = null,
    scopes_supported: ?[]const []const u8 = null,
    response_types_supported: ?[]const []const u8 = null,
    grant_types_supported: ?[]const []const u8 = null,
    token_endpoint_auth_methods_supported: ?[]const []const u8 = null,
    /// PKCE methods. Absence means no PKCE, which means do not proceed.
    code_challenge_methods_supported: ?[]const []const u8 = null,
    /// RFC 9207. When true, an authorization response without `iss` must be
    /// rejected.
    authorization_response_iss_parameter_supported: ?bool = null,
    /// Whether the server resolves Client ID Metadata Documents.
    client_id_metadata_document_supported: ?bool = null,
    /// RFC 8707. Advisory only: a client sends `resource` regardless.
    resource_indicators_supported: ?bool = null,

    /// Checks the document against the issuer it was fetched for.
    ///
    /// `expected_issuer` is the issuer identifier used to construct the URL, not
    /// anything read from the document.
    pub fn validate(
        metadata: *const Metadata,
        expected_issuer: []const u8,
    ) ValidateError!void {
        assert(expected_issuer.len > 0);

        if (metadata.issuer.len == 0) return error.InvalidIssuer;
        prm.validateIssuer(metadata.issuer) catch return error.InvalidIssuer;
        // Simple string comparison (RFC 3986 Section 6.2.1). Normalizing either side
        // first is what turns this check into a formality.
        if (!std.mem.eql(u8, metadata.issuer, expected_issuer)) return error.IssuerMismatch;

        // Every authorization server endpoint must be HTTPS. A document that names an
        // `http://` token endpoint would have the client post its authorization code
        // in the clear, and the code is exchangeable for a token.
        const endpoints = [_]?[]const u8{
            metadata.authorization_endpoint,
            metadata.token_endpoint,
            metadata.registration_endpoint,
            metadata.revocation_endpoint,
            metadata.introspection_endpoint,
            metadata.jwks_uri,
        };
        for (endpoints) |endpoint| {
            const value = endpoint orelse continue;
            const parts = url.parse(value) catch return error.InvalidEndpoint;
            if (!parts.isHttps() and !parts.isLoopback()) return error.InsecureEndpoint;
        }

        const lists = [_]?[]const []const u8{
            metadata.scopes_supported,
            metadata.response_types_supported,
            metadata.grant_types_supported,
            metadata.token_endpoint_auth_methods_supported,
            metadata.code_challenge_methods_supported,
        };
        for (lists) |list| {
            if ((list orelse continue).len > list_max) return error.TooManyEntries;
        }
    }

    /// The endpoints an authorization code flow needs, or an error naming the one
    /// that is missing.
    pub fn authorizationEndpoint(metadata: *const Metadata) ValidateError![]const u8 {
        return metadata.authorization_endpoint orelse error.InvalidEndpoint;
    }

    pub fn tokenEndpoint(metadata: *const Metadata) ValidateError![]const u8 {
        return metadata.token_endpoint orelse error.InvalidEndpoint;
    }

    /// Confirms the server supports PKCE with `S256`.
    ///
    /// Call this before starting a flow. Discovering afterwards that the server
    /// ignores `code_challenge` means the authorization code was protected by
    /// nothing.
    pub fn requirePkce(metadata: *const Metadata) PkceError!void {
        const methods = metadata.code_challenge_methods_supported orelse
            return error.PkceNotSupported;
        for (methods) |method| {
            if (std.mem.eql(u8, method, pkce_method_required)) return;
        }
        return error.S256NotSupported;
    }

    /// True when an authorization response must carry `iss`.
    ///
    /// This is the metadata half of the RFC 9207 validation table: advertised
    /// support makes a missing `iss` a rejection.
    pub fn requiresIssParameter(metadata: *const Metadata) bool {
        return metadata.authorization_response_iss_parameter_supported orelse false;
    }

    pub fn supportsClientIdMetadataDocument(metadata: *const Metadata) bool {
        return metadata.client_id_metadata_document_supported orelse false;
    }

    /// True if the server advertises Dynamic Client Registration.
    ///
    /// DCR is deprecated; this exists so a client can fall back when Client ID
    /// Metadata Documents are unavailable.
    pub fn supportsDynamicRegistration(metadata: *const Metadata) bool {
        return metadata.registration_endpoint != null;
    }

    /// `scopes_supported` as a scope set.
    pub fn supportedScopes(metadata: *const Metadata) scope.Error!?scope.Set {
        const scopes = metadata.scopes_supported orelse return null;
        var set: scope.Set = .{};
        for (scopes) |token| try set.add(token);
        return set;
    }

    /// True if `scopes_supported` lists `offline_access`, which is the condition
    /// under which a client may ask for it in order to receive a refresh token.
    pub fn offersOfflineAccess(metadata: *const Metadata) bool {
        const scopes = metadata.scopes_supported orelse return false;
        for (scopes) |token| {
            if (std.mem.eql(u8, token, "offline_access")) return true;
        }
        return false;
    }
};

/// Parses and validates a metadata document.
pub fn parse(
    arena: std.mem.Allocator,
    bytes: []const u8,
    expected_issuer: []const u8,
) ParseError!Metadata {
    if (bytes.len > document_bytes_max) return error.DocumentTooLarge;

    const metadata = std.json.parseFromSliceLeaky(Metadata, arena, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };

    try metadata.validate(expected_issuer);
    return metadata;
}

/// One discovery URL and what kind of document is expected there.
pub const Candidate = struct {
    url: []const u8,
    kind: Kind,

    pub const Kind = enum { oauth, oidc };
};

/// The discovery URLs for an issuer, in the order a client must try them.
pub const Candidates = struct {
    buffer: [candidates_max]Candidate = undefined,
    len: usize = 0,

    pub fn slice(candidates: *const Candidates) []const Candidate {
        return candidates.buffer[0..candidates.len];
    }
};

pub const DiscoveryError = error{ InvalidIssuer, OutOfMemory };

/// Builds the metadata discovery URLs for `issuer`.
///
/// For an issuer with a path component, three candidates in this order:
///
///   1. `https://as.example.com/.well-known/oauth-authorization-server/tenant1`
///   2. `https://as.example.com/.well-known/openid-configuration/tenant1`
///   3. `https://as.example.com/tenant1/.well-known/openid-configuration`
///
/// For an issuer without one, two:
///
///   1. `https://as.example.com/.well-known/oauth-authorization-server`
///   2. `https://as.example.com/.well-known/openid-configuration`
///
/// The third form exists because RFC 8414 inserts the well-known segment while
/// OpenID Connect Discovery appends it, and deployments follow one or the other.
pub fn discoveryCandidates(
    arena: std.mem.Allocator,
    issuer: []const u8,
) DiscoveryError!Candidates {
    prm.validateIssuer(issuer) catch return error.InvalidIssuer;
    const parts = url.parse(issuer) catch return error.InvalidIssuer;

    // The builders write into an arena-backed buffer, where a write failure is an
    // allocation failure and nothing else.
    var candidates: Candidates = .{};
    candidates.buffer[0] = .{
        .url = url.wellKnownInserted(arena, &parts, oauth_suffix) catch return error.OutOfMemory,
        .kind = .oauth,
    };
    candidates.buffer[1] = .{
        .url = url.wellKnownInserted(arena, &parts, oidc_suffix) catch return error.OutOfMemory,
        .kind = .oidc,
    };
    candidates.len = 2;

    if (parts.hasPathComponent()) {
        candidates.buffer[2] = .{
            .url = url.wellKnownAppended(arena, &parts, oidc_suffix) catch return error.OutOfMemory,
            .kind = .oidc,
        };
        candidates.len = 3;
    }

    assert(candidates.len >= 2);
    assert(candidates.len <= candidates_max);
    return candidates;
}

test "discoveryCandidates for an issuer with a path yields three in order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const candidates = try discoveryCandidates(arena.allocator(), "https://auth.example.com/tenant1");
    const list = candidates.slice();
    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqualStrings(
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        list[0].url,
    );
    try std.testing.expectEqual(Candidate.Kind.oauth, list[0].kind);
    try std.testing.expectEqualStrings(
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        list[1].url,
    );
    try std.testing.expectEqualStrings(
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
        list[2].url,
    );
    try std.testing.expectEqual(Candidate.Kind.oidc, list[2].kind);
}

test "discoveryCandidates for a bare issuer yields two" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const candidates = try discoveryCandidates(arena.allocator(), "https://auth.example.com");
    const list = candidates.slice();
    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqualStrings(
        "https://auth.example.com/.well-known/oauth-authorization-server",
        list[0].url,
    );
    try std.testing.expectEqualStrings(
        "https://auth.example.com/.well-known/openid-configuration",
        list[1].url,
    );
}

test "discoveryCandidates treats a trailing slash as no path component" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const candidates = try discoveryCandidates(arena.allocator(), "https://auth.example.com/");
    try std.testing.expectEqual(@as(usize, 2), candidates.len);
}

test "discoveryCandidates refuses an issuer it must not fetch from" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        error.InvalidIssuer,
        discoveryCandidates(arena.allocator(), "http://auth.example.com"),
    );
    try std.testing.expectError(
        error.InvalidIssuer,
        discoveryCandidates(arena.allocator(), "auth.example.com"),
    );
    try std.testing.expectError(
        error.InvalidIssuer,
        discoveryCandidates(arena.allocator(), "https://auth.example.com?a=b"),
    );
}

test "parse accepts a document whose issuer matches" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const metadata = try parse(arena.allocator(),
        \\{
        \\  "issuer": "https://auth.example.com",
        \\  "authorization_endpoint": "https://auth.example.com/authorize",
        \\  "token_endpoint": "https://auth.example.com/token",
        \\  "code_challenge_methods_supported": ["S256"],
        \\  "scopes_supported": ["files:read", "offline_access"],
        \\  "authorization_response_iss_parameter_supported": true,
        \\  "client_id_metadata_document_supported": true,
        \\  "a_future_registry_field": 1
        \\}
    , "https://auth.example.com");

    try std.testing.expectEqualStrings("https://auth.example.com/authorize", try metadata.authorizationEndpoint());
    try std.testing.expectEqualStrings("https://auth.example.com/token", try metadata.tokenEndpoint());
    try metadata.requirePkce();
    try std.testing.expect(metadata.requiresIssParameter());
    try std.testing.expect(metadata.supportsClientIdMetadataDocument());
    try std.testing.expect(!metadata.supportsDynamicRegistration());
    try std.testing.expect(metadata.offersOfflineAccess());
}

test "parse rejects a document claiming to be another issuer" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // The attack the check exists for: a document served from one host asserting it
    // describes another.
    try std.testing.expectError(error.IssuerMismatch, parse(
        arena.allocator(),
        "{\"issuer\":\"https://honest.example\"}",
        "https://attacker.example",
    ));
}

test "parse rejects an issuer differing only by normalization" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // Each of these would pass under the normalization the specification forbids
    // applying before comparison.
    const cases = [_][]const u8{
        "{\"issuer\":\"https://auth.example.com/\"}",
        "{\"issuer\":\"https://auth.example.com:443\"}",
        "{\"issuer\":\"https://AUTH.example.com\"}",
    };
    for (cases) |case| {
        try std.testing.expectError(
            error.IssuerMismatch,
            parse(arena.allocator(), case, "https://auth.example.com"),
        );
    }
}

test "parse rejects a plain http endpoint" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // A token endpoint over http would have the client post its authorization code
    // where anyone on the path can take it.
    try std.testing.expectError(error.InsecureEndpoint, parse(
        arena.allocator(),
        "{\"issuer\":\"https://auth.example.com\"," ++
            "\"token_endpoint\":\"http://auth.example.com/token\"}",
        "https://auth.example.com",
    ));
}

test "parse allows loopback endpoints for local development" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const metadata = try parse(
        arena.allocator(),
        "{\"issuer\":\"http://localhost:9000\"," ++
            "\"token_endpoint\":\"http://localhost:9000/token\"," ++
            "\"code_challenge_methods_supported\":[\"S256\"]}",
        "http://localhost:9000",
    );
    try metadata.requirePkce();
}

test "parse rejects malformed documents" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "[]", "https://a.example"));
    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "{}", "https://a.example"));
    try std.testing.expectError(
        error.Malformed,
        parse(arena.allocator(), "{\"issuer\":123}", "https://a.example"),
    );
    try std.testing.expectError(
        error.Malformed,
        parse(arena.allocator(), "not json", "https://a.example"),
    );
}

test "parse bounds the document size" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const big = try arena.allocator().alloc(u8, document_bytes_max + 1);
    @memset(big, ' ');
    try std.testing.expectError(
        error.DocumentTooLarge,
        parse(arena.allocator(), big, "https://a.example"),
    );
}

test "requirePkce refuses when the field is absent" {
    // Absent means no PKCE, and no PKCE means the authorization code is protected by
    // nothing — so this must be a refusal rather than a warning.
    const silent: Metadata = .{ .issuer = "https://auth.example.com" };
    try std.testing.expectError(error.PkceNotSupported, silent.requirePkce());
}

test "requirePkce refuses a server offering only plain" {
    const plain: Metadata = .{
        .issuer = "https://auth.example.com",
        .code_challenge_methods_supported = &.{"plain"},
    };
    try std.testing.expectError(error.S256NotSupported, plain.requirePkce());

    const both: Metadata = .{
        .issuer = "https://auth.example.com",
        .code_challenge_methods_supported = &.{ "plain", "S256" },
    };
    try both.requirePkce();
}

test "requirePkce applies to OpenID providers too" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // An OIDC document is not required by its own specification to carry this field,
    // but MCP requires the client to refuse without it regardless.
    const metadata = try parse(
        arena.allocator(),
        "{\"issuer\":\"https://auth.example.com\"," ++
            "\"authorization_endpoint\":\"https://auth.example.com/authorize\"," ++
            "\"token_endpoint\":\"https://auth.example.com/token\"," ++
            "\"subject_types_supported\":[\"public\"]}",
        "https://auth.example.com",
    );
    try std.testing.expectError(error.PkceNotSupported, metadata.requirePkce());
}

test "requiresIssParameter defaults to false when unadvertised" {
    const unset: Metadata = .{ .issuer = "https://auth.example.com" };
    try std.testing.expect(!unset.requiresIssParameter());

    const advertised: Metadata = .{
        .issuer = "https://auth.example.com",
        .authorization_response_iss_parameter_supported = true,
    };
    try std.testing.expect(advertised.requiresIssParameter());
}

test "missing endpoints are named rather than silently absent" {
    const metadata: Metadata = .{ .issuer = "https://auth.example.com" };
    try std.testing.expectError(error.InvalidEndpoint, metadata.authorizationEndpoint());
    try std.testing.expectError(error.InvalidEndpoint, metadata.tokenEndpoint());
}

test "supportedScopes renders a set" {
    const metadata: Metadata = .{
        .issuer = "https://auth.example.com",
        .scopes_supported = &.{ "files:read", "profile" },
    };
    const set = (try metadata.supportedScopes()).?;
    try std.testing.expectEqualStrings("files:read profile", set.value());
}

test "fuzz parse" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            const issuer = "https://auth.example.com";
            const metadata = parse(arena.allocator(), buffer[0..length], issuer) catch return;
            // Nothing can parse without matching the issuer exactly.
            try std.testing.expectEqualStrings(issuer, metadata.issuer);
        }
    }.run, .{});
}
