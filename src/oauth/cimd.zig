//! Client registration: Client ID Metadata Documents, pre-registration, and the
//! deprecated dynamic path — plus the rule for choosing between them.
//!
//! MCP's normal case is a client and a server with no prior relationship, which
//! classic OAuth has no answer for: a `client_id` has to come from somewhere, and
//! registering with every server a user might name does not scale. Client ID Metadata
//! Documents answer it by making the `client_id` an HTTPS URL that *is* the metadata:
//! the authorization server fetches it on demand.
//!
//! ## Why the identifier must contain a path
//!
//! `client_id` **MUST** be `https` and **MUST** have a path component, and the
//! document's own `client_id` **MUST** equal the URL exactly. Together those rules
//! mean one host cannot claim to be another, and cannot claim the whole origin: a
//! document at `https://app.example.com/client.json` speaks for that path and nothing
//! else. `ClientMetadata.validateAt` enforces both.
//!
//! ## Credentials belong to an issuer
//!
//! A `client_id` from pre-registration or dynamic registration is meaningful only at
//! the authorization server that issued it (RFC 6749 Section 2.2). When protected
//! resource metadata starts naming a different issuer, those credentials **MUST NOT**
//! be reused. `Registration.usableAt` is that check. A Client ID Metadata Document is
//! the exception — it is a self-hosted URL any server can resolve, so it is portable.

const std = @import("std");
const assert_mod = @import("assert");

const as_metadata = @import("as_metadata.zig");
const authorize = @import("authorize.zig");
const url = @import("url.zig");

const assert = assert_mod.assert;

/// Upper bound on a client metadata document.
pub const document_bytes_max = 64 * 1024;

/// Upper bound on registered redirect URIs.
pub const redirect_uris_max = 16;

pub const ValidateError = error{
    /// `client_id` is not an HTTPS URL, or has no path component.
    InvalidClientId,
    /// The document's `client_id` is not the URL it was served from. One host would
    /// otherwise be able to publish a document claiming another's identity.
    ClientIdMismatch,
    /// `client_name` is absent or empty.
    MissingClientName,
    /// `redirect_uris` is absent or empty.
    MissingRedirectUris,
    /// More than `redirect_uris_max` entries.
    TooManyRedirectUris,
    /// A redirect URI is neither loopback nor HTTPS.
    InvalidRedirectUri,
    /// A URL-valued field is not a valid absolute URL.
    InvalidUrl,
};

pub const ParseError = ValidateError || error{
    DocumentTooLarge,
    Malformed,
    OutOfMemory,
};

/// A Client ID Metadata Document.
///
/// Field names are the wire names, which are the RFC 7591 client metadata names.
pub const ClientMetadata = struct {
    /// The HTTPS URL this document is served from, repeated inside it.
    client_id: []const u8,
    /// Shown to the user during authorization. Required.
    client_name: []const u8,
    /// Where authorization responses may be delivered. Required and non-empty; an
    /// authorization server validates the request's `redirect_uri` against these.
    redirect_uris: []const []const u8,
    client_uri: ?[]const u8 = null,
    logo_uri: ?[]const u8 = null,
    tos_uri: ?[]const u8 = null,
    policy_uri: ?[]const u8 = null,
    /// Include `refresh_token` here to ask for refresh tokens.
    grant_types: ?[]const []const u8 = null,
    response_types: ?[]const []const u8 = null,
    /// `none` for a public client, which is what a client using PKCE without a secret
    /// is.
    token_endpoint_auth_method: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    /// For `private_key_jwt` client authentication, which this module does not
    /// perform but a caller may.
    jwks_uri: ?[]const u8 = null,
    /// OIDC dynamic registration constrains redirect URIs by this. `native` covers
    /// desktop, CLI, and anything using a loopback redirect.
    application_type: ?[]const u8 = null,

    /// Structural checks that do not need to know the document's URL.
    pub fn validate(metadata: *const ClientMetadata) ValidateError!void {
        try validateClientId(metadata.client_id);

        if (metadata.client_name.len == 0) return error.MissingClientName;
        if (metadata.redirect_uris.len == 0) return error.MissingRedirectUris;
        if (metadata.redirect_uris.len > redirect_uris_max) return error.TooManyRedirectUris;
        for (metadata.redirect_uris) |redirect_uri| {
            authorize.validateRedirectUri(redirect_uri) catch return error.InvalidRedirectUri;
        }

        const urls = [_]?[]const u8{
            metadata.client_uri,
            metadata.logo_uri,
            metadata.tos_uri,
            metadata.policy_uri,
            metadata.jwks_uri,
        };
        for (urls) |value| {
            _ = url.parse(value orelse continue) catch return error.InvalidUrl;
        }
    }

    /// Full validation, including that the document belongs at `document_url`.
    ///
    /// This is what an authorization server performs, and what a client should run
    /// against its own document before publishing it — a mismatch is rejected at
    /// authorization time, which is a confusing place to discover a typo.
    pub fn validateAt(
        metadata: *const ClientMetadata,
        document_url: []const u8,
    ) ValidateError!void {
        try metadata.validate();
        // Exact comparison. Anything looser would let a document be served from one
        // URL while claiming another.
        if (!std.mem.eql(u8, metadata.client_id, document_url)) return error.ClientIdMismatch;
    }

    /// True if the document asks for refresh tokens.
    pub fn wantsRefreshTokens(metadata: *const ClientMetadata) bool {
        const grants = metadata.grant_types orelse return false;
        for (grants) |grant| {
            if (std.mem.eql(u8, grant, "refresh_token")) return true;
        }
        return false;
    }

    /// True if `redirect_uri` is one this document registers.
    pub fn allowsRedirect(metadata: *const ClientMetadata, redirect_uri: []const u8) bool {
        for (metadata.redirect_uris) |registered| {
            // Exact match. Prefix matching is how open redirection gets introduced.
            if (std.mem.eql(u8, registered, redirect_uri)) return true;
        }
        return false;
    }

    pub fn render(metadata: *const ClientMetadata, gpa: std.mem.Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(gpa, metadata.*, .{
            .emit_null_optional_fields = false,
        });
    }
};

/// Checks a Client ID Metadata Document identifier.
pub fn validateClientId(client_id: []const u8) ValidateError!void {
    if (client_id.len == 0) return error.InvalidClientId;
    const parts = url.parse(client_id) catch return error.InvalidClientId;
    // HTTPS with no exception, not even loopback: an authorization server on the
    // internet has to fetch this, and a client identity delivered over plain http is
    // one an on-path attacker chooses.
    if (!parts.isHttps()) return error.InvalidClientId;
    // A path component is required, so that an identifier names a specific client
    // rather than an entire origin.
    if (!parts.hasPathComponent()) return error.InvalidClientId;
    if (parts.fragment != null) return error.InvalidClientId;
    return;
}

/// Parses a Client ID Metadata Document and checks it belongs at `document_url`.
pub fn parse(
    arena: std.mem.Allocator,
    bytes: []const u8,
    document_url: []const u8,
) ParseError!ClientMetadata {
    if (bytes.len > document_bytes_max) return error.DocumentTooLarge;

    const metadata = std.json.parseFromSliceLeaky(ClientMetadata, arena, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };

    try metadata.validateAt(document_url);
    return metadata;
}

/// How a client identifies itself.
pub const Registration = union(enum) {
    /// Credentials arranged out of band, valid only at `issuer`.
    pre_registered: PreRegistered,
    /// A self-hosted metadata document URL. Portable across authorization servers.
    client_id_metadata_document: []const u8,
    /// Obtained from an authorization server's registration endpoint. Deprecated, and
    /// valid only at the issuer that granted it.
    dynamic: PreRegistered,

    pub const PreRegistered = struct {
        client_id: []const u8,
        /// Absent for a public client.
        client_secret: ?[]const u8 = null,
        /// The issuer these credentials belong to. Present so that reuse against a
        /// different authorization server is detectable rather than accidental.
        issuer: []const u8,
    };

    pub fn clientId(registration: Registration) []const u8 {
        return switch (registration) {
            .pre_registered, .dynamic => |credentials| credentials.client_id,
            .client_id_metadata_document => |document_url| document_url,
        };
    }

    /// True if this registration may be used with `issuer`.
    ///
    /// A metadata document is always usable: it is resolved by whichever server is
    /// asked, so it carries no issuer binding. Everything else is bound, and using it
    /// elsewhere means presenting an identifier the server never issued.
    pub fn usableAt(registration: Registration, issuer: []const u8) bool {
        return switch (registration) {
            .pre_registered, .dynamic => |credentials| std.mem.eql(u8, credentials.issuer, issuer),
            .client_id_metadata_document => true,
        };
    }

    /// The token endpoint authentication this registration implies.
    pub fn auth(registration: Registration) Auth {
        return switch (registration) {
            .pre_registered, .dynamic => |credentials| if (credentials.client_secret) |secret|
                .{ .secret_basic = secret }
            else
                .none,
            // A document-identified client is public: the document is world-readable,
            // so it cannot contain a secret.
            .client_id_metadata_document => .none,
        };
    }

    const Auth = @import("token.zig").ClientAuth;
};

/// What a caller has available to identify itself with.
pub const Available = struct {
    /// Credentials already held for the issuer in question.
    pre_registered: ?Registration.PreRegistered = null,
    /// The caller's own hosted metadata document URL.
    client_id_metadata_document: ?[]const u8 = null,
    /// Whether the caller is willing to perform dynamic registration.
    allow_dynamic: bool = false,
};

pub const ChooseError = error{
    /// Nothing available works with this authorization server. The caller has to
    /// obtain a client id some other way — in practice, by asking the user.
    NoUsableRegistration,
};

/// Picks a registration mechanism, in the priority order the specification defines.
///
///   1. pre-registered credentials for *this* issuer, if held
///   2. a Client ID Metadata Document, if the server resolves them
///   3. dynamic registration, if the server offers it and the caller permits it
///   4. otherwise: ask the user
///
/// Pre-registration comes first because it is the strongest statement of intent: a
/// deployment that arranged credentials for this server meant to use them. Held
/// credentials for a *different* issuer are skipped rather than tried — the
/// specification requires surfacing an error instead of silently attempting a
/// mismatch.
pub fn choose(
    metadata: *const as_metadata.Metadata,
    available: Available,
) ChooseError!Registration {
    if (available.pre_registered) |credentials| {
        if (std.mem.eql(u8, credentials.issuer, metadata.issuer)) {
            return .{ .pre_registered = credentials };
        }
    }

    if (available.client_id_metadata_document) |document_url| {
        if (metadata.supportsClientIdMetadataDocument()) {
            return .{ .client_id_metadata_document = document_url };
        }
    }

    if (available.allow_dynamic and metadata.supportsDynamicRegistration()) {
        // Signalled rather than performed: registration is a request the caller must
        // make, and its result is a credential the caller must store keyed by issuer.
        return .{ .dynamic = .{ .client_id = "", .issuer = metadata.issuer } };
    }

    return error.NoUsableRegistration;
}

/// A dynamic client registration request body (RFC 7591).
///
/// Deprecated in MCP and retained for authorization servers that do not resolve
/// Client ID Metadata Documents.
pub const DynamicRequest = struct {
    client_name: []const u8,
    redirect_uris: []const []const u8,
    grant_types: []const []const u8 = &.{"authorization_code"},
    response_types: []const []const u8 = &.{"code"},
    token_endpoint_auth_method: []const u8 = "none",
    /// Must be set explicitly. Omitting it defaults to `web` under OIDC, which
    /// rejects the loopback redirect URIs a desktop or CLI client needs — a failure
    /// that reads as "registration refused" with no indication why.
    application_type: []const u8,
    scope: ?[]const u8 = null,

    pub fn render(request: *const DynamicRequest, arena: std.mem.Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(arena, request.*, .{
            .emit_null_optional_fields = false,
        });
    }
};

/// The `application_type` for a client using loopback redirects: desktop apps, mobile
/// apps, CLI tools, and locally hosted web apps.
pub const application_type_native = "native";

/// The `application_type` for a remotely hosted browser application.
pub const application_type_web = "web";

/// A dynamic registration response.
pub const DynamicResponse = struct {
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    client_id_issued_at: ?i64 = null,
    client_secret_expires_at: ?i64 = null,

    /// Binds the returned credentials to the issuer that granted them.
    pub fn registration(
        response: *const DynamicResponse,
        issuer: []const u8,
    ) Registration {
        return .{ .dynamic = .{
            .client_id = response.client_id,
            .client_secret = response.client_secret,
            .issuer = issuer,
        } };
    }

    pub fn parse(arena: std.mem.Allocator, bytes: []const u8) ParseError!DynamicResponse {
        if (bytes.len > document_bytes_max) return error.DocumentTooLarge;
        const response = std.json.parseFromSliceLeaky(DynamicResponse, arena, bytes, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Malformed,
        };
        if (response.client_id.len == 0) return error.Malformed;
        return response;
    }
};

const test_document_url = "https://app.example.com/oauth/client-metadata.json";

fn testMetadata() ClientMetadata {
    return .{
        .client_id = test_document_url,
        .client_name = "Example MCP Client",
        .redirect_uris = &.{ "http://127.0.0.1:3000/callback", "http://localhost:3000/callback" },
        .grant_types = &.{ "authorization_code", "refresh_token" },
        .response_types = &.{"code"},
        .token_endpoint_auth_method = "none",
    };
}

test "validateClientId requires https with a path" {
    try validateClientId("https://example.com/client.json");
    try validateClientId("https://example.com/a/b/c");

    try std.testing.expectError(error.InvalidClientId, validateClientId(""));
    try std.testing.expectError(error.InvalidClientId, validateClientId("http://example.com/c.json"));
    // No path means claiming a whole origin rather than one client.
    try std.testing.expectError(error.InvalidClientId, validateClientId("https://example.com"));
    try std.testing.expectError(error.InvalidClientId, validateClientId("https://example.com/"));
    try std.testing.expectError(error.InvalidClientId, validateClientId("https://example.com/c#f"));
    try std.testing.expectError(error.InvalidClientId, validateClientId("example.com/c.json"));
    // Loopback is not exempt here: an authorization server on the internet must be
    // able to fetch this document.
    try std.testing.expectError(
        error.InvalidClientId,
        validateClientId("http://localhost:3000/client.json"),
    );
}

test "validateAt requires the document to match its URL exactly" {
    const metadata = testMetadata();
    try metadata.validateAt(test_document_url);

    // The attack the rule exists for: a document served from one place asserting
    // another client's identity.
    try std.testing.expectError(
        error.ClientIdMismatch,
        metadata.validateAt("https://attacker.example/client.json"),
    );
    // Even a trailing slash is a different URL.
    try std.testing.expectError(
        error.ClientIdMismatch,
        metadata.validateAt(test_document_url ++ "/"),
    );
}

test "validate requires client_name and redirect_uris" {
    var metadata = testMetadata();

    metadata.client_name = "";
    try std.testing.expectError(error.MissingClientName, metadata.validate());

    metadata = testMetadata();
    metadata.redirect_uris = &.{};
    try std.testing.expectError(error.MissingRedirectUris, metadata.validate());
}

test "validate rejects an insecure redirect uri" {
    var metadata = testMetadata();
    metadata.redirect_uris = &.{"http://app.example.com/callback"};
    try std.testing.expectError(error.InvalidRedirectUri, metadata.validate());
}

test "validate bounds the redirect uri count" {
    var metadata = testMetadata();
    var uris: [redirect_uris_max + 1][]const u8 = undefined;
    for (&uris) |*entry| entry.* = "https://app.example.com/cb";
    metadata.redirect_uris = &uris;
    try std.testing.expectError(error.TooManyRedirectUris, metadata.validate());
}

test "validate rejects a malformed auxiliary url" {
    var metadata = testMetadata();
    metadata.logo_uri = "not-a-url";
    try std.testing.expectError(error.InvalidUrl, metadata.validate());
}

test "parse reads the document from the specification example" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const metadata = try parse(arena.allocator(),
        \\{
        \\  "client_id": "https://app.example.com/oauth/client-metadata.json",
        \\  "client_name": "Example MCP Client",
        \\  "client_uri": "https://app.example.com",
        \\  "logo_uri": "https://app.example.com/logo.png",
        \\  "redirect_uris": [
        \\    "http://127.0.0.1:3000/callback",
        \\    "http://localhost:3000/callback"
        \\  ],
        \\  "grant_types": ["authorization_code"],
        \\  "response_types": ["code"],
        \\  "token_endpoint_auth_method": "none"
        \\}
    , test_document_url);

    try std.testing.expectEqualStrings("Example MCP Client", metadata.client_name);
    try std.testing.expectEqual(@as(usize, 2), metadata.redirect_uris.len);
    try std.testing.expect(metadata.allowsRedirect("http://127.0.0.1:3000/callback"));
    try std.testing.expect(!metadata.wantsRefreshTokens());
}

test "parse rejects a document that does not belong at the url" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.ClientIdMismatch, parse(
        arena.allocator(),
        "{\"client_id\":\"https://honest.example/c.json\",\"client_name\":\"n\"," ++
            "\"redirect_uris\":[\"https://honest.example/cb\"]}",
        "https://attacker.example/c.json",
    ));
}

test "parse rejects malformed and oversized documents" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "{}", test_document_url));
    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "[]", test_document_url));

    const big = try arena.allocator().alloc(u8, document_bytes_max + 1);
    @memset(big, ' ');
    try std.testing.expectError(
        error.DocumentTooLarge,
        parse(arena.allocator(), big, test_document_url),
    );
}

test "allowsRedirect matches exactly" {
    const metadata = testMetadata();
    try std.testing.expect(metadata.allowsRedirect("http://127.0.0.1:3000/callback"));
    // Prefix or suffix tolerance here is how open redirection is introduced.
    try std.testing.expect(!metadata.allowsRedirect("http://127.0.0.1:3000/callback/evil"));
    try std.testing.expect(!metadata.allowsRedirect("http://127.0.0.1:3000/"));
    try std.testing.expect(!metadata.allowsRedirect("http://127.0.0.1:3001/callback"));
}

test "a rendered document round-trips" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const original = testMetadata();
    const rendered = try original.render(arena.allocator());
    const parsed = try parse(arena.allocator(), rendered, test_document_url);
    try std.testing.expectEqualStrings(original.client_name, parsed.client_name);
    try std.testing.expect(parsed.wantsRefreshTokens());
    try std.testing.expect(std.mem.indexOf(u8, rendered, "jwks_uri") == null);
}

fn asMetadata(options: struct { cimd: bool = false, registration: bool = false }) as_metadata.Metadata {
    return .{
        .issuer = "https://auth.example.com",
        .client_id_metadata_document_supported = if (options.cimd) true else null,
        .registration_endpoint = if (options.registration) "https://auth.example.com/register" else null,
    };
}

test "choose prefers pre-registered credentials for this issuer" {
    const metadata = asMetadata(.{ .cimd = true, .registration = true });
    const registration = try choose(&metadata, .{
        .pre_registered = .{ .client_id = "c1", .issuer = "https://auth.example.com" },
        .client_id_metadata_document = test_document_url,
        .allow_dynamic = true,
    });
    try std.testing.expectEqualStrings("c1", registration.clientId());
    try std.testing.expectEqual(Registration.pre_registered, std.meta.activeTag(registration));
}

test "choose skips credentials belonging to another issuer" {
    const metadata = asMetadata(.{ .cimd = true });
    const registration = try choose(&metadata, .{
        // Registered elsewhere. Presenting it here would be an identifier this server
        // never issued.
        .pre_registered = .{ .client_id = "c1", .issuer = "https://other-auth.example" },
        .client_id_metadata_document = test_document_url,
    });
    try std.testing.expectEqual(
        Registration.client_id_metadata_document,
        std.meta.activeTag(registration),
    );
    try std.testing.expectEqualStrings(test_document_url, registration.clientId());
}

test "choose falls back to dynamic registration only when nothing better exists" {
    // The server does not resolve metadata documents, so the deprecated path is all
    // that is left.
    const metadata = asMetadata(.{ .registration = true });
    const registration = try choose(&metadata, .{
        .client_id_metadata_document = test_document_url,
        .allow_dynamic = true,
    });
    try std.testing.expectEqual(Registration.dynamic, std.meta.activeTag(registration));
}

test "choose refuses rather than guessing when nothing is usable" {
    const bare = asMetadata(.{});
    try std.testing.expectError(error.NoUsableRegistration, choose(&bare, .{}));
    // A metadata document the server will not resolve is not a usable option.
    try std.testing.expectError(error.NoUsableRegistration, choose(&bare, .{
        .client_id_metadata_document = test_document_url,
    }));
    // Dynamic registration the caller did not permit is not one either.
    const registering = asMetadata(.{ .registration = true });
    try std.testing.expectError(error.NoUsableRegistration, choose(&registering, .{}));
}

test "usableAt binds credentials to their issuer but not documents" {
    const bound: Registration = .{
        .pre_registered = .{ .client_id = "c", .issuer = "https://auth.example.com" },
    };
    try std.testing.expect(bound.usableAt("https://auth.example.com"));
    try std.testing.expect(!bound.usableAt("https://other.example"));

    const dynamic: Registration = .{
        .dynamic = .{ .client_id = "c", .issuer = "https://auth.example.com" },
    };
    try std.testing.expect(!dynamic.usableAt("https://other.example"));

    // A self-hosted document is resolved by whichever server is asked, so it is
    // portable and needs no re-registration when the authorization server changes.
    const portable: Registration = .{ .client_id_metadata_document = test_document_url };
    try std.testing.expect(portable.usableAt("https://auth.example.com"));
    try std.testing.expect(portable.usableAt("https://other.example"));
}

test "registration implies its token endpoint authentication" {
    const public: Registration = .{ .client_id_metadata_document = test_document_url };
    try std.testing.expectEqualStrings("none", public.auth().method());

    const confidential: Registration = .{ .pre_registered = .{
        .client_id = "c",
        .client_secret = "s",
        .issuer = "https://auth.example.com",
    } };
    try std.testing.expectEqualStrings("client_secret_basic", confidential.auth().method());

    const public_pre: Registration = .{ .pre_registered = .{
        .client_id = "c",
        .issuer = "https://auth.example.com",
    } };
    try std.testing.expectEqualStrings("none", public_pre.auth().method());
}

test "DynamicRequest requires an explicit application_type" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const request: DynamicRequest = .{
        .client_name = "Example",
        .redirect_uris = &.{"http://127.0.0.1:3000/callback"},
        .application_type = application_type_native,
    };
    const rendered = try request.render(arena.allocator());
    // Without `native`, an OIDC server defaults to `web` and rejects the loopback
    // redirect this client needs.
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"application_type\":\"native\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"scope\"") == null);
}

test "DynamicResponse binds the credentials it returns to the issuer" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const response = try DynamicResponse.parse(
        arena.allocator(),
        "{\"client_id\":\"generated-1\",\"client_secret\":\"s3cr3t\",\"client_id_issued_at\":1700000000}",
    );
    const registration = response.registration("https://auth.example.com");
    try std.testing.expectEqualStrings("generated-1", registration.clientId());
    try std.testing.expect(registration.usableAt("https://auth.example.com"));
    try std.testing.expect(!registration.usableAt("https://other.example"));
    try std.testing.expectEqualStrings("client_secret_basic", registration.auth().method());
}

test "DynamicResponse rejects a response without a client id" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        error.Malformed,
        DynamicResponse.parse(arena.allocator(), "{}"),
    );
    try std.testing.expectError(
        error.Malformed,
        DynamicResponse.parse(arena.allocator(), "{\"client_id\":\"\"}"),
    );
}

test "fuzz parse" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            const metadata = parse(
                arena.allocator(),
                buffer[0..length],
                test_document_url,
            ) catch return;
            // Nothing parses without matching the URL exactly and naming a redirect.
            try std.testing.expectEqualStrings(test_document_url, metadata.client_id);
            try std.testing.expect(metadata.redirect_uris.len > 0);
        }
    }.run, .{});
}
