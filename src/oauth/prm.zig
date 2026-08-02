//! Protected Resource Metadata (RFC 9728): the document by which a resource server
//! tells clients where its authorization servers are.
//!
//! An MCP server **MUST** publish this document, and an MCP client **MUST** use it
//! for authorization server discovery. It is the only supported way for a client
//! that has never seen a server before to find out who issues tokens for it.
//!
//! Both directions live here. The field names are the wire names, so `std.json`
//! handles the mechanical part; what this module adds is the validation, which is
//! where the security properties actually live.

const std = @import("std");
const assert_mod = @import("assert");

const url = @import("url.zig");
const scope = @import("scope.zig");

const assert = assert_mod.assert;

/// The well-known URI suffix from RFC 9728 Section 3.
pub const well_known_suffix = "oauth-protected-resource";

/// Upper bound on a metadata document this module will parse.
///
/// The document is fetched from a URL named by a `WWW-Authenticate` header, so its
/// size is chosen by the peer.
pub const document_bytes_max = 256 * 1024;

/// Upper bound on entries in any list-valued field.
pub const list_max = 64;

pub const ValidateError = error{
    /// `resource` was absent, empty, or not a canonical resource URI.
    InvalidResource,
    /// `authorization_servers` was absent or empty. RFC 9728 makes the field
    /// optional; MCP requires at least one entry, because a client with no issuer
    /// has nowhere to go.
    NoAuthorizationServers,
    /// An issuer in `authorization_servers` is not a valid issuer identifier.
    InvalidIssuer,
    /// A URL-valued field was not a valid absolute URL.
    InvalidUrl,
    /// A list-valued field exceeded `list_max`.
    TooManyEntries,
    /// A scope in `scopes_supported` is not a valid scope token.
    InvalidScope,
};

pub const ParseError = ValidateError || error{
    /// The document exceeded `document_bytes_max`.
    DocumentTooLarge,
    /// The document was not a JSON object, or a field had the wrong type.
    Malformed,
    OutOfMemory,
};

pub const ResourceMatchError = error{
    /// The document's `resource` is not the resource identifier it was fetched for.
    /// RFC 9728 Section 3.3 requires them to be identical; a mismatch means the
    /// document describes some other resource.
    ResourceMismatch,
};

/// An RFC 9728 protected resource metadata document.
///
/// Fields this module does not interpret are still declared, so that a server can
/// publish them and a client can read them back; `signed_metadata` is the one
/// deliberate omission — verifying a signed document requires a trust anchor this
/// module has no way to obtain, and accepting the field while ignoring its
/// signature would be worse than not having it.
pub const ResourceMetadata = struct {
    /// The canonical URI of the protected resource. For MCP this is the canonical
    /// URI of the MCP server, and it is what clients put in the `resource`
    /// parameter and what servers require in the token audience.
    resource: []const u8,
    /// Issuer identifiers of the authorization servers that issue tokens for this
    /// resource. Each is an independent authorization server; a client must keep
    /// registration state per issuer and must not carry credentials across them.
    authorization_servers: []const []const u8 = &.{},
    jwks_uri: ?[]const u8 = null,
    /// The minimal set of scopes needed for basic functionality. Clients fall back
    /// to this when a challenge carries no `scope`.
    ///
    /// `offline_access` should not appear here: refresh tokens are a client
    /// concern, not a requirement of the resource.
    scopes_supported: ?[]const []const u8 = null,
    /// How tokens may be presented. MCP allows only the `Authorization` header,
    /// so this is `["header"]`.
    bearer_methods_supported: ?[]const []const u8 = null,
    resource_signing_alg_values_supported: ?[]const []const u8 = null,
    resource_name: ?[]const u8 = null,
    resource_documentation: ?[]const u8 = null,
    resource_policy_uri: ?[]const u8 = null,
    resource_tos_uri: ?[]const u8 = null,
    tls_client_certificate_bound_access_tokens: ?bool = null,
    authorization_details_types_supported: ?[]const []const u8 = null,
    dpop_signing_alg_values_supported: ?[]const []const u8 = null,
    dpop_bound_access_tokens_required: ?bool = null,

    /// Checks everything this module can check without network access.
    ///
    /// A server should call this once at startup: publishing a document that names
    /// no authorization server, or whose `resource` is not a canonical URI, produces
    /// clients that fail in ways that look like client bugs.
    pub fn validate(metadata: *const ResourceMetadata) ValidateError!void {
        try validateResourceIdentifier(metadata.resource);

        if (metadata.authorization_servers.len == 0) return error.NoAuthorizationServers;
        if (metadata.authorization_servers.len > list_max) return error.TooManyEntries;
        for (metadata.authorization_servers) |issuer| {
            validateIssuer(issuer) catch return error.InvalidIssuer;
        }

        const url_fields = [_]?[]const u8{
            metadata.jwks_uri,
            metadata.resource_documentation,
            metadata.resource_policy_uri,
            metadata.resource_tos_uri,
        };
        for (url_fields) |field| {
            const value = field orelse continue;
            _ = url.parse(value) catch return error.InvalidUrl;
        }

        const lists = [_]?[]const []const u8{
            metadata.bearer_methods_supported,
            metadata.resource_signing_alg_values_supported,
            metadata.authorization_details_types_supported,
            metadata.dpop_signing_alg_values_supported,
        };
        for (lists) |list| {
            if ((list orelse continue).len > list_max) return error.TooManyEntries;
        }

        if (metadata.scopes_supported) |scopes| {
            if (scopes.len > list_max) return error.TooManyEntries;
            for (scopes) |token| {
                if (!scope.validToken(token)) return error.InvalidScope;
            }
        }
    }

    /// True if tokens may be presented in the `Authorization` header.
    ///
    /// An absent `bearer_methods_supported` means the resource did not say, and
    /// RFC 6750 makes the header the default, so absence is a yes.
    pub fn allowsHeaderBearer(metadata: *const ResourceMetadata) bool {
        const methods = metadata.bearer_methods_supported orelse return true;
        for (methods) |method| {
            if (std.mem.eql(u8, method, "header")) return true;
        }
        return false;
    }

    /// The `scopes_supported` value rendered as a scope string, or null when the
    /// field is absent. Clients use this only when a challenge carried no `scope`.
    pub fn supportedScopes(metadata: *const ResourceMetadata) scope.Error!?scope.Set {
        const scopes = metadata.scopes_supported orelse return null;
        var set: scope.Set = .{};
        for (scopes) |token| try set.add(token);
        return set;
    }

    /// Verifies the document describes the resource it was fetched for
    /// (RFC 9728 Section 3.3).
    ///
    /// The comparison is byte-exact. This is the check that stops a document served
    /// from one origin from claiming to describe a resource on another.
    pub fn matchesResource(
        metadata: *const ResourceMetadata,
        expected: []const u8,
    ) ResourceMatchError!void {
        if (!std.mem.eql(u8, metadata.resource, expected)) return error.ResourceMismatch;
    }

    /// Serializes the document.
    pub fn render(metadata: *const ResourceMetadata, gpa: std.mem.Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(gpa, metadata.*, stringify_options);
    }

    pub fn write(
        metadata: *const ResourceMetadata,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        std.json.Stringify.value(metadata.*, stringify_options, writer) catch |err| switch (err) {
            error.WriteFailed => return error.WriteFailed,
        };
    }
};

const stringify_options: std.json.Stringify.Options = .{ .emit_null_optional_fields = false };

/// Parses and validates a metadata document.
///
/// Unknown fields are ignored: RFC 9728 defines a registry and deployments add to
/// it, so a client that rejected unknown members would break on the first server
/// that adopted a new one.
pub fn parse(arena: std.mem.Allocator, bytes: []const u8) ParseError!ResourceMetadata {
    if (bytes.len > document_bytes_max) return error.DocumentTooLarge;

    const metadata = std.json.parseFromSliceLeaky(
        ResourceMetadata,
        arena,
        bytes,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };

    try metadata.validate();
    return metadata;
}

pub const ResourceIdentifierError = error{InvalidResource};

/// Checks a canonical resource URI, per RFC 8707 Section 2 as narrowed by MCP.
///
/// Absolute URI, no fragment. A trailing slash is accepted but is not the form to
/// publish: the specification asks for consistency without the slash, and because
/// every downstream comparison is byte-exact, a server that publishes one form and
/// validates the other rejects its own clients.
pub fn validateResourceIdentifier(resource: []const u8) ResourceIdentifierError!void {
    if (resource.len == 0) return error.InvalidResource;
    const parts = url.parse(resource) catch return error.InvalidResource;
    if (parts.fragment != null) return error.InvalidResource;
    if (parts.query != null) return error.InvalidResource;
}

pub const IssuerError = error{InvalidIssuer};

/// Checks an issuer identifier, per RFC 8414 Section 2.
///
/// An issuer identifier is an HTTPS URL with no query and no fragment. HTTPS is
/// required rather than recommended: every authorization server endpoint **MUST**
/// be served over HTTPS, and an `http` issuer would mean discovering endpoints over
/// a channel an attacker can rewrite. Loopback is exempt so that local development
/// and tests are possible without a certificate.
pub fn validateIssuer(issuer: []const u8) IssuerError!void {
    if (issuer.len == 0) return error.InvalidIssuer;
    const parts = url.parse(issuer) catch return error.InvalidIssuer;
    if (parts.query != null) return error.InvalidIssuer;
    if (parts.fragment != null) return error.InvalidIssuer;
    if (!parts.isHttps() and !parts.isLoopback()) return error.InvalidIssuer;
}

/// The number of well-known URL candidates `wellKnownUris` produces.
pub const well_known_candidates = 2;

/// Builds the well-known metadata URLs for a resource, in the order a client must
/// try them.
///
/// RFC 9728 defines path insertion; MCP additionally allows the document at the
/// root, and requires clients to try the path-inserted form first. Both are
/// returned because a client that guessed only one would fail against
/// half of all deployments:
///
///   * `https://example.com/.well-known/oauth-protected-resource/public/mcp`
///   * `https://example.com/.well-known/oauth-protected-resource`
///
/// These are only the fallback. A `resource_metadata` parameter in a
/// `WWW-Authenticate` challenge takes precedence and must be used as given.
pub fn wellKnownUris(
    arena: std.mem.Allocator,
    resource: []const u8,
) (ResourceIdentifierError || error{OutOfMemory})![well_known_candidates][]const u8 {
    try validateResourceIdentifier(resource);
    const parts = url.parse(resource) catch return error.InvalidResource;

    const inserted = url.wellKnownInserted(arena, &parts, well_known_suffix) catch
        return error.OutOfMemory;
    // With no path component the inserted form already *is* the root form. Emitting
    // it twice is honest about the candidate count and costs one duplicate request
    // only in the case where the first attempt already succeeded.
    var root_parts = parts;
    root_parts.path = "";
    const root = url.wellKnownInserted(arena, &root_parts, well_known_suffix) catch
        return error.OutOfMemory;

    return .{ inserted, root };
}

/// True if `metadata_url` is on the same origin as `resource`.
///
/// Worth checking when the metadata URL came from a `WWW-Authenticate` header: that
/// header is chosen by whoever answered the request, so a compromised or
/// impersonating server can point a client at a metadata document of its choosing,
/// and from there at an authorization server of its choosing. Same-origin is not a
/// complete defense — the audience-restricted token is what ultimately protects the
/// resource — but it removes the cheapest version of the attack.
pub fn sameOrigin(metadata_url: []const u8, resource: []const u8) bool {
    const a = url.parse(metadata_url) catch return false;
    const b = url.parse(resource) catch return false;
    if (a.scheme != b.scheme) return false;
    if (!std.ascii.eqlIgnoreCase(a.host, b.host)) return false;
    const a_port = a.port orelse url.defaultPort(a.scheme);
    const b_port = b.port orelse url.defaultPort(b.scheme);
    return a_port == b_port;
}

test "validateResourceIdentifier accepts the canonical forms" {
    try validateResourceIdentifier("https://mcp.example.com/mcp");
    try validateResourceIdentifier("https://mcp.example.com");
    try validateResourceIdentifier("https://mcp.example.com:8443");
    try validateResourceIdentifier("https://mcp.example.com/server/mcp");
    // Uppercase scheme and host are accepted for interoperability.
    try validateResourceIdentifier("HTTPS://MCP.example.com/mcp");
    // http is allowed here: the resource identifier is not an authorization server
    // endpoint, and local MCP servers over plain http are a real deployment.
    try validateResourceIdentifier("http://127.0.0.1:8787/mcp");
}

test "validateResourceIdentifier rejects the forms the spec calls invalid" {
    try std.testing.expectError(error.InvalidResource, validateResourceIdentifier(""));
    try std.testing.expectError(error.InvalidResource, validateResourceIdentifier("mcp.example.com"));
    try std.testing.expectError(
        error.InvalidResource,
        validateResourceIdentifier("https://mcp.example.com#fragment"),
    );
    try std.testing.expectError(
        error.InvalidResource,
        validateResourceIdentifier("https://mcp.example.com?a=b"),
    );
}

test "validateIssuer requires https outside loopback" {
    try validateIssuer("https://auth.example.com");
    try validateIssuer("https://auth.example.com/tenant1");
    try validateIssuer("http://localhost:9000");
    try validateIssuer("http://127.0.0.1:9000/realm");

    try std.testing.expectError(error.InvalidIssuer, validateIssuer("http://auth.example.com"));
    try std.testing.expectError(error.InvalidIssuer, validateIssuer("https://auth.example.com?a=b"));
    try std.testing.expectError(error.InvalidIssuer, validateIssuer("https://auth.example.com#f"));
    try std.testing.expectError(error.InvalidIssuer, validateIssuer("auth.example.com"));
    try std.testing.expectError(error.InvalidIssuer, validateIssuer(""));
}

test "wellKnownUris produces the path-inserted form first" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const uris = try wellKnownUris(arena.allocator(), "https://example.com/public/mcp");
    try std.testing.expectEqualStrings(
        "https://example.com/.well-known/oauth-protected-resource/public/mcp",
        uris[0],
    );
    try std.testing.expectEqualStrings(
        "https://example.com/.well-known/oauth-protected-resource",
        uris[1],
    );
}

test "wellKnownUris on a path-less resource yields the root form twice" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const uris = try wellKnownUris(arena.allocator(), "https://example.com");
    try std.testing.expectEqualStrings(
        "https://example.com/.well-known/oauth-protected-resource",
        uris[0],
    );
    try std.testing.expectEqualStrings(uris[0], uris[1]);
}

test "wellKnownUris keeps a non-default port" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const uris = try wellKnownUris(arena.allocator(), "http://127.0.0.1:8787/mcp");
    try std.testing.expectEqualStrings(
        "http://127.0.0.1:8787/.well-known/oauth-protected-resource/mcp",
        uris[0],
    );
}

test "ResourceMetadata renders the minimal MCP document" {
    const metadata: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    try metadata.validate();

    const rendered = try metadata.render(std.testing.allocator);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "{\"resource\":\"https://mcp.example.com/mcp\"," ++
            "\"authorization_servers\":[\"https://auth.example.com\"]}",
        rendered,
    );
}

test "ResourceMetadata omits absent optional fields" {
    const metadata: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
        .scopes_supported = &.{ "files:read", "files:write" },
        .bearer_methods_supported = &.{"header"},
        .resource_name = "Example MCP Server",
    };
    const rendered = try metadata.render(std.testing.allocator);
    defer std.testing.allocator.free(rendered);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "jwks_uri") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"scopes_supported\":[\"files:read\",\"files:write\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"bearer_methods_supported\":[\"header\"]") != null);
}

test "validate rejects a document naming no authorization server" {
    const metadata: ResourceMetadata = .{ .resource = "https://mcp.example.com/mcp" };
    try std.testing.expectError(error.NoAuthorizationServers, metadata.validate());
}

test "validate rejects an http issuer" {
    const metadata: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"http://auth.example.com"},
    };
    try std.testing.expectError(error.InvalidIssuer, metadata.validate());
}

test "validate rejects a malformed scope" {
    const metadata: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
        .scopes_supported = &.{"has space"},
    };
    try std.testing.expectError(error.InvalidScope, metadata.validate());
}

test "validate rejects a bad jwks_uri" {
    const metadata: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
        .jwks_uri = "not-a-url",
    };
    try std.testing.expectError(error.InvalidUrl, metadata.validate());
}

test "parse reads a document and ignores unknown fields" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const metadata = try parse(arena.allocator(),
        \\{
        \\  "resource": "https://mcp.example.com/mcp",
        \\  "authorization_servers": ["https://auth.example.com/tenant1"],
        \\  "scopes_supported": ["files:read"],
        \\  "bearer_methods_supported": ["header"],
        \\  "a_field_from_a_future_registry_entry": {"nested": true}
        \\}
    );
    try std.testing.expectEqualStrings("https://mcp.example.com/mcp", metadata.resource);
    try std.testing.expectEqual(@as(usize, 1), metadata.authorization_servers.len);
    try std.testing.expectEqualStrings(
        "https://auth.example.com/tenant1",
        metadata.authorization_servers[0],
    );
    try std.testing.expect(metadata.allowsHeaderBearer());
}

test "parse enforces the MCP requirement of at least one issuer" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.NoAuthorizationServers, parse(
        arena.allocator(),
        "{\"resource\":\"https://mcp.example.com/mcp\",\"authorization_servers\":[]}",
    ));
}

test "parse rejects a document that is not an object or lacks resource" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "[]"));
    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "{}"));
    try std.testing.expectError(error.Malformed, parse(arena.allocator(), "not json"));
    try std.testing.expectError(
        error.Malformed,
        parse(arena.allocator(), "{\"resource\":123,\"authorization_servers\":[\"https://a.example\"]}"),
    );
}

test "parse bounds the document size" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const big = try arena.allocator().alloc(u8, document_bytes_max + 1);
    @memset(big, ' ');
    try std.testing.expectError(error.DocumentTooLarge, parse(arena.allocator(), big));
}

test "matchesResource is byte-exact" {
    const metadata: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    try metadata.matchesResource("https://mcp.example.com/mcp");

    // A document describing a different resource must not be accepted, and neither
    // must one that differs only by normalization the spec forbids applying.
    try std.testing.expectError(
        error.ResourceMismatch,
        metadata.matchesResource("https://mcp.example.com/mcp/"),
    );
    try std.testing.expectError(
        error.ResourceMismatch,
        metadata.matchesResource("https://MCP.example.com/mcp"),
    );
    try std.testing.expectError(
        error.ResourceMismatch,
        metadata.matchesResource("https://evil.example/mcp"),
    );
}

test "allowsHeaderBearer treats absence as permitted and an explicit list as binding" {
    const unset: ResourceMetadata = .{ .resource = "https://a.example", .authorization_servers = &.{"https://b.example"} };
    try std.testing.expect(unset.allowsHeaderBearer());

    const header: ResourceMetadata = .{
        .resource = "https://a.example",
        .authorization_servers = &.{"https://b.example"},
        .bearer_methods_supported = &.{"header"},
    };
    try std.testing.expect(header.allowsHeaderBearer());

    const body_only: ResourceMetadata = .{
        .resource = "https://a.example",
        .authorization_servers = &.{"https://b.example"},
        .bearer_methods_supported = &.{"body"},
    };
    try std.testing.expect(!body_only.allowsHeaderBearer());
}

test "supportedScopes renders a scope set for the fallback path" {
    const metadata: ResourceMetadata = .{
        .resource = "https://a.example",
        .authorization_servers = &.{"https://b.example"},
        .scopes_supported = &.{ "files:read", "profile" },
    };
    const set = (try metadata.supportedScopes()).?;
    try std.testing.expectEqualStrings("files:read profile", set.value());

    const none: ResourceMetadata = .{
        .resource = "https://a.example",
        .authorization_servers = &.{"https://b.example"},
    };
    try std.testing.expectEqual(@as(?scope.Set, null), try none.supportedScopes());
}

test "sameOrigin compares scheme, host, and effective port" {
    try std.testing.expect(sameOrigin(
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        "https://mcp.example.com/mcp",
    ));
    // A default port and its explicit spelling are the same origin, even though
    // they are not the same string.
    try std.testing.expect(sameOrigin(
        "https://mcp.example.com:443/.well-known/oauth-protected-resource",
        "https://mcp.example.com/mcp",
    ));

    try std.testing.expect(!sameOrigin(
        "https://evil.example/.well-known/oauth-protected-resource",
        "https://mcp.example.com/mcp",
    ));
    try std.testing.expect(!sameOrigin(
        "http://mcp.example.com/.well-known/oauth-protected-resource",
        "https://mcp.example.com/mcp",
    ));
    try std.testing.expect(!sameOrigin("garbage", "https://mcp.example.com/mcp"));
}

test "a rendered document round-trips through the parser" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const original: ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{ "https://auth.example.com", "https://backup.example.com" },
        .jwks_uri = "https://mcp.example.com/jwks",
        .scopes_supported = &.{ "files:read", "files:write" },
        .bearer_methods_supported = &.{"header"},
        .resource_name = "Example",
        .tls_client_certificate_bound_access_tokens = false,
    };
    const rendered = try original.render(arena.allocator());
    const parsed = try parse(arena.allocator(), rendered);

    try std.testing.expectEqualStrings(original.resource, parsed.resource);
    try std.testing.expectEqual(@as(usize, 2), parsed.authorization_servers.len);
    try std.testing.expectEqualStrings(original.jwks_uri.?, parsed.jwks_uri.?);
    try std.testing.expectEqualStrings("Example", parsed.resource_name.?);
    try std.testing.expectEqual(false, parsed.tls_client_certificate_bound_access_tokens.?);
}

test "fuzz parse" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            const metadata = parse(arena.allocator(), buffer[0..length]) catch return;
            // Anything that parsed must have survived validation, which means these
            // invariants hold by construction.
            try std.testing.expect(metadata.resource.len > 0);
            try std.testing.expect(metadata.authorization_servers.len > 0);
        }
    }.run, .{});
}
