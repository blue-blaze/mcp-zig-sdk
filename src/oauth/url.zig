//! The URL handling the OAuth discovery RFCs require, and nothing more.
//!
//! Three separate documents in this stack define a rule of the form "insert
//! `/.well-known/<suffix>` between the authority and the path":
//!
//!   * RFC 9728 Section 3.1, for protected resource metadata
//!   * RFC 8414 Section 3.1, for authorization server metadata
//!   * OpenID Connect Discovery 1.0, which instead *appends* the suffix
//!
//! They are close enough to look like one rule and different enough that sharing
//! one buggy implementation would produce a client that discovers nothing.
//!
//! ## Comparison is byte-exact, deliberately
//!
//! Two security checks in this stack are string comparisons: the `issuer` in a
//! metadata document against the issuer used to fetch it, and the `iss` in an
//! authorization response against the recorded issuer. The specification is
//! explicit that these use *simple string comparison* (RFC 3986 Section 6.2.1) and
//! that clients **MUST NOT** apply case folding, default-port elision,
//! trailing-slash, or percent-encoding normalization first. So this module offers
//! no `normalize`: providing one would invite exactly the call that turns a
//! mix-up-attack defense into a formality.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;

/// Upper bound on a URL this module will parse.
pub const bytes_max = 2048;

pub const Error = error{
    /// Not an absolute URL, or the scheme is not one of `http`/`https`.
    InvalidUrl,
    /// Longer than `bytes_max`.
    UrlTooLong,
};

pub const Scheme = enum { http, https };

/// The parts of an absolute HTTP URL this stack needs to reason about.
pub const Parts = struct {
    scheme: Scheme,
    /// Host without brackets for IPv6 literals removed — the brackets are kept, so
    /// that reassembling `authority` is a concatenation rather than a decision.
    host: []const u8,
    /// Explicit port, or null when the scheme default applies. Kept separate from
    /// `host` because RFC 3986 Section 6.2.3 normalization (eliding a default port)
    /// is forbidden before the comparisons this stack performs.
    port: ?u16,
    /// Path including the leading `/`, or empty when the URL had none.
    path: []const u8,
    query: ?[]const u8,
    fragment: ?[]const u8,

    /// `host` plus `:port` when a port was given explicitly.
    pub fn authority(parts: *const Parts, buffer: []u8) []const u8 {
        var writer: std.Io.Writer = .fixed(buffer);
        writer.writeAll(parts.host) catch unreachable;
        if (parts.port) |port| writer.print(":{d}", .{port}) catch unreachable;
        return writer.buffered();
    }

    /// The path with any trailing `/` removed, and empty for a root path.
    ///
    /// This is the "path component" the well-known insertion rules operate on:
    /// `https://as.example.com/tenant1` has one, `https://as.example.com/` does not.
    pub fn pathComponent(parts: *const Parts) []const u8 {
        var path = parts.path;
        while (path.len > 0 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];
        return path;
    }

    pub fn hasPathComponent(parts: *const Parts) bool {
        return parts.pathComponent().len > 0;
    }

    pub fn isHttps(parts: *const Parts) bool {
        return parts.scheme == .https;
    }

    /// True for a host that resolves to this machine by name or literal.
    ///
    /// Used for the two places the specification carves out an HTTPS exception:
    /// redirect URIs (which **MUST** be `localhost` or HTTPS) and local development.
    /// `*.localhost` is included because RFC 6761 reserves the whole TLD for loopback.
    pub fn isLoopback(parts: *const Parts) bool {
        const host = parts.host;
        if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
        if (std.ascii.endsWithIgnoreCase(host, ".localhost")) return true;
        if (std.mem.eql(u8, host, "[::1]")) return true;
        // 127.0.0.0/8 is entirely loopback, so match the whole range rather than
        // just 127.0.0.1. The dotted-quad shape must be verified, or
        // `127.0.0.1.evil.example` would pass on the prefix alone.
        if (std.mem.startsWith(u8, host, "127.")) return isDottedQuad(host);
        return false;
    }
};

/// True for exactly four decimal octets separated by dots.
fn isDottedQuad(host: []const u8) bool {
    var octets: usize = 0;
    var iterator = std.mem.splitScalar(u8, host, '.');
    while (iterator.next()) |octet| {
        octets += 1;
        if (octets > 4) return false;
        if (octet.len == 0 or octet.len > 3) return false;
        _ = std.fmt.parseInt(u8, octet, 10) catch return false;
    }
    return octets == 4;
}

/// Parses an absolute `http`/`https` URL.
pub fn parse(url: []const u8) Error!Parts {
    if (url.len > bytes_max) return error.UrlTooLong;

    var scheme: Scheme = undefined;
    var rest: []const u8 = undefined;
    // Scheme names are case-insensitive (RFC 3986 Section 3.1). Accepting
    // `HTTPS://` is the robustness the specification asks for; it does not license
    // rewriting the string before comparison.
    if (url.len >= 7 and std.ascii.eqlIgnoreCase(url[0..7], "http://")) {
        scheme = .http;
        rest = url[7..];
    } else if (url.len >= 8 and std.ascii.eqlIgnoreCase(url[0..8], "https://")) {
        scheme = .https;
        rest = url[8..];
    } else {
        return error.InvalidUrl;
    }

    // Split off fragment before query: a `?` inside a fragment is part of it.
    var fragment: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '#')) |hash| {
        fragment = rest[hash + 1 ..];
        rest = rest[0..hash];
    }

    var query: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '?')) |mark| {
        query = rest[mark + 1 ..];
        rest = rest[0..mark];
    }

    const authority_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..authority_end];
    const path = rest[authority_end..];
    if (authority.len == 0) return error.InvalidUrl;

    // Userinfo is rejected rather than ignored. `https://evil@honest.example` reads
    // as `honest.example` to a human and connects to `honest.example`, but a
    // metadata document naming either one would compare unequal; refusing the input
    // is the only outcome that cannot surprise.
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return error.InvalidUrl;

    var host = authority;
    var port: ?u16 = null;
    if (authority[0] == '[') {
        // IPv6 literal: the colons inside the brackets are not a port separator.
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidUrl;
        host = authority[0 .. close + 1];
        const after = authority[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return error.InvalidUrl;
            port = std.fmt.parseInt(u16, after[1..], 10) catch return error.InvalidUrl;
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        const digits = authority[colon + 1 ..];
        // An empty port (`host:`) is legal per RFC 3986 and means "default".
        if (digits.len > 0) {
            port = std.fmt.parseInt(u16, digits, 10) catch return error.InvalidUrl;
        }
    }
    if (host.len == 0) return error.InvalidUrl;
    for (host) |byte| {
        if (byte <= 0x20 or byte == 0x7F) return error.InvalidUrl;
    }

    assert(host.len > 0);
    return .{
        .scheme = scheme,
        .host = host,
        .port = port,
        .path = path,
        .query = query,
        .fragment = fragment,
    };
}

/// The default port for a scheme.
pub fn defaultPort(scheme: Scheme) u16 {
    return switch (scheme) {
        .http => 80,
        .https => 443,
    };
}

/// `scheme://authority` for a parsed URL, allocated.
pub fn origin(arena: std.mem.Allocator, parts: *const Parts) ![]u8 {
    var allocating: std.Io.Writer.Allocating = .init(arena);
    errdefer allocating.deinit();
    try allocating.writer.print("{s}://{s}", .{ @tagName(parts.scheme), parts.host });
    if (parts.port) |port| try allocating.writer.print(":{d}", .{port});
    return allocating.toOwnedSlice();
}

/// Builds `scheme://authority/.well-known/<suffix><path>`.
///
/// This is the RFC 8414 Section 3.1 and RFC 9728 Section 3.1 rule: the well-known
/// segment goes *before* the issuer's own path, not after it. For an issuer of
/// `https://as.example.com/tenant1` the result is
/// `https://as.example.com/.well-known/oauth-authorization-server/tenant1`.
pub fn wellKnownInserted(
    arena: std.mem.Allocator,
    parts: *const Parts,
    suffix: []const u8,
) ![]u8 {
    assert(suffix.len > 0);
    assert(suffix[0] != '/');

    var allocating: std.Io.Writer.Allocating = .init(arena);
    errdefer allocating.deinit();
    try allocating.writer.print("{s}://{s}", .{ @tagName(parts.scheme), parts.host });
    if (parts.port) |port| try allocating.writer.print(":{d}", .{port});
    try allocating.writer.print("/.well-known/{s}{s}", .{ suffix, parts.pathComponent() });
    return allocating.toOwnedSlice();
}

/// Builds `scheme://authority<path>/.well-known/<suffix>`.
///
/// This is the OpenID Connect Discovery 1.0 rule, which appends instead. Clients
/// have to try both because the two specifications disagree and deployments follow
/// one or the other.
pub fn wellKnownAppended(
    arena: std.mem.Allocator,
    parts: *const Parts,
    suffix: []const u8,
) ![]u8 {
    assert(suffix.len > 0);
    assert(suffix[0] != '/');

    var allocating: std.Io.Writer.Allocating = .init(arena);
    errdefer allocating.deinit();
    try allocating.writer.print("{s}://{s}", .{ @tagName(parts.scheme), parts.host });
    if (parts.port) |port| try allocating.writer.print(":{d}", .{port});
    try allocating.writer.print("{s}/.well-known/{s}", .{ parts.pathComponent(), suffix });
    return allocating.toOwnedSlice();
}

/// Percent-encodes `value` for use in a query string or form body.
///
/// Encodes everything outside RFC 3986 `unreserved`, which is stricter than
/// necessary but never wrong. Space becomes `%20` rather than `+`: both are
/// accepted in form bodies, but `%20` is also correct in a query string, and one
/// rule is easier to keep right than two.
pub fn encodeComponent(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    for (value) |byte| {
        const unreserved = std.ascii.isAlphanumeric(byte) or
            byte == '-' or byte == '.' or byte == '_' or byte == '~';
        if (unreserved) {
            try writer.writeByte(byte);
        } else {
            try writer.print("%{X:0>2}", .{byte});
        }
    }
}

pub const DecodeError = error{ InvalidEncoding, OutOfMemory };

/// Decodes an `application/x-www-form-urlencoded` component.
///
/// `+` becomes a space here, unlike in `encodeComponent`: this decodes values that
/// other implementations produced, and form encoders do emit `+`.
pub fn decodeComponent(arena: std.mem.Allocator, value: []const u8) DecodeError![]u8 {
    var allocating: std.Io.Writer.Allocating = .init(arena);
    errdefer allocating.deinit();

    var index: usize = 0;
    while (index < value.len) {
        switch (value[index]) {
            '%' => {
                if (index + 2 >= value.len) return error.InvalidEncoding;
                const hex = value[index + 1 ..][0..2];
                const byte = std.fmt.parseInt(u8, hex, 16) catch return error.InvalidEncoding;
                allocating.writer.writeByte(byte) catch return error.OutOfMemory;
                index += 3;
            },
            '+' => {
                allocating.writer.writeByte(' ') catch return error.OutOfMemory;
                index += 1;
            },
            else => {
                allocating.writer.writeByte(value[index]) catch return error.OutOfMemory;
                index += 1;
            },
        }
    }
    return allocating.toOwnedSlice() catch error.OutOfMemory;
}

/// Iterates `application/x-www-form-urlencoded` pairs, decoding each.
///
/// Used for authorization responses, which arrive as a query string, and for token
/// endpoint error bodies.
pub const FormIterator = struct {
    rest: []const u8,

    pub const Pair = struct { name: []const u8, value: []const u8 };

    pub fn init(query: []const u8) FormIterator {
        return .{ .rest = query };
    }

    pub fn next(iterator: *FormIterator, arena: std.mem.Allocator) DecodeError!?Pair {
        while (iterator.rest.len > 0 and iterator.rest[0] == '&') {
            iterator.rest = iterator.rest[1..];
        }
        if (iterator.rest.len == 0) return null;

        const end = std.mem.indexOfScalar(u8, iterator.rest, '&') orelse iterator.rest.len;
        const pair = iterator.rest[0..end];
        iterator.rest = iterator.rest[end..];

        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        return .{
            .name = try decodeComponent(arena, pair[0..equals]),
            .value = if (equals == pair.len)
                ""
            else
                try decodeComponent(arena, pair[equals + 1 ..]),
        };
    }
};

test "parse splits an https URL" {
    const parts = try parse("https://mcp.example.com/mcp");
    try std.testing.expectEqual(Scheme.https, parts.scheme);
    try std.testing.expectEqualStrings("mcp.example.com", parts.host);
    try std.testing.expectEqual(@as(?u16, null), parts.port);
    try std.testing.expectEqualStrings("/mcp", parts.path);
    try std.testing.expect(parts.isHttps());
}

test "parse keeps an explicit port distinct from the default" {
    const explicit = try parse("https://mcp.example.com:443/mcp");
    try std.testing.expectEqual(@as(?u16, 443), explicit.port);

    const implicit = try parse("https://mcp.example.com/mcp");
    try std.testing.expectEqual(@as(?u16, null), implicit.port);

    // Eliding the default port is exactly the normalization the specification
    // forbids before comparison, so the two must stay distinguishable.
    try std.testing.expect(explicit.port != implicit.port);
}

test "parse handles IPv6 literals without mistaking colons for a port" {
    const parts = try parse("https://[::1]:8443/mcp");
    try std.testing.expectEqualStrings("[::1]", parts.host);
    try std.testing.expectEqual(@as(?u16, 8443), parts.port);
    try std.testing.expect(parts.isLoopback());

    const no_port = try parse("https://[2001:db8::1]/mcp");
    try std.testing.expectEqualStrings("[2001:db8::1]", no_port.host);
    try std.testing.expectEqual(@as(?u16, null), no_port.port);
    try std.testing.expect(!no_port.isLoopback());
}

test "parse splits query and fragment" {
    const parts = try parse("https://as.example.com/authorize?code=abc#frag?not-query");
    try std.testing.expectEqualStrings("/authorize", parts.path);
    try std.testing.expectEqualStrings("code=abc", parts.query.?);
    try std.testing.expectEqualStrings("frag?not-query", parts.fragment.?);
}

test "parse accepts an uppercase scheme for robustness" {
    const parts = try parse("HTTPS://MCP.example.com/mcp");
    try std.testing.expectEqual(Scheme.https, parts.scheme);
    // The host is returned as written: case folding it would corrupt the
    // byte-exact comparisons this stack depends on.
    try std.testing.expectEqualStrings("MCP.example.com", parts.host);
}

test "parse rejects what cannot be compared safely" {
    try std.testing.expectError(error.InvalidUrl, parse("mcp.example.com"));
    try std.testing.expectError(error.InvalidUrl, parse("ftp://mcp.example.com"));
    try std.testing.expectError(error.InvalidUrl, parse("https://"));
    try std.testing.expectError(error.InvalidUrl, parse("https:///path"));
    try std.testing.expectError(error.InvalidUrl, parse("https://host:notaport/"));
    try std.testing.expectError(error.InvalidUrl, parse("https://host with space/"));
    // Userinfo makes the effective host ambiguous to a reader.
    try std.testing.expectError(error.InvalidUrl, parse("https://evil@honest.example/"));
    try std.testing.expectError(error.UrlTooLong, parse("https://a/" ++ ("b" ** bytes_max)));
}

test "pathComponent strips trailing slashes and reports emptiness" {
    try std.testing.expectEqualStrings("/tenant1", (try parse("https://a.example/tenant1")).pathComponent());
    try std.testing.expectEqualStrings("/tenant1", (try parse("https://a.example/tenant1/")).pathComponent());
    try std.testing.expectEqualStrings("", (try parse("https://a.example/")).pathComponent());
    try std.testing.expectEqualStrings("", (try parse("https://a.example")).pathComponent());

    try std.testing.expect((try parse("https://a.example/tenant1")).hasPathComponent());
    try std.testing.expect(!(try parse("https://a.example/")).hasPathComponent());
}

test "isLoopback covers the forms a redirect URI may use" {
    try std.testing.expect((try parse("http://localhost:3000/callback")).isLoopback());
    try std.testing.expect((try parse("http://LOCALHOST/callback")).isLoopback());
    try std.testing.expect((try parse("http://app.localhost/callback")).isLoopback());
    try std.testing.expect((try parse("http://127.0.0.1:3000/callback")).isLoopback());
    try std.testing.expect((try parse("http://127.1.2.3/callback")).isLoopback());
    try std.testing.expect((try parse("http://[::1]/callback")).isLoopback());

    try std.testing.expect(!(try parse("http://notlocalhost/callback")).isLoopback());
    try std.testing.expect(!(try parse("http://localhost.evil.example/callback")).isLoopback());
    try std.testing.expect(!(try parse("http://127.0.0.1.evil.example/callback")).isLoopback());
}

test "wellKnownInserted follows RFC 8414 for an issuer with a path" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parts = try parse("https://auth.example.com/tenant1");
    try std.testing.expectEqualStrings(
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        try wellKnownInserted(arena.allocator(), &parts, "oauth-authorization-server"),
    );
}

test "wellKnownInserted on a bare issuer yields the plain well-known URL" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parts = try parse("https://auth.example.com");
    try std.testing.expectEqualStrings(
        "https://auth.example.com/.well-known/oauth-authorization-server",
        try wellKnownInserted(arena.allocator(), &parts, "oauth-authorization-server"),
    );
}

test "wellKnownAppended follows OpenID Connect Discovery" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parts = try parse("https://auth.example.com/tenant1");
    try std.testing.expectEqualStrings(
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
        try wellKnownAppended(arena.allocator(), &parts, "openid-configuration"),
    );
}

test "well-known builders preserve an explicit port" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parts = try parse("https://auth.example.com:8443/tenant1");
    try std.testing.expectEqualStrings(
        "https://auth.example.com:8443/.well-known/oauth-protected-resource/tenant1",
        try wellKnownInserted(arena.allocator(), &parts, "oauth-protected-resource"),
    );
}

test "encodeComponent escapes everything outside unreserved" {
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try encodeComponent(&writer, "https://mcp.example.com/mcp");
    try std.testing.expectEqualStrings("https%3A%2F%2Fmcp.example.com%2Fmcp", writer.buffered());
}

test "encodeComponent encodes space as %20 and leaves unreserved alone" {
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try encodeComponent(&writer, "files:read files:write");
    try std.testing.expectEqualStrings("files%3Aread%20files%3Awrite", writer.buffered());

    var second: [128]u8 = undefined;
    var second_writer: std.Io.Writer = .fixed(&second);
    try encodeComponent(&second_writer, "aZ0-._~");
    try std.testing.expectEqualStrings("aZ0-._~", second_writer.buffered());
}

test "decodeComponent reverses percent and plus encoding" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectEqualStrings(
        "https://as.example.com",
        try decodeComponent(arena.allocator(), "https%3A%2F%2Fas.example.com"),
    );
    try std.testing.expectEqualStrings(
        "a b",
        try decodeComponent(arena.allocator(), "a+b"),
    );
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeComponent(arena.allocator(), "%zz"),
    );
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeComponent(arena.allocator(), "trailing%2"),
    );
}

test "FormIterator decodes authorization response parameters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var iterator: FormIterator = .init("code=abc&state=xyz&iss=https%3A%2F%2Fas.example.com");
    const first = (try iterator.next(arena.allocator())).?;
    try std.testing.expectEqualStrings("code", first.name);
    try std.testing.expectEqualStrings("abc", first.value);

    const second = (try iterator.next(arena.allocator())).?;
    try std.testing.expectEqualStrings("state", second.name);
    try std.testing.expectEqualStrings("xyz", second.value);

    const third = (try iterator.next(arena.allocator())).?;
    try std.testing.expectEqualStrings("iss", third.name);
    try std.testing.expectEqualStrings("https://as.example.com", third.value);

    try std.testing.expectEqual(@as(?FormIterator.Pair, null), try iterator.next(arena.allocator()));
}

test "FormIterator tolerates empty values and stray separators" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var iterator: FormIterator = .init("&a=&&b");
    const first = (try iterator.next(arena.allocator())).?;
    try std.testing.expectEqualStrings("a", first.name);
    try std.testing.expectEqualStrings("", first.value);

    const second = (try iterator.next(arena.allocator())).?;
    try std.testing.expectEqualStrings("b", second.name);
    try std.testing.expectEqualStrings("", second.value);

    try std.testing.expectEqual(@as(?FormIterator.Pair, null), try iterator.next(arena.allocator()));
}

test "encode then decode is the identity" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_][]const u8{
        "https://mcp.example.com/mcp",
        "files:read files:write",
        "a+b",
        "caf\xc3\xa9",
        "",
    };
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try encodeComponent(&writer, case);
        const decoded = try decodeComponent(arena.allocator(), writer.buffered());
        try std.testing.expectEqualStrings(case, decoded);
    }
}

test "fuzz parse" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [256]u8 = undefined;
            const length = smith.slice(&buffer);
            const parts = parse(buffer[0..length]) catch return;
            // A parse that succeeded must have produced a host, and the pieces must
            // still be slices of the input.
            try std.testing.expect(parts.host.len > 0);
            try std.testing.expect(parts.path.len <= length);
        }
    }.run, .{});
}
