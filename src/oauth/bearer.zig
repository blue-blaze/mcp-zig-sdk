//! Bearer token usage and `WWW-Authenticate` challenges (RFC 6750), extended with
//! the `resource_metadata` parameter of RFC 9728 Section 5.1.
//!
//! Both halves live here because both halves must agree: a resource server writes
//! the challenge, a client parses it, and the parameter that makes the whole
//! discovery flow work — `resource_metadata` — is only useful if the two ends
//! spell it identically.
//!
//! ## Why parsing is more than a split on commas
//!
//! `WWW-Authenticate` can carry several challenges, and its parameter values can be
//! quoted strings containing commas and escaped quotes:
//!
//! ```text
//! WWW-Authenticate: Bearer error="insufficient_scope",
//!                          scope="files:read files:write",
//!                          resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
//!                   Basic realm="legacy"
//! ```
//!
//! Splitting on `,` cuts scope lists in half. The grammar (RFC 9110 Section 11.6.1)
//! also does not delimit challenges from one another: `Basic` is recognizable as a
//! new challenge only because it is a bare token that is *not* followed by `=`.
//! `parseChallenge` implements that lookahead.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;

/// The authentication scheme this module implements.
pub const scheme = "Bearer";

/// Upper bound on a `WWW-Authenticate` value this module will parse.
///
/// The header arrives from the network before any token has been validated, so it
/// is attacker-controlled in the most literal sense.
pub const challenge_bytes_max = 8 * 1024;

/// Upper bound on an access token this module will accept from a request.
///
/// Signed tokens with large claim sets are real, so this is generous; unbounded is
/// not an option when the value is copied and compared per request.
pub const token_bytes_max = 8 * 1024;

/// Upper bound on the number of auth-params parsed from one challenge.
pub const params_max = 16;

pub const ExtractError = error{
    /// No `Authorization` header, or it was empty.
    Missing,
    /// The header used a scheme other than `Bearer`.
    UnsupportedScheme,
    /// The header was `Bearer` but the credentials were absent or malformed.
    Malformed,
    /// The credentials exceeded `token_bytes_max`.
    TokenTooLong,
};

/// True if `token` is a `b64token` per RFC 6750 Section 2.1:
/// `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
///
/// The charset is enforced rather than accepting arbitrary bytes. A token is a
/// value that gets logged, compared, and sometimes forwarded; allowing CR, LF, or
/// NUL through would make it a tool for splitting headers and truncating log
/// lines downstream. Base64url — and therefore every JWT — fits.
pub fn validToken(token: []const u8) bool {
    if (token.len == 0) return false;

    var index: usize = 0;
    while (index < token.len and token[index] != '=') : (index += 1) {
        const byte = token[index];
        const ok = std.ascii.isAlphanumeric(byte) or
            byte == '-' or byte == '.' or byte == '_' or
            byte == '~' or byte == '+' or byte == '/';
        if (!ok) return false;
    }
    if (index == 0) return false; // Nothing but padding.

    while (index < token.len) : (index += 1) {
        if (token[index] != '=') return false;
    }
    return true;
}

/// Extracts the access token from an `Authorization` header value.
///
/// `null` for `header` means the header was absent, which is `error.Missing` — the
/// same outcome as a present but empty header, since neither carries credentials.
pub fn extract(header: ?[]const u8) ExtractError![]const u8 {
    const value = header orelse return error.Missing;
    const trimmed = std.mem.trim(u8, value, " \t");
    if (trimmed.len == 0) return error.Missing;

    // The scheme name is case-insensitive (RFC 9110 Section 11.1); the credentials
    // that follow are not.
    if (trimmed.len < scheme.len) return error.UnsupportedScheme;
    if (!std.ascii.eqlIgnoreCase(trimmed[0..scheme.len], scheme)) {
        return error.UnsupportedScheme;
    }

    const rest = trimmed[scheme.len..];
    // `Bearerfoo` is not the Bearer scheme; a separator is required.
    if (rest.len == 0) return error.Malformed;
    if (rest[0] != ' ' and rest[0] != '\t') return error.UnsupportedScheme;

    const credentials = std.mem.trim(u8, rest, " \t");
    if (credentials.len == 0) return error.Malformed;
    if (credentials.len > token_bytes_max) return error.TokenTooLong;
    if (!validToken(credentials)) return error.Malformed;

    assert(credentials.len > 0);
    return credentials;
}

/// The RFC 6750 Section 3.1 error codes, and the HTTP status each implies.
pub const ErrorCode = enum {
    /// The request was malformed: no credentials, or more than one mechanism.
    invalid_request,
    /// The token was expired, revoked, malformed, or not for this audience.
    invalid_token,
    /// The token is valid but lacks the scopes this operation needs.
    insufficient_scope,

    pub fn status(code: ErrorCode) u16 {
        return switch (code) {
            .invalid_request => 400,
            .invalid_token => 401,
            .insufficient_scope => 403,
        };
    }

    pub fn text(code: ErrorCode) []const u8 {
        return @tagName(code);
    }
};

/// A `WWW-Authenticate: Bearer ...` challenge.
///
/// A challenge with no `code` is the bare "you need to authenticate" form used for
/// a request that arrived with no credentials at all, which is a 401.
pub const Challenge = struct {
    code: ?ErrorCode = null,
    /// Human-readable detail. Never put token contents or internal state here: it
    /// is returned to an unauthenticated caller.
    description: ?[]const u8 = null,
    /// The scopes required to satisfy *this* operation. Clients treat this as
    /// authoritative and union it with what they already hold.
    scope: ?[]const u8 = null,
    /// URL of the protected resource metadata document (RFC 9728 Section 5.1).
    /// This is what lets a client discover the authorization server, so a 401
    /// without it leaves the client with nowhere to go.
    resource_metadata: ?[]const u8 = null,
    realm: ?[]const u8 = null,

    pub fn status(challenge: *const Challenge) u16 {
        const code = challenge.code orelse return 401;
        return code.status();
    }

    /// Renders the header value.
    ///
    /// Parameter order is fixed rather than incidental: `error` first when present
    /// (it is the most specific thing a client can branch on), then the guidance
    /// parameters. RFC 9110 does not constrain the order.
    pub fn write(challenge: *const Challenge, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(scheme);

        var written: usize = 0;
        if (challenge.code) |code| {
            try writeParam(writer, &written, "error", code.text());
        }
        if (challenge.description) |description| {
            try writeParam(writer, &written, "error_description", description);
        }
        if (challenge.scope) |value| {
            try writeParam(writer, &written, "scope", value);
        }
        if (challenge.resource_metadata) |value| {
            try writeParam(writer, &written, "resource_metadata", value);
        }
        if (challenge.realm) |value| {
            try writeParam(writer, &written, "realm", value);
        }
    }

    /// The header value, allocated.
    pub fn render(challenge: *const Challenge, gpa: std.mem.Allocator) ![]u8 {
        var allocating: std.Io.Writer.Allocating = .init(gpa);
        defer allocating.deinit();
        try challenge.write(&allocating.writer);
        return allocating.toOwnedSlice();
    }

    fn writeParam(
        writer: *std.Io.Writer,
        written: *usize,
        name: []const u8,
        value: []const u8,
    ) std.Io.Writer.Error!void {
        try writer.writeAll(if (written.* == 0) " " else ", ");
        written.* += 1;
        try writer.writeAll(name);
        // Every parameter is quoted, even those that would be legal bare tokens.
        // `scope` values contain spaces and so must be quoted anyway, and a
        // uniform shape removes a category of "works until the value changes" bug.
        try writer.writeByte('=');
        try writeQuoted(writer, value);
    }

    /// Writes a quoted-string, escaping the two characters that would end it.
    ///
    /// Control characters are dropped rather than escaped: `quoted-string` has no
    /// escape that survives them, and a CR or LF in a header value is a response
    /// splitting bug, not a formatting one.
    fn writeQuoted(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
        try writer.writeByte('"');
        for (value) |byte| {
            switch (byte) {
                '"', '\\' => {
                    try writer.writeByte('\\');
                    try writer.writeByte(byte);
                },
                0...0x1F, 0x7F => {},
                else => try writer.writeByte(byte),
            }
        }
        try writer.writeByte('"');
    }
};

pub const ParseError = error{
    /// The value exceeded `challenge_bytes_max`.
    ChallengeTooLong,
    /// The value could not be read as a sequence of challenges.
    Malformed,
    OutOfMemory,
};

/// A parsed `Bearer` challenge, as a client sees it.
///
/// Unknown parameters are dropped: RFC 6750 allows extensions, and a client that
/// failed on them would break the first time a server added one.
pub const ParsedChallenge = struct {
    /// The `error` parameter, when it was one this module knows. An unrecognized
    /// value leaves this null and `error_text` set, because a client should be able
    /// to surface what it was told even when it cannot act on it.
    code: ?ErrorCode = null,
    error_text: ?[]const u8 = null,
    description: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    resource_metadata: ?[]const u8 = null,
    realm: ?[]const u8 = null,
};

/// Parses the `Bearer` challenge out of a `WWW-Authenticate` value.
///
/// Returns null when the header carries no `Bearer` challenge — a server offering
/// only other schemes is not something this module can act on. Values are
/// allocated in `arena` because unescaping a quoted-string cannot be done in
/// place.
pub fn parseChallenge(
    arena: std.mem.Allocator,
    header: []const u8,
) ParseError!?ParsedChallenge {
    if (header.len > challenge_bytes_max) return error.ChallengeTooLong;

    var scanner: Scanner = .{ .rest = header };
    var in_bearer = false;
    var found = false;
    var parsed: ParsedChallenge = .{};
    var params: usize = 0;

    while (try scanner.next(arena)) |item| {
        switch (item) {
            .challenge_start => |name| {
                in_bearer = std.ascii.eqlIgnoreCase(name, scheme);
                if (in_bearer) {
                    // A second Bearer challenge is unusual; keep the first, which
                    // is the server's preferred one (RFC 9110 lists them in order
                    // of preference).
                    if (found) in_bearer = false else found = true;
                }
            },
            .param => |param| {
                if (!in_bearer) continue;
                params += 1;
                if (params > params_max) return error.Malformed;
                applyParam(&parsed, param);
            },
        }
    }

    if (!found) return null;
    return parsed;
}

fn applyParam(parsed: *ParsedChallenge, param: Param) void {
    // Parameter names are case-insensitive (RFC 9110 Section 11.4). First
    // occurrence wins; a duplicate is a server bug and picking the later one would
    // let a trailing parameter override the one the server meant.
    if (std.ascii.eqlIgnoreCase(param.name, "error")) {
        if (parsed.error_text != null) return;
        parsed.error_text = param.value;
        parsed.code = std.meta.stringToEnum(ErrorCode, param.value);
    } else if (std.ascii.eqlIgnoreCase(param.name, "error_description")) {
        if (parsed.description == null) parsed.description = param.value;
    } else if (std.ascii.eqlIgnoreCase(param.name, "scope")) {
        if (parsed.scope == null) parsed.scope = param.value;
    } else if (std.ascii.eqlIgnoreCase(param.name, "resource_metadata")) {
        if (parsed.resource_metadata == null) parsed.resource_metadata = param.value;
    } else if (std.ascii.eqlIgnoreCase(param.name, "realm")) {
        if (parsed.realm == null) parsed.realm = param.value;
    }
}

const Param = struct { name: []const u8, value: []const u8 };

const Item = union(enum) {
    challenge_start: []const u8,
    param: Param,
};

/// Walks a `WWW-Authenticate` value, emitting challenge names and parameters.
///
/// The one subtle rule: a bare token that is not followed by `=` begins a new
/// challenge. That lookahead is the only thing distinguishing `Basic realm="x"`
/// (a new challenge) from `realm="x"` (a parameter of the current one).
const Scanner = struct {
    rest: []const u8,

    fn next(scanner: *Scanner, arena: std.mem.Allocator) ParseError!?Item {
        scanner.skipDelimiters();
        if (scanner.rest.len == 0) return null;

        const name = scanner.takeToken();
        if (name.len == 0) return error.Malformed;

        const save = scanner.rest;
        scanner.skipWhitespace();
        if (scanner.rest.len > 0 and scanner.rest[0] == '=') {
            scanner.rest = scanner.rest[1..];
            scanner.skipWhitespace();
            const value = try scanner.takeValue(arena);
            return .{ .param = .{ .name = name, .value = value } };
        }

        // Not a parameter, so `name` is a scheme. Restore so that whatever follows
        // is scanned as its first parameter (or token68) on the next call.
        scanner.rest = save;
        return .{ .challenge_start = name };
    }

    fn skipDelimiters(scanner: *Scanner) void {
        while (scanner.rest.len > 0) {
            switch (scanner.rest[0]) {
                ' ', '\t', ',' => scanner.rest = scanner.rest[1..],
                else => return,
            }
        }
    }

    fn skipWhitespace(scanner: *Scanner) void {
        while (scanner.rest.len > 0 and (scanner.rest[0] == ' ' or scanner.rest[0] == '\t')) {
            scanner.rest = scanner.rest[1..];
        }
    }

    fn takeToken(scanner: *Scanner) []const u8 {
        var end: usize = 0;
        while (end < scanner.rest.len and isTokenChar(scanner.rest[end])) end += 1;
        const token = scanner.rest[0..end];
        scanner.rest = scanner.rest[end..];
        return token;
    }

    fn takeValue(scanner: *Scanner, arena: std.mem.Allocator) ParseError![]const u8 {
        if (scanner.rest.len == 0) return error.Malformed;
        if (scanner.rest[0] != '"') {
            const token = scanner.takeToken();
            if (token.len == 0) return error.Malformed;
            return token;
        }

        scanner.rest = scanner.rest[1..];
        var unescaped: std.Io.Writer.Allocating = .init(arena);
        // No `defer deinit`: the buffer is handed to the caller on success, and on
        // failure the arena reclaims it.
        while (scanner.rest.len > 0) {
            const byte = scanner.rest[0];
            scanner.rest = scanner.rest[1..];
            switch (byte) {
                '"' => return unescaped.written(),
                '\\' => {
                    if (scanner.rest.len == 0) return error.Malformed;
                    unescaped.writer.writeByte(scanner.rest[0]) catch return error.OutOfMemory;
                    scanner.rest = scanner.rest[1..];
                },
                else => unescaped.writer.writeByte(byte) catch return error.OutOfMemory,
            }
        }
        // Unterminated quoted-string: the value was truncated, so its contents
        // cannot be trusted.
        return error.Malformed;
    }

    fn isTokenChar(byte: u8) bool {
        // RFC 9110 `tchar`.
        return switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => std.ascii.isAlphanumeric(byte),
        };
    }
};

test "extract reads a Bearer token" {
    try std.testing.expectEqualStrings("abc.def.ghi", try extract("Bearer abc.def.ghi"));
    try std.testing.expectEqualStrings("abc", try extract("  bearer   abc  "));
    try std.testing.expectEqualStrings("abc", try extract("BEARER abc"));
}

test "extract accepts base64url and padding" {
    try std.testing.expectEqualStrings("a-b_c~d.e+f/g==", try extract("Bearer a-b_c~d.e+f/g=="));
}

test "extract distinguishes absent, wrong scheme, and malformed" {
    try std.testing.expectError(error.Missing, extract(null));
    try std.testing.expectError(error.Missing, extract(""));
    try std.testing.expectError(error.Missing, extract("   "));
    try std.testing.expectError(error.UnsupportedScheme, extract("Basic dXNlcjpwYXNz"));
    try std.testing.expectError(error.UnsupportedScheme, extract("Bear"));
    try std.testing.expectError(error.Malformed, extract("Bearer"));
    try std.testing.expectError(error.Malformed, extract("Bearer   "));
    // `Bearerfoo` is a different scheme, not a Bearer token.
    try std.testing.expectError(error.UnsupportedScheme, extract("Bearerfoo"));
}

test "extract rejects tokens carrying header-splitting bytes" {
    try std.testing.expectError(error.Malformed, extract("Bearer abc\r\nX-Evil: 1"));
    try std.testing.expectError(error.Malformed, extract("Bearer ab c"));
    try std.testing.expectError(error.Malformed, extract("Bearer \"abc\""));
    try std.testing.expectError(error.Malformed, extract("Bearer ==="));
}

test "extract bounds the token length" {
    const long = "Bearer " ++ ("a" ** (token_bytes_max + 1));
    try std.testing.expectError(error.TokenTooLong, extract(long));
}

test "Challenge renders the 401 discovery form" {
    const challenge: Challenge = .{
        .resource_metadata = "https://mcp.example.com/.well-known/oauth-protected-resource",
        .scope = "files:read",
    };
    try std.testing.expectEqual(@as(u16, 401), challenge.status());

    const rendered = try challenge.render(std.testing.allocator);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "Bearer scope=\"files:read\", " ++
            "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
        rendered,
    );
}

test "Challenge renders the 403 insufficient_scope form" {
    const challenge: Challenge = .{
        .code = .insufficient_scope,
        .scope = "files:write",
        .resource_metadata = "https://mcp.example.com/.well-known/oauth-protected-resource",
        .description = "File write permission required for this operation",
    };
    try std.testing.expectEqual(@as(u16, 403), challenge.status());

    const rendered = try challenge.render(std.testing.allocator);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "Bearer error=\"insufficient_scope\", " ++
            "error_description=\"File write permission required for this operation\", " ++
            "scope=\"files:write\", " ++
            "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
        rendered,
    );
}

test "Challenge maps each error code to its status" {
    try std.testing.expectEqual(@as(u16, 400), (Challenge{ .code = .invalid_request }).status());
    try std.testing.expectEqual(@as(u16, 401), (Challenge{ .code = .invalid_token }).status());
    try std.testing.expectEqual(@as(u16, 403), (Challenge{ .code = .insufficient_scope }).status());
}

test "Challenge escapes quotes and drops control characters" {
    const challenge: Challenge = .{
        .code = .invalid_token,
        .description = "say \"hi\" \\ and\r\nsplit",
    };
    const rendered = try challenge.render(std.testing.allocator);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings(
        "Bearer error=\"invalid_token\", error_description=\"say \\\"hi\\\" \\\\ andsplit\"",
        rendered,
    );
    // Nothing that could terminate the header survived.
    try std.testing.expect(std.mem.indexOfScalar(u8, rendered, '\r') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, rendered, '\n') == null);
}

test "parseChallenge reads the discovery parameters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", " ++
            "scope=\"files:read\"",
    )).?;
    try std.testing.expectEqualStrings(
        "https://mcp.example.com/.well-known/oauth-protected-resource",
        parsed.resource_metadata.?,
    );
    try std.testing.expectEqualStrings("files:read", parsed.scope.?);
    try std.testing.expectEqual(@as(?ErrorCode, null), parsed.code);
}

test "parseChallenge keeps a scope list whole" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // A naive split on commas would cut this value in half.
    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer error=\"insufficient_scope\", scope=\"files:read files:write mail:send\"",
    )).?;
    try std.testing.expectEqual(ErrorCode.insufficient_scope, parsed.code.?);
    try std.testing.expectEqualStrings("files:read files:write mail:send", parsed.scope.?);
}

test "parseChallenge finds Bearer among several challenges" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Basic realm=\"legacy\", Bearer scope=\"a b\", realm=\"mcp\", Negotiate",
    )).?;
    try std.testing.expectEqualStrings("a b", parsed.scope.?);
    // `realm` after the Bearer scheme belongs to Bearer, not to Basic.
    try std.testing.expectEqualStrings("mcp", parsed.realm.?);
}

test "parseChallenge stops attributing params once a new scheme begins" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer scope=\"a\", Basic realm=\"legacy\"",
    )).?;
    try std.testing.expectEqualStrings("a", parsed.scope.?);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.realm);
}

test "parseChallenge returns null when no Bearer challenge is offered" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectEqual(
        @as(?ParsedChallenge, null),
        try parseChallenge(arena.allocator(), "Basic realm=\"legacy\""),
    );
}

test "parseChallenge unescapes quoted values" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer error_description=\"say \\\"hi\\\" \\\\ ok\"",
    )).?;
    try std.testing.expectEqualStrings("say \"hi\" \\ ok", parsed.description.?);
}

test "parseChallenge accepts bare token values and odd spacing" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer  error = invalid_token ,realm=mcp",
    )).?;
    try std.testing.expectEqual(ErrorCode.invalid_token, parsed.code.?);
    try std.testing.expectEqualStrings("mcp", parsed.realm.?);
}

test "parseChallenge surfaces an unknown error code without claiming to know it" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(arena.allocator(), "Bearer error=\"tomorrows_code\"")).?;
    try std.testing.expectEqual(@as(?ErrorCode, null), parsed.code);
    try std.testing.expectEqualStrings("tomorrows_code", parsed.error_text.?);
}

test "parseChallenge ignores unknown parameters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer future_param=\"x\", scope=\"a\"",
    )).?;
    try std.testing.expectEqualStrings("a", parsed.scope.?);
}

test "parseChallenge keeps the first of duplicate parameters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = (try parseChallenge(
        arena.allocator(),
        "Bearer scope=\"first\", scope=\"second\"",
    )).?;
    try std.testing.expectEqualStrings("first", parsed.scope.?);
}

test "parseChallenge rejects an unterminated quoted string" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        error.Malformed,
        parseChallenge(arena.allocator(), "Bearer scope=\"unterminated"),
    );
}

test "parseChallenge bounds its input" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const long = "Bearer scope=\"" ++ ("a" ** challenge_bytes_max) ++ "\"";
    try std.testing.expectError(error.ChallengeTooLong, parseChallenge(arena.allocator(), long));
}

test "a rendered challenge round-trips through the parser" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const original: Challenge = .{
        .code = .insufficient_scope,
        .description = "needs \"write\"",
        .scope = "files:read files:write",
        .resource_metadata = "https://mcp.example.com/.well-known/oauth-protected-resource",
        .realm = "mcp",
    };
    const rendered = try original.render(arena.allocator());
    const parsed = (try parseChallenge(arena.allocator(), rendered)).?;

    try std.testing.expectEqual(original.code.?, parsed.code.?);
    try std.testing.expectEqualStrings(original.description.?, parsed.description.?);
    try std.testing.expectEqualStrings(original.scope.?, parsed.scope.?);
    try std.testing.expectEqualStrings(original.resource_metadata.?, parsed.resource_metadata.?);
    try std.testing.expectEqualStrings(original.realm.?, parsed.realm.?);
}

test "fuzz parseChallenge" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            const parsed = parseChallenge(arena.allocator(), buffer[0..length]) catch return;
            // Any value handed back must be something the caller can safely put in
            // a log line or a URL.
            if (parsed) |challenge| {
                if (challenge.scope) |value| {
                    try std.testing.expect(std.mem.indexOfScalar(u8, value, 0) == null);
                }
            }
        }
    }.run, .{});
}
