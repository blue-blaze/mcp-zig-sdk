//! OAuth scope sets: parsing, canonical rendering, and the union operation that
//! step-up authorization is defined in terms of.
//!
//! A scope value is a space-delimited list of tokens (RFC 6749 Section 3.3). That
//! is simple enough that most code manipulates it as a raw string — and then gets
//! the step-up flow wrong, because "request the union of what you had and what you
//! were just challenged for" is not a string operation. Concatenating produces
//! duplicates; replacing silently drops permissions the client still needs for
//! other operations. Both are observable as a user being re-prompted, or as an
//! operation that worked yesterday failing today.
//!
//! ## Bounded by construction
//!
//! `Set` holds its tokens in a fixed inline buffer and never allocates. The scopes
//! a client asks for come from a `WWW-Authenticate` challenge, which is to say
//! from the network: an unbounded set would let a server grow client memory by
//! challenging for scopes in a loop. `bytes_max` and `tokens_max` are the caps.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;

/// Upper bound on the rendered length of a scope set.
///
/// Authorization requests travel in a URL, and user agents have their own limits
/// well under this; a set this large is a bug in the caller, not a scenario to
/// support.
pub const bytes_max = 4096;

/// Upper bound on the number of tokens in a scope set.
pub const tokens_max = 128;

/// Upper bound on a single scope token.
pub const token_bytes_max = 256;

pub const Error = error{
    /// The token is empty or contains a character RFC 6749 does not allow.
    InvalidScope,
    /// Adding the token would exceed `bytes_max` or `token_bytes_max`.
    ScopeTooLong,
    /// Adding the token would exceed `tokens_max`.
    TooManyScopes,
};

/// True if `token` is a valid `scope-token` per RFC 6749 Section 3.3:
/// `1*( %x21 / %x23-5B / %x5D-7E )` — visible ASCII except space, `"`, and `\`.
pub fn validToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |byte| {
        const ok = byte == 0x21 or
            (byte >= 0x23 and byte <= 0x5B) or
            (byte >= 0x5D and byte <= 0x7E);
        if (!ok) return false;
    }
    return true;
}

/// Iterates the tokens of a scope string, skipping runs of separators.
///
/// RFC 6749 says the delimiter is a space. Real deployments emit `+` (from a
/// form-encoded value that was never decoded) and tabs; a strict split on `' '`
/// turns those into one long bogus scope, so separators here are space and tab.
/// `+` is deliberately *not* a separator: it is a legal scope-token character,
/// and guessing which meaning was intended would corrupt scopes that legitimately
/// contain it.
pub const Iterator = struct {
    rest: []const u8,

    pub fn init(scopes: []const u8) Iterator {
        return .{ .rest = scopes };
    }

    pub fn next(iterator: *Iterator) ?[]const u8 {
        while (iterator.rest.len > 0 and isSeparator(iterator.rest[0])) {
            iterator.rest = iterator.rest[1..];
        }
        if (iterator.rest.len == 0) return null;

        var end: usize = 0;
        while (end < iterator.rest.len and !isSeparator(iterator.rest[end])) end += 1;

        const token = iterator.rest[0..end];
        iterator.rest = iterator.rest[end..];
        assert(token.len > 0);
        return token;
    }

    fn isSeparator(byte: u8) bool {
        return byte == ' ' or byte == '\t';
    }
};

/// True if `scopes` contains `token` as a whole token.
///
/// Substring search would report that `files:read` is present in `files:readonly`.
pub fn contains(scopes: []const u8, token: []const u8) bool {
    var iterator: Iterator = .init(scopes);
    while (iterator.next()) |candidate| {
        if (std.mem.eql(u8, candidate, token)) return true;
    }
    return false;
}

/// True if every token in `required` appears in `granted`.
///
/// This is exact token matching. Scope *hierarchies* — where `files:write` is
/// meant to imply `files:read` — are deployment policy, not something a generic
/// library can infer from the strings, so a server with a hierarchy must supply
/// its own predicate. The specification requires servers to account for
/// hierarchies; it does not define one.
pub fn containsAll(granted: []const u8, required: []const u8) bool {
    var iterator: Iterator = .init(required);
    while (iterator.next()) |token| {
        if (!contains(granted, token)) return false;
    }
    return true;
}

// Aliases taken at file scope: inside `Set` the bare names resolve ambiguously
// between the free functions and the methods of the same name.
const containsToken = contains;
const containsAllTokens = containsAll;

/// A deduplicated, order-preserving set of scope tokens with a fixed capacity.
pub const Set = struct {
    buffer: [bytes_max]u8 = undefined,
    len: usize = 0,
    count: usize = 0,

    /// A set holding the tokens of `scopes`.
    pub fn parse(scopes: []const u8) Error!Set {
        var set: Set = .{};
        try set.addAll(scopes);
        return set;
    }

    /// The union of two scope strings, which is what a step-up authorization
    /// request must ask for: the scopes from the current challenge *plus*
    /// everything previously requested, so that permissions needed by other
    /// operations survive a per-operation challenge.
    pub fn unionOf(a: []const u8, b: []const u8) Error!Set {
        var set: Set = .{};
        try set.addAll(a);
        try set.addAll(b);
        return set;
    }

    /// Adds one token. A token already present is not an error and not a
    /// duplicate: a set is what the caller asked for.
    pub fn add(set: *Set, token: []const u8) Error!void {
        if (!validToken(token)) return error.InvalidScope;
        if (token.len > token_bytes_max) return error.ScopeTooLong;
        if (set.contains(token)) return;
        if (set.count == tokens_max) return error.TooManyScopes;

        const separator: usize = if (set.len == 0) 0 else 1;
        if (set.len + separator + token.len > bytes_max) return error.ScopeTooLong;

        if (separator == 1) {
            set.buffer[set.len] = ' ';
            set.len += 1;
        }
        @memcpy(set.buffer[set.len..][0..token.len], token);
        set.len += token.len;
        set.count += 1;

        assert(set.len <= bytes_max);
        assert(set.count <= tokens_max);
        assert(set.contains(token));
    }

    /// Adds every token of a scope string.
    pub fn addAll(set: *Set, scopes: []const u8) Error!void {
        var iterator: Iterator = .init(scopes);
        while (iterator.next()) |token| try set.add(token);
    }

    /// The canonical rendering: tokens separated by single spaces, in insertion
    /// order. This is the exact bytes of a `scope` parameter.
    pub fn value(set: *const Set) []const u8 {
        return set.buffer[0..set.len];
    }

    pub fn contains(set: *const Set, token: []const u8) bool {
        return containsToken(set.value(), token);
    }

    pub fn containsAll(set: *const Set, required: []const u8) bool {
        return containsAllTokens(set.value(), required);
    }

    pub fn isEmpty(set: *const Set) bool {
        assert((set.len == 0) == (set.count == 0));
        return set.count == 0;
    }

    /// The scope value, or null when empty.
    ///
    /// An empty `scope` parameter is not the same as an absent one: the
    /// specification says to omit the parameter when there is nothing to ask for,
    /// and some authorization servers reject `scope=`.
    pub fn optionalValue(set: *const Set) ?[]const u8 {
        if (set.isEmpty()) return null;
        return set.value();
    }
};

test "validToken accepts RFC 6749 scope tokens and rejects the rest" {
    try std.testing.expect(validToken("files:read"));
    try std.testing.expect(validToken("openid"));
    try std.testing.expect(validToken("offline_access"));
    try std.testing.expect(validToken("!"));
    try std.testing.expect(validToken("~"));
    try std.testing.expect(validToken("a+b"));

    try std.testing.expect(!validToken(""));
    try std.testing.expect(!validToken("has space"));
    try std.testing.expect(!validToken("has\"quote"));
    try std.testing.expect(!validToken("has\\backslash"));
    try std.testing.expect(!validToken("has\ttab"));
    try std.testing.expect(!validToken("\x00"));
    try std.testing.expect(!validToken("caf\xc3\xa9"));
}

test "Iterator skips separator runs and tolerates tabs" {
    var iterator: Iterator = .init("  files:read \t files:write  ");
    try std.testing.expectEqualStrings("files:read", iterator.next().?);
    try std.testing.expectEqualStrings("files:write", iterator.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), iterator.next());
}

test "Iterator on an empty or blank string yields nothing" {
    var empty: Iterator = .init("");
    try std.testing.expectEqual(@as(?[]const u8, null), empty.next());

    var blank: Iterator = .init("   ");
    try std.testing.expectEqual(@as(?[]const u8, null), blank.next());
}

test "contains matches whole tokens only" {
    try std.testing.expect(contains("files:read files:write", "files:read"));
    try std.testing.expect(contains("files:read files:write", "files:write"));

    // Substring search would say yes to both of these.
    try std.testing.expect(!contains("files:readonly", "files:read"));
    try std.testing.expect(!contains("files:read", "files"));
}

test "containsAll requires every token" {
    try std.testing.expect(containsAll("a b c", "a c"));
    try std.testing.expect(containsAll("a b c", ""));
    try std.testing.expect(!containsAll("a b", "a b c"));
}

test "Set deduplicates and preserves insertion order" {
    var set: Set = try .parse("b a b c a");
    try std.testing.expectEqualStrings("b a c", set.value());
    try std.testing.expectEqual(@as(usize, 3), set.count);
}

test "Set renders single spaces regardless of input spacing" {
    const set: Set = try .parse("  a \t\t b  ");
    try std.testing.expectEqualStrings("a b", set.value());
}

test "unionOf preserves previously requested scopes alongside the challenge" {
    // The step-up requirement: a server challenging for `files:write` alone must
    // not cost the client the `files:read` it already had.
    const granted = "files:read profile";
    const challenged = "files:write";
    const set: Set = try .unionOf(granted, challenged);
    try std.testing.expectEqualStrings("files:read profile files:write", set.value());
    try std.testing.expect(set.containsAll("files:read"));
    try std.testing.expect(set.containsAll("files:write"));
}

test "unionOf is idempotent when the challenge adds nothing" {
    const set: Set = try .unionOf("a b", "b a");
    try std.testing.expectEqualStrings("a b", set.value());
}

test "empty Set reports absent rather than empty" {
    const set: Set = .{};
    try std.testing.expect(set.isEmpty());
    try std.testing.expectEqual(@as(?[]const u8, null), set.optionalValue());
    try std.testing.expectEqualStrings("", set.value());
}

test "Set rejects invalid tokens instead of storing them" {
    var set: Set = .{};
    try std.testing.expectError(error.InvalidScope, set.add("has space"));
    try std.testing.expectError(error.InvalidScope, set.add(""));
    try std.testing.expect(set.isEmpty());
}

test "Set enforces its token count bound" {
    var set: Set = .{};
    var buffer: [8]u8 = undefined;
    for (0..tokens_max) |index| {
        const token = try std.fmt.bufPrint(&buffer, "s{d}", .{index});
        try set.add(token);
    }
    try std.testing.expectEqual(tokens_max, set.count);
    try std.testing.expectError(error.TooManyScopes, set.add("one-too-many"));
}

test "Set enforces its byte bound" {
    var set: Set = .{};
    const chunk = "x" ** token_bytes_max;
    var count: usize = 0;
    while (true) {
        var buffer: [token_bytes_max]u8 = undefined;
        @memcpy(&buffer, chunk);
        // Make each token distinct so deduplication does not hide the growth.
        _ = std.fmt.bufPrint(buffer[0..8], "{d:0>8}", .{count}) catch unreachable;
        set.add(&buffer) catch |err| {
            try std.testing.expect(err == error.ScopeTooLong or err == error.TooManyScopes);
            break;
        };
        count += 1;
    }
    try std.testing.expect(set.len <= bytes_max);
}

test "Set rejects an oversized single token" {
    var set: Set = .{};
    const long = "x" ** (token_bytes_max + 1);
    try std.testing.expectError(error.ScopeTooLong, set.add(long));
}

test "fuzz Set.parse against arbitrary scope strings" {
    // Scope strings arrive in `WWW-Authenticate` challenges, so the bytes are chosen by
    // whoever answered the request. The set is fixed-size on purpose; this checks that its
    // bounds hold rather than that they are large enough.
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [2048]u8 = undefined;
            const length = smith.slice(&buffer);
            const scopes = buffer[0..length];

            const set = Set.parse(scopes) catch return;
            try std.testing.expect(set.len <= bytes_max);
            try std.testing.expect(set.count <= tokens_max);
            // Every token that went in must be findable by whole-token match — the
            // property `contains` exists for, and the one a substring search would break.
            var iterator: Iterator = .init(scopes);
            while (iterator.next()) |token| {
                try std.testing.expect(set.contains(token));
            }
            // A set is its own fixed point: re-parsing what it renders yields the same
            // tokens, which is what makes `unionOf` composable across step-up rounds.
            const again = try Set.parse(set.value());
            try std.testing.expectEqual(set.count, again.count);
        }
    }.run, .{});
}
