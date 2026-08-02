//! base64url without padding (RFC 4648 Section 5), the encoding JOSE uses for
//! every one of its segments and key parameters.
//!
//! Standard base64 is a different alphabet (`+` and `/` rather than `-` and `_`)
//! and JOSE forbids the padding. Decoding a JWT with a standard-base64 decoder
//! fails on roughly a third of real tokens — the ones whose random bytes happen to
//! produce a `-` or `_` — which is the kind of proportion that gets shipped.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;

const decoder = std.base64.url_safe_no_pad.Decoder;
const encoder = std.base64.url_safe_no_pad.Encoder;

pub const Error = error{ InvalidEncoding, OutOfMemory };

/// Decoded length of `encoded`, without decoding it.
pub fn decodedLength(encoded: []const u8) Error!usize {
    return decoder.calcSizeForSlice(encoded) catch error.InvalidEncoding;
}

/// Decodes into `arena`.
pub fn decode(arena: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    const length = try decodedLength(encoded);
    const buffer = arena.alloc(u8, length) catch return error.OutOfMemory;
    decoder.decode(buffer, encoded) catch return error.InvalidEncoding;
    return buffer;
}

/// Decodes into a caller-provided buffer, returning the used prefix.
///
/// For key parameters and signatures, whose sizes are known and small; keeps them
/// off the heap and out of an allocator's failure paths.
pub fn decodeInto(buffer: []u8, encoded: []const u8) Error![]u8 {
    const length = try decodedLength(encoded);
    if (length > buffer.len) return error.InvalidEncoding;
    decoder.decode(buffer[0..length], encoded) catch return error.InvalidEncoding;
    return buffer[0..length];
}

/// Decodes into a fixed-size array, requiring an exact length match.
///
/// A JOSE parameter whose size is fixed by its algorithm — a P-256 coordinate, an
/// ES256 signature half — must be exactly that size. Accepting a short value and
/// zero-padding it would silently accept malformed keys.
pub fn decodeExact(comptime length: usize, encoded: []const u8) Error![length]u8 {
    if (try decodedLength(encoded) != length) return error.InvalidEncoding;
    var buffer: [length]u8 = undefined;
    decoder.decode(&buffer, encoded) catch return error.InvalidEncoding;
    return buffer;
}

/// Encoded length of `bytes`.
pub fn encodedLength(bytes: usize) usize {
    return encoder.calcSize(bytes);
}

/// Encodes into `arena`.
pub fn encode(arena: std.mem.Allocator, bytes: []const u8) error{OutOfMemory}![]u8 {
    const buffer = try arena.alloc(u8, encodedLength(bytes.len));
    const written = encoder.encode(buffer, bytes);
    assert(written.len == buffer.len);
    return buffer;
}

/// Encodes into a caller-provided buffer.
pub fn encodeInto(buffer: []u8, bytes: []const u8) []const u8 {
    assert(buffer.len >= encodedLength(bytes.len));
    return encoder.encode(buffer, bytes);
}

test "decode reads the url-safe alphabet without padding" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // `{"alg":"RS256","typ":"JWT"}` as a real JWT header segment.
    try std.testing.expectEqualStrings(
        "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
        try decode(arena.allocator(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"),
    );
}

test "decode accepts bytes that standard base64 would spell differently" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // 0xFB 0xEF encodes as `++8` in standard base64 and `--8` in base64url. A
    // standard decoder rejects the url-safe spelling outright.
    const bytes = try decode(arena.allocator(), "--8");
    try std.testing.expectEqualSlices(u8, &.{ 0xFB, 0xEF }, bytes);

    const underscore = try decode(arena.allocator(), "_w");
    try std.testing.expectEqualSlices(u8, &.{0xFF}, underscore);
}

test "decode rejects padding and invalid characters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.InvalidEncoding, decode(arena.allocator(), "aGk="));
    try std.testing.expectError(error.InvalidEncoding, decode(arena.allocator(), "a+b"));
    try std.testing.expectError(error.InvalidEncoding, decode(arena.allocator(), "a/b"));
    try std.testing.expectError(error.InvalidEncoding, decode(arena.allocator(), "a b"));
    // A single trailing character cannot be a whole byte.
    try std.testing.expectError(error.InvalidEncoding, decode(arena.allocator(), "a"));
}

test "decode of an empty string is empty" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("", try decode(arena.allocator(), ""));
}

test "decodeInto bounds its output" {
    var small: [1]u8 = undefined;
    try std.testing.expectError(error.InvalidEncoding, decodeInto(&small, "aGVsbG8"));

    var big: [8]u8 = undefined;
    try std.testing.expectEqualStrings("hello", try decodeInto(&big, "aGVsbG8"));
}

test "decodeExact requires the algorithm's exact size" {
    // A 32-byte P-256 coordinate.
    const thirty_two = try decodeExact(32, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    try std.testing.expectEqual(@as(usize, 32), thirty_two.len);

    // A short value must not be accepted and silently zero-extended.
    try std.testing.expectError(error.InvalidEncoding, decodeExact(32, "AAAA"));
    try std.testing.expectError(error.InvalidEncoding, decodeExact(32, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

test "encode round-trips through decode" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_][]const u8{
        "",
        "h",
        "hi",
        "hello",
        &.{ 0xFB, 0xEF, 0xFF, 0x00 },
        "{\"alg\":\"ES256\"}",
    };
    for (cases) |case| {
        const encoded = try encode(arena.allocator(), case);
        // Never padded, never outside the url-safe alphabet.
        try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '=') == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '+') == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '/') == null);
        try std.testing.expectEqualStrings(case, try decode(arena.allocator(), encoded));
    }
}

test "fuzz decode" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [256]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            const decoded = decode(arena.allocator(), buffer[0..length]) catch return;
            // A successful decode must shrink: 4 encoded characters carry 3 bytes.
            try std.testing.expect(decoded.len <= length);
        }
    }.run, .{});
}
