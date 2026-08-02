//! Sealed `requestState` for multi-round-trip requests.
//!
//! MRTR keeps a server stateless by handing its resume state to the client and
//! having the client echo it back. That is what makes the pattern work behind a
//! load balancer with no shared storage — and it is also why the state arrives back
//! as attacker-controlled input. The specification is explicit: a `requestState`
//! that influences authorization, resource access or business logic MUST be
//! integrity-protected and state that fails verification MUST be rejected.
//!
//! This is that protection. A `Sealer` wraps the server's own opaque state in an
//! authenticated envelope binding it to:
//!
//!   * the authenticated principal, so one user cannot present another's state;
//!   * an expiry, so a captured state stops working;
//!   * the method and a digest of the request's salient parameters, so state issued
//!     for one operation cannot be replayed onto a different one.
//!
//! Those three are exactly what the spec asks servers to include and verify. What it
//! does *not* provide is single use: bounding the replay window is not the same as
//! preventing replay, and a server whose state must be redeemed once — a one-time
//! payment, say — has to enforce that itself with storage. `verify` cannot do it,
//! and pretending otherwise would be worse than saying so.
//!
//! ## Why HMAC and not encryption
//!
//! The threat is tampering, not disclosure: the client already saw the request it
//! is resuming. Authentication alone is the smaller mechanism that solves the stated
//! problem. A server that genuinely needs the payload hidden should encrypt its own
//! state before sealing it, which composes with this without changing anything here.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64 = std.base64.url_safe_no_pad;

/// Envelope format version, so a key rotation or format change is detectable rather
/// than silently misparsed.
const format_version: u8 = 1;

const digest_length = Sha256.digest_length;
const mac_length = Hmac.mac_length;

/// Upper bounds on the variable-length fields. They exist so that a sealed token has
/// a bounded size and `verify` can reject an oversized one before allocating.
pub const principal_max = 512;
pub const method_max = 128;
pub const state_max = 8 * 1024;

/// The largest envelope a `Sealer` will produce or accept, before base64.
pub const envelope_max =
    1 + 8 + // version, expiry
    2 + principal_max +
    2 + method_max +
    2 + state_max +
    digest_length + mac_length;

/// What a sealed state carries.
pub const Payload = struct {
    /// The authenticated principal the state belongs to — typically the `sub` claim
    /// of the access token. Empty is allowed for transports without authorization,
    /// where there is no principal to bind to.
    principal: []const u8 = "",
    /// The request method the state was issued for.
    method: []const u8,
    /// The server's own state. Opaque to everything here.
    state: []const u8,
    /// Unix seconds after which the state is no longer accepted.
    expires_at: i64,
    /// Digest of the request parameters the state is bound to.
    params_digest: [digest_length]u8 = @splat(0),
};

pub const SealError = error{
    /// A field exceeded its bound.
    TooLong,
    OutOfMemory,
};

pub const VerifyError = error{
    /// Not a well-formed envelope: wrong length, wrong version, bad base64.
    Malformed,
    /// The MAC did not match. The state was tampered with, or was sealed with a
    /// different key.
    BadSignature,
    /// The state is past its expiry.
    Expired,
    /// The state belongs to a different principal. This is the cross-user replay the
    /// spec calls out.
    WrongPrincipal,
    /// The state was issued for a different request.
    WrongRequest,
    OutOfMemory,
};

/// What `verify` must check the payload against.
///
/// These are required rather than optional so that a caller cannot skip a check by
/// forgetting it. A server with no principal passes an empty one, which still has to
/// match what was sealed.
pub const Expectations = struct {
    principal: []const u8 = "",
    method: []const u8,
    params_digest: [digest_length]u8 = @splat(0),
    /// Current time in Unix seconds. Passed in rather than read from a clock so that
    /// expiry is testable and this module needs no `Io`.
    now: i64,
};

pub const Sealer = struct {
    key: [Hmac.key_length]u8,

    /// Derives a sealer from arbitrary key material.
    ///
    /// Hashing rather than truncating means a short or low-entropy secret still
    /// produces a full-width key, and a caller cannot accidentally supply a key
    /// shorter than the MAC expects.
    pub fn init(secret: []const u8) Sealer {
        assert(secret.len > 0);
        var key: [Hmac.key_length]u8 = undefined;
        Sha256.hash(secret, &key, .{});
        return .{ .key = key };
    }

    /// Generates a fresh random key, for a server that does not need its state to
    /// survive a restart.
    ///
    /// Takes an `Io` because entropy comes from the operating system, and 0.16 is
    /// right to treat that as I/O rather than something a pure function can do.
    ///
    /// Note the consequence: state sealed before a restart fails verification
    /// afterwards, so a client mid-flow gets a rejected retry rather than a wrong
    /// answer. That is the safe failure — but a server behind a load balancer needs a
    /// shared secret via `init`, because one instance cannot verify what another
    /// sealed.
    pub fn generate(io: std.Io) std.Io.RandomSecureError!Sealer {
        var key: [Hmac.key_length]u8 = undefined;
        try io.randomSecure(&key);
        return .{ .key = key };
    }

    /// Seals a payload into a token safe to put in JSON.
    pub fn seal(
        sealer: *const Sealer,
        arena: std.mem.Allocator,
        payload: Payload,
    ) SealError![]const u8 {
        if (payload.principal.len > principal_max) return error.TooLong;
        if (payload.method.len > method_max) return error.TooLong;
        if (payload.state.len > state_max) return error.TooLong;
        assert(payload.method.len > 0);

        var envelope: std.Io.Writer.Allocating = .init(arena);
        const writer = &envelope.writer;

        writeByte(writer, format_version) catch return error.OutOfMemory;
        writeInt(writer, payload.expires_at) catch return error.OutOfMemory;
        writeField(writer, payload.principal) catch return error.OutOfMemory;
        writeField(writer, payload.method) catch return error.OutOfMemory;
        writeField(writer, payload.state) catch return error.OutOfMemory;
        writer.writeAll(&payload.params_digest) catch return error.OutOfMemory;

        // The MAC covers everything above, so no field can be moved, resized or
        // swapped without detection.
        var mac: [mac_length]u8 = undefined;
        Hmac.create(&mac, envelope.written(), &sealer.key);
        writer.writeAll(&mac) catch return error.OutOfMemory;

        const bytes = envelope.written();
        const token = try arena.alloc(u8, base64.Encoder.calcSize(bytes.len));
        return base64.Encoder.encode(token, bytes);
    }

    /// Verifies a token and returns what was sealed.
    ///
    /// Every check is mandatory and they run in this order: format, then signature,
    /// then binding. Signature before binding matters — comparing an unauthenticated
    /// principal would leak whether a guess was right through the failure it
    /// produces.
    pub fn verify(
        sealer: *const Sealer,
        arena: std.mem.Allocator,
        token: []const u8,
        expected: Expectations,
    ) VerifyError!Payload {
        assert(expected.method.len > 0);

        const size = base64.Decoder.calcSizeForSlice(token) catch return error.Malformed;
        // Reject an oversized token before allocating for it: its length is chosen
        // by the peer.
        if (size > envelope_max) return error.Malformed;
        if (size < 1 + 8 + digest_length + mac_length) return error.Malformed;

        const envelope = try arena.alloc(u8, size);
        base64.Decoder.decode(envelope, token) catch return error.Malformed;

        const signed = envelope[0 .. envelope.len - mac_length];
        const presented = envelope[envelope.len - mac_length ..];

        var mac: [mac_length]u8 = undefined;
        Hmac.create(&mac, signed, &sealer.key);
        if (!equalConstantTime(&mac, presented)) return error.BadSignature;

        var cursor: Cursor = .{ .bytes = signed };
        if (try cursor.byte() != format_version) return error.Malformed;

        var payload: Payload = .{
            .method = "",
            .state = "",
            .expires_at = try cursor.int(),
        };
        payload.principal = try cursor.field();
        payload.method = try cursor.field();
        payload.state = try cursor.field();
        payload.params_digest = try cursor.digest();
        // Trailing bytes would mean the envelope is not what we wrote, even though
        // the MAC matched — which can only happen if our own writer and reader
        // disagree.
        if (!cursor.exhausted()) return error.Malformed;

        // Expiry before identity: a stale state is the ordinary case and deserves the
        // clearer error.
        if (expected.now > payload.expires_at) return error.Expired;
        if (!std.mem.eql(u8, payload.principal, expected.principal)) {
            return error.WrongPrincipal;
        }
        if (!std.mem.eql(u8, payload.method, expected.method)) return error.WrongRequest;
        if (!std.mem.eql(u8, &payload.params_digest, &expected.params_digest)) {
            return error.WrongRequest;
        }

        return payload;
    }
};

/// Digests the parameters a state is bound to.
///
/// Keys are visited in sorted order, so a client that reserialises the object with a
/// different field order still produces the same digest. Without that, a perfectly
/// well-behaved retry would be rejected as a replay.
pub fn digestParams(value: std.json.Value) [digest_length]u8 {
    var hasher: Sha256 = .init(.{});
    hashValue(&hasher, value);
    var digest: [digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Digests only the named keys of an object, for a server that wants to bind state to
/// the tool name but not to arguments the user is about to change.
pub fn digestFields(value: std.json.Value, keys: []const []const u8) [digest_length]u8 {
    var hasher: Sha256 = .init(.{});
    const object = switch (value) {
        .object => |object| object,
        else => {
            var digest: [digest_length]u8 = undefined;
            hasher.final(&digest);
            return digest;
        },
    };
    for (keys) |key| {
        hasher.update(key);
        hasher.update(":");
        if (object.get(key)) |found| hashValue(&hasher, found);
        hasher.update(";");
    }
    var digest: [digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Hashes a JSON value in a form that does not depend on key order.
///
/// Type tags are mixed in so that values of different types cannot collide: without
/// them the string `"1"` and the number `1` would hash alike, and so would an empty
/// array and an empty object.
fn hashValue(hasher: *Sha256, value: std.json.Value) void {
    switch (value) {
        .null => hasher.update("n"),
        .bool => |flag| hasher.update(if (flag) "b1" else "b0"),
        .integer => |integer| {
            hasher.update("i");
            var buffer: [8]u8 = undefined;
            std.mem.writeInt(i64, &buffer, integer, .big);
            hasher.update(&buffer);
        },
        .float => |float| {
            hasher.update("f");
            var buffer: [8]u8 = undefined;
            std.mem.writeInt(u64, &buffer, @bitCast(float), .big);
            hasher.update(&buffer);
        },
        .number_string => |text| {
            hasher.update("N");
            hasher.update(text);
        },
        .string => |text| {
            hasher.update("s");
            hashLength(hasher, text.len);
            hasher.update(text);
        },
        .array => |array| {
            hasher.update("a");
            hashLength(hasher, array.items.len);
            for (array.items) |item| hashValue(hasher, item);
        },
        .object => |object| {
            hasher.update("o");
            hashLength(hasher, object.count());

            // Sorted key order is what makes the digest independent of how the peer
            // serialised the object. `std.json.ObjectMap` preserves insertion order,
            // so without sorting the digest would depend on the wire.
            var indices: [object_keys_max]u32 = undefined;
            const count = @min(object.count(), object_keys_max);
            for (0..count) |index| indices[index] = @intCast(index);

            const keys = object.keys();
            std.mem.sort(u32, indices[0..count], keys, struct {
                fn lessThan(all: []const []const u8, a: u32, b: u32) bool {
                    return std.mem.order(u8, all[a], all[b]) == .lt;
                }
            }.lessThan);

            for (indices[0..count]) |index| {
                const key = keys[index];
                hashLength(hasher, key.len);
                hasher.update(key);
                hashValue(hasher, object.values()[index]);
            }
        },
    }
}

/// Bound on how many keys of one object contribute to a digest.
///
/// A cap is needed because sorting happens on the stack. Objects larger than this
/// hash only their first keys, which weakens binding but cannot break it: the digest
/// stays deterministic, and a request with that many top-level parameters is outside
/// what this protocol carries.
const object_keys_max = 256;

fn hashLength(hasher: *Sha256, length: usize) void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, length, .big);
    hasher.update(&buffer);
}

/// Compares in time independent of where the first difference is.
///
/// A byte-by-byte early return would let an attacker recover a valid MAC one byte at
/// a time by timing the rejection.
fn equalConstantTime(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |x, y| difference |= x ^ y;
    return difference == 0;
}

fn writeByte(writer: *std.Io.Writer, byte: u8) std.Io.Writer.Error!void {
    try writer.writeByte(byte);
}

fn writeInt(writer: *std.Io.Writer, value: i64) std.Io.Writer.Error!void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(i64, &buffer, value, .big);
    try writer.writeAll(&buffer);
}

fn writeField(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    assert(bytes.len <= std.math.maxInt(u16));
    var length: [2]u8 = undefined;
    std.mem.writeInt(u16, &length, @intCast(bytes.len), .big);
    try writer.writeAll(&length);
    try writer.writeAll(bytes);
}

/// Reads the envelope back. Every accessor checks the bound first, so a truncated or
/// hostile length prefix produces `Malformed` rather than a read past the end.
const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    fn byte(cursor: *Cursor) error{Malformed}!u8 {
        if (cursor.position + 1 > cursor.bytes.len) return error.Malformed;
        defer cursor.position += 1;
        return cursor.bytes[cursor.position];
    }

    fn int(cursor: *Cursor) error{Malformed}!i64 {
        if (cursor.position + 8 > cursor.bytes.len) return error.Malformed;
        defer cursor.position += 8;
        return std.mem.readInt(i64, cursor.bytes[cursor.position..][0..8], .big);
    }

    fn field(cursor: *Cursor) error{Malformed}![]const u8 {
        if (cursor.position + 2 > cursor.bytes.len) return error.Malformed;
        const length = std.mem.readInt(u16, cursor.bytes[cursor.position..][0..2], .big);
        cursor.position += 2;
        if (cursor.position + length > cursor.bytes.len) return error.Malformed;
        defer cursor.position += length;
        return cursor.bytes[cursor.position..][0..length];
    }

    fn digest(cursor: *Cursor) error{Malformed}![digest_length]u8 {
        if (cursor.position + digest_length > cursor.bytes.len) return error.Malformed;
        defer cursor.position += digest_length;
        return cursor.bytes[cursor.position..][0..digest_length].*;
    }

    fn exhausted(cursor: *const Cursor) bool {
        return cursor.position == cursor.bytes.len;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn arenaFor(instance: *std.heap.ArenaAllocator) std.mem.Allocator {
    instance.* = .init(testing.allocator);
    return instance.allocator();
}

test "a sealed state round-trips" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("server secret");
    const token = try sealer.seal(arena, .{
        .principal = "user-42",
        .method = "tools/call",
        .state = "{\"step\":2}",
        .expires_at = 1_000,
    });

    // The token is safe to put in a JSON string as-is.
    for (token) |byte| try testing.expect(byte != '"' and byte != '\\' and byte > 0x20);

    const opened = try sealer.verify(arena, token, .{
        .principal = "user-42",
        .method = "tools/call",
        .now = 900,
    });
    try testing.expectEqualStrings("user-42", opened.principal);
    try testing.expectEqualStrings("tools/call", opened.method);
    try testing.expectEqualStrings("{\"step\":2}", opened.state);
    try testing.expectEqual(@as(i64, 1_000), opened.expires_at);
}

test "any modification to a token is rejected" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("server secret");
    const token = try sealer.seal(arena, .{
        .principal = "user-42",
        .method = "tools/call",
        .state = "authorized=true",
        .expires_at = 1_000,
    });

    // Flipping any single character must fail, not just characters in the MAC: the
    // whole envelope is signed.
    for (0..token.len) |index| {
        const tampered = try arena.dupe(u8, token);
        tampered[index] = if (tampered[index] == 'A') 'B' else 'A';

        const result = sealer.verify(arena, tampered, .{
            .principal = "user-42",
            .method = "tools/call",
            .now = 900,
        });
        try testing.expect(std.meta.isError(result));
    }
}

test "a token from a different key is rejected" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const mine: Sealer = .init("my secret");
    const theirs: Sealer = .init("their secret");

    const token = try theirs.seal(arena, .{
        .method = "tools/call",
        .state = "x",
        .expires_at = 1_000,
    });
    try testing.expectError(error.BadSignature, mine.verify(arena, token, .{
        .method = "tools/call",
        .now = 1,
    }));
}

test "an expired token is rejected" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("secret");
    const token = try sealer.seal(arena, .{
        .method = "tools/call",
        .state = "x",
        .expires_at = 1_000,
    });

    // Exactly at the expiry is still valid; one second later is not.
    _ = try sealer.verify(arena, token, .{ .method = "tools/call", .now = 1_000 });
    try testing.expectError(error.Expired, sealer.verify(arena, token, .{
        .method = "tools/call",
        .now = 1_001,
    }));
}

test "one principal cannot present another's state" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("secret");
    const token = try sealer.seal(arena, .{
        .principal = "alice",
        .method = "tools/call",
        .state = "alice's pending payment",
        .expires_at = 1_000,
    });

    // This is the cross-user replay the spec calls out: Bob presenting Alice's state.
    try testing.expectError(error.WrongPrincipal, sealer.verify(arena, token, .{
        .principal = "bob",
        .method = "tools/call",
        .now = 1,
    }));
    // And an unauthenticated caller cannot present it either.
    try testing.expectError(error.WrongPrincipal, sealer.verify(arena, token, .{
        .method = "tools/call",
        .now = 1,
    }));
}

test "state issued for one method cannot be replayed onto another" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("secret");
    const token = try sealer.seal(arena, .{
        .method = "tools/call",
        .state = "x",
        .expires_at = 1_000,
    });
    try testing.expectError(error.WrongRequest, sealer.verify(arena, token, .{
        .method = "resources/read",
        .now = 1,
    }));
}

test "state is bound to the parameters it was issued for" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    var original: std.json.ObjectMap = .empty;
    try original.put(arena, "name", .{ .string = "transfer_funds" });
    try original.put(arena, "amount", .{ .integer = 10 });

    var altered: std.json.ObjectMap = .empty;
    try altered.put(arena, "name", .{ .string = "transfer_funds" });
    try altered.put(arena, "amount", .{ .integer = 10_000 });

    const sealer: Sealer = .init("secret");
    const token = try sealer.seal(arena, .{
        .method = "tools/call",
        .state = "approved",
        .expires_at = 1_000,
        .params_digest = digestParams(.{ .object = original }),
    });

    // Approving a small transfer must not approve a large one.
    try testing.expectError(error.WrongRequest, sealer.verify(arena, token, .{
        .method = "tools/call",
        .now = 1,
        .params_digest = digestParams(.{ .object = altered }),
    }));
    _ = try sealer.verify(arena, token, .{
        .method = "tools/call",
        .now = 1,
        .params_digest = digestParams(.{ .object = original }),
    });
}

test "the parameter digest ignores key order" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    var first: std.json.ObjectMap = .empty;
    try first.put(arena, "a", .{ .integer = 1 });
    try first.put(arena, "b", .{ .string = "two" });

    var second: std.json.ObjectMap = .empty;
    try second.put(arena, "b", .{ .string = "two" });
    try second.put(arena, "a", .{ .integer = 1 });

    // A client that reserialises the object is well-behaved; rejecting it as a replay
    // would be a bug in us.
    try testing.expectEqual(
        digestParams(.{ .object = first }),
        digestParams(.{ .object = second }),
    );
}

test "the parameter digest distinguishes values of different types" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const array: std.json.Array = .init(arena);

    const cases = [_]std.json.Value{
        .{ .integer = 1 },
        .{ .string = "1" },
        .{ .bool = true },
        .{ .null = {} },
        .{ .array = array },
        .{ .object = .empty },
    };
    for (cases, 0..) |a, i| {
        for (cases, 0..) |b, j| {
            if (i == j) continue;
            try testing.expect(!std.mem.eql(u8, &digestParams(a), &digestParams(b)));
        }
    }
}

test "the parameter digest distinguishes concatenation-ambiguous strings" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    var first: std.json.ObjectMap = .empty;
    try first.put(arena, "a", .{ .string = "bc" });

    var second: std.json.ObjectMap = .empty;
    try second.put(arena, "ab", .{ .string = "c" });

    // Length prefixes are what keep these apart; without them both hash "abc".
    try testing.expect(!std.mem.eql(
        u8,
        &digestParams(.{ .object = first }),
        &digestParams(.{ .object = second }),
    ));
}

test "digestFields binds only the named keys" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    var before: std.json.ObjectMap = .empty;
    try before.put(arena, "name", .{ .string = "book_flight" });
    try before.put(arena, "seat", .{ .string = "12A" });

    var after: std.json.ObjectMap = .empty;
    try after.put(arena, "name", .{ .string = "book_flight" });
    try after.put(arena, "seat", .{ .string = "14C" });

    // Binding to the tool name but not the seat lets the user change their mind
    // mid-flow without invalidating the state.
    const keys = [_][]const u8{"name"};
    try testing.expectEqual(
        digestFields(.{ .object = before }, &keys),
        digestFields(.{ .object = after }, &keys),
    );
    try testing.expect(!std.mem.eql(
        u8,
        &digestParams(.{ .object = before }),
        &digestParams(.{ .object = after }),
    ));
}

test "malformed tokens are rejected rather than misread" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("secret");
    for ([_][]const u8{
        "",
        "!!!not base64!!!",
        "AAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }) |token| {
        const result = sealer.verify(arena, token, .{ .method = "tools/call", .now = 1 });
        try testing.expect(std.meta.isError(result));
    }
}

test "an oversized token is refused before it is allocated for" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    // The peer chooses this length, so it must be bounded.
    const huge = try testing.allocator.alloc(u8, envelope_max * 2);
    defer testing.allocator.free(huge);
    @memset(huge, 'A');

    const sealer: Sealer = .init("secret");
    try testing.expectError(error.Malformed, sealer.verify(arena, huge, .{
        .method = "tools/call",
        .now = 1,
    }));
}

test "sealing refuses fields beyond their bounds" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    const sealer: Sealer = .init("secret");

    const long = try arena.alloc(u8, state_max + 1);
    @memset(long, 'x');
    try testing.expectError(error.TooLong, sealer.seal(arena, .{
        .method = "tools/call",
        .state = long,
        .expires_at = 1,
    }));

    const long_principal = try arena.alloc(u8, principal_max + 1);
    @memset(long_principal, 'x');
    try testing.expectError(error.TooLong, sealer.seal(arena, .{
        .principal = long_principal,
        .method = "tools/call",
        .state = "x",
        .expires_at = 1,
    }));
}

test "an empty state and an empty principal are allowed" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    // A transport without authorization has no principal to bind to, and a server may
    // need only "the client retried" rather than any state of its own.
    const sealer: Sealer = .init("secret");
    const token = try sealer.seal(arena, .{
        .method = "resources/read",
        .state = "",
        .expires_at = 1_000,
    });
    const opened = try sealer.verify(arena, token, .{
        .method = "resources/read",
        .now = 1,
    });
    try testing.expectEqualStrings("", opened.principal);
    try testing.expectEqualStrings("", opened.state);
}

test "two generated sealers cannot read each other's state" {
    var instance: std.heap.ArenaAllocator = undefined;
    const arena = arenaFor(&instance);
    defer instance.deinit();

    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The consequence worth knowing: a restarted server rejects state it issued
    // before, so a shared secret is required behind a load balancer.
    const before: Sealer = try .generate(io);
    const after: Sealer = try .generate(io);

    const token = try before.seal(arena, .{
        .method = "tools/call",
        .state = "x",
        .expires_at = 1_000,
    });
    try testing.expectError(error.BadSignature, after.verify(arena, token, .{
        .method = "tools/call",
        .now = 1,
    }));
}

test "fuzz verification against arbitrary tokens" {
    const Fuzz = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var instance: std.heap.ArenaAllocator = .init(testing.allocator);
            defer instance.deinit();

            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);

            const sealer: Sealer = .init("secret");
            // No input may be accepted, and none may crash.
            const result = sealer.verify(instance.allocator(), buffer[0..length], .{
                .method = "tools/call",
                .now = 1,
            });
            try testing.expect(std.meta.isError(result));
        }
    };
    try testing.fuzz(Fuzz{}, Fuzz.testOne, .{});
}
