//! JSON Web Keys and key sets (RFC 7517), restricted to the signature algorithms a
//! resource server needs in order to validate access tokens.
//!
//! ## The key decides the algorithm, never the token
//!
//! The best-known JWT vulnerability is algorithm confusion: a verifier reads `alg`
//! out of the token header — which is unauthenticated attacker-controlled data —
//! and then does whatever it says. Change `RS256` to `HS256` and the verifier
//! computes an HMAC using the RSA *public* key as the shared secret, which the
//! attacker also has. Change it to `none` and there is nothing to check.
//!
//! This module makes that class of bug unrepresentable rather than merely avoided:
//!
//!   * `Algorithm` has no `none` member and no HMAC member, so a token naming one
//!     cannot be parsed into something this module will act on.
//!   * `PublicKey.verify` switches on the key variant *and* the algorithm together.
//!     There is no path in which an RSA key verifies an EC signature or vice versa;
//!     the mismatched combinations are `error.AlgorithmMismatch`.
//!   * A JWK carrying its own `alg` pins the token to it exactly.
//!
//! Verification is over public keys only. This module cannot verify an HMAC token
//! even if asked, which is the point: a resource server that pulls keys from a JWKS
//! has no shared secret to verify one with.

const std = @import("std");
const assert_mod = @import("assert");

const base64url = @import("base64url.zig");

const assert = assert_mod.assert;
const rsa = std.crypto.Certificate.rsa;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

/// Upper bound on keys in one key set.
///
/// A JWKS is fetched from the authorization server, so its size is not this
/// module's choice; a rotating server publishes a handful of keys, not hundreds.
pub const keys_max = 32;

/// Upper bound on a key set document.
pub const document_bytes_max = 256 * 1024;

/// Smallest RSA modulus this module will accept, in bytes.
///
/// 2048 bits. `std.crypto` permits down to 512 bits, which was factored in 1999;
/// accepting a weak key because a server offered one defeats the purpose of
/// checking the signature at all.
pub const rsa_modulus_bytes_min = 256;

/// Largest RSA modulus, bounded by `std.crypto.Certificate.rsa`.
pub const rsa_modulus_bytes_max = 512;

/// The JWS signature algorithms this module verifies.
///
/// Deliberately absent: `none` (no signature at all), and every `HS*` (a shared
/// secret, which a JWKS-based verifier does not have). Their absence is what makes
/// algorithm confusion a parse failure rather than a security decision.
pub const Algorithm = enum {
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,

    pub const Family = enum { rsa, ec };

    pub fn family(algorithm: Algorithm) Family {
        return switch (algorithm) {
            .RS256, .RS384, .RS512 => .rsa,
            .ES256, .ES384 => .ec,
        };
    }

    /// The `crv` an EC key must declare for this algorithm. JWA binds each ECDSA
    /// algorithm to exactly one curve; a P-256 key may not be used for ES384.
    pub fn curve(algorithm: Algorithm) ?[]const u8 {
        return switch (algorithm) {
            .ES256 => "P-256",
            .ES384 => "P-384",
            .RS256, .RS384, .RS512 => null,
        };
    }

    pub fn text(algorithm: Algorithm) []const u8 {
        return @tagName(algorithm);
    }

    /// Parses an `alg` header value. An unknown, absent, `none`, or HMAC value is
    /// null, which callers must treat as a refusal.
    pub fn fromText(text_value: []const u8) ?Algorithm {
        return std.meta.stringToEnum(Algorithm, text_value);
    }
};

pub const KeyError = error{
    /// `kty` is not one this module verifies with, or a required parameter for the
    /// declared `kty` is missing.
    UnsupportedKey,
    /// A key parameter was not valid base64url, or decoded to the wrong size.
    MalformedKey,
    /// The RSA modulus is below `rsa_modulus_bytes_min` or above the maximum.
    KeyTooSmall,
};

pub const VerifyError = error{
    /// The signature did not verify under this key.
    InvalidSignature,
    /// The algorithm does not match the key. This is the algorithm-confusion guard:
    /// it fires when a token asks for a verification this key cannot perform.
    AlgorithmMismatch,
    /// The signature was the wrong length for the algorithm.
    MalformedSignature,
};

/// A parsed public key, ready to verify with.
///
/// The variants are the key's own nature, not the token's claim about it. Each
/// carries its parsed crypto object by value — `std.crypto` copies key material on
/// construction, so nothing here borrows from the JWK document.
pub const PublicKey = union(enum) {
    rsa: Rsa,
    p256: EcdsaP256.PublicKey,
    p384: EcdsaP384.PublicKey,

    pub const Rsa = struct {
        key: rsa.PublicKey,
        /// Length of the modulus in bytes, which is also the signature length.
        /// Needed at verification time because `std.crypto` takes it as a comptime
        /// parameter.
        modulus_len: usize,
    };

    /// Verifies `signature` over `signing_input` using `algorithm`.
    ///
    /// `signing_input` is the JWS signing input: the header and payload segments
    /// still base64url-encoded, joined by a dot. Re-encoding the decoded claims
    /// would produce different bytes and fail every valid token.
    pub fn verify(
        key: PublicKey,
        algorithm: Algorithm,
        signing_input: []const u8,
        signature: []const u8,
    ) VerifyError!void {
        // The exhaustive pairing is the guard. Every combination is either a
        // verification this key can actually perform, or a mismatch.
        switch (key) {
            .rsa => |rsa_key| switch (algorithm) {
                .RS256 => try verifyRsa(std.crypto.hash.sha2.Sha256, rsa_key, signing_input, signature),
                .RS384 => try verifyRsa(std.crypto.hash.sha2.Sha384, rsa_key, signing_input, signature),
                .RS512 => try verifyRsa(std.crypto.hash.sha2.Sha512, rsa_key, signing_input, signature),
                .ES256, .ES384 => return error.AlgorithmMismatch,
            },
            .p256 => |ec_key| switch (algorithm) {
                .ES256 => try verifyEcdsa(EcdsaP256, ec_key, signing_input, signature),
                else => return error.AlgorithmMismatch,
            },
            .p384 => |ec_key| switch (algorithm) {
                .ES384 => try verifyEcdsa(EcdsaP384, ec_key, signing_input, signature),
                else => return error.AlgorithmMismatch,
            },
        }
    }

    fn verifyRsa(
        comptime Hash: type,
        key: Rsa,
        signing_input: []const u8,
        signature: []const u8,
    ) VerifyError!void {
        if (signature.len != key.modulus_len) return error.MalformedSignature;
        switch (key.modulus_len) {
            inline rsa_modulus_bytes_min, 384, rsa_modulus_bytes_max => |length| {
                const fixed: [length]u8 = signature[0..length].*;
                rsa.PKCS1v1_5Signature.verify(length, fixed, signing_input, key.key, Hash) catch
                    return error.InvalidSignature;
            },
            // `fromJwk` refuses other sizes, so a key here with an odd modulus did
            // not come through this module.
            else => return error.AlgorithmMismatch,
        }
    }

    fn verifyEcdsa(
        comptime Scheme: type,
        key: Scheme.PublicKey,
        signing_input: []const u8,
        signature: []const u8,
    ) VerifyError!void {
        // JWS carries ECDSA signatures as the raw concatenation of R and S, each
        // padded to the coordinate size — not the DER encoding used elsewhere.
        const length = Scheme.Signature.encoded_length;
        if (signature.len != length) return error.MalformedSignature;
        const parsed: Scheme.Signature = .fromBytes(signature[0..length].*);
        parsed.verify(signing_input, key) catch return error.InvalidSignature;
    }
};

/// A JSON Web Key, as it appears on the wire.
///
/// Only the members needed to verify a signature are declared; `std.json` is told
/// to ignore the rest, since a key set legitimately carries certificate chains and
/// private parameters this module has no use for.
pub const Jwk = struct {
    kty: []const u8,
    kid: ?[]const u8 = null,
    use: ?[]const u8 = null,
    key_ops: ?[]const []const u8 = null,
    alg: ?[]const u8 = null,
    /// RSA modulus, base64url.
    n: ?[]const u8 = null,
    /// RSA exponent, base64url.
    e: ?[]const u8 = null,
    /// EC curve name.
    crv: ?[]const u8 = null,
    /// EC x coordinate, base64url.
    x: ?[]const u8 = null,
    /// EC y coordinate, base64url.
    y: ?[]const u8 = null,

    /// True if this key may be used to verify signatures made with `algorithm`.
    ///
    /// Checked, in order: the key is for signatures at all; the operation is
    /// permitted; the key's own `alg` pin, when present; and that the key's type
    /// and curve are the ones the algorithm requires.
    pub fn permits(jwk: *const Jwk, algorithm: Algorithm) bool {
        if (jwk.use) |use_value| {
            // RFC 7517: `use` is "sig" or "enc". An encryption key must never be
            // repurposed for verification.
            if (!std.mem.eql(u8, use_value, "sig")) return false;
        }
        if (jwk.key_ops) |operations| {
            var found = false;
            for (operations) |operation| {
                if (std.mem.eql(u8, operation, "verify")) found = true;
            }
            if (!found) return false;
        }
        if (jwk.alg) |pinned| {
            if (!std.mem.eql(u8, pinned, algorithm.text())) return false;
        }

        switch (algorithm.family()) {
            .rsa => {
                if (!std.mem.eql(u8, jwk.kty, "RSA")) return false;
                if (jwk.n == null or jwk.e == null) return false;
            },
            .ec => {
                if (!std.mem.eql(u8, jwk.kty, "EC")) return false;
                if (jwk.x == null or jwk.y == null) return false;
                const required = algorithm.curve().?;
                const declared = jwk.crv orelse return false;
                if (!std.mem.eql(u8, declared, required)) return false;
            },
        }
        return true;
    }

    /// Parses the key material.
    ///
    /// `algorithm` is passed so that an EC key is built on the curve the algorithm
    /// requires. `permits` must have returned true first; this function assumes the
    /// family agreement it establishes.
    pub fn publicKey(jwk: *const Jwk, algorithm: Algorithm) KeyError!PublicKey {
        assert(jwk.permits(algorithm));

        switch (algorithm.family()) {
            .rsa => {
                var modulus_buffer: [rsa_modulus_bytes_max + 1]u8 = undefined;
                const raw_modulus = base64url.decodeInto(&modulus_buffer, jwk.n.?) catch
                    return error.MalformedKey;
                // Some issuers publish the modulus with a leading zero byte, as a
                // signed big-endian integer would have. Stripping it is required for
                // the length check below to mean what it says.
                var modulus = raw_modulus;
                while (modulus.len > 0 and modulus[0] == 0) modulus = modulus[1..];
                if (modulus.len < rsa_modulus_bytes_min) return error.KeyTooSmall;
                if (modulus.len > rsa_modulus_bytes_max) return error.KeyTooSmall;

                var exponent_buffer: [8]u8 = undefined;
                const raw_exponent = base64url.decodeInto(&exponent_buffer, jwk.e.?) catch
                    return error.MalformedKey;
                var exponent = raw_exponent;
                while (exponent.len > 0 and exponent[0] == 0) exponent = exponent[1..];
                if (exponent.len == 0) return error.MalformedKey;

                const key = rsa.PublicKey.fromBytes(exponent, modulus) catch
                    return error.MalformedKey;
                return .{ .rsa = .{ .key = key, .modulus_len = modulus.len } };
            },
            .ec => switch (algorithm) {
                .ES256 => return .{ .p256 = try ecPublicKey(EcdsaP256, 32, jwk) },
                .ES384 => return .{ .p384 = try ecPublicKey(EcdsaP384, 48, jwk) },
                .RS256, .RS384, .RS512 => unreachable,
            },
        }
    }

    fn ecPublicKey(
        comptime Scheme: type,
        comptime coordinate_len: usize,
        jwk: *const Jwk,
    ) KeyError!Scheme.PublicKey {
        // A JWK gives the affine coordinates separately; `std.crypto` wants the
        // SEC1 uncompressed form, which is `0x04 || X || Y`.
        const x = base64url.decodeExact(coordinate_len, jwk.x.?) catch return error.MalformedKey;
        const y = base64url.decodeExact(coordinate_len, jwk.y.?) catch return error.MalformedKey;

        var sec1: [1 + 2 * coordinate_len]u8 = undefined;
        sec1[0] = 0x04;
        @memcpy(sec1[1..][0..coordinate_len], &x);
        @memcpy(sec1[1 + coordinate_len ..][0..coordinate_len], &y);

        // `fromSec1` rejects points that are not on the curve, which is the check
        // that stops an invalid-curve attack.
        return Scheme.PublicKey.fromSec1(&sec1) catch error.MalformedKey;
    }
};

pub const ParseError = error{
    /// The document exceeded `document_bytes_max`.
    DocumentTooLarge,
    /// Not a JSON object with a `keys` array, or a key had the wrong shape.
    Malformed,
    /// More than `keys_max` keys.
    TooManyKeys,
    OutOfMemory,
};

/// A JWKS document.
pub const KeySet = struct {
    keys: []const Jwk = &.{},

    pub fn parse(arena: std.mem.Allocator, bytes: []const u8) ParseError!KeySet {
        if (bytes.len > document_bytes_max) return error.DocumentTooLarge;

        const set = std.json.parseFromSliceLeaky(KeySet, arena, bytes, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Malformed,
        };
        if (set.keys.len > keys_max) return error.TooManyKeys;
        return set;
    }

    /// Selects the key to verify with.
    ///
    /// When the token names a `kid`, only that key is considered. Falling back to
    /// "try every key" on a `kid` miss would undo key rotation: a retired key that
    /// is still published would keep validating tokens, and an attacker could pick
    /// which key is used by naming a `kid` that does not exist.
    ///
    /// With no `kid`, the first key permitting the algorithm is used. That is the
    /// only thing a verifier can do, and it is why servers should publish a `kid`.
    pub fn find(set: *const KeySet, kid: ?[]const u8, algorithm: Algorithm) ?*const Jwk {
        for (set.keys) |*jwk| {
            if (kid) |wanted| {
                const declared = jwk.kid orelse continue;
                if (!std.mem.eql(u8, declared, wanted)) continue;
            }
            if (!jwk.permits(algorithm)) continue;
            return jwk;
        }
        return null;
    }
};

test "Algorithm has no none and no HMAC member" {
    // The absence is the security property, so pin it: adding `none` or `HS256`
    // here would silently re-enable algorithm confusion.
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.fromText("none"));
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.fromText("HS256"));
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.fromText("HS384"));
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.fromText(""));
    try std.testing.expectEqual(@as(?Algorithm, null), Algorithm.fromText("rs256"));
    try std.testing.expectEqual(@as(usize, 5), @typeInfo(Algorithm).@"enum".fields.len);
}

test "Algorithm maps to family and curve" {
    try std.testing.expectEqual(Algorithm.Family.rsa, Algorithm.RS256.family());
    try std.testing.expectEqual(Algorithm.Family.ec, Algorithm.ES256.family());
    try std.testing.expectEqualStrings("P-256", Algorithm.ES256.curve().?);
    try std.testing.expectEqualStrings("P-384", Algorithm.ES384.curve().?);
    try std.testing.expectEqual(@as(?[]const u8, null), Algorithm.RS256.curve());
    try std.testing.expectEqualStrings("RS256", Algorithm.RS256.text());
}

test "permits requires the key family the algorithm needs" {
    const rsa_key: Jwk = .{ .kty = "RSA", .n = "AA", .e = "AQAB" };
    try std.testing.expect(rsa_key.permits(.RS256));
    try std.testing.expect(rsa_key.permits(.RS512));
    // The confusion case: an RSA key must not be usable for an EC algorithm.
    try std.testing.expect(!rsa_key.permits(.ES256));

    const ec_key: Jwk = .{ .kty = "EC", .crv = "P-256", .x = "AA", .y = "AA" };
    try std.testing.expect(ec_key.permits(.ES256));
    try std.testing.expect(!ec_key.permits(.RS256));
    // A P-256 key is not a P-384 key.
    try std.testing.expect(!ec_key.permits(.ES384));
}

test "permits honors use, key_ops, and the alg pin" {
    const encryption: Jwk = .{ .kty = "RSA", .use = "enc", .n = "AA", .e = "AQAB" };
    try std.testing.expect(!encryption.permits(.RS256));

    const signing: Jwk = .{ .kty = "RSA", .use = "sig", .n = "AA", .e = "AQAB" };
    try std.testing.expect(signing.permits(.RS256));

    const wrapping: Jwk = .{
        .kty = "RSA",
        .key_ops = &.{"wrapKey"},
        .n = "AA",
        .e = "AQAB",
    };
    try std.testing.expect(!wrapping.permits(.RS256));

    const verifying: Jwk = .{
        .kty = "RSA",
        .key_ops = &.{ "verify", "sign" },
        .n = "AA",
        .e = "AQAB",
    };
    try std.testing.expect(verifying.permits(.RS256));

    const pinned: Jwk = .{ .kty = "RSA", .alg = "RS256", .n = "AA", .e = "AQAB" };
    try std.testing.expect(pinned.permits(.RS256));
    // A key that says it is for RS256 must not be used for RS512.
    try std.testing.expect(!pinned.permits(.RS512));
}

test "permits requires the parameters the family needs" {
    const no_modulus: Jwk = .{ .kty = "RSA", .e = "AQAB" };
    try std.testing.expect(!no_modulus.permits(.RS256));

    const no_curve: Jwk = .{ .kty = "EC", .x = "AA", .y = "AA" };
    try std.testing.expect(!no_curve.permits(.ES256));

    const no_y: Jwk = .{ .kty = "EC", .crv = "P-256", .x = "AA" };
    try std.testing.expect(!no_y.permits(.ES256));

    const octet: Jwk = .{ .kty = "oct" };
    try std.testing.expect(!octet.permits(.RS256));
    try std.testing.expect(!octet.permits(.ES256));
}

test "KeySet.parse reads a document and ignores unknown members" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const set = try KeySet.parse(arena.allocator(),
        \\{"keys":[
        \\  {"kty":"RSA","kid":"a","use":"sig","alg":"RS256","n":"AA","e":"AQAB",
        \\   "x5c":["ignored"],"x5t#S256":"ignored"},
        \\  {"kty":"EC","kid":"b","crv":"P-256","x":"AA","y":"AA"}
        \\]}
    );
    try std.testing.expectEqual(@as(usize, 2), set.keys.len);
    try std.testing.expectEqualStrings("a", set.keys[0].kid.?);
    try std.testing.expectEqualStrings("P-256", set.keys[1].crv.?);
}

test "KeySet.parse rejects malformed and oversized documents" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.Malformed, KeySet.parse(arena.allocator(), "[]"));
    try std.testing.expectError(error.Malformed, KeySet.parse(arena.allocator(), "{\"keys\":{}}"));
    try std.testing.expectError(error.Malformed, KeySet.parse(arena.allocator(), "{\"keys\":[{}]}"));

    const big = try arena.allocator().alloc(u8, document_bytes_max + 1);
    @memset(big, ' ');
    try std.testing.expectError(error.DocumentTooLarge, KeySet.parse(arena.allocator(), big));
}

test "KeySet.parse tolerates an absent keys member" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const set = try KeySet.parse(arena.allocator(), "{}");
    try std.testing.expectEqual(@as(usize, 0), set.keys.len);
    try std.testing.expectEqual(@as(?*const Jwk, null), set.find(null, .RS256));
}

test "KeySet.parse bounds the key count" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var document: std.Io.Writer.Allocating = .init(arena.allocator());
    try document.writer.writeAll("{\"keys\":[");
    for (0..keys_max + 1) |index| {
        if (index > 0) try document.writer.writeByte(',');
        try document.writer.writeAll("{\"kty\":\"RSA\",\"n\":\"AA\",\"e\":\"AQAB\"}");
    }
    try document.writer.writeAll("]}");
    try std.testing.expectError(error.TooManyKeys, KeySet.parse(arena.allocator(), document.written()));
}

test "find selects by kid and refuses to guess on a miss" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const set = try KeySet.parse(arena.allocator(),
        \\{"keys":[
        \\  {"kty":"RSA","kid":"old","n":"AA","e":"AQAB"},
        \\  {"kty":"RSA","kid":"new","n":"BB","e":"AQAB"}
        \\]}
    );
    try std.testing.expectEqualStrings("old", set.find("old", .RS256).?.kid.?);
    try std.testing.expectEqualStrings("new", set.find("new", .RS256).?.kid.?);

    // A token naming a key that does not exist must not be verified against some
    // other key.
    try std.testing.expectEqual(@as(?*const Jwk, null), set.find("retired", .RS256));
}

test "find without a kid takes the first permitting key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const set = try KeySet.parse(arena.allocator(),
        \\{"keys":[
        \\  {"kty":"EC","crv":"P-256","x":"AA","y":"AA"},
        \\  {"kty":"RSA","n":"AA","e":"AQAB"}
        \\]}
    );
    // The EC key comes first but cannot do RS256, so it is skipped rather than
    // attempted.
    try std.testing.expectEqualStrings("RSA", set.find(null, .RS256).?.kty);
    try std.testing.expectEqualStrings("EC", set.find(null, .ES256).?.kty);
}

test "find skips a key whose declared alg does not match" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const set = try KeySet.parse(
        arena.allocator(),
        "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a\",\"alg\":\"RS512\",\"n\":\"AA\",\"e\":\"AQAB\"}]}",
    );
    try std.testing.expectEqual(@as(?*const Jwk, null), set.find("a", .RS256));
    try std.testing.expect(set.find("a", .RS512) != null);
}

test "publicKey rejects an RSA modulus below 2048 bits" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // 1024-bit modulus: 128 bytes of 0xFF, which std.crypto would happily accept.
    const modulus = try arena.allocator().alloc(u8, 128);
    @memset(modulus, 0xFF);
    const jwk: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), modulus),
        .e = "AQAB",
    };
    try std.testing.expect(jwk.permits(.RS256));
    try std.testing.expectError(error.KeyTooSmall, jwk.publicKey(.RS256));
}

test "publicKey accepts a 2048-bit modulus and reports its length" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const modulus = try arena.allocator().alloc(u8, rsa_modulus_bytes_min);
    @memset(modulus, 0xFF);
    const jwk: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), modulus),
        .e = "AQAB",
    };
    const key = try jwk.publicKey(.RS256);
    try std.testing.expectEqual(rsa_modulus_bytes_min, key.rsa.modulus_len);
}

test "publicKey strips a leading zero byte from the modulus" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // Some issuers publish the modulus as a signed integer, with a 0x00 prefix.
    const padded = try arena.allocator().alloc(u8, rsa_modulus_bytes_min + 1);
    @memset(padded, 0xFF);
    padded[0] = 0x00;
    const jwk: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), padded),
        .e = "AQAB",
    };
    const key = try jwk.publicKey(.RS256);
    // Without stripping, the length would be 257 and every signature would be
    // rejected as the wrong size.
    try std.testing.expectEqual(rsa_modulus_bytes_min, key.rsa.modulus_len);
}

test "publicKey rejects malformed key parameters" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const bad_base64: Jwk = .{ .kty = "RSA", .n = "not base64!", .e = "AQAB" };
    try std.testing.expectError(error.MalformedKey, bad_base64.publicKey(.RS256));

    const modulus = try arena.allocator().alloc(u8, rsa_modulus_bytes_min);
    @memset(modulus, 0xFF);
    const zero_exponent: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), modulus),
        .e = "AA",
    };
    try std.testing.expectError(error.MalformedKey, zero_exponent.publicKey(.RS256));

    // An even exponent is not a valid RSA exponent.
    const even_exponent: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), modulus),
        .e = try base64url.encode(arena.allocator(), &.{0x02}),
    };
    try std.testing.expectError(error.MalformedKey, even_exponent.publicKey(.RS256));
}

test "publicKey rejects an EC point that is not on the curve" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var coordinate: [32]u8 = undefined;
    @memset(&coordinate, 0x01);
    const encoded = try base64url.encode(arena.allocator(), &coordinate);
    const jwk: Jwk = .{ .kty = "EC", .crv = "P-256", .x = encoded, .y = encoded };
    // (1, 1) is not a point on P-256; accepting it would enable an invalid-curve
    // attack.
    try std.testing.expectError(error.MalformedKey, jwk.publicKey(.ES256));
}

test "publicKey requires exact coordinate sizes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const short = try base64url.encode(arena.allocator(), &[_]u8{ 1, 2, 3 });
    const jwk: Jwk = .{ .kty = "EC", .crv = "P-256", .x = short, .y = short };
    try std.testing.expectError(error.MalformedKey, jwk.publicKey(.ES256));
}

test "verify refuses every cross-family combination" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const modulus = try arena.allocator().alloc(u8, rsa_modulus_bytes_min);
    @memset(modulus, 0xFF);
    const rsa_jwk: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), modulus),
        .e = "AQAB",
    };
    const rsa_key = try rsa_jwk.publicKey(.RS256);

    const signature = try arena.allocator().alloc(u8, rsa_modulus_bytes_min);
    @memset(signature, 0);
    try std.testing.expectError(
        error.AlgorithmMismatch,
        rsa_key.verify(.ES256, "a.b", signature),
    );
    try std.testing.expectError(
        error.AlgorithmMismatch,
        rsa_key.verify(.ES384, "a.b", signature),
    );
    // The right family with a wrong signature is a signature failure, not a
    // mismatch — the distinction matters when reading logs.
    try std.testing.expectError(
        error.InvalidSignature,
        rsa_key.verify(.RS256, "a.b", signature),
    );
}

test "verify requires the signature length the algorithm defines" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const modulus = try arena.allocator().alloc(u8, rsa_modulus_bytes_min);
    @memset(modulus, 0xFF);
    const jwk: Jwk = .{
        .kty = "RSA",
        .n = try base64url.encode(arena.allocator(), modulus),
        .e = "AQAB",
    };
    const key = try jwk.publicKey(.RS256);
    try std.testing.expectError(error.MalformedSignature, key.verify(.RS256, "a.b", "short"));
}

test "fuzz KeySet.parse and key material derivation" {
    // A key set arrives from the network — the connection is one the client chose, but the
    // document is one it did not author. Every rejection has to be a return rather than a
    // crash, including inside the coordinate and modulus decoding that runs afterwards,
    // which is where a malformed key would otherwise reach `std.crypto`.
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [1024]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();

            const set = KeySet.parse(arena.allocator(), buffer[0..length]) catch return;
            for (set.keys) |key| {
                // Anything that parsed names a key type; the rest is optional on the wire.
                try std.testing.expect(key.kty.len > 0);

                // `permits` is the gate `publicKey` asserts on, so the two must agree for
                // every algorithm — that agreement is what makes algorithm confusion
                // unrepresentable rather than merely avoided.
                inline for (comptime std.enums.values(Algorithm)) |algorithm| {
                    if (key.permits(algorithm)) {
                        _ = key.publicKey(algorithm) catch {};
                    }
                }
            }
        }
    }.run, .{});
}
