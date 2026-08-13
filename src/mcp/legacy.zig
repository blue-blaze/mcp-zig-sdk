//! The 2025-era wire vocabulary, for a client talking to a server that predates
//! 2026-07-28.
//!
//! The protocol splits into two eras, and the split is not a detail:
//!
//! * **Legacy** — `2025-11-25` and earlier. The connection is stateful. A client opens
//!   with `initialize`, the server counter-offers a version, the client confirms with
//!   `notifications/initialized`, and only then may anything else be sent. Capabilities
//!   are exchanged once, in the handshake.
//! * **Modern** — `2026-07-28` and later. There is no handshake. Every request carries
//!   its own `_meta` envelope naming the protocol version and the client's capabilities,
//!   and a server advertises what it speaks through `server/discover`.
//!
//! Everything here is the legacy half, kept in its own file for the same reason the
//! reference TypeScript SDK keeps `wire/rev2025-11-25/` apart from `wire/rev2026-07-28/`:
//! the two vocabularies must not leak into each other. A 2025 request must not carry a
//! `_meta` envelope, and a 2025 server must never be shown a modern version string —
//! `MCP-Protocol-Version: 2026-07-28` is a `400` from a server that does not know it.
//!
//! ## Where this came from
//!
//! The 2025 shapes are transcribed from the reference implementation rather than from
//! memory: `@modelcontextprotocol/server` 2.0.0 ships sourcemaps carrying its original
//! `core-internal/src/wire/rev2025-11-25/` and `shared/protocolEras.ts`, which is where
//! the method list, the `initialize` params, the `InitializeResult` shape and the
//! "never-stamp" rule below all come from. `spec/schema.json` in this repository is
//! 2026-07-28 only and says nothing about any of it.
//!
//! ## Never stamp, never strip
//!
//! Two rules the reference codec states explicitly, and this file follows:
//!
//! * A legacy request carries **no** 2026 vocabulary. Not the `_meta` envelope keys, not
//!   `resultType`, not the cache hints. `progressToken` is the one thing that spans both
//!   eras, because it predates the prefix convention and is spelled bare in each.
//! * `resultType` on an inbound legacy result is a misbehaving peer, and is *dropped*
//!   rather than read. This client needs no code for that: `types.resultTypeOf` reads an
//!   absent `resultType` as `complete`, which is the specification's own rule for a
//!   modern client reading an older server, and a present one is simply believed.

const std = @import("std");
const types = @import("types.zig");

/// The first revision of the modern era.
///
/// Revision identifiers are ISO dates, so lexicographic order is chronological order and
/// a string comparison is a real version comparison. That is a property of the naming
/// scheme the specification chose, not a coincidence worth relying on silently.
pub const first_modern_version = "2026-07-28";

/// The legacy revision this client offers in its `initialize`.
///
/// The newest of the legacy era, which is what a client should ask for: a server that
/// speaks an older one counter-offers, and `Handshake.version` records what it chose.
pub const version = "2025-11-25";

/// Whether a revision belongs to the modern era.
pub fn isModern(revision: []const u8) bool {
    return std.mem.order(u8, revision, first_modern_version) != .lt;
}

/// The methods that exist in the legacy era.
///
/// A request this client can build but the era cannot carry is refused locally rather
/// than sent: the alternative is a `-32601` from the server, which reads as "this server
/// is missing a feature" when the truth is "this connection cannot express it".
pub const method = struct {
    pub const initialize = "initialize";
    pub const initialized = "notifications/initialized";
    pub const set_level = "logging/setLevel";
    pub const subscribe = "resources/subscribe";
    pub const unsubscribe = "resources/unsubscribe";
};

/// Whether `name` is a request method the legacy era defines.
///
/// The list is the reference SDK's own `requestMethodKeys` for the 2025 registry, minus
/// the three server-to-client methods (`sampling/createMessage`, `elicitation/create`,
/// `roots/list`), which a client answers rather than sends, and minus the `tasks/*`
/// family, which that SDK marks as wire vocabulary with no runtime.
pub fn hasRequestMethod(name: []const u8) bool {
    const known = [_][]const u8{
        "ping",
        method.initialize,
        types.method.completion_complete,
        method.set_level,
        types.method.prompts_get,
        types.method.prompts_list,
        types.method.resources_list,
        types.method.resources_templates_list,
        types.method.resources_read,
        method.subscribe,
        method.unsubscribe,
        types.method.tools_call,
        types.method.tools_list,
    };
    for (known) |candidate| {
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

/// What a completed handshake established.
///
/// Stored by value on the `Client`, which owns no allocator — so the version is a fixed
/// buffer and the capabilities are presence flags rather than the `std.json.Value` fields
/// `types.ServerCapabilities` carries. Nothing here borrows from the arena the handshake
/// was decoded in, because the connection outlives every one of those.
pub const Handshake = struct {
    /// Longest revision identifier this will hold. An identifier is an ISO date; the
    /// margin is for a suffixed one, and a server offering something longer than this is
    /// refused rather than truncated into a version that was never sent.
    pub const version_bytes_max = 32;

    version_buffer: [version_bytes_max]u8 = undefined,
    version_len: u8 = 0,
    /// Which capabilities the server declared. Only presence is kept: the bodies are
    /// sub-capability objects this client does not act on, and keeping them would mean
    /// keeping the arena they were decoded in.
    tools: bool = false,
    prompts: bool = false,
    resources: bool = false,
    completions: bool = false,
    logging: bool = false,

    pub fn negotiatedVersion(self: *const Handshake) []const u8 {
        return self.version_buffer[0..self.version_len];
    }

    /// Reads an `InitializeResult`.
    ///
    /// `instructions` is deliberately not kept: it is a string this struct would have to
    /// own, it can be arbitrarily long, and a caller that wants it gets it from the
    /// `DiscoverResult` this synthesizes on the call that performed the handshake.
    pub fn fromResult(result: std.json.Value) error{UnexpectedResult}!Handshake {
        const object = switch (result) {
            .object => |object| object,
            else => return error.UnexpectedResult,
        };

        const negotiated = switch (object.get("protocolVersion") orelse
            return error.UnexpectedResult) {
            .string => |string| string,
            else => return error.UnexpectedResult,
        };
        // A server may counter-offer, and this client has to be able to say what it
        // agreed to. A version it cannot store is not one it can report honestly.
        if (negotiated.len == 0 or negotiated.len > version_bytes_max) {
            return error.UnexpectedResult;
        }
        // A modern revision must never come back from `initialize`: the handshake belongs
        // to the legacy era, and a server answering it with `2026-07-28` is describing a
        // connection this envelope cannot carry.
        if (isModern(negotiated)) return error.UnexpectedResult;

        var handshake: Handshake = .{};
        @memcpy(handshake.version_buffer[0..negotiated.len], negotiated);
        handshake.version_len = @intCast(negotiated.len);

        if (object.get("capabilities")) |value| switch (value) {
            .object => |capabilities| {
                handshake.tools = capabilities.get("tools") != null;
                handshake.prompts = capabilities.get("prompts") != null;
                handshake.resources = capabilities.get("resources") != null;
                handshake.completions = capabilities.get("completions") != null;
                handshake.logging = capabilities.get("logging") != null;
            },
            else => return error.UnexpectedResult,
        };
        return handshake;
    }

    /// The same news as a `server/discover` result, so a caller does not have to know
    /// which era it is on to read it.
    ///
    /// `supportedVersions` holds the one version that was negotiated, which is the whole
    /// truth available: `initialize` returns the server's choice, not its list. Reporting
    /// the list this client happens to know would be inventing it.
    pub fn discoverResult(
        self: *const Handshake,
        arena: std.mem.Allocator,
        instructions: ?[]const u8,
    ) error{OutOfMemory}!types.DiscoverResult {
        const versions = try arena.alloc([]const u8, 1);
        versions[0] = self.negotiatedVersion();
        return .{
            .supportedVersions = versions,
            .capabilities = .{
                .tools = presence(self.tools),
                .prompts = presence(self.prompts),
                .resources = presence(self.resources),
                .completions = presence(self.completions),
                .logging = presence(self.logging),
            },
            .instructions = instructions,
            // The legacy era has no cache hints, and "do not cache" is the honest answer
            // rather than a made-up TTL.
            .cache = .no_cache,
            .meta = null,
        };
    }

    fn presence(declared: bool) ?std.json.Value {
        return if (declared) .{ .object = .empty } else null;
    }
};

/// The `instructions` from an `InitializeResult`, borrowed from the decoded value.
pub fn instructionsOf(result: std.json.Value) ?[]const u8 {
    const object = switch (result) {
        .object => |object| object,
        else => return null,
    };
    return switch (object.get("instructions") orelse return null) {
        .string => |string| string,
        else => null,
    };
}

/// Encodes the params of an `initialize` request.
///
/// Written out rather than assembled from `types.RequestMeta` because it is the one place
/// the two eras' vocabularies could touch, and the shapes have nothing in common: the
/// version and capabilities are named `params` members here, not `_meta` keys, and
/// `clientInfo` is required rather than optional.
pub fn writeInitializeParams(
    writer: *std.Io.Writer,
    info: types.Implementation,
    capabilities: types.ClientCapabilities,
) std.Io.Writer.Error!void {
    try writer.writeAll("{\"protocolVersion\":");
    try types.stringify(writer, version);
    try writer.writeAll(",\"capabilities\":");
    try types.stringify(writer, capabilities);
    try writer.writeAll(",\"clientInfo\":");
    try types.stringify(writer, info);
    try writer.writeAll("}");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "era comparison orders revisions by date" {
    try testing.expect(isModern("2026-07-28"));
    try testing.expect(isModern("2027-01-01"));
    try testing.expect(!isModern("2025-11-25"));
    try testing.expect(!isModern("2025-06-18"));
    try testing.expect(!isModern("2024-10-07"));
    // The boundary is inclusive on the modern side: 2026-07-28 is the first modern one.
    try testing.expect(!isModern("2026-07-27"));
}

test "the legacy method list is the era's, not this revision's" {
    try testing.expect(hasRequestMethod("tools/call"));
    try testing.expect(hasRequestMethod("resources/subscribe"));
    try testing.expect(hasRequestMethod("logging/setLevel"));

    // Both of these exist in 2026-07-28 and in neither case in 2025: `server/discover`
    // replaced the handshake, and `subscriptions/listen` replaced `resources/subscribe`.
    try testing.expect(!hasRequestMethod("server/discover"));
    try testing.expect(!hasRequestMethod("subscriptions/listen"));
}

test "a handshake result is read into storage the connection can keep" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const result = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(),
        \\{"protocolVersion":"2025-11-25","serverInfo":{"name":"srv","version":"1"},
        \\ "capabilities":{"tools":{},"logging":{}},"instructions":"read me"}
    , .{});

    const handshake = try Handshake.fromResult(result);
    try testing.expectEqualStrings("2025-11-25", handshake.negotiatedVersion());
    try testing.expect(handshake.tools);
    try testing.expect(handshake.logging);
    try testing.expect(!handshake.prompts);
    try testing.expectEqualStrings("read me", instructionsOf(result).?);

    // The version survives the arena it was decoded from, which is the property that
    // lets a `Client` with no allocator remember it.
    _ = arena.reset(.free_all);
    try testing.expectEqualStrings("2025-11-25", handshake.negotiatedVersion());
}

test "a server counter-offering an older revision is believed" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // `initialize` returns the server's choice, which need not be what was asked for.
    const result = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(),
        \\{"protocolVersion":"2025-03-26","capabilities":{}}
    , .{});
    const handshake = try Handshake.fromResult(result);
    try testing.expectEqualStrings("2025-03-26", handshake.negotiatedVersion());
}

test "a handshake answered with a modern revision is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // `initialize` belongs to the legacy era. A server answering it with 2026-07-28 is
    // describing a connection whose envelope this side would then get wrong in both
    // directions, so there is nothing safe to do but refuse.
    const result = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(),
        \\{"protocolVersion":"2026-07-28","capabilities":{}}
    , .{});
    try testing.expectError(error.UnexpectedResult, Handshake.fromResult(result));
}

test "a malformed or oversized handshake is refused rather than truncated" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    for ([_][]const u8{
        "[]",
        "{}",
        \\{"protocolVersion":7}
        ,
        \\{"protocolVersion":""}
        ,
        \\{"protocolVersion":"2025-11-25","capabilities":[]}
        ,
    }) |bytes| {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, bytes, .{});
        try testing.expectError(error.UnexpectedResult, Handshake.fromResult(value));
    }

    // Longer than the buffer. Truncating would make this client report agreement to a
    // version that was never offered.
    const long = try std.fmt.allocPrint(
        gpa,
        "{{\"protocolVersion\":\"{s}\"}}",
        .{"2025-" ++ ("0" ** Handshake.version_bytes_max)},
    );
    const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, long, .{});
    try testing.expectError(error.UnexpectedResult, Handshake.fromResult(value));
}

test "the synthesized discover result reads like a modern one" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const result = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
        \\{"protocolVersion":"2025-11-25","capabilities":{"tools":{},"prompts":{}},
        \\ "instructions":"hello"}
    , .{});
    const handshake = try Handshake.fromResult(result);
    const discovered = try handshake.discoverResult(gpa, instructionsOf(result));

    try testing.expectEqual(@as(usize, 1), discovered.supportedVersions.len);
    try testing.expectEqualStrings("2025-11-25", discovered.supportedVersions[0]);
    try testing.expect(discovered.capabilities.tools != null);
    try testing.expect(discovered.capabilities.prompts != null);
    try testing.expect(discovered.capabilities.resources == null);
    try testing.expectEqualStrings("hello", discovered.instructions.?);
    try testing.expectEqual(@as(u64, 0), discovered.cache.ttl_ms);
}

test "initialize params carry the version in params, never in _meta" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    try writeInitializeParams(
        &out.writer,
        .{ .name = "c", .version = "1" },
        .{ .elicitation = .{ .object = .empty } },
    );
    const bytes = out.written();

    try testing.expect(std.mem.indexOf(u8, bytes, "\"protocolVersion\":\"2025-11-25\"") != null);
    try testing.expect(std.mem.indexOf(u8, bytes, "\"clientInfo\":") != null);
    // The never-stamp rule: not one modern envelope key may appear here.
    try testing.expect(std.mem.indexOf(u8, bytes, "_meta") == null);
    try testing.expect(std.mem.indexOf(u8, bytes, "io.modelcontextprotocol/") == null);
    try testing.expect(std.mem.indexOf(u8, bytes, first_modern_version) == null);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, bytes, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("c", parsed.value.object.get("clientInfo").?.object.get("name").?.string);
}
