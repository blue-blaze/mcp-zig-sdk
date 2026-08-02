//! JSON-RPC 2.0, the framing MCP is carried over.
//!
//! MCP constrains plain JSON-RPC in ways worth stating up front, because they
//! shape the types here:
//!
//!   * Batching is not used. A message is always a single object, never an array.
//!   * `params` and `result` are left as `std.json.Value`. The method name selects
//!     how they are interpreted, so decoding them eagerly would mean decoding
//!     into a union of every request type in the protocol; instead the dispatch
//!     layer parses them into concrete types once the method is known.
//!   * An error response may legitimately arrive with no `id` — a parse failure,
//!     or a request rejected before its id could be read (see the schema, where
//!     `id` is absent from `JSONRPCErrorResponse.required`).
//!
//! Parsing hands back a `Parsed(T)` that owns an arena; the borrowed slices inside
//! the message stay valid until `deinit`.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;
const comptime_assert = assert_mod.comptime_assert;

/// Upper bound on a single message, applied before parsing. A peer that sends more
/// than this is either broken or hostile, and unbounded input is not a resource we
/// are willing to hand out. 16 MiB is far above any legitimate MCP message while
/// staying small enough that a rogue peer cannot exhaust memory.
pub const message_size_max: usize = 16 * 1024 * 1024;

/// The only JSON-RPC version MCP uses.
pub const jsonrpc_version = "2.0";

/// Error codes. The base four come from JSON-RPC itself; the rest are allocated by
/// MCP, which partitions the server-error range: `-32000`..`-32019` stays
/// implementation-defined, `-32020`..`-32099` is reserved for the specification.
///
/// Deliberately not an exhaustive enum: peers may send implementation-defined
/// codes from the grandfathered range, and rejecting them would be wrong.
pub const error_code = struct {
    // JSON-RPC 2.0.
    pub const parse_error: i32 = -32700;
    pub const invalid_request: i32 = -32600;
    pub const method_not_found: i32 = -32601;
    pub const invalid_params: i32 = -32602;
    pub const internal_error: i32 = -32603;

    // MCP-reserved range.
    pub const header_mismatch: i32 = -32020;
    pub const missing_required_client_capability: i32 = -32021;
    pub const unsupported_protocol_version: i32 = -32022;

    /// Inclusive bounds of the range MCP reserves for specification-defined codes.
    pub const reserved_min: i32 = -32099;
    pub const reserved_max: i32 = -32020;

    /// A short, spec-aligned sentence for a known code. Callers may always supply
    /// their own message; this exists so that the common paths do not have to.
    pub fn describe(code: i32) []const u8 {
        return switch (code) {
            parse_error => "Parse error",
            invalid_request => "Invalid Request",
            method_not_found => "Method not found",
            invalid_params => "Invalid params",
            internal_error => "Internal error",
            header_mismatch => "Header mismatch",
            missing_required_client_capability => "Missing required client capability",
            unsupported_protocol_version => "Unsupported protocol version",
            else => "Error",
        };
    }
};

comptime {
    // The reserved window has to contain every code the specification allocates,
    // or one of them would collide with an SDK-defined code somewhere.
    comptime_assert(error_code.header_mismatch <= error_code.reserved_max);
    comptime_assert(error_code.header_mismatch >= error_code.reserved_min);
    comptime_assert(error_code.unsupported_protocol_version <= error_code.reserved_max);
    comptime_assert(error_code.unsupported_protocol_version >= error_code.reserved_min);
}

/// A request identifier: a string or an integer, per the schema's
/// `"type": ["string", "integer"]`.
///
/// JSON-RPC 2.0 also permits a fractional number, which this rejects. MCP's schema
/// says `integer`, and accepting floats would make identity comparison depend on
/// float equality.
pub const Id = union(enum) {
    number: i64,
    string: []const u8,

    pub fn eql(a: Id, b: Id) bool {
        return switch (a) {
            .number => |an| switch (b) {
                .number => |bn| an == bn,
                .string => false,
            },
            .string => |as| switch (b) {
                .number => false,
                .string => |bs| std.mem.eql(u8, as, bs),
            },
        };
    }

    /// Reads an id out of an already-parsed JSON value.
    pub fn fromValue(value: std.json.Value) error{InvalidRequest}!Id {
        return switch (value) {
            .integer => |n| .{ .number = n },
            .string => |s| .{ .string = s },
            // A float id is valid JSON-RPC but not valid MCP, and `null` is only
            // meaningful in a response we are not the one constructing.
            else => error.InvalidRequest,
        };
    }

    /// Duplicates any borrowed bytes into `gpa`, so the id can outlive the arena
    /// the message was parsed into. Numeric ids need no allocation.
    pub fn clone(id: Id, gpa: std.mem.Allocator) error{OutOfMemory}!Id {
        return switch (id) {
            .number => id,
            .string => |s| .{ .string = try gpa.dupe(u8, s) },
        };
    }

    /// Frees what `clone` allocated. Safe on numeric ids.
    pub fn deinit(id: Id, gpa: std.mem.Allocator) void {
        switch (id) {
            .number => {},
            .string => |s| gpa.free(s),
        }
    }

    pub fn jsonStringify(id: Id, stream: anytype) !void {
        switch (id) {
            .number => |n| try stream.write(n),
            .string => |s| try stream.write(s),
        }
    }

    pub fn format(id: Id, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (id) {
            .number => |n| try writer.print("{d}", .{n}),
            .string => |s| try writer.print("\"{s}\"", .{s}),
        }
    }
};

/// The error object of an error response.
pub const ErrorObject = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value = null,

    pub fn jsonStringify(self: ErrorObject, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("code");
        try stream.write(self.code);
        try stream.objectField("message");
        try stream.write(self.message);
        if (self.data) |data| {
            try stream.objectField("data");
            try stream.write(data);
        }
        try stream.endObject();
    }
};

/// A request: has an id, expects a response.
pub const Request = struct {
    id: Id,
    method: []const u8,
    params: ?std.json.Value = null,

    pub fn jsonStringify(self: Request, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("jsonrpc");
        try stream.write(jsonrpc_version);
        try stream.objectField("id");
        try stream.write(self.id);
        try stream.objectField("method");
        try stream.write(self.method);
        if (self.params) |params| {
            try stream.objectField("params");
            try stream.write(params);
        }
        try stream.endObject();
    }
};

/// A notification: no id, no response.
pub const Notification = struct {
    method: []const u8,
    params: ?std.json.Value = null,

    pub fn jsonStringify(self: Notification, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("jsonrpc");
        try stream.write(jsonrpc_version);
        try stream.objectField("method");
        try stream.write(self.method);
        if (self.params) |params| {
            try stream.objectField("params");
            try stream.write(params);
        }
        try stream.endObject();
    }
};

/// A successful response.
pub const ResultResponse = struct {
    id: Id,
    result: std.json.Value,

    pub fn jsonStringify(self: ResultResponse, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("jsonrpc");
        try stream.write(jsonrpc_version);
        try stream.objectField("id");
        try stream.write(self.id);
        try stream.objectField("result");
        try stream.write(self.result);
        try stream.endObject();
    }
};

/// An error response. `id` is optional: a message that failed to parse, or that
/// was rejected before its id could be recovered, has none to echo.
pub const ErrorResponse = struct {
    id: ?Id = null,
    @"error": ErrorObject,

    pub fn jsonStringify(self: ErrorResponse, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("jsonrpc");
        try stream.write(jsonrpc_version);
        if (self.id) |id| {
            try stream.objectField("id");
            try stream.write(id);
        }
        try stream.objectField("error");
        try stream.write(self.@"error");
        try stream.endObject();
    }

    /// Builds an error response from a code, taking the spec's own wording.
    pub fn init(id: ?Id, code: i32) ErrorResponse {
        return .{
            .id = id,
            .@"error" = .{ .code = code, .message = error_code.describe(code) },
        };
    }
};

/// Any message that can appear on the wire.
pub const Message = union(enum) {
    request: Request,
    notification: Notification,
    result_response: ResultResponse,
    error_response: ErrorResponse,

    pub fn jsonStringify(self: Message, stream: anytype) !void {
        switch (self) {
            inline else => |message| try stream.write(message),
        }
    }

    /// The id carried by this message, if any.
    pub fn id(self: Message) ?Id {
        return switch (self) {
            .request => |r| r.id,
            .notification => null,
            .result_response => |r| r.id,
            .error_response => |r| r.id,
        };
    }

    /// The method name, for the two variants that carry one.
    pub fn method(self: Message) ?[]const u8 {
        return switch (self) {
            .request => |r| r.method,
            .notification => |n| n.method,
            .result_response, .error_response => null,
        };
    }
};

/// Failures that can arise while decoding a message. Each maps onto exactly one
/// JSON-RPC error code, so the caller can answer without a lookup table:
///
///   * `MessageTooLarge`, `Malformed` -> `-32700` parse error
///   * `InvalidRequest`               -> `-32600` invalid request
pub const ParseError = error{
    /// Exceeded `message_size_max` before parsing was attempted.
    MessageTooLarge,
    /// Not well-formed JSON, or not a JSON object.
    Malformed,
    /// Well-formed JSON, but not a well-formed JSON-RPC message: wrong `jsonrpc`
    /// version, missing `method`, an id of the wrong type, and so on.
    InvalidRequest,
    OutOfMemory,
};

/// The JSON-RPC error code that answers a given `ParseError`.
pub fn parseErrorCode(err: ParseError) i32 {
    return switch (err) {
        error.MessageTooLarge, error.Malformed => error_code.parse_error,
        error.InvalidRequest => error_code.invalid_request,
        // Running out of memory is ours, not the peer's.
        error.OutOfMemory => error_code.internal_error,
    };
}

/// A parsed message together with the arena backing every slice inside it.
pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    message: Message,

    pub fn deinit(self: *Parsed) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Decodes one message. The returned `Parsed` owns its storage; slices in the
/// message borrow from it and are valid until `deinit`.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) ParseError!Parsed {
    if (bytes.len > message_size_max) return error.MessageTooLarge;

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    const message = try parseLeaky(arena.allocator(), bytes);
    return .{ .arena = arena, .message = message };
}

/// As `parse`, but allocating into a caller-owned arena. Use this on the server's
/// per-request arena to avoid nesting one arena inside another.
pub fn parseLeaky(arena: std.mem.Allocator, bytes: []const u8) ParseError!Message {
    if (bytes.len > message_size_max) return error.MessageTooLarge;

    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    return fromValue(value);
}

/// Classifies an already-parsed JSON value as a JSON-RPC message.
///
/// The four shapes are told apart by which keys are present, which is what the
/// schema's `anyOf` amounts to. Order matters: `error` is checked before `result`
/// so that a malformed peer sending both is treated as the error it announces.
pub fn fromValue(value: std.json.Value) ParseError!Message {
    const object = switch (value) {
        .object => |o| o,
        else => return error.Malformed,
    };

    // `jsonrpc: "2.0"` is required on every shape.
    const version = object.get("jsonrpc") orelse return error.InvalidRequest;
    switch (version) {
        .string => |s| if (!std.mem.eql(u8, s, jsonrpc_version)) return error.InvalidRequest,
        else => return error.InvalidRequest,
    }

    const id_value = object.get("id");
    const has_error = object.get("error") != null;
    const has_result = object.get("result") != null;
    const method_value = object.get("method");

    if (has_error) {
        // `id` may be absent; when present it must still be well-typed.
        const id: ?Id = if (id_value) |v| switch (v) {
            .null => null,
            else => try Id.fromValue(v),
        } else null;
        return .{ .error_response = .{
            .id = id,
            .@"error" = try errorObjectFromValue(object.get("error").?),
        } };
    }

    if (has_result) {
        const id_present = id_value orelse return error.InvalidRequest;
        return .{ .result_response = .{
            .id = try Id.fromValue(id_present),
            .result = object.get("result").?,
        } };
    }

    const method = switch (method_value orelse return error.InvalidRequest) {
        .string => |s| s,
        else => return error.InvalidRequest,
    };
    // An empty method name can never be dispatched, so reject it here rather than
    // letting it fall through to a confusing "method not found".
    if (method.len == 0) return error.InvalidRequest;

    const params: ?std.json.Value = if (object.get("params")) |p| switch (p) {
        .object => p,
        .null => null,
        // MCP always uses by-name parameters; a positional array is not valid here.
        else => return error.InvalidRequest,
    } else null;

    if (id_value) |v| {
        switch (v) {
            // A request with an explicit null id is not a notification: JSON-RPC
            // reserves null ids for responses, so this is simply invalid.
            .null => return error.InvalidRequest,
            else => return .{ .request = .{
                .id = try Id.fromValue(v),
                .method = method,
                .params = params,
            } },
        }
    }

    return .{ .notification = .{ .method = method, .params = params } };
}

fn errorObjectFromValue(value: std.json.Value) ParseError!ErrorObject {
    const object = switch (value) {
        .object => |o| o,
        else => return error.InvalidRequest,
    };
    const code = switch (object.get("code") orelse return error.InvalidRequest) {
        .integer => |n| std.math.cast(i32, n) orelse return error.InvalidRequest,
        else => return error.InvalidRequest,
    };
    const message = switch (object.get("message") orelse return error.InvalidRequest) {
        .string => |s| s,
        else => return error.InvalidRequest,
    };
    return .{ .code = code, .message = message, .data = object.get("data") };
}

/// Encodes a message into freshly allocated bytes; the caller owns them.
pub fn stringifyAlloc(gpa: std.mem.Allocator, message: anytype) error{OutOfMemory}![]u8 {
    return std.json.Stringify.valueAlloc(gpa, message, .{});
}

/// Encodes a message straight into a writer, without an intermediate buffer.
pub fn stringify(writer: *std.Io.Writer, message: anytype) std.Io.Writer.Error!void {
    try std.json.Stringify.value(message, .{}, writer);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse request with numeric id" {
    const bytes =
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"abc"}}
    ;
    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();

    const request = parsed.message.request;
    try testing.expectEqual(@as(i64, 1), request.id.number);
    try testing.expectEqualStrings("tools/list", request.method);
    try testing.expectEqualStrings("abc", request.params.?.object.get("cursor").?.string);
}

test "parse request with string id" {
    const bytes =
        \\{"jsonrpc":"2.0","id":"req-7","method":"server/discover"}
    ;
    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();

    const request = parsed.message.request;
    try testing.expectEqualStrings("req-7", request.id.string);
    try testing.expect(request.params == null);
}

test "parse notification has no id" {
    const bytes =
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}
    ;
    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();

    try testing.expect(parsed.message == .notification);
    try testing.expect(parsed.message.id() == null);
    try testing.expectEqualStrings("notifications/cancelled", parsed.message.method().?);
}

test "parse result response" {
    const bytes =
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[]}}
    ;
    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();

    const response = parsed.message.result_response;
    try testing.expectEqual(@as(i64, 2), response.id.number);
    try testing.expectEqualStrings("complete", response.result.object.get("resultType").?.string);
}

test "parse error response with and without id" {
    {
        const bytes =
            \\{"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"Method not found"}}
        ;
        var parsed = try parse(testing.allocator, bytes);
        defer parsed.deinit();

        const response = parsed.message.error_response;
        try testing.expectEqual(@as(i64, 4), response.id.?.number);
        try testing.expectEqual(error_code.method_not_found, response.@"error".code);
        try testing.expect(response.@"error".data == null);
    }
    {
        // The spec explicitly allows an error response with no id, for failures
        // detected before the id could be read.
        const bytes =
            \\{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"}}
        ;
        var parsed = try parse(testing.allocator, bytes);
        defer parsed.deinit();

        try testing.expect(parsed.message.error_response.id == null);
    }
    {
        // An explicit null id decodes the same way as an absent one.
        const bytes =
            \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}
        ;
        var parsed = try parse(testing.allocator, bytes);
        defer parsed.deinit();

        try testing.expect(parsed.message.error_response.id == null);
    }
}

test "parse error response carries data" {
    const bytes =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version",
        \\"data":{"requested":"2025-11-25","supported":["2026-07-28"]}}}
    ;
    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();

    const err = parsed.message.error_response.@"error";
    try testing.expectEqual(error_code.unsupported_protocol_version, err.code);
    const data = err.data.?.object;
    try testing.expectEqualStrings("2025-11-25", data.get("requested").?.string);
    try testing.expectEqualStrings("2026-07-28", data.get("supported").?.array.items[0].string);
}

test "reject messages that are not valid JSON-RPC" {
    const cases = [_]struct { bytes: []const u8, expected: ParseError }{
        // Not JSON at all.
        .{ .bytes = "not json", .expected = error.Malformed },
        .{ .bytes = "{", .expected = error.Malformed },
        // JSON, but not an object.
        .{ .bytes = "[]", .expected = error.Malformed },
        .{ .bytes = "42", .expected = error.Malformed },
        .{ .bytes = "null", .expected = error.Malformed },
        // Object, but not JSON-RPC 2.0.
        .{ .bytes = "{}", .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"1.0","id":1,"method":"x"}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":2.0,"id":1,"method":"x"}
        , .expected = error.InvalidRequest },
        // Missing or unusable method.
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1,"method":""}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1,"method":5}
        , .expected = error.InvalidRequest },
        // Ids that MCP does not allow.
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1.5,"method":"x"}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":null,"method":"x"}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":{"a":1},"method":"x"}
        , .expected = error.InvalidRequest },
        // Positional params.
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1,"method":"x","params":[1,2]}
        , .expected = error.InvalidRequest },
        // A result response needs an id.
        .{ .bytes =
        \\{"jsonrpc":"2.0","result":{}}
        , .expected = error.InvalidRequest },
        // Malformed error objects.
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-1}}
        , .expected = error.InvalidRequest },
        .{ .bytes =
        \\{"jsonrpc":"2.0","id":1,"error":"nope"}
        , .expected = error.InvalidRequest },
    };

    for (cases) |case| {
        try testing.expectError(case.expected, parse(testing.allocator, case.bytes));
    }
}

test "reject oversized messages before parsing" {
    // A real allocation rather than a fabricated slice: the size check runs before
    // anything dereferences the bytes, but a test should not rely on that to stay
    // free of undefined behaviour.
    const huge = try testing.allocator.alloc(u8, message_size_max + 1);
    defer testing.allocator.free(huge);
    @memset(huge, ' ');

    try testing.expectError(error.MessageTooLarge, parse(testing.allocator, huge));
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.MessageTooLarge, parseLeaky(arena.allocator(), huge));
}

test "parse error codes map onto JSON-RPC codes" {
    try testing.expectEqual(error_code.parse_error, parseErrorCode(error.Malformed));
    try testing.expectEqual(error_code.parse_error, parseErrorCode(error.MessageTooLarge));
    try testing.expectEqual(error_code.invalid_request, parseErrorCode(error.InvalidRequest));
    try testing.expectEqual(error_code.internal_error, parseErrorCode(error.OutOfMemory));
}

test "stringify request round-trips" {
    var params_object: std.json.ObjectMap = .empty;
    defer params_object.deinit(testing.allocator);
    try params_object.put(testing.allocator, "name", .{ .string = "get_weather" });

    const request: Request = .{
        .id = .{ .number = 9 },
        .method = "tools/call",
        .params = .{ .object = params_object },
    };

    const bytes = try stringifyAlloc(testing.allocator, request);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_weather"}}
    , bytes);

    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 9), parsed.message.request.id.number);
    try testing.expectEqualStrings("tools/call", parsed.message.request.method);
}

test "stringify omits absent optional fields" {
    const notification: Notification = .{ .method = "notifications/tools/list_changed" };
    const bytes = try stringifyAlloc(testing.allocator, notification);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
    , bytes);
}

test "stringify error response with string id" {
    const response: ErrorResponse = .{
        .id = .{ .string = "abc" },
        .@"error" = .{ .code = error_code.invalid_params, .message = "Invalid params" },
    };
    const bytes = try stringifyAlloc(testing.allocator, response);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":"abc","error":{"code":-32602,"message":"Invalid params"}}
    , bytes);
}

test "stringify error response without id" {
    const response: ErrorResponse = .init(null, error_code.parse_error);
    const bytes = try stringifyAlloc(testing.allocator, response);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"}}
    , bytes);
}

test "stringify message union dispatches to the active variant" {
    const message: Message = .{ .notification = .{ .method = "notifications/progress" } };
    const bytes = try stringifyAlloc(testing.allocator, message);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/progress"}
    , bytes);
}

test "id equality distinguishes strings from numbers" {
    const one: Id = .{ .number = 1 };
    const one_again: Id = .{ .number = 1 };
    const two: Id = .{ .number = 2 };
    const text: Id = .{ .string = "1" };

    try testing.expect(one.eql(one_again));
    try testing.expect(!one.eql(two));
    try testing.expect(!one.eql(text));
    try testing.expect(!text.eql(one));
    try testing.expect(text.eql(.{ .string = "1" }));
    try testing.expect(!text.eql(.{ .string = "2" }));
}

test "id clone outlives the parse arena" {
    const owned: Id = blk: {
        var parsed = try parse(testing.allocator,
            \\{"jsonrpc":"2.0","id":"outlives","method":"x"}
        );
        defer parsed.deinit();
        break :blk try parsed.message.request.id.clone(testing.allocator);
    };
    defer owned.deinit(testing.allocator);

    try testing.expectEqualStrings("outlives", owned.string);
}

test "id clone of a number allocates nothing" {
    const id: Id = .{ .number = 42 };
    const cloned = try id.clone(testing.allocator);
    defer cloned.deinit(testing.allocator);
    try testing.expectEqual(@as(i64, 42), cloned.number);
}

test "id formats for diagnostics" {
    var buffer: [32]u8 = undefined;
    {
        var writer: std.Io.Writer = .fixed(&buffer);
        try writer.print("{f}", .{Id{ .number = 7 }});
        try testing.expectEqualStrings("7", writer.buffered());
    }
    {
        var writer: std.Io.Writer = .fixed(&buffer);
        try writer.print("{f}", .{Id{ .string = "x" }});
        try testing.expectEqualStrings("\"x\"", writer.buffered());
    }
}

test "error code descriptions match the spec wording" {
    try testing.expectEqualStrings("Parse error", error_code.describe(error_code.parse_error));
    try testing.expectEqualStrings("Method not found", error_code.describe(error_code.method_not_found));
    try testing.expectEqualStrings("Header mismatch", error_code.describe(error_code.header_mismatch));
    try testing.expectEqualStrings(
        "Unsupported protocol version",
        error_code.describe(error_code.unsupported_protocol_version),
    );
    // An implementation-defined code from the grandfathered range still gets a
    // usable message rather than a crash.
    try testing.expectEqualStrings("Error", error_code.describe(-32000));
}

test "parseLeaky shares a caller-owned arena" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const message = try parseLeaky(arena.allocator(),
        \\{"jsonrpc":"2.0","id":1,"method":"ping-ish"}
    );
    try testing.expectEqualStrings("ping-ish", message.method().?);
    try testing.expectEqual(@as(i64, 1), message.id().?.number);
}

test "stringify writes straight into a writer" {
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try stringify(&writer, Notification{ .method = "notifications/message" });
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/message"}
    , writer.buffered());
}

test "an error response wins over a result when a peer sends both" {
    // Not legal to send, but the classification has to be deterministic.
    const bytes =
        \\{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"Internal error"}}
    ;
    var parsed = try parse(testing.allocator, bytes);
    defer parsed.deinit();
    try testing.expect(parsed.message == .error_response);
}

test "fuzz the parser against arbitrary input" {
    const Context = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const length = smith.slice(&buffer);
            // Any outcome but a crash or a leak is acceptable; `testing.allocator`
            // makes a leak fail the test.
            var parsed = parse(testing.allocator, buffer[0..length]) catch return;
            parsed.deinit();
        }
    };
    try testing.fuzz(Context{}, Context.testOne, .{});
}
