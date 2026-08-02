//! Derives JSON Schema 2020-12 documents from Zig types at compile time.
//!
//! A tool's `inputSchema` is the contract between a server and a model, and
//! writing it by hand next to the Zig type that decodes the arguments means
//! keeping two descriptions of the same shape in agreement forever. This module
//! generates one from the other, at comptime, so the two cannot drift: adding a
//! field to the argument struct changes the advertised schema in the same edit.
//!
//! The output is a comptime `[]const u8` — a string literal baked into the binary.
//! Nothing is allocated or parsed at run time, and a server's tool list costs no
//! heap at all.
//!
//! ## Supported types
//!
//! | Zig                        | JSON Schema |
//! |---|---|
//! | `bool`                     | `{"type":"boolean"}` |
//! | `i32`, `u8`, …             | `{"type":"integer"}`, with `minimum: 0` when unsigned |
//! | `f32`, `f64`               | `{"type":"number"}` |
//! | `[]const u8`               | `{"type":"string"}` |
//! | `enum`                     | `{"type":"string","enum":[…]}` |
//! | `struct`                   | `{"type":"object","properties":…,"required":…}` |
//! | `[]const T`, `[N]T`        | `{"type":"array","items":…}` |
//! | `?T`                       | schema of `T`, and the field is not required |
//! | `std.json.Value`           | `{}` — any JSON |
//!
//! Anything else is a compile error rather than a silently wrong schema.
//!
//! ## Descriptions and annotations
//!
//! Zig has no comptime access to doc comments, so an argument struct opts into
//! descriptions and header mirroring with declarations:
//!
//! ```zig
//! const Args = struct {
//!     city: []const u8,
//!     units: ?enum { metric, imperial } = null,
//!
//!     /// Per-field `description` values for the generated schema.
//!     pub const schema_docs = .{
//!         .city = "The city to look up, e.g. \"Seattle, WA\"",
//!         .units = "Unit system for the response",
//!     };
//!
//!     /// Mirrors a parameter into the `Mcp-Param-{name}` HTTP header.
//!     pub const mcp_headers = .{ .city = "City" };
//! };
//! ```
//!
//! `mcp_headers` entries are checked at compile time against the constraints the
//! Streamable HTTP transport places on `x-mcp-header`: primitive types only,
//! `number` excluded, names matching the HTTP token grammar, and unique
//! case-insensitively.

const std = @import("std");
const assert_mod = @import("assert");

const comptime_assert = assert_mod.comptime_assert;

/// Name of the optional declaration carrying per-field descriptions.
const docs_decl = "schema_docs";

/// Name of the optional declaration carrying `x-mcp-header` annotations.
const headers_decl = "mcp_headers";

/// The JSON Schema annotation that asks for a parameter to be mirrored into a header.
///
/// Named because both ends of the wire need it: this generator writes it into a tool's
/// schema, and a client reads it back out of `tools/list` to learn which headers to
/// send. Two copies of the string would be two chances to drift.
pub const header_annotation = "x-mcp-header";

/// Generates the JSON Schema for `T` as comptime JSON text.
///
/// For a tool's `inputSchema` the top level must be an object schema, which the
/// caller gets by passing a struct type; `of` itself will happily describe any
/// supported type.
pub fn of(comptime T: type) []const u8 {
    // A container-level declaration is always comptime-evaluated, and is memoized
    // per instantiation — so a type's schema is built once during compilation no
    // matter how many places ask for it.
    const generated = struct {
        const text = build: {
            var buffer: []const u8 = "";
            writeSchema(&buffer, T, null);
            break :build buffer;
        };
    };
    return generated.text;
}

/// Generates an object schema, rejecting non-struct types with a clear message.
///
/// Use this for tool arguments: JSON-RPC params are by-name, so the top level has
/// to be an object.
pub fn ofArguments(comptime T: type) []const u8 {
    const generated = struct {
        const text = build: {
            if (T == void) break :build "{\"type\":\"object\",\"properties\":{}}";
            if (@typeInfo(T) != .@"struct") {
                @compileError("tool arguments must be a struct or void, found " ++ @typeName(T));
            }
            validateHeaderAnnotations(T);
            break :build of(T);
        };
    };
    return generated.text;
}

/// The `x-mcp-header` name a field is mirrored into, if any.
///
/// The HTTP transport needs this to build `Mcp-Param-*` headers, and the server
/// side needs it to validate them against the body.
pub fn headerName(comptime T: type, comptime field_name: []const u8) ?[]const u8 {
    const resolved = struct {
        const value = build: {
            if (@typeInfo(T) != .@"struct") break :build null;
            if (!@hasDecl(T, headers_decl)) break :build null;
            const headers = @field(T, headers_decl);
            if (!@hasField(@TypeOf(headers), field_name)) break :build null;
            const name: []const u8 = @field(headers, field_name);
            break :build name;
        };
    };
    return resolved.value;
}

/// Every `x-mcp-header` mapping on `T`, as field/header pairs.
pub fn headerMappings(comptime T: type) []const HeaderMapping {
    const resolved = struct {
        const mappings = build: {
            if (@typeInfo(T) != .@"struct") break :build &.{};
            if (!@hasDecl(T, headers_decl)) break :build &.{};
            const headers = @field(T, headers_decl);
            var list: []const HeaderMapping = &.{};
            for (@typeInfo(@TypeOf(headers)).@"struct".fields) |field| {
                list = list ++ [_]HeaderMapping{.{
                    .field = field.name,
                    .header = @field(headers, field.name),
                }};
            }
            break :build list;
        };
    };
    return resolved.mappings;
}

pub const HeaderMapping = struct {
    /// Name of the Zig field, which is also the JSON property name.
    field: []const u8,
    /// The `x-mcp-header` value; the wire header is `Mcp-Param-{header}`.
    header: []const u8,
};

/// The description declared for a field, if the type opted in via `schema_docs`.
///
/// Prompt arguments are advertised as a flat list rather than a JSON Schema, so the
/// registry needs the descriptions without going through schema generation.
pub fn descriptionFor(comptime T: type, comptime field_name: []const u8) ?[]const u8 {
    const resolved = struct {
        const value = build: {
            if (@typeInfo(T) != .@"struct") break :build null;
            break :build docFor(T, field_name);
        };
    };
    return resolved.value;
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

fn writeSchema(
    comptime buffer: *[]const u8,
    comptime T: type,
    comptime description: ?[]const u8,
) void {
    // An optional contributes nothing of its own: the "may be absent" part is
    // expressed by leaving the field out of `required`.
    if (@typeInfo(T) == .optional) {
        return writeSchema(buffer, @typeInfo(T).optional.child, description);
    }

    if (T == std.json.Value) {
        // Deliberately unconstrained. 2026-07-28 allows any JSON Schema 2020-12
        // keyword in a tool schema, and any JSON value in structured content, so a
        // passthrough field must not narrow anything.
        buffer.* = buffer.* ++ "{";
        writeDescription(buffer, description, false);
        buffer.* = buffer.* ++ "}";
        return;
    }

    switch (@typeInfo(T)) {
        .bool => {
            buffer.* = buffer.* ++ "{\"type\":\"boolean\"";
            writeDescription(buffer, description, true);
            buffer.* = buffer.* ++ "}";
        },
        .int => |info| {
            buffer.* = buffer.* ++ "{\"type\":\"integer\"";
            // An unsigned Zig field cannot hold a negative value, so say so
            // rather than letting a caller send one and get a decode error.
            if (info.signedness == .unsigned) buffer.* = buffer.* ++ ",\"minimum\":0";
            writeDescription(buffer, description, true);
            buffer.* = buffer.* ++ "}";
        },
        .float => {
            buffer.* = buffer.* ++ "{\"type\":\"number\"";
            writeDescription(buffer, description, true);
            buffer.* = buffer.* ++ "}";
        },
        .@"enum" => |info| {
            buffer.* = buffer.* ++ "{\"type\":\"string\",\"enum\":[";
            for (info.fields, 0..) |field, index| {
                if (index > 0) buffer.* = buffer.* ++ ",";
                buffer.* = buffer.* ++ "\"" ++ escape(field.name) ++ "\"";
            }
            buffer.* = buffer.* ++ "]";
            writeDescription(buffer, description, true);
            buffer.* = buffer.* ++ "}";
        },
        .@"struct" => writeObjectSchema(buffer, T, description),
        .pointer => |info| {
            if (info.size != .slice) {
                @compileError("only slices are supported, found " ++ @typeName(T));
            }
            if (info.child == u8) {
                buffer.* = buffer.* ++ "{\"type\":\"string\"";
                writeDescription(buffer, description, true);
                buffer.* = buffer.* ++ "}";
                return;
            }
            buffer.* = buffer.* ++ "{\"type\":\"array\",\"items\":";
            writeSchema(buffer, info.child, null);
            writeDescription(buffer, description, true);
            buffer.* = buffer.* ++ "}";
        },
        .array => |info| {
            if (info.child == u8) {
                buffer.* = buffer.* ++ "{\"type\":\"string\"";
                writeDescription(buffer, description, true);
                buffer.* = buffer.* ++ "}";
                return;
            }
            buffer.* = buffer.* ++ "{\"type\":\"array\",\"items\":";
            writeSchema(buffer, info.child, null);
            buffer.* = buffer.* ++ std.fmt.comptimePrint(
                ",\"minItems\":{d},\"maxItems\":{d}",
                .{ info.len, info.len },
            );
            writeDescription(buffer, description, true);
            buffer.* = buffer.* ++ "}";
        },
        else => @compileError(
            "cannot derive a JSON Schema for " ++ @typeName(T) ++
                "; use std.json.Value for an unconstrained value",
        ),
    }
}

fn writeObjectSchema(
    comptime buffer: *[]const u8,
    comptime T: type,
    comptime description: ?[]const u8,
) void {
    const fields = @typeInfo(T).@"struct".fields;

    buffer.* = buffer.* ++ "{\"type\":\"object\",\"properties\":{";
    var written: usize = 0;
    for (fields) |field| {
        if (field.is_comptime) continue;
        if (written > 0) buffer.* = buffer.* ++ ",";
        written += 1;

        buffer.* = buffer.* ++ "\"" ++ escape(field.name) ++ "\":";

        // Splice the header annotation into the property schema, which is where
        // the transport spec expects to find it.
        const header = headerName(T, field.name);
        if (header) |name| {
            // The property schema is generated first, then reopened to append the
            // annotation, so the annotation cannot disturb the type keywords.
            var property: []const u8 = "";
            writeSchema(&property, field.type, docFor(T, field.name));
            comptime_assert(property.len >= 2);
            buffer.* = buffer.* ++ property[0 .. property.len - 1];
            const separator = if (property.len > 2) "," else "";
            buffer.* = buffer.* ++ separator ++
                "\"" ++ header_annotation ++ "\":\"" ++ escape(name) ++ "\"}";
        } else {
            writeSchema(buffer, field.type, docFor(T, field.name));
        }
    }
    buffer.* = buffer.* ++ "}";

    // Required is every field that is neither optional nor defaulted: those are
    // exactly the ones a caller must supply for the Zig decode to succeed.
    var required: []const u8 = "";
    var required_count: usize = 0;
    for (fields) |field| {
        if (field.is_comptime) continue;
        if (@typeInfo(field.type) == .optional) continue;
        if (field.default_value_ptr != null) continue;
        if (required_count > 0) required = required ++ ",";
        required = required ++ "\"" ++ escape(field.name) ++ "\"";
        required_count += 1;
    }
    if (required_count > 0) {
        buffer.* = buffer.* ++ ",\"required\":[" ++ required ++ "]";
    }

    // Unknown properties are rejected: the Zig decode would fail on them anyway,
    // and saying so up front lets a model correct itself before calling.
    buffer.* = buffer.* ++ ",\"additionalProperties\":false";
    writeDescription(buffer, description, true);
    buffer.* = buffer.* ++ "}";
}

fn writeDescription(
    comptime buffer: *[]const u8,
    comptime description: ?[]const u8,
    comptime needs_comma: bool,
) void {
    const text = description orelse return;
    if (text.len == 0) return;
    const separator = if (needs_comma) "," else "";
    buffer.* = buffer.* ++ separator ++ "\"description\":\"" ++ escape(text) ++ "\"";
}

/// The description declared for `field_name`, if the type opted in.
fn docFor(comptime T: type, comptime field_name: []const u8) ?[]const u8 {
    if (!@hasDecl(T, docs_decl)) return null;
    const docs = @field(T, docs_decl);
    if (!@hasField(@TypeOf(docs), field_name)) return null;
    const text: []const u8 = @field(docs, field_name);
    return text;
}

/// JSON string escaping, at comptime.
fn escape(comptime text: []const u8) []const u8 {
    const escaped = struct {
        const value = build: {
            var out: []const u8 = "";
            for (text) |byte| {
                out = out ++ switch (byte) {
                    '"' => "\\\"",
                    '\\' => "\\\\",
                    '\n' => "\\n",
                    '\r' => "\\r",
                    '\t' => "\\t",
                    0x08 => "\\b",
                    0x0c => "\\f",
                    // Other control characters have no short escape and must be
                    // written as \u00XX to stay valid JSON.
                    0x00...0x07, 0x0b, 0x0e...0x1f => std.fmt.comptimePrint("\\u{x:0>4}", .{byte}),
                    else => &[_]u8{byte},
                };
            }
            break :build out;
        };
    };
    return escaped.value;
}

// ---------------------------------------------------------------------------
// `x-mcp-header` constraints
// ---------------------------------------------------------------------------

/// Enforces, at compile time, the constraints the Streamable HTTP transport puts
/// on `x-mcp-header`. A violation makes the whole tool definition invalid, and a
/// conforming client must drop such a tool — so catching it here turns a silent
/// interoperability failure into a build failure.
fn validateHeaderAnnotations(comptime T: type) void {
    if (!@hasDecl(T, headers_decl)) return;
    const headers = @field(T, headers_decl);
    const header_fields = @typeInfo(@TypeOf(headers)).@"struct".fields;

    for (header_fields, 0..) |entry, index| {
        if (!@hasField(T, entry.name)) {
            @compileError(headers_decl ++ " names '" ++ entry.name ++
                "', which is not a field of " ++ @typeName(T));
        }

        const name: []const u8 = @field(headers, entry.name);
        if (name.len == 0) {
            @compileError("x-mcp-header for '" ++ entry.name ++ "' must not be empty");
        }
        for (name) |byte| {
            if (!isTokenChar(byte)) {
                @compileError("x-mcp-header '" ++ name ++ "' for '" ++ entry.name ++
                    "' is not a valid HTTP field-name token (RFC 9110 §5.1)");
            }
        }

        // Case-insensitively unique, because HTTP field names are.
        for (header_fields[index + 1 ..]) |other| {
            const other_name: []const u8 = @field(headers, other.name);
            if (eqlIgnoreCaseComptime(name, other_name)) {
                @compileError("x-mcp-header '" ++ name ++
                    "' is used twice (case-insensitively) in " ++ @typeName(T));
            }
        }

        validateHeaderType(T, entry.name);
    }
}

fn validateHeaderType(comptime T: type, comptime field_name: []const u8) void {
    const Field = @FieldType(T, field_name);
    const Unwrapped = if (@typeInfo(Field) == .optional)
        @typeInfo(Field).optional.child
    else
        Field;

    switch (@typeInfo(Unwrapped)) {
        .bool, .int => {},
        .@"enum" => {}, // Serializes as a string, so header-safe.
        .pointer => |info| if (!(info.size == .slice and info.child == u8)) {
            @compileError("x-mcp-header on '" ++ field_name ++
                "' requires a primitive type (string, integer, boolean)");
        },
        .float => @compileError("x-mcp-header on '" ++ field_name ++
            "' is not allowed: the transport spec excludes `number` parameters"),
        else => @compileError("x-mcp-header on '" ++ field_name ++
            "' requires a primitive type (string, integer, boolean), found " ++
            @typeName(Unwrapped)),
    }

    // Integers wider than JavaScript's safe range cannot round-trip through a
    // header value that other implementations will parse as a double.
    if (@typeInfo(Unwrapped) == .int) {
        const bits = @typeInfo(Unwrapped).int.bits;
        const signed = @typeInfo(Unwrapped).int.signedness == .signed;
        const usable_bits = if (signed) bits - 1 else bits;
        if (usable_bits > 53) {
            @compileError("x-mcp-header on '" ++ field_name ++
                "' uses an integer wider than the JavaScript safe range (2^53-1)");
        }
    }
}

/// RFC 9110 §5.1 `tchar`.
fn isTokenChar(comptime byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn eqlIgnoreCaseComptime(comptime a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (lower(x) != lower(y)) return false;
    }
    return true;
}

fn lower(comptime byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + 32,
        else => byte,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Asserts the generated schema is byte-identical to `expected`, and that it is
/// valid JSON — a generator bug that produced malformed text would otherwise only
/// surface once a peer tried to parse it.
fn expectSchema(comptime T: type, expected: []const u8) !void {
    const generated = of(T);
    try testing.expectEqualStrings(expected, generated);

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        generated,
        .{},
    );
    defer parsed.deinit();
}

test "scalars map onto their JSON Schema types" {
    try expectSchema(bool,
        \\{"type":"boolean"}
    );
    try expectSchema(i64,
        \\{"type":"integer"}
    );
    try expectSchema(f64,
        \\{"type":"number"}
    );
    try expectSchema([]const u8,
        \\{"type":"string"}
    );
}

test "unsigned integers declare a lower bound" {
    // A caller cannot send -1 to a u8 field, and the schema should say so rather
    // than leaving the model to discover it through a decode error.
    try expectSchema(u8,
        \\{"type":"integer","minimum":0}
    );
    try expectSchema(u64,
        \\{"type":"integer","minimum":0}
    );
    try expectSchema(i8,
        \\{"type":"integer"}
    );
}

test "enums become string enumerations" {
    const Units = enum { metric, imperial };
    try expectSchema(Units,
        \\{"type":"string","enum":["metric","imperial"]}
    );
}

test "json values stay unconstrained" {
    try expectSchema(std.json.Value, "{}");
}

test "structs describe properties and required fields" {
    const Args = struct {
        city: []const u8,
        days: u8,
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"city":{"type":"string"},
    ++
        \\"days":{"type":"integer","minimum":0}},
    ++
        \\"required":["city","days"],"additionalProperties":false}
    );
}

test "optional fields are not required" {
    const Args = struct {
        city: []const u8,
        units: ?[]const u8 = null,
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"city":{"type":"string"},
    ++
        \\"units":{"type":"string"}},
    ++
        \\"required":["city"],"additionalProperties":false}
    );
}

test "defaulted fields are not required" {
    // A default means the handler can run without the caller supplying anything,
    // which is the same contract as an absent-but-allowed property.
    const Args = struct {
        limit: u32 = 10,
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"limit":{"type":"integer","minimum":0}},
    ++
        \\"additionalProperties":false}
    );
}

test "a struct with no required fields omits the required keyword" {
    const Args = struct {
        a: ?bool = null,
    };
    const generated = of(Args);
    try testing.expect(std.mem.indexOf(u8, generated, "\"required\"") == null);
}

test "slices become arrays" {
    const Args = struct {
        tags: []const []const u8,
        scores: []const i32,
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}},
    ++
        \\"scores":{"type":"array","items":{"type":"integer"}}},
    ++
        \\"required":["tags","scores"],"additionalProperties":false}
    );
}

test "fixed-size arrays carry length bounds" {
    try expectSchema([3]i32,
        \\{"type":"array","items":{"type":"integer"},"minItems":3,"maxItems":3}
    );
    // A byte array is a string, not an array of integers.
    try expectSchema([4]u8,
        \\{"type":"string"}
    );
}

test "nested structs nest their schemas" {
    const Point = struct { x: f64, y: f64 };
    const Args = struct {
        origin: Point,
        target: ?Point = null,
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"origin":{"type":"object","properties":
    ++
        \\{"x":{"type":"number"},"y":{"type":"number"}},"required":["x","y"],
    ++
        \\"additionalProperties":false},"target":{"type":"object","properties":
    ++
        \\{"x":{"type":"number"},"y":{"type":"number"}},"required":["x","y"],
    ++
        \\"additionalProperties":false}},"required":["origin"],"additionalProperties":false}
    );
}

test "descriptions come from the schema_docs declaration" {
    const Args = struct {
        city: []const u8,
        days: ?u8 = null,

        pub const schema_docs = .{
            .city = "The city to look up",
            .days = "How many days to forecast",
        };
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"city":{"type":"string","description":"The city to look up"},
    ++
        \\"days":{"type":"integer","minimum":0,"description":"How many days to forecast"}},
    ++
        \\"required":["city"],"additionalProperties":false}
    );
}

test "descriptions are JSON-escaped" {
    const Args = struct {
        city: []const u8,

        pub const schema_docs = .{
            .city = "Quote \" backslash \\ newline \n tab \t",
        };
    };
    const generated = of(Args);
    try testing.expect(std.mem.indexOf(u8, generated, "\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, generated, "\\\\") != null);
    try testing.expect(std.mem.indexOf(u8, generated, "\\n") != null);
    // Still parseable, which is the property that actually matters.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, generated, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(
        "Quote \" backslash \\ newline \n tab \t",
        parsed.value.object.get("properties").?.object.get("city").?.object.get("description").?.string,
    );
}

test "a described json value stays an open schema" {
    const Args = struct {
        payload: std.json.Value,

        pub const schema_docs = .{ .payload = "Anything" };
    };
    try expectSchema(Args,
        \\{"type":"object","properties":{"payload":{"description":"Anything"}},
    ++
        \\"required":["payload"],"additionalProperties":false}
    );
}

test "header annotations are spliced into the property schema" {
    const Args = struct {
        region: []const u8,
        query: []const u8,

        pub const schema_docs = .{ .region = "The region to execute the query in" };
        pub const mcp_headers = .{ .region = "Region" };
    };
    // Matches the shape of the example in the transport specification.
    try expectSchema(Args,
        \\{"type":"object","properties":{"region":{"type":"string",
    ++
        \\"description":"The region to execute the query in","x-mcp-header":"Region"},
    ++
        \\"query":{"type":"string"}},"required":["region","query"],"additionalProperties":false}
    );
}

test "a header annotation on an open value produces valid json" {
    const Args = struct {
        anything: std.json.Value,

        pub const mcp_headers = .{ .anything = "Anything" };
    };
    // The property schema is `{}`, so the annotation must not be preceded by a
    // comma. This is the case that a naive splice gets wrong.
    try expectSchema(Args,
        \\{"type":"object","properties":{"anything":{"x-mcp-header":"Anything"}},
    ++
        \\"required":["anything"],"additionalProperties":false}
    );
}

test "header mappings are reported for the transport" {
    const Args = struct {
        region: []const u8,
        tenant: ?u32 = null,
        query: []const u8,

        pub const mcp_headers = .{ .region = "Region", .tenant = "Tenant" };
    };

    try testing.expectEqualStrings("Region", headerName(Args, "region").?);
    try testing.expectEqualStrings("Tenant", headerName(Args, "tenant").?);
    try testing.expect(headerName(Args, "query") == null);

    const mappings = headerMappings(Args);
    try testing.expectEqual(@as(usize, 2), mappings.len);
    try testing.expectEqualStrings("region", mappings[0].field);
    try testing.expectEqualStrings("Region", mappings[0].header);
    try testing.expectEqualStrings("tenant", mappings[1].field);
}

test "types without annotations report no mappings" {
    const Args = struct { a: bool };
    try testing.expectEqual(@as(usize, 0), headerMappings(Args).len);
    try testing.expect(headerName(Args, "a") == null);
    try testing.expect(headerName(u8, "a") == null);
}

test "argument schemas accept void for a tool with no parameters" {
    try testing.expectEqualStrings(
        \\{"type":"object","properties":{}}
    , ofArguments(void));
}

test "argument schemas validate header annotations" {
    const Args = struct {
        region: []const u8,
        pub const mcp_headers = .{ .region = "Region" };
    };
    // Compiles, which is the assertion: the constraint checks pass for a valid
    // annotation. The rejection cases cannot be expressed as tests because they
    // are compile errors by design.
    const generated = ofArguments(Args);
    try testing.expect(std.mem.indexOf(u8, generated, "\"x-mcp-header\":\"Region\"") != null);
}

test "generated schemas satisfy JSON Schema 2020-12 structural expectations" {
    const Args = struct {
        city: []const u8,
        days: ?u8 = null,
        tags: []const []const u8,

        pub const schema_docs = .{ .city = "City" };
    };

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        of(Args),
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value.object;
    try testing.expectEqualStrings("object", root.get("type").?.string);

    const properties = root.get("properties").?.object;
    try testing.expectEqual(@as(usize, 3), properties.count());
    try testing.expectEqualStrings("string", properties.get("city").?.object.get("type").?.string);
    try testing.expectEqualStrings("integer", properties.get("days").?.object.get("type").?.string);
    try testing.expectEqualStrings("array", properties.get("tags").?.object.get("type").?.string);

    const required = root.get("required").?.array;
    try testing.expectEqual(@as(usize, 2), required.items.len);
    try testing.expectEqualStrings("city", required.items[0].string);
    try testing.expectEqualStrings("tags", required.items[1].string);

    try testing.expectEqual(false, root.get("additionalProperties").?.bool);
}

test "generated schemas decode the values they describe" {
    const Args = struct {
        city: []const u8,
        days: ?u8 = null,
        units: enum { metric, imperial } = .metric,
    };

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The point of generating from the type: a payload the schema accepts is a
    // payload the Zig decoder accepts.
    const args = try std.json.parseFromSliceLeaky(Args, arena.allocator(),
        \\{"city":"Seattle","days":3,"units":"imperial"}
    , .{});
    try testing.expectEqualStrings("Seattle", args.city);
    try testing.expectEqual(@as(u8, 3), args.days.?);
    try testing.expectEqual(.imperial, args.units);

    // And the optional/defaulted fields really are optional.
    const minimal = try std.json.parseFromSliceLeaky(Args, arena.allocator(),
        \\{"city":"Seattle"}
    , .{});
    try testing.expect(minimal.days == null);
    try testing.expectEqual(.metric, minimal.units);
}

test "generation costs nothing at run time" {
    const Args = struct { city: []const u8 };
    // A comptime-known string: the schema is a literal in the binary, so a server
    // can advertise its tools without allocating.
    comptime {
        const generated = of(Args);
        comptime_assert(generated.len > 0);
        comptime_assert(generated[0] == '{');
    }
    try testing.expect(@typeInfo(@TypeOf(of(Args))) == .pointer);
}
