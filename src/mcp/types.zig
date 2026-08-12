//! MCP protocol types for revision 2026-07-28, mirroring `spec/schema.json`.
//!
//! Two conventions run through this file.
//!
//! **Optional fields are `?T` and omitted when null.** Serialize with
//! `stringify_options` (or the `stringifyAlloc` helper) so that
//! `emit_null_optional_fields` is off; emitting `"title": null` where the schema
//! expects the key to be absent is a real interoperability problem, not a
//! cosmetic one.
//!
//! **`_meta` is modelled, not passed through blindly.** The specification reserves
//! keys under `io.modelcontextprotocol/` and carries required protocol state
//! there — the protocol version, the client's capabilities, the per-request log
//! level. Those get named Zig fields; everything else in `_meta` (application
//! metadata, OpenTelemetry trace context) travels in `extra` untouched, because
//! the spec requires implementations to preserve keys they do not understand.
//!
//! Where the schema leaves a value open — tool arguments, `structuredContent`,
//! `inputSchema` — the type here is `std.json.Value`. Those are user-defined by
//! design and pinning them to a Zig type would be wrong.

const std = @import("std");
const assert_mod = @import("assert");
const jsonrpc = @import("jsonrpc.zig");

const assert = assert_mod.assert;

/// The protocol revision this SDK implements.
pub const protocol_version = "2026-07-28";

/// Reserved `_meta` keys, spelled exactly as they appear on the wire.
pub const meta_key = struct {
    pub const protocol_version = "io.modelcontextprotocol/protocolVersion";
    pub const client_info = "io.modelcontextprotocol/clientInfo";
    pub const client_capabilities = "io.modelcontextprotocol/clientCapabilities";
    pub const server_info = "io.modelcontextprotocol/serverInfo";
    pub const log_level = "io.modelcontextprotocol/logLevel";
    pub const subscription_id = "io.modelcontextprotocol/subscriptionId";
    /// Unprefixed, unlike the others: `progressToken` predates the prefix
    /// convention and the schema still spells it bare.
    pub const progress_token = "progressToken";
};

/// Serialization options for every MCP payload. Absent optionals must not appear
/// as `null` on the wire.
pub const stringify_options: std.json.Stringify.Options = .{
    .emit_null_optional_fields = false,
};

/// Encodes any MCP type with the right options. Caller owns the bytes.
pub fn stringifyAlloc(gpa: std.mem.Allocator, value: anytype) error{OutOfMemory}![]u8 {
    return std.json.Stringify.valueAlloc(gpa, value, stringify_options);
}

/// Encodes any MCP type straight into a writer.
pub fn stringify(writer: *std.Io.Writer, value: anytype) std.Io.Writer.Error!void {
    return std.json.Stringify.value(value, stringify_options, writer);
}

/// A JSON value that is either already encoded or built at run time.
///
/// The `raw` variant exists for schemas generated at compile time: those are
/// string literals in the binary, and re-parsing one into a `std.json.Value` just
/// to serialize it again would allocate for no reason. The `value` variant covers
/// anything assembled at run time.
///
/// A `raw` payload is emitted verbatim, so it must be valid JSON. `validate`
/// checks that, and the registry calls it when a definition is added.
pub const Json = union(enum) {
    raw: []const u8,
    value: std.json.Value,

    pub fn jsonStringify(self: Json, stream: anytype) !void {
        switch (self) {
            .raw => |bytes| {
                try stream.beginWriteRaw();
                try stream.writer.writeAll(bytes);
                stream.endWriteRaw();
            },
            .value => |value| try stream.write(value),
        }
    }

    /// Confirms a `raw` payload really is JSON. Cheap for the `value` variant,
    /// which is well-formed by construction.
    pub fn validate(self: Json, gpa: std.mem.Allocator) error{ InvalidJson, OutOfMemory }!void {
        switch (self) {
            .raw => |bytes| {
                const ok = std.json.Scanner.validate(gpa, bytes) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                };
                if (!ok) return error.InvalidJson;
            },
            .value => {},
        }
    }

    /// Decoding always produces the `value` variant. `raw` exists so that a
    /// comptime-generated schema can be written without allocating; nothing on the
    /// receiving side benefits from re-deriving it, and a client that wants the
    /// original bytes can re-encode.
    pub fn jsonParseFromValue(
        _: std.mem.Allocator,
        source: std.json.Value,
        _: std.json.ParseOptions,
    ) !Json {
        return .{ .value = source };
    }
};

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Every result carries one of these. `input_required` marks the interim result of
/// a multi round-trip request; `complete` marks a final one.
///
/// New in 2026-07-28, where a server MUST send it. A client, however, MUST accept
/// its absence: the schema requires that a result from a server implementing an
/// earlier revision — which has no such field — be read as `complete`. That rule is
/// unconditional, not something a single-revision client may opt out of, so this SDK
/// sends the field on every result it produces and defaults it on every result it
/// reads. See `resultTypeOf`.
pub const ResultType = enum {
    complete,
    input_required,
};

/// Whether a cached response may be shared across authorization contexts.
pub const CacheScope = enum {
    public,
    private,
};

/// Who a piece of content is intended for.
pub const Role = enum {
    user,
    assistant,
};

/// Log severities, mapped from syslog (RFC 5424 §6.2.1).
///
/// Logging is deprecated in 2026-07-28 but still specified: servers may only emit
/// `notifications/message` for a request that asked for a level, and this is how
/// the level is named.
pub const LoggingLevel = enum {
    debug,
    info,
    notice,
    warning,
    // `error` is a Zig keyword; the quoted form keeps the wire name identical.
    @"error",
    critical,
    alert,
    emergency,

    /// Ordering by severity, so a server can filter against the requested level.
    /// Lower is less severe, matching syslog's own ordering.
    pub fn severity(level: LoggingLevel) u3 {
        return switch (level) {
            .debug => 0,
            .info => 1,
            .notice => 2,
            .warning => 3,
            .@"error" => 4,
            .critical => 5,
            .alert => 6,
            .emergency => 7,
        };
    }

    /// True when a message at `level` should be delivered to a client that asked
    /// for `minimum`.
    pub fn atLeast(level: LoggingLevel, minimum: LoggingLevel) bool {
        return level.severity() >= minimum.severity();
    }
};

/// An opaque pagination position. Servers mint these; clients echo them back.
pub const Cursor = []const u8;

/// Correlates progress notifications with the request that asked for them. Same
/// string-or-integer shape as a JSON-RPC id.
pub const ProgressToken = jsonrpc.Id;

// ---------------------------------------------------------------------------
// Shared metadata
// ---------------------------------------------------------------------------

/// Identifies a peer's software. Self-reported and unverified: useful for display
/// and debugging, and explicitly not to be used for security decisions.
pub const Implementation = struct {
    name: []const u8,
    version: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    websiteUrl: ?[]const u8 = null,
    icons: ?[]const Icon = null,
};

/// A sized icon a client may render.
pub const Icon = struct {
    src: []const u8,
    mimeType: ?[]const u8 = null,
    sizes: ?[]const []const u8 = null,
    theme: ?enum { light, dark } = null,
};

/// Hints about how content should be used or displayed.
pub const Annotations = struct {
    audience: ?[]const Role = null,
    /// 1 means effectively required, 0 entirely optional.
    priority: ?f64 = null,
    /// ISO 8601, e.g. `2025-01-12T15:00:58Z`.
    lastModified: ?[]const u8 = null,
};

/// Optional capabilities a client declares. Sent on *every* request in
/// 2026-07-28: the protocol is stateless, so a server must not infer capabilities
/// from anything it saw earlier.
///
/// `roots` and `sampling` are deprecated in this revision; they are modelled so
/// that a peer declaring them can be understood, not because this SDK offers them.
pub const ClientCapabilities = struct {
    elicitation: ?std.json.Value = null,
    roots: ?std.json.Value = null,
    sampling: ?std.json.Value = null,
    experimental: ?std.json.Value = null,
    extensions: ?std.json.Value = null,

    /// A client with no optional capabilities. Serializes to `{}`, which the spec
    /// requires rather than allowing the field to be absent.
    pub const none: ClientCapabilities = .{};
};

/// What a server offers, as advertised by `server/discover`.
pub const ServerCapabilities = struct {
    tools: ?std.json.Value = null,
    prompts: ?std.json.Value = null,
    resources: ?std.json.Value = null,
    completions: ?std.json.Value = null,
    logging: ?std.json.Value = null,
    experimental: ?std.json.Value = null,
    extensions: ?std.json.Value = null,
};

/// `_meta` on a request.
///
/// `protocol_version` and `capabilities` are required by the schema; the rest are
/// optional. Unrecognized keys survive a decode/encode round trip in `extra`.
pub const RequestMeta = struct {
    protocol_version: []const u8 = protocol_version,
    capabilities: ClientCapabilities = .none,
    client_info: ?Implementation = null,
    /// When absent, the server MUST NOT emit `notifications/message` for this
    /// request. There is no separate `logging/setLevel` any more: this field is
    /// the only way a client opts in, and it does so per request.
    log_level: ?LoggingLevel = null,
    /// Asks for `notifications/progress` tagged with this token.
    progress_token: ?ProgressToken = null,
    /// Keys this SDK does not interpret, preserved verbatim.
    extra: ?std.json.ObjectMap = null,

    /// The keys this type owns. Used both to strip them out of `extra` on decode
    /// and to keep them from being duplicated on encode.
    const reserved_keys = [_][]const u8{
        meta_key.protocol_version,
        meta_key.client_capabilities,
        meta_key.client_info,
        meta_key.log_level,
        meta_key.progress_token,
    };

    pub fn jsonStringify(self: RequestMeta, stream: anytype) !void {
        try stream.beginObject();
        try writeExtra(stream, self.extra, &reserved_keys);
        try stream.objectField(meta_key.protocol_version);
        try stream.write(self.protocol_version);
        try stream.objectField(meta_key.client_capabilities);
        try stream.write(self.capabilities);
        if (self.client_info) |info| {
            try stream.objectField(meta_key.client_info);
            try stream.write(info);
        }
        if (self.log_level) |level| {
            try stream.objectField(meta_key.log_level);
            try stream.write(level);
        }
        if (self.progress_token) |token| {
            try stream.objectField(meta_key.progress_token);
            try stream.write(token);
        }
        try stream.endObject();
    }

    /// Decodes `_meta` from a request's params. Borrows from `value`.
    pub fn fromValue(gpa: std.mem.Allocator, value: std.json.Value) !RequestMeta {
        const object = switch (value) {
            .object => |o| o,
            else => return error.InvalidMeta,
        };

        var meta: RequestMeta = .{};
        meta.protocol_version = switch (object.get(meta_key.protocol_version) orelse
            return error.MissingProtocolVersion) {
            .string => |s| s,
            else => return error.InvalidMeta,
        };
        if (object.get(meta_key.client_capabilities)) |capabilities| {
            meta.capabilities = try capabilitiesFromValue(capabilities);
        } else {
            return error.MissingClientCapabilities;
        }
        if (object.get(meta_key.client_info)) |info| {
            meta.client_info = try implementationFromValue(gpa, info);
        }
        if (object.get(meta_key.log_level)) |level| {
            meta.log_level = try enumFromValue(LoggingLevel, level);
        }
        if (object.get(meta_key.progress_token)) |token| {
            meta.progress_token = jsonrpc.Id.fromValue(token) catch return error.InvalidMeta;
        }
        meta.extra = try collectExtra(gpa, object, &reserved_keys);
        return meta;
    }

    pub fn deinit(self: *RequestMeta, gpa: std.mem.Allocator) void {
        if (self.extra) |*extra| extra.deinit(gpa);
        self.extra = null;
    }
};

/// `_meta` on a result. Servers should identify themselves here on every response.
pub const ResultMeta = struct {
    server_info: ?Implementation = null,
    /// Set by the server on every notification delivered over a
    /// `subscriptions/listen` stream, so the client can attribute it.
    subscription_id: ?jsonrpc.Id = null,
    extra: ?std.json.ObjectMap = null,

    const reserved_keys = [_][]const u8{
        meta_key.server_info,
        meta_key.subscription_id,
    };

    pub fn jsonStringify(self: ResultMeta, stream: anytype) !void {
        try stream.beginObject();
        try writeExtra(stream, self.extra, &reserved_keys);
        if (self.server_info) |info| {
            try stream.objectField(meta_key.server_info);
            try stream.write(info);
        }
        if (self.subscription_id) |id| {
            try stream.objectField(meta_key.subscription_id);
            try stream.write(id);
        }
        try stream.endObject();
    }

    pub fn fromValue(gpa: std.mem.Allocator, value: std.json.Value) !ResultMeta {
        const object = switch (value) {
            .object => |o| o,
            else => return error.InvalidMeta,
        };
        var meta: ResultMeta = .{};
        if (object.get(meta_key.server_info)) |info| {
            meta.server_info = try implementationFromValue(gpa, info);
        }
        if (object.get(meta_key.subscription_id)) |id| {
            meta.subscription_id = jsonrpc.Id.fromValue(id) catch return error.InvalidMeta;
        }
        meta.extra = try collectExtra(gpa, object, &reserved_keys);
        return meta;
    }

    pub fn deinit(self: *ResultMeta, gpa: std.mem.Allocator) void {
        if (self.extra) |*extra| extra.deinit(gpa);
        self.extra = null;
    }
};

/// Writes passthrough keys, skipping any that the protocol owns.
///
/// Filtering rather than letting a later write win matters: emitting the same key
/// twice produces JSON that strict parsers — including `std.json` — reject, so a
/// caller who put a reserved key in `extra` would otherwise corrupt the message.
fn writeExtra(
    stream: anytype,
    extra: ?std.json.ObjectMap,
    comptime reserved: []const []const u8,
) !void {
    const map = extra orelse return;
    var it = map.iterator();
    outer: while (it.next()) |entry| {
        inline for (reserved) |key| {
            if (std.mem.eql(u8, entry.key_ptr.*, key)) continue :outer;
        }
        try stream.objectField(entry.key_ptr.*);
        try stream.write(entry.value_ptr.*);
    }
}

/// Copies every key of `object` except `known` into a fresh map.
fn collectExtra(
    gpa: std.mem.Allocator,
    object: std.json.ObjectMap,
    comptime known: []const []const u8,
) !?std.json.ObjectMap {
    var extra: std.json.ObjectMap = .empty;
    errdefer extra.deinit(gpa);

    var it = object.iterator();
    outer: while (it.next()) |entry| {
        inline for (known) |key| {
            if (std.mem.eql(u8, entry.key_ptr.*, key)) continue :outer;
        }
        try extra.put(gpa, entry.key_ptr.*, entry.value_ptr.*);
    }
    if (extra.count() == 0) {
        extra.deinit(gpa);
        return null;
    }
    return extra;
}

fn capabilitiesFromValue(value: std.json.Value) !ClientCapabilities {
    const object = switch (value) {
        .object => |o| o,
        else => return error.InvalidMeta,
    };
    return .{
        .elicitation = object.get("elicitation"),
        .roots = object.get("roots"),
        .sampling = object.get("sampling"),
        .experimental = object.get("experimental"),
        .extensions = object.get("extensions"),
    };
}

fn implementationFromValue(gpa: std.mem.Allocator, value: std.json.Value) !Implementation {
    return std.json.parseFromValueLeaky(Implementation, gpa, value, .{
        .ignore_unknown_fields = true,
    }) catch error.InvalidMeta;
}

fn enumFromValue(comptime E: type, value: std.json.Value) !E {
    const name = switch (value) {
        .string => |s| s,
        else => return error.InvalidMeta,
    };
    return std.meta.stringToEnum(E, name) orelse error.InvalidMeta;
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

pub const TextContent = struct {
    text: []const u8,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,

    pub fn jsonStringify(self: TextContent, stream: anytype) !void {
        try writeTagged(stream, "text", self);
    }
};

pub const ImageContent = struct {
    /// Base64-encoded image bytes.
    data: []const u8,
    mimeType: []const u8,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,

    pub fn jsonStringify(self: ImageContent, stream: anytype) !void {
        try writeTagged(stream, "image", self);
    }
};

pub const AudioContent = struct {
    /// Base64-encoded audio bytes.
    data: []const u8,
    mimeType: []const u8,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,

    pub fn jsonStringify(self: AudioContent, stream: anytype) !void {
        try writeTagged(stream, "audio", self);
    }
};

/// A pointer to a resource the client may read separately, as opposed to one
/// embedded inline.
pub const ResourceLink = struct {
    uri: []const u8,
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mimeType: ?[]const u8 = null,
    size: ?i64 = null,
    icons: ?[]const Icon = null,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,

    pub fn jsonStringify(self: ResourceLink, stream: anytype) !void {
        try writeTagged(stream, "resource_link", self);
    }
};

/// Resource contents carried inline in a result.
pub const EmbeddedResource = struct {
    resource: ResourceContents,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,

    pub fn jsonStringify(self: EmbeddedResource, stream: anytype) !void {
        try writeTagged(stream, "resource", self);
    }
};

/// Emits `{"type": <tag>, ...fields}` without the struct having to carry a
/// mutable `type` field that a caller could set inconsistently.
fn writeTagged(stream: anytype, comptime tag: []const u8, value: anytype) !void {
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write(tag);
    inline for (@typeInfo(@TypeOf(value)).@"struct".fields) |field| {
        const field_value = @field(value, field.name);
        if (@typeInfo(field.type) == .optional) {
            if (field_value) |present| {
                try stream.objectField(field.name);
                try stream.write(present);
            }
        } else {
            try stream.objectField(field.name);
            try stream.write(field_value);
        }
    }
    try stream.endObject();
}

/// The contents of a resource: text or binary, never both.
pub const ResourceContents = union(enum) {
    text: TextResourceContents,
    blob: BlobResourceContents,

    pub fn jsonStringify(self: ResourceContents, stream: anytype) !void {
        switch (self) {
            inline else => |contents| try stream.write(contents),
        }
    }

    pub fn uri(self: ResourceContents) []const u8 {
        return switch (self) {
            inline else => |contents| contents.uri,
        };
    }
};

pub const TextResourceContents = struct {
    uri: []const u8,
    text: []const u8,
    mimeType: ?[]const u8 = null,
    _meta: ?std.json.Value = null,
};

pub const BlobResourceContents = struct {
    uri: []const u8,
    /// Base64-encoded bytes.
    blob: []const u8,
    mimeType: ?[]const u8 = null,
    _meta: ?std.json.Value = null,
};

/// Any content block that can appear in a tool result or prompt message.
pub const ContentBlock = union(enum) {
    text: TextContent,
    image: ImageContent,
    audio: AudioContent,
    resource_link: ResourceLink,
    resource: EmbeddedResource,

    pub fn jsonStringify(self: ContentBlock, stream: anytype) !void {
        switch (self) {
            inline else => |block| try stream.write(block),
        }
    }

    /// Convenience constructor for the overwhelmingly common case.
    pub fn fromText(text: []const u8) ContentBlock {
        return .{ .text = .{ .text = text } };
    }

    /// Decodes a block, dispatching on the `type` discriminator.
    pub fn fromValue(gpa: std.mem.Allocator, value: std.json.Value) !ContentBlock {
        const object = switch (value) {
            .object => |o| o,
            else => return error.InvalidContent,
        };
        const tag = switch (object.get("type") orelse return error.InvalidContent) {
            .string => |s| s,
            else => return error.InvalidContent,
        };
        if (std.mem.eql(u8, tag, "text")) {
            return .{ .text = try parseWire(TextContent, gpa, value) };
        }
        if (std.mem.eql(u8, tag, "image")) {
            return .{ .image = try parseWire(ImageContent, gpa, value) };
        }
        if (std.mem.eql(u8, tag, "audio")) {
            return .{ .audio = try parseWire(AudioContent, gpa, value) };
        }
        if (std.mem.eql(u8, tag, "resource_link")) {
            return .{ .resource_link = try parseWire(ResourceLink, gpa, value) };
        }
        if (std.mem.eql(u8, tag, "resource")) {
            const resource = object.get("resource") orelse return error.InvalidContent;
            return .{ .resource = .{
                .resource = try resourceContentsFromValue(gpa, resource),
            } };
        }
        return error.UnknownContentType;
    }
};

/// Parses a wire struct, keeping "we ran out of memory" distinct from "the peer sent
/// something invalid".
///
/// Collapsing the two would be a real bug: a client that reports malformed input
/// when it actually failed to allocate sends the caller looking in the wrong place,
/// and may make it retry a request that will fail again for the same reason.
fn parseWire(
    comptime T: type,
    gpa: std.mem.Allocator,
    value: std.json.Value,
) error{ InvalidContent, OutOfMemory }!T {
    return std.json.parseFromValueLeaky(T, gpa, value, .{
        // A newer peer may add fields; refusing them would break on the next
        // revision.
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidContent,
    };
}

fn resourceContentsFromValue(
    gpa: std.mem.Allocator,
    value: std.json.Value,
) !ResourceContents {
    const object = switch (value) {
        .object => |o| o,
        else => return error.InvalidContent,
    };
    if (object.get("text") != null) {
        return .{ .text = try parseWire(TextResourceContents, gpa, value) };
    }
    if (object.get("blob") != null) {
        return .{ .blob = try parseWire(BlobResourceContents, gpa, value) };
    }
    return error.InvalidContent;
}

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

/// Behavioural hints about a tool. All of them are untrusted unless the server is
/// trusted, and the schema says as much: a client must not make security
/// decisions on their basis.
pub const ToolAnnotations = struct {
    title: ?[]const u8 = null,
    readOnlyHint: ?bool = null,
    destructiveHint: ?bool = null,
    idempotentHint: ?bool = null,
    openWorldHint: ?bool = null,
};

pub const Tool = struct {
    name: []const u8,
    /// JSON Schema for the arguments. 2026-07-28 allows any JSON Schema 2020-12
    /// keyword here, so this stays an unconstrained value — and a `Json.raw`
    /// payload lets a comptime-generated schema be emitted without allocating.
    inputSchema: Json,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    outputSchema: ?Json = null,
    annotations: ?ToolAnnotations = null,
    icons: ?[]const Icon = null,
    _meta: ?std.json.Value = null,
};

pub const PromptArgument = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    required: ?bool = null,
};

pub const Prompt = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    arguments: ?[]const PromptArgument = null,
    icons: ?[]const Icon = null,
    _meta: ?std.json.Value = null,
};

pub const PromptMessage = struct {
    role: Role,
    content: ContentBlock,
};

pub const Resource = struct {
    uri: []const u8,
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mimeType: ?[]const u8 = null,
    size: ?i64 = null,
    icons: ?[]const Icon = null,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,
};

pub const ResourceTemplate = struct {
    uriTemplate: []const u8,
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mimeType: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    annotations: ?Annotations = null,
    _meta: ?std.json.Value = null,
};

// ---------------------------------------------------------------------------
// Request params
// ---------------------------------------------------------------------------

/// Params shared by the list endpoints.
pub const PaginatedParams = struct {
    cursor: ?Cursor = null,
    _meta: RequestMeta,
};

pub const CallToolParams = struct {
    name: []const u8,
    arguments: ?std.json.Value = null,
    /// Present when the client is retrying a request that returned
    /// `input_required`; see `InputRequiredResult`.
    inputResponses: ?std.json.Value = null,
    /// Opaque state the server asked the client to echo back on the retry.
    requestState: ?[]const u8 = null,
    _meta: RequestMeta,
};

pub const GetPromptParams = struct {
    name: []const u8,
    arguments: ?std.json.Value = null,
    inputResponses: ?std.json.Value = null,
    requestState: ?[]const u8 = null,
    _meta: RequestMeta,
};

pub const ReadResourceParams = struct {
    uri: []const u8,
    inputResponses: ?std.json.Value = null,
    requestState: ?[]const u8 = null,
    _meta: RequestMeta,
};

/// What a completion request is completing against: a prompt argument or a
/// resource template variable.
pub const CompletionReference = union(enum) {
    prompt: struct { name: []const u8, title: ?[]const u8 = null },
    resource: struct { uri: []const u8 },

    pub fn jsonStringify(self: CompletionReference, stream: anytype) !void {
        switch (self) {
            .prompt => |prompt| {
                try stream.beginObject();
                try stream.objectField("type");
                try stream.write("ref/prompt");
                try stream.objectField("name");
                try stream.write(prompt.name);
                if (prompt.title) |title| {
                    try stream.objectField("title");
                    try stream.write(title);
                }
                try stream.endObject();
            },
            .resource => |resource| {
                try stream.beginObject();
                try stream.objectField("type");
                try stream.write("ref/resource");
                try stream.objectField("uri");
                try stream.write(resource.uri);
                try stream.endObject();
            },
        }
    }

    pub fn fromValue(value: std.json.Value) !CompletionReference {
        const object = switch (value) {
            .object => |o| o,
            else => return error.InvalidParams,
        };
        const tag = switch (object.get("type") orelse return error.InvalidParams) {
            .string => |s| s,
            else => return error.InvalidParams,
        };
        if (std.mem.eql(u8, tag, "ref/prompt")) {
            const name = switch (object.get("name") orelse return error.InvalidParams) {
                .string => |s| s,
                else => return error.InvalidParams,
            };
            const title: ?[]const u8 = if (object.get("title")) |t| switch (t) {
                .string => |s| s,
                else => null,
            } else null;
            return .{ .prompt = .{ .name = name, .title = title } };
        }
        if (std.mem.eql(u8, tag, "ref/resource")) {
            const uri = switch (object.get("uri") orelse return error.InvalidParams) {
                .string => |s| s,
                else => return error.InvalidParams,
            };
            return .{ .resource = .{ .uri = uri } };
        }
        return error.InvalidParams;
    }
};

pub const CompleteParams = struct {
    ref: CompletionReference,
    argument: struct { name: []const u8, value: []const u8 },
    context: ?struct { arguments: ?std.json.Value = null } = null,
    _meta: RequestMeta,
};

/// The notification types a client opts in to on `subscriptions/listen`. Every
/// type is opt-in: a server must not send one that was not asked for.
pub const SubscriptionFilter = struct {
    toolsListChanged: ?bool = null,
    promptsListChanged: ?bool = null,
    resourcesListChanged: ?bool = null,
    /// Resource URIs to watch. Replaces the removed `resources/subscribe` RPC.
    resourceSubscriptions: ?[]const []const u8 = null,

    /// Whether this filter asks for `notifications/tools/list_changed`.
    ///
    /// An absent field is not a subscription: the spec says omitting a field is
    /// equivalent to not subscribing, so absent and `false` mean the same thing and
    /// the distinction is deliberately not exposed.
    pub fn wantsToolsListChanged(filter: SubscriptionFilter) bool {
        return filter.toolsListChanged orelse false;
    }

    pub fn wantsPromptsListChanged(filter: SubscriptionFilter) bool {
        return filter.promptsListChanged orelse false;
    }

    pub fn wantsResourcesListChanged(filter: SubscriptionFilter) bool {
        return filter.resourcesListChanged orelse false;
    }

    /// The watched URIs, or an empty slice.
    pub fn uris(filter: SubscriptionFilter) []const []const u8 {
        return filter.resourceSubscriptions orelse &.{};
    }

    /// Whether this filter subscribes to nothing at all.
    ///
    /// A server may still accept such a subscription — the stream is valid, it just
    /// carries nothing but the acknowledgement and keep-alives.
    pub fn isEmpty(filter: SubscriptionFilter) bool {
        return !filter.wantsToolsListChanged() and
            !filter.wantsPromptsListChanged() and
            !filter.wantsResourcesListChanged() and
            filter.uris().len == 0;
    }

    /// Decodes the `notifications` member of a `subscriptions/listen` request.
    ///
    /// Wrong types are rejected rather than coerced: a client that sends
    /// `"toolsListChanged": "yes"` has a bug, and silently reading it as `false`
    /// would leave it waiting for notifications that never come.
    pub fn fromValue(
        arena: std.mem.Allocator,
        value: std.json.Value,
    ) error{ InvalidFilter, OutOfMemory }!SubscriptionFilter {
        const object = switch (value) {
            .object => |o| o,
            else => return error.InvalidFilter,
        };

        var filter: SubscriptionFilter = .{};
        filter.toolsListChanged = try boolField(object, "toolsListChanged");
        filter.promptsListChanged = try boolField(object, "promptsListChanged");
        filter.resourcesListChanged = try boolField(object, "resourcesListChanged");

        if (object.get("resourceSubscriptions")) |entry| switch (entry) {
            .null => {},
            .array => |items| {
                const list = try arena.alloc([]const u8, items.items.len);
                for (items.items, list) |item, *slot| {
                    slot.* = switch (item) {
                        .string => |s| s,
                        else => return error.InvalidFilter,
                    };
                }
                filter.resourceSubscriptions = list;
            },
            else => return error.InvalidFilter,
        };

        return filter;
    }

    fn boolField(
        object: std.json.ObjectMap,
        name: []const u8,
    ) error{InvalidFilter}!?bool {
        const entry = object.get(name) orelse return null;
        return switch (entry) {
            .bool => |b| b,
            .null => null,
            else => error.InvalidFilter,
        };
    }
};

pub const SubscriptionsListenParams = struct {
    notifications: SubscriptionFilter,
    _meta: RequestMeta,
};

pub const DiscoverParams = struct {
    _meta: RequestMeta,
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// Caching hints required on the list and read results by `CacheableResult`.
pub const CacheHint = struct {
    /// Milliseconds the client may treat the result as fresh. 0 means "always
    /// re-fetch".
    ttl_ms: u64 = 0,
    scope: CacheScope = .private,

    /// A conservative default: never cached, never shared. Correct for anything
    /// user- or authorization-specific, which is the safe assumption.
    pub const no_cache: CacheHint = .{ .ttl_ms = 0, .scope = .private };
};

pub const DiscoverResult = struct {
    supportedVersions: []const []const u8,
    capabilities: ServerCapabilities,
    instructions: ?[]const u8 = null,
    cache: CacheHint = .no_cache,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: DiscoverResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try writeCacheHint(stream, self.cache);
        try stream.objectField("supportedVersions");
        try stream.write(self.supportedVersions);
        try stream.objectField("capabilities");
        try stream.write(self.capabilities);
        if (self.instructions) |instructions| {
            try stream.objectField("instructions");
            try stream.write(instructions);
        }
        try stream.endObject();
    }
};

pub const ListToolsResult = struct {
    tools: []const Tool,
    nextCursor: ?Cursor = null,
    cache: CacheHint = .no_cache,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: ListToolsResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try writeCacheHint(stream, self.cache);
        try writeCursor(stream, self.nextCursor);
        try stream.objectField("tools");
        try stream.write(self.tools);
        try stream.endObject();
    }
};

pub const ListPromptsResult = struct {
    prompts: []const Prompt,
    nextCursor: ?Cursor = null,
    cache: CacheHint = .no_cache,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: ListPromptsResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try writeCacheHint(stream, self.cache);
        try writeCursor(stream, self.nextCursor);
        try stream.objectField("prompts");
        try stream.write(self.prompts);
        try stream.endObject();
    }
};

pub const ListResourcesResult = struct {
    resources: []const Resource,
    nextCursor: ?Cursor = null,
    cache: CacheHint = .no_cache,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: ListResourcesResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try writeCacheHint(stream, self.cache);
        try writeCursor(stream, self.nextCursor);
        try stream.objectField("resources");
        try stream.write(self.resources);
        try stream.endObject();
    }
};

pub const ListResourceTemplatesResult = struct {
    resourceTemplates: []const ResourceTemplate,
    nextCursor: ?Cursor = null,
    cache: CacheHint = .no_cache,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: ListResourceTemplatesResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try writeCacheHint(stream, self.cache);
        try writeCursor(stream, self.nextCursor);
        try stream.objectField("resourceTemplates");
        try stream.write(self.resourceTemplates);
        try stream.endObject();
    }
};

pub const ReadResourceResult = struct {
    contents: []const ResourceContents,
    cache: CacheHint = .no_cache,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: ReadResourceResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try writeCacheHint(stream, self.cache);
        try stream.objectField("contents");
        try stream.write(self.contents);
        try stream.endObject();
    }
};

/// The result of `tools/call`.
///
/// `is_error` reports a *tool* failure — the tool ran and did not succeed — which
/// is different from a protocol error. Protocol errors travel as JSON-RPC error
/// responses; a failing tool still returns a successful result with this set, so
/// that the model can see and react to what went wrong.
pub const CallToolResult = struct {
    content: []const ContentBlock,
    structuredContent: ?std.json.Value = null,
    isError: ?bool = null,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: CallToolResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try stream.objectField("content");
        try stream.write(self.content);
        if (self.structuredContent) |structured| {
            try stream.objectField("structuredContent");
            try stream.write(structured);
        }
        if (self.isError) |is_error| {
            try stream.objectField("isError");
            try stream.write(is_error);
        }
        try stream.endObject();
    }
};

pub const GetPromptResult = struct {
    messages: []const PromptMessage,
    description: ?[]const u8 = null,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: GetPromptResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        if (self.description) |description| {
            try stream.objectField("description");
            try stream.write(description);
        }
        try stream.objectField("messages");
        try stream.write(self.messages);
        try stream.endObject();
    }
};

pub const Completion = struct {
    values: []const []const u8,
    total: ?i64 = null,
    hasMore: ?bool = null,
};

pub const CompleteResult = struct {
    completion: Completion,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: CompleteResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try stream.objectField("completion");
        try stream.write(self.completion);
        try stream.endObject();
    }
};

/// The interim result of a multi round-trip request: the server needs something
/// from the client before it can finish.
///
/// This replaces server-initiated requests entirely. Rather than the server
/// sending its own JSON-RPC request, it answers with this; the client fulfils the
/// `input_requests` and retries the *original* request, echoing `request_state`
/// back so the server can resume.
pub const InputRequiredResult = struct {
    /// Server-assigned key -> request object. Absent when the server only needs the
    /// client to retry, which happens with out-of-band interactions: the state
    /// alone tells it where to resume.
    inputRequests: ?std.json.Value = null,
    /// Opaque server state to be echoed on the retry.
    ///
    /// The client must not inspect, parse or modify it — and the server must treat
    /// what comes back as attacker-controlled. See `RequestState` for a sealed
    /// representation that makes tampering detectable.
    requestState: ?[]const u8 = null,
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: InputRequiredResult, stream: anytype) !void {
        // The spec requires at least one of the two: a result with neither tells the
        // client nothing about what to do next, and it would retry forever.
        assert(self.inputRequests != null or self.requestState != null);

        try stream.beginObject();
        try writeResultPreamble(stream, .input_required, self.meta);
        if (self.inputRequests) |requests| {
            try stream.objectField("inputRequests");
            try stream.write(requests);
        }
        if (self.requestState) |state| {
            try stream.objectField("requestState");
            try stream.write(state);
        }
        try stream.endObject();
    }
};

// ---------------------------------------------------------------------------
// Elicitation
// ---------------------------------------------------------------------------

/// How the user is asked.
///
/// The distinction is a security boundary, not a UI preference: form data passes
/// through the client and the model, URL interactions do not. Anything that grants
/// access or authorizes a transaction — passwords, API keys, tokens, payment
/// details — MUST go through `url`.
pub const ElicitMode = enum { form, url };

/// What the user did.
pub const ElicitAction = enum {
    /// Submitted. For form mode `content` carries the data; for url mode it means
    /// the user consented to open the URL, *not* that the interaction finished.
    accept,
    /// Explicitly refused.
    decline,
    /// Dismissed without choosing — closed the dialog, pressed escape, or the page
    /// failed to load.
    cancel,

    /// Whether the server may proceed with whatever it asked about.
    pub fn accepted(action: ElicitAction) bool {
        return action == .accept;
    }
};

/// A request for structured input, collected by the client.
pub const ElicitForm = struct {
    message: []const u8,
    /// A flat object schema of primitive properties. Nesting is deliberately not
    /// supported so that any client can render it.
    requestedSchema: Json,
};

/// A request for the user to complete something out of band.
pub const ElicitUrl = struct {
    message: []const u8,
    /// Where to send the user. Must not be pre-authenticated and must not carry
    /// anything sensitive about them: a malicious client sees this URL.
    url: []const u8,
};

/// One entry of an `inputRequests` map.
///
/// Only elicitation is modelled here. Sampling and roots are also permitted by the
/// schema, but this SDK does not implement the deprecated client features, and
/// producing a request the client cannot answer would leave it stuck.
pub const ElicitRequest = union(enum) {
    form: ElicitForm,
    url: ElicitUrl,

    pub fn mode(self: ElicitRequest) ElicitMode {
        return switch (self) {
            .form => .form,
            .url => .url,
        };
    }

    /// Serializes as the full request object the map holds: a method and its params.
    pub fn jsonStringify(self: ElicitRequest, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("method");
        try stream.write(method.elicitation_create);
        try stream.objectField("params");
        try stream.beginObject();
        try stream.objectField("mode");
        switch (self) {
            .form => |form| {
                // Emitted explicitly even though it is the default: a client reading
                // it should not have to know the default to know what it is looking
                // at.
                try stream.write("form");
                try stream.objectField("message");
                try stream.write(form.message);
                try stream.objectField("requestedSchema");
                try stream.write(form.requestedSchema);
            },
            .url => |url| {
                try stream.write("url");
                try stream.objectField("message");
                try stream.write(url.message);
                try stream.objectField("url");
                try stream.write(url.url);
            },
        }
        try stream.endObject();
        try stream.endObject();
    }

    /// Decodes one entry of an `inputRequests` map, for a client fulfilling it.
    pub fn fromValue(value: std.json.Value) error{ Malformed, Unsupported }!ElicitRequest {
        const object = switch (value) {
            .object => |object| object,
            else => return error.Malformed,
        };
        const name = switch (object.get("method") orelse return error.Malformed) {
            .string => |string| string,
            else => return error.Malformed,
        };
        // Sampling and roots requests are well-formed but unimplementable here.
        if (!std.mem.eql(u8, name, method.elicitation_create)) return error.Unsupported;

        const params = switch (object.get("params") orelse return error.Malformed) {
            .object => |params| params,
            else => return error.Malformed,
        };
        const message = switch (params.get("message") orelse return error.Malformed) {
            .string => |string| string,
            else => return error.Malformed,
        };

        // An absent mode means form, for compatibility with servers written against
        // the revision that had only one mode.
        const requested: ElicitMode = if (params.get("mode")) |value_mode|
            enumFromValue(ElicitMode, value_mode) catch return error.Malformed
        else
            .form;

        return switch (requested) {
            .form => .{ .form = .{
                .message = message,
                .requestedSchema = .{
                    .value = params.get("requestedSchema") orelse return error.Malformed,
                },
            } },
            .url => .{ .url = .{
                .message = message,
                .url = switch (params.get("url") orelse return error.Malformed) {
                    .string => |string| string,
                    else => return error.Malformed,
                },
            } },
        };
    }
};

/// The client's answer to one elicitation.
pub const ElicitResult = struct {
    action: ElicitAction,
    /// The submitted values. Present only for an accepted form; omitted for url mode
    /// because the data never passes through the client.
    content: ?std.json.Value = null,

    pub fn jsonStringify(self: ElicitResult, stream: anytype) !void {
        // Sending content alongside a decline or cancel would contradict the action.
        assert(self.content == null or self.action == .accept);

        try stream.beginObject();
        try stream.objectField("action");
        try stream.write(self.action);
        if (self.content) |content| {
            try stream.objectField("content");
            try stream.write(content);
        }
        try stream.endObject();
    }

    pub fn fromValue(value: std.json.Value) error{Malformed}!ElicitResult {
        const object = switch (value) {
            .object => |object| object,
            else => return error.Malformed,
        };
        const action = enumFromValue(
            ElicitAction,
            object.get("action") orelse return error.Malformed,
        ) catch return error.Malformed;

        return .{
            .action = action,
            // Content on a non-accept action is ignored rather than rejected: the
            // action is what decides, and the spec tells servers to ignore what they
            // do not need.
            .content = if (action == .accept) object.get("content") else null,
        };
    }

    /// Reads one submitted string field.
    pub fn field(self: ElicitResult, name: []const u8) ?std.json.Value {
        const content = self.content orelse return null;
        return switch (content) {
            .object => |object| object.get(name),
            else => null,
        };
    }

    /// Reads one submitted string field, if it is a string.
    pub fn string(self: ElicitResult, name: []const u8) ?[]const u8 {
        const value = self.field(name) orelse return null;
        return switch (value) {
            .string => |text| text,
            else => null,
        };
    }
};

/// Which elicitation modes a client declared support for.
pub const ElicitationSupport = struct {
    form: bool = false,
    url: bool = false,

    pub fn none() ElicitationSupport {
        return .{};
    }

    pub fn supports(support: ElicitationSupport, mode: ElicitMode) bool {
        return switch (mode) {
            .form => support.form,
            .url => support.url,
        };
    }

    pub fn any(support: ElicitationSupport) bool {
        return support.form or support.url;
    }

    /// Reads the capability out of what a client declared.
    ///
    /// An `elicitation` object with neither sub-key means form only. That is the
    /// spec's backwards-compatibility rule: clients written against the revision
    /// with a single mode sent a bare `{}`, and treating that as "supports url"
    /// would send them URLs they cannot open.
    pub fn fromCapabilities(capabilities: ClientCapabilities) ElicitationSupport {
        const declared = capabilities.elicitation orelse return .{};
        const object = switch (declared) {
            .object => |object| object,
            else => return .{},
        };
        if (object.count() == 0) return .{ .form = true };
        return .{
            .form = object.get("form") != null,
            .url = object.get("url") != null,
        };
    }

    /// Renders back as a `ClientCapabilities` for the `-32021` error payload, which
    /// has to tell the client what was required.
    pub fn toCapabilities(
        support: ElicitationSupport,
        arena: std.mem.Allocator,
    ) error{OutOfMemory}!ClientCapabilities {
        var modes: std.json.ObjectMap = .empty;
        if (support.form) try modes.put(arena, "form", .{ .object = .empty });
        if (support.url) try modes.put(arena, "url", .{ .object = .empty });
        return .{ .elicitation = .{ .object = modes } };
    }
};

/// The response to `subscriptions/listen`, sent when the *server* tears the
/// subscription down — during shutdown, say. It is not an acknowledgement: the
/// stream is acknowledged with `notifications/subscriptions/acknowledged`, and this
/// result arrives only at the end.
///
/// Its presence is what distinguishes a graceful close from a dropped transport,
/// which carries no response at all, so a client can tell "the server is done with
/// me" from "reconnect". The subscription id is required here, unlike on other
/// results.
pub const SubscriptionsListenResult = struct {
    subscription_id: jsonrpc.Id,
    server_info: ?Implementation = null,

    pub fn jsonStringify(self: SubscriptionsListenResult, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("resultType");
        try stream.write(ResultType.complete);
        try stream.objectField("_meta");
        try stream.write(ResultMeta{
            .server_info = self.server_info,
            .subscription_id = self.subscription_id,
        });
        try stream.endObject();
    }
};

/// A result with no payload beyond the required fields.
pub const EmptyResult = struct {
    meta: ?ResultMeta = null,

    pub fn jsonStringify(self: EmptyResult, stream: anytype) !void {
        try stream.beginObject();
        try writeResultPreamble(stream, .complete, self.meta);
        try stream.endObject();
    }
};

fn writeResultPreamble(stream: anytype, result_type: ResultType, meta: ?ResultMeta) !void {
    try stream.objectField("resultType");
    try stream.write(result_type);
    if (meta) |m| {
        try stream.objectField("_meta");
        try stream.write(m);
    }
}

fn writeCacheHint(stream: anytype, cache: CacheHint) !void {
    try stream.objectField("ttlMs");
    try stream.write(cache.ttl_ms);
    try stream.objectField("cacheScope");
    try stream.write(cache.scope);
}

fn writeCursor(stream: anytype, cursor: ?Cursor) !void {
    if (cursor) |c| {
        try stream.objectField("nextCursor");
        try stream.write(c);
    }
}

// ---------------------------------------------------------------------------
// Notification params
// ---------------------------------------------------------------------------

pub const ProgressParams = struct {
    progressToken: ProgressToken,
    progress: f64,
    total: ?f64 = null,
    message: ?[]const u8 = null,
    _meta: ?ResultMeta = null,
};

pub const LoggingMessageParams = struct {
    level: LoggingLevel,
    data: std.json.Value,
    logger: ?[]const u8 = null,
    _meta: ?ResultMeta = null,
};

pub const CancelledParams = struct {
    requestId: jsonrpc.Id,
    reason: ?[]const u8 = null,
};

pub const ResourceUpdatedParams = struct {
    uri: []const u8,
    _meta: ?ResultMeta = null,
};

pub const SubscriptionsAcknowledgedParams = struct {
    notifications: SubscriptionFilter,
    _meta: ?ResultMeta = null,
};

// ---------------------------------------------------------------------------
// Method names
// ---------------------------------------------------------------------------

/// Every method this revision defines. Keeping them in one place means the
/// dispatch table, the client, and the HTTP `Mcp-Method` header cannot drift.
pub const method = struct {
    pub const discover = "server/discover";
    pub const tools_list = "tools/list";
    pub const tools_call = "tools/call";
    pub const prompts_list = "prompts/list";
    pub const prompts_get = "prompts/get";
    pub const resources_list = "resources/list";
    pub const resources_read = "resources/read";
    pub const resources_templates_list = "resources/templates/list";
    pub const completion_complete = "completion/complete";
    pub const subscriptions_listen = "subscriptions/listen";

    /// The one server-to-client request this SDK implements. It never travels as a
    /// JSON-RPC request of its own: 2026-07-28 delivers it inside an
    /// `InputRequiredResult`, which is what removed the need for a bidirectional
    /// request channel.
    pub const elicitation_create = "elicitation/create";

    /// Whether a method may be answered with an `InputRequiredResult`.
    ///
    /// The spec names exactly three, and forbids the rest. The restriction is
    /// meaningful: a client cannot usefully retry a listing with extra input, so
    /// allowing it there would only produce loops.
    pub fn supportsInputRequired(name: []const u8) bool {
        return std.mem.eql(u8, name, tools_call) or
            std.mem.eql(u8, name, prompts_get) or
            std.mem.eql(u8, name, resources_read);
    }
};

/// Notification method names.
pub const notification = struct {
    pub const cancelled = "notifications/cancelled";
    pub const progress = "notifications/progress";
    pub const message = "notifications/message";
    pub const tools_list_changed = "notifications/tools/list_changed";
    pub const prompts_list_changed = "notifications/prompts/list_changed";
    pub const resources_list_changed = "notifications/resources/list_changed";
    pub const resources_updated = "notifications/resources/updated";
    pub const subscriptions_acknowledged = "notifications/subscriptions/acknowledged";
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Parses `bytes` and returns the object map, for assertions on exact wire shape.
// ---------------------------------------------------------------------------
// Decoding results
// ---------------------------------------------------------------------------
//
// The result types above are written for the server: their `jsonStringify` methods
// inject `resultType` and expand `CacheHint` into `ttlMs`/`cacheScope`, so the Zig
// field names deliberately do not match the wire one-for-one. A client needs the
// reverse direction, which is what `decode` provides.
//
// Descriptor types (`Tool`, `Prompt`, `Resource`, …) do match the wire, so they go
// through `std.json` directly with unknown fields ignored — a client must not break
// when a newer server adds a field.

pub const DecodeError = error{
    /// The payload is not shaped like the result it claims to be.
    Malformed,
    /// The payload carries a `resultType` from a revision later than this SDK's, so
    /// how to read the rest of it is unknown. Distinct from `Malformed` because the
    /// peer is not at fault and the fix is a newer SDK, not a corrected server.
    UnsupportedResultType,
    OutOfMemory,
};

/// Decodes a result payload of type `T` from a parsed JSON value.
pub fn decode(comptime T: type, arena: std.mem.Allocator, value: std.json.Value) DecodeError!T {
    const object = switch (value) {
        .object => |object| object,
        else => return error.Malformed,
    };
    return switch (T) {
        DiscoverResult => decodeDiscover(arena, object),
        ListToolsResult => decodeListTools(arena, object),
        CallToolResult => decodeCallTool(arena, object),
        ListPromptsResult => decodeListPrompts(arena, object),
        GetPromptResult => decodeGetPrompt(arena, object),
        ListResourcesResult => decodeListResources(arena, object),
        ListResourceTemplatesResult => decodeListResourceTemplates(arena, object),
        ReadResourceResult => decodeReadResource(arena, object),
        CompleteResult => decodeCompleteResult(arena, object),
        else => @compileError("no decoder for " ++ @typeName(T)),
    };
}

/// The `resultType` a 2026-07-28 result carries. A client must check this before
/// trusting the rest: an `input_required` payload has none of the fields a complete
/// result does, and interpreting one as the other would silently drop the server's
/// request for more input.
///
/// An absent field reads as `complete`, which the schema requires: a server on an
/// earlier revision does not send one, and the rule that its results be read as
/// complete is written as a client MUST. Defaulting costs nothing, because
/// `input_required` is only ever reached by a server that sent the field explicitly —
/// so the tolerance cannot mask an interim result as a final one.
///
/// A field that is present but names something this SDK does not know is a different
/// matter: only a later revision produces one, and guessing how to read its payload
/// is exactly the mistake this function exists to prevent. That is
/// `UnsupportedResultType`, kept apart from `Malformed` so a caller can tell "your
/// peer is newer than this SDK" from "your peer is broken".
pub fn resultTypeOf(value: std.json.Value) DecodeError!ResultType {
    const object = switch (value) {
        .object => |object| object,
        else => return error.Malformed,
    };
    const tag = object.get("resultType") orelse return .complete;
    return enumFromValue(ResultType, tag) catch error.UnsupportedResultType;
}

fn decodeDiscover(arena: std.mem.Allocator, object: std.json.ObjectMap) DecodeError!DiscoverResult {
    const versions = switch (object.get("supportedVersions") orelse return error.Malformed) {
        .array => |array| array,
        else => return error.Malformed,
    };
    const supported = try arena.alloc([]const u8, versions.items.len);
    for (versions.items, supported) |item, *slot| {
        slot.* = switch (item) {
            .string => |string| string,
            else => return error.Malformed,
        };
    }

    return .{
        .supportedVersions = supported,
        .capabilities = try decodeServerCapabilities(
            object.get("capabilities") orelse return error.Malformed,
        ),
        .instructions = optionalString(object, "instructions"),
        .cache = decodeCacheHint(object),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeListTools(arena: std.mem.Allocator, object: std.json.ObjectMap) DecodeError!ListToolsResult {
    return .{
        .tools = try decodeArray(Tool, arena, object, "tools"),
        .nextCursor = optionalString(object, "nextCursor"),
        .cache = decodeCacheHint(object),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeCallTool(arena: std.mem.Allocator, object: std.json.ObjectMap) DecodeError!CallToolResult {
    const blocks = switch (object.get("content") orelse return error.Malformed) {
        .array => |array| array,
        else => return error.Malformed,
    };
    const content = try arena.alloc(ContentBlock, blocks.items.len);
    for (blocks.items, content) |item, *slot| {
        slot.* = ContentBlock.fromValue(arena, item) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Malformed,
        };
    }

    return .{
        .content = content,
        .structuredContent = object.get("structuredContent"),
        .isError = optionalBool(object, "isError"),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeListPrompts(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!ListPromptsResult {
    return .{
        .prompts = try decodeArray(Prompt, arena, object, "prompts"),
        .nextCursor = optionalString(object, "nextCursor"),
        .cache = decodeCacheHint(object),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeGetPrompt(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!GetPromptResult {
    const items = switch (object.get("messages") orelse return error.Malformed) {
        .array => |array| array,
        else => return error.Malformed,
    };
    const messages = try arena.alloc(PromptMessage, items.items.len);
    for (items.items, messages) |item, *slot| {
        const entry = switch (item) {
            .object => |entry| entry,
            else => return error.Malformed,
        };
        slot.* = .{
            .role = enumFromValue(Role, entry.get("role") orelse return error.Malformed) catch
                return error.Malformed,
            .content = ContentBlock.fromValue(
                arena,
                entry.get("content") orelse return error.Malformed,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Malformed,
            },
        };
    }

    return .{
        .messages = messages,
        .description = optionalString(object, "description"),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeListResources(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!ListResourcesResult {
    return .{
        .resources = try decodeArray(Resource, arena, object, "resources"),
        .nextCursor = optionalString(object, "nextCursor"),
        .cache = decodeCacheHint(object),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeListResourceTemplates(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!ListResourceTemplatesResult {
    return .{
        .resourceTemplates = try decodeArray(
            ResourceTemplate,
            arena,
            object,
            "resourceTemplates",
        ),
        .nextCursor = optionalString(object, "nextCursor"),
        .cache = decodeCacheHint(object),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeReadResource(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!ReadResourceResult {
    const items = switch (object.get("contents") orelse return error.Malformed) {
        .array => |array| array,
        else => return error.Malformed,
    };
    const contents = try arena.alloc(ResourceContents, items.items.len);
    for (items.items, contents) |item, *slot| {
        slot.* = resourceContentsFromValue(arena, item) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Malformed,
        };
    }

    return .{
        .contents = contents,
        .cache = decodeCacheHint(object),
        .meta = try decodeResultMeta(arena, object),
    };
}

fn decodeCompleteResult(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!CompleteResult {
    const completion = switch (object.get("completion") orelse return error.Malformed) {
        .object => |completion| completion,
        else => return error.Malformed,
    };
    const items = switch (completion.get("values") orelse return error.Malformed) {
        .array => |array| array,
        else => return error.Malformed,
    };
    const values = try arena.alloc([]const u8, items.items.len);
    for (items.items, values) |item, *slot| {
        slot.* = switch (item) {
            .string => |string| string,
            else => return error.Malformed,
        };
    }

    return .{
        .completion = .{
            .values = values,
            .total = switch (completion.get("total") orelse std.json.Value{ .null = {} }) {
                .integer => |integer| integer,
                else => null,
            },
            .hasMore = optionalBool(completion, "hasMore"),
        },
        .meta = try decodeResultMeta(arena, object),
    };
}

/// Decodes a homogeneous array of descriptor structs whose field names match the
/// wire format.
fn decodeArray(
    comptime T: type,
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
    key: []const u8,
) DecodeError![]const T {
    const array = switch (object.get(key) orelse return error.Malformed) {
        .array => |array| array,
        else => return error.Malformed,
    };
    const items = try arena.alloc(T, array.items.len);
    for (array.items, items) |value, *slot| {
        slot.* = std.json.parseFromValueLeaky(T, arena, value, .{
            // A client that rejected unknown fields would break the first time a
            // server added one, which the spec explicitly allows.
            .ignore_unknown_fields = true,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Malformed,
        };
    }
    return items;
}

/// Reads the two wire fields back into one `CacheHint`.
///
/// Missing fields fall back to "do not cache". A server is required to send them,
/// but treating an omission as permission to cache forever would be the wrong way
/// to be lenient.
fn decodeCacheHint(object: std.json.ObjectMap) CacheHint {
    var hint: CacheHint = .no_cache;
    if (object.get("ttlMs")) |ttl| switch (ttl) {
        .integer => |integer| hint.ttl_ms = if (integer > 0) @intCast(integer) else 0,
        else => {},
    };
    if (object.get("cacheScope")) |scope| {
        hint.scope = enumFromValue(CacheScope, scope) catch .private;
    }
    return hint;
}

fn decodeResultMeta(
    arena: std.mem.Allocator,
    object: std.json.ObjectMap,
) DecodeError!?ResultMeta {
    const value = object.get("_meta") orelse return null;
    return ResultMeta.fromValue(arena, value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
}

fn decodeServerCapabilities(value: std.json.Value) DecodeError!ServerCapabilities {
    const object = switch (value) {
        .object => |object| object,
        else => return error.Malformed,
    };
    return .{
        .tools = object.get("tools"),
        .prompts = object.get("prompts"),
        .resources = object.get("resources"),
        .completions = object.get("completions"),
        .logging = object.get("logging"),
        .experimental = object.get("experimental"),
        .extensions = object.get("extensions"),
    };
}

fn optionalString(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |string| string,
        else => null,
    };
}

fn optionalBool(object: std.json.ObjectMap, key: []const u8) ?bool {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .bool => |flag| flag,
        else => null,
    };
}

fn parseObject(arena: std.mem.Allocator, bytes: []const u8) !std.json.ObjectMap {
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
    return value.object;
}

test "logging levels order by syslog severity" {
    try testing.expect(LoggingLevel.debug.severity() < LoggingLevel.info.severity());
    try testing.expect(LoggingLevel.emergency.severity() > LoggingLevel.@"error".severity());
    try testing.expect(LoggingLevel.@"error".atLeast(.warning));
    try testing.expect(!LoggingLevel.debug.atLeast(.warning));
    try testing.expect(LoggingLevel.warning.atLeast(.warning));
}

test "logging level serializes with the wire spelling of error" {
    const bytes = try stringifyAlloc(testing.allocator, LoggingLevel.@"error");
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("\"error\"", bytes);
}

test "result type spells input_required as the schema does" {
    const bytes = try stringifyAlloc(testing.allocator, ResultType.input_required);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("\"input_required\"", bytes);
}

test "request meta emits the required prefixed keys" {
    const meta: RequestMeta = .{
        .client_info = .{ .name = "ExampleClient", .version = "1.0.0" },
    };
    const bytes = try stringifyAlloc(testing.allocator, meta);
    defer testing.allocator.free(bytes);

    try testing.expectEqualStrings(
        \\{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
    ++
        \\"io.modelcontextprotocol/clientCapabilities":{},
    ++
        \\"io.modelcontextprotocol/clientInfo":{"name":"ExampleClient","version":"1.0.0"}}
    , bytes);
}

test "request meta omits the log level when the client did not ask for logs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const bytes = try stringifyAlloc(testing.allocator, RequestMeta{});
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    try testing.expect(object.get(meta_key.log_level) == null);
    // Capabilities are required even when empty.
    try testing.expect(object.get(meta_key.client_capabilities) != null);
}

test "request meta carries a log level and progress token when set" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const meta: RequestMeta = .{
        .log_level = .warning,
        .progress_token = .{ .string = "tok-1" },
    };
    const bytes = try stringifyAlloc(testing.allocator, meta);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    try testing.expectEqualStrings("warning", object.get(meta_key.log_level).?.string);
    try testing.expectEqualStrings("tok-1", object.get(meta_key.progress_token).?.string);
}

test "request meta round-trips through fromValue" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const bytes =
        \\{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\ "io.modelcontextprotocol/clientCapabilities":{"elicitation":{}},
        \\ "io.modelcontextprotocol/clientInfo":{"name":"c","version":"2"},
        \\ "io.modelcontextprotocol/logLevel":"debug",
        \\ "progressToken":7,
        \\ "com.example/tenant":"acme"}
    ;
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), bytes, .{});
    var meta = try RequestMeta.fromValue(arena.allocator(), value);
    defer meta.deinit(arena.allocator());

    try testing.expectEqualStrings("2026-07-28", meta.protocol_version);
    try testing.expect(meta.capabilities.elicitation != null);
    try testing.expect(meta.capabilities.sampling == null);
    try testing.expectEqualStrings("c", meta.client_info.?.name);
    try testing.expectEqual(LoggingLevel.debug, meta.log_level.?);
    try testing.expectEqual(@as(i64, 7), meta.progress_token.?.number);
    // An application key this SDK knows nothing about has to survive.
    try testing.expectEqualStrings("acme", meta.extra.?.get("com.example/tenant").?.string);
}

test "request meta preserves unknown keys when re-encoded" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const bytes =
        \\{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\ "io.modelcontextprotocol/clientCapabilities":{},
        \\ "traceparent":"00-abc-def-01"}
    ;
    const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, bytes, .{});
    var meta = try RequestMeta.fromValue(gpa, value);
    defer meta.deinit(gpa);

    const encoded = try stringifyAlloc(testing.allocator, meta);
    defer testing.allocator.free(encoded);

    const object = try parseObject(gpa, encoded);
    // OpenTelemetry trace context is exactly the case the spec calls out.
    try testing.expectEqualStrings("00-abc-def-01", object.get("traceparent").?.string);
    try testing.expectEqualStrings("2026-07-28", object.get(meta_key.protocol_version).?.string);
}

test "request meta rejects payloads missing required protocol fields" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
            \\{"io.modelcontextprotocol/clientCapabilities":{}}
        , .{});
        try testing.expectError(error.MissingProtocolVersion, RequestMeta.fromValue(gpa, value));
    }
    {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
            \\{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}
        , .{});
        try testing.expectError(error.MissingClientCapabilities, RequestMeta.fromValue(gpa, value));
    }
    {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, "[]", .{});
        try testing.expectError(error.InvalidMeta, RequestMeta.fromValue(gpa, value));
    }
}

test "reserved protocol keys in extra are dropped, not duplicated" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var extra: std.json.ObjectMap = .empty;
    defer extra.deinit(gpa);
    // A caller trying to override a protocol-owned key, deliberately or by
    // round-tripping a `_meta` from elsewhere.
    try extra.put(gpa, meta_key.protocol_version, .{ .string = "1999-01-01" });
    try extra.put(gpa, "com.example/keep", .{ .bool = true });

    const meta: RequestMeta = .{ .extra = extra };
    const bytes = try stringifyAlloc(testing.allocator, meta);
    defer testing.allocator.free(bytes);

    // Parses cleanly, which is the point: a duplicated key would make this fail
    // with `error.DuplicateField`.
    const object = try parseObject(gpa, bytes);
    try testing.expectEqualStrings("2026-07-28", object.get(meta_key.protocol_version).?.string);
    try testing.expectEqual(true, object.get("com.example/keep").?.bool);
}

test "result meta carries server info and subscription id" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const meta: ResultMeta = .{
        .server_info = .{ .name = "s", .version = "0.1.0" },
        .subscription_id = .{ .number = 4 },
    };
    const bytes = try stringifyAlloc(testing.allocator, meta);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    try testing.expectEqualStrings("s", object.get(meta_key.server_info).?.object.get("name").?.string);
    try testing.expectEqual(@as(i64, 4), object.get(meta_key.subscription_id).?.integer);
}

test "result meta round-trips" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
        \\{"io.modelcontextprotocol/serverInfo":{"name":"srv","version":"9"},
        \\ "io.modelcontextprotocol/subscriptionId":"sub-1",
        \\ "vendor/extra":true}
    , .{});
    var meta = try ResultMeta.fromValue(gpa, value);
    defer meta.deinit(gpa);

    try testing.expectEqualStrings("srv", meta.server_info.?.name);
    try testing.expectEqualStrings("sub-1", meta.subscription_id.?.string);
    try testing.expectEqual(true, meta.extra.?.get("vendor/extra").?.bool);
}

test "text content emits its type discriminator" {
    const bytes = try stringifyAlloc(testing.allocator, ContentBlock.fromText("hello"));
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"type":"text","text":"hello"}
    , bytes);
}

test "image content requires data and mime type" {
    const block: ContentBlock = .{ .image = .{ .data = "AAAA", .mimeType = "image/png" } };
    const bytes = try stringifyAlloc(testing.allocator, block);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"type":"image","data":"AAAA","mimeType":"image/png"}
    , bytes);
}

test "audio content emits its own discriminator" {
    const block: ContentBlock = .{ .audio = .{ .data = "BBBB", .mimeType = "audio/wav" } };
    const bytes = try stringifyAlloc(testing.allocator, block);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"type":"audio","data":"BBBB","mimeType":"audio/wav"}
    , bytes);
}

test "resource link carries uri and optional size" {
    const block: ContentBlock = .{ .resource_link = .{
        .uri = "file:///a.txt",
        .name = "a.txt",
        .size = 12,
    } };
    const bytes = try stringifyAlloc(testing.allocator, block);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"type":"resource_link","uri":"file:///a.txt","name":"a.txt","size":12}
    , bytes);
}

test "embedded resource nests text contents" {
    const block: ContentBlock = .{ .resource = .{ .resource = .{ .text = .{
        .uri = "file:///a.txt",
        .text = "body",
        .mimeType = "text/plain",
    } } } };
    const bytes = try stringifyAlloc(testing.allocator, block);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"type":"resource","resource":{"uri":"file:///a.txt","text":"body","mimeType":"text/plain"}}
    , bytes);
}

test "embedded resource nests blob contents" {
    const contents: ResourceContents = .{ .blob = .{ .uri = "file:///a.bin", .blob = "Zm9v" } };
    try testing.expectEqualStrings("file:///a.bin", contents.uri());

    const bytes = try stringifyAlloc(testing.allocator, contents);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"uri":"file:///a.bin","blob":"Zm9v"}
    , bytes);
}

test "content blocks decode from the wire" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const cases = [_][]const u8{
        \\{"type":"text","text":"hi"}
        ,
        \\{"type":"image","data":"AA","mimeType":"image/png"}
        ,
        \\{"type":"audio","data":"AA","mimeType":"audio/wav"}
        ,
        \\{"type":"resource_link","uri":"u","name":"n"}
        ,
        \\{"type":"resource","resource":{"uri":"u","text":"t"}}
        ,
    };
    const expected = [_]std.meta.Tag(ContentBlock){
        .text, .image, .audio, .resource_link, .resource,
    };

    for (cases, expected) |bytes, tag| {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, bytes, .{});
        const block = try ContentBlock.fromValue(gpa, value);
        try testing.expectEqual(tag, std.meta.activeTag(block));
    }
}

test "content block decoding rejects malformed input" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const cases = [_]struct { bytes: []const u8, expected: anyerror }{
        .{ .bytes = "[]", .expected = error.InvalidContent },
        .{ .bytes = "{}", .expected = error.InvalidContent },
        .{ .bytes =
        \\{"type":5}
        , .expected = error.InvalidContent },
        .{ .bytes =
        \\{"type":"video","data":"AA"}
        , .expected = error.UnknownContentType },
        // `text` is required on a text block.
        .{ .bytes =
        \\{"type":"text"}
        , .expected = error.InvalidContent },
        // A resource block with neither text nor blob is not decodable.
        .{ .bytes =
        \\{"type":"resource","resource":{"uri":"u"}}
        , .expected = error.InvalidContent },
    };

    for (cases) |case| {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, case.bytes, .{});
        try testing.expectError(case.expected, ContentBlock.fromValue(gpa, value));
    }
}

test "call tool result carries the required result type" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const result: CallToolResult = .{
        .content = &.{ContentBlock.fromText("42")},
        .isError = false,
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"resultType":"complete","content":[{"type":"text","text":"42"}],"isError":false}
    , bytes);
}

test "call tool result reports tool failure separately from protocol failure" {
    const result: CallToolResult = .{
        .content = &.{ContentBlock.fromText("boom")},
        .isError = true,
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const object = try parseObject(arena.allocator(), bytes);
    // Still a successful result: the failure is the tool's, not the protocol's.
    try testing.expectEqualStrings("complete", object.get("resultType").?.string);
    try testing.expectEqual(true, object.get("isError").?.bool);
}

test "list results carry the cache fields the schema requires" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const tool_schema = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        \\{"type":"object","properties":{}}
    ,
        .{},
    );
    const result: ListToolsResult = .{
        .tools = &.{.{ .name = "add", .inputSchema = .{ .value = tool_schema } }},
        .cache = .{ .ttl_ms = 60_000, .scope = .public },
        .nextCursor = "page-2",
    };

    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    try testing.expectEqualStrings("complete", object.get("resultType").?.string);
    try testing.expectEqual(@as(i64, 60_000), object.get("ttlMs").?.integer);
    try testing.expectEqualStrings("public", object.get("cacheScope").?.string);
    try testing.expectEqualStrings("page-2", object.get("nextCursor").?.string);
    try testing.expectEqualStrings("add", object.get("tools").?.array.items[0].object.get("name").?.string);
}

test "list results default to a conservative cache hint" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const result: ListPromptsResult = .{ .prompts = &.{} };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    try testing.expectEqual(@as(i64, 0), object.get("ttlMs").?.integer);
    try testing.expectEqualStrings("private", object.get("cacheScope").?.string);
    // Absent, not null: no further pages.
    try testing.expect(object.get("nextCursor") == null);
}

test "read resource result carries contents and cache fields" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const result: ReadResourceResult = .{
        .contents = &.{.{ .text = .{ .uri = "file:///a", .text = "x" } }},
        .cache = .{ .ttl_ms = 5, .scope = .private },
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    try testing.expectEqual(@as(i64, 5), object.get("ttlMs").?.integer);
    try testing.expectEqualStrings("x", object.get("contents").?.array.items[0].object.get("text").?.string);
}

test "resource templates result uses the schema field name" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const result: ListResourceTemplatesResult = .{
        .resourceTemplates = &.{.{ .uriTemplate = "file:///{path}", .name = "files" }},
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    const template = object.get("resourceTemplates").?.array.items[0].object;
    try testing.expectEqualStrings("file:///{path}", template.get("uriTemplate").?.string);
}

test "discover result advertises versions and capabilities" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const empty = try std.json.parseFromSliceLeaky(std.json.Value, gpa, "{}", .{});
    const result: DiscoverResult = .{
        .supportedVersions = &.{protocol_version},
        .capabilities = .{ .tools = empty },
        .instructions = "Use the add tool.",
        .cache = .{ .ttl_ms = 3_600_000, .scope = .public },
        .meta = .{ .server_info = .{ .name = "srv", .version = "0.1.0" } },
    };

    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(gpa, bytes);
    try testing.expectEqualStrings("complete", object.get("resultType").?.string);
    try testing.expectEqualStrings("2026-07-28", object.get("supportedVersions").?.array.items[0].string);
    try testing.expect(object.get("capabilities").?.object.get("tools") != null);
    // A server that declares no prompts must omit the key, not send null.
    try testing.expect(object.get("capabilities").?.object.get("prompts") == null);
    try testing.expectEqual(@as(i64, 3_600_000), object.get("ttlMs").?.integer);
    try testing.expectEqualStrings(
        "srv",
        object.get("_meta").?.object.get(meta_key.server_info).?.object.get("name").?.string,
    );
}

test "input required result marks itself as such" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const requests = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
        \\{"confirm":{"method":"elicitation/create","params":{}}}
    , .{});
    const result: InputRequiredResult = .{
        .inputRequests = requests,
        .requestState = "opaque-state",
    };

    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(gpa, bytes);
    try testing.expectEqualStrings("input_required", object.get("resultType").?.string);
    try testing.expectEqualStrings("opaque-state", object.get("requestState").?.string);
    try testing.expect(object.get("inputRequests").?.object.get("confirm") != null);
}

test "subscriptions listen result requires a subscription id in meta" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const result: SubscriptionsListenResult = .{
        .subscription_id = .{ .number = 11 },
        .server_info = .{ .name = "srv", .version = "1" },
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);

    const object = try parseObject(arena.allocator(), bytes);
    const meta = object.get("_meta").?.object;
    try testing.expectEqual(@as(i64, 11), meta.get(meta_key.subscription_id).?.integer);
    try testing.expectEqualStrings("srv", meta.get(meta_key.server_info).?.object.get("name").?.string);
}

test "empty result still carries a result type" {
    const bytes = try stringifyAlloc(testing.allocator, EmptyResult{});
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"resultType":"complete"}
    , bytes);
}

test "get prompt result orders description before messages" {
    const result: GetPromptResult = .{
        .description = "A greeting",
        .messages = &.{.{ .role = .user, .content = ContentBlock.fromText("hi") }},
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"resultType":"complete","description":"A greeting","messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}
    , bytes);
}

test "complete result nests the completion object" {
    const result: CompleteResult = .{
        .completion = .{ .values = &.{ "a", "b" }, .total = 2, .hasMore = false },
    };
    const bytes = try stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"resultType":"complete","completion":{"values":["a","b"],"total":2,"hasMore":false}}
    , bytes);
}

test "completion reference encodes both reference kinds" {
    {
        const reference: CompletionReference = .{ .prompt = .{ .name = "greet" } };
        const bytes = try stringifyAlloc(testing.allocator, reference);
        defer testing.allocator.free(bytes);
        try testing.expectEqualStrings(
            \\{"type":"ref/prompt","name":"greet"}
        , bytes);
    }
    {
        const reference: CompletionReference = .{ .resource = .{ .uri = "file:///{p}" } };
        const bytes = try stringifyAlloc(testing.allocator, reference);
        defer testing.allocator.free(bytes);
        try testing.expectEqualStrings(
            \\{"type":"ref/resource","uri":"file:///{p}"}
        , bytes);
    }
}

test "completion reference decodes both kinds and rejects others" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
            \\{"type":"ref/prompt","name":"greet","title":"Greet"}
        , .{});
        const reference = try CompletionReference.fromValue(value);
        try testing.expectEqualStrings("greet", reference.prompt.name);
        try testing.expectEqualStrings("Greet", reference.prompt.title.?);
    }
    {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa,
            \\{"type":"ref/resource","uri":"u"}
        , .{});
        const reference = try CompletionReference.fromValue(value);
        try testing.expectEqualStrings("u", reference.resource.uri);
    }
    for ([_][]const u8{
        "[]",
        "{}",
        \\{"type":"ref/unknown"}
        ,
        \\{"type":"ref/prompt"}
        ,
        \\{"type":"ref/resource"}
        ,
    }) |bytes| {
        const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, bytes, .{});
        try testing.expectError(error.InvalidParams, CompletionReference.fromValue(value));
    }
}

test "subscription filter omits types the client did not opt in to" {
    const filter: SubscriptionFilter = .{ .toolsListChanged = true };
    const bytes = try stringifyAlloc(testing.allocator, filter);
    defer testing.allocator.free(bytes);
    // Absent means "not subscribed"; the server must not send those types.
    try testing.expectEqualStrings(
        \\{"toolsListChanged":true}
    , bytes);
}

test "subscription filter carries watched resource uris" {
    const filter: SubscriptionFilter = .{
        .resourceSubscriptions = &.{ "file:///a", "file:///b" },
    };
    const bytes = try stringifyAlloc(testing.allocator, filter);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"resourceSubscriptions":["file:///a","file:///b"]}
    , bytes);
}

test "progress params carry the token they were asked for" {
    const params: ProgressParams = .{
        .progressToken = .{ .number = 3 },
        .progress = 0.5,
        .total = 1.0,
        .message = "halfway",
    };
    const bytes = try stringifyAlloc(testing.allocator, params);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"progressToken":3,"progress":0.5,"total":1,"message":"halfway"}
    , bytes);
}

test "cancelled params identify the request being cancelled" {
    const params: CancelledParams = .{
        .requestId = .{ .string = "r-1" },
        .reason = "user aborted",
    };
    const bytes = try stringifyAlloc(testing.allocator, params);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"requestId":"r-1","reason":"user aborted"}
    , bytes);
}

test "tool descriptor omits optional fields it does not have" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const schema = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        \\{"type":"object"}
    ,
        .{},
    );
    const tool: Tool = .{ .name = "add", .inputSchema = .{ .value = schema } };
    const bytes = try stringifyAlloc(testing.allocator, tool);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"name":"add","inputSchema":{"type":"object"}}
    , bytes);
}

test "tool annotations serialize with schema field names" {
    const tool_annotations: ToolAnnotations = .{
        .title = "Add",
        .readOnlyHint = true,
        .destructiveHint = false,
    };
    const bytes = try stringifyAlloc(testing.allocator, tool_annotations);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"title":"Add","readOnlyHint":true,"destructiveHint":false}
    , bytes);
}

test "prompt descriptor nests its arguments" {
    const prompt: Prompt = .{
        .name = "greet",
        .arguments = &.{.{ .name = "who", .required = true }},
    };
    const bytes = try stringifyAlloc(testing.allocator, prompt);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"name":"greet","arguments":[{"name":"who","required":true}]}
    , bytes);
}

test "resource descriptor carries uri and name" {
    const resource: Resource = .{
        .uri = "file:///readme.md",
        .name = "readme.md",
        .mimeType = "text/markdown",
    };
    const bytes = try stringifyAlloc(testing.allocator, resource);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"uri":"file:///readme.md","name":"readme.md","mimeType":"text/markdown"}
    , bytes);
}

test "implementation carries icons when present" {
    const implementation: Implementation = .{
        .name = "srv",
        .version = "1",
        .icons = &.{.{ .src = "https://e/i.png", .mimeType = "image/png", .theme = .dark }},
    };
    const bytes = try stringifyAlloc(testing.allocator, implementation);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"name":"srv","version":"1","icons":[{"src":"https://e/i.png","mimeType":"image/png","theme":"dark"}]}
    , bytes);
}

test "annotations encode audience and priority" {
    const annotations: Annotations = .{
        .audience = &.{ .user, .assistant },
        .priority = 1.0,
        .lastModified = "2025-01-12T15:00:58Z",
    };
    const bytes = try stringifyAlloc(testing.allocator, annotations);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"audience":["user","assistant"],"priority":1,"lastModified":"2025-01-12T15:00:58Z"}
    , bytes);
}

test "method names match the schema constants" {
    try testing.expectEqualStrings("server/discover", method.discover);
    try testing.expectEqualStrings("tools/call", method.tools_call);
    try testing.expectEqualStrings("resources/templates/list", method.resources_templates_list);
    try testing.expectEqualStrings("subscriptions/listen", method.subscriptions_listen);
    try testing.expectEqualStrings("notifications/cancelled", notification.cancelled);
    try testing.expectEqualStrings(
        "notifications/subscriptions/acknowledged",
        notification.subscriptions_acknowledged,
    );
}

test "params decode into concrete types" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const bytes =
        \\{"name":"get_weather","arguments":{"city":"Seattle"},
        \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\          "io.modelcontextprotocol/clientCapabilities":{}}}
    ;
    const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, bytes, .{});
    const object = value.object;

    // The dispatch layer reads `name`/`arguments` directly and hands `_meta` to
    // `RequestMeta`, which is the split this test pins down.
    try testing.expectEqualStrings("get_weather", object.get("name").?.string);
    try testing.expectEqualStrings("Seattle", object.get("arguments").?.object.get("city").?.string);

    var meta = try RequestMeta.fromValue(gpa, object.get("_meta").?);
    defer meta.deinit(gpa);
    try testing.expectEqualStrings(protocol_version, meta.protocol_version);
}

test "protocol version agrees with the schema revision" {
    try testing.expectEqualStrings("2026-07-28", protocol_version);
}

test "fuzz the result decoders against arbitrary JSON" {
    // These run on a client, over bytes a server chose. The decoders exist because the
    // result types are written for the serialising side — `cache` is two wire fields,
    // `meta` is `_meta` — so they are hand-written, which is exactly the code where a
    // malformed document is most likely to be read as a valid one.
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [1024]u8 = undefined;
            const length = smith.slice(&buffer);

            var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            const value = std.json.parseFromSliceLeaky(
                std.json.Value,
                arena,
                buffer[0..length],
                .{},
            ) catch return;

            // Every decoder, so a crash is attributable to one of them rather than to
            // whichever happened to be tried first.
            inline for (.{
                DiscoverResult,
                ListToolsResult,
                ListPromptsResult,
                ListResourcesResult,
                ListResourceTemplatesResult,
                ReadResourceResult,
                CallToolResult,
                GetPromptResult,
                CompleteResult,
            }) |Result| {
                if (decode(Result, arena, value)) |decoded| {
                    // A decoded cache hint must be one of the two scopes: an absent or
                    // malformed hint has to read as no-cache, never as permission to cache.
                    if (@hasField(Result, "cache")) {
                        try std.testing.expect(
                            decoded.cache.scope == .private or decoded.cache.scope == .public,
                        );
                    }
                } else |_| {}
            }

            _ = resultTypeOf(value) catch {};
        }
    }.run, .{});
}
