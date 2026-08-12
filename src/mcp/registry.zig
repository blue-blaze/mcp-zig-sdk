//! The registry of what a server offers: tools, prompts, resources and resource
//! templates.
//!
//! Two ways in, one representation out.
//!
//! **Comptime.** `tool("add", add)` takes a typed handler, derives the JSON Schema
//! from its argument struct, and wraps it so the dispatcher can call it through a
//! uniform signature. The schema is a string literal in the binary and the
//! argument decode is generated; nothing about the tool's shape is built at run
//! time.
//!
//! **Run time.** `addToolDefinition` takes an already-erased definition, for tools
//! whose set is not known until the process runs — a server proxying another
//! service, say. The subscription machinery needs this anyway: `tools/list_changed`
//! only means something if the list can change.
//!
//! Entries are kept sorted by name. That satisfies the specification's request for
//! a deterministic `tools/list` order, which exists so clients and model prompt
//! caches can rely on it, and it makes pagination cursors trivial: a cursor is
//! just the name to resume after.

const std = @import("std");
const assert_mod = @import("assert");
const types = @import("types.zig");
const schema_gen = @import("schema_gen.zig");
const context_mod = @import("context.zig");

const assert = assert_mod.assert;
const comptime_assert = assert_mod.comptime_assert;

pub const Context = context_mod.Context;
pub const Error = context_mod.Error;

/// Upper bound on registered entries of each kind.
///
/// A bound rather than unbounded growth: a registry that can grow without limit
/// turns a bug in a proxy server's discovery loop into memory exhaustion. 4096 is
/// far past any plausible tool count while staying a real ceiling.
pub const entries_max: usize = 4096;

// ---------------------------------------------------------------------------
// Erased handler signatures
// ---------------------------------------------------------------------------

/// Invoked for `tools/call`. `arguments` is whatever the caller sent, undecoded.
pub const ToolHandler = *const fn (
    context: *Context,
    arguments: ?std.json.Value,
) Error!types.CallToolResult;

/// Invoked for `prompts/get`.
pub const PromptHandler = *const fn (
    context: *Context,
    arguments: ?std.json.Value,
) Error!types.GetPromptResult;

/// Invoked for `resources/read` on a concrete resource.
pub const ResourceHandler = *const fn (
    context: *Context,
    uri: []const u8,
) Error!types.ReadResourceResult;

/// Invoked for `completion/complete`. Returns the candidate values; the dispatcher
/// wraps them into a `CompleteResult`.
pub const CompletionHandler = *const fn (
    context: *Context,
    argument_name: []const u8,
    partial_value: []const u8,
) Error![]const []const u8;

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

pub const ToolDefinition = struct {
    name: []const u8,
    /// Pre-encoded JSON Schema. Comptime registration fills this from
    /// `schema_gen`; runtime registration may pass either variant.
    input_schema: types.Json,
    handler: ToolHandler,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    output_schema: ?types.Json = null,
    annotations: ?types.ToolAnnotations = null,
    icons: ?[]const types.Icon = null,
    /// Parameters mirrored into `Mcp-Param-*` headers by the HTTP transport.
    header_mappings: []const schema_gen.HeaderMapping = &.{},

    /// OAuth scopes a caller must hold to invoke this. Null means the transport's
    /// baseline requirement applies.
    ///
    /// Declared next to the handler because whoever writes the operation is the only
    /// one who knows what it does. A table kept elsewhere drifts the moment a tool
    /// starts touching something new, and it drifts silently.
    scopes: ?[]const u8 = null,

    /// The wire-facing descriptor for `tools/list`.
    pub fn descriptor(definition: ToolDefinition) types.Tool {
        return .{
            .name = definition.name,
            .inputSchema = definition.input_schema,
            .title = definition.title,
            .description = definition.description,
            .outputSchema = definition.output_schema,
            .annotations = definition.annotations,
            .icons = definition.icons,
        };
    }
};

pub const PromptDefinition = struct {
    name: []const u8,
    handler: PromptHandler,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    arguments: []const types.PromptArgument = &.{},
    icons: ?[]const types.Icon = null,
    /// Supplies `completion/complete` candidates for this prompt's arguments.
    completion: ?CompletionHandler = null,

    /// OAuth scopes a caller must hold to invoke this. Null means the transport's
    /// baseline requirement applies.
    ///
    /// Declared next to the handler because whoever writes the operation is the only
    /// one who knows what it does. A table kept elsewhere drifts the moment a tool
    /// starts touching something new, and it drifts silently.
    scopes: ?[]const u8 = null,

    pub fn descriptor(definition: PromptDefinition) types.Prompt {
        return .{
            .name = definition.name,
            .title = definition.title,
            .description = definition.description,
            .arguments = if (definition.arguments.len == 0) null else definition.arguments,
            .icons = definition.icons,
        };
    }
};

pub const ResourceDefinition = struct {
    uri: []const u8,
    name: []const u8,
    handler: ResourceHandler,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mime_type: ?[]const u8 = null,
    size: ?i64 = null,
    icons: ?[]const types.Icon = null,
    annotations: ?types.Annotations = null,

    /// OAuth scopes a caller must hold to invoke this. Null means the transport's
    /// baseline requirement applies.
    ///
    /// Declared next to the handler because whoever writes the operation is the only
    /// one who knows what it does. A table kept elsewhere drifts the moment a tool
    /// starts touching something new, and it drifts silently.
    scopes: ?[]const u8 = null,

    pub fn descriptor(definition: ResourceDefinition) types.Resource {
        return .{
            .uri = definition.uri,
            .name = definition.name,
            .title = definition.title,
            .description = definition.description,
            .mimeType = definition.mime_type,
            .size = definition.size,
            .icons = definition.icons,
            .annotations = definition.annotations,
        };
    }
};

pub const ResourceTemplateDefinition = struct {
    uri_template: []const u8,
    name: []const u8,
    /// Reads any URI matching the template.
    handler: ResourceHandler,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mime_type: ?[]const u8 = null,
    icons: ?[]const types.Icon = null,
    annotations: ?types.Annotations = null,
    /// Supplies `completion/complete` candidates for template variables.
    completion: ?CompletionHandler = null,

    /// OAuth scopes a caller must hold to invoke this. Null means the transport's
    /// baseline requirement applies.
    ///
    /// Declared next to the handler because whoever writes the operation is the only
    /// one who knows what it does. A table kept elsewhere drifts the moment a tool
    /// starts touching something new, and it drifts silently.
    scopes: ?[]const u8 = null,

    pub fn descriptor(definition: ResourceTemplateDefinition) types.ResourceTemplate {
        return .{
            .uriTemplate = definition.uri_template,
            .name = definition.name,
            .title = definition.title,
            .description = definition.description,
            .mimeType = definition.mime_type,
            .icons = definition.icons,
            .annotations = definition.annotations,
        };
    }
};

// ---------------------------------------------------------------------------
// Comptime registration
// ---------------------------------------------------------------------------

/// Builds a tool definition from a typed handler.
///
/// `handler` must be `fn (*Context, Args) !types.CallToolResult`, where `Args` is
/// a struct describing the parameters, or `void` for a tool that takes none. The
/// schema is derived from `Args` and the argument decode is generated, so the
/// advertised contract and the code that relies on it cannot disagree.
///
/// ```zig
/// const AddArgs = struct {
///     a: i64,
///     b: i64,
///     pub const schema_docs = .{ .a = "First addend", .b = "Second addend" };
/// };
///
/// fn add(ctx: *mcp.Context, args: AddArgs) !mcp.types.CallToolResult {
///     return ctx.textResult(try ctx.print("{d}", .{args.a + args.b}));
/// }
///
/// const definition = registry.tool("add", add, .{ .description = "Adds two numbers" });
/// ```
pub fn tool(
    comptime name: []const u8,
    comptime handler: anytype,
    comptime options: ToolOptions,
) ToolDefinition {
    comptime_assert(name.len > 0);
    const Args = ArgumentsOf(@TypeOf(handler), types.CallToolResult, "tool");

    return .{
        .name = name,
        .input_schema = .{ .raw = schema_gen.ofArguments(Args) },
        .handler = erasedTool(handler, Args),
        .title = options.title,
        .description = options.description,
        .output_schema = if (options.Output) |Output|
            .{ .raw = schema_gen.of(Output) }
        else
            null,
        .annotations = options.annotations,
        .icons = options.icons,
        .header_mappings = schema_gen.headerMappings(Args),
        .scopes = options.scopes,
    };
}

pub const ToolOptions = struct {
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    /// When set, its schema is advertised as `outputSchema`.
    Output: ?type = null,
    annotations: ?types.ToolAnnotations = null,
    icons: ?[]const types.Icon = null,
    /// OAuth scopes required to invoke this. See `ToolDefinition.scopes`.
    scopes: ?[]const u8 = null,
};

/// Builds a prompt definition from a typed handler.
pub fn prompt(
    comptime name: []const u8,
    comptime handler: anytype,
    comptime options: PromptOptions,
) PromptDefinition {
    comptime_assert(name.len > 0);
    const Args = ArgumentsOf(@TypeOf(handler), types.GetPromptResult, "prompt");

    return .{
        .name = name,
        .handler = erasedPrompt(handler, Args),
        .title = options.title,
        .description = options.description,
        // Prompt arguments are advertised as a flat list, not a JSON Schema, so
        // they are derived from the struct fields directly.
        .arguments = promptArguments(Args),
        .icons = options.icons,
        .completion = options.completion,
        .scopes = options.scopes,
    };
}

pub const PromptOptions = struct {
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    icons: ?[]const types.Icon = null,
    completion: ?CompletionHandler = null,
    /// OAuth scopes required to invoke this. See `ToolDefinition.scopes`.
    scopes: ?[]const u8 = null,
};

/// Derives `PromptArgument` descriptors from an argument struct.
fn promptArguments(comptime Args: type) []const types.PromptArgument {
    const derived = struct {
        const list = build: {
            if (Args == void) break :build &.{};
            // Prompt arguments skip `ofArguments` but not `decodeArguments`, so the
            // check that keeps `required` honest has to be repeated here.
            schema_gen.requireDecodable(Args);
            var arguments: []const types.PromptArgument = &.{};
            for (@typeInfo(Args).@"struct".fields) |field| {
                if (field.is_comptime) continue;
                const required = @typeInfo(field.type) != .optional and
                    field.default_value_ptr == null;
                arguments = arguments ++ [_]types.PromptArgument{.{
                    .name = field.name,
                    .description = schema_gen.descriptionFor(Args, field.name),
                    .required = required,
                }};
            }
            break :build arguments;
        };
    };
    return derived.list;
}

/// Extracts the argument type from a handler's signature, with diagnostics aimed
/// at the mistake rather than at the reflection code.
fn ArgumentsOf(
    comptime Handler: type,
    comptime Result: type,
    comptime kind: []const u8,
) type {
    const info = switch (@typeInfo(Handler)) {
        .@"fn" => |f| f,
        .pointer => |p| switch (@typeInfo(p.child)) {
            .@"fn" => |f| f,
            else => @compileError(kind ++ " handler must be a function"),
        },
        else => @compileError(kind ++ " handler must be a function, found " ++ @typeName(Handler)),
    };

    if (info.params.len != 2) {
        @compileError(kind ++ " handler must take (*Context, Args), found " ++
            std.fmt.comptimePrint("{d}", .{info.params.len}) ++ " parameter(s)");
    }
    if (info.params[0].type != *Context) {
        @compileError(kind ++ " handler's first parameter must be *Context");
    }

    const Return = info.return_type orelse
        @compileError(kind ++ " handler must have a concrete return type");
    const Payload = switch (@typeInfo(Return)) {
        .error_union => |u| u.payload,
        else => Return,
    };
    if (Payload != Result) {
        @compileError(kind ++ " handler must return " ++ @typeName(Result) ++
            ", found " ++ @typeName(Payload));
    }

    return info.params[1].type orelse
        @compileError(kind ++ " handler's argument type must be concrete");
}

/// Wraps a typed tool handler in the erased signature the dispatcher calls.
fn erasedTool(comptime handler: anytype, comptime Args: type) ToolHandler {
    const Wrapper = struct {
        fn call(context: *Context, arguments: ?std.json.Value) Error!types.CallToolResult {
            const args = try decodeArguments(Args, context, arguments);
            return handler(context, args) catch |err| translate(err);
        }
    };
    return Wrapper.call;
}

fn erasedPrompt(comptime handler: anytype, comptime Args: type) PromptHandler {
    const Wrapper = struct {
        fn call(context: *Context, arguments: ?std.json.Value) Error!types.GetPromptResult {
            const args = try decodeArguments(Args, context, arguments);
            return handler(context, args) catch |err| translate(err);
        }
    };
    return Wrapper.call;
}

/// Decodes call arguments into `Args`, allocating in the request arena.
fn decodeArguments(
    comptime Args: type,
    context: *Context,
    arguments: ?std.json.Value,
) Error!Args {
    if (Args == void) return {};

    // An absent `arguments` is equivalent to `{}`: a tool whose parameters are all
    // optional may legitimately be called with nothing.
    const value = arguments orelse std.json.Value{ .object = .empty };

    return std.json.parseFromValueLeaky(Args, context.arena, value, .{
        // Unknown properties are rejected by the advertised schema
        // (`additionalProperties: false`), so rejecting them here keeps the
        // decode and the contract consistent.
        .ignore_unknown_fields = false,
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidParams,
    };
}

/// Maps a handler's own error set onto the protocol's.
///
/// A handler that fails in a way it did not classify gets `Internal`, because the
/// alternative — guessing that an unfamiliar error means bad input — would blame
/// the caller for a server bug.
/// Maps a handler's error onto the protocol's.
///
/// Members of `Error` pass through unchanged; anything else becomes `Internal`,
/// because an error the SDK does not know about is a server fault and must not be
/// reported as the caller's mistake.
///
/// The pass-through list is generated from `Error` rather than written out. Written by
/// hand it was a whitelist with a catch-all, which meant every member added to `Error`
/// silently collapsed into `Internal` — exactly what happened when input-required and
/// missing-capability were introduced.
fn translate(err: anyerror) Error {
    inline for (@typeInfo(Error).error_set.?) |member| {
        if (err == @field(anyerror, member.name)) return @field(Error, member.name);
    }
    return error.Internal;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// What a server offers. Not thread-safe on its own: the server owns the lock,
/// because a mutation has to be visible atomically alongside the `list_changed`
/// notification it triggers.
pub const Registry = struct {
    gpa: std.mem.Allocator,
    tools: std.ArrayListUnmanaged(ToolDefinition) = .empty,
    prompts: std.ArrayListUnmanaged(PromptDefinition) = .empty,
    resources: std.ArrayListUnmanaged(ResourceDefinition) = .empty,
    resource_templates: std.ArrayListUnmanaged(ResourceTemplateDefinition) = .empty,

    /// Bumped on every mutation, so a caller can tell whether a cached list is
    /// still current without comparing contents.
    revision: u64 = 0,

    pub const AddError = error{
        /// A definition with this name (or URI) is already registered.
        Duplicate,
        /// Would exceed `entries_max`.
        TooManyEntries,
        /// A `Json.raw` schema that is not valid JSON.
        InvalidSchema,
        OutOfMemory,
    };

    pub fn init(gpa: std.mem.Allocator) Registry {
        return .{ .gpa = gpa };
    }

    /// Creates a registry seeded from comptime definitions.
    ///
    /// The tuple is comptime-known, so capacity is exact and no growth ever
    /// happens for a server whose offerings are fixed.
    pub fn initComptime(gpa: std.mem.Allocator, comptime definitions: anytype) AddError!Registry {
        var registry: Registry = .init(gpa);
        errdefer registry.deinit();

        inline for (definitions) |definition| {
            switch (@TypeOf(definition)) {
                ToolDefinition => try registry.addTool(definition),
                PromptDefinition => try registry.addPrompt(definition),
                ResourceDefinition => try registry.addResource(definition),
                ResourceTemplateDefinition => try registry.addResourceTemplate(definition),
                else => @compileError(
                    "unsupported registry entry " ++ @typeName(@TypeOf(definition)),
                ),
            }
        }
        return registry;
    }

    pub fn deinit(registry: *Registry) void {
        registry.tools.deinit(registry.gpa);
        registry.prompts.deinit(registry.gpa);
        registry.resources.deinit(registry.gpa);
        registry.resource_templates.deinit(registry.gpa);
        registry.* = undefined;
    }

    // ---- Tools ----------------------------------------------------------

    pub fn addTool(registry: *Registry, definition: ToolDefinition) AddError!void {
        assert(definition.name.len > 0);
        if (registry.tools.items.len >= entries_max) return error.TooManyEntries;
        if (registry.findTool(definition.name) != null) return error.Duplicate;

        // A raw schema is emitted verbatim, so a malformed one would corrupt every
        // `tools/list` response. Catch it when the tool is registered, not when a
        // client tries to parse the reply.
        definition.input_schema.validate(registry.gpa) catch |err| switch (err) {
            error.InvalidJson => return error.InvalidSchema,
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (definition.output_schema) |schema| {
            schema.validate(registry.gpa) catch |err| switch (err) {
                error.InvalidJson => return error.InvalidSchema,
                error.OutOfMemory => return error.OutOfMemory,
            };
        }

        try insertSorted(ToolDefinition, &registry.tools, registry.gpa, definition, keyOfTool);
        registry.revision += 1;
    }

    pub fn removeTool(registry: *Registry, name: []const u8) bool {
        const index = registry.indexOfTool(name) orelse return false;
        _ = registry.tools.orderedRemove(index);
        registry.revision += 1;
        return true;
    }

    pub fn findTool(registry: *const Registry, name: []const u8) ?*const ToolDefinition {
        const index = registry.indexOfTool(name) orelse return null;
        return &registry.tools.items[index];
    }

    fn indexOfTool(registry: *const Registry, name: []const u8) ?usize {
        return binarySearch(ToolDefinition, registry.tools.items, name, keyOfTool);
    }

    // ---- Prompts --------------------------------------------------------

    pub fn addPrompt(registry: *Registry, definition: PromptDefinition) AddError!void {
        assert(definition.name.len > 0);
        if (registry.prompts.items.len >= entries_max) return error.TooManyEntries;
        if (registry.findPrompt(definition.name) != null) return error.Duplicate;
        try insertSorted(PromptDefinition, &registry.prompts, registry.gpa, definition, keyOfPrompt);
        registry.revision += 1;
    }

    pub fn removePrompt(registry: *Registry, name: []const u8) bool {
        const index = binarySearch(
            PromptDefinition,
            registry.prompts.items,
            name,
            keyOfPrompt,
        ) orelse return false;
        _ = registry.prompts.orderedRemove(index);
        registry.revision += 1;
        return true;
    }

    pub fn findPrompt(registry: *const Registry, name: []const u8) ?*const PromptDefinition {
        const index = binarySearch(
            PromptDefinition,
            registry.prompts.items,
            name,
            keyOfPrompt,
        ) orelse return null;
        return &registry.prompts.items[index];
    }

    // ---- Resources ------------------------------------------------------

    pub fn addResource(registry: *Registry, definition: ResourceDefinition) AddError!void {
        assert(definition.uri.len > 0);
        assert(definition.name.len > 0);
        if (registry.resources.items.len >= entries_max) return error.TooManyEntries;
        if (registry.findResource(definition.uri) != null) return error.Duplicate;
        try insertSorted(
            ResourceDefinition,
            &registry.resources,
            registry.gpa,
            definition,
            keyOfResource,
        );
        registry.revision += 1;
    }

    pub fn removeResource(registry: *Registry, uri: []const u8) bool {
        const index = binarySearch(
            ResourceDefinition,
            registry.resources.items,
            uri,
            keyOfResource,
        ) orelse return false;
        _ = registry.resources.orderedRemove(index);
        registry.revision += 1;
        return true;
    }

    pub fn findResource(registry: *const Registry, uri: []const u8) ?*const ResourceDefinition {
        const index = binarySearch(
            ResourceDefinition,
            registry.resources.items,
            uri,
            keyOfResource,
        ) orelse return null;
        return &registry.resources.items[index];
    }

    // ---- Resource templates ---------------------------------------------

    pub fn addResourceTemplate(
        registry: *Registry,
        definition: ResourceTemplateDefinition,
    ) AddError!void {
        assert(definition.uri_template.len > 0);
        if (registry.resource_templates.items.len >= entries_max) return error.TooManyEntries;
        for (registry.resource_templates.items) |existing| {
            if (std.mem.eql(u8, existing.uri_template, definition.uri_template)) {
                return error.Duplicate;
            }
        }
        try insertSorted(
            ResourceTemplateDefinition,
            &registry.resource_templates,
            registry.gpa,
            definition,
            keyOfResourceTemplate,
        );
        registry.revision += 1;
    }

    /// The first template whose pattern matches `uri`.
    ///
    /// Templates are RFC 6570 level-1 here: `{var}` matches a single path segment
    /// or the remainder, which covers the shapes MCP servers actually publish.
    pub fn matchResourceTemplate(
        registry: *const Registry,
        uri: []const u8,
    ) ?*const ResourceTemplateDefinition {
        for (registry.resource_templates.items, 0..) |*template, index| {
            _ = index;
            if (matchesTemplate(template.uri_template, uri)) return template;
        }
        return null;
    }

    // ---- Capabilities ---------------------------------------------------

    /// What to advertise from `server/discover`, derived from what is registered.
    ///
    /// Declaring a capability a server cannot serve is worse than declaring none:
    /// a client would call and get an error. So the answer comes from the registry
    /// rather than from configuration.
    ///
    /// Takes an allocator because a capability value is a JSON object; pass the
    /// request arena, and the result lives exactly as long as the response does.
    /// What the server is willing to do beyond answering requests.
    ///
    /// These are not derived from the registry because the registry cannot know
    /// them: whether list changes are announced and whether resource subscriptions
    /// are honoured depends on the transport and on the application, not on what
    /// happens to be registered.
    pub const CapabilityOptions = struct {
        /// Whether the server emits `notifications/*/list_changed`.
        list_changed: bool = false,
        /// Whether the server honours `resourceSubscriptions`.
        resource_subscribe: bool = false,
    };

    pub fn capabilities(
        registry: *const Registry,
        arena: std.mem.Allocator,
        options: CapabilityOptions,
    ) error{OutOfMemory}!types.ServerCapabilities {
        const empty: std.json.Value = .{ .object = .empty };
        var result: types.ServerCapabilities = .{};

        if (registry.tools.items.len > 0) {
            result.tools = if (options.list_changed) try listChangedObject(arena) else empty;
        }
        if (registry.prompts.items.len > 0) {
            result.prompts = if (options.list_changed) try listChangedObject(arena) else empty;
        }
        if (registry.resources.items.len > 0 or registry.resource_templates.items.len > 0) {
            result.resources = try resourcesObject(arena, options);
        }
        if (registry.hasCompletions()) result.completions = empty;
        return result;
    }

    fn resourcesObject(
        arena: std.mem.Allocator,
        options: CapabilityOptions,
    ) error{OutOfMemory}!std.json.Value {
        var object: std.json.ObjectMap = .empty;
        if (options.list_changed) try object.put(arena, "listChanged", .{ .bool = true });
        if (options.resource_subscribe) try object.put(arena, "subscribe", .{ .bool = true });
        return .{ .object = object };
    }

    fn hasCompletions(registry: *const Registry) bool {
        for (registry.prompts.items) |definition| {
            if (definition.completion != null) return true;
        }
        for (registry.resource_templates.items) |definition| {
            if (definition.completion != null) return true;
        }
        return false;
    }
};

/// `{"listChanged":true}`, allocated in `arena`.
fn listChangedObject(arena: std.mem.Allocator) error{OutOfMemory}!std.json.Value {
    var map: std.json.ObjectMap = .empty;
    try map.put(arena, "listChanged", .{ .bool = true });
    return .{ .object = map };
}

fn keyOfTool(definition: ToolDefinition) []const u8 {
    return definition.name;
}

fn keyOfPrompt(definition: PromptDefinition) []const u8 {
    return definition.name;
}

fn keyOfResource(definition: ResourceDefinition) []const u8 {
    return definition.uri;
}

fn keyOfResourceTemplate(definition: ResourceTemplateDefinition) []const u8 {
    return definition.uri_template;
}

/// Inserts while keeping the list sorted by key.
fn insertSorted(
    comptime T: type,
    list: *std.ArrayListUnmanaged(T),
    gpa: std.mem.Allocator,
    definition: T,
    comptime keyOf: fn (T) []const u8,
) error{OutOfMemory}!void {
    const key = keyOf(definition);
    var index: usize = 0;
    while (index < list.items.len) : (index += 1) {
        if (std.mem.order(u8, key, keyOf(list.items[index])) == .lt) break;
    }
    try list.insert(gpa, index, definition);
}

fn binarySearch(
    comptime T: type,
    items: []const T,
    key: []const u8,
    comptime keyOf: fn (T) []const u8,
) ?usize {
    var low: usize = 0;
    var high: usize = items.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, keyOf(items[middle]), key)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return middle,
        }
    }
    return null;
}

/// RFC 6570 level-1 matching: literal text with `{var}` placeholders.
///
/// A placeholder matches one or more characters, and the final placeholder may
/// match a remainder containing slashes — `file:///{path}` should match
/// `file:///a/b.txt`, which is how servers publish tree-shaped resources.
fn matchesTemplate(template: []const u8, uri: []const u8) bool {
    var template_index: usize = 0;
    var uri_index: usize = 0;

    while (template_index < template.len) {
        if (template[template_index] == '{') {
            const close = std.mem.indexOfScalarPos(u8, template, template_index, '}') orelse
                return false;
            template_index = close + 1;

            // Text between this placeholder and the next one (or the end) has to
            // appear in the URI; that is what bounds the placeholder's match.
            const literal_end = std.mem.indexOfScalarPos(u8, template, template_index, '{') orelse
                template.len;
            const literal = template[template_index..literal_end];

            if (literal.len == 0) {
                // Trailing placeholder: absorbs the rest, provided there is a rest.
                return uri_index < uri.len;
            }
            const found = std.mem.indexOfPos(u8, uri, uri_index, literal) orelse return false;
            // A placeholder must match at least one character.
            if (found == uri_index) return false;
            uri_index = found + literal.len;
            template_index = literal_end;
            continue;
        }

        if (uri_index >= uri.len) return false;
        if (template[template_index] != uri[uri_index]) return false;
        template_index += 1;
        uri_index += 1;
    }

    return uri_index == uri.len;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const AddArgs = struct {
    a: i64,
    b: i64,

    pub const schema_docs = .{ .a = "First addend", .b = "Second addend" };
};

fn addTool(context: *Context, args: AddArgs) Error!types.CallToolResult {
    return context.textResult(try context.print("{d}", .{args.a + args.b}));
}

fn noArgsTool(context: *Context, _: void) Error!types.CallToolResult {
    return context.textResult("no arguments needed");
}

fn greetPrompt(context: *Context, args: struct { who: []const u8 }) Error!types.GetPromptResult {
    const messages = try context.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{
        .role = .user,
        .content = types.ContentBlock.fromText(try context.print("Hello, {s}", .{args.who})),
    };
    return .{ .messages = messages };
}

fn readReadme(context: *Context, uri: []const u8) Error!types.ReadResourceResult {
    const contents = try context.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "# Readme" } };
    return .{ .contents = contents };
}

/// A context backed by a throwaway arena, for exercising handlers directly.
const TestContext = struct {
    arena: std.heap.ArenaAllocator,
    context: Context,

    fn init() TestContext {
        return .{ .arena = undefined, .context = undefined };
    }

    fn setup(self: *TestContext) void {
        self.arena = .init(testing.allocator);
        self.context = .init(self.arena.allocator(), .{});
    }

    fn deinit(self: *TestContext) void {
        self.arena.deinit();
    }
};

test "a comptime tool derives its schema from the handler's argument type" {
    const definition = tool("add", addTool, .{ .description = "Adds two numbers" });

    try testing.expectEqualStrings("add", definition.name);
    try testing.expectEqualStrings("Adds two numbers", definition.description.?);
    try testing.expectEqualStrings(
        \\{"type":"object","properties":{"a":{"type":"integer","minimum":-9223372036854775808,
    ++
        \\"maximum":9223372036854775807,"description":"First addend"},
    ++
        \\"b":{"type":"integer","minimum":-9223372036854775808,
    ++
        \\"maximum":9223372036854775807,"description":"Second addend"}},
    ++
        \\"required":["a","b"],"additionalProperties":false}
    , definition.input_schema.raw);
}

test "a comptime tool's handler decodes arguments and runs" {
    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = tool("add", addTool, .{});
    const arguments = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.arena.allocator(),
        \\{"a":2,"b":40}
    ,
        .{},
    );

    const result = try definition.handler(&fixture.context, arguments);
    try testing.expectEqualStrings("42", result.content[0].text.text);
}

test "a tool handler rejects arguments that do not match its schema" {
    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = tool("add", addTool, .{});

    for ([_][]const u8{
        // Missing a required property.
        \\{"a":1}
        ,
        // Wrong type.
        \\{"a":"one","b":2}
        ,
        // An unknown property, which the advertised schema forbids.
        \\{"a":1,"b":2,"c":3}
        ,
    }) |bytes| {
        const arguments = try std.json.parseFromSliceLeaky(
            std.json.Value,
            fixture.arena.allocator(),
            bytes,
            .{},
        );
        try testing.expectError(
            error.InvalidParams,
            definition.handler(&fixture.context, arguments),
        );
    }
}

test "a tool taking void arguments accepts an absent params object" {
    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = tool("ping", noArgsTool, .{});
    try testing.expectEqualStrings(
        \\{"type":"object","properties":{}}
    , definition.input_schema.raw);

    const result = try definition.handler(&fixture.context, null);
    try testing.expectEqualStrings("no arguments needed", result.content[0].text.text);
}

test "a tool with all-optional arguments may be called with nothing" {
    const Args = struct { limit: u32 = 10 };
    const Handler = struct {
        fn call(context: *Context, args: Args) Error!types.CallToolResult {
            return context.textResult(try context.print("limit={d}", .{args.limit}));
        }
    };

    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = tool("search", Handler.call, .{});
    const result = try definition.handler(&fixture.context, null);
    try testing.expectEqualStrings("limit=10", result.content[0].text.text);
}

test "a tool advertises an output schema when one is declared" {
    const Output = struct { sum: i64 };
    const definition = tool("add", addTool, .{ .Output = Output });
    try testing.expectEqualStrings(
        \\{"type":"object","properties":{"sum":{"type":"integer","minimum":-9223372036854775808,
    ++
        \\"maximum":9223372036854775807}},
    ++
        \\"required":["sum"],"additionalProperties":false}
    , definition.output_schema.?.raw);
}

test "a tool reports its header mappings for the HTTP transport" {
    const Args = struct {
        region: []const u8,
        query: []const u8,

        pub const mcp_headers = .{ .region = "Region" };
    };
    const Handler = struct {
        fn call(context: *Context, _: Args) Error!types.CallToolResult {
            return context.textResult("ok");
        }
    };

    const definition = tool("execute_sql", Handler.call, .{});
    try testing.expectEqual(@as(usize, 1), definition.header_mappings.len);
    try testing.expectEqualStrings("region", definition.header_mappings[0].field);
    try testing.expectEqualStrings("Region", definition.header_mappings[0].header);
    try testing.expect(std.mem.indexOf(
        u8,
        definition.input_schema.raw,
        "\"x-mcp-header\":\"Region\"",
    ) != null);
}

test "handler errors that are not classified become internal errors" {
    const Handler = struct {
        fn call(_: *Context, _: void) error{ Boom, OutOfMemory }!types.CallToolResult {
            return error.Boom;
        }
    };

    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = tool("boom", Handler.call, .{});
    // Blaming the caller for an unfamiliar server-side failure would be wrong.
    try testing.expectError(error.Internal, definition.handler(&fixture.context, null));
}

test "handler errors that are classified are preserved" {
    const Handler = struct {
        fn call(_: *Context, _: void) Error!types.CallToolResult {
            return error.NotFound;
        }
    };

    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = tool("missing", Handler.call, .{});
    try testing.expectError(error.NotFound, definition.handler(&fixture.context, null));
}

test "a comptime prompt derives its argument descriptors" {
    const definition = prompt("greet", greetPrompt, .{ .description = "Greets someone" });

    try testing.expectEqualStrings("greet", definition.name);
    try testing.expectEqual(@as(usize, 1), definition.arguments.len);
    try testing.expectEqualStrings("who", definition.arguments[0].name);
    try testing.expectEqual(true, definition.arguments[0].required.?);
}

test "optional prompt arguments are not marked required" {
    const Args = struct { who: []const u8, formal: ?bool = null };
    const Handler = struct {
        fn call(context: *Context, _: Args) Error!types.GetPromptResult {
            return .{ .messages = try context.arena.alloc(types.PromptMessage, 0) };
        }
    };

    const definition = prompt("greet", Handler.call, .{});
    try testing.expectEqual(@as(usize, 2), definition.arguments.len);
    try testing.expectEqual(true, definition.arguments[0].required.?);
    try testing.expectEqual(false, definition.arguments[1].required.?);
}

test "a prompt handler decodes arguments and runs" {
    var fixture: TestContext = .init();
    fixture.setup();
    defer fixture.deinit();

    const definition = prompt("greet", greetPrompt, .{});
    const arguments = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.arena.allocator(),
        \\{"who":"world"}
    ,
        .{},
    );

    const result = try definition.handler(&fixture.context, arguments);
    try testing.expectEqualStrings("Hello, world", result.messages[0].content.text.text);
}

test "a registry seeded at comptime holds what it was given" {
    var registry = try Registry.initComptime(testing.allocator, .{
        tool("add", addTool, .{}),
        tool("ping", noArgsTool, .{}),
        prompt("greet", greetPrompt, .{}),
        ResourceDefinition{
            .uri = "file:///readme.md",
            .name = "readme.md",
            .handler = readReadme,
        },
        ResourceTemplateDefinition{
            .uri_template = "file:///project/{path}",
            .name = "project files",
            .handler = readReadme,
        },
    });
    defer registry.deinit();

    try testing.expectEqual(@as(usize, 2), registry.tools.items.len);
    try testing.expectEqual(@as(usize, 1), registry.prompts.items.len);
    try testing.expectEqual(@as(usize, 1), registry.resources.items.len);
    try testing.expectEqual(@as(usize, 1), registry.resource_templates.items.len);

    try testing.expect(registry.findTool("add") != null);
    try testing.expect(registry.findTool("nope") == null);
    try testing.expect(registry.findPrompt("greet") != null);
    try testing.expect(registry.findResource("file:///readme.md") != null);
}

test "entries are stored sorted by name for a deterministic list order" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    // Registered out of order on purpose.
    try registry.addTool(tool("zebra", noArgsTool, .{}));
    try registry.addTool(tool("apple", noArgsTool, .{}));
    try registry.addTool(tool("mango", noArgsTool, .{}));

    try testing.expectEqualStrings("apple", registry.tools.items[0].name);
    try testing.expectEqualStrings("mango", registry.tools.items[1].name);
    try testing.expectEqualStrings("zebra", registry.tools.items[2].name);
}

test "lookup works for every entry regardless of insertion order" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    const names = [_][]const u8{ "delta", "alpha", "echo", "bravo", "charlie" };
    for (names) |name| {
        try registry.addTool(.{
            .name = name,
            .input_schema = .{ .raw = "{}" },
            .handler = tool("x", noArgsTool, .{}).handler,
        });
    }

    // Binary search over the sorted storage has to find all of them.
    for (names) |name| {
        const found = registry.findTool(name) orelse return error.TestExpectedFound;
        try testing.expectEqualStrings(name, found.name);
    }
    try testing.expect(registry.findTool("foxtrot") == null);
    try testing.expect(registry.findTool("") == null);
}

test "registering a duplicate name is rejected" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    try registry.addTool(tool("add", addTool, .{}));
    try testing.expectError(error.Duplicate, registry.addTool(tool("add", addTool, .{})));
    try testing.expectEqual(@as(usize, 1), registry.tools.items.len);

    try registry.addPrompt(prompt("greet", greetPrompt, .{}));
    try testing.expectError(
        error.Duplicate,
        registry.addPrompt(prompt("greet", greetPrompt, .{})),
    );

    const resource: ResourceDefinition = .{
        .uri = "file:///a",
        .name = "a",
        .handler = readReadme,
    };
    try registry.addResource(resource);
    try testing.expectError(error.Duplicate, registry.addResource(resource));

    const template: ResourceTemplateDefinition = .{
        .uri_template = "file:///{p}",
        .name = "files",
        .handler = readReadme,
    };
    try registry.addResourceTemplate(template);
    try testing.expectError(error.Duplicate, registry.addResourceTemplate(template));
}

test "a malformed raw schema is rejected at registration" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    // A raw schema is emitted verbatim, so this would otherwise corrupt every
    // tools/list response.
    try testing.expectError(error.InvalidSchema, registry.addTool(.{
        .name = "broken",
        .input_schema = .{ .raw = "{not json" },
        .handler = tool("x", noArgsTool, .{}).handler,
    }));
    try testing.expectEqual(@as(usize, 0), registry.tools.items.len);

    try testing.expectError(error.InvalidSchema, registry.addTool(.{
        .name = "broken-output",
        .input_schema = .{ .raw = "{}" },
        .output_schema = .{ .raw = "]" },
        .handler = tool("x", noArgsTool, .{}).handler,
    }));
}

test "removal drops an entry and bumps the revision" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    try registry.addTool(tool("add", addTool, .{}));
    try registry.addTool(tool("ping", noArgsTool, .{}));
    const revision_before = registry.revision;

    try testing.expect(registry.removeTool("add"));
    try testing.expectEqual(@as(usize, 1), registry.tools.items.len);
    try testing.expect(registry.findTool("add") == null);
    // A changed list has to be observable, which is what drives list_changed.
    try testing.expect(registry.revision > revision_before);

    // Removing something absent is not an error, just false.
    try testing.expect(!registry.removeTool("add"));
}

test "removal works for prompts and resources too" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    try registry.addPrompt(prompt("greet", greetPrompt, .{}));
    try registry.addResource(.{ .uri = "file:///a", .name = "a", .handler = readReadme });

    try testing.expect(registry.removePrompt("greet"));
    try testing.expect(!registry.removePrompt("greet"));
    try testing.expect(registry.removeResource("file:///a"));
    try testing.expect(!registry.removeResource("file:///a"));
}

test "the revision tracks every mutation" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    try testing.expectEqual(@as(u64, 0), registry.revision);
    try registry.addTool(tool("a", noArgsTool, .{}));
    try testing.expectEqual(@as(u64, 1), registry.revision);
    try registry.addPrompt(prompt("p", greetPrompt, .{}));
    try testing.expectEqual(@as(u64, 2), registry.revision);
    _ = registry.removeTool("a");
    try testing.expectEqual(@as(u64, 3), registry.revision);
    // A failed mutation must not bump it.
    _ = registry.removeTool("a");
    try testing.expectEqual(@as(u64, 3), registry.revision);
}

test "capabilities are derived from what is actually registered" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    // Nothing registered: advertise nothing, so a client never calls into a void.
    {
        const capabilities = try registry.capabilities(gpa, .{});
        try testing.expect(capabilities.tools == null);
        try testing.expect(capabilities.prompts == null);
        try testing.expect(capabilities.resources == null);
        try testing.expect(capabilities.completions == null);
    }

    try registry.addTool(tool("add", addTool, .{}));
    {
        const capabilities = try registry.capabilities(gpa, .{});
        try testing.expect(capabilities.tools != null);
        try testing.expect(capabilities.prompts == null);
    }

    try registry.addPrompt(prompt("greet", greetPrompt, .{}));
    try registry.addResource(.{ .uri = "file:///a", .name = "a", .handler = readReadme });
    {
        const capabilities = try registry.capabilities(gpa, .{});
        try testing.expect(capabilities.prompts != null);
        try testing.expect(capabilities.resources != null);
    }
}

test "a resource template alone advertises the resources capability" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    try registry.addResourceTemplate(.{
        .uri_template = "file:///{p}",
        .name = "files",
        .handler = readReadme,
    });
    const capabilities = try registry.capabilities(arena.allocator(), .{});
    try testing.expect(capabilities.resources != null);
}

test "a completion handler advertises the completions capability" {
    const Completions = struct {
        fn complete(_: *Context, _: []const u8, _: []const u8) Error![]const []const u8 {
            return &.{"world"};
        }
    };

    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    try registry.addPrompt(prompt("greet", greetPrompt, .{}));
    try testing.expect((try registry.capabilities(gpa, .{})).completions == null);

    _ = registry.removePrompt("greet");
    try registry.addPrompt(prompt("greet", greetPrompt, .{ .completion = Completions.complete }));
    try testing.expect((try registry.capabilities(gpa, .{})).completions != null);
}

test "capabilities can advertise listChanged support" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    try registry.addTool(tool("add", addTool, .{}));
    try registry.addPrompt(prompt("greet", greetPrompt, .{}));

    const capabilities = try registry.capabilities(arena.allocator(), .{ .list_changed = true });
    try testing.expectEqual(true, capabilities.tools.?.object.get("listChanged").?.bool);
    try testing.expectEqual(true, capabilities.prompts.?.object.get("listChanged").?.bool);
    // Each capability gets its own object rather than sharing one, so a caller
    // mutating one cannot disturb another.
    try testing.expect(capabilities.tools.?.object.entries.items(.value).ptr !=
        capabilities.prompts.?.object.entries.items(.value).ptr);
}

test "resource templates match level-1 URI templates" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    try registry.addResourceTemplate(.{
        .uri_template = "file:///project/{path}",
        .name = "project files",
        .handler = readReadme,
    });

    try testing.expect(registry.matchResourceTemplate("file:///project/readme.md") != null);
    // A trailing placeholder absorbs slashes, which is how tree-shaped resources
    // are published.
    try testing.expect(registry.matchResourceTemplate("file:///project/src/main.zig") != null);
    // The placeholder must match something.
    try testing.expect(registry.matchResourceTemplate("file:///project/") == null);
    try testing.expect(registry.matchResourceTemplate("file:///other/readme.md") == null);
    try testing.expect(registry.matchResourceTemplate("") == null);
}

test "template matching handles placeholders followed by literals" {
    try testing.expect(matchesTemplate("db://{table}/rows", "db://users/rows"));
    try testing.expect(!matchesTemplate("db://{table}/rows", "db:///rows"));
    try testing.expect(!matchesTemplate("db://{table}/rows", "db://users/columns"));
    try testing.expect(matchesTemplate("a{x}b{y}c", "aXbYc"));
    try testing.expect(!matchesTemplate("a{x}b{y}c", "abYc"));
    // A template with no placeholders is an exact match.
    try testing.expect(matchesTemplate("file:///a", "file:///a"));
    try testing.expect(!matchesTemplate("file:///a", "file:///ab"));
    // An unterminated placeholder cannot match anything.
    try testing.expect(!matchesTemplate("file:///{oops", "file:///x"));
}

test "the registry refuses to grow past its bound" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    // Fill to the bound with distinct names, then confirm the next add is refused
    // rather than allocating without limit.
    var name_buffer: [entries_max][8]u8 = undefined;
    for (0..entries_max) |index| {
        const name = std.fmt.bufPrint(&name_buffer[index], "t{d:0>6}", .{index}) catch unreachable;
        try registry.addTool(.{
            .name = name,
            .input_schema = .{ .raw = "{}" },
            .handler = tool("x", noArgsTool, .{}).handler,
        });
    }
    try testing.expectEqual(entries_max, registry.tools.items.len);
    try testing.expectError(error.TooManyEntries, registry.addTool(.{
        .name = "one-too-many",
        .input_schema = .{ .raw = "{}" },
        .handler = tool("x", noArgsTool, .{}).handler,
    }));
}

test "a tool descriptor serializes with the generated schema inline" {
    const definition = tool("add", addTool, .{ .description = "Adds two numbers" });
    const bytes = try types.stringifyAlloc(testing.allocator, definition.descriptor());
    defer testing.allocator.free(bytes);

    try testing.expectEqualStrings(
        \\{"name":"add","inputSchema":{"type":"object","properties":
    ++
        \\{"a":{"type":"integer","minimum":-9223372036854775808,
    ++
        \\"maximum":9223372036854775807,"description":"First addend"},
    ++
        \\"b":{"type":"integer","minimum":-9223372036854775808,
    ++
        \\"maximum":9223372036854775807,"description":"Second addend"}},"required":["a","b"],
    ++
        \\"additionalProperties":false},"description":"Adds two numbers"}
    , bytes);
}

test "descriptors satisfy the schema for their wire types" {
    var registry = try Registry.initComptime(testing.allocator, .{
        tool("add", addTool, .{}),
        prompt("greet", greetPrompt, .{}),
        ResourceDefinition{
            .uri = "file:///readme.md",
            .name = "readme.md",
            .mime_type = "text/markdown",
            .handler = readReadme,
        },
        ResourceTemplateDefinition{
            .uri_template = "file:///project/{path}",
            .name = "project files",
            .handler = readReadme,
        },
    });
    defer registry.deinit();

    // Round-tripping through JSON proves the descriptors are well-formed; the
    // `zig build spec` step checks them against the published schema.
    for (registry.tools.items) |definition| {
        const bytes = try types.stringifyAlloc(testing.allocator, definition.descriptor());
        defer testing.allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, bytes, .{});
        defer parsed.deinit();
        try testing.expect(parsed.value.object.get("inputSchema") != null);
    }
    for (registry.prompts.items) |definition| {
        const bytes = try types.stringifyAlloc(testing.allocator, definition.descriptor());
        defer testing.allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, bytes, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings("greet", parsed.value.object.get("name").?.string);
    }
    for (registry.resources.items) |definition| {
        const bytes = try types.stringifyAlloc(testing.allocator, definition.descriptor());
        defer testing.allocator.free(bytes);
        try testing.expect(std.mem.indexOf(u8, bytes, "text/markdown") != null);
    }
    for (registry.resource_templates.items) |definition| {
        const bytes = try types.stringifyAlloc(testing.allocator, definition.descriptor());
        defer testing.allocator.free(bytes);
        try testing.expect(std.mem.indexOf(u8, bytes, "uriTemplate") != null);
    }
}

test "a runtime-registered tool works alongside comptime ones" {
    var registry = try Registry.initComptime(testing.allocator, .{
        tool("add", addTool, .{}),
    });
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The dynamic case: a schema built at run time rather than derived.
    const schema = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        \\{"type":"object","properties":{"q":{"type":"string"}}}
    ,
        .{},
    );
    try registry.addTool(.{
        .name = "search",
        .input_schema = .{ .value = schema },
        .handler = tool("x", noArgsTool, .{}).handler,
    });

    try testing.expectEqual(@as(usize, 2), registry.tools.items.len);
    try testing.expect(registry.findTool("search") != null);
    try testing.expect(registry.findTool("add") != null);

    const bytes = try types.stringifyAlloc(
        testing.allocator,
        registry.findTool("search").?.descriptor(),
    );
    defer testing.allocator.free(bytes);
    try testing.expect(std.mem.indexOf(u8, bytes, "\"q\"") != null);
}
