//! The request dispatcher: transport-agnostic by construction.
//!
//! `Server` turns one inbound JSON-RPC message into the bytes of one outbound
//! response, and nothing else. It does no I/O, opens no sockets, and reads no
//! streams. That is what lets the same dispatch logic serve stdio and Streamable
//! HTTP without either transport knowing what a tool is.
//!
//! ## Statelessness
//!
//! 2026-07-28 removed the `initialize` handshake, so there is no per-connection
//! state to keep. Each request carries its own protocol version, client identity
//! and capabilities in `_meta`, and is accepted or rejected on its own terms. A
//! `Server` is therefore just a registry plus configuration; two requests that
//! arrive on different connections are handled identically.
//!
//! ## Memory
//!
//! Every entry point takes an arena. Everything produced while handling a request
//! — the parsed message, decoded params, handler allocations, the response bytes —
//! lives in it, and the transport resets it once the response is written. Handlers
//! never free anything individually.

const std = @import("std");
const assert_mod = @import("assert");
const jsonrpc = @import("jsonrpc.zig");
const types = @import("types.zig");
const registry_mod = @import("registry.zig");
const context_mod = @import("context.zig");

const assert = assert_mod.assert;

pub const Registry = registry_mod.Registry;
pub const Context = context_mod.Context;
pub const Error = context_mod.Error;
pub const NotificationSink = context_mod.NotificationSink;
pub const Cancellation = context_mod.Cancellation;

/// Everything the transport provides for the duration of one request.
///
/// This is one parameter instead of a growing list, and it is the whole contract
/// between a transport and the dispatcher: give it memory, optionally somewhere to
/// put notifications, and optionally a way to learn the peer gave up.
pub const Scope = struct {
    /// Backs everything produced while handling the request, and is reset by the
    /// transport once the reply has been written.
    arena: std.mem.Allocator,
    /// Where request-scoped notifications go.
    ///
    /// Absent means the transport cannot carry them, and handlers that report
    /// progress or log become silent rather than failing. That is the right
    /// default: a notification is advisory, and a transport should not have to
    /// implement streaming to serve a tool that happens to call `reportProgress`.
    sink: ?NotificationSink = null,
    /// Observed by the handler to see whether the peer cancelled.
    ///
    /// A transport can only supply this if it can read from the peer while a
    /// handler runs. The sequential stdio loop cannot, and passes null.
    cancellation: ?*const Cancellation = null,
};

/// Default page size for the list endpoints. Large enough that most servers return
/// everything in one response, small enough that a server with thousands of tools
/// does not build a multi-megabyte reply.
pub const page_size_default: usize = 100;

/// What handling a message produced.
pub const Outcome = union(enum) {
    /// Bytes to send back, allocated in the request arena.
    reply: Reply,
    /// Nothing to send. Notifications get no response, and neither does a
    /// cancelled request.
    no_reply,
    /// A `subscriptions/listen` request the dispatcher accepted. There is no reply
    /// to send *yet*: the transport now owns a long-lived stream, and the response
    /// only appears if the server later closes it gracefully.
    ///
    /// This is where the request/response shape of the dispatcher stops being
    /// enough, so the dispatcher hands the decision back rather than pretending.
    listen: Listen,
};

/// An accepted subscription, as the dispatcher understands it.
pub const Listen = struct {
    /// The subscription id, which the spec defines as the listen request's id.
    id: jsonrpc.Id,
    /// What the client asked for.
    requested: types.SubscriptionFilter,
    /// The subset the server agreed to honour, which is what the acknowledgement
    /// reports and what bounds every later delivery.
    granted: types.SubscriptionFilter,
};

pub const Reply = struct {
    /// The encoded JSON-RPC response.
    bytes: []const u8,
    /// Set when the reply is an error response. Transports that need to map a
    /// protocol error onto their own failure signalling — HTTP status codes, in
    /// particular — read it from here rather than re-parsing the body.
    error_code: ?i32 = null,

    /// The HTTP status this reply should be sent with.
    ///
    /// The transport specification is explicit about three of these: header and
    /// version failures are `400`, and an unimplemented method is `404` so that a
    /// client can tell it apart from a `404` produced by a server that does not
    /// host an MCP endpoint at all.
    pub fn httpStatus(reply: Reply) u16 {
        const code = reply.error_code orelse return 200;
        return switch (code) {
            jsonrpc.error_code.method_not_found => 404,
            jsonrpc.error_code.header_mismatch,
            jsonrpc.error_code.unsupported_protocol_version,
            jsonrpc.error_code.missing_required_client_capability,
            jsonrpc.error_code.parse_error,
            jsonrpc.error_code.invalid_request,
            => 400,
            // Everything else is a well-formed request that failed, which is a
            // successful HTTP exchange carrying a JSON-RPC error.
            else => 200,
        };
    }
};

pub const Options = struct {
    /// Natural-language guidance returned by `server/discover`.
    instructions: ?[]const u8 = null,
    /// Whether the server emits `notifications/*/list_changed`. Advertised in
    /// capabilities, so it must reflect what the transport can actually deliver.
    list_changed: bool = false,
    /// Whether the server honours `resourceSubscriptions` on
    /// `subscriptions/listen`. Like `list_changed`, this is a claim about the
    /// application and the transport, so it cannot be inferred.
    resource_subscribe: bool = false,
    /// Maximum entries per list response.
    page_size: usize = page_size_default,
    /// Cache hints for the results that require them.
    cache: CachePolicy = .{},
    /// Whether to identify the server in each result's `_meta`. The spec says
    /// SHOULD, with an explicit escape hatch for deployments that would rather not.
    include_server_info: bool = true,
    /// Application state handed to every handler as `Context.user`.
    ///
    /// Here rather than per handler because a server's handlers share one application:
    /// per-handler pointers would let two of them disagree about what they are serving.
    /// Read it with `context.userAs(*State)`.
    user: ?*anyopaque = null,
};

/// Per-endpoint cache hints. `CacheableResult` makes `ttlMs` and `cacheScope`
/// mandatory on these results, so there is no "unset" — only a choice, and the
/// default is the conservative one.
pub const CachePolicy = struct {
    discover: types.CacheHint = .no_cache,
    tools: types.CacheHint = .no_cache,
    prompts: types.CacheHint = .no_cache,
    resources: types.CacheHint = .no_cache,
    resource_templates: types.CacheHint = .no_cache,
    resource_read: types.CacheHint = .no_cache,
};

pub const Server = struct {
    registry: *Registry,
    info: types.Implementation,
    options: Options,

    pub fn init(registry: *Registry, info: types.Implementation, options: Options) Server {
        assert(info.name.len > 0);
        assert(info.version.len > 0);
        return .{ .registry = registry, .info = info, .options = options };
    }

    /// Handles one raw message: parse, dispatch, encode.
    pub fn handleBytes(
        server: *const Server,
        scope: Scope,
        bytes: []const u8,
    ) error{OutOfMemory}!Outcome {
        const message = jsonrpc.parseLeaky(scope.arena, bytes) catch |err| {
            return server.parseFailureReply(scope.arena, err);
        };
        return server.handleMessage(scope, message);
    }

    /// Handles an already-parsed message. Transports that must inspect the body
    /// before dispatching — Streamable HTTP validates headers against it — parse
    /// once and come in here.
    pub fn handleMessage(
        server: *const Server,
        scope: Scope,
        message: jsonrpc.Message,
    ) error{OutOfMemory}!Outcome {
        return switch (message) {
            .request => |request| server.handleRequest(scope, request),
            // Notifications never get a response, not even an error one.
            .notification => .no_reply,
            // A server receiving a response has nothing to correlate it with: this
            // revision has no server-initiated requests. Server-to-client
            // interaction happens through MRTR, where the client drives.
            .result_response, .error_response => .no_reply,
        };
    }

    /// Dispatches a request to its method handler.
    pub fn handleRequest(
        server: *const Server,
        scope: Scope,
        request: jsonrpc.Request,
    ) error{OutOfMemory}!Outcome {
        const arena = scope.arena;
        const method = request.method;

        // `server/discover` is deliberately handled before version validation.
        // It is the version-negotiation entry point — and on stdio the
        // backward-compatibility probe — so a client asking "what do you speak?"
        // has to get an answer even when it asked in a version we do not speak.
        if (std.mem.eql(u8, method, types.method.discover)) {
            return server.handleDiscover(arena, request);
        }

        const meta = server.decodeMeta(arena, request.params) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedVersion => return server.unsupportedVersionReply(
                arena,
                request.id,
                server.requestedVersion(request.params),
            ),
            error.InvalidMeta => return server.errorReply(
                arena,
                request.id,
                jsonrpc.error_code.invalid_params,
                "params._meta is missing or malformed",
            ),
        };

        var context: Context = .init(arena, meta);
        context.sink = scope.sink;
        context.cancellation = scope.cancellation;
        context.user = server.options.user;
        // A retry carries the previous round's answers alongside the original params.
        if (objectOf(request.params)) |params| {
            context.input_responses = objectOf(params.get("inputResponses"));
            context.incoming_state = stringField(params, "requestState");
        }

        if (std.mem.eql(u8, method, types.method.tools_list)) {
            return server.handleToolsList(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.tools_call)) {
            return server.handleToolsCall(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.prompts_list)) {
            return server.handlePromptsList(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.prompts_get)) {
            return server.handlePromptsGet(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.resources_list)) {
            return server.handleResourcesList(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.resources_read)) {
            return server.handleResourcesRead(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.resources_templates_list)) {
            return server.handleResourceTemplatesList(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.completion_complete)) {
            return server.handleComplete(arena, request, &context);
        }
        if (std.mem.eql(u8, method, types.method.subscriptions_listen)) {
            return server.handleSubscriptionsListen(arena, request);
        }

        return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.method_not_found,
            null,
        );
    }

    // ---- Method handlers -------------------------------------------------

    /// Accepts or rejects a `subscriptions/listen` request.
    ///
    /// The dispatcher's job ends at deciding *what* the subscription covers. It does
    /// not open anything: the stream belongs to the transport, which is the only
    /// layer that knows whether it can hold one open.
    fn handleSubscriptionsListen(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
    ) error{OutOfMemory}!Outcome {
        const params = objectOf(request.params) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params is required",
        );
        // `notifications` is required by the schema. Defaulting it to "nothing" would
        // open a stream that can never deliver anything, which is worse than saying so.
        const requested_value = params.get("notifications") orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.notifications is required",
        );
        const requested = types.SubscriptionFilter.fromValue(arena, requested_value) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return server.errorReply(
                arena,
                request.id,
                jsonrpc.error_code.invalid_params,
                "params.notifications is malformed",
            );
        };

        return .{ .listen = .{
            .id = request.id,
            .requested = requested,
            .granted = try server.grant(arena, requested),
        } };
    }

    /// Narrows a requested filter to what this server can actually honour.
    ///
    /// The spec requires the acknowledgement to report only supported types, and
    /// requires the server never to send an unrequested one. Computing the
    /// intersection once, here, is what makes both true everywhere downstream: a
    /// delivery decision is a lookup in `granted`, never a re-derivation.
    pub fn grant(
        server: *const Server,
        arena: std.mem.Allocator,
        requested: types.SubscriptionFilter,
    ) error{OutOfMemory}!types.SubscriptionFilter {
        var granted: types.SubscriptionFilter = .{};
        const registry = server.registry;

        // A list-changed notification the server never emits is not honoured, and
        // neither is one for a kind it has nothing of.
        if (server.options.list_changed) {
            if (requested.wantsToolsListChanged() and registry.tools.items.len > 0) {
                granted.toolsListChanged = true;
            }
            if (requested.wantsPromptsListChanged() and registry.prompts.items.len > 0) {
                granted.promptsListChanged = true;
            }
            const has_resources = registry.resources.items.len > 0 or
                registry.resource_templates.items.len > 0;
            if (requested.wantsResourcesListChanged() and has_resources) {
                granted.resourcesListChanged = true;
            }
        }

        const wanted_uris = requested.uris();
        if (server.options.resource_subscribe and wanted_uris.len > 0) {
            // Keep only URIs this server could actually serve. A subscription to a
            // resource that does not exist would sit silent forever; reporting the
            // omission lets the client notice its mistake.
            var kept: std.ArrayListUnmanaged([]const u8) = .empty;
            for (wanted_uris) |uri| {
                if (!server.subscribable(uri)) continue;
                try kept.append(arena, uri);
            }
            if (kept.items.len > 0) granted.resourceSubscriptions = kept.items;
        }

        return granted;
    }

    /// The scopes the operation this request names requires, or null when it declares
    /// none and the transport's baseline is all that applies.
    ///
    /// Answered by the dispatcher rather than by the transport because the lookup must
    /// be the same one dispatch will perform — including the fall back from a
    /// registered resource to a template. A transport that guessed differently would
    /// authorize one operation and run another.
    ///
    /// Methods that address no single entity (`tools/list`, `server/discover`) return
    /// null: there is no per-entity requirement to read, and inventing one here would
    /// hide it from the place that configures the baseline.
    pub fn requiredScopes(server: *const Server, rpc: jsonrpc.Request) ?[]const u8 {
        const subject = subjectOf(rpc) orelse return null;

        if (std.mem.eql(u8, rpc.method, types.method.tools_call)) {
            const definition = server.registry.findTool(subject) orelse return null;
            return definition.scopes;
        }
        if (std.mem.eql(u8, rpc.method, types.method.prompts_get)) {
            const definition = server.registry.findPrompt(subject) orelse return null;
            return definition.scopes;
        }
        if (std.mem.eql(u8, rpc.method, types.method.resources_read)) {
            // Exact registration first, then templates: the same precedence
            // `handleReadResource` uses.
            if (server.registry.findResource(subject)) |definition| return definition.scopes;
            if (server.registry.matchResourceTemplate(subject)) |template| return template.scopes;
            return null;
        }
        return null;
    }

    /// Whether a URI names something this server knows how to produce.
    fn subscribable(server: *const Server, uri: []const u8) bool {
        if (server.registry.findResource(uri) != null) return true;
        if (server.registry.matchResourceTemplate(uri) != null) return true;
        return false;
    }

    fn handleDiscover(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
    ) error{OutOfMemory}!Outcome {
        const capabilities = try server.registry.capabilities(arena, .{
            .list_changed = server.options.list_changed,
            .resource_subscribe = server.options.resource_subscribe,
        });
        const supported = try arena.alloc([]const u8, 1);
        supported[0] = types.protocol_version;

        return server.resultReply(arena, request.id, types.DiscoverResult{
            .supportedVersions = supported,
            .capabilities = capabilities,
            .instructions = server.options.instructions,
            .cache = server.options.cache.discover,
            .meta = server.resultMeta(),
        });
    }

    fn handleToolsList(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        _ = context;
        const cursor = cursorOf(request.params);
        const items = server.registry.tools.items;
        const page = paginate(registry_mod.ToolDefinition, items, cursor, server.options.page_size);

        const descriptors = try arena.alloc(types.Tool, page.items.len);
        for (page.items, descriptors) |definition, *descriptor| {
            descriptor.* = definition.descriptor();
        }

        return server.resultReply(arena, request.id, types.ListToolsResult{
            .tools = descriptors,
            .nextCursor = page.next_cursor,
            .cache = server.options.cache.tools,
            .meta = server.resultMeta(),
        });
    }

    fn handleToolsCall(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        const params = objectOf(request.params) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params is required",
        );
        const name = stringField(params, "name") orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.name is required",
        );

        const definition = server.registry.findTool(name) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            try std.fmt.allocPrint(arena, "unknown tool: {s}", .{name}),
        );

        var result = definition.handler(context, params.get("arguments")) catch |err| {
            return server.inputReply(arena, request.id, types.method.tools_call, context, err);
        };
        result.meta = server.mergeResultMeta(result.meta);
        return server.resultReply(arena, request.id, result);
    }

    fn handlePromptsList(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        _ = context;
        const cursor = cursorOf(request.params);
        const items = server.registry.prompts.items;
        const page = paginate(registry_mod.PromptDefinition, items, cursor, server.options.page_size);

        const descriptors = try arena.alloc(types.Prompt, page.items.len);
        for (page.items, descriptors) |definition, *descriptor| {
            descriptor.* = definition.descriptor();
        }

        return server.resultReply(arena, request.id, types.ListPromptsResult{
            .prompts = descriptors,
            .nextCursor = page.next_cursor,
            .cache = server.options.cache.prompts,
            .meta = server.resultMeta(),
        });
    }

    fn handlePromptsGet(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        const params = objectOf(request.params) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params is required",
        );
        const name = stringField(params, "name") orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.name is required",
        );

        const definition = server.registry.findPrompt(name) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            try std.fmt.allocPrint(arena, "unknown prompt: {s}", .{name}),
        );

        var result = definition.handler(context, params.get("arguments")) catch |err| {
            return server.inputReply(arena, request.id, types.method.prompts_get, context, err);
        };
        result.meta = server.mergeResultMeta(result.meta);
        return server.resultReply(arena, request.id, result);
    }

    fn handleResourcesList(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        _ = context;
        const cursor = cursorOf(request.params);
        const items = server.registry.resources.items;
        const page = paginate(
            registry_mod.ResourceDefinition,
            items,
            cursor,
            server.options.page_size,
        );

        const descriptors = try arena.alloc(types.Resource, page.items.len);
        for (page.items, descriptors) |definition, *descriptor| {
            descriptor.* = definition.descriptor();
        }

        return server.resultReply(arena, request.id, types.ListResourcesResult{
            .resources = descriptors,
            .nextCursor = page.next_cursor,
            .cache = server.options.cache.resources,
            .meta = server.resultMeta(),
        });
    }

    fn handleResourceTemplatesList(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        _ = context;
        const cursor = cursorOf(request.params);
        const items = server.registry.resource_templates.items;
        const page = paginate(
            registry_mod.ResourceTemplateDefinition,
            items,
            cursor,
            server.options.page_size,
        );

        const descriptors = try arena.alloc(types.ResourceTemplate, page.items.len);
        for (page.items, descriptors) |definition, *descriptor| {
            descriptor.* = definition.descriptor();
        }

        return server.resultReply(arena, request.id, types.ListResourceTemplatesResult{
            .resourceTemplates = descriptors,
            .nextCursor = page.next_cursor,
            .cache = server.options.cache.resource_templates,
            .meta = server.resultMeta(),
        });
    }

    fn handleResourcesRead(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        const params = objectOf(request.params) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params is required",
        );
        const uri = stringField(params, "uri") orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.uri is required",
        );

        // Concrete resources first, then templates: an exact registration should
        // win over a pattern that happens to cover the same URI.
        const handler = blk: {
            if (server.registry.findResource(uri)) |definition| break :blk definition.handler;
            if (server.registry.matchResourceTemplate(uri)) |template| break :blk template.handler;
            // 2026-07-28 moved resource-not-found from -32002 to -32602 to align
            // with JSON-RPC's own use of the code.
            return server.errorReply(
                arena,
                request.id,
                jsonrpc.error_code.invalid_params,
                try std.fmt.allocPrint(arena, "unknown resource: {s}", .{uri}),
            );
        };

        var result = handler(context, uri) catch |err| {
            return server.inputReply(
                arena,
                request.id,
                types.method.resources_read,
                context,
                err,
            );
        };
        result.cache = server.options.cache.resource_read;
        result.meta = server.mergeResultMeta(result.meta);
        return server.resultReply(arena, request.id, result);
    }

    fn handleComplete(
        server: *const Server,
        arena: std.mem.Allocator,
        request: jsonrpc.Request,
        context: *Context,
    ) error{OutOfMemory}!Outcome {
        const params = objectOf(request.params) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params is required",
        );

        const reference = types.CompletionReference.fromValue(
            params.get("ref") orelse std.json.Value{ .null = {} },
        ) catch return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.ref is missing or malformed",
        );

        const argument = objectOf(params.get("argument")) orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.argument is required",
        );
        const argument_name = stringField(argument, "name") orelse return server.errorReply(
            arena,
            request.id,
            jsonrpc.error_code.invalid_params,
            "params.argument.name is required",
        );
        const partial = stringField(argument, "value") orelse "";

        const handler = switch (reference) {
            .prompt => |prompt_reference| blk: {
                const definition = server.registry.findPrompt(prompt_reference.name) orelse
                    return server.errorReply(
                        arena,
                        request.id,
                        jsonrpc.error_code.invalid_params,
                        try std.fmt.allocPrint(
                            arena,
                            "unknown prompt: {s}",
                            .{prompt_reference.name},
                        ),
                    );
                break :blk definition.completion;
            },
            .resource => |resource_reference| blk: {
                const template = server.registry.matchResourceTemplate(resource_reference.uri) orelse
                    return server.errorReply(
                        arena,
                        request.id,
                        jsonrpc.error_code.invalid_params,
                        try std.fmt.allocPrint(
                            arena,
                            "unknown resource template: {s}",
                            .{resource_reference.uri},
                        ),
                    );
                break :blk template.completion;
            },
        };

        // Nothing registered to complete against is not an error: an empty list is
        // a valid answer, and it keeps a client's UI from breaking.
        const values = if (handler) |complete|
            complete(context, argument_name, partial) catch |err| {
                return server.inputReply(
                    arena,
                    request.id,
                    types.method.completion_complete,
                    context,
                    err,
                );
            }
        else
            &[_][]const u8{};

        return server.resultReply(arena, request.id, types.CompleteResult{
            .completion = .{
                .values = values,
                .total = @intCast(values.len),
                .hasMore = false,
            },
            .meta = server.resultMeta(),
        });
    }

    // ---- `_meta` -----------------------------------------------------------

    const MetaError = error{ InvalidMeta, UnsupportedVersion, OutOfMemory };

    /// Decodes and validates the request's `_meta`.
    fn decodeMeta(
        server: *const Server,
        arena: std.mem.Allocator,
        params: ?std.json.Value,
    ) MetaError!types.RequestMeta {
        _ = server;
        const object = objectOf(params) orelse return error.InvalidMeta;
        const meta_value = object.get("_meta") orelse return error.InvalidMeta;

        const meta = types.RequestMeta.fromValue(arena, meta_value) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // A request that does not say which version it speaks cannot be served
            // safely: field semantics differ between revisions.
            else => return error.InvalidMeta,
        };

        if (!std.mem.eql(u8, meta.protocol_version, types.protocol_version)) {
            return error.UnsupportedVersion;
        }
        return meta;
    }

    /// The version a request asked for, for reporting back in the error.
    fn requestedVersion(server: *const Server, params: ?std.json.Value) []const u8 {
        _ = server;
        const object = objectOf(params) orelse return "";
        const meta = objectOf(object.get("_meta")) orelse return "";
        return stringField(meta, types.meta_key.protocol_version) orelse "";
    }

    fn resultMeta(server: *const Server) ?types.ResultMeta {
        if (!server.options.include_server_info) return null;
        return .{ .server_info = server.info };
    }

    /// Adds the server's identity to a handler-supplied `_meta` without discarding
    /// what the handler put there.
    fn mergeResultMeta(server: *const Server, existing: ?types.ResultMeta) ?types.ResultMeta {
        if (!server.options.include_server_info) return existing;
        var meta = existing orelse return .{ .server_info = server.info };
        if (meta.server_info == null) meta.server_info = server.info;
        return meta;
    }

    // ---- Reply construction ----------------------------------------------

    fn resultReply(
        server: *const Server,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        result: anytype,
    ) error{OutOfMemory}!Outcome {
        _ = server;
        var allocating: std.Io.Writer.Allocating = .init(arena);
        const writer = &allocating.writer;

        writer.writeAll("{\"jsonrpc\":\"2.0\",\"id\":") catch return error.OutOfMemory;
        types.stringify(writer, id) catch return error.OutOfMemory;
        writer.writeAll(",\"result\":") catch return error.OutOfMemory;
        types.stringify(writer, result) catch return error.OutOfMemory;
        writer.writeAll("}") catch return error.OutOfMemory;

        return .{ .reply = .{ .bytes = allocating.written() } };
    }

    /// Builds a JSON-RPC error response.
    ///
    /// Public because transports need it. Streamable HTTP rejects a request on header
    /// grounds before dispatch, and stdio parses a message itself so that it can spot
    /// a subscription cancellation — both then have to produce a protocol error with
    /// no handler involved.
    pub fn errorReply(
        server: *const Server,
        arena: std.mem.Allocator,
        id: ?jsonrpc.Id,
        code: i32,
        message: ?[]const u8,
    ) error{OutOfMemory}!Outcome {
        _ = server;
        const response: jsonrpc.ErrorResponse = .{
            .id = id,
            .@"error" = .{
                .code = code,
                .message = message orelse jsonrpc.error_code.describe(code),
            },
        };
        const bytes = try types.stringifyAlloc(arena, response);
        return .{ .reply = .{ .bytes = bytes, .error_code = code } };
    }

    /// The reply for a message that could not be parsed.
    ///
    /// A transport that parses before dispatching — because it must inspect the body,
    /// as both HTTP and stdio do — needs the same answer `handleBytes` would have
    /// given, and there is exactly one right answer.
    pub fn parseFailureReply(
        server: *const Server,
        arena: std.mem.Allocator,
        err: jsonrpc.ParseError,
    ) error{OutOfMemory}!Outcome {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        // No id is recoverable from a message that failed to parse, and the spec
        // allows an error response without one.
        return server.errorReply(arena, null, jsonrpc.parseErrorCode(err), null);
    }

    /// The `-32022` reply, carrying the versions this server does support so the
    /// client can retry rather than guess.
    fn unsupportedVersionReply(
        server: *const Server,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        requested: []const u8,
    ) error{OutOfMemory}!Outcome {
        _ = server;
        // `std.json.Array` is the managed list variant, so the arena goes in at
        // construction rather than on each append.
        var supported: std.json.Array = .init(arena);
        try supported.append(.{ .string = types.protocol_version });

        var data: std.json.ObjectMap = .empty;
        try data.put(arena, "requested", .{ .string = requested });
        try data.put(arena, "supported", .{ .array = supported });

        const response: jsonrpc.ErrorResponse = .{
            .id = id,
            .@"error" = .{
                .code = jsonrpc.error_code.unsupported_protocol_version,
                .message = jsonrpc.error_code.describe(
                    jsonrpc.error_code.unsupported_protocol_version,
                ),
                .data = .{ .object = data },
            },
        };
        const bytes = try types.stringifyAlloc(arena, response);
        return .{ .reply = .{
            .bytes = bytes,
            .error_code = jsonrpc.error_code.unsupported_protocol_version,
        } };
    }

    /// Maps a handler failure onto a JSON-RPC error response.
    ///
    /// `InputRequired` is absent on purpose: it is not a failure and does not belong
    /// here. It is handled where the method is known, because only three methods may
    /// answer with an `InputRequiredResult`.
    fn handlerErrorReply(
        server: *const Server,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        err: Error,
    ) error{OutOfMemory}!Outcome {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            // A cancelled request gets no response at all: the peer is no longer
            // waiting for one.
            error.Cancelled => .no_reply,
            error.InvalidParams => server.errorReply(
                arena,
                id,
                jsonrpc.error_code.invalid_params,
                null,
            ),
            error.NotFound => server.errorReply(
                arena,
                id,
                jsonrpc.error_code.invalid_params,
                "not found",
            ),
            error.Internal => server.errorReply(
                arena,
                id,
                jsonrpc.error_code.internal_error,
                null,
            ),
            // Reached only when a handler asks for input on a method that may not
            // answer with it, which is a bug in the handler rather than in the
            // caller's request.
            error.InputRequired => server.errorReply(
                arena,
                id,
                jsonrpc.error_code.internal_error,
                "this method cannot request additional input",
            ),
            error.MissingClientCapability => unreachable, // handled by the caller
        };
    }

    /// Answers a handler that needs another round trip, or explains why it cannot.
    ///
    /// Both outcomes are produced here because both depend on the same thing: what
    /// the handler recorded on its context before stopping.
    fn inputReply(
        server: *const Server,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        method: []const u8,
        context: *Context,
        err: Error,
    ) error{OutOfMemory}!Outcome {
        switch (err) {
            error.InputRequired => {
                // The spec permits this on exactly three methods. A handler that asks
                // elsewhere would put the client in a loop it cannot exit, so it is
                // reported as a server fault rather than passed on.
                if (!types.method.supportsInputRequired(method)) {
                    return server.errorReply(
                        arena,
                        id,
                        jsonrpc.error_code.internal_error,
                        "this method cannot request additional input",
                    );
                }
                var result = context.inputRequiredResult();
                result.meta = server.mergeResultMeta(result.meta);
                return server.resultReply(arena, id, result);
            },
            error.MissingClientCapability => {
                var data: std.json.ObjectMap = .empty;
                const required = try context.requiredCapabilities(arena);
                const encoded = try types.stringifyAlloc(arena, required);
                const parsed = std.json.parseFromSliceLeaky(
                    std.json.Value,
                    arena,
                    encoded,
                    .{},
                ) catch return error.OutOfMemory;
                try data.put(arena, "requiredCapabilities", parsed);

                const response: jsonrpc.ErrorResponse = .{
                    .id = id,
                    .@"error" = .{
                        .code = jsonrpc.error_code.missing_required_client_capability,
                        .message = jsonrpc.error_code.describe(
                            jsonrpc.error_code.missing_required_client_capability,
                        ),
                        .data = .{ .object = data },
                    },
                };
                const bytes = try types.stringifyAlloc(arena, response);
                return .{ .reply = .{
                    .bytes = bytes,
                    .error_code = jsonrpc.error_code.missing_required_client_capability,
                } };
            },
            else => return server.handlerErrorReply(arena, id, err),
        }
    }
};

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// Extracts the request id from a `notifications/cancelled` message.
///
/// Returns null for any other message, and for a cancellation whose `requestId` is
/// missing or not a valid JSON-RPC id — a malformed cancellation is dropped rather
/// than guessed at, because guessing would mean cancelling the wrong request.
pub fn cancelledRequestId(message: jsonrpc.Message) ?jsonrpc.Id {
    const notification = switch (message) {
        .notification => |notification| notification,
        else => return null,
    };
    if (!std.mem.eql(u8, notification.method, types.notification.cancelled)) return null;

    const params = objectOf(notification.params) orelse return null;
    return jsonrpc.Id.fromValue(params.get("requestId") orelse return null) catch null;
}

/// Tracks in-flight requests so that a cancellation notification can reach the
/// handler that is serving the request it names.
///
/// Only transports that can read from the peer while a handler runs need this. A
/// sequential transport has nothing to deliver a cancellation to: by the time the
/// notification is read, the request it names has already been answered.
///
/// Capacity is fixed. A server with more concurrent requests than this has a
/// bigger problem than a full table, and refusing to track one is strictly better
/// than allocating without bound on input the peer controls.
pub const InFlight = struct {
    pub const capacity = 1024;

    const Entry = struct {
        /// Borrowed from the request's arena, which outlives the entry: the
        /// transport removes the entry before releasing the arena.
        id: jsonrpc.Id,
        cancellation: *Cancellation,
    };

    /// A spin lock rather than a blocking mutex.
    ///
    /// Every critical section here is a bounded scan over at most `capacity`
    /// entries with no syscall in it, so parking a thread would cost more than
    /// the wait. It also keeps the table free of any dependency on an `Io`, which
    /// matters because a transport may want to cancel from a signal handler or a
    /// reader thread that has no runtime of its own.
    lock: std.atomic.Mutex = .unlocked,
    entries: [capacity]Entry = undefined,
    length: usize = 0,

    fn acquire(table: *InFlight) void {
        while (!table.lock.tryLock()) std.atomic.spinLoopHint();
    }

    fn release(table: *InFlight) void {
        table.lock.unlock();
    }

    /// Registers a request. Returns false if the table is full, in which case the
    /// request still runs — it just cannot be cancelled.
    pub fn add(table: *InFlight, id: jsonrpc.Id, cancellation: *Cancellation) bool {
        table.acquire();
        defer table.release();

        if (table.length == capacity) return false;
        table.entries[table.length] = .{ .id = id, .cancellation = cancellation };
        table.length += 1;
        return true;
    }

    /// Deregisters a request. Safe to call for an id that was never added.
    pub fn remove(table: *InFlight, id: jsonrpc.Id) void {
        table.acquire();
        defer table.release();

        for (table.entries[0..table.length], 0..) |entry, index| {
            if (!entry.id.eql(id)) continue;
            // Order does not matter, so fill the hole from the end.
            table.length -= 1;
            table.entries[index] = table.entries[table.length];
            return;
        }
    }

    /// Cancels a request if it is still in flight. Returns whether it was found.
    ///
    /// A cancellation for a request that already finished is not an error: the spec
    /// says so explicitly, because the notification and the response race.
    pub fn cancel(table: *InFlight, id: jsonrpc.Id) bool {
        table.acquire();
        defer table.release();

        for (table.entries[0..table.length]) |entry| {
            if (!entry.id.eql(id)) continue;
            entry.cancellation.cancel();
            return true;
        }
        return false;
    }

    /// Cancels everything still in flight, for a transport shutting down.
    pub fn cancelAll(table: *InFlight) void {
        table.acquire();
        defer table.release();

        for (table.entries[0..table.length]) |entry| entry.cancellation.cancel();
    }

    pub fn count(table: *InFlight) usize {
        table.acquire();
        defer table.release();
        return table.length;
    }
};

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

fn Page(comptime T: type) type {
    return struct {
        items: []const T,
        next_cursor: ?types.Cursor,
    };
}

/// Slices one page out of a sorted list.
///
/// The cursor is the key of the last entry already delivered, which works because
/// the registry keeps entries sorted: resuming means skipping past that key. It
/// also degrades well — an entry removed between two pages does not shift the
/// window or cause a client to miss an unrelated entry, which an index-based cursor
/// would.
fn paginate(
    comptime T: type,
    items: []const T,
    cursor: ?types.Cursor,
    page_size: usize,
) Page(T) {
    assert(page_size > 0);

    var start: usize = 0;
    if (cursor) |after| {
        while (start < items.len and std.mem.order(u8, keyOf(T, items[start]), after) != .gt) {
            start += 1;
        }
    }

    const end = @min(start + page_size, items.len);
    const page = items[start..end];
    return .{
        .items = page,
        // A cursor is only meaningful if there is something after it.
        .next_cursor = if (end < items.len) keyOf(T, page[page.len - 1]) else null,
    };
}

fn keyOf(comptime T: type, item: T) []const u8 {
    return switch (T) {
        registry_mod.ToolDefinition, registry_mod.PromptDefinition => item.name,
        registry_mod.ResourceDefinition => item.uri,
        registry_mod.ResourceTemplateDefinition => item.uri_template,
        else => @compileError("no pagination key for " ++ @typeName(T)),
    };
}

// ---------------------------------------------------------------------------
// Params helpers
// ---------------------------------------------------------------------------

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const present = value orelse return null;
    return switch (present) {
        .object => |object| object,
        else => null,
    };
}

fn stringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |string| string,
        else => null,
    };
}

/// The tool name, prompt name, or resource URI a request addresses.
///
/// Public because three separate concerns need the same answer: the HTTP transport
/// validates `Mcp-Name` against it, a client has to produce that header, and
/// `requiredScopes` has to look up the entity that is about to run. Three
/// implementations would be three chances to address different entities.
pub fn subjectOf(rpc: jsonrpc.Request) ?[]const u8 {
    const params = objectOf(rpc.params) orelse return null;
    if (std.mem.eql(u8, rpc.method, types.method.tools_call) or
        std.mem.eql(u8, rpc.method, types.method.prompts_get))
    {
        return stringField(params, "name");
    }
    if (std.mem.eql(u8, rpc.method, types.method.resources_read)) {
        return stringField(params, "uri");
    }
    return null;
}

fn cursorOf(params: ?std.json.Value) ?types.Cursor {
    const object = objectOf(params) orelse return null;
    return stringField(object, "cursor");
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

fn failingTool(_: *Context, _: void) Error!types.CallToolResult {
    return error.Internal;
}

fn cancelledTool(_: *Context, _: void) Error!types.CallToolResult {
    return error.Cancelled;
}

fn toolReportingFailure(context: *Context, _: void) Error!types.CallToolResult {
    return context.errorResult("the tool ran and failed");
}

fn greetPrompt(context: *Context, args: struct { who: []const u8 }) Error!types.GetPromptResult {
    const messages = try context.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{
        .role = .user,
        .content = types.ContentBlock.fromText(try context.print("Hello, {s}", .{args.who})),
    };
    return .{ .messages = messages, .description = "A greeting" };
}

fn readReadme(context: *Context, uri: []const u8) Error!types.ReadResourceResult {
    const contents = try context.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "# Readme", .mimeType = "text/markdown" } };
    return .{ .contents = contents };
}

fn readProjectFile(context: *Context, uri: []const u8) Error!types.ReadResourceResult {
    const contents = try context.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "template body" } };
    return .{ .contents = contents };
}

fn completeWho(
    context: *Context,
    argument_name: []const u8,
    partial: []const u8,
) Error![]const []const u8 {
    if (!std.mem.eql(u8, argument_name, "who")) return &.{};
    const all = [_][]const u8{ "world", "worm", "alice" };
    var matches: std.ArrayListUnmanaged([]const u8) = .empty;
    for (all) |candidate| {
        if (std.mem.startsWith(u8, candidate, partial)) {
            try matches.append(context.arena, candidate);
        }
    }
    return matches.items;
}

/// A server plus registry plus arena, wired up for one test.
const Fixture = struct {
    registry: Registry,
    server: Server,
    arena: std.heap.ArenaAllocator,

    fn init(fixture: *Fixture, options: Options) !void {
        fixture.arena = .init(testing.allocator);
        fixture.registry = try Registry.initComptime(testing.allocator, .{
            registry_mod.tool("add", addTool, .{ .description = "Adds two numbers" }),
            registry_mod.tool("fail", failingTool, .{}),
            registry_mod.tool("report_failure", toolReportingFailure, .{}),
            registry_mod.prompt("greet", greetPrompt, .{ .completion = completeWho }),
            registry_mod.ResourceDefinition{
                .uri = "file:///readme.md",
                .name = "readme.md",
                .mime_type = "text/markdown",
                .handler = readReadme,
            },
            registry_mod.ResourceTemplateDefinition{
                .uri_template = "file:///project/{path}",
                .name = "project files",
                .handler = readProjectFile,
            },
        });
        fixture.server = .init(
            &fixture.registry,
            .{ .name = "test-server", .version = "0.1.0" },
            options,
        );
    }

    fn deinit(fixture: *Fixture) void {
        fixture.registry.deinit();
        fixture.arena.deinit();
    }

    fn allocator(fixture: *Fixture) std.mem.Allocator {
        return fixture.arena.allocator();
    }

    /// Sends a raw message and returns the decoded reply object.
    fn send(fixture: *Fixture, bytes: []const u8) !std.json.ObjectMap {
        const outcome = try fixture.server.handleBytes(.{ .arena = fixture.allocator() }, bytes);
        const reply = switch (outcome) {
            .reply => |reply| reply,
            .no_reply, .listen => return error.TestExpectedReply,
        };
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            fixture.allocator(),
            reply.bytes,
            .{},
        );
        return parsed.object;
    }

    fn sendOutcome(fixture: *Fixture, bytes: []const u8) !Outcome {
        return fixture.server.handleBytes(.{ .arena = fixture.allocator() }, bytes);
    }
};

/// The `_meta` every well-formed request needs.
const meta_json =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
    \\          "io.modelcontextprotocol/clientCapabilities":{}}
;

test "subscriptions/listen is accepted rather than replied to" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .list_changed = true });
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":5,"method":"subscriptions/listen","params":{
    ++ meta_json ++
        \\,"notifications":{"toolsListChanged":true}}}
    );

    // No reply: the acknowledgement is a notification, and the response is reserved
    // for a graceful close that may never come.
    const listen = switch (outcome) {
        .listen => |listen| listen,
        else => return error.TestExpectedListen,
    };
    try testing.expect(listen.id.eql(.{ .number = 5 }));
    try testing.expect(listen.granted.wantsToolsListChanged());
}

test "the grant omits notification types the server cannot honour" {
    var fixture: Fixture = undefined;
    // `list_changed` is off, so no list-changed type can be granted however it is asked
    // for — advertising otherwise would promise notifications that never arrive.
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
    ++ meta_json ++
        \\,"notifications":{"toolsListChanged":true,"resourcesListChanged":true}}}
    );

    const listen = outcome.listen;
    try testing.expect(listen.requested.wantsToolsListChanged());
    try testing.expect(listen.granted.isEmpty());
}

test "the grant keeps only subscribable resource URIs" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .resource_subscribe = true });
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
    ++ meta_json ++
        \\,"notifications":{"resourceSubscriptions":[
        \\ "file:///readme.md","file:///project/src/main.zig","file:///nope"]}}}
    );

    const granted = outcome.listen.granted.uris();
    // The registered resource and the template match; the third names nothing.
    try testing.expectEqual(@as(usize, 2), granted.len);
    try testing.expectEqualStrings("file:///readme.md", granted[0]);
    try testing.expectEqualStrings("file:///project/src/main.zig", granted[1]);
}

test "resource subscriptions are refused when the server does not offer them" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
    ++ meta_json ++
        \\,"notifications":{"resourceSubscriptions":["file:///readme.md"]}}}
    );
    try testing.expectEqual(@as(usize, 0), outcome.listen.granted.uris().len);
}

test "a malformed notification filter is invalid params" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .list_changed = true });
    defer fixture.deinit();

    const cases = [_][]const u8{
        // Missing `notifications`, which the schema requires.
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
        ++ meta_json ++ "}}",
        // Wrong type, which must not be coerced: a client that sends this is waiting
        // for notifications it will never get.
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
        ++ meta_json ++
            \\,"notifications":{"toolsListChanged":"yes"}}}
        ,
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
        ++ meta_json ++
            \\,"notifications":{"resourceSubscriptions":[7]}}}
        ,
    };

    for (cases) |bytes| {
        const reply = try fixture.send(bytes);
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.invalid_params),
            reply.get("error").?.object.get("code").?.integer,
        );
    }
}

test "an empty filter opens a valid but silent subscription" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .list_changed = true });
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
    ++ meta_json ++
        \\,"notifications":{}}}
    );
    try testing.expect(outcome.listen.granted.isEmpty());
}

test "capabilities advertise resource subscription support" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .list_changed = true, .resource_subscribe = true });
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{
    ++ meta_json ++
        \\}}
    );

    const resources = reply.get("result").?.object
        .get("capabilities").?.object
        .get("resources").?.object;
    try testing.expect(resources.get("subscribe").?.bool);
    try testing.expect(resources.get("listChanged").?.bool);
}

test "discover advertises supported versions, capabilities and identity" {
    var fixture: Fixture = undefined;
    try fixture.init(.{
        .instructions = "Use the add tool.",
        .cache = .{ .discover = .{ .ttl_ms = 3_600_000, .scope = .public } },
    });
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{
    ++ meta_json ++
        \\}}
    );

    const result = reply.get("result").?.object;
    try testing.expectEqualStrings("complete", result.get("resultType").?.string);
    try testing.expectEqualStrings(
        "2026-07-28",
        result.get("supportedVersions").?.array.items[0].string,
    );
    try testing.expectEqualStrings("Use the add tool.", result.get("instructions").?.string);
    try testing.expectEqual(@as(i64, 3_600_000), result.get("ttlMs").?.integer);
    try testing.expectEqualStrings("public", result.get("cacheScope").?.string);

    // Capabilities reflect what is registered, not what was configured.
    const capabilities = result.get("capabilities").?.object;
    try testing.expect(capabilities.get("tools") != null);
    try testing.expect(capabilities.get("prompts") != null);
    try testing.expect(capabilities.get("resources") != null);
    try testing.expect(capabilities.get("completions") != null);

    const meta = result.get("_meta").?.object;
    try testing.expectEqualStrings(
        "test-server",
        meta.get(types.meta_key.server_info).?.object.get("name").?.string,
    );
}

test "discover answers even when the client asked in an unsupported version" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // Discovery is the negotiation entry point: rejecting it for speaking the
    // wrong version would leave the client with no way to learn the right one.
    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{
        \\ "io.modelcontextprotocol/protocolVersion":"1900-01-01",
        \\ "io.modelcontextprotocol/clientCapabilities":{}}}}
    );
    try testing.expect(reply.get("error") == null);
    try testing.expectEqualStrings(
        "2026-07-28",
        reply.get("result").?.object.get("supportedVersions").?.array.items[0].string,
    );
}

test "discover answers a request with no params at all" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // The stdio backward-compatibility probe: a dual-era client needs a
    // deterministic answer here.
    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"server/discover"}
    );
    try testing.expect(reply.get("result") != null);
}

test "a request in an unsupported version is rejected with the supported list" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{
        \\ "io.modelcontextprotocol/protocolVersion":"2025-11-25",
        \\ "io.modelcontextprotocol/clientCapabilities":{}}}}
    );
    const reply = outcome.reply;
    try testing.expectEqual(
        jsonrpc.error_code.unsupported_protocol_version,
        reply.error_code.?,
    );
    // The transport spec requires 400 for this.
    try testing.expectEqual(@as(u16, 400), reply.httpStatus());

    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.allocator(),
        reply.bytes,
        .{},
    );
    const err = parsed.object.get("error").?.object;
    try testing.expectEqual(@as(i64, -32022), err.get("code").?.integer);
    const data = err.get("data").?.object;
    try testing.expectEqualStrings("2025-11-25", data.get("requested").?.string);
    try testing.expectEqualStrings("2026-07-28", data.get("supported").?.array.items[0].string);
}

test "a request without _meta is rejected as invalid params" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    for ([_][]const u8{
        // No params at all.
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
        ,
        // Params but no _meta.
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
        ,
        // _meta without the required protocol version.
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        \\ "io.modelcontextprotocol/clientCapabilities":{}}}}
        ,
        // _meta without the required client capabilities.
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        \\ "io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}
        ,
    }) |bytes| {
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
    }
}

test "an unknown method is answered with method not found" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/nonexistent","params":{
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqual(jsonrpc.error_code.method_not_found, outcome.reply.error_code.?);
    // The transport spec asks for 404 here, so a client can tell this apart from a
    // 404 produced by a server that hosts no MCP endpoint.
    try testing.expectEqual(@as(u16, 404), outcome.reply.httpStatus());
}

test "removed methods from earlier revisions are not found" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // These existed in 2025-11-25 and were removed. Answering them would be worse
    // than refusing: a legacy client would think it had a working session.
    for ([_][]const u8{
        "initialize",
        "ping",
        "logging/setLevel",
        "resources/subscribe",
        "resources/unsubscribe",
    }) |method| {
        const bytes = try std.fmt.allocPrint(
            fixture.allocator(),
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{{{s}}}}}",
            .{ method, meta_json },
        );
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expectEqual(jsonrpc.error_code.method_not_found, outcome.reply.error_code.?);
    }
}

test "tools/list returns descriptors in a deterministic order" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .cache = .{ .tools = .{ .ttl_ms = 60_000, .scope = .public } } });
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{
    ++ meta_json ++
        \\}}
    );
    const result = reply.get("result").?.object;
    const tools = result.get("tools").?.array.items;

    try testing.expectEqual(@as(usize, 3), tools.len);
    // Sorted by name, which is what the spec asks for so clients and prompt caches
    // can rely on the order.
    try testing.expectEqualStrings("add", tools[0].object.get("name").?.string);
    try testing.expectEqualStrings("fail", tools[1].object.get("name").?.string);
    try testing.expectEqualStrings("report_failure", tools[2].object.get("name").?.string);

    // The comptime-derived schema arrives inline.
    const schema = tools[0].object.get("inputSchema").?.object;
    try testing.expectEqualStrings("object", schema.get("type").?.string);
    try testing.expectEqualStrings(
        "First addend",
        schema.get("properties").?.object.get("a").?.object.get("description").?.string,
    );

    // CacheableResult makes these mandatory.
    try testing.expectEqual(@as(i64, 60_000), result.get("ttlMs").?.integer);
    try testing.expectEqualStrings("public", result.get("cacheScope").?.string);
    try testing.expect(result.get("nextCursor") == null);
}

test "tools/call decodes arguments and returns the handler's result" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        \\ "name":"add","arguments":{"a":2,"b":40},
    ++ meta_json ++
        \\}}
    );
    const result = reply.get("result").?.object;
    try testing.expectEqualStrings("complete", result.get("resultType").?.string);
    try testing.expectEqualStrings(
        "42",
        result.get("content").?.array.items[0].object.get("text").?.string,
    );
    // The server identifies itself on the result too.
    try testing.expect(result.get("_meta").?.object.get(types.meta_key.server_info) != null);
}

test "tools/call on an unknown tool is invalid params" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        \\ "name":"nope","arguments":{},
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
    // A well-formed request that failed is still HTTP 200.
    try testing.expectEqual(@as(u16, 200), outcome.reply.httpStatus());
}

test "tools/call rejects arguments that do not match the schema" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        \\ "name":"add","arguments":{"a":"two","b":40},
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
}

test "tools/call without a name is invalid params" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    for ([_][]const u8{
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        ++ meta_json ++
            \\}}
        ,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":5,
        ++ meta_json ++
            \\}}
        ,
    }) |bytes| {
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
    }
}

test "a tool that fails internally becomes an internal error" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fail",
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqual(jsonrpc.error_code.internal_error, outcome.reply.error_code.?);
}

test "a tool reporting its own failure returns a successful result" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"report_failure",
    ++ meta_json ++
        \\}}
    );
    // The distinction that matters: a tool that ran and failed is not a protocol
    // error, so the model gets to see what happened.
    try testing.expect(reply.get("error") == null);
    const result = reply.get("result").?.object;
    try testing.expectEqual(true, result.get("isError").?.bool);
    try testing.expectEqualStrings("complete", result.get("resultType").?.string);
}

test "a cancelled handler produces no response" {
    var registry = try Registry.initComptime(testing.allocator, .{
        registry_mod.tool("cancelled", cancelledTool, .{}),
    });
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});
    const outcome = try server.handleBytes(.{ .arena = arena.allocator() },
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cancelled",
    ++ meta_json ++
        \\}}
    );
    // The peer stopped waiting, so there is nobody to answer.
    try testing.expect(outcome == .no_reply);
}

test "prompts/list and prompts/get work end to end" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    {
        const reply = try fixture.send(
            \\{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{
        ++ meta_json ++
            \\}}
        );
        const prompts = reply.get("result").?.object.get("prompts").?.array.items;
        try testing.expectEqual(@as(usize, 1), prompts.len);
        try testing.expectEqualStrings("greet", prompts[0].object.get("name").?.string);
        const arguments = prompts[0].object.get("arguments").?.array.items;
        try testing.expectEqualStrings("who", arguments[0].object.get("name").?.string);
        try testing.expectEqual(true, arguments[0].object.get("required").?.bool);
    }
    {
        const reply = try fixture.send(
            \\{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{
            \\ "name":"greet","arguments":{"who":"world"},
        ++ meta_json ++
            \\}}
        );
        const result = reply.get("result").?.object;
        try testing.expectEqualStrings("A greeting", result.get("description").?.string);
        const message = result.get("messages").?.array.items[0].object;
        try testing.expectEqualStrings("user", message.get("role").?.string);
        try testing.expectEqualStrings(
            "Hello, world",
            message.get("content").?.object.get("text").?.string,
        );
    }
}

test "prompts/get on an unknown prompt is invalid params" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"nope",
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
}

test "resources/list and resources/read work end to end" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .cache = .{ .resource_read = .{ .ttl_ms = 5_000, .scope = .private } } });
    defer fixture.deinit();

    {
        const reply = try fixture.send(
            \\{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{
        ++ meta_json ++
            \\}}
        );
        const resources = reply.get("result").?.object.get("resources").?.array.items;
        try testing.expectEqual(@as(usize, 1), resources.len);
        try testing.expectEqualStrings("file:///readme.md", resources[0].object.get("uri").?.string);
        try testing.expectEqualStrings("text/markdown", resources[0].object.get("mimeType").?.string);
    }
    {
        const reply = try fixture.send(
            \\{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{
            \\ "uri":"file:///readme.md",
        ++ meta_json ++
            \\}}
        );
        const result = reply.get("result").?.object;
        try testing.expectEqualStrings(
            "# Readme",
            result.get("contents").?.array.items[0].object.get("text").?.string,
        );
        // The server applies its own cache policy rather than trusting the handler.
        try testing.expectEqual(@as(i64, 5_000), result.get("ttlMs").?.integer);
        try testing.expectEqualStrings("private", result.get("cacheScope").?.string);
    }
}

test "resources/read falls back to a matching template" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{
        \\ "uri":"file:///project/src/main.zig",
    ++ meta_json ++
        \\}}
    );
    const contents = reply.get("result").?.object.get("contents").?.array.items;
    try testing.expectEqualStrings("template body", contents[0].object.get("text").?.string);
    try testing.expectEqualStrings(
        "file:///project/src/main.zig",
        contents[0].object.get("uri").?.string,
    );
}

test "resources/read on an unknown uri uses invalid params, not the old code" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{
        \\ "uri":"file:///nowhere",
    ++ meta_json ++
        \\}}
    );
    // 2026-07-28 moved this from -32002 to -32602.
    try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
    try testing.expect(outcome.reply.error_code.? != -32002);
}

test "resources/templates/list returns the registered templates" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"resources/templates/list","params":{
    ++ meta_json ++
        \\}}
    );
    const templates = reply.get("result").?.object.get("resourceTemplates").?.array.items;
    try testing.expectEqual(@as(usize, 1), templates.len);
    try testing.expectEqualStrings(
        "file:///project/{path}",
        templates[0].object.get("uriTemplate").?.string,
    );
}

test "completion/complete filters candidates by the partial value" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "ref":{"type":"ref/prompt","name":"greet"},
        \\ "argument":{"name":"who","value":"wor"},
    ++ meta_json ++
        \\}}
    );
    const completion = reply.get("result").?.object.get("completion").?.object;
    const values = completion.get("values").?.array.items;
    try testing.expectEqual(@as(usize, 2), values.len);
    try testing.expectEqualStrings("world", values[0].string);
    try testing.expectEqualStrings("worm", values[1].string);
    try testing.expectEqual(@as(i64, 2), completion.get("total").?.integer);
    try testing.expectEqual(false, completion.get("hasMore").?.bool);
}

test "completion/complete returns an empty list when nothing can complete" {
    var registry = try Registry.initComptime(testing.allocator, .{
        // A prompt with no completion handler.
        registry_mod.prompt("greet", greetPrompt, .{}),
    });
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});
    const outcome = try server.handleBytes(.{ .arena = arena.allocator() },
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "ref":{"type":"ref/prompt","name":"greet"},
        \\ "argument":{"name":"who","value":"w"},
    ++ meta_json ++
        \\}}
    );
    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        outcome.reply.bytes,
        .{},
    );
    // An empty list rather than an error: a client's completion UI should not break
    // because a server has nothing to suggest.
    try testing.expect(parsed.object.get("error") == null);
    const values = parsed.object.get("result").?.object
        .get("completion").?.object.get("values").?.array;
    try testing.expectEqual(@as(usize, 0), values.items.len);
}

test "completion/complete rejects malformed params" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    for ([_][]const u8{
        // No ref.
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "argument":{"name":"who","value":"w"},
        ++ meta_json ++
            \\}}
        ,
        // Unknown ref type.
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "ref":{"type":"ref/other"},"argument":{"name":"who","value":"w"},
        ++ meta_json ++
            \\}}
        ,
        // No argument.
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "ref":{"type":"ref/prompt","name":"greet"},
        ++ meta_json ++
            \\}}
        ,
        // Argument without a name.
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "ref":{"type":"ref/prompt","name":"greet"},"argument":{"value":"w"},
        ++ meta_json ++
            \\}}
        ,
        // Reference to a prompt that does not exist.
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{
        \\ "ref":{"type":"ref/prompt","name":"nope"},"argument":{"name":"who","value":"w"},
        ++ meta_json ++
            \\}}
        ,
    }) |bytes| {
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expectEqual(jsonrpc.error_code.invalid_params, outcome.reply.error_code.?);
    }
}

test "notifications get no response" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    for ([_][]const u8{
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}
        ,
        \\{"jsonrpc":"2.0","method":"notifications/unknown"}
        ,
    }) |bytes| {
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expect(outcome == .no_reply);
    }
}

test "responses arriving at a server are ignored" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // This revision has no server-initiated requests, so there is nothing a
    // response could correlate with.
    for ([_][]const u8{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}
        ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}
        ,
    }) |bytes| {
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expect(outcome == .no_reply);
    }
}

test "malformed input produces a parse error with no id" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome("{not json");
    try testing.expectEqual(jsonrpc.error_code.parse_error, outcome.reply.error_code.?);
    try testing.expectEqual(@as(u16, 400), outcome.reply.httpStatus());

    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.allocator(),
        outcome.reply.bytes,
        .{},
    );
    // The spec allows an error response without an id, which is the only honest
    // answer when the id could not be read.
    try testing.expect(parsed.object.get("id") == null);
}

test "a structurally invalid request produces invalid request" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"1.0","id":1,"method":"tools/list"}
    );
    try testing.expectEqual(jsonrpc.error_code.invalid_request, outcome.reply.error_code.?);
}

test "string ids are echoed as strings" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":"req-abc","method":"tools/list","params":{
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqualStrings("req-abc", reply.get("id").?.string);
}

test "server info can be suppressed" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .include_server_info = false });
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{
    ++ meta_json ++
        \\}}
    );
    // SHOULD, not MUST: a deployment may prefer not to advertise its software.
    try testing.expect(reply.get("result").?.object.get("_meta") == null);
}

test "pagination walks a list in order without gaps or repeats" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    var name_storage: [7][8]u8 = undefined;
    for (0..7) |index| {
        const name = try std.fmt.bufPrint(&name_storage[index], "tool{d}", .{index});
        try registry.addTool(.{
            .name = name,
            .input_schema = .{ .raw = "{}" },
            .handler = registry_mod.tool("x", failingTool, .{}).handler,
        });
    }

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(
        &registry,
        .{ .name = "s", .version = "1" },
        .{ .page_size = 3 },
    );

    var seen: std.ArrayListUnmanaged([]const u8) = .empty;
    defer seen.deinit(testing.allocator);

    var cursor: ?[]const u8 = null;
    var pages: usize = 0;
    while (true) {
        const bytes = if (cursor) |after| try std.fmt.allocPrint(
            arena.allocator(),
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"," ++
                "\"params\":{{\"cursor\":\"{s}\",{s}}}}}",
            .{ after, meta_json },
        ) else try std.fmt.allocPrint(
            arena.allocator(),
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{{{s}}}}}",
            .{meta_json},
        );

        const outcome = try server.handleBytes(.{ .arena = arena.allocator() }, bytes);
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            arena.allocator(),
            outcome.reply.bytes,
            .{},
        );
        const result = parsed.object.get("result").?.object;
        for (result.get("tools").?.array.items) |item| {
            try seen.append(testing.allocator, item.object.get("name").?.string);
        }
        pages += 1;

        cursor = if (result.get("nextCursor")) |next| next.string else null;
        if (cursor == null) break;
        try testing.expect(pages < 10);
    }

    try testing.expectEqual(@as(usize, 3), pages);
    try testing.expectEqual(@as(usize, 7), seen.items.len);
    for (seen.items, 0..) |name, index| {
        var expected: [8]u8 = undefined;
        try testing.expectEqualStrings(
            try std.fmt.bufPrint(&expected, "tool{d}", .{index}),
            name,
        );
    }
}

test "a cursor past the end yields an empty page" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"zzz",
    ++ meta_json ++
        \\}}
    );
    const result = reply.get("result").?.object;
    try testing.expectEqual(@as(usize, 0), result.get("tools").?.array.items.len);
    try testing.expect(result.get("nextCursor") == null);
}

test "paginate slices correctly at the boundaries" {
    const Item = registry_mod.ToolDefinition;
    const handler = registry_mod.tool("x", failingTool, .{}).handler;
    const items = [_]Item{
        .{ .name = "a", .input_schema = .{ .raw = "{}" }, .handler = handler },
        .{ .name = "b", .input_schema = .{ .raw = "{}" }, .handler = handler },
        .{ .name = "c", .input_schema = .{ .raw = "{}" }, .handler = handler },
    };

    // A page that exactly covers the list must not advertise a next cursor.
    {
        const page = paginate(Item, &items, null, 3);
        try testing.expectEqual(@as(usize, 3), page.items.len);
        try testing.expect(page.next_cursor == null);
    }
    {
        const page = paginate(Item, &items, null, 2);
        try testing.expectEqual(@as(usize, 2), page.items.len);
        try testing.expectEqualStrings("b", page.next_cursor.?);
    }
    {
        const page = paginate(Item, &items, "b", 2);
        try testing.expectEqual(@as(usize, 1), page.items.len);
        try testing.expectEqualStrings("c", page.items[0].name);
        try testing.expect(page.next_cursor == null);
    }
    // An empty list is not a special case.
    {
        const page = paginate(Item, &.{}, null, 10);
        try testing.expectEqual(@as(usize, 0), page.items.len);
        try testing.expect(page.next_cursor == null);
    }
}

test "the same registry serves two requests independently" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // Statelessness: nothing carries over between requests, including the client
    // identity and capabilities, which arrive fresh each time.
    const first = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        \\ "name":"add","arguments":{"a":1,"b":1},
        \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\          "io.modelcontextprotocol/clientCapabilities":{},
        \\          "io.modelcontextprotocol/clientInfo":{"name":"first","version":"1"}}}}
    );
    try testing.expectEqualStrings(
        "2",
        first.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string,
    );

    const second = try fixture.send(
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        \\ "name":"add","arguments":{"a":20,"b":22},
        \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\          "io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}}}
    );
    try testing.expectEqualStrings(
        "42",
        second.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string,
    );
}

test "an empty registry still answers discover" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});
    const outcome = try server.handleBytes(.{ .arena = arena.allocator() },
        \\{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{
    ++ meta_json ++
        \\}}
    );
    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        outcome.reply.bytes,
        .{},
    );
    const capabilities = parsed.object.get("result").?.object.get("capabilities").?.object;
    // Nothing registered means nothing advertised, so a client never calls into a
    // capability that is not there.
    try testing.expectEqual(@as(usize, 0), capabilities.count());
}

test "lists are empty rather than absent when nothing is registered" {
    var registry: Registry = .init(testing.allocator);
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});
    for ([_]struct { method: []const u8, key: []const u8 }{
        .{ .method = "tools/list", .key = "tools" },
        .{ .method = "prompts/list", .key = "prompts" },
        .{ .method = "resources/list", .key = "resources" },
        .{ .method = "resources/templates/list", .key = "resourceTemplates" },
    }) |case| {
        const bytes = try std.fmt.allocPrint(
            arena.allocator(),
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{{{s}}}}}",
            .{ case.method, meta_json },
        );
        const outcome = try server.handleBytes(.{ .arena = arena.allocator() }, bytes);
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            arena.allocator(),
            outcome.reply.bytes,
            .{},
        );
        const result = parsed.object.get("result").?.object;
        try testing.expectEqual(@as(usize, 0), result.get(case.key).?.array.items.len);
    }
}

test "handling a message twice on a reset arena leaks nothing" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // Mirrors what a transport does: one arena per request, reset in between.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    for (0..64) |_| {
        const outcome = try fixture.server.handleBytes(.{ .arena = arena.allocator() },
            \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            \\ "name":"add","arguments":{"a":1,"b":2},
        ++ meta_json ++
            \\}}
        );
        try testing.expect(outcome == .reply);
        _ = arena.reset(.retain_capacity);
    }
}

test "every reply is well-formed JSON-RPC" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const messages = [_][]const u8{
        \\{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{
        ++ meta_json ++
            \\}}
        ,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{
        ++ meta_json ++
            \\}}
        ,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add",
        \\ "arguments":{"a":1,"b":2},
        ++ meta_json ++
            \\}}
        ,
        \\{"jsonrpc":"2.0","id":4,"method":"prompts/list","params":{
        ++ meta_json ++
            \\}}
        ,
        \\{"jsonrpc":"2.0","id":5,"method":"resources/list","params":{
        ++ meta_json ++
            \\}}
        ,
        \\{"jsonrpc":"2.0","id":6,"method":"nope","params":{
        ++ meta_json ++
            \\}}
        ,
        "garbage",
    };

    for (messages) |bytes| {
        const outcome = try fixture.sendOutcome(bytes);
        const reply = switch (outcome) {
            .reply => |reply| reply,
            .no_reply, .listen => continue,
        };
        // Re-parsing as a JSON-RPC message is the strongest cheap check: it proves
        // the envelope, the id handling and the result/error split are all valid.
        const message = try jsonrpc.parseLeaky(fixture.allocator(), reply.bytes);
        try testing.expect(message == .result_response or message == .error_response);
    }
}

test "fuzz the dispatcher against arbitrary input" {
    const Context_ = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var registry = try Registry.initComptime(testing.allocator, .{
                registry_mod.tool("add", addTool, .{}),
            });
            defer registry.deinit();

            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

            var buffer: [1024]u8 = undefined;
            const length = smith.slice(&buffer);
            // Any answer is fine; crashing or leaking is not.
            _ = server.handleBytes(.{ .arena = arena.allocator() }, buffer[0..length]) catch return;
        }
    };
    try testing.fuzz(Context_{}, Context_.testOne, .{});
}

// ---------------------------------------------------------------------------
// Request-scoped notifications
// ---------------------------------------------------------------------------

/// Reports progress and logs while it works, so a test can observe the ordering.
fn chattyTool(context: *Context, _: void) Error!types.CallToolResult {
    context.logPrint(.debug, "starting", .{});
    context.reportProgress(0, .{ .total = 2, .message = "step one" });
    context.reportProgress(1, .{ .total = 2, .message = "step two" });
    context.logPrint(.info, "finishing", .{});
    context.reportProgress(2, .{ .total = 2 });
    return context.textResult("done");
}

/// Stops as soon as the peer cancels.
fn interruptibleTool(context: *Context, _: void) Error!types.CallToolResult {
    for (0..8) |step| {
        try context.checkCancelled();
        context.reportProgress(@floatFromInt(step), .{ .total = 8 });
    }
    return context.textResult("ran to completion");
}

const NotifyFixture = struct {
    registry: Registry,
    server: Server,
    arena: std.heap.ArenaAllocator,
    collector: context_mod.CollectingSink,

    fn init(fixture: *NotifyFixture) !void {
        fixture.arena = .init(testing.allocator);
        fixture.collector = .init(testing.allocator);
        fixture.registry = try Registry.initComptime(testing.allocator, .{
            registry_mod.tool("chatty", chattyTool, .{}),
            registry_mod.tool("interruptible", interruptibleTool, .{}),
        });
        fixture.server = .init(
            &fixture.registry,
            .{ .name = "notify-test", .version = "1" },
            .{},
        );
    }

    fn deinit(fixture: *NotifyFixture) void {
        fixture.collector.deinit();
        fixture.registry.deinit();
        fixture.arena.deinit();
    }

    fn call(
        fixture: *NotifyFixture,
        bytes: []const u8,
        cancellation: ?*const Cancellation,
    ) !Outcome {
        return fixture.server.handleBytes(.{
            .arena = fixture.arena.allocator(),
            .sink = fixture.collector.sink(),
            .cancellation = cancellation,
        }, bytes);
    }
};

test "a handler's notifications reach the transport's sink" {
    var fixture: NotifyFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const outcome = try fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chatty",
        \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\          "io.modelcontextprotocol/clientCapabilities":{},
        \\          "io.modelcontextprotocol/logLevel":"debug",
        \\          "progressToken":"tok"}}}
    , null);
    try testing.expect(outcome == .reply);

    // Five notifications, in the order the handler emitted them: a client rendering
    // a progress bar depends on that order.
    const messages = fixture.collector.messages.items;
    try testing.expectEqual(@as(usize, 5), messages.len);
    try testing.expect(std.mem.indexOf(u8, messages[0], "\"starting\"") != null);
    try testing.expect(std.mem.indexOf(u8, messages[1], "\"message\":\"step one\"") != null);
    try testing.expect(std.mem.indexOf(u8, messages[2], "\"message\":\"step two\"") != null);
    try testing.expect(std.mem.indexOf(u8, messages[3], "\"finishing\"") != null);
    try testing.expect(std.mem.indexOf(u8, messages[4], "\"progress\":2") != null);

    // Every progress notification carries the token the client supplied.
    for ([_]usize{ 1, 2, 4 }) |index| {
        try testing.expect(std.mem.indexOf(u8, messages[index], "\"progressToken\":\"tok\"") != null);
    }
}

test "a client that asked for neither progress nor logs gets neither" {
    var fixture: NotifyFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    // The same handler, same sink: what changes is only what the client opted into.
    const outcome = try fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chatty",
    ++ meta_json ++
        \\}}
    , null);
    try testing.expect(outcome == .reply);
    try testing.expectEqual(@as(usize, 0), fixture.collector.messages.items.len);
}

test "opting into progress alone suppresses log messages" {
    var fixture: NotifyFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    _ = try fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chatty",
        \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\          "io.modelcontextprotocol/clientCapabilities":{},
        \\          "progressToken":7}}}
    , null);

    const messages = fixture.collector.messages.items;
    try testing.expectEqual(@as(usize, 3), messages.len);
    for (messages) |message| {
        try testing.expect(std.mem.indexOf(u8, message, "notifications/progress") != null);
    }
}

test "a log level filters which messages are emitted" {
    var fixture: NotifyFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    _ = try fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chatty",
        \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\          "io.modelcontextprotocol/clientCapabilities":{},
        \\          "io.modelcontextprotocol/logLevel":"info"}}}
    , null);

    // The debug line is dropped, the info line is kept, and no progress is sent
    // because no token was supplied.
    const messages = fixture.collector.messages.items;
    try testing.expectEqual(@as(usize, 1), messages.len);
    try testing.expect(std.mem.indexOf(u8, messages[0], "\"finishing\"") != null);
}

test "a cancelled request produces no response" {
    var fixture: NotifyFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    var cancellation: Cancellation = .{};
    cancellation.cancel();

    const outcome = try fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"interruptible",
    ++ meta_json ++
        \\}}
    , &cancellation);

    // Already cancelled, so the handler stops on its first poll and the dispatcher
    // sends nothing: the peer is not waiting, and an error response would be an
    // unsolicited message.
    try testing.expect(outcome == .no_reply);
    try testing.expectEqual(@as(usize, 0), fixture.collector.messages.items.len);
}

test "an uncancelled request runs to completion" {
    var fixture: NotifyFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    var cancellation: Cancellation = .{};
    const outcome = try fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"interruptible",
    ++ meta_json ++
        \\}}
    , &cancellation);
    try testing.expect(outcome == .reply);
}

test "cancelledRequestId reads the id out of a cancellation notification" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { bytes: []const u8, expected: ?jsonrpc.Id }{
        .{
            .bytes =
            \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":42}}
            ,
            .expected = .{ .number = 42 },
        },
        .{
            .bytes =
            \\{"jsonrpc":"2.0","method":"notifications/cancelled",
            \\ "params":{"requestId":"abc","reason":"user pressed stop"}}
            ,
            .expected = .{ .string = "abc" },
        },
        // Not a cancellation.
        .{
            .bytes =
            \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1}}
            ,
            .expected = null,
        },
        // A cancellation with no id: dropped rather than guessed at, because
        // guessing means cancelling somebody else's request.
        .{
            .bytes =
            \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}
            ,
            .expected = null,
        },
        .{
            .bytes =
            \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1.5}}
            ,
            .expected = null,
        },
        // A request, not a notification.
        .{
            .bytes =
            \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
            ,
            .expected = null,
        },
    };

    for (cases) |case| {
        const message = try jsonrpc.parseLeaky(arena.allocator(), case.bytes);
        const actual = cancelledRequestId(message);
        if (case.expected) |expected| {
            try testing.expect(actual != null);
            try testing.expect(expected.eql(actual.?));
        } else {
            try testing.expect(actual == null);
        }
    }
}

test "the in-flight table routes a cancellation to the right request" {
    var table: InFlight = .{};

    var first: Cancellation = .{};
    var second: Cancellation = .{};

    try testing.expect(table.add(.{ .number = 1 }, &first));
    try testing.expect(table.add(.{ .string = "two" }, &second));
    try testing.expectEqual(@as(usize, 2), table.count());

    try testing.expect(table.cancel(.{ .string = "two" }));
    try testing.expect(!first.isCancelled());
    try testing.expect(second.isCancelled());

    // A cancellation for something that already finished is not an error: the
    // notification and the response race by design.
    table.remove(.{ .number = 1 });
    try testing.expect(!table.cancel(.{ .number = 1 }));
    try testing.expectEqual(@as(usize, 1), table.count());
}

test "a number id and a string id that look alike are distinct" {
    var table: InFlight = .{};

    var numeric: Cancellation = .{};
    try testing.expect(table.add(.{ .number = 1 }, &numeric));

    // JSON-RPC ids are typed, so `1` and `"1"` name different requests.
    try testing.expect(!table.cancel(.{ .string = "1" }));
    try testing.expect(!numeric.isCancelled());
    try testing.expect(table.cancel(.{ .number = 1 }));
}

test "the in-flight table refuses to grow past its capacity" {
    var table: InFlight = .{};

    var tokens: [InFlight.capacity]Cancellation = undefined;
    for (&tokens, 0..) |*token, index| {
        token.* = .{};
        try testing.expect(table.add(.{ .number = @intCast(index) }, token));
    }

    // Refusing is the point: the peer controls how many requests are in flight, so
    // an unbounded table is an unbounded allocation on input.
    var overflow: Cancellation = .{};
    try testing.expect(!table.add(.{ .number = -1 }, &overflow));

    table.cancelAll();
    for (&tokens) |*token| try testing.expect(token.isCancelled());
    try testing.expect(!overflow.isCancelled());
}

test "removing entries keeps the rest reachable" {
    var table: InFlight = .{};

    var tokens: [8]Cancellation = undefined;
    for (&tokens, 0..) |*token, index| {
        token.* = .{};
        try testing.expect(table.add(.{ .number = @intCast(index) }, token));
    }

    // Removal fills the hole from the end, so this exercises the case where an
    // entry moves.
    table.remove(.{ .number = 2 });
    table.remove(.{ .number = 0 });
    try testing.expectEqual(@as(usize, 6), table.count());

    for ([_]i64{ 1, 3, 4, 5, 6, 7 }) |id| {
        try testing.expect(table.cancel(.{ .number = id }));
    }
    try testing.expect(!table.cancel(.{ .number = 0 }));
    try testing.expect(!table.cancel(.{ .number = 2 }));
}

// ---------------------------------------------------------------------------
// Multi-round-trip requests
// ---------------------------------------------------------------------------

const name_schema: types.Json = .{ .raw =
    \\{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}
};

/// Asks for a username on the first attempt, greets on the retry.
fn greetGithubUser(context: *Context, _: void) Error!types.CallToolResult {
    if (context.elicited("github_login")) |answer| {
        // Decline and cancel are answers, and the tool has to handle both: the spec
        // tells servers not to assume an elicitation succeeds.
        if (!answer.action.accepted()) {
            return context.errorResult("no username was provided");
        }
        const name = answer.string("name") orelse
            return context.errorResult("the username was missing from the response");
        return context.textResult(try context.print("hello {s}", .{name}));
    }

    try context.elicitForm("github_login", "Please provide your GitHub username", name_schema);
    return context.needInput(.{ .state = "greet:round-1" });
}

/// Needs a URL interaction, which not every client can do.
fn connectAccount(context: *Context, _: void) Error!types.CallToolResult {
    if (context.requestState()) |state| {
        if (std.mem.eql(u8, state, "connect:pending")) {
            return context.textResult("connected");
        }
    }
    try context.elicitUrl(
        "connect",
        "Connect your account to continue.",
        "https://example.com/connect",
    );
    return context.needInput(.{ .state = "connect:pending" });
}

/// Wants only to be retried, with no question to ask.
fn waitForExternal(context: *Context, _: void) Error!types.CallToolResult {
    if (context.isRetry()) return context.textResult("finished");
    return context.needInput(.{ .state = "waiting" });
}

/// Asks for input from a method that may not do so.
fn overreachingCompletion(
    context: *Context,
    _: []const u8,
    _: []const u8,
) Error![]const []const u8 {
    try context.elicitForm("who", "Who?", name_schema);
    return context.needInput(.{ .state = "x" });
}

fn plainPrompt(context: *Context, _: struct {}) Error!types.GetPromptResult {
    const messages = try context.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = types.ContentBlock.fromText("hi") };
    return .{ .messages = messages };
}

const MrtrFixture = struct {
    registry: Registry,
    server: Server,
    arena: std.heap.ArenaAllocator,

    fn init(fixture: *MrtrFixture) !void {
        fixture.arena = .init(testing.allocator);
        fixture.registry = try Registry.initComptime(testing.allocator, .{
            registry_mod.tool("greet_github_user", greetGithubUser, .{}),
            registry_mod.tool("connect_account", connectAccount, .{}),
            registry_mod.tool("wait", waitForExternal, .{}),
            registry_mod.prompt("plain", plainPrompt, .{ .completion = overreachingCompletion }),
        });
        fixture.server = .init(&fixture.registry, .{ .name = "mrtr", .version = "1" }, .{});
    }

    fn deinit(fixture: *MrtrFixture) void {
        fixture.registry.deinit();
        fixture.arena.deinit();
    }

    fn allocator(fixture: *MrtrFixture) std.mem.Allocator {
        return fixture.arena.allocator();
    }

    fn send(fixture: *MrtrFixture, bytes: []const u8) !std.json.ObjectMap {
        const outcome = try fixture.server.handleBytes(
            .{ .arena = fixture.allocator() },
            bytes,
        );
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            fixture.allocator(),
            outcome.reply.bytes,
            .{},
        );
        return parsed.object;
    }

    fn sendOutcome(fixture: *MrtrFixture, bytes: []const u8) !Outcome {
        return fixture.server.handleBytes(.{ .arena = fixture.allocator() }, bytes);
    }
};

/// `_meta` declaring form-mode elicitation, on a single line for framing safety.
const meta_form = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientCapabilities\":{\"elicitation\":{}}}";

/// `_meta` declaring both elicitation modes.
const meta_both = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientCapabilities\":" ++
    "{\"elicitation\":{\"form\":{},\"url\":{}}}}";

test "a handler that needs input answers with an input_required result" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\"," ++ meta_form ++ "}}",
    );

    const result = reply.get("result").?.object;
    try testing.expectEqualStrings("input_required", result.get("resultType").?.string);
    try testing.expectEqualStrings("greet:round-1", result.get("requestState").?.string);

    const requests = result.get("inputRequests").?.object;
    const request = requests.get("github_login").?.object;
    try testing.expectEqualStrings("elicitation/create", request.get("method").?.string);

    const params = request.get("params").?.object;
    try testing.expectEqualStrings("form", params.get("mode").?.string);
    try testing.expectEqualStrings(
        "Please provide your GitHub username",
        params.get("message").?.string,
    );
    try testing.expectEqualStrings(
        "string",
        params.get("requestedSchema").?.object
            .get("properties").?.object.get("name").?.object.get("type").?.string,
    );

    // The server still identifies itself on this result.
    try testing.expect(result.get("_meta").?.object.get(types.meta_key.server_info) != null);
}

test "a retry carrying the answer completes the request" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\",\"requestState\":\"greet:round-1\"," ++
            "\"inputResponses\":{\"github_login\":{\"action\":\"accept\"," ++
            "\"content\":{\"name\":\"octocat\"}}}," ++ meta_form ++ "}}",
    );

    const result = reply.get("result").?.object;
    try testing.expectEqualStrings("complete", result.get("resultType").?.string);
    try testing.expectEqualStrings(
        "hello octocat",
        result.get("content").?.array.items[0].object.get("text").?.string,
    );
}

test "a declined answer is handled by the tool, not by the protocol" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\"," ++
            "\"inputResponses\":{\"github_login\":{\"action\":\"decline\"}}," ++
            meta_form ++ "}}",
    );

    // A user who declined is not a protocol failure: the tool reports it as content
    // so the model can respond to it.
    const result = reply.get("result").?.object;
    try testing.expect(reply.get("error") == null);
    try testing.expectEqual(true, result.get("isError").?.bool);
}

test "a client that cannot elicit is told what was required" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const outcome = try fixture.sendOutcome(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"greet_github_user",
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqual(
        jsonrpc.error_code.missing_required_client_capability,
        outcome.reply.error_code.?,
    );
    // The transport spec requires 400 for this.
    try testing.expectEqual(@as(u16, 400), outcome.reply.httpStatus());

    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.allocator(),
        outcome.reply.bytes,
        .{},
    );
    const data = parsed.object.get("error").?.object.get("data").?.object;
    // Naming what is missing is what lets the client fix it rather than guess.
    try testing.expect(
        data.get("requiredCapabilities").?.object.get("elicitation") != null,
    );
}

test "a form-only client is not sent a url elicitation" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    // A bare `elicitation: {}` means form only. Sending a URL to such a client would
    // leave the flow stuck: it cannot open it and cannot answer.
    const outcome = try fixture.sendOutcome(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"connect_account\"," ++ meta_form ++ "}}",
    );
    try testing.expectEqual(
        jsonrpc.error_code.missing_required_client_capability,
        outcome.reply.error_code.?,
    );
}

test "a client declaring url mode receives the url elicitation" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"connect_account\"," ++ meta_both ++ "}}",
    );

    const params = reply.get("result").?.object
        .get("inputRequests").?.object.get("connect").?.object.get("params").?.object;
    try testing.expectEqualStrings("url", params.get("mode").?.string);
    try testing.expectEqualStrings("https://example.com/connect", params.get("url").?.string);
    // No schema in url mode: nothing is collected through the client.
    try testing.expect(params.get("requestedSchema") == null);
}

test "a result may carry state alone, with nothing to ask" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const reply = try fixture.send(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait",
    ++ meta_json ++
        \\}}
    );
    const result = reply.get("result").?.object;
    try testing.expectEqualStrings("input_required", result.get("resultType").?.string);
    try testing.expectEqualStrings("waiting", result.get("requestState").?.string);
    // Absent, not empty: an empty map would tell the client to answer nothing.
    try testing.expect(result.get("inputRequests") == null);

    const retried = try fixture.send(
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wait",
        \\ "requestState":"waiting",
    ++ meta_json ++
        \\}}
    );
    try testing.expectEqualStrings(
        "complete",
        retried.get("result").?.object.get("resultType").?.string,
    );
}

test "a method that may not request input is refused if it tries" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    // The spec allows `input_required` on exactly three methods. A completion handler
    // asking for input would put the client in a loop it cannot exit, so this is
    // reported as a server fault rather than passed on.
    const outcome = try fixture.sendOutcome(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"completion/complete\",\"params\":{" ++
            "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"plain\"}," ++
            "\"argument\":{\"name\":\"x\",\"value\":\"\"}," ++ meta_form ++ "}}",
    );
    try testing.expectEqual(jsonrpc.error_code.internal_error, outcome.reply.error_code.?);
}

test "prompts/get and resources/read may also request input" {
    // Both are on the spec's list alongside tools/call, so the dispatcher must route
    // them the same way.
    try testing.expect(types.method.supportsInputRequired(types.method.tools_call));
    try testing.expect(types.method.supportsInputRequired(types.method.prompts_get));
    try testing.expect(types.method.supportsInputRequired(types.method.resources_read));

    // And the rest must not.
    for ([_][]const u8{
        types.method.discover,
        types.method.tools_list,
        types.method.prompts_list,
        types.method.resources_list,
        types.method.resources_templates_list,
        types.method.completion_complete,
        types.method.subscriptions_listen,
    }) |method| {
        try testing.expect(!types.method.supportsInputRequired(method));
    }
}

test "an unanswered key leaves the handler asking again" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    // The client answered a different key than the one asked. The spec's guidance is
    // to ask again rather than error, because a missing answer is not a violation.
    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\"," ++
            "\"inputResponses\":{\"something_else\":{\"action\":\"accept\"}}," ++
            meta_form ++ "}}",
    );
    try testing.expectEqualStrings(
        "input_required",
        reply.get("result").?.object.get("resultType").?.string,
    );
}

test "unexpected extra input is ignored" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\"," ++
            "\"inputResponses\":{\"github_login\":{\"action\":\"accept\"," ++
            "\"content\":{\"name\":\"octocat\",\"unexpected\":42}}," ++
            "\"stray\":{\"action\":\"cancel\"}}," ++ meta_form ++ "}}",
    );
    // The spec says to ignore what is not recognised or needed.
    try testing.expectEqualStrings(
        "hello octocat",
        reply.get("result").?.object.get("content").?.array.items[0]
            .object.get("text").?.string,
    );
}

test "an accepted answer missing its field is handled, not crashed on" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    // A client may accept and still send nothing useful. The server validates rather
    // than trusting the schema it sent to be honoured.
    const reply = try fixture.send(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\"," ++
            "\"inputResponses\":{\"github_login\":{\"action\":\"accept\",\"content\":{}}}," ++
            meta_form ++ "}}",
    );
    try testing.expectEqual(true, reply.get("result").?.object.get("isError").?.bool);
}

test "malformed input responses do not crash the dispatcher" {
    var fixture: MrtrFixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    for ([_][]const u8{
        // Not an object.
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\",\"inputResponses\":\"nope\"," ++ meta_form ++ "}}",
        // An entry that is not an object.
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\",\"inputResponses\":{\"github_login\":5}," ++
            meta_form ++ "}}",
        // An unknown action.
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\"," ++
            "\"inputResponses\":{\"github_login\":{\"action\":\"maybe\"}}," ++
            meta_form ++ "}}",
        // State of the wrong type.
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"greet_github_user\",\"requestState\":42," ++ meta_form ++ "}}",
    }) |bytes| {
        // Every one of these is treated as "no usable answer", so the handler asks
        // again. Nothing here may be fatal: it all arrives from the network.
        const outcome = try fixture.sendOutcome(bytes);
        try testing.expect(outcome == .reply);
    }
}

test "elicitation support is read from what the client declared" {
    // A bare object means form only. This is the spec's compatibility rule for clients
    // written when there was one mode; reading it as "supports url" would send them
    // URLs they cannot open.
    try testing.expectEqual(
        types.ElicitationSupport{ .form = true, .url = false },
        types.ElicitationSupport.fromCapabilities(.{ .elicitation = .{ .object = .empty } }),
    );
    // No capability at all means neither.
    try testing.expectEqual(
        types.ElicitationSupport{ .form = false, .url = false },
        types.ElicitationSupport.fromCapabilities(.{}),
    );
}

test "elicitation support distinguishes the two modes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var url_only: std.json.ObjectMap = .empty;
    try url_only.put(arena.allocator(), "url", .{ .object = .empty });

    const support = types.ElicitationSupport.fromCapabilities(.{
        .elicitation = .{ .object = url_only },
    });
    try testing.expect(!support.supports(.form));
    try testing.expect(support.supports(.url));
    try testing.expect(support.any());
}
