//! Emits sample payloads for validation against `spec/schema.json`.
//!
//! Unit tests pin the exact bytes this SDK produces, but they cannot tell whether
//! those bytes satisfy the published schema — only the schema can. This program
//! writes one NDJSON record per sample:
//!
//!     {"def": "<schema $def name>", "value": <payload>}
//!
//! `tools/validate-spec.py` reads that stream and validates each `value` against
//! the corresponding `$defs` entry, so a drift between this SDK's types and the
//! specification fails a build step rather than surfacing during interop.
//!
//! Run it through `zig build spec`.

const std = @import("std");
const mcp = @import("mcp");

const types = mcp.types;
const jsonrpc = mcp.jsonrpc;
const registry = mcp.registry;

/// Arguments for the comptime-registered sample tool. The schema advertised for
/// `get_forecast` is derived from this type, so validating that descriptor
/// validates the generator's output as well as the hand-written types.
const ForecastArgs = struct {
    city: []const u8,
    days: ?u8 = null,
    units: enum { metric, imperial } = .metric,

    pub const schema_docs = .{
        .city = "The city to forecast, e.g. \"Seattle, WA\"",
        .days = "How many days ahead to forecast",
        .units = "Unit system for temperatures",
    };
};

fn forecast(context: *mcp.Context, args: ForecastArgs) mcp.Error!types.CallToolResult {
    return context.textResult(try context.print("forecast for {s}", .{args.city}));
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var buffer: [64 * 1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buffer);
    const out = &stdout.interface;

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    try emitSamples(arena.allocator(), out);
    try emitServerReplies(gpa, out);
    try emitNotifications(gpa, out);
    try emitInputRequired(gpa, out);
    try emitTransportErrors(gpa, out);
    try emitSubscriptions(gpa, out);
    try emitClientRequests(gpa, out);
    try out.flush();
}

/// Runs a real server and emits the replies it produces.
///
/// This is the strongest check in the harness: it validates whole JSON-RPC
/// envelopes straight off the dispatch path, so a mistake in how a result is
/// wrapped, how `resultType` is injected, or how cache fields are applied fails the
/// build rather than an interop session.
fn emitServerReplies(gpa: std.mem.Allocator, out: *std.Io.Writer) !void {
    var reg = try mcp.Registry.initComptime(gpa, .{
        registry.tool("get_forecast", forecast, .{
            .title = "Get forecast",
            .description = "Multi-day forecast for a city.",
            .annotations = .{ .readOnlyHint = true },
        }),
        registry.prompt("greet", greet, .{ .completion = completeWho }),
        registry.ResourceDefinition{
            .uri = "file:///readme.md",
            .name = "readme.md",
            .mime_type = "text/markdown",
            .handler = readResource,
        },
        registry.ResourceTemplateDefinition{
            .uri_template = "file:///project/{path}",
            .name = "project files",
            .handler = readResource,
        },
    });
    defer reg.deinit();

    const server: mcp.Server = .init(&reg, .{
        .name = "mcp-zig-sdk-sample",
        .version = "0.1.0",
    }, .{
        .instructions = "Call get_forecast for weather.",
        .cache = .{
            .discover = .{ .ttl_ms = 3_600_000, .scope = .public },
            .tools = .{ .ttl_ms = 60_000, .scope = .public },
            .prompts = .{ .ttl_ms = 60_000, .scope = .public },
            .resources = .{ .ttl_ms = 30_000, .scope = .private },
            .resource_templates = .{ .ttl_ms = 30_000, .scope = .private },
            .resource_read = .{ .ttl_ms = 5_000, .scope = .private },
        },
    });

    const request_meta =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        \\"io.modelcontextprotocol/clientInfo":{"name":"ExampleClient","version":"1.0.0"},
        \\"io.modelcontextprotocol/clientCapabilities":{}}
    ;

    const cases = [_]struct {
        def: []const u8,
        request: []const u8,
        /// Whether the schema definition describes the `error` member rather than
        /// the whole response.
        ///
        /// The schema is not uniform here: the classic JSON-RPC failures
        /// (`ParseError`, `InvalidParamsError`, `MethodNotFoundError`, …) are
        /// defined as `Error` objects, while the errors MCP itself added
        /// (`UnsupportedProtocolVersionError`, `HeaderMismatchError`) are defined
        /// as complete response envelopes. The sample has to match whichever shape
        /// the definition describes.
        error_object: bool = false,
    }{
        .{
            .def = "DiscoverResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":\"d1\",\"method\":\"server/discover\"," ++
                "\"params\":{" ++ request_meta ++ "}}",
        },
        .{
            .def = "ListToolsResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"," ++
                "\"params\":{" ++ request_meta ++ "}}",
        },
        .{
            .def = "CallToolResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\"," ++
                "\"params\":{\"name\":\"get_forecast\",\"arguments\":{\"city\":\"Seattle\"}," ++
                request_meta ++ "}}",
        },
        .{
            .def = "ListPromptsResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"prompts/list\"," ++
                "\"params\":{" ++ request_meta ++ "}}",
        },
        .{
            .def = "GetPromptResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"prompts/get\"," ++
                "\"params\":{\"name\":\"greet\",\"arguments\":{\"who\":\"world\"}," ++
                request_meta ++ "}}",
        },
        .{
            .def = "ListResourcesResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"resources/list\"," ++
                "\"params\":{" ++ request_meta ++ "}}",
        },
        .{
            .def = "ReadResourceResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\"," ++
                "\"params\":{\"uri\":\"file:///readme.md\"," ++ request_meta ++ "}}",
        },
        .{
            .def = "ReadResourceResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"resources/read\"," ++
                "\"params\":{\"uri\":\"file:///project/src/main.zig\"," ++ request_meta ++ "}}",
        },
        .{
            .def = "ListResourceTemplatesResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"resources/templates/list\"," ++
                "\"params\":{" ++ request_meta ++ "}}",
        },
        .{
            .def = "CompleteResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"completion/complete\"," ++
                "\"params\":{\"ref\":{\"type\":\"ref/prompt\",\"name\":\"greet\"}," ++
                "\"argument\":{\"name\":\"who\",\"value\":\"wor\"}," ++ request_meta ++ "}}",
        },
        // Error paths, which have their own definitions in the schema.
        .{
            .def = "MethodNotFoundError",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"nope\"," ++
                "\"params\":{" ++ request_meta ++ "}}",
            .error_object = true,
        },
        .{
            .def = "UnsupportedProtocolVersionError",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/list\",\"params\":{" ++
                "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"1900-01-01\"," ++
                "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
        },
        .{
            .def = "InvalidParamsError",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\"," ++
                "\"params\":{\"name\":\"missing\"," ++ request_meta ++ "}}",
            .error_object = true,
        },
        .{
            .def = "ParseError",
            .request = "{not json",
            .error_object = true,
        },
    };

    for (cases) |case| {
        // A fresh arena per request, exactly as a transport does it.
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();

        const outcome = try server.handleBytes(.{ .arena = arena.allocator() }, case.request);
        const reply = switch (outcome) {
            .reply => |reply| reply,
            .no_reply, .listen => continue,
        };

        try out.writeAll("{\"def\":");
        try std.json.Stringify.value(case.def, .{}, out);
        try out.writeAll(",\"value\":");
        if (case.error_object) {
            // Pull the `error` member back out of the envelope the server produced.
            const parsed = try std.json.parseFromSliceLeaky(
                std.json.Value,
                arena.allocator(),
                reply.bytes,
                .{},
            );
            try std.json.Stringify.value(parsed.object.get("error").?, .{}, out);
        } else {
            try out.writeAll(reply.bytes);
        }
        try out.writeAll("}\n");
    }
}

/// Emits the request-scoped notifications a handler produces.
///
/// Same reasoning as `emitServerReplies`: these envelopes are built by hand in
/// `Context.emit`, so validating the real output is what catches a wrong key or a
/// missing required field.
fn emitNotifications(gpa: std.mem.Allocator, out: *std.Io.Writer) !void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    var collector: mcp.context.CollectingSink = .init(gpa);
    defer collector.deinit();

    var context: mcp.Context = .init(arena.allocator(), .{
        .protocol_version = types.protocol_version,
        .log_level = .debug,
        .progress_token = .{ .string = "sample-token" },
    });
    context.sink = collector.sink();

    context.reportProgress(2, .{ .total = 10, .message = "fetching forecast" });
    context.log(.warning, .{ .string = "upstream is slow" }, .{ .logger = "weather" });

    const definitions = [_][]const u8{ "ProgressNotification", "LoggingMessageNotification" };
    for (collector.messages.items, definitions) |message, def| {
        try out.writeAll("{\"def\":");
        try std.json.Stringify.value(def, .{}, out);
        try out.writeAll(",\"value\":");
        try out.writeAll(message);
        try out.writeAll("}\n");
    }
}

/// Emits the request envelopes the client puts on the wire.
///
/// Nothing else validates these. Every result in this file is something the *server*
/// produced; a client's requests are assembled by `encodeRequest`, which splices `_meta`
/// into `params` by hand, and a mistake there would be invisible to a test that only
/// ever asks a real server to answer.
fn emitClientRequests(gpa: std.mem.Allocator, out: *std.Io.Writer) !void {
    var recorder: Recorder = .{ .gpa = gpa };
    defer recorder.deinit();

    var mcp_client: mcp.Client = .init(
        recorder.transport(),
        .{ .name = "mcp-zig-sdk-sample", .version = "0.1.0" },
        .{},
    );

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const scratch = arena.allocator();

    var tool_arguments: std.json.ObjectMap = .empty;
    try tool_arguments.put(scratch, "city", .{ .string = "Reykjavik" });
    var call_params: std.json.ObjectMap = .empty;
    try call_params.put(scratch, "name", .{ .string = "get_forecast" });
    try call_params.put(scratch, "arguments", .{ .object = tool_arguments });

    var read_params: std.json.ObjectMap = .empty;
    try read_params.put(scratch, "uri", .{ .string = "file:///readme.md" });

    var listen_filter: std.json.ObjectMap = .empty;
    try listen_filter.put(scratch, "toolsListChanged", .{ .bool = true });
    var listen_params: std.json.ObjectMap = .empty;
    try listen_params.put(scratch, "notifications", .{ .object = listen_filter });

    const call_params_json =
        "{\"name\":\"get_forecast\",\"arguments\":{\"city\":\"Reykjavik\"}}";

    const cases = [_]struct {
        def: []const u8,
        method: []const u8,
        params: mcp.client.Params,
        options: mcp.client.CallOptions = .{},
    }{
        .{ .def = "DiscoverRequest", .method = types.method.discover, .params = .none },
        .{ .def = "ListToolsRequest", .method = types.method.tools_list, .params = .none },
        .{
            .def = "CallToolRequest",
            .method = types.method.tools_call,
            .params = .{ .value = .{ .object = call_params } },
            // The per-call opt-ins live in `_meta`, so exercise them here too.
            .options = .{ .progress_token = .{ .string = "sample" }, .log_level = .info },
        },
        .{
            // The same request, from pre-encoded params. Splicing text into the object
            // `_meta` also lives in is the one path that can put a stray comma or a
            // duplicate brace on the wire, and the schema is what catches it.
            .def = "CallToolRequest",
            .method = types.method.tools_call,
            .params = .{ .raw = call_params_json },
        },
        .{
            .def = "ReadResourceRequest",
            .method = types.method.resources_read,
            .params = .{ .value = .{ .object = read_params } },
        },
        .{
            .def = "SubscriptionsListenRequest",
            .method = types.method.subscriptions_listen,
            .params = .{ .value = .{ .object = listen_params } },
        },
    };

    for (cases) |case| {
        recorder.clear();
        // The transport records and answers nothing, so the call fails after sending —
        // which is fine, because the sent bytes are what is under test.
        _ = mcp_client.exchange(scratch, case.method, case.params, case.options) catch {};

        try out.writeAll("{\"def\":");
        try std.json.Stringify.value(case.def, .{}, out);
        try out.writeAll(",\"value\":");
        try out.writeAll(recorder.messages.items[0]);
        try out.writeAll("}\n");
    }
}

/// A transport that records what was sent and never answers.
const Recorder = struct {
    gpa: std.mem.Allocator,
    messages: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(recorder: *Recorder) void {
        recorder.clear();
        recorder.messages.deinit(recorder.gpa);
    }

    fn clear(recorder: *Recorder) void {
        for (recorder.messages.items) |message| recorder.gpa.free(message);
        recorder.messages.clearRetainingCapacity();
    }

    fn transport(recorder: *Recorder) mcp.client.Transport {
        return .{ .ptr = recorder, .vtable = &vtable };
    }

    const vtable: mcp.client.Transport.VTable = .{ .send = send, .receive = receive };

    fn send(ptr: *anyopaque, message: []const u8) mcp.client.Transport.SendError!void {
        const recorder: *Recorder = @ptrCast(@alignCast(ptr));
        const copy = try recorder.gpa.dupe(u8, message);
        errdefer recorder.gpa.free(copy);
        try recorder.messages.append(recorder.gpa, copy);
    }

    fn receive(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
    ) mcp.client.Transport.ReceiveError!?[]const u8 {
        _ = .{ ptr, arena };
        return null;
    }
};

/// Emits every message a `subscriptions/listen` stream carries.
///
/// These come out of the broker rather than being written by hand, which is the point:
/// the acknowledgement, the notifications and the closure response all have to carry
/// `io.modelcontextprotocol/subscriptionId`, and that is injected by code rather than
/// spelled out by a caller.
fn emitSubscriptions(gpa: std.mem.Allocator, out: *std.Io.Writer) !void {
    var collector: Collector = .{ .gpa = gpa };
    defer collector.deinit();

    var broker: mcp.subscriptions.Broker = .init(gpa, .{
        .name = "mcp-zig-sdk-sample",
        .version = "0.1.0",
    });

    const subscriber = try broker.subscribe(.{
        .id = .{ .number = 1 },
        .requested = .{ .toolsListChanged = true },
        .granted = .{
            .toolsListChanged = true,
            .promptsListChanged = true,
            .resourcesListChanged = true,
            .resourceSubscriptions = &.{"file:///project/config.json"},
        },
    }, collector.sink());

    broker.publishToolsListChanged();
    broker.publishPromptsListChanged();
    broker.publishResourcesListChanged();
    broker.publishResourceUpdated("file:///project/config.json");
    broker.closeGracefully(subscriber);

    const definitions = [_][]const u8{
        "SubscriptionsAcknowledgedNotification",
        "ToolListChangedNotification",
        "PromptListChangedNotification",
        "ResourceListChangedNotification",
        "ResourceUpdatedNotification",
        "SubscriptionsListenResultResponse",
    };
    for (collector.messages.items, definitions) |message, def| {
        try out.writeAll("{\"def\":");
        try std.json.Stringify.value(def, .{}, out);
        try out.writeAll(",\"value\":");
        try out.writeAll(message);
        try out.writeAll("}\n");
    }
}

/// Keeps every message a broker delivered, in order.
const Collector = struct {
    gpa: std.mem.Allocator,
    messages: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(collector: *Collector) void {
        for (collector.messages.items) |message| collector.gpa.free(message);
        collector.messages.deinit(collector.gpa);
    }

    fn sink(collector: *Collector) mcp.NotificationSink {
        return .{ .ptr = collector, .vtable = &vtable };
    }

    const vtable: mcp.NotificationSink.VTable = .{ .send = send };

    fn send(ptr: *anyopaque, message: []const u8) void {
        const collector: *Collector = @ptrCast(@alignCast(ptr));
        const copy = collector.gpa.dupe(u8, message) catch return;
        collector.messages.append(collector.gpa, copy) catch collector.gpa.free(copy);
    }
};

/// Emits the multi-round-trip payloads a server produces.
///
/// `InputRequiredResult` and the elicitation request objects inside it are assembled
/// by hand in `Context`, so validating the real output is what catches a wrong mode
/// constant or a misplaced field.
fn emitInputRequired(gpa: std.mem.Allocator, out: *std.Io.Writer) !void {
    var reg = try mcp.Registry.initComptime(gpa, .{
        registry.tool("ask_form", askForm, .{}),
        registry.tool("ask_url", askUrl, .{}),
        registry.tool("ask_state_only", askStateOnly, .{}),
    });
    defer reg.deinit();

    const server: mcp.Server = .init(&reg, .{
        .name = "mcp-zig-sdk-sample",
        .version = "0.1.0",
    }, .{});

    const meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
        "\"io.modelcontextprotocol/clientCapabilities\":" ++
        "{\"elicitation\":{\"form\":{},\"url\":{}}}}";

    // Validated against the response definition rather than `InputRequiredResult`
    // alone: its `result` is `anyOf[InputRequiredResult, CallToolResult]`, so this
    // checks the envelope and the payload in one pass.
    const cases = [_]struct { def: []const u8, request: []const u8 }{
        .{
            .def = "CallToolResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"ask_form\"," ++ meta ++ "}}",
        },
        .{
            .def = "CallToolResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"ask_url\"," ++ meta ++ "}}",
        },
        .{
            .def = "CallToolResultResponse",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"ask_state_only\"," ++ meta ++ "}}",
        },
        .{
            .def = "MissingRequiredClientCapabilityError",
            .request = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"ask_form\",\"_meta\":{" ++
                "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
                "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
        },
    };

    for (cases) |case| {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();

        const outcome = try server.handleBytes(.{ .arena = arena.allocator() }, case.request);
        try out.writeAll("{\"def\":");
        try std.json.Stringify.value(case.def, .{}, out);
        try out.writeAll(",\"value\":");
        try out.writeAll(outcome.reply.bytes);
        try out.writeAll("}\n");
    }

    // The client's side of the exchange: the results it puts in `inputResponses`.
    {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();

        var content: std.json.ObjectMap = .empty;
        try content.put(arena.allocator(), "name", .{ .string = "octocat" });

        const results = [_]types.ElicitResult{
            .{ .action = .accept, .content = .{ .object = content } },
            .{ .action = .decline },
            .{ .action = .cancel },
            // URL mode accepts with consent only.
            .{ .action = .accept },
        };
        for (results) |result| {
            try out.writeAll("{\"def\":\"ElicitResult\",\"value\":");
            try types.stringify(out, result);
            try out.writeAll("}\n");
        }
    }
}

const ask_schema: types.Json = .{ .raw =
    \\{"type":"object","properties":{"name":{"type":"string","title":"Name"}},"required":["name"]}
};

fn askForm(context: *mcp.Context, _: void) mcp.Error!types.CallToolResult {
    try context.elicitForm("github_login", "Please provide your GitHub username", ask_schema);
    return context.needInput(.{ .state = "sample-state" });
}

fn askUrl(context: *mcp.Context, _: void) mcp.Error!types.CallToolResult {
    try context.elicitUrl(
        "connect",
        "Please provide your API key to continue.",
        "https://mcp.example.com/ui/set_api_key",
    );
    return context.needInput(.{ .state = "sample-state" });
}

fn askStateOnly(context: *mcp.Context, _: void) mcp.Error!types.CallToolResult {
    return context.needInput(.{ .state = "waiting-out-of-band" });
}

/// Emits the error bodies the HTTP transport produces.
///
/// `HeaderMismatchError` has no other way to be exercised: it is a transport-level
/// failure, produced before the dispatcher ever sees the request. Validating the real
/// body is what proves the envelope and the code are right.
fn emitTransportErrors(gpa: std.mem.Allocator, out: *std.Io.Writer) !void {
    var reg = try mcp.Registry.initComptime(gpa, .{
        registry.tool("get_forecast", forecast, .{}),
    });
    defer reg.deinit();

    const server: mcp.Server = .init(&reg, .{
        .name = "mcp-zig-sdk-sample",
        .version = "0.1.0",
    }, .{});
    const endpoint: mcp.http.Endpoint = .{
        .server = &server,
        .options = .{ .stream_responses = false },
    };

    const meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
        "\"io.modelcontextprotocol/clientCapabilities\":{}}";

    const cases = [_]struct {
        def: []const u8,
        pairs: []const [2][]const u8,
        body: []const u8,
    }{
        // A required header missing.
        .{
            .def = "HeaderMismatchError",
            .pairs = &.{.{ "MCP-Protocol-Version", "2026-07-28" }},
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
                meta ++ "}}",
        },
        // A header that disagrees with the body.
        .{
            .def = "HeaderMismatchError",
            .pairs = &.{
                .{ "MCP-Protocol-Version", "2026-07-28" },
                .{ "Mcp-Method", "tools/call" },
            },
            .body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{" ++
                meta ++ "}}",
        },
        // A version the server does not implement, declared consistently.
        .{
            .def = "UnsupportedProtocolVersionError",
            .pairs = &.{
                .{ "MCP-Protocol-Version", "2025-11-25" },
                .{ "Mcp-Method", "tools/list" },
            },
            .body = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{\"_meta\":{" ++
                "\"io.modelcontextprotocol/protocolVersion\":\"2025-11-25\"," ++
                "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
        },
    };

    for (cases) |case| {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();

        var headers: SampleHeaders = .{ .pairs = case.pairs };
        const outcome = try endpoint.handle(arena.allocator(), .{
            .method = "POST",
            .body = case.body,
            .headers = headers.headers(),
            // These samples are about transport-level rejections, which do not depend on
            // the clock; a fixed instant keeps the emitted payloads reproducible.
            .received_at = 1_800_000_000,
        });

        try out.writeAll("{\"def\":");
        try std.json.Stringify.value(case.def, .{}, out);
        try out.writeAll(",\"value\":");
        try out.writeAll(outcome.json.bytes);
        try out.writeAll("}\n");
    }
}

const SampleHeaders = struct {
    pairs: []const [2][]const u8,

    fn headers(self: *const SampleHeaders) mcp.http.Request.Headers {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: mcp.http.Request.Headers.VTable = .{ .get = get };

    fn get(ptr: *const anyopaque, name: []const u8) ?[]const u8 {
        const self: *const SampleHeaders = @ptrCast(@alignCast(ptr));
        for (self.pairs) |pair| {
            if (std.ascii.eqlIgnoreCase(pair[0], name)) return pair[1];
        }
        return null;
    }
};

fn greet(context: *mcp.Context, args: struct { who: []const u8 }) mcp.Error!types.GetPromptResult {
    const messages = try context.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{
        .role = .user,
        .content = types.ContentBlock.fromText(try context.print("Hello, {s}", .{args.who})),
    };
    return .{ .messages = messages, .description = "A greeting" };
}

fn readResource(context: *mcp.Context, uri: []const u8) mcp.Error!types.ReadResourceResult {
    const contents = try context.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "# Readme", .mimeType = "text/markdown" } };
    return .{ .contents = contents };
}

fn completeWho(
    context: *mcp.Context,
    argument_name: []const u8,
    partial: []const u8,
) mcp.Error![]const []const u8 {
    if (!std.mem.eql(u8, argument_name, "who")) return &.{};
    var matches: std.ArrayListUnmanaged([]const u8) = .empty;
    for ([_][]const u8{ "world", "worm", "alice" }) |candidate| {
        if (std.mem.startsWith(u8, candidate, partial)) {
            try matches.append(context.arena, candidate);
        }
    }
    return matches.items;
}

/// Writes one record per sample. `def` names the schema definition the payload is
/// expected to satisfy.
fn emit(writer: *std.Io.Writer, def: []const u8, value: anytype) !void {
    try writer.writeAll("{\"def\":");
    try std.json.Stringify.value(def, .{}, writer);
    try writer.writeAll(",\"value\":");
    try types.stringify(writer, value);
    try writer.writeAll("}\n");
}

fn emitSamples(arena: std.mem.Allocator, out: *std.Io.Writer) !void {
    const empty_object = try json(arena, "{}");
    const tool_schema = try json(arena,
        \\{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}
    );

    // ---- Metadata --------------------------------------------------------
    try emit(out, "Implementation", types.Implementation{
        .name = "mcp-zig-sdk",
        .version = "0.1.0",
        .title = "Zig MCP SDK",
        .websiteUrl = "https://example.invalid/mcp-zig-sdk",
        .icons = &.{.{ .src = "https://example.invalid/i.png", .mimeType = "image/png", .theme = .light }},
    });
    try emit(out, "Icon", types.Icon{ .src = "https://example.invalid/i.png", .sizes = &.{"48x48"} });
    try emit(out, "Annotations", types.Annotations{
        .audience = &.{ .user, .assistant },
        .priority = 1.0,
        .lastModified = "2025-01-12T15:00:58Z",
    });
    try emit(out, "ClientCapabilities", types.ClientCapabilities.none);
    try emit(out, "ClientCapabilities", types.ClientCapabilities{ .elicitation = empty_object });
    try emit(out, "ServerCapabilities", types.ServerCapabilities{
        .tools = empty_object,
        .prompts = empty_object,
        .resources = empty_object,
        .completions = empty_object,
    });
    try emit(out, "RequestMetaObject", types.RequestMeta{
        .client_info = .{ .name = "ExampleClient", .version = "1.0.0" },
    });
    try emit(out, "RequestMetaObject", types.RequestMeta{
        .client_info = .{ .name = "ExampleClient", .version = "1.0.0" },
        .log_level = .warning,
        .progress_token = .{ .string = "tok-1" },
    });
    try emit(out, "ResultMetaObject", types.ResultMeta{
        .server_info = .{ .name = "srv", .version = "0.1.0" },
    });

    // ---- Content ---------------------------------------------------------
    try emit(out, "TextContent", types.TextContent{ .text = "hello" });
    try emit(out, "ImageContent", types.ImageContent{ .data = "AAAA", .mimeType = "image/png" });
    try emit(out, "AudioContent", types.AudioContent{ .data = "AAAA", .mimeType = "audio/wav" });
    try emit(out, "ResourceLink", types.ResourceLink{
        .uri = "file:///project/readme.md",
        .name = "readme.md",
        .mimeType = "text/markdown",
        .size = 1024,
    });
    try emit(out, "EmbeddedResource", types.EmbeddedResource{
        .resource = .{ .text = .{ .uri = "file:///a.txt", .text = "body", .mimeType = "text/plain" } },
    });
    try emit(out, "TextResourceContents", types.TextResourceContents{
        .uri = "file:///a.txt",
        .text = "body",
    });
    try emit(out, "BlobResourceContents", types.BlobResourceContents{
        .uri = "file:///a.bin",
        .blob = "Zm9v",
    });
    for ([_]types.ContentBlock{
        .{ .text = .{ .text = "hi" } },
        .{ .image = .{ .data = "AA", .mimeType = "image/png" } },
        .{ .audio = .{ .data = "AA", .mimeType = "audio/wav" } },
        .{ .resource_link = .{ .uri = "file:///a", .name = "a" } },
        .{ .resource = .{ .resource = .{ .text = .{ .uri = "file:///a", .text = "t" } } } },
    }) |block| {
        try emit(out, "ContentBlock", block);
    }

    // ---- Descriptors -----------------------------------------------------
    try emit(out, "Tool", types.Tool{
        .name = "get_weather",
        .title = "Get weather",
        .description = "Look up the weather for a city.",
        .inputSchema = .{ .value = tool_schema },
        .annotations = .{ .title = "Get weather", .readOnlyHint = true },
    });
    // A descriptor whose schema was derived from a Zig type at compile time: this
    // is what a comptime-registered tool actually puts on the wire.
    try emit(out, "Tool", registry.tool("get_forecast", forecast, .{
        .title = "Get forecast",
        .description = "Multi-day forecast for a city.",
        .annotations = .{ .readOnlyHint = true },
    }).descriptor());

    try emit(out, "ToolAnnotations", types.ToolAnnotations{
        .title = "Get weather",
        .readOnlyHint = true,
        .destructiveHint = false,
        .idempotentHint = true,
        .openWorldHint = true,
    });
    try emit(out, "Prompt", types.Prompt{
        .name = "greet",
        .description = "Greet someone",
        .arguments = &.{.{ .name = "who", .description = "Who to greet", .required = true }},
    });
    try emit(out, "PromptArgument", types.PromptArgument{ .name = "who", .required = true });
    try emit(out, "PromptMessage", types.PromptMessage{
        .role = .user,
        .content = types.ContentBlock.fromText("hi"),
    });
    try emit(out, "Resource", types.Resource{
        .uri = "file:///project/readme.md",
        .name = "readme.md",
        .mimeType = "text/markdown",
        .size = 1024,
        .annotations = .{ .priority = 0.5 },
    });
    try emit(out, "ResourceTemplate", types.ResourceTemplate{
        .uriTemplate = "file:///project/{path}",
        .name = "project files",
        .mimeType = "text/plain",
    });

    // ---- Results ---------------------------------------------------------
    try emit(out, "DiscoverResult", types.DiscoverResult{
        .supportedVersions = &.{types.protocol_version},
        .capabilities = .{ .tools = empty_object },
        .instructions = "Call get_weather for forecasts.",
        .cache = .{ .ttl_ms = 3_600_000, .scope = .public },
        .meta = .{ .server_info = .{ .name = "srv", .version = "0.1.0" } },
    });
    try emit(out, "ListToolsResult", types.ListToolsResult{
        .tools = &.{.{ .name = "get_weather", .inputSchema = .{ .value = tool_schema } }},
        .cache = .{ .ttl_ms = 60_000, .scope = .public },
        .nextCursor = "cursor-2",
    });
    try emit(out, "ListToolsResult", types.ListToolsResult{ .tools = &.{} });
    try emit(out, "CallToolResult", types.CallToolResult{
        .content = &.{types.ContentBlock.fromText("18C and clear")},
        .structuredContent = try json(arena,
            \\{"temperatureC":18,"conditions":"clear"}
        ),
    });
    try emit(out, "CallToolResult", types.CallToolResult{
        .content = &.{types.ContentBlock.fromText("city not found")},
        .isError = true,
    });
    try emit(out, "ListPromptsResult", types.ListPromptsResult{
        .prompts = &.{.{ .name = "greet" }},
        .cache = .{ .ttl_ms = 0, .scope = .private },
    });
    try emit(out, "GetPromptResult", types.GetPromptResult{
        .description = "A greeting",
        .messages = &.{.{ .role = .user, .content = types.ContentBlock.fromText("hi") }},
    });
    try emit(out, "ListResourcesResult", types.ListResourcesResult{
        .resources = &.{.{ .uri = "file:///a", .name = "a" }},
    });
    try emit(out, "ReadResourceResult", types.ReadResourceResult{
        .contents = &.{
            .{ .text = .{ .uri = "file:///a", .text = "body" } },
            .{ .blob = .{ .uri = "file:///a.bin", .blob = "Zm9v" } },
        },
    });
    try emit(out, "ListResourceTemplatesResult", types.ListResourceTemplatesResult{
        .resourceTemplates = &.{.{ .uriTemplate = "file:///{p}", .name = "files" }},
    });
    try emit(out, "CompleteResult", types.CompleteResult{
        .completion = .{ .values = &.{ "alpha", "beta" }, .total = 2, .hasMore = false },
    });
    try emit(out, "EmptyResult", types.EmptyResult{});
    try emit(out, "InputRequiredResult", types.InputRequiredResult{
        .inputRequests = try json(arena,
            \\{"confirm":{"method":"elicitation/create","params":{
            \\ "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
            \\           "io.modelcontextprotocol/clientCapabilities":{}},
            \\ "mode":"form","message":"Proceed?",
            \\ "requestedSchema":{"type":"object","properties":{}}}}}
        ),
        .requestState = "state-token",
    });
    try emit(out, "SubscriptionsListenResult", types.SubscriptionsListenResult{
        .subscription_id = .{ .number = 7 },
        .server_info = .{ .name = "srv", .version = "0.1.0" },
    });

    // ---- Notification params --------------------------------------------
    try emit(out, "ProgressNotificationParams", types.ProgressParams{
        .progressToken = .{ .number = 3 },
        .progress = 0.5,
        .total = 1.0,
        .message = "halfway",
    });
    try emit(out, "LoggingMessageNotificationParams", types.LoggingMessageParams{
        .level = .@"error",
        .data = try json(arena,
            \\{"message":"disk full"}
        ),
        .logger = "storage",
    });
    try emit(out, "CancelledNotificationParams", types.CancelledParams{
        .requestId = .{ .number = 12 },
        .reason = "user aborted",
    });
    try emit(out, "ResourceUpdatedNotificationParams", types.ResourceUpdatedParams{
        .uri = "file:///a",
    });
    try emit(out, "SubscriptionsAcknowledgedNotificationParams", types.SubscriptionsAcknowledgedParams{
        .notifications = .{ .toolsListChanged = true },
    });

    // ---- Request params --------------------------------------------------
    const request_meta: types.RequestMeta = .{
        .client_info = .{ .name = "ExampleClient", .version = "1.0.0" },
    };
    try emit(out, "PaginatedRequestParams", types.PaginatedParams{
        .cursor = "cursor-1",
        ._meta = request_meta,
    });
    try emit(out, "CallToolRequestParams", types.CallToolParams{
        .name = "get_weather",
        .arguments = try json(arena,
            \\{"city":"Seattle"}
        ),
        ._meta = request_meta,
    });
    try emit(out, "GetPromptRequestParams", types.GetPromptParams{
        .name = "greet",
        .arguments = try json(arena,
            \\{"who":"world"}
        ),
        ._meta = request_meta,
    });
    try emit(out, "ReadResourceRequestParams", types.ReadResourceParams{
        .uri = "file:///a",
        ._meta = request_meta,
    });
    try emit(out, "CompleteRequestParams", types.CompleteParams{
        .ref = .{ .prompt = .{ .name = "greet" } },
        .argument = .{ .name = "who", .value = "wo" },
        ._meta = request_meta,
    });
    try emit(out, "CompleteRequestParams", types.CompleteParams{
        .ref = .{ .resource = .{ .uri = "file:///{p}" } },
        .argument = .{ .name = "p", .value = "re" },
        ._meta = request_meta,
    });
    try emit(out, "SubscriptionsListenRequestParams", types.SubscriptionsListenParams{
        .notifications = .{
            .toolsListChanged = true,
            .resourceSubscriptions = &.{"file:///a"},
        },
        ._meta = request_meta,
    });
    try emit(out, "SubscriptionFilter", types.SubscriptionFilter{
        .toolsListChanged = true,
        .promptsListChanged = false,
        .resourcesListChanged = true,
        .resourceSubscriptions = &.{ "file:///a", "file:///b" },
    });

    // ---- JSON-RPC envelopes ---------------------------------------------
    try emit(out, "JSONRPCRequest", jsonrpc.Request{
        .id = .{ .number = 1 },
        .method = types.method.tools_list,
        .params = try json(arena,
            \\{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
            \\           "io.modelcontextprotocol/clientCapabilities":{}}}
        ),
    });
    try emit(out, "JSONRPCRequest", jsonrpc.Request{
        .id = .{ .string = "req-1" },
        .method = types.method.discover,
    });
    try emit(out, "JSONRPCNotification", jsonrpc.Notification{
        .method = types.notification.tools_list_changed,
    });
    try emit(out, "JSONRPCResultResponse", jsonrpc.ResultResponse{
        .id = .{ .number = 1 },
        .result = try json(arena,
            \\{"resultType":"complete"}
        ),
    });
    try emit(out, "JSONRPCErrorResponse", jsonrpc.ErrorResponse{
        .id = .{ .number = 1 },
        .@"error" = .{
            .code = jsonrpc.error_code.method_not_found,
            .message = "Method not found",
        },
    });
    try emit(out, "JSONRPCErrorResponse", jsonrpc.ErrorResponse.init(
        null,
        jsonrpc.error_code.parse_error,
    ));
    try emit(out, "HeaderMismatchError", jsonrpc.ErrorResponse{
        .id = .{ .number = 1 },
        .@"error" = .{
            .code = jsonrpc.error_code.header_mismatch,
            .message = "Header mismatch: Mcp-Name does not match the request body",
        },
    });
    try emit(out, "UnsupportedProtocolVersionError", jsonrpc.ErrorResponse{
        .id = .{ .number = 1 },
        .@"error" = .{
            .code = jsonrpc.error_code.unsupported_protocol_version,
            .message = "Unsupported protocol version",
            .data = try json(arena,
                \\{"requested":"2025-11-25","supported":["2026-07-28"]}
            ),
        },
    });
    try emit(out, "MissingRequiredClientCapabilityError", jsonrpc.ErrorResponse{
        .id = .{ .number = 1 },
        .@"error" = .{
            .code = jsonrpc.error_code.missing_required_client_capability,
            .message = "Missing required client capability",
            .data = try json(arena,
                \\{"requiredCapabilities":{"elicitation":{}}}
            ),
        },
    });
}

/// Parses a JSON literal into a value owned by `arena`.
fn json(arena: std.mem.Allocator, comptime bytes: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
}
