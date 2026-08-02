//! An MCP server over Streamable HTTP.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/http-server            # binds 127.0.0.1:8787
//! ```
//!
//! Then, from another terminal:
//!
//! ```sh
//! curl -sS http://127.0.0.1:8787/mcp \
//!   -H 'Content-Type: application/json' \
//!   -H 'Accept: application/json, text/event-stream' \
//!   -H 'MCP-Protocol-Version: 2026-07-28' \
//!   -H 'Mcp-Method: tools/list' \
//!   -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
//!        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
//!        "io.modelcontextprotocol/clientCapabilities":{}}}}'
//! ```
//!
//! SECURITY: this binds loopback only and requires no authentication, which is
//! appropriate for a local example and nothing else. A server reachable from the
//! network needs an access token — see the `oauth` module and the authorization
//! specification. The `Origin` allowlist below is the DNS-rebinding defence the
//! transport specification requires, not a substitute for authentication.

const std = @import("std");
const mcp = @import("mcp");

const ExecuteSqlArgs = struct {
    region: []const u8,
    query: []const u8,

    pub const schema_docs = .{
        .region = "The region to execute the query in",
        .query = "The SQL query to execute",
    };

    /// Mirrors `region` into an `Mcp-Param-Region` header so that a gateway can route
    /// on it without parsing the body. The transport then validates that the header and
    /// the body agree — which is the whole point: a router acting on the header while
    /// the server acts on the body would be handling two different requests.
    pub const mcp_headers = .{ .region = "Region" };
};

fn executeSql(context: *mcp.Context, args: ExecuteSqlArgs) mcp.Error!mcp.types.CallToolResult {
    return context.textResult(try context.print(
        "would run in {s}: {s}",
        .{ args.region, args.query },
    ));
}

const CountArgs = struct {
    to: u8 = 5,

    pub const schema_docs = .{ .to = "How high to count, 1 to 20" };
};

/// Counts slowly, so that a streamed response has something to stream.
fn count(context: *mcp.Context, args: CountArgs) mcp.Error!mcp.types.CallToolResult {
    if (args.to == 0 or args.to > 20) return context.errorResult("to must be between 1 and 20");

    context.logPrint(.info, "counting to {d}", .{args.to});

    var report: std.Io.Writer.Allocating = .init(context.arena);
    const total: f64 = @floatFromInt(args.to);
    for (1..@as(usize, args.to) + 1) |step| {
        // On this transport a closed response stream is the cancellation signal, so
        // this actually fires when a client disconnects — unlike on stdio.
        try context.checkCancelled();

        report.writer.print("{d} ", .{step}) catch return error.OutOfMemory;
        context.reportProgress(@floatFromInt(step), .{ .total = total, .message = "counting" });
    }
    return context.textResult(std.mem.trimEnd(u8, report.written(), " "));
}

fn readReadme(context: *mcp.Context, uri: []const u8) mcp.Error!mcp.types.ReadResourceResult {
    const contents = try context.arena.alloc(mcp.types.ResourceContents, 1);
    contents[0] = .{ .text = .{
        .uri = uri,
        .text = "# HTTP example server\n\nServed over Streamable HTTP.",
        .mimeType = "text/markdown",
    } };
    return .{ .contents = contents };
}

/// What this server's handlers need, reached through `Context.user`.
///
/// Comptime-registered handlers take only a `*Context`, so the state comes in on the
/// context rather than from a container-level `var` — which would be a global with extra
/// steps, and would make two servers in one process share one broker.
const Application = struct {
    broker: *mcp.subscriptions.Broker,
};

/// Announces that the readme changed, so a subscriber has something to receive.
///
/// Publishing happens on this request's thread while subscription streams are held
/// open by others. That is the intended shape: the broker takes each subscriber's own
/// delivery lock, so one slow client cannot delay this call for the rest.
fn touchReadme(context: *mcp.Context, args: struct {}) mcp.Error!mcp.types.CallToolResult {
    _ = args;
    const application = context.userAs(*Application);
    application.broker.publishResourceUpdated("file:///readme.md");
    application.broker.publishResourcesListChanged();
    return context.textResult("announced file:///readme.md");
}

/// Reports how many subscriptions are open.
///
/// Exists so that slot release is observable over the wire: a client that disconnects
/// should free its slot, and the only way to be sure of that from outside is to ask.
fn subscriberCount(context: *mcp.Context, args: struct {}) mcp.Error!mcp.types.CallToolResult {
    _ = args;
    const application = context.userAs(*Application);
    return context.textResult(try context.print("{d}", .{application.broker.count()}));
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var registry = try mcp.Registry.initComptime(gpa, .{
        mcp.tool("execute_sql", executeSql, .{
            .title = "Execute SQL",
            .description = "Pretends to execute SQL in a region.",
        }),
        mcp.tool("count", count, .{
            .title = "Count",
            .description = "Counts up, reporting progress as it goes.",
            .annotations = .{ .readOnlyHint = true },
        }),
        mcp.tool("touch_readme", touchReadme, .{
            .title = "Touch readme",
            .description = "Announces a change to file:///readme.md to any subscriber.",
        }),
        mcp.tool("subscriber_count", subscriberCount, .{
            .title = "Subscriber count",
            .description = "How many subscription streams are open right now.",
            .annotations = .{ .readOnlyHint = true },
        }),
        mcp.registry.ResourceDefinition{
            .uri = "file:///readme.md",
            .name = "readme.md",
            .mime_type = "text/markdown",
            .handler = readReadme,
        },
    });
    defer registry.deinit();

    // Hoisted so the broker can be built before the server: the broker stamps this
    // identity onto the notifications it publishes, and the server needs a pointer to the
    // application that owns the broker. One shared constant breaks the cycle without
    // either of them holding a half-built version of the other.
    const info: mcp.types.Implementation = .{
        .name = "zig-mcp-sdk-http-example",
        .version = "0.1.0",
    };

    var broker: mcp.subscriptions.Broker = .init(gpa, info);
    defer broker.closeAll();

    var application: Application = .{ .broker = &broker };

    const server: mcp.Server = .init(&registry, info, .{
        .instructions = "Call count to watch progress notifications arrive over SSE.",
        // Handlers reach the broker through this rather than through a global.
        .user = &application,
        // Both are claims about what this server will actually deliver, which is why
        // they are not inferred: the subscription grant and the advertised capabilities
        // are both derived from them.
        .list_changed = true,
        .resource_subscribe = true,
        .cache = .{
            .discover = .{ .ttl_ms = 300_000, .scope = .public },
            .tools = .{ .ttl_ms = 300_000, .scope = .public },
        },
    });

    var state: mcp.velo_http.State = .init(gpa, &server, .{
        // The DNS-rebinding defence the spec requires. A request with no `Origin` is
        // still accepted: programmatic clients send none, and the header only exists to
        // tell us a browser page is involved.
        .allowed_origins = &.{ "http://127.0.0.1:8787", "http://localhost:8787" },
        // Streaming so that progress notifications reach the client while the handler
        // runs, and so that a disconnect is observable as cancellation.
        .stream_responses = true,
    });
    state.broker = &broker;
    // Short enough that a curl session sees keep-alives without waiting.
    state.subscription = .{ .keep_alive_ms = 5_000 };

    var app: mcp.velo_http.App = undefined;
    app.init(&state);
    try mcp.velo_http.mount(&app, "/mcp");

    // Not `app.listen`: that waits for connections to drain, and a subscription stream
    // holds one open on purpose, so Ctrl-C would never return. This entry point stops
    // the broker first.
    try mcp.velo_http.listen(&app, &state, 8787, .{});
}
