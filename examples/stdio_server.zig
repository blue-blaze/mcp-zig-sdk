//! A complete MCP server over stdio.
//!
//! Run it directly and type a request, or point a client at it:
//!
//! ```sh
//! zig build examples
//! npx @modelcontextprotocol/inspector ./zig-out/bin/stdio-server
//! ```
//!
//! Everything the server exposes is declared at comptime, so the JSON schema for
//! each tool is derived from its argument type and there is no schema to keep in
//! sync by hand.

const std = @import("std");
const mcp = @import("mcp");

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const AddArgs = struct {
    a: f64,
    b: f64,

    pub const schema_docs = .{
        .a = "The first addend",
        .b = "The second addend",
    };
};

fn add(context: *mcp.Context, args: AddArgs) mcp.Error!mcp.types.CallToolResult {
    return context.textResult(try context.print("{d}", .{args.a + args.b}));
}

const DivideArgs = struct {
    numerator: f64,
    denominator: f64,
};

fn divide(context: *mcp.Context, args: DivideArgs) mcp.Error!mcp.types.CallToolResult {
    // A tool that ran and could not produce an answer reports that in its result,
    // not as a protocol error. The model sees the failure and can correct itself;
    // a JSON-RPC error would be swallowed by the client as a transport problem.
    if (args.denominator == 0) {
        return context.errorResult("cannot divide by zero");
    }
    return context.textResult(try context.print("{d}", .{args.numerator / args.denominator}));
}

const ForecastArgs = struct {
    city: []const u8,
    days: u8 = 3,
    units: enum { metric, imperial } = .metric,

    pub const schema_docs = .{
        .city = "The city to forecast for",
        .days = "How many days ahead, 1 to 7",
        .units = "Which unit system to report temperatures in",
    };
};

fn forecast(context: *mcp.Context, args: ForecastArgs) mcp.Error!mcp.types.CallToolResult {
    if (args.days == 0 or args.days > 7) {
        return context.errorResult("days must be between 1 and 7");
    }

    // Both of these are no-ops unless the client opted in — a progress token for the
    // first, a log level for the second — so there is no reason for a handler to
    // guard them.
    context.logPrint(.debug, "forecasting {d} day(s) for {s}", .{ args.days, args.city });

    // An arena-backed writer has exactly one failure mode, so `WriteFailed` here
    // means the allocator gave up.
    var report: std.Io.Writer.Allocating = .init(context.arena);
    report.writer.print("Forecast for {s}:\n", .{args.city}) catch return error.OutOfMemory;

    // Deterministic stand-in for a real weather source: this example must not need
    // the network to be useful.
    var seed = std.hash.Wyhash.hash(0, args.city);
    const total: f64 = @floatFromInt(args.days);
    for (1..@as(usize, args.days) + 1) |day| {
        // A long-running handler should stop as soon as the peer loses interest.
        // Whether it ever observes cancellation depends on the transport.
        try context.checkCancelled();

        seed = std.hash.Wyhash.hash(seed, "day");
        const celsius: i64 = @intCast(@mod(@as(i64, @intCast(seed >> 8)), 25) - 2);
        const value = switch (args.units) {
            .metric => celsius,
            .imperial => @divTrunc(celsius * 9, 5) + 32,
        };
        const unit = switch (args.units) {
            .metric => "C",
            .imperial => "F",
        };
        report.writer.print("  day {d}: {d}{s}\n", .{ day, value, unit }) catch
            return error.OutOfMemory;

        context.reportProgress(@floatFromInt(day), .{
            .total = total,
            .message = "computing daily values",
        });
    }

    return context.textResult(report.written());
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

const ReviewArgs = struct {
    language: []const u8,
    focus: ?[]const u8 = null,

    pub const schema_docs = .{
        .language = "The programming language of the code under review",
        .focus = "An optional aspect to concentrate on, such as memory safety",
    };
};

fn reviewPrompt(context: *mcp.Context, args: ReviewArgs) mcp.Error!mcp.types.GetPromptResult {
    const body = if (args.focus) |focus|
        try context.print(
            "Review the following {s} code, paying particular attention to {s}.",
            .{ args.language, focus },
        )
    else
        try context.print("Review the following {s} code.", .{args.language});

    const messages = try context.arena.alloc(mcp.types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = mcp.types.ContentBlock.fromText(body) };
    return .{ .messages = messages, .description = "Ask for a code review" };
}

/// Completions for the review prompt's arguments.
fn completeReview(
    context: *mcp.Context,
    argument_name: []const u8,
    partial: []const u8,
) mcp.Error![]const []const u8 {
    const candidates: []const []const u8 = if (std.mem.eql(u8, argument_name, "language"))
        &.{ "zig", "rust", "python", "typescript" }
    else if (std.mem.eql(u8, argument_name, "focus"))
        &.{ "memory safety", "error handling", "readability" }
    else
        &.{};

    var matches: std.ArrayListUnmanaged([]const u8) = .empty;
    for (candidates) |candidate| {
        if (std.mem.startsWith(u8, candidate, partial)) {
            try matches.append(context.arena, candidate);
        }
    }
    return matches.items;
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

const readme_body =
    \\# Example server
    \\
    \\A stdio MCP server built with mcp-zig-sdk. It exposes three tools, one
    \\prompt, and this file.
;

fn readReadme(context: *mcp.Context, uri: []const u8) mcp.Error!mcp.types.ReadResourceResult {
    const contents = try context.arena.alloc(mcp.types.ResourceContents, 1);
    contents[0] = .{ .text = .{
        .uri = uri,
        .text = readme_body,
        .mimeType = "text/markdown",
    } };
    return .{ .contents = contents };
}

/// Serves any `greeting://<name>` URI, to show a template in use.
fn readGreeting(context: *mcp.Context, uri: []const u8) mcp.Error!mcp.types.ReadResourceResult {
    const prefix = "greeting://";
    if (!std.mem.startsWith(u8, uri, prefix)) return error.NotFound;
    const name = uri[prefix.len..];

    const contents = try context.arena.alloc(mcp.types.ResourceContents, 1);
    contents[0] = .{ .text = .{
        .uri = uri,
        .text = try context.print("Hello, {s}!", .{name}),
        .mimeType = "text/plain",
    } };
    return .{ .contents = contents };
}

// ---------------------------------------------------------------------------
// Multi-round-trip: a tool that needs input before it can answer
// ---------------------------------------------------------------------------

const greeting_schema: mcp.types.Json = .{ .raw =
    \\{"type":"object","properties":{"name":{"type":"string","title":"Your name",
    \\"minLength":1}},"required":["name"]}
};

/// Greets the user by a name it has to ask for.
///
/// Two passes through the same function: the first has no answer and asks for one,
/// the second finds it and finishes. That is the whole shape of a multi-round-trip
/// handler — there is no suspended coroutine, just a function that runs twice, and
/// everything it needs to resume travels in `requestState`.
fn greetUser(context: *mcp.Context, _: struct {}) mcp.Error!mcp.types.CallToolResult {
    if (context.elicited("name")) |answer| {
        // A user who declined has answered. Treating it as a failure of the tool
        // rather than of the protocol is what lets the model say something sensible.
        if (!answer.action.accepted()) {
            return context.errorResult("no name was given, so there is nobody to greet");
        }
        const name = answer.string("name") orelse
            return context.errorResult("the response did not contain a name");
        return context.textResult(try context.print("Hello, {s}!", .{name}));
    }

    try context.elicitForm("name", "What should I call you?", greeting_schema);
    // The state is trivial here. A real server would seal it — see
    // `mcp.request_state.Sealer` — because it comes back through the client.
    return context.needInput(.{ .state = "greet:v1" });
}

// ---------------------------------------------------------------------------

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();

    var registry = try mcp.Registry.initComptime(gpa, .{
        mcp.tool("add", add, .{
            .title = "Add",
            .description = "Adds two numbers.",
            .annotations = .{ .readOnlyHint = true, .idempotentHint = true },
        }),
        mcp.tool("divide", divide, .{
            .title = "Divide",
            .description = "Divides one number by another.",
            .annotations = .{ .readOnlyHint = true, .idempotentHint = true },
        }),
        mcp.tool("get_forecast", forecast, .{
            .title = "Get forecast",
            .description = "Returns a multi-day weather forecast for a city.",
            .annotations = .{ .readOnlyHint = true },
        }),
        mcp.tool("greet_user", greetUser, .{
            .title = "Greet the user",
            .description = "Greets the user, asking for their name if it is not known.",
        }),
        mcp.prompt("review_code", reviewPrompt, .{
            .title = "Review code",
            .description = "Asks for a review of a piece of code.",
            .completion = completeReview,
        }),
        mcp.registry.ResourceDefinition{
            .uri = "file:///readme.md",
            .name = "readme.md",
            .title = "Example server readme",
            .mime_type = "text/markdown",
            .handler = readReadme,
        },
        mcp.registry.ResourceTemplateDefinition{
            .uri_template = "greeting://{name}",
            .name = "greeting",
            .title = "A greeting for any name",
            .mime_type = "text/plain",
            .handler = readGreeting,
        },
    });
    defer registry.deinit();

    const server: mcp.Server = .init(&registry, .{
        .name = "mcp-zig-sdk-example",
        .title = "mcp-zig-sdk example server",
        .version = "0.1.0",
    }, .{
        .instructions =
        \\Use add and divide for arithmetic, and get_forecast for weather.
        \\The review_code prompt drafts a code-review request.
        ,
        // Tool and prompt lists are fixed for the process lifetime, so clients may
        // cache them for a while. Advertising a TTL here saves a round trip per
        // conversation turn on clients that honour it.
        .cache = .{
            .discover = .{ .ttl_ms = 300_000, .scope = .public },
            .tools = .{ .ttl_ms = 300_000, .scope = .public },
            .prompts = .{ .ttl_ms = 300_000, .scope = .public },
            .resources = .{ .ttl_ms = 300_000, .scope = .public },
            .resource_templates = .{ .ttl_ms = 300_000, .scope = .public },
        },
    });

    // Nothing may be printed to stdout outside the protocol, so there is no
    // "listening" banner here. Diagnostics go to stderr, which `serve` wires up.
    try mcp.stdio.serve(gpa, threaded.io(), &server);
}
