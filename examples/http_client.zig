//! An MCP client over Streamable HTTP.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/http-server &            # binds 127.0.0.1:8787
//! ./zig-out/bin/http-client              # or pass a URL
//! ```
//!
//! What it demonstrates, in order, is the reason the client has to work this way:
//! `tools/list` comes first not for display but because that is where the
//! `x-mcp-header` annotations live — without them the `execute_sql` call below would be
//! rejected with `-32020` for a missing `Mcp-Param-Region`.

const std = @import("std");
const mcp = @import("mcp");

const default_url = "http://127.0.0.1:8787/mcp";

/// Prints the notifications that arrive on the response stream while a call runs.
const Printer = struct {
    out: *std.Io.Writer,

    fn observer(self: *Printer) mcp.client.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: mcp.client.Observer.VTable = .{ .notify = notify };

    fn notify(ptr: *anyopaque, notification: mcp.jsonrpc.Notification) void {
        const self: *Printer = @ptrCast(@alignCast(ptr));
        self.out.print("    .. {s} {f}\n", .{
            notification.method,
            std.json.fmt(notification.params orelse .null, .{}),
        }) catch return;
        self.out.flush() catch {};
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // `iterateAllocator` rather than `iterate`: the latter is a compile error on Windows,
    // where argv has to be decoded from UTF-16 into a buffer the iterator owns.
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.skip();

    var url: []const u8 = default_url;
    var listen = false;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--listen")) {
            listen = true;
        } else {
            url = argument;
        }
    }

    var out_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const out = &stdout.interface;

    var printer: Printer = .{ .out = out };

    // Learned from `tools/list` below, then consulted on every `tools/call`.
    var param_headers: mcp.http_client.ParamHeaders = .{};
    defer param_headers.deinit(gpa);

    var transport: mcp.http_client.Transport = .init(gpa, io, url, .{
        .param_headers = &param_headers,
    });
    defer transport.deinit();

    var mcp_client: mcp.Client = .init(
        transport.transport(),
        .{ .name = "mcp-zig-sdk-http-client", .version = "0.1.0" },
        .{ .observer = printer.observer() },
    );

    var arena_instance: std.heap.ArenaAllocator = .init(gpa);
    defer arena_instance.deinit();

    try out.print("connecting to {s}\n\n", .{url});

    if (listen) return subscribe(&mcp_client, &arena_instance, out);

    // ---- discover --------------------------------------------------------
    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        const result = try mcp_client.discover(arena, .{});
        try out.print("server: {s} {s}\n", .{
            result.meta.?.server_info.?.name,
            result.meta.?.server_info.?.version,
        });
        try out.print("versions: {s}\n", .{result.supportedVersions[0]});
        if (result.instructions) |text| try out.print("instructions: {s}\n", .{text});
        try out.writeAll("\n");
    }

    // ---- tools/list, which is also where header annotations come from ----
    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        const result = try mcp_client.listTools(arena, .{});
        try out.writeAll("tools:\n");
        for (result.tools) |tool| {
            try out.print("  {s}", .{tool.name});
            if (tool.description) |text| try out.print(" — {s}", .{text});
            try out.writeAll("\n");
        }

        // Learned into `gpa` because the arena holding this result is about to be reset,
        // while the mapping has to outlive every later call.
        try param_headers.learn(gpa, result.tools);
        try out.writeAll("\n");
    }

    // ---- a call whose arguments are mirrored into headers -----------------
    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        var arguments: std.json.ObjectMap = .empty;
        try arguments.put(arena, "region", .{ .string = "us-west1" });
        try arguments.put(arena, "query", .{ .string = "SELECT 1" });

        try out.writeAll("calling execute_sql (region is mirrored into Mcp-Param-Region):\n");
        const result = try mcp_client.callTool(arena, "execute_sql", .{ .object = arguments }, .{});
        try printContent(out, result);
    }

    // ---- a call that streams progress while it runs -----------------------
    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        var arguments: std.json.ObjectMap = .empty;
        try arguments.put(arena, "to", .{ .integer = 4 });

        try out.writeAll("\ncalling count with progress and logging enabled:\n");
        const result = try mcp_client.callTool(arena, "count", .{ .object = arguments }, .{
            // Opt in per call: without a token the server must not send progress, and
            // without a level it must not log.
            .progress_token = .{ .string = "count-1" },
            .log_level = .info,
        });
        try printContent(out, result);
    }

    try out.flush();
}

fn printContent(out: *std.Io.Writer, result: mcp.types.CallToolResult) !void {
    for (result.content) |block| {
        switch (block) {
            .text => |text| try out.print("  {s}\n", .{text.text}),
            else => try out.writeAll("  <non-text content>\n"),
        }
    }
    if (result.isError orelse false) try out.writeAll("  (the tool reported failure)\n");
    try out.flush();
}

/// Opens a `subscriptions/listen` stream and prints what arrives on it.
///
/// This is the case the transport's streaming exists for: the request does not complete
/// until the server tears the subscription down, so a client that buffered the response
/// would print nothing and then run out of memory. `exchange` blocks here on purpose,
/// handing each notification to the observer as it arrives, and returns only when the
/// graceful-closure response comes back.
fn subscribe(
    mcp_client: *mcp.Client,
    arena_instance: *std.heap.ArenaAllocator,
    out: *std.Io.Writer,
) !void {
    const arena = arena_instance.allocator();

    var watched: std.json.Array = .init(arena);
    try watched.append(.{ .string = "file:///readme.md" });

    var filter: std.json.ObjectMap = .empty;
    try filter.put(arena, "resourcesListChanged", .{ .bool = true });
    try filter.put(arena, "resourceSubscriptions", .{ .array = watched });

    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "notifications", .{ .object = filter });

    try out.writeAll("listening; call touch_readme from another client, or Ctrl-C\n");
    try out.flush();

    const call = try mcp_client.exchange(
        arena,
        mcp.types.method.subscriptions_listen,
        .{ .value = .{ .object = params } },
        .{},
    );
    if (call.failure) |failure| {
        try out.print("subscription refused: {d} {s}\n", .{ failure.code, failure.message });
    } else {
        // Only a deliberate teardown produces this. A dropped connection would have
        // ended the loop with a transport error instead, which is the distinction the
        // spec asks a client to act on.
        try out.writeAll("the server closed the subscription gracefully\n");
    }
    try out.flush();
}
