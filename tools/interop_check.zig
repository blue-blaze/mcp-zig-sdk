//! Interoperability checker: this SDK's client against another implementation's server.
//!
//! Built as a tool rather than an example because its assertions are written against the
//! surface of `interop/ts-server-common.mjs` specifically — it is a test, not a
//! demonstration.
//!
//! ```sh
//! interop-check http http://127.0.0.1:8792/mcp
//! interop-check stdio node interop/ts-server-stdio.mjs
//! ```
//!
//! Exit code 0 means every check passed. Each check prints a line either way, so a
//! failure says which property of the protocol the two implementations disagree about
//! rather than just that something went wrong.

const std = @import("std");
const mcp = @import("mcp");

var passed: usize = 0;
var failed: usize = 0;
var out_writer: ?*std.Io.Writer = null;

fn check(name: []const u8, ok: bool, detail: []const u8) void {
    const out = out_writer.?;
    if (ok) passed += 1 else failed += 1;
    out.print("{s} {s}", .{ if (ok) "ok  " else "FAIL", name }) catch {};
    if (detail.len > 0) out.print(" — {s}", .{detail}) catch {};
    out.writeAll("\n") catch {};
    out.flush() catch {};
}

/// Collects the notifications a call produces, so progress and logging can be asserted
/// on rather than merely printed.
const Recorder = struct {
    progress: std.ArrayListUnmanaged(f64) = .empty,
    logs: usize = 0,
    gpa: std.mem.Allocator,

    fn observer(self: *Recorder) mcp.client.Observer {
        return .{ .ptr = self, .vtable = &.{ .notify = notify } };
    }

    fn notify(ptr: *anyopaque, notification: mcp.jsonrpc.Notification) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        if (std.mem.eql(u8, notification.method, mcp.notification.progress)) {
            const params = notification.params orelse return;
            const object = switch (params) {
                .object => |object| object,
                else => return,
            };
            const value = object.get("progress") orelse return;
            const number: f64 = switch (value) {
                .integer => |i| @floatFromInt(i),
                .float => |f| f,
                else => return,
            };
            self.progress.append(self.gpa, number) catch {};
        } else if (std.mem.eql(u8, notification.method, mcp.notification.message)) {
            self.logs += 1;
        }
    }

    fn deinit(self: *Recorder) void {
        self.progress.deinit(self.gpa);
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var stdout_buffer: [8192]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    out_writer = &stdout.interface;

    // `iterateAllocator` rather than `iterate`: the latter is a compile error on Windows.
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.skip();
    const mode = args.next() orelse return error.MissingMode;

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(gpa);
    while (args.next()) |arg| try argv.append(gpa, arg);
    if (argv.items.len == 0) return error.MissingTarget;

    if (std.mem.eql(u8, mode, "http")) {
        try runHttp(gpa, io, argv.items[0]);
    } else if (std.mem.eql(u8, mode, "stdio")) {
        try runStdio(gpa, io, argv.items);
    } else {
        return error.UnknownMode;
    }

    try out_writer.?.print("\n{d}/{d} checks passed\n", .{ passed, passed + failed });
    try out_writer.?.flush();
    if (failed != 0) std.process.exit(1);
}

fn runHttp(gpa: std.mem.Allocator, io: std.Io, url: []const u8) !void {
    // Learned from `tools/list` and then consulted by `tools/call`. The annotation only
    // exists in the tool's schema, so this ordering is the protocol's, not ours.
    var param_headers: mcp.http_client.ParamHeaders = .{};
    defer param_headers.deinit(gpa);

    var recorder: Recorder = .{ .gpa = gpa };
    defer recorder.deinit();

    var transport: mcp.http_client.Transport = .init(gpa, io, url, .{
        .param_headers = &param_headers,
    });
    defer transport.deinit();

    var client: mcp.Client = .init(transport.transport(), .{
        .name = "mcp-zig-sdk-interop",
        .version = "0.1.0",
    }, .{ .observer = recorder.observer() });

    try runChecks(gpa, &client, &recorder, &param_headers);
}

fn runStdio(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    var param_headers: mcp.http_client.ParamHeaders = .{};
    defer param_headers.deinit(gpa);

    var recorder: Recorder = .{ .gpa = gpa };
    defer recorder.deinit();

    var input_buffer: [64 * 1024]u8 = undefined;
    var output_buffer: [64 * 1024]u8 = undefined;
    var child: mcp.stdio.ChildServer = try .spawn(io, argv, &input_buffer, &output_buffer, .{});
    defer _ = child.shutdown();

    const transport = child.transport();
    var client: mcp.Client = .init(transport, .{
        .name = "mcp-zig-sdk-interop",
        .version = "0.1.0",
    }, .{ .observer = recorder.observer() });

    // `Mcp-Param-*` is an HTTP concept, so stdio skips the header-mirroring checks by
    // passing no learned mappings.
    try runChecks(gpa, &client, &recorder, null);
}

fn runChecks(
    gpa: std.mem.Allocator,
    client: *mcp.Client,
    recorder: *Recorder,
    param_headers: ?*mcp.http_client.ParamHeaders,
) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // ---- server/discover ----
    const discovered = try client.discover(arena, .{});
    var speaks = false;
    for (discovered.supportedVersions) |version| {
        if (std.mem.eql(u8, version, mcp.protocol_version)) speaks = true;
    }
    check("server/discover lists 2026-07-28", speaks, discovered.supportedVersions[0]);

    // ---- tools/list ----
    const tools = try client.listTools(arena, .{});
    var has_add = false;
    var has_echo = false;
    var has_count = false;
    for (tools.tools) |tool| {
        if (std.mem.eql(u8, tool.name, "add")) has_add = true;
        if (std.mem.eql(u8, tool.name, "echo_region")) has_echo = true;
        if (std.mem.eql(u8, tool.name, "count")) has_count = true;
    }
    check("tools/list", has_add and has_echo and has_count, try nameList(arena, tools.tools));

    // Cache hints are required on this revision, and an absent one must read as
    // no-cache rather than as permission to cache forever.
    check(
        "tools/list carries a cache hint",
        tools.cache.scope == .private or tools.cache.scope == .public,
        try std.fmt.allocPrint(arena, "ttlMs={d} scope={t}", .{ tools.cache.ttl_ms, tools.cache.scope }),
    );

    if (param_headers) |headers| {
        try headers.learn(gpa, tools.tools);
        const mappings = headers.find("echo_region");
        check(
            "x-mcp-header learned from the other SDK's schema",
            mappings.len == 1 and std.mem.eql(u8, mappings[0].header, "Region"),
            if (mappings.len == 1) mappings[0].header else "(none)",
        );
    }

    // ---- tools/call ----
    var add_args: std.json.ObjectMap = .empty;
    try add_args.put(arena, "a", .{ .integer = 17 });
    try add_args.put(arena, "b", .{ .integer = 25 });
    const sum = try client.callTool(arena, "add", .{ .object = add_args }, .{});
    check("tools/call", textOf(sum) != null and std.mem.eql(u8, textOf(sum).?, "42"), textOf(sum) orelse "(none)");

    if (param_headers != null) {
        // Our client mirrors `region` into `Mcp-Param-Region`; the TS server validates
        // the header against the body and answers -32020 on any disagreement.
        var echo_args: std.json.ObjectMap = .empty;
        try echo_args.put(arena, "region", .{ .string = "eu-west-1" });
        const echoed = try client.callTool(arena, "echo_region", .{ .object = echo_args }, .{});
        check(
            "Mcp-Param-* accepted by the other SDK",
            textOf(echoed) != null and std.mem.indexOf(u8, textOf(echoed).?, "eu-west-1") != null,
            textOf(echoed) orelse "(none)",
        );
    }

    // ---- progress and per-request logging ----
    // Both are opt-in through `_meta`, so this asserts the envelope was understood, not
    // merely that the tool ran.
    recorder.progress.clearRetainingCapacity();
    recorder.logs = 0;
    var count_args: std.json.ObjectMap = .empty;
    try count_args.put(arena, "to", .{ .integer = 3 });
    const counted = try client.callTool(arena, "count", .{ .object = count_args }, .{
        .progress_token = .{ .number = 7 },
        .log_level = .info,
    });
    check(
        "tools/call streaming result",
        textOf(counted) != null and std.mem.eql(u8, textOf(counted).?, "1 2 3"),
        textOf(counted) orelse "(none)",
    );
    check(
        "progress notifications received",
        recorder.progress.items.len == 3,
        try std.fmt.allocPrint(arena, "{d} notifications", .{recorder.progress.items.len}),
    );
    check(
        "per-request logLevel honoured",
        recorder.logs >= 1,
        try std.fmt.allocPrint(arena, "{d} log messages", .{recorder.logs}),
    );

    // ---- resources ----
    const resources = try client.listResources(arena, .{});
    var has_readme = false;
    for (resources.resources) |resource| {
        if (std.mem.eql(u8, resource.uri, "file:///ts-readme.md")) has_readme = true;
    }
    check("resources/list", has_readme, try uriList(arena, resources.resources));

    const read = try client.readResource(arena, "file:///ts-readme.md", .{});
    const body = switch (read.contents[0]) {
        .text => |text| text.text,
        .blob => "(blob)",
    };
    check("resources/read", std.mem.indexOf(u8, body, "TypeScript SDK") != null, body);

    // ---- prompts ----
    const prompts = try client.listPrompts(arena, .{});
    check(
        "prompts/list",
        prompts.prompts.len >= 1,
        if (prompts.prompts.len >= 1) prompts.prompts[0].name else "(none)",
    );

    var prompt_args: std.json.ObjectMap = .empty;
    try prompt_args.put(arena, "who", .{ .string = "Ada" });
    const prompt = try client.getPrompt(arena, "greet", .{ .object = prompt_args }, .{});
    const message = switch (prompt.messages[0].content) {
        .text => |text| text.text,
        else => "(not text)",
    };
    check("prompts/get", std.mem.indexOf(u8, message, "Ada") != null, message);
}

fn textOf(result: mcp.types.CallToolResult) ?[]const u8 {
    if (result.content.len == 0) return null;
    return switch (result.content[0]) {
        .text => |text| text.text,
        else => null,
    };
}

fn nameList(arena: std.mem.Allocator, tools: []const mcp.types.Tool) ![]const u8 {
    var allocating: std.Io.Writer.Allocating = .init(arena);
    for (tools, 0..) |tool, index| {
        if (index != 0) try allocating.writer.writeAll(", ");
        try allocating.writer.writeAll(tool.name);
    }
    return allocating.written();
}

fn uriList(arena: std.mem.Allocator, resources: []const mcp.types.Resource) ![]const u8 {
    var allocating: std.Io.Writer.Allocating = .init(arena);
    for (resources, 0..) |resource, index| {
        if (index != 0) try allocating.writer.writeAll(", ");
        try allocating.writer.writeAll(resource.uri);
    }
    return allocating.written();
}
