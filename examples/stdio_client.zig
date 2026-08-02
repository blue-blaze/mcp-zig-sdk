//! A client that launches a stdio MCP server and talks to it.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/stdio-client ./zig-out/bin/stdio-server
//! ```
//!
//! Pass any MCP stdio server as the argument; it does not have to be the one in this
//! repository.

const std = @import("std");
const mcp = @import("mcp");

/// Prints the notifications the server sends while it works.
const Printer = struct {
    out: *std.Io.Writer,

    fn observer(printer: *Printer) mcp.client.Observer {
        return .{ .ptr = printer, .vtable = &vtable };
    }

    const vtable: mcp.client.Observer.VTable = .{ .notify = notify };

    fn notify(ptr: *anyopaque, notification: mcp.jsonrpc.Notification) void {
        const printer: *Printer = @ptrCast(@alignCast(ptr));
        const params = notification.params orelse return;

        // Switching on the method name rather than expecting a fixed set: the
        // protocol adds notifications over time, and an unknown one must not be
        // fatal.
        if (std.mem.eql(u8, notification.method, mcp.notification.progress)) {
            const object = switch (params) {
                .object => |object| object,
                else => return,
            };
            const progress = object.get("progress") orelse return;
            printer.out.print("    ..progress {f}", .{std.json.fmt(progress, .{})}) catch return;
            if (object.get("total")) |total| {
                printer.out.print(" of {f}", .{std.json.fmt(total, .{})}) catch return;
            }
            if (object.get("message")) |message| switch (message) {
                .string => |text| printer.out.print(" — {s}", .{text}) catch return,
                else => {},
            };
            printer.out.writeAll("\n") catch return;
        } else if (std.mem.eql(u8, notification.method, mcp.notification.message)) {
            const object = switch (params) {
                .object => |object| object,
                else => return,
            };
            const level = object.get("level") orelse return;
            const data = object.get("data") orelse return;
            printer.out.print("    [{f}] {f}\n", .{
                std.json.fmt(level, .{}),
                std.json.fmt(data, .{}),
            }) catch return;
        } else {
            printer.out.print("    ({s})\n", .{notification.method}) catch return;
        }
    }
};

/// Taking `std.process.Init` hands us the argument vector, a leak-checked allocator
/// and an `Io` without building them by hand.
/// Answers the server's elicitation requests.
///
/// A real client would show a form or open a browser and let the user decide. This one
/// answers from a fixed script so the example is reproducible — but it demonstrates the
/// two obligations that matter: url mode returns consent only, never data, and
/// declining is a normal answer rather than an error.
const Answerer = struct {
    out: *std.Io.Writer,
    name: []const u8,

    fn elicitor(self: *Answerer) mcp.client.Elicitor {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: mcp.client.Elicitor.VTable = .{ .elicit = elicit };

    fn elicit(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        key: []const u8,
        request: mcp.types.ElicitRequest,
    ) error{OutOfMemory}!mcp.types.ElicitResult {
        const self: *Answerer = @ptrCast(@alignCast(ptr));

        switch (request) {
            .form => |form| {
                self.out.print("    server asks ({s}): {s}\n", .{ key, form.message }) catch {};
                self.out.print("    answering with {s}\n", .{self.name}) catch {};

                var content: std.json.ObjectMap = .empty;
                try content.put(arena, "name", .{ .string = self.name });
                return .{ .action = .accept, .content = .{ .object = content } };
            },
            .url => |url| {
                // A real client MUST show the full URL and get explicit consent before
                // opening it, and MUST NOT pre-fetch it.
                self.out.print("    server asks ({s}): {s}\n", .{ key, url.message }) catch {};
                self.out.print("    would open: {s}\n", .{url.url}) catch {};
                // Consent only: nothing the user enters comes back through here.
                return .{ .action = .accept };
            },
        }
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &stdout_buffer);
    const out = &stdout.interface;
    defer out.flush() catch {};

    // `iterateAllocator` rather than `iterate`: the latter is a compile error on Windows,
    // where argv has to be decoded from UTF-16 into a buffer the iterator owns.
    var command_line = try init.minimal.args.iterateAllocator(gpa);
    defer command_line.deinit();
    _ = command_line.skip(); // our own name

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(gpa);
    while (command_line.next()) |argument| try argv.append(gpa, argument);

    if (argv.items.len == 0) {
        try out.writeAll("usage: stdio-client <server-command> [args...]\n");
        return;
    }

    // Buffers for the pipes to the child. They must outlive every call made through
    // the transport, which is why they are declared here rather than inside `spawn`.
    var input_buffer: [64 * 1024]u8 = undefined;
    var output_buffer: [64 * 1024]u8 = undefined;

    var server = try mcp.stdio.ChildServer.spawn(
        io,
        argv.items,
        &input_buffer,
        &output_buffer,
        .{},
    );
    // Closing stdin lets a well-behaved server exit on its own.
    defer _ = server.shutdown();

    var printer: Printer = .{ .out = out };
    var answerer: Answerer = .{ .out = out, .name = "Ada" };

    // Declaring both elicitation modes. A bare `{}` would mean form only, and a server
    // would then never send a URL — so a client that can open one has to say so.
    var elicitation_modes: std.json.ObjectMap = .empty;
    defer elicitation_modes.deinit(gpa);
    try elicitation_modes.put(gpa, "form", .{ .object = .empty });
    try elicitation_modes.put(gpa, "url", .{ .object = .empty });

    var client: mcp.Client = .init(server.transport(), .{
        .name = "mcp-zig-sdk-example-client",
        .version = "0.1.0",
    }, .{
        .capabilities = .{ .elicitation = .{ .object = elicitation_modes } },
        .observer = printer.observer(),
        .elicitor = answerer.elicitor(),
    });

    // One arena per exchange, released as soon as the results have been printed.
    var arena_instance: std.heap.ArenaAllocator = .init(gpa);
    defer arena_instance.deinit();

    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        const discovered = try client.discover(arena, .{});
        try out.print("server speaks:", .{});
        for (discovered.supportedVersions) |version| try out.print(" {s}", .{version});
        try out.writeAll("\n");
        if (discovered.meta) |meta| if (meta.server_info) |info| {
            try out.print("server is:     {s} {s}\n", .{ info.name, info.version });
        };
        if (discovered.instructions) |instructions| {
            try out.print("instructions:  {s}\n", .{instructions});
        }
        try out.print("tools cacheable for {d} ms ({t})\n\n", .{
            discovered.cache.ttl_ms,
            discovered.cache.scope,
        });
    }

    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        const listed = try client.listTools(arena, .{});
        try out.writeAll("tools:\n");
        for (listed.tools) |tool| {
            try out.print("  {s}", .{tool.name});
            if (tool.description) |description| try out.print(" — {s}", .{description});
            try out.writeAll("\n");
        }
        try out.writeAll("\n");
    }

    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        var arguments: std.json.ObjectMap = .empty;
        try arguments.put(arena, "city", .{ .string = "Reykjavik" });
        try arguments.put(arena, "days", .{ .integer = 3 });

        try out.writeAll("calling get_forecast with progress and debug logging:\n");
        const result = client.callTool(arena, "get_forecast", .{ .object = arguments }, .{
            .log_level = .debug,
            .progress_token = .{ .string = "forecast-1" },
        }) catch |err| switch (err) {
            // A server that does not offer this tool is not a failure of the client.
            error.RequestFailed => {
                try out.writeAll("  (this server has no get_forecast tool)\n");
                return;
            },
            else => return err,
        };

        // A tool that ran and failed is a successful call: the failure is content,
        // not a protocol error.
        if (result.isError orelse false) try out.writeAll("  tool reported failure:\n");
        for (result.content) |block| switch (block) {
            .text => |text| try out.print("  {s}\n", .{text.text}),
            else => try out.writeAll("  (non-text content)\n"),
        };
        try out.writeAll("\n");
    }

    {
        const arena = arena_instance.allocator();
        defer _ = arena_instance.reset(.retain_capacity);

        try out.writeAll("calling greet_user, which needs input first:\n");

        // `callToolInteractive` follows the multi-round-trip flow: it answers whatever
        // the server asks and retries the original request until it completes. Each
        // retry is an independent request with a new id.
        const result = client.callToolInteractive(arena, "greet_user", null, .{}) catch |err| switch (err) {
            error.RequestFailed => {
                try out.writeAll("  (this server has no greet_user tool)\n");
                return;
            },
            else => return err,
        };
        for (result.content) |block| switch (block) {
            .text => |text| try out.print("  {s}\n", .{text.text}),
            else => {},
        };
    }
}
