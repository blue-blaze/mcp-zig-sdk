//! The smallest complete MCP server: one tool, over stdio.
//!
//! Everything else in `examples/` shows a feature. This one shows the shape — what a
//! server has to have and nothing it does not — and it is the code the README quotes, so
//! the snippet there cannot drift from something that compiles and runs.
//!
//! ```sh
//! zig build examples
//! echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
//!   "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
//!            "io.modelcontextprotocol/clientCapabilities":{}},
//!   "name":"greet","arguments":{"who":"Ada"}}}' | ./zig-out/bin/hello
//! ```

const std = @import("std");
const mcp = @import("mcp");

/// A handler's arguments are a plain struct. Its JSON Schema is generated from this type
/// at compile time, so the contract published to the model and the code that decodes
/// against it cannot disagree.
const GreetArgs = struct {
    who: []const u8,
    /// Optional needs `= null`, or the schema would say the field may be omitted while
    /// the decoder still demands it. The build refuses the version without it.
    greeting: ?[]const u8 = null,

    /// Zig has no comptime access to doc comments, so descriptions are declared.
    pub const schema_docs = .{
        .who = "Who to greet",
        .greeting = "Greeting to use instead of \"Hello\"",
    };
};

fn greet(context: *mcp.Context, args: GreetArgs) mcp.Error!mcp.types.CallToolResult {
    // `context.arena` is freed once the reply has been written, so nothing here is
    // released by hand and nothing can outlive the request that allocated it.
    return context.textResult(try context.print("{s}, {s}!", .{
        args.greeting orelse "Hello",
        args.who,
    }));
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();

    var registry = try mcp.Registry.initComptime(gpa, .{
        mcp.tool("greet", greet, .{ .description = "Greets somebody by name." }),
    });
    defer registry.deinit();

    const server: mcp.Server = .init(&registry, .{
        .name = "hello",
        .version = "0.1.0",
    }, .{});

    // A stdio server must keep stdout for the protocol alone, so there is no banner
    // here; `serve` wires diagnostics to stderr.
    try mcp.stdio.serve(gpa, threaded.io(), &server);
}
