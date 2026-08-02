//! Scaffolding smoke check: proves that a consumer can import both modules and
//! that the build graph is wired up. Replaced by real examples as the SDK grows.

const std = @import("std");
const mcp = @import("mcp");
const oauth = @import("oauth");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var buffer: [256]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buffer);
    const out = &stdout.interface;

    try out.print("mcp protocol revision: {s}\n", .{mcp.protocol_version});
    try out.print("mcp _meta version key: {s}\n", .{mcp.meta_key.protocol_version});
    try out.print("oauth module linked:   {}\n", .{@TypeOf(oauth.assert_mod.assert) != void});
    try out.flush();
}
