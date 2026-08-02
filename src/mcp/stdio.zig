//! The stdio transport: newline-delimited JSON over a pair of pipes.
//!
//! The framing is the whole protocol here — one JSON-RPC message per line, and a
//! message may not contain a raw newline. That is a stricter contract than it
//! looks, because the stream has no other structure: a single stray newline does
//! not corrupt one message, it desynchronises every message after it.
//!
//! ## stdout belongs to the protocol
//!
//! A server launched over stdio owns stdin and stdout for protocol traffic and
//! nothing else. Anything a server wants to say to its operator — startup
//! diagnostics, panics, tracing — goes to stderr. A stray `print` on stdout is the
//! single most common way to break a stdio server, and it fails in a confusing way:
//! the client reports a parse error for a message the server never meant to send.
//!
//! ## Concurrency
//!
//! The serve loop is sequential: read a message, handle it, write the reply. That
//! is a deliberate choice rather than a limitation. The transport is a single pipe
//! with no framing beyond newlines, so two handlers writing at once would interleave
//! bytes and destroy the stream; serialising writes is mandatory either way. Since
//! 2026-07-28 is stateless there is nothing to gain from overlapping requests at the
//! transport level — a server that wants concurrency runs over HTTP, where each
//! request has its own response body.
//!
//! ## No authorization
//!
//! This transport has no `Authorization` header and does not use the authorization
//! specification, which says explicitly that a stdio server SHOULD NOT. That is not a
//! gap in this implementation:
//!
//! - The client launched the process. It can pass credentials in the environment or on
//!   the command line, which is a shorter and more auditable path than an OAuth flow.
//! - There is no `Origin` and no network peer, so the attacks the authorization rules
//!   defend against are not reachable. Whoever can speak to these pipes already runs
//!   code as the same user.
//! - An access token here would have to be validated against an authorization server,
//!   which would make a local process depend on a network service to answer requests
//!   from its own parent.
//!
//! A stdio server that needs to reach a protected API upstream reads its *own*
//! credentials from the environment and uses `mcp.authorization.bearerHeader` to
//! present them. It must never forward a credential it was handed — that is the
//! confused-deputy pattern the audience restriction in `oauth` exists to prevent.

const std = @import("std");
const assert_mod = @import("assert");
const jsonrpc = @import("jsonrpc.zig");
const server_mod = @import("server.zig");
const context_mod = @import("context.zig");
const subscriptions = @import("subscriptions.zig");
const client_mod = @import("client.zig");

const assert = assert_mod.assert;

const Server = server_mod.Server;

/// The frame delimiter. Not configurable: it is what the transport specification
/// says.
pub const delimiter: u8 = '\n';

/// The largest message the transport will read, shared with the JSON-RPC layer so
/// that a message which would be rejected as too large is not first accumulated in
/// full.
pub const message_size_max = jsonrpc.message_size_max;

pub const ReadError = error{
    /// The underlying stream failed. The reader holds the specific cause.
    ReadFailed,
    /// A line exceeded `message_size_max` before a delimiter appeared.
    MessageTooLarge,
    OutOfMemory,
};

/// Reads one message, or returns null at end of stream.
///
/// The returned slice is allocated in `arena` rather than borrowed from the
/// reader's buffer. That costs one copy per message and buys a guarantee worth far
/// more: `std.json` may leave parsed strings pointing into the input, so a borrowed
/// line would leave a decoded request aliasing a buffer that the next read
/// overwrites. Owning the bytes makes the lifetime match the request's arena.
pub fn readMessage(
    reader: *std.Io.Reader,
    arena: std.mem.Allocator,
) ReadError!?[]const u8 {
    while (true) {
        var line: std.Io.Writer.Allocating = .init(arena);
        const length = reader.streamDelimiterLimit(
            &line.writer,
            delimiter,
            .limited(message_size_max),
        ) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            // The only sink is an arena-backed writer, so a write failure is a
            // failed allocation.
            error.WriteFailed => return error.OutOfMemory,
            error.StreamTooLong => return error.MessageTooLarge,
        };
        assert(length == line.written().len);

        // The delimiter is left in the stream, so consuming it is what distinguishes
        // "the line ended" from "the stream ended".
        const terminated = blk: {
            const byte = reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => break :blk false,
                error.ReadFailed => return error.ReadFailed,
            };
            assert(byte == delimiter);
            break :blk true;
        };

        // A peer that writes CRLF is not following the spec, but dropping the
        // carriage return is cheaper than the interoperability bug.
        const bytes = std.mem.trimEnd(u8, line.written(), "\r");
        if (bytes.len > 0) return bytes;

        // A blank line is not a message, so it gets no parse error: answering would
        // put noise on the stream and could desynchronise a peer that is counting
        // responses.
        if (!terminated) return null;
    }
}

/// Writes one message and flushes it.
///
/// Flushing per message is not negotiable on stdio. The peer is blocked reading a
/// line, so a reply sitting in a buffer is a deadlock, not a latency problem.
pub fn writeMessage(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    // There is no escape hatch in this framing: a newline inside a message would be
    // read as a boundary and split it in two. This asserts a property of our own
    // encoder — every value this SDK emits is compact JSON — rather than validating
    // untrusted input.
    assert(std.mem.indexOfScalar(u8, bytes, delimiter) == null);
    assert(bytes.len > 0);

    try writer.writeAll(bytes);
    try writer.writeByte(delimiter);
    try writer.flush();
}

pub const ServeOptions = struct {
    /// Where to report problems that cannot be reported in-band. Framing failures
    /// have no request to attach an error to, so without this they are silent.
    ///
    /// On a real stdio server this is stderr. It must never be stdout.
    diagnostics: ?*std.Io.Writer = null,
    /// Where `subscriptions/listen` streams live. Without one, the method is
    /// reported as unimplemented rather than accepted and silently ignored.
    ///
    /// On stdio every subscription shares the single output stream, which is why
    /// the spec has each message carry its subscription id.
    broker: ?*subscriptions.Broker = null,
};

pub const ServeError = error{
    /// Reading from the peer failed. Distinct from a clean end of stream, which
    /// simply ends the loop.
    ReadFailed,
    /// Writing to the peer failed, which on stdio means the pipe is gone.
    WriteFailed,
    OutOfMemory,
};

/// Delivers request-scoped notifications onto the protocol stream.
///
/// On stdio there is one stream for everything, so a notification emitted while a
/// handler runs is written before that handler's response — which is exactly the
/// order a client needs: progress updates arrive while it is still waiting.
///
/// Correlation is the client's problem and the spec's answer differs per
/// notification: `notifications/progress` carries the token the client supplied,
/// while `notifications/message` carries nothing, and is attributed to the request
/// the client is currently awaiting. That is unambiguous here precisely because the
/// loop is sequential.
const StreamSink = struct {
    writer: *std.Io.Writer,
    diagnostics: ?*std.Io.Writer,
    /// Set once the stream has failed, so a handler that keeps reporting progress
    /// does not produce one diagnostic line per update.
    broken: bool = false,
    /// Serialises every write to the stream.
    ///
    /// Request-scoped notifications come from the serve loop's own thread, but a
    /// subscription publish comes from whichever thread noticed the change. Two
    /// concurrent writers on one pipe would interleave bytes and produce messages
    /// neither of them sent. The critical section is one message and its flush.
    lock: std.atomic.Mutex = .unlocked,

    const vtable: context_mod.NotificationSink.VTable = .{ .send = send };

    fn sink(self: *StreamSink) context_mod.NotificationSink {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn send(ptr: *anyopaque, message: []const u8) void {
        const self: *StreamSink = @ptrCast(@alignCast(ptr));
        self.write(message) catch {};
    }

    /// Writes one framed message, or records that the stream is gone.
    fn write(self: *StreamSink, message: []const u8) error{WriteFailed}!void {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();

        if (self.broken) return error.WriteFailed;
        writeMessage(self.writer, message) catch {
            // A notification that cannot be delivered must not fail the request, so
            // the failure is recorded here and surfaces when the reply is written.
            self.broken = true;
            report(self.diagnostics, "failed to write to the protocol stream\n", .{});
            return error.WriteFailed;
        };
    }
};

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// A client transport over a pair of streams.
///
/// This is the counterpart to `serveStreams`: the same framing, read from the other
/// end. Keeping it stream-shaped rather than process-shaped means the same type
/// serves a spawned subprocess, a socket pair, or a server running in the same
/// process — which is what makes an in-process round trip test possible.
pub const StreamTransport = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    /// Where to report a framing problem that has no request to attach to.
    diagnostics: ?*std.Io.Writer = null,

    pub fn transport(self: *StreamTransport) client_mod.Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: client_mod.Transport.VTable = .{ .send = send, .receive = receive };

    fn send(ptr: *anyopaque, message: []const u8) client_mod.Transport.SendError!void {
        const self: *StreamTransport = @ptrCast(@alignCast(ptr));
        writeMessage(self.writer, message) catch return error.TransportFailed;
    }

    fn receive(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
    ) client_mod.Transport.ReceiveError!?[]const u8 {
        const self: *StreamTransport = @ptrCast(@alignCast(ptr));
        return readMessage(self.reader, arena) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.MessageTooLarge => error.MessageTooLarge,
            error.ReadFailed => error.TransportFailed,
        };
    }
};

/// A server launched as a subprocess, connected over its stdin and stdout.
///
/// This is how a stdio MCP server is normally used: the client owns the process
/// lifetime, writes requests to its stdin and reads replies from its stdout. The
/// child's stderr is left attached to the parent's so that a server's diagnostics
/// reach the operator instead of vanishing.
pub const ChildServer = struct {
    io: std.Io,
    child: std.process.Child,
    stdin: std.Io.File.Writer,
    stdout: std.Io.File.Reader,
    streams: StreamTransport,

    pub const SpawnError = std.process.SpawnError || error{MissingPipe};

    pub const Options = struct {
        /// Working directory for the child.
        cwd: std.process.Child.Cwd = .inherit,
        /// Environment for the child. Inherited when null.
        environ: ?*const std.process.Environ.Map = null,
        /// What to do with the child's stderr.
        ///
        /// Inheriting by default is deliberate: a stdio server's only way to report
        /// a problem is stderr, and discarding it makes a misconfigured server look
        /// like a silent one.
        stderr: std.process.SpawnOptions.StdIo = .inherit,
    };

    /// Spawns the server. `argv[0]` is resolved against the parent's PATH.
    ///
    /// Buffers are supplied by the caller so that their lifetime is visibly tied to
    /// the transport's: both must outlive every call made through it.
    pub fn spawn(
        io: std.Io,
        argv: []const []const u8,
        input_buffer: []u8,
        output_buffer: []u8,
        options: Options,
    ) SpawnError!ChildServer {
        assert(argv.len > 0);
        assert(input_buffer.len > 0);
        assert(output_buffer.len > 0);

        var child = try std.process.spawn(io, .{
            .argv = argv,
            .cwd = options.cwd,
            .environ_map = options.environ,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = options.stderr,
        });

        // A missing pipe would mean writing into nothing and waiting forever for a
        // reply, so fail here rather than at the first request.
        const child_stdin = child.stdin orelse {
            child.kill(io);
            return error.MissingPipe;
        };
        const child_stdout = child.stdout orelse {
            child.kill(io);
            return error.MissingPipe;
        };

        return .{
            .io = io,
            .child = child,
            // Pipes cannot be read or written positionally.
            .stdin = child_stdin.writerStreaming(io, output_buffer),
            .stdout = child_stdout.readerStreaming(io, input_buffer),
            .streams = undefined,
        };
    }

    /// Wires up the transport. Call once, after `spawn`, on the final location of
    /// the `ChildServer` — the transport holds pointers into it.
    pub fn transport(server: *ChildServer) client_mod.Transport {
        server.streams = .{
            .reader = &server.stdout.interface,
            .writer = &server.stdin.interface,
        };
        return server.streams.transport();
    }

    /// Closes the child's stdin and waits for it to exit.
    ///
    /// Closing stdin first is what lets a well-behaved server shut down on its own:
    /// its read loop sees end of stream and returns. Killing it outright would
    /// discard work it might be in the middle of flushing.
    pub fn shutdown(server: *ChildServer) std.process.Child.Term {
        server.stdin.interface.flush() catch {};
        if (server.child.stdin) |pipe| {
            pipe.close(server.io);
            server.child.stdin = null;
        }
        return server.child.wait(server.io) catch {
            server.child.kill(server.io);
            return .{ .unknown = 0 };
        };
    }
};

/// Serves requests over an arbitrary reader and writer until the stream ends.
///
/// Taking streams rather than reaching for the process's own handles is what makes
/// the transport testable: a test drives it over fixed buffers, and an in-process
/// client can be connected to a server without spawning anything.
pub fn serveStreams(
    gpa: std.mem.Allocator,
    server: *const Server,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: ServeOptions,
) ServeError!void {
    // One arena, reset per message: the steady-state allocation count is zero
    // because capacity is retained across requests.
    var arena_instance: std.heap.ArenaAllocator = .init(gpa);
    defer arena_instance.deinit();

    var stream_sink: StreamSink = .{ .writer = writer, .diagnostics = options.diagnostics };
    const sink = stream_sink.sink();

    // Any subscription still open when the loop ends is closed gracefully, which both
    // tells the client this was deliberate and frees the slot.
    defer if (options.broker) |broker| broker.closeAll();

    while (true) {
        defer _ = arena_instance.reset(.retain_capacity);
        const arena = arena_instance.allocator();

        const bytes = readMessage(reader, arena) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ReadFailed => return error.ReadFailed,
            error.MessageTooLarge => {
                // The stream is unusable: the oversized line was consumed up to the
                // limit, so where the next message begins is unknown. Continuing
                // would answer requests that were never sent.
                report(options.diagnostics, "message exceeded {d} bytes; closing\n", .{
                    message_size_max,
                });
                return;
            },
        } orelse return;

        // Parsed here rather than inside the dispatcher because this loop has to look
        // at the message first: a `notifications/cancelled` naming a subscription is
        // how a stdio client closes one, and the dispatcher has no subscriptions.
        const message = jsonrpc.parseLeaky(arena, bytes) catch |err| {
            const outcome = try server.parseFailureReply(arena, err);
            try stream_sink.write(outcome.reply.bytes);
            continue;
        };

        if (options.broker) |broker| {
            if (server_mod.cancelledRequestId(message)) |id| _ = broker.cancel(id);
        }

        // No cancellation token is supplied for ordinary requests, and that is honest
        // rather than lazy: a sequential loop cannot read a cancellation while a
        // handler is running, so by the time `notifications/cancelled` is parsed the
        // request it names has already been answered. Subscriptions are the exception
        // precisely because they do not occupy the loop. Concurrency, not plumbing, is
        // what would change this for requests — and it is available on the HTTP
        // transport, where each request has its own response body.
        const outcome = try server.handleMessage(.{
            .arena = arena,
            .sink = sink,
        }, message);

        switch (outcome) {
            .reply => |reply| try stream_sink.write(reply.bytes),
            .no_reply => {},
            .listen => |listen| {
                const reply = try openSubscription(server, arena, listen, options, sink);
                if (reply) |bytes_out| try stream_sink.write(bytes_out);
            },
        }
    }
}

/// Registers an accepted subscription, or produces the error to send instead.
///
/// A successful subscription has no reply: the acknowledgement notification is the
/// only immediate output, and the JSON-RPC response is reserved for the graceful
/// close that may come much later.
fn openSubscription(
    server: *const Server,
    arena: std.mem.Allocator,
    listen: server_mod.Listen,
    options: ServeOptions,
    sink: context_mod.NotificationSink,
) error{OutOfMemory}!?[]const u8 {
    const broker = options.broker orelse {
        // The dispatcher accepted the request, but this transport was not given
        // anywhere to put the stream. Reporting the method as unimplemented is the
        // truthful answer; accepting and then delivering nothing is not.
        const outcome = try server.errorReply(
            arena,
            listen.id,
            jsonrpc.error_code.method_not_found,
            "this server does not serve subscriptions",
        );
        return outcome.reply.bytes;
    };

    _ = broker.subscribe(listen, sink) catch |err| {
        const outcome = try server.errorReply(
            arena,
            listen.id,
            jsonrpc.error_code.internal_error,
            switch (err) {
                error.TooManySubscribers => "too many open subscriptions",
                error.TooManyUris => "too many subscribed resource URIs",
                error.ShuttingDown => "the server is shutting down",
                error.OutOfMemory => return error.OutOfMemory,
            },
        );
        return outcome.reply.bytes;
    };
    return null;
}

/// Serves requests on the process's stdin and stdout, with diagnostics on stderr.
pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    server: *const Server,
) ServeError!void {
    // Sized so that a typical request and reply each fit in one syscall, without
    // reserving the protocol maximum up front; larger messages still work because
    // reads accumulate into the request arena.
    var input_buffer: [64 * 1024]u8 = undefined;
    var output_buffer: [64 * 1024]u8 = undefined;
    var diagnostics_buffer: [1024]u8 = undefined;

    var stdin = std.Io.File.stdin().readerStreaming(io, &input_buffer);
    var stdout = std.Io.File.stdout().writerStreaming(io, &output_buffer);
    var stderr = std.Io.File.stderr().writerStreaming(io, &diagnostics_buffer);

    defer stderr.interface.flush() catch {};

    return serveStreams(gpa, server, &stdin.interface, &stdout.interface, .{
        .diagnostics = &stderr.interface,
    });
}

/// Best-effort diagnostics. A server that cannot report a problem must still keep
/// serving, so failures here are dropped rather than propagated.
fn report(writer: ?*std.Io.Writer, comptime fmt: []const u8, args: anytype) void {
    const out = writer orelse return;
    out.print(fmt, args) catch return;
    out.flush() catch return;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const types = @import("types.zig");
const registry_mod = @import("registry.zig");
const Context = context_mod.Context;
const Error = context_mod.Error;

fn echoTool(context: *Context, args: struct { text: []const u8 }) Error!types.CallToolResult {
    return context.textResult(args.text);
}

/// The `_meta` every well-formed request needs.
///
/// Deliberately a single-line literal: a multiline literal carries the newlines
/// between its lines, which on this transport would split one request into two.
const request_meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientCapabilities\":{}}";

/// Runs the serve loop over a fixed input and returns everything written.
fn serveFixture(input: []const u8, output: *std.Io.Writer.Allocating) !void {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("echo", echoTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "stdio-test", .version = "1" }, .{});

    var reader: std.Io.Reader = .fixed(input);
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{});
}

/// Runs the serve loop with a broker, and publishes an event once the loop is done
/// reading. Deferred publishing is what lets a sequential test observe the ordering
/// the spec cares about: acknowledgement first, notifications after.
fn subscriptionFixture(
    input: []const u8,
    output: *std.Io.Writer.Allocating,
    broker: *subscriptions.Broker,
) !void {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("echo", echoTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(
        &registry,
        .{ .name = "stdio-test", .version = "1" },
        .{ .list_changed = true },
    );

    var reader: std.Io.Reader = .fixed(input);
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{
        .broker = broker,
    });
}

/// Splits framed output into parsed messages.
fn parsedFrames(arena: std.mem.Allocator, written: []const u8) ![]std.json.Value {
    var list: std.ArrayListUnmanaged(std.json.Value) = .empty;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, written, "\n"), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
        try list.append(arena, value);
    }
    return list.items;
}

test "a stdio subscription is acknowledged and then receives notifications" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var broker: subscriptions.Broker = .init(testing.allocator, null);

    // The tool call is what triggers the publish, so the whole exchange happens inside
    // one sequential loop, exactly as a real stdio server would run it.
    try subscriptionFixture(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscriptions/listen\",\"params\":{" ++
            "\"notifications\":{\"toolsListChanged\":true}," ++ request_meta ++ "}}\n",
        &output,
        &broker,
    );

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const frames = try parsedFrames(arena.allocator(), output.written());

    // Acknowledgement, then the graceful closure written when the loop ended.
    try testing.expectEqual(@as(usize, 2), frames.len);
    try testing.expectEqualStrings(
        types.notification.subscriptions_acknowledged,
        frames[0].object.get("method").?.string,
    );
    try testing.expectEqual(
        @as(i64, 1),
        frames[0].object.get("params").?.object
            .get("_meta").?.object.get(types.meta_key.subscription_id).?.integer,
    );

    // The closure response is a JSON-RPC response, correlated by the listen id.
    try testing.expectEqual(@as(i64, 1), frames[1].object.get("id").?.integer);
    try testing.expect(frames[1].object.get("result") != null);
}

test "a stdio publish is delivered on the subscription stream" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("echo", echoTool, .{}),
    });
    defer registry.deinit();
    const server: Server = .init(
        &registry,
        .{ .name = "stdio-test", .version = "1" },
        .{ .list_changed = true },
    );

    var broker: subscriptions.Broker = .init(testing.allocator, null);
    var sink: StreamSink = .{ .writer = &output.writer, .diagnostics = null };

    const listen: server_mod.Listen = .{
        .id = .{ .number = 3 },
        .requested = .{ .toolsListChanged = true },
        .granted = .{ .toolsListChanged = true },
    };
    const subscriber = try broker.subscribe(listen, sink.sink());
    broker.publishToolsListChanged();
    broker.closeGracefully(subscriber);
    _ = server;

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const frames = try parsedFrames(arena.allocator(), output.written());

    try testing.expectEqual(@as(usize, 3), frames.len);
    try testing.expectEqualStrings(
        types.notification.subscriptions_acknowledged,
        frames[0].object.get("method").?.string,
    );
    try testing.expectEqualStrings(
        types.notification.tools_list_changed,
        frames[1].object.get("method").?.string,
    );
    try testing.expectEqual(@as(i64, 3), frames[2].object.get("id").?.integer);
}

test "a stdio client cancels a subscription with notifications/cancelled" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var broker: subscriptions.Broker = .init(testing.allocator, null);

    try subscriptionFixture(
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"subscriptions/listen\",\"params\":{" ++
            "\"notifications\":{\"toolsListChanged\":true}," ++ request_meta ++ "}}\n" ++
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"," ++
            "\"params\":{\"requestId\":4}}\n",
        &output,
        &broker,
    );

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const frames = try parsedFrames(arena.allocator(), output.written());

    // Only the acknowledgement: a client-cancelled subscription gets no closure
    // response, because the client already knows it is over.
    try testing.expectEqual(@as(usize, 1), frames.len);
    try testing.expectEqualStrings(
        types.notification.subscriptions_acknowledged,
        frames[0].object.get("method").?.string,
    );
    try testing.expectEqual(@as(usize, 0), broker.count());
}

test "without a broker, subscriptions/listen is reported as unimplemented" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    try serveFixture(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscriptions/listen\",\"params\":{" ++
            "\"notifications\":{\"toolsListChanged\":true}," ++ request_meta ++ "}}\n",
        &output,
    );

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const frames = try parsedFrames(arena.allocator(), output.written());

    try testing.expectEqual(@as(usize, 1), frames.len);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.method_not_found),
        frames[0].object.get("error").?.object.get("code").?.integer,
    );
}

test "two stdio subscriptions share the stream and stay distinguishable" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var broker: subscriptions.Broker = .init(testing.allocator, null);
    var sink: StreamSink = .{ .writer = &output.writer, .diagnostics = null };

    const tools = try broker.subscribe(.{
        .id = .{ .number = 1 },
        .requested = .{ .toolsListChanged = true },
        .granted = .{ .toolsListChanged = true },
    }, sink.sink());
    defer broker.release(tools);
    const prompts = try broker.subscribe(.{
        .id = .{ .string = "p" },
        .requested = .{ .promptsListChanged = true },
        .granted = .{ .promptsListChanged = true },
    }, sink.sink());
    defer broker.release(prompts);

    broker.publishToolsListChanged();
    broker.publishPromptsListChanged();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const frames = try parsedFrames(arena.allocator(), output.written());

    try testing.expectEqual(@as(usize, 4), frames.len);
    // This is the property stdio depends on: one channel, and the subscription id is
    // the only thing that says which stream a message belongs to.
    const third = frames[2].object.get("params").?.object.get("_meta").?.object;
    try testing.expectEqual(@as(i64, 1), third.get(types.meta_key.subscription_id).?.integer);
    const fourth = frames[3].object.get("params").?.object.get("_meta").?.object;
    try testing.expectEqualStrings("p", fourth.get(types.meta_key.subscription_id).?.string);
}

test "readMessage returns one line at a time and null at end of stream" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var reader: std.Io.Reader = .fixed("{\"a\":1}\n{\"b\":2}\n");
    try testing.expectEqualStrings(
        "{\"a\":1}",
        (try readMessage(&reader, arena.allocator())).?,
    );
    try testing.expectEqualStrings(
        "{\"b\":2}",
        (try readMessage(&reader, arena.allocator())).?,
    );
    try testing.expect(try readMessage(&reader, arena.allocator()) == null);
}

test "readMessage accepts a final message with no trailing newline" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // A peer that closes the pipe straight after writing is well-behaved enough;
    // dropping its last message would be a real bug.
    var reader: std.Io.Reader = .fixed("{\"a\":1}");
    try testing.expectEqualStrings(
        "{\"a\":1}",
        (try readMessage(&reader, arena.allocator())).?,
    );
    try testing.expect(try readMessage(&reader, arena.allocator()) == null);
}

test "readMessage skips blank lines rather than answering them" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var reader: std.Io.Reader = .fixed("\n\n{\"a\":1}\n\n\n");
    try testing.expectEqualStrings(
        "{\"a\":1}",
        (try readMessage(&reader, arena.allocator())).?,
    );
    try testing.expect(try readMessage(&reader, arena.allocator()) == null);
}

test "readMessage tolerates carriage returns" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var reader: std.Io.Reader = .fixed("{\"a\":1}\r\n");
    try testing.expectEqualStrings(
        "{\"a\":1}",
        (try readMessage(&reader, arena.allocator())).?,
    );
}

test "readMessage owns its bytes rather than borrowing the reader buffer" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const input = "{\"first\":1}\n{\"second\":2}\n";
    var reader: std.Io.Reader = .fixed(input);

    const first = (try readMessage(&reader, arena.allocator())).?;
    // Reading again must not disturb what the first call returned. On a real pipe
    // the second read overwrites the buffer the first line came from.
    _ = try readMessage(&reader, arena.allocator());
    try testing.expectEqualStrings("{\"first\":1}", first);
    try testing.expect(first.ptr != input.ptr);
}

test "readMessage rejects a line that exceeds the protocol maximum" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Build a line one byte past the limit without a delimiter in it.
    const oversized = try testing.allocator.alloc(u8, message_size_max + 1);
    defer testing.allocator.free(oversized);
    @memset(oversized, 'x');

    var reader: std.Io.Reader = .fixed(oversized);
    try testing.expectError(error.MessageTooLarge, readMessage(&reader, arena.allocator()));
}

test "writeMessage frames a message with the delimiter" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    try writeMessage(&output.writer, "{\"a\":1}");
    try writeMessage(&output.writer, "{\"b\":2}");
    try testing.expectEqualStrings("{\"a\":1}\n{\"b\":2}\n", output.written());
}

test "the serve loop answers requests and stops at end of stream" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    try serveFixture(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
            request_meta ++ "}}\n" ++
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"echo\",\"arguments\":{\"text\":\"hi\"}," ++ request_meta ++ "}}\n",
        &output,
    );

    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, output.written(), "\n"), '\n');

    const first = lines.next().?;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const list = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        first,
        .{},
    );
    try testing.expectEqual(@as(i64, 1), list.object.get("id").?.integer);
    try testing.expectEqualStrings(
        "echo",
        list.object.get("result").?.object.get("tools").?.array.items[0]
            .object.get("name").?.string,
    );

    const second = lines.next().?;
    const call = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        second,
        .{},
    );
    try testing.expectEqual(@as(i64, 2), call.object.get("id").?.integer);
    try testing.expectEqualStrings(
        "hi",
        call.object.get("result").?.object.get("content").?.array.items[0]
            .object.get("text").?.string,
    );

    try testing.expect(lines.next() == null);
}

test "the serve loop writes exactly one line per reply" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    try serveFixture(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{" ++
            request_meta ++ "}}\n",
        &output,
    );

    // The reply carries nested objects and a schema; none of it may reach the wire
    // with an embedded newline.
    const written = output.written();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, written, "\n"));
    try testing.expectEqual(delimiter, written[written.len - 1]);
}

test "the serve loop sends nothing for a notification" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    try serveFixture(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"," ++
            "\"params\":{\"requestId\":1}}\n",
        &output,
    );
    try testing.expectEqualStrings("", output.written());
}

test "the serve loop keeps going after a malformed message" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    // One bad message must not take the session down: the reply is a parse error
    // and the next request is served normally.
    try serveFixture(
        "not json\n" ++
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{" ++
            request_meta ++ "}}\n",
        &output,
    );

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, output.written(), "\n"), '\n');
    const first = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        lines.next().?,
        .{},
    );
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.parse_error),
        first.object.get("error").?.object.get("code").?.integer,
    );

    const second = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        lines.next().?,
        .{},
    );
    try testing.expect(second.object.get("result") != null);
}

test "an oversized message closes the stream instead of desynchronising" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("echo", echoTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    const oversized = try testing.allocator.alloc(u8, message_size_max + 16);
    defer testing.allocator.free(oversized);
    @memset(oversized, 'x');

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();
    var diagnostics: std.Io.Writer.Allocating = .init(testing.allocator);
    defer diagnostics.deinit();

    var reader: std.Io.Reader = .fixed(oversized);
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{
        .diagnostics = &diagnostics.writer,
    });

    // Nothing on the protocol stream: there is no id to answer, and guessing where
    // the next message starts would mean answering requests nobody sent.
    try testing.expectEqualStrings("", output.written());
    // The operator still finds out, out of band.
    try testing.expect(std.mem.indexOf(u8, diagnostics.written(), "exceeded") != null);
}

test "the serve loop handles many messages without growing its arena" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("echo", echoTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var input: std.Io.Writer.Allocating = .init(testing.allocator);
    defer input.deinit();
    for (0..256) |index| {
        // `request_meta` goes in as an argument rather than into the format string:
        // its braces are JSON, not placeholders.
        try input.writer.print(
            "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/call\",\"params\":{{" ++
                "\"name\":\"echo\",\"arguments\":{{\"text\":\"message\"}},{s}}}}}\n",
            .{ index, request_meta },
        );
    }

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var reader: std.Io.Reader = .fixed(input.written());
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{});

    // One reply per request, and the loop's arena is reset in between, so a long
    // session does not accumulate memory.
    try testing.expectEqual(@as(usize, 256), std.mem.count(u8, output.written(), "\n"));
}

// ---- Client transport -----------------------------------------------------

/// Runs a server over a recorded transcript so a real client can be driven against a
/// real server with no process or socket in between.
///
/// The client's requests are captured first, replayed through the server, and its
/// replies fed back. Not concurrent — but enough to prove the two halves of this SDK
/// agree on the wire format, which is the property most worth checking and the least
/// likely to hold by accident.
fn roundTrip(
    gpa: std.mem.Allocator,
    server: *const Server,
    requests: []const []const u8,
    replies: *std.Io.Writer.Allocating,
) !void {
    var input: std.Io.Writer.Allocating = .init(gpa);
    defer input.deinit();
    for (requests) |request| try writeMessage(&input.writer, request);

    var reader: std.Io.Reader = .fixed(input.written());
    try serveStreams(gpa, server, &reader, &replies.writer, .{});
}

/// Records what a client sends and never answers, so requests can be captured with
/// no server present.
const OutboundOnly = struct {
    gpa: std.mem.Allocator,
    sent: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *OutboundOnly) void {
        for (self.sent.items) |message| self.gpa.free(message);
        self.sent.deinit(self.gpa);
    }

    fn transport(self: *OutboundOnly) client_mod.Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: client_mod.Transport.VTable = .{ .send = send, .receive = receive };

    fn send(ptr: *anyopaque, message: []const u8) client_mod.Transport.SendError!void {
        const self: *OutboundOnly = @ptrCast(@alignCast(ptr));
        const owned = try self.gpa.dupe(u8, message);
        errdefer self.gpa.free(owned);
        try self.sent.append(self.gpa, owned);
    }

    fn receive(_: *anyopaque, _: std.mem.Allocator) client_mod.Transport.ReceiveError!?[]const u8 {
        return null;
    }
};

/// Replays recorded server replies to a client.
const ReplayTransport = struct {
    inbound: []const []const u8,
    position: usize = 0,

    fn transport(self: *ReplayTransport) client_mod.Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: client_mod.Transport.VTable = .{ .send = send, .receive = receive };

    fn send(_: *anyopaque, _: []const u8) client_mod.Transport.SendError!void {}

    fn receive(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
    ) client_mod.Transport.ReceiveError!?[]const u8 {
        const self: *ReplayTransport = @ptrCast(@alignCast(ptr));
        if (self.position == self.inbound.len) return null;
        defer self.position += 1;
        return try arena.dupe(u8, self.inbound[self.position]);
    }
};

/// Splits a transcript into its frames.
fn framesOf(
    gpa: std.mem.Allocator,
    transcript: []const u8,
) !std.ArrayListUnmanaged([]const u8) {
    var frames: std.ArrayListUnmanaged([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, transcript, "\n"), '\n');
    while (lines.next()) |line| try frames.append(gpa, line);
    return frames;
}

fn addTool(context: *Context, args: struct { a: i64, b: i64 }) Error!types.CallToolResult {
    return context.textResult(try context.print("{d}", .{args.a + args.b}));
}

fn readDoc(context: *Context, uri: []const u8) Error!types.ReadResourceResult {
    const contents = try context.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "# Doc", .mimeType = "text/markdown" } };
    return .{ .contents = contents };
}

test "a client and a server built here agree on the wire format" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("add", addTool, .{ .description = "Adds two numbers." }),
        registry_mod.ResourceDefinition{
            .uri = "file:///doc.md",
            .name = "doc.md",
            .mime_type = "text/markdown",
            .handler = readDoc,
        },
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{
        .name = "loopback",
        .version = "1.0.0",
    }, .{ .instructions = "Use add." });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Phase one: let a client encode the requests it would send.
    var outbound: OutboundOnly = .{ .gpa = testing.allocator };
    defer outbound.deinit();

    var encoder: client_mod.Client = .init(
        outbound.transport(),
        .{ .name = "loopback-client", .version = "1.0.0" },
        .{},
    );
    _ = encoder.discover(arena.allocator(), .{}) catch {};
    _ = encoder.listTools(arena.allocator(), .{}) catch {};
    var arguments: std.json.ObjectMap = .empty;
    try arguments.put(arena.allocator(), "a", .{ .integer = 20 });
    try arguments.put(arena.allocator(), "b", .{ .integer = 22 });
    _ = encoder.callTool(arena.allocator(), "add", .{ .object = arguments }, .{}) catch {};
    _ = encoder.readResource(arena.allocator(), "file:///doc.md", .{}) catch {};

    try testing.expectEqual(@as(usize, 4), outbound.sent.items.len);

    // Phase two: run them through the server.
    var replies: std.Io.Writer.Allocating = .init(testing.allocator);
    defer replies.deinit();
    try roundTrip(testing.allocator, &server, outbound.sent.items, &replies);

    // Phase three: decode the replies with a fresh client, in order.
    var inbound = try framesOf(testing.allocator, replies.written());
    defer inbound.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), inbound.items.len);

    var replayer: ReplayTransport = .{ .inbound = inbound.items };
    var decoder: client_mod.Client = .init(
        replayer.transport(),
        .{ .name = "loopback-client", .version = "1.0.0" },
        .{},
    );

    const discovered = try decoder.discover(arena.allocator(), .{});
    try testing.expectEqualStrings("2026-07-28", discovered.supportedVersions[0]);
    try testing.expectEqualStrings("Use add.", discovered.instructions.?);
    try testing.expectEqualStrings("loopback", discovered.meta.?.server_info.?.name);

    const tools = try decoder.listTools(arena.allocator(), .{});
    try testing.expectEqual(@as(usize, 1), tools.tools.len);
    try testing.expectEqualStrings("add", tools.tools[0].name);
    // The schema the server derived at comptime survives the round trip.
    try testing.expectEqualStrings(
        "integer",
        tools.tools[0].inputSchema.value.object
            .get("properties").?.object.get("a").?.object.get("type").?.string,
    );

    const called = try decoder.callTool(arena.allocator(), "add", null, .{});
    try testing.expectEqualStrings("42", called.content[0].text.text);

    const read = try decoder.readResource(arena.allocator(), "file:///doc.md", .{});
    try testing.expectEqualStrings("# Doc", read.contents[0].text.text);
    try testing.expectEqualStrings("text/markdown", read.contents[0].text.mimeType.?);
}

test "StreamTransport frames what it sends and unframes what it reads" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var reader: std.Io.Reader = .fixed("{\"a\":1}\n{\"b\":2}\n");
    var streams: StreamTransport = .{ .reader = &reader, .writer = &output.writer };
    const transport = streams.transport();

    try transport.send("{\"out\":1}");
    try testing.expectEqualStrings("{\"out\":1}\n", output.written());

    try testing.expectEqualStrings("{\"a\":1}", (try transport.receive(arena.allocator())).?);
    try testing.expectEqualStrings("{\"b\":2}", (try transport.receive(arena.allocator())).?);
    // End of stream, not an error: the peer is allowed to stop talking.
    try testing.expect(try transport.receive(arena.allocator()) == null);
}

test "a client observes the notifications a server emits while working" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("chatty", chattyTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var outbound: OutboundOnly = .{ .gpa = testing.allocator };
    defer outbound.deinit();
    var encoder: client_mod.Client = .init(
        outbound.transport(),
        .{ .name = "c", .version = "1" },
        .{},
    );
    _ = encoder.callTool(arena.allocator(), "chatty", null, .{
        .log_level = .info,
        .progress_token = .{ .string = "t" },
    }) catch {};

    var replies: std.Io.Writer.Allocating = .init(testing.allocator);
    defer replies.deinit();
    try roundTrip(testing.allocator, &server, outbound.sent.items, &replies);

    var inbound = try framesOf(testing.allocator, replies.written());
    defer inbound.deinit(testing.allocator);

    var collector: client_mod.CollectingObserver = .init(testing.allocator);
    defer collector.deinit();

    var replayer: ReplayTransport = .{ .inbound = inbound.items };
    var decoder: client_mod.Client = .init(
        replayer.transport(),
        .{ .name = "c", .version = "1" },
        .{ .observer = collector.observer() },
    );

    const result = try decoder.callTool(arena.allocator(), "chatty", null, .{});
    try testing.expectEqualStrings("done", result.content[0].text.text);

    // The server's notifications shared the stream with the response and were routed
    // to the observer rather than mistaken for it.
    try testing.expectEqual(@as(usize, 3), collector.methods.items.len);
    try testing.expectEqualStrings("notifications/progress", collector.methods.items[0]);
    try testing.expectEqualStrings("notifications/message", collector.methods.items[1]);
}

test "fuzz the serve loop against arbitrary stream contents" {
    const Fuzz = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
                registry_mod.tool("echo", echoTool, .{}),
            });
            defer registry.deinit();

            const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

            var buffer: [2048]u8 = undefined;
            const length = smith.slice(&buffer);

            var output: std.Io.Writer.Allocating = .init(testing.allocator);
            defer output.deinit();

            var reader: std.Io.Reader = .fixed(buffer[0..length]);
            serveStreams(testing.allocator, &server, &reader, &output.writer, .{}) catch return;

            // Whatever came in, what goes out must stay correctly framed.
            const written = output.written();
            if (written.len > 0) {
                try testing.expectEqual(delimiter, written[written.len - 1]);
            }
        }
    };
    try testing.fuzz(Fuzz{}, Fuzz.testOne, .{});
}

// ---- Request-scoped notifications ----------------------------------------

/// Emits progress and a log line before returning.
fn chattyTool(context: *Context, _: void) Error!types.CallToolResult {
    context.reportProgress(1, .{ .total = 2, .message = "halfway" });
    context.logPrint(.info, "nearly there", .{});
    context.reportProgress(2, .{ .total = 2 });
    return context.textResult("done");
}

test "notifications are written on the protocol stream before the response" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("chatty", chattyTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var reader: std.Io.Reader = .fixed(
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"chatty\"," ++
            "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
            "\"io.modelcontextprotocol/clientCapabilities\":{}," ++
            "\"io.modelcontextprotocol/logLevel\":\"debug\"," ++
            "\"progressToken\":\"t\"}}}\n",
    );
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{});

    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, output.written(), "\n"), '\n');

    // Ordering is the whole point: a progress update that arrives after the result
    // is useless, so the notifications must be flushed as the handler emits them.
    try testing.expect(std.mem.indexOf(u8, lines.next().?, "\"progress\":1") != null);
    try testing.expect(std.mem.indexOf(u8, lines.next().?, "\"nearly there\"") != null);
    try testing.expect(std.mem.indexOf(u8, lines.next().?, "\"progress\":2") != null);

    const response = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, response, "\"id\":9") != null);
    try testing.expect(std.mem.indexOf(u8, response, "\"result\"") != null);
    try testing.expect(lines.next() == null);
}

test "a client that opted out of notifications sees only the response" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("chatty", chattyTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var reader: std.Io.Reader = .fixed(
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\"," ++
            "\"params\":{\"name\":\"chatty\"," ++ request_meta ++ "}}\n",
    );
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{});

    // Exactly one line: the same handler is silent when nothing was opted into, so a
    // server author does not need two code paths.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, output.written(), "\n"));
    try testing.expect(std.mem.indexOf(u8, output.written(), "notifications/") == null);
}

test "every notification is its own frame" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("chatty", chattyTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    var reader: std.Io.Reader = .fixed(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"chatty\"," ++
            "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
            "\"io.modelcontextprotocol/clientCapabilities\":{},\"progressToken\":1}}}\n",
    );
    try serveStreams(testing.allocator, &server, &reader, &output.writer, .{});

    // Re-parsing each line proves the interleaving did not corrupt the framing.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, output.written(), "\n"), '\n');
    var notifications: usize = 0;
    var responses: usize = 0;
    while (lines.next()) |line| {
        switch (try jsonrpc.parseLeaky(arena.allocator(), line)) {
            .notification => notifications += 1,
            .result_response => responses += 1,
            else => return error.TestUnexpectedMessage,
        }
    }
    try testing.expectEqual(@as(usize, 2), notifications);
    try testing.expectEqual(@as(usize, 1), responses);
}
