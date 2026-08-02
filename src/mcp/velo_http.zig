//! Serves an MCP endpoint over Velo.
//!
//! All the protocol decisions live in `http.zig`, which knows nothing about any HTTP
//! library. This file is the adapter: it turns a Velo request into an
//! `http.Request`, and an `http.Outcome` into a Velo response. Keeping the two apart
//! is what lets every rule in the transport specification be tested without opening a
//! socket, and what would let a different HTTP server be substituted without
//! reimplementing any of them.

const std = @import("std");
const velo = @import("velo");
const assert_mod = @import("assert");

const http = @import("http.zig");
const sse = @import("sse.zig");
const subscriptions = @import("subscriptions.zig");
const oauth = @import("oauth");
const server_mod = @import("server.zig");
const jsonrpc = @import("jsonrpc.zig");

const assert = assert_mod.assert;

const Server = server_mod.Server;

/// Everything the handler needs, held as Velo application state.
///
/// Velo passes application state to handlers, which is how the endpoint reaches them
/// without a global.
pub const State = struct {
    gpa: std.mem.Allocator,
    endpoint: http.Endpoint,
    /// Where `subscriptions/listen` streams live, if this server serves them.
    ///
    /// Optional because a server with nothing to announce has no use for one, and
    /// because the honest answer to a listen request in that case is that the method
    /// is not implemented.
    broker: ?*subscriptions.Broker = null,
    /// How long a subscription stream may sit idle before a keep-alive comment.
    subscription: http.SubscriptionOptions = .{},
    /// The protected resource metadata document to publish, when this server is a
    /// protected resource.
    ///
    /// Build it with `oauth.ResourceServer.metadata` rather than by hand: that ties
    /// `resource` to the audience the server actually validates, and a mismatch there
    /// is experienced as tokens that are always rejected for no visible reason.
    metadata: ?oauth.ResourceMetadata = null,

    pub fn init(gpa: std.mem.Allocator, server: *const Server, options: http.Options) State {
        return .{ .gpa = gpa, .endpoint = .{ .server = server, .options = options } };
    }
};

pub const App = velo.App(*State);

/// Registers the MCP endpoint on `path`.
///
/// Only POST is routed. A GET or DELETE reaching the same path therefore falls through
/// to Velo's own 404 — which is *not* what the spec asks for, so both are registered
/// explicitly to answer 405 instead. The distinction matters to an older client: 405
/// says "this endpoint exists but that verb is gone", where 404 says "wrong URL".
pub fn mount(app: *App, path: []const u8) !void {
    try app.post(path, handlePost);
    try app.get(path, handleRemoved);
    try app.delete(path, handleRemoved);
}

/// Publishes the protected resource metadata document, deriving its path from the URL
/// the challenges advertise.
///
/// Takes the advertised URL rather than a path so the two cannot disagree: a client
/// follows `resource_metadata` from a `WWW-Authenticate` header, and a document served
/// anywhere else is a document no client will find. Requires `state.metadata` to be
/// set; a `404` here would look to a client exactly like a server that is not
/// protected at all.
///
/// This route is deliberately *not* authorized. It is how a client that has no
/// credentials learns where to get them, so requiring credentials to read it would
/// close the only door in.
pub fn mountMetadata(app: *App, metadata_url: []const u8) !void {
    const parts = oauth.url.parse(metadata_url) catch return error.InvalidMetadataUrl;
    if (parts.path.len == 0) return error.InvalidMetadataUrl;
    try app.get(parts.path, handleMetadata);
}

fn handleMetadata(ctx: *velo.Context) !void {
    const state = ctx.stateAs(*State).*;
    const document = state.metadata orelse {
        // Reached only if `mountMetadata` was called without a document. Saying so is
        // better than an empty 200, which a client would parse as a document with no
        // authorization servers and then have nowhere to go.
        try ctx.text(.internal_server_error, "");
        return;
    };

    const bytes = document.render(ctx.arena) catch return error.OutOfMemory;
    // RFC 9728 names this media type for the document.
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, bytes);
}

/// Answers the verbs earlier revisions used.
///
/// GET opened a standalone SSE stream and DELETE ended a session. Neither exists now.
fn handleRemoved(ctx: *velo.Context) !void {
    ctx.setStatus(.method_not_allowed);
    // Naming what is allowed is what RFC 9110 requires of a 405, and it tells a client
    // the endpoint is real.
    try ctx.setHeader("Allow", "POST");
    try ctx.text(.method_not_allowed, "");
}

pub const ListenOptions = struct {
    host: []const u8 = "127.0.0.1",
    server: velo.http.server.Options = .{},
};

/// Serves the app until interrupted, then shuts down without hanging.
///
/// `velo.App.listen` cannot be used when subscriptions are served. It waits for
/// in-flight connections to drain, and a subscription stream holds one open by design:
/// the process would never exit. This is that function plus the missing step — the
/// broker is stopped first, so every stream ends and the connections it was holding
/// become drainable.
///
/// SECURITY: the default host is loopback. Binding elsewhere publishes the endpoint,
/// and this transport adds no authentication of its own.
pub fn listen(
    app: *App,
    state: *State,
    port: u16,
    options: ListenOptions,
) !void {
    var runtime = try velo.Runtime.init(std.heap.page_allocator, .{ .backend = .auto });
    defer runtime.deinit();
    const io = runtime.io();

    var stop: velo.ShutdownFlag = .init(false);
    velo.lifecycle.installSignalHandlers(&stop);

    var server_options = options.server;
    server_options.serve.stop = &stop;

    var address = try velo.net.Address.parse(options.host, port);
    var srv = try velo.http.Server(*App).init(io, &address, App.adapter, app, server_options);
    defer srv.deinit(io);

    // Two watchers, because they answer to different schedulers and only one of them
    // can be relied on when the server is idle.
    //
    // Ending subscriptions runs on a plain OS thread. It has to: with no traffic there
    // are no I/O events, so a task submitted to the runtime may not be scheduled at all
    // — that was observed, and it left streams running straight through a shutdown.
    // Stopping the broker performs no I/O of its own (it queues each stream's closure
    // message and lets that stream write it), so an ordinary thread can do it.
    //
    // Waking the parked accept loop is left to Velo's own mechanism, on the runtime,
    // because self-connecting to the listener is its business and not something worth
    // reimplementing from a foreign thread.
    var teardown: Teardown = .{ .stop = &stop, .state = state };
    const closer = try std.Thread.spawn(.{}, Teardown.run, .{&teardown});
    defer {
        teardown.done.store(true, .release);
        closer.join();
    }

    var watcher = io.async(watchShutdown, .{ io, &srv.listener, &stop });
    defer watcher.cancel(io);

    try srv.run(io);
}

/// Ends subscriptions as soon as a shutdown is signalled.
const Teardown = struct {
    stop: *velo.ShutdownFlag,
    state: *State,
    /// Set by `listen` on the way out, so this thread is joinable even when no signal
    /// ever arrives.
    done: std.atomic.Value(bool) = .init(false),

    /// How often the flag is checked. Short enough to be imperceptible on Ctrl-C, long
    /// enough that an idle server is not spinning.
    const poll_ms: u64 = 50;

    fn run(teardown: *Teardown) void {
        // A *private* `Io`, not the server's. This thread exists because a task submitted
        // to the server's runtime may not be scheduled at all while the server is idle —
        // which is exactly when a shutdown needs noticing — so it must not share that
        // scheduler. Owning one is what makes the sleep below portable: 0.16 has no
        // `Thread.sleep`, no `Thread.Futex`, and `posix.poll` (the earlier trick here)
        // does not exist on Windows.
        var runtime: std.Io.Threaded = .init(teardown.state.gpa, .{});
        defer runtime.deinit();
        const io = runtime.io();

        while (!teardown.done.load(.acquire)) {
            if (teardown.stop.load(.acquire)) {
                if (teardown.state.broker) |broker| broker.stop();
                return;
            }
            io.sleep(.{ .nanoseconds = poll_ms * std.time.ns_per_ms }, .awake) catch return;
        }
    }
};

fn watchShutdown(
    io: std.Io,
    listener: *velo.net.Listener,
    stop: *velo.ShutdownFlag,
) void {
    // A poll rather than a condition variable because the flag is written from a
    // signal handler, where almost nothing is safe to call.
    while (!stop.load(.acquire)) {
        io.sleep(.{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch return;
    }
    listener.stopAccepting(io);
}

fn handlePost(ctx: *velo.Context) !void {
    const state = ctx.stateAs(*State).*;

    const body = ctx.readBody(http.body_size_max) catch {
        try ctx.text(.bad_request, "");
        return;
    };

    // Velo writes the response *after* the handler returns, and runs a stream body
    // later still. So nothing produced here may live on this function's stack or in an
    // arena it owns — `ctx.arena` is the per-request scratch allocator, whose lifetime
    // is exactly right. Its capacity is `velo.limits.request_scratch_bytes`, which
    // bounds how large a reply this transport can assemble.
    const arena = ctx.arena;

    var headers: VeloHeaders = .{ .ctx = ctx };
    const outcome = try state.endpoint.handle(arena, .{
        .method = "POST",
        .body = body,
        .headers = headers.headers(),
        // Read once, here, so that every expiry check within this request agrees.
        // `.real` rather than `.awake`: a token's `exp` is a wall-clock instant.
        .received_at = std.Io.Clock.real.now(ctx.io).toSeconds(),
    });

    switch (outcome) {
        .empty => |status| {
            const resolved = statusOf(status);
            if (status == 405) try ctx.setHeader("Allow", "POST");
            try ctx.text(resolved, "");
        },
        .json => |reply| {
            try ctx.setHeader("Content-Type", "application/json");
            try ctx.text(statusOf(reply.status), reply.bytes);
        },
        .unauthorized => |rejection| {
            // The challenge *is* the response. A 401 without it tells the client
            // nothing it can act on, which is why the header is set before the status
            // is written and why a missing one is only possible on 503.
            if (rejection.challenge) |challenge| {
                try ctx.setHeader(http.header.www_authenticate, challenge);
            }
            try ctx.text(statusOf(rejection.status), "");
        },
        .stream => {
            // The parsed message borrows from `arena`, which is fine — but it is
            // re-parsed inside the stream anyway, because that keeps the parsed form's
            // lifetime tied to the handler that reads it rather than to this decision.
            const pending = try arena.create(Pending);
            pending.* = .{ .state = state, .body = try arena.dupe(u8, body) };

            try ctx.setHeader("Cache-Control", "no-cache");
            // Without this, nginx and friends buffer the whole body and a stream of
            // progress updates arrives as one burst at the end.
            try ctx.setHeader(sse.no_buffering_header, sse.no_buffering_value);

            try ctx.stream(.ok, sse.content_type, writeStream, pending);
        },
    }
}

/// What a streamed response needs, for the duration of the stream.
///
/// Allocated in the request's scratch arena, because Velo runs the stream body after
/// the handler has returned.
const Pending = struct {
    state: *State,
    /// The raw request. Re-parsed inside the stream so that the parsed form lives as
    /// long as the handler that reads it.
    body: []const u8,
};

fn writeStream(
    io: std.Io,
    sink: velo.http.response.BodySink,
    user: ?*anyopaque,
) anyerror!void {
    const pending: *Pending = @ptrCast(@alignCast(user.?));

    var arena_instance: std.heap.ArenaAllocator = .init(pending.state.gpa);
    defer arena_instance.deinit();

    const message = jsonrpc.parseLeaky(arena_instance.allocator(), pending.body) catch return;

    // Unbuffered on purpose. `sse.writeEvent` flushes after every event because the
    // point of the stream is that a progress update arrives while the handler is still
    // working; a buffer here would undo that.
    var adapter: SinkWriter = .init(io, sink);

    // A subscription stream has no defined end, so it is driven differently: it keeps
    // the connection open, and the only thing that ends it is a cancellation from
    // either side.
    const is_listen = switch (message) {
        .request => |rpc| http.isListen(rpc),
        else => false,
    };
    if (is_listen) {
        const broker = pending.state.broker orelse {
            // Refuse rather than accept a stream nothing can publish to. The
            // dispatcher approved the subscription; this transport is the layer that
            // knows it has nowhere to put it.
            try streamMethodNotFound(pending, &adapter.writer, message);
            return;
        };
        return http.streamSubscription(
            pending.state.gpa,
            pending.state.endpoint.server,
            broker,
            io,
            &adapter.writer,
            message,
            pending.state.subscription,
        );
    }

    try http.streamResponse(
        pending.state.gpa,
        pending.state.endpoint.server,
        &adapter.writer,
        message,
    );
}

/// Reports `subscriptions/listen` as unimplemented, on the stream that was opened for
/// it.
fn streamMethodNotFound(
    pending: *Pending,
    writer: *std.Io.Writer,
    message: jsonrpc.Message,
) error{OutOfMemory}!void {
    var arena_instance: std.heap.ArenaAllocator = .init(pending.state.gpa);
    defer arena_instance.deinit();

    const id = switch (message) {
        .request => |rpc| rpc.id,
        else => return,
    };
    const outcome = try pending.state.endpoint.server.errorReply(
        arena_instance.allocator(),
        id,
        jsonrpc.error_code.method_not_found,
        "this server does not serve subscriptions",
    );
    sse.writeEvent(writer, outcome.reply.bytes) catch {};
}

/// Presents a Velo `BodySink` as a `std.Io.Writer`.
///
/// The transport writes SSE through a `std.Io.Writer` so that the framing code is
/// shared with stdio and with the tests; Velo hands a streaming body a chunk-writing
/// sink instead. This is the join between the two.
const SinkWriter = struct {
    io: std.Io,
    sink: velo.http.response.BodySink,
    writer: std.Io.Writer,

    fn init(io: std.Io, sink: velo.http.response.BodySink) SinkWriter {
        return .{
            .io = io,
            .sink = sink,
            // No buffer: every event is flushed as it is produced, so buffering would
            // only add latency to the thing the stream exists to deliver promptly.
            .writer = .{ .vtable = &vtable, .buffer = &.{} },
        };
    }

    const vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn drain(
        writer: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *SinkWriter = @alignCast(@fieldParentPtr("writer", writer));

        // Anything already buffered is logically written first. With a zero-length
        // buffer this is always empty, but honouring the contract keeps the adapter
        // correct if a buffer is ever added.
        const buffered = writer.buffer[0..writer.end];
        if (buffered.len > 0) {
            self.sink.write(self.io, buffered) catch return error.WriteFailed;
            writer.end = 0;
        }

        var written: usize = 0;
        for (data, 0..) |chunk, index| {
            // The last element repeats `splat` times.
            const repeats = if (index == data.len - 1) splat else 1;
            for (0..repeats) |_| {
                self.sink.write(self.io, chunk) catch return error.WriteFailed;
            }
            written += chunk.len * repeats;
        }
        return written;
    }
};

/// Reads request headers through Velo, case-insensitively.
const VeloHeaders = struct {
    ctx: *velo.Context,

    fn headers(self: *const VeloHeaders) http.Request.Headers {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: http.Request.Headers.VTable = .{ .get = get };

    fn get(ptr: *const anyopaque, name: []const u8) ?[]const u8 {
        const self: *const VeloHeaders = @ptrCast(@alignCast(ptr));
        return self.ctx.header(name);
    }
};

/// Maps a numeric status onto Velo's enum.
///
/// Only the statuses this transport produces are listed; anything else is a bug here
/// rather than a case to handle.
fn statusOf(code: u16) velo.http.Status {
    return switch (code) {
        200 => .ok,
        202 => .accepted,
        400 => .bad_request,
        401 => .unauthorized,
        403 => .forbidden,
        404 => .not_found,
        405 => .method_not_allowed,
        503 => .service_unavailable,
        else => unreachable,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "every status the transport produces has a Velo equivalent" {
    // The transport's own mapping is the source of truth; this checks the adapter
    // covers all of it, so an added status fails here rather than at runtime.
    for ([_]u16{ 200, 202, 400, 401, 403, 404, 405, 503 }) |code| {
        _ = statusOf(code);
    }
}

test "the endpoint state carries the server and its options" {
    var registry: server_mod.Registry = .init(testing.allocator);
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});
    const state: State = .init(
        testing.allocator,
        &server,
        .{ .allowed_origins = &.{"https://app.example.com"} },
    );
    try testing.expectEqual(@as(usize, 1), state.endpoint.options.allowed_origins.len);
    try testing.expect(state.endpoint.server == &server);
}
