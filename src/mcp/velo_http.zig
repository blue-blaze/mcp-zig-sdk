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

/// The largest request body this transport accepts.
///
/// Deliberately *not* `http.body_size_max`. That is the protocol's own ceiling, 16 MiB,
/// and it is right for stdio, where the request arena grows on the heap. Here the body is
/// read into Velo's per-request scratch arena — a fixed buffer — so what this transport
/// can honour is bounded by Velo, and claiming otherwise only moves the failure later.
///
/// Passing the protocol ceiling was worse than merely optimistic. `readBody` sizes its
/// buffer from the declared `Content-Length` when there is one and from *this bound* when
/// there is not, so the number is an allocation request as well as a limit: a request
/// with no declared length asked a 128 KiB fixed arena for 16 MiB and could not
/// possibly succeed.
pub const body_size_max: usize = velo.limits.request_body_bytes_max;

comptime {
    // The body is read into the scratch arena, so a bound at or above the arena's size
    // would not be a bound at all. If Velo ever raises one without the other, this
    // fails here rather than as an out-of-memory reply under load.
    assert_mod.comptime_assert(body_size_max < velo.limits.request_scratch_bytes);
}

/// Replies that must not allocate, because the reason they are being sent is that
/// allocation failed or cannot be trusted.
///
/// Velo's response *borrows* its body rather than copying it, so a constant is enough.
/// Each is a complete JSON-RPC error object: a client reading a bare status with an empty
/// body learns nothing it can act on, and this transport's whole contract is that the
/// error is in the body.
const static_reply = struct {
    /// `id` is null because it is genuinely unknown: naming the request's id would mean
    /// parsing the body with the allocator that just refused.
    const out_of_memory =
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"the server ran out of memory handling this request"}}
    ;
    /// `parse_error`, matching what `http.Endpoint` answers an oversized body with, so
    /// the two paths do not describe the same condition differently.
    const body_too_large =
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"request body too large for this transport"}}
    ;
    const body_unreadable =
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"request body could not be read"}}
    ;
    /// Named rather than reported as a parse error, which is what an absent body would
    /// otherwise produce. Telling a client with valid JSON that its JSON is broken sends
    /// it looking in the wrong place.
    const chunked_unsupported =
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"chunked request bodies are not supported by this transport; send Content-Length"}}
    ;
};

/// Answers with a body that needs no allocation.
///
/// The Content-Type is set before the status because `text` only supplies its own when
/// none is present, and these bodies are JSON rather than the `text/plain` it assumes.
fn respondStatic(ctx: *velo.Context, status: velo.http.Status, body: []const u8) !void {
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(status, body);
}

/// Whether the request declared a body that Velo did not deliver.
///
/// Velo wires a body reader for `Content-Length` framing only, so a chunked request
/// reaches a handler with its body silently absent — indistinguishable, from the body
/// alone, from a request that legitimately sent nothing.
fn bodyWasDropped(ctx: *velo.Context) bool {
    const encoding = ctx.header("transfer-encoding") orelse return false;
    return encoding.len > 0;
}

/// Registers the MCP endpoint on `path`.
///
/// POST carries the protocol. Every other method Velo can parse is routed to a 405,
/// because a route registered for one method only means the rest fall through to Velo's
/// own 404 — and 404 is a lie about a URL that exists. The distinction is what a client
/// acts on: 405 with `Allow: POST` says "this endpoint is real, that verb is not", where
/// 404 sends it looking for a different address.
///
/// GET and DELETE are the ones that matter in practice — earlier revisions used them for
/// a standalone SSE stream and for ending a session — but PUT, PATCH, HEAD, OPTIONS,
/// TRACE and CONNECT were reaching the 404 for no better reason than that nobody had
/// listed them.
///
/// A server that mounts this and serves subscriptions must also set
/// `timeouts.write_ms = 0`, which is what `listen` does for you and what `WriteBound`
/// explains. Velo's default caps one response write at 30 seconds, and a subscription
/// stream is one response, so leaving it in place ends every subscription after 30
/// seconds — visible to the client as a stream that closes with no reply.
pub fn mount(app: *App, path: []const u8) !void {
    try app.post(path, handlePost);
    // Derived from the method enum rather than listed, so a method Velo learns to parse
    // cannot quietly go back to answering 404 here.
    inline for (comptime std.enums.values(velo.http.Method)) |method| {
        if (method == .post) continue;
        try app.route(method, path, handleRemoved, .{});
    }
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

/// Answers every method the endpoint does not implement.
///
/// GET opened a standalone SSE stream and DELETE ended a session in earlier revisions;
/// neither exists now. The rest were never part of the protocol.
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
    write_bound: WriteBound = .lift_for_subscriptions,
};

/// What to do about Velo's bound on how long writing one response may take.
///
/// Velo bounds a response write (`Timeouts.write_ms`, 30 seconds by default) so that a
/// peer which stops reading cannot pin a connection — the mirror image of a slow
/// request, and the same denial of service. That bound is armed once around the whole
/// response, which is right for a response that ends. A `subscriptions/listen` stream
/// is one response that does *not* end, so the bound is a hard cap on how long any
/// subscription can live: every stream was cut exactly `write_ms` after it opened.
///
/// Keep-alives do not help, and the reason is worth stating because it is the part that
/// misleads. They are writes that succeed, and the bound is on the elapsed write phase
/// rather than on idleness — so the mechanism that exists to keep a stream healthy
/// cannot extend one. Nothing in the SDK could observe this either: the keep-alive
/// interval, every test, and all four interoperability legs finish well inside 30
/// seconds. It took holding a subscription open and waiting.
pub const WriteBound = enum {
    /// Remove the bound when this server serves subscriptions. The default, because a
    /// finite write bound and a working subscription are mutually exclusive.
    ///
    /// What that gives up is real and worth stating: on this server a peer that stops
    /// reading holds its connection until someone closes it, bounded then only by
    /// `connections_max`. A deployment unwilling to accept that should serve
    /// subscriptions from a listener of their own, where lifting the bound reaches
    /// nothing else.
    lift_for_subscriptions,
    /// Leave `server.timeouts` exactly as given, and accept that a subscription lives
    /// no longer than `write_ms`.
    keep,
};

/// The response-write bound a server with these options should run with.
///
/// Separate from `listen` so that it is testable without a process: the interesting
/// case is a *combination* of options, and the cost of getting it wrong is a stream
/// that works for thirty seconds.
pub fn writeBoundMs(policy: WriteBound, subscriptions_served: bool, requested: u32) u32 {
    return switch (policy) {
        .keep => requested,
        .lift_for_subscriptions => if (subscriptions_served) 0 else requested,
    };
}

/// The Velo options `listen` will run with, given this state and these options.
///
/// Assembled here rather than inline so that what `listen` ends up configuring can be
/// asserted without binding a port. The bug this exists to prevent was not a wrong
/// policy but a policy that was never applied.
fn serverOptionsFor(
    state: *const State,
    options: ListenOptions,
    stop: *velo.ShutdownFlag,
) velo.http.server.Options {
    var server_options = options.server;
    server_options.serve.stop = stop;
    // A subscription stream cannot live under a bound on the response write; see
    // `WriteBound`.
    server_options.timeouts.write_ms = writeBoundMs(
        options.write_bound,
        state.broker != null,
        server_options.timeouts.write_ms,
    );
    return server_options;
}

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

    const server_options = serverOptionsFor(state, options, &stop);

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

    const body = ctx.readBody(body_size_max) catch |err| return respondStatic(
        ctx,
        .bad_request,
        switch (err) {
            error.PayloadTooLarge => static_reply.body_too_large,
            else => static_reply.body_unreadable,
        },
    );

    if (body.len == 0 and bodyWasDropped(ctx)) {
        return respondStatic(ctx, .bad_request, static_reply.chunked_unsupported);
    }

    // Velo writes the response *after* the handler returns, and runs a stream body
    // later still. So nothing produced here may live on this function's stack or in an
    // arena it owns — `ctx.arena` is the per-request scratch allocator, whose lifetime
    // is exactly right. Its capacity is `velo.limits.request_scratch_bytes`, which
    // bounds how large a reply this transport can assemble.
    const arena = ctx.arena;

    var headers: VeloHeaders = .{ .ctx = ctx };
    const outcome = state.endpoint.handle(arena, .{
        .method = "POST",
        .body = body,
        .headers = headers.headers(),
        // Read once, here, so that every expiry check within this request agrees.
        // `.real` rather than `.awake`: a token's `exp` is a wall-clock instant.
        .received_at = std.Io.Clock.real.now(ctx.io).toSeconds(),
    }) catch |err| switch (err) {
        // Reached when the reply did not fit the scratch arena. Velo turns an error
        // returned from here into a bare 500 with no body, which tells a client only
        // that something went wrong and never what.
        error.OutOfMemory => return respondStatic(
            ctx,
            .internal_server_error,
            static_reply.out_of_memory,
        ),
    };

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
            const pending = arena.create(Pending) catch return respondStatic(
                ctx,
                .internal_server_error,
                static_reply.out_of_memory,
            );
            // `readBody` allocated the body in `ctx.arena`, and that arena outlives the
            // streamed response, so the bytes are already owned for exactly long enough.
            // They used to be duplicated here, which put two copies of every request in
            // a fixed 128 KiB arena and roughly halved the largest request that worked.
            pending.* = .{ .state = state, .body = body };

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

test "mount answers every method it does not implement, rather than 404" {
    var registry: server_mod.Registry = .init(testing.allocator);
    defer registry.deinit();
    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var state: State = .init(testing.allocator, &server, .{});
    var app: App = undefined;
    app.init(&state);
    try mount(&app, "/mcp");

    // Driven off the method enum, which is the same source `mount` iterates: adding one
    // to Velo cannot leave a hole here that this test reads as covered.
    inline for (comptime std.enums.values(velo.http.Method)) |method| {
        const found = app.router.find(method, "/mcp") orelse {
            std.debug.print("no route for {t} on /mcp\n", .{method});
            return error.MethodFellThroughTo404;
        };
        const handler = app.routes[found.handler].handler;
        if (method == .post) {
            try testing.expect(handler == handlePost);
        } else {
            // PUT, PATCH, HEAD, OPTIONS, TRACE and CONNECT used to reach Velo's 404,
            // which tells a client the URL is wrong when the verb is.
            try testing.expect(handler == handleRemoved);
        }
    }

    // A different path is still a 404, which is the answer 405 must not displace.
    try testing.expect(app.router.find(.post, "/other") == null);
}

test "the write bound is lifted for a server that serves subscriptions" {
    // 30_000 stands in for Velo's default here; what matters is that a requested bound
    // is discarded when subscriptions are served and kept when they are not.
    try testing.expectEqual(@as(u32, 0), writeBoundMs(.lift_for_subscriptions, true, 30_000));
    try testing.expectEqual(@as(u32, 30_000), writeBoundMs(.lift_for_subscriptions, false, 30_000));

    // `.keep` is the caller saying they would rather have the bound than the stream.
    try testing.expectEqual(@as(u32, 30_000), writeBoundMs(.keep, true, 30_000));
    try testing.expectEqual(@as(u32, 30_000), writeBoundMs(.keep, false, 30_000));

    // Nothing to lift.
    try testing.expectEqual(@as(u32, 0), writeBoundMs(.lift_for_subscriptions, true, 0));
    try testing.expectEqual(@as(u32, 0), writeBoundMs(.keep, true, 0));
}

test "listen applies the write bound policy rather than merely defining it" {
    var registry: server_mod.Registry = .init(testing.allocator);
    defer registry.deinit();
    const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});

    var broker: subscriptions.Broker = .init(testing.allocator, .{ .name = "s", .version = "1" });
    defer broker.closeAll();

    var stop: velo.ShutdownFlag = .init(false);

    // Velo's own default is what a caller who passes `.{}` gets, and it is finite. This
    // is the case that was broken: every subscription ended after `write_ms`.
    const velo_default = (velo.http.server.Options{}).timeouts.write_ms;
    try testing.expect(velo_default > 0);

    var serving: State = .init(testing.allocator, &server, .{});
    serving.broker = &broker;
    const serving_options = serverOptionsFor(&serving, .{}, &stop);
    try testing.expectEqual(@as(u32, 0), serving_options.timeouts.write_ms);

    // A server with no broker answers `subscriptions/listen` as unimplemented, so it has
    // no long-lived response and no reason to give up the bound.
    var plain: State = .init(testing.allocator, &server, .{});
    const plain_options = serverOptionsFor(&plain, .{}, &stop);
    try testing.expectEqual(velo_default, plain_options.timeouts.write_ms);

    // `.keep` reaches Velo untouched even when subscriptions are served.
    const kept = serverOptionsFor(&serving, .{ .write_bound = .keep }, &stop);
    try testing.expectEqual(velo_default, kept.timeouts.write_ms);

    // The stop flag is wired either way; it is what makes Ctrl-C work.
    try testing.expect(serving_options.serve.stop == &stop);
}

test "every static reply is a JSON-RPC error a client can act on" {
    // These exist because the paths that send them cannot allocate, which also means
    // nothing formats or validates them at runtime. A typo would ship a malformed body
    // on exactly the paths that are hardest to reach — worse than the empty body this
    // replaced, since a client would then fail to parse rather than fail to learn.
    const cases = [_]struct { body: []const u8, code: i64 }{
        .{ .body = static_reply.out_of_memory, .code = jsonrpc.error_code.internal_error },
        .{ .body = static_reply.body_too_large, .code = jsonrpc.error_code.parse_error },
        .{ .body = static_reply.body_unreadable, .code = jsonrpc.error_code.parse_error },
        .{ .body = static_reply.chunked_unsupported, .code = jsonrpc.error_code.invalid_request },
    };

    for (cases) |case| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();

        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            arena.allocator(),
            case.body,
            .{},
        );
        const object = parsed.object;
        try testing.expectEqualStrings("2.0", object.get("jsonrpc").?.string);
        // Null rather than absent: a client matching on `id` should see the field and
        // find it unknown, not have to guess whether the server omitted it.
        try testing.expect(object.get("id").? == .null);

        const err = object.get("error").?.object;
        try testing.expectEqual(case.code, err.get("code").?.integer);
        try testing.expect(err.get("message").?.string.len > 0);
    }
}

test "the transport's body bound is Velo's, not the protocol's" {
    // The protocol ceiling is right for stdio and unreachable here, and the gap is
    // large enough that using the wrong one looks like it works until a request has no
    // `Content-Length` — at which point the bound becomes the size of the allocation
    // that must fail.
    try testing.expect(body_size_max < http.body_size_max);
    try testing.expectEqual(velo.limits.request_body_bytes_max, body_size_max);

    // Restated as a runtime check so the relationship appears in the test output, not
    // only as a compile error nobody sees once it holds.
    try testing.expect(body_size_max < velo.limits.request_scratch_bytes);
}
