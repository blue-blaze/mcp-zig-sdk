//! The Streamable HTTP transport's rules, separated from any HTTP library.
//!
//! Everything this revision requires of an MCP endpoint — which methods it answers,
//! when it returns 403, 405, 404, 202 or 200, and the header-versus-body validation
//! that produces `-32020` — is decided here, from an abstract request. An adapter
//! turns a real HTTP server's request into `Request` and this outcome into a real
//! response.
//!
//! That split is what makes the transport testable. Every rule below is a `MUST` in
//! the specification, and none of them need a socket to check.
//!
//! ## Why the headers are validated at all
//!
//! The transport mirrors `method`, `params.name`/`params.uri` and the protocol version
//! into HTTP headers so that load balancers and gateways can route without parsing a
//! JSON body. The moment two components read different sources of truth, the header
//! becomes a way to lie to the router about what the body will do. Rejecting any
//! mismatch is what keeps the mirror honest, and the spec makes it mandatory.
//!
//! ## What was removed in 2026-07-28
//!
//! No sessions (`Mcp-Session-Id` is ignored, never minted), no standalone GET stream,
//! no resumption (`Last-Event-ID` is ignored), and no server-initiated requests on a
//! stream. GET and DELETE to the endpoint get `405`, which is how an older client
//! learns to stop trying.

const std = @import("std");
const assert_mod = @import("assert");
const jsonrpc = @import("jsonrpc.zig");
const types = @import("types.zig");
const schema_gen = @import("schema_gen.zig");
const server_mod = @import("server.zig");
const sse_mod = @import("sse.zig");
const subscriptions = @import("subscriptions.zig");
const authorization = @import("authorization.zig");
const oauth = @import("oauth");

const assert = assert_mod.assert;

const Server = server_mod.Server;

/// Header names the transport defines. Compared case-insensitively, as RFC 9110
/// requires of field names.
/// Re-exported so a transport does not have to reach into the schema generator.
pub const header_annotation = schema_gen.header_annotation;

pub const header = struct {
    pub const protocol_version = "MCP-Protocol-Version";
    pub const method = "Mcp-Method";
    pub const name = "Mcp-Name";
    /// Prefix for headers mirrored from `x-mcp-header`-annotated tool parameters.
    pub const param_prefix = "Mcp-Param-";
    pub const accept = "Accept";
    pub const content_type = "Content-Type";
    pub const origin = "Origin";
    pub const authorization = "Authorization";
    pub const www_authenticate = "WWW-Authenticate";
};

/// The marker wrapping a Base64-encoded header value.
///
/// Needed because HTTP field values are restricted to visible ASCII, while a tool
/// name or a resource URI is not. The markers are case-sensitive and must appear
/// exactly like this.
pub const base64_prefix = "=?base64?";
pub const base64_suffix = "?=";

const base64 = std.base64.standard;

/// Largest request body the endpoint will read.
pub const body_size_max = jsonrpc.message_size_max;

/// An inbound HTTP request, reduced to what the transport cares about.
pub const Request = struct {
    /// The HTTP method, uppercase.
    method: []const u8,
    /// The request body. Empty for GET and DELETE.
    body: []const u8 = "",
    /// Header lookup. Must compare names case-insensitively.
    headers: Headers,
    /// Seconds since the Unix epoch, read once when the request arrived.
    ///
    /// Supplied by the caller rather than read here, so that one request cannot see
    /// two different times and so that token expiry is testable without a clock.
    ///
    /// Required rather than defaulted on purpose. A default of zero would place every
    /// request in 1970, where no token has expired yet — an endpoint whose caller
    /// forgot to set this would accept expired tokens indefinitely, and nothing about
    /// its behaviour would look wrong. Making it mandatory turns that into a
    /// compile error.
    received_at: i64,

    pub const Headers = struct {
        ptr: *const anyopaque,
        vtable: *const VTable,

        pub const VTable = struct {
            /// Returns the value of `name`, compared case-insensitively, or null.
            get: *const fn (ptr: *const anyopaque, name: []const u8) ?[]const u8,
        };

        pub fn get(headers: Headers, name: []const u8) ?[]const u8 {
            return headers.vtable.get(headers.ptr, name);
        }
    };
};

/// What the endpoint decided to do.
pub const Outcome = union(enum) {
    /// Send this status with no body. Used for `202 Accepted` on a notification and
    /// for `405 Method Not Allowed`.
    empty: u16,
    /// Send this status with a JSON body.
    json: Body,
    /// Send `200` with an SSE stream: the handler will run, emitting notifications as
    /// events, and the final response terminates the stream.
    stream: Stream,
    /// Refuse on authorization grounds: a status, a `WWW-Authenticate` header, no body.
    ///
    /// A separate variant rather than a `json` body because these failures are not
    /// about the JSON-RPC request — it was never looked at — and there is no error code
    /// that means "you need a token". RFC 6750 defines the response for this, and it
    /// is the header. Being its own variant also makes every transport's `switch`
    /// name it, so no transport can drop the challenge and send a bare 401.
    unauthorized: authorization.Rejection,

    pub const Body = struct {
        status: u16,
        bytes: []const u8,
    };

    pub const Stream = struct {
        /// The parsed request to dispatch once the stream is open.
        message: jsonrpc.Message,
    };
};

pub const Options = struct {
    /// Origins permitted to reach this endpoint.
    ///
    /// An empty list means no `Origin` is accepted, which is the right default for a
    /// server that only expects programmatic clients: those send no `Origin` at all,
    /// and a request that does send one came from a browser page. Without this check a
    /// remote website can reach a localhost MCP server by DNS rebinding.
    allowed_origins: []const []const u8 = &.{},
    /// Whether to answer requests with an SSE stream rather than a single JSON object.
    ///
    /// Both are permitted per request, and the client must support both. A stream is
    /// what lets progress and log notifications arrive while the handler works — and
    /// what makes cancellation detectable, since a closed stream *is* the
    /// cancellation signal.
    stream_responses: bool = true,
    /// Whether a request that omits `MCP-Protocol-Version` is rejected.
    ///
    /// The spec allows a server that wants to serve pre-2025-06-18 clients to treat an
    /// absent header as `2025-03-26`. This SDK speaks only 2026-07-28, so there is
    /// nothing useful to do with such a request except say so.
    require_protocol_version: bool = true,
    /// Authorization, when this endpoint is a protected resource.
    ///
    /// Null leaves the endpoint open, which is right for stdio-adjacent and
    /// loopback-only deployments — the specification says a stdio server SHOULD NOT
    /// use OAuth at all — and wrong for anything reachable over a network.
    authorization: ?authorization.Guard = null,
};

pub const Endpoint = struct {
    server: *const Server,
    options: Options = .{},

    /// Decides what to do with one HTTP request.
    ///
    /// Ordering matters and follows the spec: the origin check comes before anything
    /// that reads the body, because a DNS-rebinding request must be refused before it
    /// can have any effect.
    pub fn handle(
        endpoint: *const Endpoint,
        arena: std.mem.Allocator,
        request: Request,
    ) error{OutOfMemory}!Outcome {
        if (!endpoint.originAllowed(request)) {
            return .{
                .json = .{
                    .status = 403,
                    // No id: the body has not been looked at, so there is none to echo.
                    .bytes = try errorBody(arena, null, jsonrpc.error_code.invalid_request, "origin not allowed"),
                },
            };
        }

        // The endpoint accepts POST and nothing else. GET was the standalone stream and
        // DELETE ended a session; both are gone, and 405 is how an older client finds
        // that out.
        if (!std.ascii.eqlIgnoreCase(request.method, "POST")) {
            return .{ .empty = 405 };
        }

        if (request.body.len > body_size_max) {
            return .{ .json = .{
                .status = 400,
                .bytes = try errorBody(
                    arena,
                    null,
                    jsonrpc.error_code.parse_error,
                    "request body too large",
                ),
            } };
        }

        // Credentials come before the body is parsed. A client with no token has to
        // learn that from a 401 carrying `resource_metadata`; answering its malformed
        // body with a 400 would tell it about its JSON and never about the fact that
        // the resource is protected. See `authorization.zig` for the full reasoning.
        const grant: ?oauth.Grant = if (endpoint.options.authorization) |guard| blk: {
            const decision = try guard.authenticate(
                arena,
                request.headers.get(header.authorization),
                request.received_at,
            );
            switch (decision) {
                .granted => |granted| break :blk granted,
                .reject => |rejection| return .{ .unauthorized = rejection },
            }
        } else null;

        const message = jsonrpc.parseLeaky(arena, request.body) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return .{ .json = .{
                .status = 400,
                .bytes = try errorBody(arena, null, jsonrpc.parseErrorCode(err), null),
            } };
        };

        switch (message) {
            .notification => {
                // Accepted and answered with no body. This revision defines no
                // client-to-server notifications over HTTP, but the transport mechanics
                // are specified, and refusing one a peer is entitled to send would be
                // stricter than the spec.
                return .{ .empty = 202 };
            },
            // A client must not send responses. There is nothing to correlate one with.
            .result_response, .error_response => {
                return .{ .json = .{
                    .status = 400,
                    .bytes = try errorBody(
                        arena,
                        null,
                        jsonrpc.error_code.invalid_request,
                        "a client must not send JSON-RPC responses",
                    ),
                } };
            },
            .request => |rpc| {
                // Now that the body is parsed we know which operation was asked for, so
                // its own requirement can be applied to the grant already established.
                // No second token validation happens here: this can only produce a 403.
                if (endpoint.options.authorization) |guard| {
                    const rejection = try guard.authorizeOperation(
                        arena,
                        &grant.?,
                        endpoint.server.requiredScopes(rpc),
                    );
                    if (rejection) |reject| return .{ .unauthorized = reject };
                }

                if (try endpoint.validateHeaders(arena, request, rpc)) |failure| return failure;

                // An unimplemented method is 404 with a JSON-RPC error, so a client can
                // tell it apart from the 404 of a server that hosts no MCP endpoint.
                if (!known(rpc.method)) {
                    return .{ .json = .{
                        .status = 404,
                        .bytes = try errorBody(
                            arena,
                            rpc.id,
                            jsonrpc.error_code.method_not_found,
                            null,
                        ),
                    } };
                }

                // A subscription is a long-lived stream by definition, so it never
                // takes the single-JSON-object path even when that is the configured
                // default: there is no one object to send.
                if (endpoint.options.stream_responses or isListen(rpc)) {
                    return .{ .stream = .{ .message = message } };
                }

                const outcome = try endpoint.server.handleMessage(.{ .arena = arena }, message);
                return switch (outcome) {
                    .reply => |reply| .{ .json = .{
                        .status = reply.httpStatus(),
                        .bytes = reply.bytes,
                    } },
                    // Only a cancellation produces this, and a request cannot be
                    // cancelled before it starts on this path.
                    .no_reply => .{ .empty = 202 },
                    // Unreachable: a listen request took the stream path above.
                    .listen => unreachable,
                };
            },
        }
    }

    /// Whether the request's `Origin` is acceptable.
    ///
    /// An absent `Origin` passes: programmatic clients do not send one, and the header
    /// only exists to tell us a browser page is involved. A present one must be on the
    /// list.
    fn originAllowed(endpoint: *const Endpoint, request: Request) bool {
        const origin = request.headers.get(header.origin) orelse return true;
        for (endpoint.options.allowed_origins) |allowed| {
            // Origins are compared case-insensitively on scheme and host, and these
            // are configured values rather than parsed ones, so a plain
            // case-insensitive match is both correct and predictable.
            if (std.ascii.eqlIgnoreCase(origin, allowed)) return true;
        }
        return false;
    }

    /// Checks the mirrored headers against the body.
    ///
    /// Returns null when everything matches, or the `400` to send. Every failure here
    /// is `-32020`, which the spec defines for exactly this: a header that disagrees
    /// with the body, or a required one missing.
    fn validateHeaders(
        endpoint: *const Endpoint,
        arena: std.mem.Allocator,
        request: Request,
        rpc: jsonrpc.Request,
    ) error{OutOfMemory}!?Outcome {
        // ---- MCP-Protocol-Version ----
        const version_header = request.headers.get(header.protocol_version);
        if (version_header == null and endpoint.options.require_protocol_version) {
            return try endpoint.mismatch(
                arena,
                rpc.id,
                "the MCP-Protocol-Version header is required",
            );
        }
        if (version_header) |declared| {
            // It must equal what the body says. A router that trusted the header while
            // the server executed the body would be reading a different request.
            const in_body = bodyProtocolVersion(rpc.params);
            if (in_body == null or !std.mem.eql(u8, declared, in_body.?)) {
                return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    "the MCP-Protocol-Version header does not match the request body",
                );
            }
            // A version this server does not speak is its own error, listing what it
            // does — a client can act on that, where a bare rejection leaves it
            // guessing. Discovery is exempt: it is the negotiation entry point.
            if (!std.mem.eql(u8, declared, types.protocol_version) and
                !std.mem.eql(u8, rpc.method, types.method.discover))
            {
                return .{ .json = .{
                    .status = 400,
                    .bytes = try unsupportedVersionBody(arena, rpc.id, declared),
                } };
            }
        }

        // ---- Mcp-Method ----
        const method_header = request.headers.get(header.method) orelse {
            return try endpoint.mismatch(arena, rpc.id, "the Mcp-Method header is required");
        };
        // Header values are case-sensitive, unlike names, and a method name is a
        // protocol identifier.
        if (!std.mem.eql(u8, method_header, rpc.method)) {
            return try endpoint.mismatch(
                arena,
                rpc.id,
                "the Mcp-Method header does not match the request body",
            );
        }

        // ---- Mcp-Name ----
        if (subjectOf(rpc)) |expected| {
            const raw = request.headers.get(header.name) orelse {
                return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    "the Mcp-Name header is required for this method",
                );
            };
            const decoded = decodeHeaderValue(arena, raw) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Invalid => return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    "the Mcp-Name header is not correctly encoded",
                ),
            };
            if (!std.mem.eql(u8, decoded, expected)) {
                return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    "the Mcp-Name header does not match the request body",
                );
            }
        }

        // ---- Mcp-Param-* ----
        if (std.mem.eql(u8, rpc.method, types.method.tools_call)) {
            if (try endpoint.validateParamHeaders(arena, request, rpc)) |failure| return failure;
        }

        return null;
    }

    /// Checks the `Mcp-Param-*` headers a tool's `x-mcp-header` annotations require.
    ///
    /// The direction that matters is "a value in the body must be in a header": a
    /// non-conforming client that omits the header while sending the value is exactly
    /// what a router would be fooled by, and the spec says to reject it.
    fn validateParamHeaders(
        endpoint: *const Endpoint,
        arena: std.mem.Allocator,
        request: Request,
        rpc: jsonrpc.Request,
    ) error{OutOfMemory}!?Outcome {
        const params = objectOf(rpc.params) orelse return null;
        const name = stringField(params, "name") orelse return null;

        const definition = endpoint.server.registry.findTool(name) orelse return null;
        const mappings = definition.header_mappings;
        if (mappings.len == 0) return null;

        const arguments = objectOf(params.get("arguments")) orelse std.json.ObjectMap.empty;

        for (mappings) |mapping| {
            const header_name = try std.fmt.allocPrint(
                arena,
                header.param_prefix ++ "{s}",
                .{mapping.header},
            );
            const supplied = request.headers.get(header_name);
            // A single segment: `mcp_headers` names top-level fields, so that is the
            // whole path. The spec also permits an annotation on a nested property
            // reachable through `properties` keys; accepting only the top level is a
            // strict subset, and a server cannot produce the nested form here.
            const value = valueAtPath(arguments, &.{mapping.field});

            // Absent from the arguments, or null: the client must omit the header and
            // the server must not expect it.
            if (value == null or value.? == .null) {
                if (supplied != null) {
                    return try endpoint.mismatch(
                        arena,
                        rpc.id,
                        try std.fmt.allocPrint(
                            arena,
                            "the {s} header was sent but the parameter is absent",
                            .{header_name},
                        ),
                    );
                }
                continue;
            }

            const raw = supplied orelse {
                return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    try std.fmt.allocPrint(
                        arena,
                        "the {s} header is required for this parameter",
                        .{header_name},
                    ),
                );
            };
            const decoded = decodeHeaderValue(arena, raw) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Invalid => return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    try std.fmt.allocPrint(
                        arena,
                        "the {s} header is not correctly encoded",
                        .{header_name},
                    ),
                ),
            };

            if (!headerMatchesValue(decoded, value.?)) {
                return try endpoint.mismatch(
                    arena,
                    rpc.id,
                    try std.fmt.allocPrint(
                        arena,
                        "the {s} header does not match the request body",
                        .{header_name},
                    ),
                );
            }
        }
        return null;
    }

    fn mismatch(
        endpoint: *const Endpoint,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        message: []const u8,
    ) error{OutOfMemory}!Outcome {
        _ = endpoint;
        return .{ .json = .{
            .status = 400,
            .bytes = try errorBody(arena, id, jsonrpc.error_code.header_mismatch, message),
        } };
    }
};

// ---------------------------------------------------------------------------
// Streaming a response
// ---------------------------------------------------------------------------

/// Writes a request's notifications and its response to an SSE stream.
///
/// The stream *is* the request's lifetime: notifications the handler emits become
/// events as it runs, and the final response terminates it. If the client closes the
/// stream early, the write fails, which is how cancellation is observed — no
/// `notifications/cancelled` is expected on this transport.
pub fn streamResponse(
    gpa: std.mem.Allocator,
    server: *const Server,
    writer: *std.Io.Writer,
    message: jsonrpc.Message,
) error{OutOfMemory}!void {
    var arena_instance: std.heap.ArenaAllocator = .init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var cancellation: server_mod.Cancellation = .{};
    var sink: EventSink = .{ .writer = writer, .cancellation = &cancellation };

    const outcome = try server.handleMessage(.{
        .arena = arena,
        .sink = sink.sink(),
        .cancellation = &cancellation,
    }, message);

    switch (outcome) {
        .reply => |reply| sse_mod.writeEvent(writer, reply.bytes) catch return,
        // Cancelled: the peer stopped reading, so there is nothing to send and nowhere
        // to send it.
        .no_reply => {},
        // Unreachable: `Endpoint.handle` routes a listen request to
        // `streamSubscription`, because this function returns when the request is done
        // and a subscription is not.
        .listen => unreachable,
    }
}

/// Whether this request opens a subscription stream.
///
/// The transport has to know before dispatching, because the answer decides the shape
/// of the response body — one object, one bounded stream, or a stream with no defined
/// end.
pub fn isListen(rpc: jsonrpc.Request) bool {
    return std.mem.eql(u8, rpc.method, types.method.subscriptions_listen);
}

pub const SubscriptionOptions = struct {
    /// How often a comment line is written when nothing else is.
    ///
    /// The spec encourages periodic keep-alives on long-lived streams. They serve two
    /// purposes here: they stop intermediaries from timing out an idle connection, and
    /// a failed one is how this end learns the client went away — on this transport a
    /// closed stream *is* the cancellation, and there is no other signal to wait for.
    keep_alive_ms: u64 = 15_000,
    /// How often the loop wakes to check whether it should still be running.
    ///
    /// Separate from the keep-alive interval because the two answer different
    /// questions. Sleeping for a whole keep-alive interval would make shutdown take
    /// that long — and a transport that waits for its connections to drain would wait
    /// with it, since this stream is deliberately holding one open.
    poll_ms: u64 = 100,
};

/// Runs a `subscriptions/listen` stream until it ends.
///
/// Returns when the client closes the stream, when the server closes the subscription,
/// or when the request is rejected. The caller's stream is finished at that point.
pub fn streamSubscription(
    gpa: std.mem.Allocator,
    server: *const Server,
    broker: *subscriptions.Broker,
    io: std.Io,
    writer: *std.Io.Writer,
    message: jsonrpc.Message,
    options: SubscriptionOptions,
) error{OutOfMemory}!void {
    var arena_instance: std.heap.ArenaAllocator = .init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    const outcome = try server.handleMessage(.{ .arena = arena }, message);
    const listen = switch (outcome) {
        // A rejection is an ordinary error response, delivered as one event.
        .reply => |reply| {
            sse_mod.writeEvent(writer, reply.bytes) catch {};
            return;
        },
        .no_reply => return,
        .listen => |listen| listen,
    };

    var stream: SubscriptionSink = .{ .gpa = gpa };
    defer stream.deinit();

    const subscriber = broker.subscribe(listen, stream.sink()) catch |err| {
        const reply = try server.errorReply(
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
        sse_mod.writeEvent(writer, reply.reply.bytes) catch {};
        return;
    };

    // The acknowledgement was queued by `subscribe`; it must go out before anything
    // else, which is exactly what draining first achieves.
    stream.drain(writer);

    const poll_ms = @max(options.poll_ms, 1);
    const slice: std.Io.Duration = .{
        .nanoseconds = @intCast(poll_ms * std.time.ns_per_ms),
    };
    // Ceiling division: a keep-alive interval shorter than one poll still gets one
    // keep-alive per poll rather than none.
    const slices_per_keep_alive = (options.keep_alive_ms + poll_ms - 1) / poll_ms;

    var slices: u64 = 0;
    while (!stream.broken) {
        // `.awake` rather than `.real`: a keep-alive interval must not be affected by
        // someone setting the system clock. A cancelled sleep means the host is
        // shutting the request down.
        io.sleep(slice, .awake) catch break;

        // Anything published while we slept.
        stream.drain(writer);

        // The subscription may have been closed from the server side, in which case the
        // closure response was in what we just drained and the slot may belong to
        // someone else by now. Identity, not the pointer, is what settles it.
        if (!broker.holds(subscriber, &stream)) return;

        // Checked every poll, not every keep-alive: this is what bounds how long a
        // shutdown waits for a stream that is holding its connection open on purpose.
        if (broker.isStopping()) break;

        slices += 1;
        if (slices < slices_per_keep_alive) continue;
        slices = 0;
        stream.keepAlive(writer);
    }

    // Reached only when this end still owns the subscription: the client went away, or
    // the loop was interrupted. Release without a closure response — a graceful close
    // is something the *server* initiates, and a client that dropped the stream is not
    // listening for one.
    if (broker.holds(subscriber, &stream)) broker.release(subscriber);
    // Whatever the server queued on the way out still deserves to be written.
    stream.drain(writer);
}

/// Delivers a subscription's messages as SSE events.
///
/// Messages are queued rather than written where they are published, and the reason is
/// not taste. The stream's writer belongs to the task that owns the connection, and a
/// write is a blocking operation: writing to it from a publisher's thread means doing
/// I/O inside a lock that other threads spin on, and it means driving another task's
/// I/O context. Both were tried, and shutdown could hang on either. Queueing keeps a
/// single writer — the loop below — and reduces every publisher to an append.
const SubscriptionSink = struct {
    gpa: std.mem.Allocator,
    /// Guards the ring. Held only for an append or a pop, never across a write.
    lock: std.atomic.Mutex = .unlocked,
    ring: [queue_max][]const u8 = @splat(&.{}),
    head: usize = 0,
    len: usize = 0,
    /// Messages that did not fit. The client cannot see this, so it is here for the
    /// server's own accounting.
    dropped: usize = 0,
    /// Set when a write fails, which on this transport means the client closed the
    /// stream — and that is the documented way to cancel a subscription.
    broken: bool = false,

    /// How many messages may be pending for one subscriber.
    ///
    /// Bounded because a client that stops reading must not be able to grow server
    /// memory. Coalescing identical messages means the steady state for a busy
    /// resource is one entry, not one per event.
    const queue_max: usize = 64;

    const vtable: server_mod.NotificationSink.VTable = .{ .send = send };

    fn sink(self: *SubscriptionSink) server_mod.NotificationSink {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn send(ptr: *anyopaque, message: []const u8) void {
        const self: *SubscriptionSink = @ptrCast(@alignCast(ptr));
        self.enqueue(message);
    }

    fn enqueue(self: *SubscriptionSink, message: []const u8) void {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();

        // Every notification on this stream is an idempotent signal — "the list
        // changed", "read this again" — so an identical one already waiting says
        // everything the new one would. Collapsing them is what keeps a hot resource
        // from filling the queue.
        for (0..self.len) |offset| {
            const index = (self.head + offset) % queue_max;
            if (std.mem.eql(u8, self.ring[index], message)) return;
        }

        if (self.len == queue_max) {
            self.dropped += 1;
            return;
        }
        const copy = self.gpa.dupe(u8, message) catch {
            self.dropped += 1;
            return;
        };
        self.ring[(self.head + self.len) % queue_max] = copy;
        self.len += 1;
    }

    fn pop(self: *SubscriptionSink) ?[]const u8 {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();

        if (self.len == 0) return null;
        const message = self.ring[self.head];
        self.head = (self.head + 1) % queue_max;
        self.len -= 1;
        return message;
    }

    /// Writes everything pending. The only writer, running on the stream's own task.
    fn drain(self: *SubscriptionSink, writer: *std.Io.Writer) void {
        while (self.pop()) |message| {
            defer self.gpa.free(message);
            if (self.broken) continue; // keep draining so nothing leaks
            sse_mod.writeEvent(writer, message) catch {
                self.broken = true;
            };
        }
    }

    fn keepAlive(self: *SubscriptionSink, writer: *std.Io.Writer) void {
        if (self.broken) return;
        sse_mod.writeKeepAlive(writer) catch {
            self.broken = true;
        };
    }

    /// Frees anything still queued. Called once the stream is over.
    fn deinit(self: *SubscriptionSink) void {
        while (self.pop()) |message| self.gpa.free(message);
    }
};

/// Delivers a request's notifications as SSE events.
const EventSink = struct {
    writer: *std.Io.Writer,
    /// Flipped when a write fails, which on this transport means the client closed the
    /// stream — and a closed stream is the cancellation signal.
    cancellation: *server_mod.Cancellation,

    const vtable: server_mod.NotificationSink.VTable = .{ .send = send };

    fn sink(self: *EventSink) server_mod.NotificationSink {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn send(ptr: *anyopaque, message: []const u8) void {
        const self: *EventSink = @ptrCast(@alignCast(ptr));
        if (self.cancellation.isCancelled()) return;

        sse_mod.writeEvent(self.writer, message) catch {
            // The only way this fails is a broken stream. Recording it as cancellation
            // is not a guess: on Streamable HTTP, closing the response stream is
            // exactly how a client cancels.
            self.cancellation.cancel();
        };
    }
};

// ---------------------------------------------------------------------------
// Header values
// ---------------------------------------------------------------------------

pub const DecodeHeaderError = error{ Invalid, OutOfMemory };

/// Decodes a header value, undoing the Base64 sentinel if present.
///
/// A plain value is returned as-is. This must run before any comparison against the
/// body: a client is required to encode anything that is not safe as a bare field
/// value, so comparing the raw header would reject a conforming request.
pub fn decodeHeaderValue(
    arena: std.mem.Allocator,
    raw: []const u8,
) DecodeHeaderError![]const u8 {
    if (!std.mem.startsWith(u8, raw, base64_prefix)) {
        // A bare value must be a legal field value. Rejecting control characters here
        // is what stops a header from carrying a line break into anything downstream
        // that reconstructs a request.
        if (!isSafeHeaderValue(raw)) return error.Invalid;
        return raw;
    }
    if (!std.mem.endsWith(u8, raw, base64_suffix)) return error.Invalid;
    if (raw.len < base64_prefix.len + base64_suffix.len) return error.Invalid;

    const encoded = raw[base64_prefix.len .. raw.len - base64_suffix.len];
    const size = base64.Decoder.calcSizeForSlice(encoded) catch return error.Invalid;
    const decoded = try arena.alloc(u8, size);
    base64.Decoder.decode(decoded, encoded) catch return error.Invalid;
    return decoded;
}

/// Encodes a value for a header, applying the Base64 sentinel when needed.
///
/// Used by the client transport. A plain-ASCII value that happens to look like the
/// sentinel is encoded too, so that a receiver can never be unsure which it is
/// holding.
pub fn encodeHeaderValue(
    arena: std.mem.Allocator,
    value: []const u8,
) error{OutOfMemory}![]const u8 {
    const looks_encoded = std.mem.startsWith(u8, value, base64_prefix) and
        std.mem.endsWith(u8, value, base64_suffix);
    if (isSafeHeaderValue(value) and !looks_encoded) return value;

    const encoded = try arena.alloc(u8, base64.Encoder.calcSize(value.len));
    _ = base64.Encoder.encode(encoded, value);
    return std.fmt.allocPrint(arena, base64_prefix ++ "{s}" ++ base64_suffix, .{encoded});
}

/// Whether a value can travel as a bare HTTP field value.
///
/// RFC 9110 allows visible ASCII, space and horizontal tab — but leading or trailing
/// whitespace is stripped in transit, so a value with either cannot survive the trip
/// unencoded.
fn isSafeHeaderValue(value: []const u8) bool {
    if (value.len == 0) return true;
    if (value[0] == ' ' or value[0] == '\t') return false;
    if (value[value.len - 1] == ' ' or value[value.len - 1] == '\t') return false;
    for (value) |byte| {
        const printable = byte >= 0x21 and byte <= 0x7e;
        if (!printable and byte != ' ' and byte != '\t') return false;
    }
    return true;
}

/// Compares a decoded header value against the body value it mirrors.
///
/// Integers are compared numerically rather than as strings, because `42` and `42.0`
/// denote the same value and the spec says a server should treat them as equal.
fn headerMatchesValue(decoded: []const u8, value: std.json.Value) bool {
    return switch (value) {
        .string => |text| std.mem.eql(u8, decoded, text),
        .bool => |flag| std.mem.eql(u8, decoded, if (flag) "true" else "false"),
        .integer => |integer| {
            const parsed = std.fmt.parseInt(i64, decoded, 10) catch {
                const as_float = std.fmt.parseFloat(f64, decoded) catch return false;
                return as_float == @as(f64, @floatFromInt(integer));
            };
            return parsed == integer;
        },
        // `x-mcp-header` is not permitted on other types, so anything here is a schema
        // this server should not have produced.
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Body inspection
// ---------------------------------------------------------------------------

/// The value `Mcp-Name` mirrors, or null for a method that does not need it.
/// The value `Mcp-Name` must carry, or null when the method does not need it.
///
/// The tool name, prompt name, or resource URI a request addresses.
///
/// Re-exported from the dispatcher: the `Mcp-Name` header must carry exactly what
/// the dispatcher will look up, and a second implementation of "which entity does
/// this request address" is a second answer waiting to disagree with the first.
pub const subjectOf = server_mod.subjectOf;

/// The protocol version declared inside the body's `_meta`.
///
/// A client derives the `MCP-Protocol-Version` header from this rather than from its
/// own configuration, so the two agree by construction instead of by convention — and
/// disagreeing is exactly what the server rejects with `-32020`.
pub fn bodyProtocolVersion(params: ?std.json.Value) ?[]const u8 {
    const object = objectOf(params) orelse return null;
    const request_meta = objectOf(object.get("_meta")) orelse return null;
    return stringField(request_meta, types.meta_key.protocol_version);
}

/// Reads the value at a chain of `properties` keys.
///
/// The chain is what the annotation's position in the schema defines, so a nested
/// object property is reachable while anything behind an array or a composition
/// keyword is not.
fn valueAtPath(root: std.json.ObjectMap, path: []const []const u8) ?std.json.Value {
    assert(path.len > 0);

    var current: std.json.Value = .{ .object = root };
    for (path) |segment| {
        const object = switch (current) {
            .object => |object| object,
            else => return null,
        };
        current = object.get(segment) orelse return null;
    }
    return current;
}

fn known(method: []const u8) bool {
    const names = [_][]const u8{
        types.method.discover,
        types.method.tools_list,
        types.method.tools_call,
        types.method.prompts_list,
        types.method.prompts_get,
        types.method.resources_list,
        types.method.resources_read,
        types.method.resources_templates_list,
        types.method.completion_complete,
        types.method.subscriptions_listen,
    };
    for (names) |name| {
        if (std.mem.eql(u8, method, name)) return true;
    }
    return false;
}

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const present = value orelse return null;
    return switch (present) {
        .object => |object| object,
        else => null,
    };
}

fn stringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |string| string,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Response bodies
// ---------------------------------------------------------------------------

fn errorBody(
    arena: std.mem.Allocator,
    id: ?jsonrpc.Id,
    code: i32,
    message: ?[]const u8,
) error{OutOfMemory}![]const u8 {
    const response: jsonrpc.ErrorResponse = .{
        .id = id,
        .@"error" = .{
            .code = code,
            .message = message orelse jsonrpc.error_code.describe(code),
        },
    };
    return types.stringifyAlloc(arena, response);
}

fn unsupportedVersionBody(
    arena: std.mem.Allocator,
    id: jsonrpc.Id,
    requested: []const u8,
) error{OutOfMemory}![]const u8 {
    var supported: std.json.Array = .init(arena);
    try supported.append(.{ .string = types.protocol_version });

    var data: std.json.ObjectMap = .empty;
    try data.put(arena, "requested", .{ .string = requested });
    try data.put(arena, "supported", .{ .array = supported });

    const response: jsonrpc.ErrorResponse = .{
        .id = id,
        .@"error" = .{
            .code = jsonrpc.error_code.unsupported_protocol_version,
            .message = jsonrpc.error_code.describe(
                jsonrpc.error_code.unsupported_protocol_version,
            ),
            .data = .{ .object = data },
        },
    };
    return types.stringifyAlloc(arena, response);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const registry_mod = @import("registry.zig");
const Context = @import("context.zig").Context;
const Error = @import("context.zig").Error;

/// A header map backed by a slice of pairs, compared case-insensitively.
/// A fixed point in time for tests, so that expiry is a property of the fixture
/// rather than of when the suite happens to run.
const test_now: i64 = 1_800_000_000;

const TestHeaders = struct {
    pairs: []const [2][]const u8,

    fn headers(self: *const TestHeaders) Request.Headers {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Request.Headers.VTable = .{ .get = get };

    fn get(ptr: *const anyopaque, name: []const u8) ?[]const u8 {
        const self: *const TestHeaders = @ptrCast(@alignCast(ptr));
        for (self.pairs) |pair| {
            if (std.ascii.eqlIgnoreCase(pair[0], name)) return pair[1];
        }
        return null;
    }
};

const ExecuteSql = struct {
    region: []const u8,
    query: []const u8,

    pub const mcp_headers = .{ .region = "Region" };
};

fn executeSql(context: *Context, args: ExecuteSql) Error!types.CallToolResult {
    return context.textResult(try context.print("{s}: {s}", .{ args.region, args.query }));
}

const Retries = struct {
    // `i32` rather than `i64`: `schema_gen` refuses an annotation on an integer wider
    // than the JavaScript safe range, which is the spec's constraint on header values.
    attempts: i32,
    verbose: bool = false,

    pub const mcp_headers = .{ .attempts = "Attempts", .verbose = "Verbose" };
};

fn withRetries(context: *Context, args: Retries) Error!types.CallToolResult {
    return context.textResult(try context.print("{d} {}", .{ args.attempts, args.verbose }));
}

fn plainTool(context: *Context, _: void) Error!types.CallToolResult {
    return context.textResult("ok");
}

fn readDoc(context: *Context, uri: []const u8) Error!types.ReadResourceResult {
    const contents = try context.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "body" } };
    return .{ .contents = contents };
}

const Fixture = struct {
    registry: registry_mod.Registry,
    server: Server,
    endpoint: Endpoint,
    arena: std.heap.ArenaAllocator,

    fn init(fixture: *Fixture, options: Options) !void {
        fixture.arena = .init(testing.allocator);
        fixture.registry = try registry_mod.Registry.initComptime(testing.allocator, .{
            registry_mod.tool("execute_sql", executeSql, .{}),
            registry_mod.tool("with_retries", withRetries, .{}),
            registry_mod.tool("plain", plainTool, .{}),
            registry_mod.tool("privileged", plainTool, .{ .scopes = "files:write" }),
            registry_mod.ResourceDefinition{
                .uri = "file:///doc.md",
                .name = "doc.md",
                .handler = readDoc,
            },
        });
        fixture.server = .init(&fixture.registry, .{ .name = "http", .version = "1" }, .{});
        // Most tests check the non-streaming path so the body can be inspected
        // directly; streaming is exercised separately.
        var effective = options;
        effective.stream_responses = false;
        fixture.endpoint = .{ .server = &fixture.server, .options = effective };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.registry.deinit();
        fixture.arena.deinit();
    }

    fn allocator(fixture: *Fixture) std.mem.Allocator {
        return fixture.arena.allocator();
    }

    fn post(
        fixture: *Fixture,
        pairs: []const [2][]const u8,
        body: []const u8,
    ) !Outcome {
        var headers: TestHeaders = .{ .pairs = pairs };
        return fixture.endpoint.handle(fixture.allocator(), .{
            .method = "POST",
            .body = body,
            .headers = headers.headers(),
            .received_at = test_now,
        });
    }

    /// The decoded JSON body of a `json` outcome.
    fn bodyOf(fixture: *Fixture, outcome: Outcome) !std.json.ObjectMap {
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            fixture.allocator(),
            outcome.json.bytes,
            .{},
        );
        return parsed.object;
    }

    fn errorCodeOf(fixture: *Fixture, outcome: Outcome) !i64 {
        const body = try fixture.bodyOf(outcome);
        return body.get("error").?.object.get("code").?.integer;
    }
};

/// A verifier that accepts one token and reports fixed scopes.
///
/// The point of these tests is the transport's ordering and status mapping; token
/// validation itself is covered against real signatures in `oauth`.
const StubVerifier = struct {
    scopes: []const u8 = "mcp:use",
    fail: ?oauth.resource_server.Error = null,

    fn verifyFn(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        token: []const u8,
        _: i64,
    ) oauth.resource_server.Error!oauth.Grant {
        const stub: *StubVerifier = @ptrCast(@alignCast(ptr));
        if (stub.fail) |err| return err;
        if (!std.mem.eql(u8, token, "good")) return error.InvalidToken;
        return .{
            .issuer = "https://as.example.com",
            .audience = "https://mcp.example.com",
            .scopes = stub.scopes,
        };
    }

    fn verifier(stub: *StubVerifier) oauth.Verifier {
        return .{ .ptr = stub, .vtable = &.{ .verify = StubVerifier.verifyFn } };
    }
};

/// A fixture whose endpoint is a protected resource.
const Protected = struct {
    fixture: Fixture,
    stub: StubVerifier,
    resource_server: oauth.ResourceServer,
    guard: authorization.Guard,

    fn init(protected: *Protected, granted: []const u8) !void {
        protected.stub = .{ .scopes = granted };
        protected.resource_server = .init(protected.stub.verifier(), .{
            .resource = "https://mcp.example.com",
            .metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource",
            .scopes_supported = "mcp:use",
        });
        protected.guard = .{
            .resource_server = &protected.resource_server,
            .baseline = "mcp:use",
        };
        try protected.fixture.init(.{ .authorization = protected.guard });
    }

    fn deinit(protected: *Protected) void {
        protected.fixture.deinit();
    }
};

const auth_pair = [2][]const u8{ header.authorization, "Bearer good" };

test "a request with no credentials is refused with a challenge and no body" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    const outcome = try protected.fixture.post(
        &.{ version_pair, .{ header.method, types.method.tools_list } },
        request_list_tools,
    );
    try testing.expect(outcome == .unauthorized);
    try testing.expectEqual(@as(u16, 401), outcome.unauthorized.status);
    const challenge = outcome.unauthorized.challenge.?;
    try testing.expect(std.mem.startsWith(u8, challenge, "Bearer"));
    // The client's whole path forward runs through this parameter.
    try testing.expect(std.mem.indexOf(u8, challenge, "resource_metadata=") != null);
}

test "a valid token reaches the dispatcher" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    const outcome = try protected.fixture.post(
        &.{ version_pair, .{ header.method, types.method.tools_list }, auth_pair },
        request_list_tools,
    );
    try testing.expect(outcome == .json);
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "credentials are checked before the body is parsed" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    // Garbage body, no token. The answer must be the 401, not `-32700`: a client told
    // only about its JSON never discovers that the resource is protected, and the
    // challenge is the sole mechanism the spec gives it to find out.
    const outcome = try protected.fixture.post(
        &.{ version_pair, .{ header.method, types.method.tools_list } },
        "not json at all",
    );
    try testing.expect(outcome == .unauthorized);
    try testing.expectEqual(@as(u16, 401), outcome.unauthorized.status);
}

test "a notification is authorized like anything else" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    // 202 would tell an anonymous caller its notification was accepted, and the
    // endpoint would have processed an unauthenticated message to decide that.
    const outcome = try protected.fixture.post(
        &.{ version_pair, .{ header.method, types.notification.cancelled } },
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{}}",
    );
    try testing.expect(outcome == .unauthorized);
    try testing.expectEqual(@as(u16, 401), outcome.unauthorized.status);
}

test "a tool whose scopes the grant lacks is 403 naming every scope needed" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    const outcome = try protected.fixture.post(&.{
        version_pair,
        .{ header.method, types.method.tools_call },
        .{ header.name, "privileged" },
        auth_pair,
    }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        meta ++ ",\"name\":\"privileged\",\"arguments\":{}}}");

    try testing.expect(outcome == .unauthorized);
    try testing.expectEqual(@as(u16, 403), outcome.unauthorized.status);
    const challenge = outcome.unauthorized.challenge.?;
    try testing.expect(std.mem.indexOf(u8, challenge, "insufficient_scope") != null);
    try testing.expect(std.mem.indexOf(u8, challenge, "files:write") != null);
    try testing.expect(std.mem.indexOf(u8, challenge, "mcp:use") != null);
}

test "a tool whose scopes the grant holds runs" {
    var protected: Protected = undefined;
    try protected.init("mcp:use files:write");
    defer protected.deinit();

    const outcome = try protected.fixture.post(&.{
        version_pair,
        .{ header.method, types.method.tools_call },
        .{ header.name, "privileged" },
        auth_pair,
    }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        meta ++ ",\"name\":\"privileged\",\"arguments\":{}}}");

    try testing.expect(outcome == .json);
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "a tool declaring no scopes needs only the baseline" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    const outcome = try protected.fixture.post(&.{
        version_pair,
        .{ header.method, types.method.tools_call },
        .{ header.name, "plain" },
        auth_pair,
    }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        meta ++ ",\"name\":\"plain\",\"arguments\":{}}}");

    try testing.expect(outcome == .json);
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "a verifier that cannot check answers 503 without a challenge" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();
    protected.stub.fail = error.Unavailable;

    const outcome = try protected.fixture.post(
        &.{ version_pair, .{ header.method, types.method.tools_list }, auth_pair },
        request_list_tools,
    );
    try testing.expect(outcome == .unauthorized);
    // Not 401. Telling a client its token is bad when the truth is that we cannot look
    // is how a working client gets driven into a reauthorization loop it cannot exit.
    try testing.expectEqual(@as(u16, 503), outcome.unauthorized.status);
    try testing.expectEqual(@as(?[]const u8, null), outcome.unauthorized.challenge);
}

test "an unprotected endpoint is unaffected" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, types.method.tools_list } },
        request_list_tools,
    );
    try testing.expect(outcome == .json);
}

test "the origin check still precedes authorization" {
    var protected: Protected = undefined;
    try protected.init("mcp:use");
    defer protected.deinit();

    // A DNS-rebinding request must be refused before anything else looks at it, token
    // or no token — including before a challenge would disclose the metadata URL.
    const outcome = try protected.fixture.post(&.{
        version_pair,
        .{ header.method, types.method.tools_list },
        .{ header.origin, "https://evil.example" },
        auth_pair,
    }, request_list_tools);
    try testing.expect(outcome == .json);
    try testing.expectEqual(@as(u16, 403), outcome.json.status);
}

const version_pair = [2][]const u8{ header.protocol_version, "2026-07-28" };

/// A single-line `_meta` for use inside a request body.
const meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientCapabilities\":{}}";

/// The plainest well-formed request there is, used wherever a test is about
/// something other than the body.
const request_list_tools = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
    meta ++ "}}";

test "a well-formed tools/list is answered" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, "tools/list" } },
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
    try testing.expect((try fixture.bodyOf(outcome)).get("result") != null);
}

test "GET and DELETE are not allowed on the endpoint" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // GET was the standalone stream and DELETE ended a session. Both were removed in
    // this revision, and 405 is how an older client learns to stop trying.
    for ([_][]const u8{ "GET", "DELETE", "PUT", "PATCH" }) |method| {
        var headers: TestHeaders = .{ .pairs = &.{} };
        const outcome = try fixture.endpoint.handle(fixture.allocator(), .{
            .method = method,
            .headers = headers.headers(),
            .received_at = test_now,
        });
        try testing.expectEqual(@as(u16, 405), outcome.empty);
    }
}

test "an unknown origin is refused before the body is read" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .allowed_origins = &.{"https://app.example.com"} });
    defer fixture.deinit();

    // DNS rebinding: a remote page resolving a name to 127.0.0.1 to reach a local
    // server. The body is never dispatched, so the request has no effect.
    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, "tools/list" }, .{ header.origin, "https://evil.example" } },
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 403), outcome.json.status);
    // The spec allows a JSON-RPC error body with no id, which is all that is knowable
    // before the body is parsed.
    try testing.expect((try fixture.bodyOf(outcome)).get("id") == null);
}

test "a listed origin is accepted, case-insensitively" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .allowed_origins = &.{"https://app.example.com"} });
    defer fixture.deinit();

    for ([_][]const u8{ "https://app.example.com", "HTTPS://APP.EXAMPLE.COM" }) |origin| {
        const outcome = try fixture.post(
            &.{ version_pair, .{ header.method, "tools/list" }, .{ header.origin, origin } },
            request_list_tools,
        );
        try testing.expectEqual(@as(u16, 200), outcome.json.status);
    }
}

test "a request with no origin is accepted" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .allowed_origins = &.{"https://app.example.com"} });
    defer fixture.deinit();

    // Programmatic clients send no Origin at all. The header exists to tell us a
    // browser is involved; its absence is not suspicious.
    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, "tools/list" } },
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "a notification is accepted with no body" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{},
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}",
    );
    try testing.expectEqual(@as(u16, 202), outcome.empty);
}

test "a client-sent response is refused" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // The spec is explicit that a client must not POST responses, and there is nothing
    // a server could correlate one with.
    const outcome = try fixture.post(
        &.{version_pair},
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}",
    );
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
}

test "an unimplemented method is 404 with a JSON-RPC error" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, "tools/nope" } },
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/nope\",\"params\":{" ++ meta ++ "}}",
    );
    // 404 with a body: that is what distinguishes this from the 404 of a server that
    // hosts no MCP endpoint, which is how a client decides whether to fall back.
    try testing.expectEqual(@as(u16, 404), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.method_not_found),
        try fixture.errorCodeOf(outcome),
    );
}

test "a missing protocol version header is a header mismatch" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{.{ header.method, "tools/list" }},
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.header_mismatch),
        try fixture.errorCodeOf(outcome),
    );
}

test "a protocol version header that disagrees with the body is refused" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // This is the whole point of the validation: a router acting on the header while
    // the server acts on the body would be handling two different requests.
    const outcome = try fixture.post(
        &.{ .{ header.protocol_version, "2025-11-25" }, .{ header.method, "tools/list" } },
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.header_mismatch),
        try fixture.errorCodeOf(outcome),
    );
}

test "a consistently declared unsupported version lists what is supported" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{ .{ header.protocol_version, "2025-11-25" }, .{ header.method, "tools/list" } },
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{" ++
            "\"io.modelcontextprotocol/protocolVersion\":\"2025-11-25\"," ++
            "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
    );
    try testing.expectEqual(@as(u16, 400), outcome.json.status);

    const body = try fixture.bodyOf(outcome);
    const failure = body.get("error").?.object;
    try testing.expectEqual(@as(i64, -32022), failure.get("code").?.integer);
    // A client can act on this; a bare rejection would leave it guessing.
    try testing.expectEqualStrings(
        "2026-07-28",
        failure.get("data").?.object.get("supported").?.array.items[0].string,
    );
}

test "discovery is answered even in an unsupported version" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // Discovery is the negotiation entry point. Refusing it for speaking the wrong
    // version leaves the client with no way to learn the right one.
    const outcome = try fixture.post(
        &.{ .{ header.protocol_version, "1900-01-01" }, .{ header.method, "server/discover" } },
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{" ++
            "\"io.modelcontextprotocol/protocolVersion\":\"1900-01-01\"," ++
            "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
    );
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
    try testing.expect((try fixture.bodyOf(outcome)).get("result") != null);
}

test "the version header may be waived for older clients" {
    var fixture: Fixture = undefined;
    try fixture.init(.{ .require_protocol_version = false });
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{.{ header.method, "tools/list" }},
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "a missing or mismatched method header is refused" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
        meta ++ "}}";

    // Missing.
    {
        const outcome = try fixture.post(&.{version_pair}, body);
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
    // Mismatched. Header values are case-sensitive, unlike names.
    for ([_][]const u8{ "tools/call", "TOOLS/LIST", "" }) |value| {
        const outcome = try fixture.post(
            &.{ version_pair, .{ header.method, value } },
            body,
        );
        try testing.expectEqual(@as(u16, 400), outcome.json.status);
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
}

test "header names are matched case-insensitively" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // RFC 9110 makes field names case-insensitive, so a client is free to send any
    // casing and a server that cared would reject conforming requests.
    const outcome = try fixture.post(
        &.{ .{ "mcp-protocol-version", "2026-07-28" }, .{ "MCP-METHOD", "tools/list" } },
        request_list_tools,
    );
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "the name header is required for the three methods that carry a subject" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // tools/call
    {
        const outcome = try fixture.post(
            &.{ version_pair, .{ header.method, "tools/call" } },
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"plain\"," ++ meta ++ "}}",
        );
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
    // resources/read mirrors the uri, not a name.
    {
        const outcome = try fixture.post(
            &.{ version_pair, .{ header.method, "resources/read" } },
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{" ++
                "\"uri\":\"file:///doc.md\"," ++ meta ++ "}}",
        );
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
    // With the header present, both succeed.
    {
        const outcome = try fixture.post(
            &.{
                version_pair,
                .{ header.method, "resources/read" },
                .{ header.name, "file:///doc.md" },
            },
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{" ++
                "\"uri\":\"file:///doc.md\"," ++ meta ++ "}}",
        );
        try testing.expectEqual(@as(u16, 200), outcome.json.status);
    }
}

test "the name header is not expected where the method has no subject" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    for ([_][]const u8{ "tools/list", "prompts/list", "resources/list", "server/discover" }) |method| {
        const body = try std.fmt.allocPrint(
            fixture.allocator(),
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{{{s}}}}}",
            .{ method, meta },
        );
        const outcome = try fixture.post(
            &.{ version_pair, .{ header.method, method } },
            body,
        );
        try testing.expectEqual(@as(u16, 200), outcome.json.status);
    }
}

test "a name header that disagrees with the body is refused" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, "tools/call" }, .{ header.name, "other_tool" } },
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"plain\"," ++ meta ++ "}}",
    );
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.header_mismatch),
        try fixture.errorCodeOf(outcome),
    );
}

test "a base64-encoded name header is decoded before comparison" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // A resource URI need not be header-safe. Comparing the raw header would reject a
    // conforming client.
    const uri = "file:///projects/世界/config.json";
    const encoded = try encodeHeaderValue(fixture.allocator(), uri);
    try testing.expect(std.mem.startsWith(u8, encoded, base64_prefix));

    const body = try std.fmt.allocPrint(
        fixture.allocator(),
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{{" ++
            "\"uri\":\"{s}\",{s}}}}}",
        .{ uri, meta },
    );
    const outcome = try fixture.post(
        &.{ version_pair, .{ header.method, "resources/read" }, .{ header.name, encoded } },
        body,
    );
    // Reaches the dispatcher, which then reports the resource as unknown — proving the
    // header check passed rather than short-circuiting.
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.invalid_params),
        try fixture.errorCodeOf(outcome),
    );
}

test "a malformed base64 header is refused" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    for ([_][]const u8{
        "=?base64?not valid base64!?=",
        "=?base64?",
        "=?base64?abc",
    }) |value| {
        const outcome = try fixture.post(
            &.{ version_pair, .{ header.method, "tools/call" }, .{ header.name, value } },
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"plain\"," ++ meta ++ "}}",
        );
        try testing.expectEqual(@as(u16, 400), outcome.json.status);
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
}

test "a custom parameter header is validated against the body" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        "\"name\":\"execute_sql\",\"arguments\":{\"region\":\"us-west1\"," ++
        "\"query\":\"SELECT 1\"}," ++ meta ++ "}}";

    // Matching.
    {
        const outcome = try fixture.post(&.{
            version_pair,
            .{ header.method, "tools/call" },
            .{ header.name, "execute_sql" },
            .{ "Mcp-Param-Region", "us-west1" },
        }, body);
        try testing.expectEqual(@as(u16, 200), outcome.json.status);
    }
    // Disagreeing: this is the case a router would be fooled by.
    {
        const outcome = try fixture.post(&.{
            version_pair,
            .{ header.method, "tools/call" },
            .{ header.name, "execute_sql" },
            .{ "Mcp-Param-Region", "eu-central1" },
        }, body);
        try testing.expectEqual(@as(u16, 400), outcome.json.status);
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
    // Omitted while the value is in the body: a non-conforming client, and the spec
    // says to reject it.
    {
        const outcome = try fixture.post(&.{
            version_pair,
            .{ header.method, "tools/call" },
            .{ header.name, "execute_sql" },
        }, body);
        try testing.expectEqual(@as(u16, 400), outcome.json.status);
        try testing.expectEqual(
            @as(i64, jsonrpc.error_code.header_mismatch),
            try fixture.errorCodeOf(outcome),
        );
    }
}

test "a header for an absent parameter must not be sent" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // `verbose` has a default, so a client may omit it. Sending the header anyway means
    // the header and the body disagree about what the call is.
    const outcome = try fixture.post(&.{
        version_pair,
        .{ header.method, "tools/call" },
        .{ header.name, "with_retries" },
        .{ "Mcp-Param-Attempts", "3" },
        .{ "Mcp-Param-Verbose", "true" },
    }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        "\"name\":\"with_retries\",\"arguments\":{\"attempts\":3}," ++ meta ++ "}}");

    try testing.expectEqual(@as(u16, 400), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.header_mismatch),
        try fixture.errorCodeOf(outcome),
    );
}

test "integer and boolean parameters are compared by value" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        "\"name\":\"with_retries\",\"arguments\":{\"attempts\":42,\"verbose\":true}," ++
        meta ++ "}}";

    // `42.0` and `42` denote the same number; the spec says to compare numerically.
    for ([_][]const u8{ "42", "42.0" }) |attempts| {
        const outcome = try fixture.post(&.{
            version_pair,
            .{ header.method, "tools/call" },
            .{ header.name, "with_retries" },
            .{ "Mcp-Param-Attempts", attempts },
            .{ "Mcp-Param-Verbose", "true" },
        }, body);
        try testing.expectEqual(@as(u16, 200), outcome.json.status);
    }

    // Booleans are lowercase.
    for ([_][]const u8{ "True", "1", "yes" }) |verbose| {
        const outcome = try fixture.post(&.{
            version_pair,
            .{ header.method, "tools/call" },
            .{ header.name, "with_retries" },
            .{ "Mcp-Param-Attempts", "42" },
            .{ "Mcp-Param-Verbose", verbose },
        }, body);
        try testing.expectEqual(@as(u16, 400), outcome.json.status);
    }
}

test "a tool with no annotations needs no parameter headers" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(&.{
        version_pair,
        .{ header.method, "tools/call" },
        .{ header.name, "plain" },
    }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
        "\"name\":\"plain\"," ++ meta ++ "}}");
    try testing.expectEqual(@as(u16, 200), outcome.json.status);
}

test "session and resumption headers from older revisions are ignored" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    // The spec says to ignore both rather than reject: an older client sending them is
    // not otherwise doing anything wrong, and it will learn the truth from discovery.
    const outcome = try fixture.post(&.{
        version_pair,
        .{ header.method, "tools/list" },
        .{ "Mcp-Session-Id", "abc123" },
        .{ "Last-Event-ID", "42" },
    }, request_list_tools);

    try testing.expectEqual(@as(u16, 200), outcome.json.status);
    // And no session id is minted in return.
    try testing.expect((try fixture.bodyOf(outcome)).get("sessionId") == null);
}

test "a malformed body is a parse error with no id" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const outcome = try fixture.post(&.{version_pair}, "{not json");
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
    try testing.expectEqual(
        @as(i64, jsonrpc.error_code.parse_error),
        try fixture.errorCodeOf(outcome),
    );
}

test "an oversized body is refused without being parsed" {
    var fixture: Fixture = undefined;
    try fixture.init(.{});
    defer fixture.deinit();

    const huge = try testing.allocator.alloc(u8, body_size_max + 1);
    defer testing.allocator.free(huge);
    @memset(huge, 'x');

    const outcome = try fixture.post(&.{version_pair}, huge);
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
}

test "header value encoding round-trips" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const cases = [_][]const u8{
        "us-west1",
        "Hello, 世界",
        " padded ",
        "line1\nline2",
        "=?base64?literal?=",
        "",
        "file:///projects/myapp/config.json",
    };
    for (cases) |original| {
        const encoded = try encodeHeaderValue(arena.allocator(), original);
        const decoded = try decodeHeaderValue(arena.allocator(), encoded);
        try testing.expectEqualStrings(original, decoded);
    }
}

test "a plain ASCII value travels unencoded" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // No point paying for base64 on the common case, and an unencoded value is what an
    // intermediary can actually read.
    try testing.expectEqualStrings(
        "us-west1",
        try encodeHeaderValue(arena.allocator(), "us-west1"),
    );
}

test "a value that looks encoded is encoded anyway" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Otherwise a receiver could not tell a literal from an encoding.
    const encoded = try encodeHeaderValue(arena.allocator(), "=?base64?literal?=");
    try testing.expect(!std.mem.eql(u8, encoded, "=?base64?literal?="));
    try testing.expectEqualStrings(
        "=?base64?literal?=",
        try decodeHeaderValue(arena.allocator(), encoded),
    );
}

test "a bare header value with control characters is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // A line break in a header value is how a request smuggling attack starts.
    for ([_][]const u8{ "a\r\nb", "a\nb", "a\x00b", " leading", "trailing " }) |value| {
        try testing.expectError(
            error.Invalid,
            decodeHeaderValue(arena.allocator(), value),
        );
    }
}

test "streaming a response emits notifications before the result" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("chatty", chattyTool, .{}),
    });
    defer registry.deinit();

    const server: Server = .init(&registry, .{ .name = "http", .version = "1" }, .{});

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const message = try jsonrpc.parseLeaky(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"chatty\"," ++
            "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
            "\"io.modelcontextprotocol/clientCapabilities\":{},\"progressToken\":\"t\"}}}",
    );

    var stream: std.Io.Writer.Allocating = .init(testing.allocator);
    defer stream.deinit();

    try streamResponse(testing.allocator, &server, &stream.writer, message);

    // Decoding the stream back proves the SSE framing and the ordering together.
    var reader: std.Io.Reader = .fixed(stream.written());
    var decoder: sse_mod.Decoder = .init(&reader);

    var progress: usize = 0;
    var responses: usize = 0;
    while (try decoder.next(arena.allocator())) |event| {
        switch (try jsonrpc.parseLeaky(arena.allocator(), event)) {
            .notification => progress += 1,
            .result_response => responses += 1,
            else => return error.TestUnexpectedMessage,
        }
    }
    try testing.expectEqual(@as(usize, 2), progress);
    try testing.expectEqual(@as(usize, 1), responses);
    // The response terminates the stream, so it must come last.
    try testing.expect(std.mem.indexOf(u8, stream.written(), "\"id\":7").? >
        std.mem.indexOf(u8, stream.written(), "\"progress\":1").?);
}

fn chattyTool(context: *Context, _: void) Error!types.CallToolResult {
    context.reportProgress(1, .{ .total = 2 });
    context.reportProgress(2, .{ .total = 2 });
    return context.textResult("done");
}

test "a request routed to a stream reports that it should be streamed" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("plain", plainTool, .{}),
    });
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(&registry, .{ .name = "http", .version = "1" }, .{});
    const endpoint: Endpoint = .{ .server = &server, .options = .{ .stream_responses = true } };

    var headers: TestHeaders = .{ .pairs = &.{
        version_pair,
        .{ header.method, "tools/list" },
    } };
    const outcome = try endpoint.handle(arena.allocator(), .{
        .method = "POST",
        .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
            meta ++ "}}",
        .headers = headers.headers(),
        .received_at = test_now,
    });
    try testing.expect(outcome == .stream);
}

test "validation failures are reported before the stream is opened" {
    var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("plain", plainTool, .{}),
    });
    defer registry.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const server: Server = .init(&registry, .{ .name = "http", .version = "1" }, .{});
    const endpoint: Endpoint = .{ .server = &server, .options = .{ .stream_responses = true } };

    // A 400 has to be an ordinary response: once an SSE stream is open the status is
    // already 200 and there is no way to take it back.
    var headers: TestHeaders = .{ .pairs = &.{version_pair} };
    const outcome = try endpoint.handle(arena.allocator(), .{
        .method = "POST",
        .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
            meta ++ "}}",
        .headers = headers.headers(),
        .received_at = test_now,
    });
    try testing.expectEqual(@as(u16, 400), outcome.json.status);
}

test "fuzz the endpoint against arbitrary requests" {
    const Fuzz = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var registry = try registry_mod.Registry.initComptime(testing.allocator, .{
                registry_mod.tool("execute_sql", executeSql, .{}),
            });
            defer registry.deinit();

            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            const server: Server = .init(&registry, .{ .name = "s", .version = "1" }, .{});
            const endpoint: Endpoint = .{
                .server = &server,
                .options = .{ .stream_responses = false },
            };

            var buffer: [1024]u8 = undefined;
            const length = smith.slice(&buffer);
            const body = buffer[0..length];

            // The headers are fuzzed too, by pointing them at slices of the same input.
            var headers: TestHeaders = .{ .pairs = &.{
                .{ header.protocol_version, body[0..@min(body.len, 16)] },
                .{ header.method, body[0..@min(body.len, 32)] },
                .{ header.name, body },
                .{ "Mcp-Param-Region", body },
            } };
            _ = endpoint.handle(arena.allocator(), .{
                .method = "POST",
                .body = body,
                .headers = headers.headers(),
                .received_at = test_now,
            }) catch return;
        }
    };
    try testing.fuzz(Fuzz{}, Fuzz.testOne, .{});
}

test {
    // `schema_gen` supplies the header mappings the parameter validation relies on.
    _ = schema_gen;
}
