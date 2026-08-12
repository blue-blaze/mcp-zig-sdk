//! The client half of the Streamable HTTP transport.
//!
//! One `POST` per request, and the response is read as it arrives: either a single JSON
//! object or a stream of SSE events. Both shapes are required of a client, and the
//! streaming one is not optional in practice — progress notifications that only appear
//! after the handler finished are useless, and a `subscriptions/listen` stream never
//! finishes at all.
//!
//! ## Why the HTTP framing is written here
//!
//! Velo's client buffers a whole response before returning it. That is the right shape
//! for most callers and the wrong one for this transport: a subscription stream would
//! grow a buffer forever. What is reused instead is one layer down — `std.Io.net` for
//! the connection and Velo's TLS binding for `https` — leaving only HTTP/1.1 response
//! framing to be written, which is what Velo does not expose. If it ever grows a
//! streaming response API, most of this file becomes a call to it.
//!
//! ## Header obligations
//!
//! The spec requires a client to mirror parts of the body into headers, so an
//! intermediary can route without parsing JSON. Every one of them is derived from the
//! body rather than from configuration, because the server rejects any disagreement
//! with `-32020` — deriving them is what makes them agree by construction:
//!
//! * `MCP-Protocol-Version` comes from the body's `_meta`.
//! * `Mcp-Method` is the JSON-RPC method.
//! * `Mcp-Name` is `params.name` or `params.uri`, for the three methods that have one.
//! * `Mcp-Param-*` mirrors tool arguments annotated with `x-mcp-header`. Those
//!   annotations are only knowable from `tools/list`, so see `ParamHeaders`.

const std = @import("std");
const velo = @import("velo");

const assert_mod = @import("assert");
const assert = assert_mod.assert;

const client_mod = @import("client.zig");
const http = @import("http.zig");
const jsonrpc = @import("jsonrpc.zig");
const sse = @import("sse.zig");
const types = @import("types.zig");

/// What a client must advertise it can read. The server picks between the two.
pub const accept_value = "application/json, text/event-stream";

/// Read buffer for one connection. Large enough that a typical response head and a
/// typical event each land in one read.
const connection_buffer_bytes: usize = 16 * 1024;

pub const Error = error{
    /// The connection could not be established, or failed mid-exchange.
    ConnectionFailed,
    /// The peer did not speak HTTP/1.1 well enough to continue.
    MalformedResponse,
    /// A body, or a single event, exceeded its bound.
    MessageTooLarge,
    /// `https` was requested but TLS was not built in.
    TlsNotSupported,
    /// The URL is not an absolute `http`/`https` URL.
    InvalidUrl,
    /// The server refused on authorization grounds. `Transport.challenge` holds what
    /// it said.
    Unauthorized,
    /// `Options.receive_timeout_ms` expired with the response unfinished. The
    /// connection is dropped, but the request may already have been carried out.
    Timeout,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Mcp-Param-* mappings
// ---------------------------------------------------------------------------

/// Which tool arguments must be mirrored into `Mcp-Param-*` headers.
///
/// A client cannot know this by itself: the `x-mcp-header` annotation lives in the tool's
/// `inputSchema`, which arrives from `tools/list`. So the mapping is *learned*, and a
/// client that calls a tool before listing tools will be rejected by a conformant
/// server. That is a real ordering requirement, not an implementation quirk, and
/// `learn` is where it is discharged.
pub const ParamHeaders = struct {
    /// Bounded so that a server cannot grow client memory by advertising tools.
    pub const tools_max: usize = 256;
    pub const params_per_tool_max: usize = 16;

    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub const Entry = struct {
        tool: []const u8,
        /// Argument name paired with the header it is mirrored into.
        params: []const Mapping,
    };

    pub const Mapping = struct {
        field: []const u8,
        header: []const u8,
    };

    /// Storage is caller-owned: `learn` duplicates into `gpa` so the mapping outlives
    /// the arena a `tools/list` result was decoded into.
    pub fn deinit(self: *ParamHeaders, gpa: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            gpa.free(entry.tool);
            for (entry.params) |mapping| {
                gpa.free(mapping.field);
                gpa.free(mapping.header);
            }
            gpa.free(entry.params);
        }
        self.entries.deinit(gpa);
    }

    /// Records the annotations carried by a `tools/list` result.
    ///
    /// Replaces what was known before rather than merging: the list is the server's
    /// current answer, and a tool whose annotation was removed must stop being
    /// mirrored.
    pub fn learn(
        self: *ParamHeaders,
        gpa: std.mem.Allocator,
        tools: []const types.Tool,
    ) error{ OutOfMemory, TooManyTools }!void {
        if (tools.len > tools_max) return error.TooManyTools;

        var learned: ParamHeaders = .{};
        errdefer learned.deinit(gpa);

        for (tools) |tool| {
            const mappings = try mappingsOf(gpa, tool.inputSchema);
            if (mappings.len == 0) {
                gpa.free(mappings);
                continue;
            }
            errdefer {
                for (mappings) |mapping| {
                    gpa.free(mapping.field);
                    gpa.free(mapping.header);
                }
                gpa.free(mappings);
            }
            const name = try gpa.dupe(u8, tool.name);
            errdefer gpa.free(name);
            try learned.entries.append(gpa, .{ .tool = name, .params = mappings });
        }

        self.deinit(gpa);
        self.* = learned;
    }

    /// Reads `properties.<field>["x-mcp-header"]` out of a tool's input schema.
    fn mappingsOf(
        gpa: std.mem.Allocator,
        schema: types.Json,
    ) error{OutOfMemory}![]const Mapping {
        // Only a decoded schema carries annotations to read. A `raw` variant exists so a
        // comptime-generated schema can be emitted without allocating; it is what a
        // *server* holds, never what a client receives.
        const value = switch (schema) {
            .value => |v| v,
            .raw => return &.{},
        };
        const object = switch (value) {
            .object => |o| o,
            else => return &.{},
        };
        const properties = switch (object.get("properties") orelse return &.{}) {
            .object => |o| o,
            else => return &.{},
        };

        var list: std.ArrayListUnmanaged(Mapping) = .empty;
        errdefer {
            for (list.items) |mapping| {
                gpa.free(mapping.field);
                gpa.free(mapping.header);
            }
            list.deinit(gpa);
        }

        for (properties.keys(), properties.values()) |field, property| {
            if (list.items.len == params_per_tool_max) break;
            const property_object = switch (property) {
                .object => |o| o,
                else => continue,
            };
            const annotation = switch (property_object.get(http.header_annotation) orelse continue) {
                .string => |s| s,
                else => continue,
            };
            if (annotation.len == 0) continue;

            const field_copy = try gpa.dupe(u8, field);
            errdefer gpa.free(field_copy);
            const header_copy = try gpa.dupe(u8, annotation);
            try list.append(gpa, .{ .field = field_copy, .header = header_copy });
        }
        return list.toOwnedSlice(gpa);
    }

    pub fn find(self: *const ParamHeaders, tool: []const u8) []const Mapping {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.tool, tool)) return entry.params;
        }
        return &.{};
    }
};

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

pub const Options = struct {
    /// Headers added to every request. `Authorization` goes here.
    extra_headers: []const [2][]const u8 = &.{},
    /// Bound on a single JSON response body, and on one SSE event.
    response_bytes_max: usize = jsonrpc.message_size_max,
    /// How long to wait for the next bytes of a response before giving up, in
    /// milliseconds. Null waits forever, which is the previous behaviour and the
    /// default.
    ///
    /// This is the only place a hung server can be noticed. `Client` holds no `Io` and
    /// no clock — that is what lets it drive a pipe or an in-memory pair as readily as a
    /// socket — so the transport that owns the socket is the layer that can bound the
    /// wait. Expiry surfaces as `error.Timeout` all the way up, and abandoning the call
    /// is safe for the reason `client.Transport` documents: ids are never reused, so a
    /// late reply is discarded rather than mistaken for the next one.
    ///
    /// It is a gap between bytes, not a bound on the whole exchange, and that is the
    /// point: a `subscriptions/listen` stream is a response that never ends, and a total
    /// deadline would kill it. A server that keeps talking keeps the connection.
    ///
    /// Two limits worth knowing before choosing a value:
    ///
    /// * **`https` is not covered.** Under TLS the socket belongs to Velo's session and
    ///   the read happens inside OpenSSL, which this transport cannot interpose on. The
    ///   option is accepted and has no effect there; a diagnostic says so when such an
    ///   exchange opens, rather than leaving it to be discovered.
    /// * **Connecting is not covered.** `std.Io.net` exposes no deadline on connect, so
    ///   an unroutable address still waits for the operating system's own bound.
    receive_timeout_ms: ?u32 = null,
    /// Skip TLS certificate and hostname verification. Insecure; for a self-signed
    /// certificate in a test, never for real traffic.
    tls_insecure: bool = false,
    /// The `x-mcp-header` annotations learned from `tools/list`.
    ///
    /// Optional because a client that never calls an annotated tool needs none, and
    /// pretending otherwise would make the first `tools/list` impossible.
    param_headers: ?*const ParamHeaders = null,
    /// Where to report problems that have no request to attach to.
    diagnostics: ?*std.Io.Writer = null,
};

/// A `client.Transport` speaking Streamable HTTP.
///
/// One exchange at a time: `send` performs the POST and reads the response head, then
/// `receive` yields the messages in its body until there are none left. That is exactly
/// the shape `client.Transport` asks for, which is why it was defined that way.
pub const Transport = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Absolute URL of the single MCP endpoint.
    url: []const u8,
    options: Options,

    /// The exchange in flight, if any.
    ///
    /// Heap-allocated because the reader, the writer and the body framing all hold
    /// pointers into it. Storing it by value would invalidate every one of them the
    /// moment the exchange were assigned into this field.
    exchange: ?*Exchange = null,
    /// Set when the request was accepted with no body to read.
    accepted: bool = false,
    /// What the server said when it last refused on authorization grounds.
    ///
    /// Recorded here rather than returned from `send`, because the value it points at
    /// lives in an arena that `send` releases, and because the caller that has to act
    /// on it is several layers up: `Client` sees `error.Unauthorized` and the
    /// application decides what to do about it.
    ///
    /// Cleared at the start of every `send`, and freed by `deinit`. That is the
    /// invariant that makes it safe to read: a challenge is either the current
    /// exchange's or absent, never a stale one from an earlier request. (An earlier
    /// draft exposed the status code the same way; it was removed because its window of
    /// validity was impossible to state, and this field only avoids that by being
    /// cleared unconditionally.)
    ///
    /// Borrowed, not owned by the reader. Anything that outlives this transport — a
    /// value returned from the function that created it, most obviously — must take a
    /// copy with `copyChallenge`.
    challenge: ?Challenge = null,

    /// An authorization refusal, as the server phrased it.
    pub const Challenge = struct {
        /// 401 when credentials are missing or rejected, 403 when they are
        /// insufficient. The difference decides what the client should do: obtain a
        /// token versus widen the one it has.
        status: u16,
        /// The raw `WWW-Authenticate` value. Parse it with `oauth.bearer.parseChallenge`.
        ///
        /// Optional because a 503 carries none, and because a server may refuse without
        /// saying anything useful — in which case there is nothing to act on, and
        /// pretending otherwise would send the client into discovery with no target.
        header: ?[]const u8,
    };

    pub fn init(
        gpa: std.mem.Allocator,
        io: std.Io,
        url: []const u8,
        options: Options,
    ) Transport {
        assert(url.len > 0);
        return .{ .gpa = gpa, .io = io, .url = url, .options = options };
    }

    /// Closes any connection still open. Safe to call more than once.
    pub fn deinit(self: *Transport) void {
        self.finish();
        self.clearChallenge();
    }

    /// The recorded challenge, copied into `arena`.
    ///
    /// Exists because the borrowed lifetime of `challenge` is easy to get wrong in the
    /// exact shape this is used in: a helper that creates a transport, sends one
    /// request and returns what happened. Its `defer transport.deinit()` frees the
    /// challenge on the way out, so returning the field yields a dangling slice — and
    /// with a plain allocator that reads as a crash with no allocator report to explain
    /// it. Copying is one call, so the safe path is the short one.
    pub fn copyChallenge(
        self: *const Transport,
        arena: std.mem.Allocator,
    ) error{OutOfMemory}!?Challenge {
        const recorded = self.challenge orelse return null;
        return .{
            .status = recorded.status,
            .header = if (recorded.header) |value| try arena.dupe(u8, value) else null,
        };
    }

    fn clearChallenge(self: *Transport) void {
        const previous = self.challenge orelse return;
        if (previous.header) |header_value| self.gpa.free(header_value);
        self.challenge = null;
    }

    pub fn transport(self: *Transport) client_mod.Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: client_mod.Transport.VTable = .{ .send = sendErased, .receive = receiveErased };

    fn sendErased(ptr: *anyopaque, message: []const u8) client_mod.Transport.SendError!void {
        const self: *Transport = @ptrCast(@alignCast(ptr));
        return self.send(message) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.MessageTooLarge => error.MessageTooLarge,
            error.Unauthorized => error.Unauthorized,
            error.Timeout => error.Timeout,
            else => {
                self.report("send failed: {t}\n", .{err});
                return error.TransportFailed;
            },
        };
    }

    fn receiveErased(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
    ) client_mod.Transport.ReceiveError!?[]const u8 {
        const self: *Transport = @ptrCast(@alignCast(ptr));
        return self.receive(arena) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.MessageTooLarge => error.MessageTooLarge,
            error.Timeout => error.Timeout,
            else => {
                self.report("receive failed: {t}\n", .{err});
                return error.TransportFailed;
            },
        };
    }

    /// Posts one message and reads the response head.
    pub fn send(self: *Transport, message: []const u8) Error!void {
        if (message.len > jsonrpc.message_size_max) return error.MessageTooLarge;

        // A previous exchange that was not read to the end is abandoned here. On this
        // transport closing a response stream is how a client cancels, so dropping the
        // connection is the correct way to say "never mind".
        self.finish();
        self.clearChallenge();

        var arena_instance: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_instance.deinit();
        const arena = arena_instance.allocator();

        const headers = try self.headersFor(arena, message);

        const exchange = try Exchange.open(self.gpa, self.io, self.url, self.options);
        errdefer exchange.close(self.io);
        if (self.options.receive_timeout_ms != null and exchange.tls != null) {
            // Said out loud rather than left to be discovered: a deadline that is
            // configured and not enforced is worse than one that was never asked for.
            self.report(
                "receive_timeout_ms is not enforced on https; the TLS session owns the socket\n",
                .{},
            );
        }

        try exchange.writeRequest(message, headers);
        try exchange.readHead(arena, self.options.response_bytes_max);

        // An authorization refusal is reported as its own error rather than delivered
        // as a body, because there is no body: the status and the challenge are the
        // whole of it. A caller that saw only "the exchange yielded no messages" would
        // have to guess why.
        if (authorizationRefusal(exchange.response.status)) {
            const raw = exchange.response.challenge;
            // Duped before the head arena goes away, and before the connection closes.
            const owned = if (raw) |value| try self.gpa.dupe(u8, value) else null;
            self.challenge = .{ .status = exchange.response.status, .header = owned };
            // Closed by the `errdefer` above on the way out. Closing here as well would
            // free the connection twice, and the second free is a use-after-free of the
            // TLS session it owns.
            return error.Unauthorized;
        }

        self.accepted = exchange.status() == 202;
        self.exchange = exchange;
    }

    /// Yields the next message the server sent, or null when the response is spent.
    pub fn receive(self: *Transport, arena: std.mem.Allocator) Error!?[]const u8 {
        const exchange = self.exchange orelse return null;
        if (self.accepted) {
            // 202 with no body: a notification was accepted. There is nothing to read
            // and nothing to wait for.
            self.finish();
            return null;
        }

        const message = exchange.next(arena, self.options.response_bytes_max) catch |err| {
            self.finish();
            return err;
        };
        // Asked before the message is looked at, because a read that stopped at the
        // deadline leaves a *plausible* result behind rather than an error: a truncated
        // length-delimited body comes back as whatever arrived, and a cut SSE stream comes
        // back as null, which otherwise reads as "the server is done". Either one would
        // hand the client a lie about a request that is still outstanding.
        if (exchange.timedOut()) {
            self.finish();
            return error.Timeout;
        }
        if (message == null) self.finish();
        return message;
    }

    fn finish(self: *Transport) void {
        if (self.exchange) |exchange| exchange.close(self.io);
        self.exchange = null;
        self.accepted = false;
    }

    fn report(self: *const Transport, comptime fmt: []const u8, args: anytype) void {
        const writer = self.options.diagnostics orelse return;
        writer.print(fmt, args) catch return;
        writer.flush() catch {};
    }

    /// Builds the headers the spec requires for this body.
    fn headersFor(
        self: *const Transport,
        arena: std.mem.Allocator,
        message: []const u8,
    ) Error![]const [2][]const u8 {
        var list: std.ArrayListUnmanaged([2][]const u8) = .empty;
        try list.append(arena, .{ http.header.content_type, "application/json" });
        try list.append(arena, .{ http.header.accept, accept_value });
        for (self.options.extra_headers) |pair| try list.append(arena, pair);

        // A body that does not parse still gets posted: the server's answer to a
        // malformed message is more useful than a local guess, and it is the server's
        // job to produce `-32700`.
        const parsed = jsonrpc.parseLeaky(arena, message) catch return list.items;
        const rpc = switch (parsed) {
            .request => |rpc| rpc,
            // Notifications and responses carry no method header obligations beyond the
            // version, which the server needs either way.
            else => {
                if (versionOf(parsed)) |version| {
                    try list.append(arena, .{ http.header.protocol_version, version });
                }
                return list.items;
            },
        };

        if (http.bodyProtocolVersion(rpc.params)) |version| {
            try list.append(arena, .{ http.header.protocol_version, version });
        }
        try list.append(arena, .{ http.header.method, rpc.method });

        if (http.subjectOf(rpc)) |subject| {
            try list.append(arena, .{
                http.header.name,
                try http.encodeHeaderValue(arena, subject),
            });
        }
        try self.appendParamHeaders(arena, &list, rpc);
        return list.items;
    }

    /// Mirrors `x-mcp-header`-annotated tool arguments.
    fn appendParamHeaders(
        self: *const Transport,
        arena: std.mem.Allocator,
        list: *std.ArrayListUnmanaged([2][]const u8),
        rpc: jsonrpc.Request,
    ) Error!void {
        const known = self.options.param_headers orelse return;
        if (!std.mem.eql(u8, rpc.method, types.method.tools_call)) return;

        const params = objectOf(rpc.params) orelse return;
        const tool = stringField(params, "name") orelse return;
        const arguments = objectOf(params.get("arguments")) orelse return;

        for (known.find(tool)) |mapping| {
            const value = arguments.get(mapping.field) orelse continue;
            // A null argument is the same as an absent one: the spec has the client omit
            // the header, and the server must not expect it.
            const rendered = try renderHeaderValue(arena, value) orelse continue;
            const name = try std.fmt.allocPrint(
                arena,
                "{s}{s}",
                .{ http.header.param_prefix, mapping.header },
            );
            try list.append(arena, .{ name, try http.encodeHeaderValue(arena, rendered) });
        }
    }
};

/// Renders a JSON scalar the way the spec's header comparison expects, or null when the
/// value must not be mirrored at all.
/// Whether a status means "not authorized", as opposed to any other refusal.
///
/// 503 is excluded on purpose: it says the server could not check, and a client that
/// treated it as an authorization failure would discard a working token and reauthorize
/// to fix a problem that is not its own.
fn authorizationRefusal(status: u16) bool {
    return status == 401 or status == 403;
}

fn renderHeaderValue(
    arena: std.mem.Allocator,
    value: std.json.Value,
) error{OutOfMemory}!?[]const u8 {
    return switch (value) {
        .null => null,
        .string => |s| s,
        .bool => |b| if (b) "true" else "false",
        .integer => |i| try std.fmt.allocPrint(arena, "{d}", .{i}),
        // A float is refused at compile time by `schema_gen` on the server side, so a
        // client should never meet one; mirroring it would invite a formatting mismatch
        // that reads as tampering.
        .float, .number_string, .array, .object => null,
    };
}

fn versionOf(message: jsonrpc.Message) ?[]const u8 {
    return switch (message) {
        .request => |rpc| http.bodyProtocolVersion(rpc.params),
        .notification => |notification| http.bodyProtocolVersion(notification.params),
        else => null,
    };
}

// ---------------------------------------------------------------------------
// One HTTP/1.1 exchange
// ---------------------------------------------------------------------------

/// A connection with a request written and a response being read.
///
/// Always heap-allocated: `reader`, `writer` and `body` are wired to each other and to
/// the buffers by pointer, so this object must not move once opened.
const Exchange = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    target: Target,

    read_buffer: []u8,
    write_buffer: []u8,
    reader: SocketReader,
    writer: std.Io.net.Stream.Writer,
    tls: ?TlsSession = null,

    /// The response being read. Filled in by `readHead`.
    response: Response = undefined,

    /// Whichever reader is reading the socket.
    ///
    /// Two of them because the deadline is optional and the plain reader is the one
    /// `std.Io.net` already provides. A configured deadline substitutes `TimedReader`
    /// rather than layering on top, so a client that sets no deadline reads through
    /// exactly the code it read through before — no new failure mode on a platform where
    /// concurrent waiting is unavailable.
    const SocketReader = union(enum) {
        plain: std.Io.net.Stream.Reader,
        timed: TimedReader,

        fn interface(self: *SocketReader) *std.Io.Reader {
            return switch (self.*) {
                .plain => |*plain| &plain.interface,
                .timed => |*timed| &timed.interface,
            };
        }
    };

    fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        url: []const u8,
        options: Options,
    ) Error!*Exchange {
        const target = try parseUrl(url);

        const exchange = gpa.create(Exchange) catch return error.OutOfMemory;
        errdefer gpa.destroy(exchange);

        const read_buffer = gpa.alloc(u8, connection_buffer_bytes) catch return error.OutOfMemory;
        errdefer gpa.free(read_buffer);
        const write_buffer = gpa.alloc(u8, connection_buffer_bytes) catch return error.OutOfMemory;
        errdefer gpa.free(write_buffer);

        const stream = connect(io, target.host, target.port) catch return error.ConnectionFailed;
        errdefer stream.close(io);

        // Under TLS the bytes are read by OpenSSL from a handle Velo owns, so there is
        // nothing here to bound; substituting a reader would only bound the TLS record
        // layer's own framing, which is not where a hung server is waited on.
        const deadline: ?u32 = if (target.tls) null else options.receive_timeout_ms;

        exchange.* = .{
            .gpa = gpa,
            .io = io,
            .stream = stream,
            .target = target,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .reader = if (deadline) |ms|
                .{ .timed = .init(io, stream, read_buffer, ms) }
            else
                .{ .plain = stream.reader(io, read_buffer) },
            .writer = stream.writer(io, write_buffer),
        };

        if (target.tls) {
            exchange.tls = try TlsSession.connect(gpa, stream, target.host, options.tls_insecure);
        }
        return exchange;
    }

    fn close(exchange: *Exchange, io: std.Io) void {
        if (exchange.tls) |*session| session.deinit(exchange.gpa);
        exchange.stream.close(io);
        exchange.gpa.free(exchange.read_buffer);
        exchange.gpa.free(exchange.write_buffer);
        exchange.gpa.destroy(exchange);
    }

    fn socketWriter(exchange: *Exchange) *std.Io.Writer {
        if (exchange.tls) |*session| return session.writer();
        return &exchange.writer.interface;
    }

    fn socketReader(exchange: *Exchange) *std.Io.Reader {
        if (exchange.tls) |*session| return session.reader();
        return exchange.reader.interface();
    }

    /// Whether the last read stopped because the deadline passed.
    ///
    /// Has to be asked rather than returned: `std.Io.Reader` collapses every failure into
    /// `error.ReadFailed`, and the layers above deliberately treat the end of a body as
    /// news rather than as an error — `readAll` keeps whatever arrived, and the SSE
    /// decoder reads a closed stream as "the server is done". A deadline that expired
    /// looks identical to both of them, so the reader is the only thing that knows.
    fn timedOut(exchange: *const Exchange) bool {
        return switch (exchange.reader) {
            .plain => false,
            .timed => |timed| if (timed.err) |err| err == error.Timeout else false,
        };
    }

    fn writeRequest(
        exchange: *Exchange,
        body: []const u8,
        headers: []const [2][]const u8,
    ) Error!void {
        const writer = exchange.socketWriter();

        writer.print("POST {s} HTTP/1.1\r\n", .{exchange.target.path}) catch
            return error.ConnectionFailed;
        writer.print("Host: {s}\r\n", .{exchange.target.authority}) catch
            return error.ConnectionFailed;
        // One exchange per connection. Reuse would save a handshake, but a subscription
        // stream occupies its connection for as long as it lives, so a pool would have
        // to model that; the simple thing is correct and the cost is local.
        writer.writeAll("Connection: close\r\n") catch return error.ConnectionFailed;
        for (headers) |pair| {
            writer.print("{s}: {s}\r\n", .{ pair[0], pair[1] }) catch
                return error.ConnectionFailed;
        }
        writer.print("Content-Length: {d}\r\n\r\n", .{body.len}) catch
            return error.ConnectionFailed;
        writer.writeAll(body) catch return error.ConnectionFailed;
        writer.flush() catch return error.ConnectionFailed;
    }

    fn readHead(exchange: *Exchange, arena: std.mem.Allocator, limit: usize) Error!void {
        exchange.response = Response.read(exchange.socketReader(), arena, limit) catch |err| {
            // A head that stopped mid-line reads as `ConnectionFailed`, which is the
            // right name when the peer went away and the wrong one when it simply stopped
            // talking. Only the reader can tell those apart.
            if (exchange.timedOut()) return error.Timeout;
            return err;
        };
    }

    fn next(exchange: *Exchange, arena: std.mem.Allocator, limit: usize) Error!?[]const u8 {
        return exchange.response.next(arena, limit);
    }

    fn status(exchange: *const Exchange) u16 {
        return exchange.response.status;
    }
};

/// A `std.Io.Reader` over a socket that gives up when nothing arrives in time.
///
/// `std.Io.net.Stream.Reader` waits as long as the peer likes, which is right for a
/// stream with no deadline and wrong for a request that has one: a server which accepts
/// the POST and then says nothing holds the caller forever. This routes the same read
/// through `Io.operateTimeout`, so the wait is bounded by the socket becoming readable
/// rather than by the server's cooperation.
///
/// **Not `SO_RCVTIMEO`**, which is the obvious alternative and does not work here. A
/// blocking socket with a receive timeout fails a read with `EAGAIN`, and
/// `std.Io.Threaded` treats `EAGAIN` on a blocking descriptor as a bug in its caller —
/// `netReadPosix` maps it to `errnoBug`, which aborts the process. The socket option
/// would turn a slow server into a panic. `recvmsg` under `operateTimeout` is the same
/// wait expressed where the `Io` implementation can see it: `MSG_DONTWAIT` plus `poll`,
/// on a descriptor that stays blocking.
const TimedReader = struct {
    io: std.Io,
    handle: std.Io.net.Socket.Handle,
    timeout: std.Io.Timeout,
    interface: std.Io.Reader,
    /// The last failure, because `std.Io.Reader` has one error for all of them and only
    /// `error.Timeout` means the connection is still good. Read through
    /// `Exchange.timedOut`.
    err: ?ReadError = null,

    /// Everything a bounded receive can fail with. `ConcurrencyUnavailable` is in here
    /// because it is real: waiting concurrently needs `poll`, which WASI and a build
    /// without it do not have, and on those targets a deadline cannot be honoured. It
    /// surfaces as a failed read rather than as a silent unbounded wait.
    pub const ReadError = std.Io.OperateTimeoutError || std.Io.net.Socket.ReceiveError;

    fn init(
        io: std.Io,
        connection: std.Io.net.Stream,
        buffer: []u8,
        timeout_ms: u32,
    ) TimedReader {
        return .{
            .io = io,
            .handle = connection.socket.handle,
            // `awake` rather than `boot`, so a laptop that suspends mid-request does not
            // wake with its whole deadline already spent. What is being bounded is how
            // long the server is allowed to stay quiet, not how long the machine was.
            .timeout = .{ .duration = .{
                .raw = .fromMilliseconds(timeout_ms),
                .clock = .awake,
            } },
            .interface = .{ .vtable = &vtable, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    // Only `stream`: the default `readVec` routes through it. Implementing `readVec`
    // would mean filling several buffers per call, and `net_receive` takes one
    // contiguous destination, so it would gain nothing but a second code path.
    const vtable: std.Io.Reader.VTable = .{ .stream = stream };

    fn stream(
        io_r: *std.Io.Reader,
        io_w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *TimedReader = @alignCast(@fieldParentPtr("interface", io_r));
        const dest = limit.slice(try io_w.writableSliceGreedy(1));

        // The deadline is measured per call, so it bounds the gap between bytes rather
        // than the whole response. A stream that keeps producing keeps its connection,
        // which is what a subscription needs.
        var message: std.Io.net.IncomingMessage = .init;
        const result = self.io.operateTimeout(.{ .net_receive = .{
            .socket_handle = self.handle,
            .message_buffer = (&message)[0..1],
            .data_buffer = dest,
            .flags = .{},
        } }, self.timeout) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };

        const failure, const count = result.net_receive;
        if (failure) |err| {
            self.err = err;
            return error.ReadFailed;
        }
        assert(count == 1);
        // A stream socket delivering zero bytes is the peer closing, not a short read.
        if (message.data.len == 0) return error.EndOfStream;
        io_w.advance(message.data.len);
        return message.data.len;
    }
};

/// An HTTP response whose head has been read and whose body has not.
///
/// Separate from the connection so that every decision made here — the status, the
/// framing, JSON versus SSE — is testable against a fixed buffer. What is left on the
/// connection side is opening it and writing the request, which only a real socket can
/// exercise.
pub const Response = struct {
    status: u16,
    /// The `WWW-Authenticate` value, when the server sent one.
    ///
    /// Kept because it is the only actionable content of a 401 or 403: it names the
    /// metadata document to start discovery from, and on a 403 the full set of scopes
    /// the operation needs. Allocated in the head arena, so a caller that outlives the
    /// arena has to copy it — `Transport` does.
    challenge: ?[]const u8,
    /// True when the body is `text/event-stream`.
    streaming: bool,
    /// Set once the body has been fully delivered.
    spent: bool,
    /// Strips the body's framing. Reused across calls: it carries chunk state and
    /// buffered bytes, so building a fresh one per message would read a chunk header
    /// from the middle of a chunk.
    body: BodyReader,

    /// Reads the status line and headers, and works out how the body is delimited.
    pub fn read(
        source: *std.Io.Reader,
        arena: std.mem.Allocator,
        limit: usize,
    ) Error!Response {
        const status_line = try readLine(source, arena, head_line_bytes_max);
        const status = try parseStatus(status_line);

        var length: ?usize = null;
        var chunked = false;
        var streaming = false;
        var challenge: ?[]const u8 = null;

        // Each line is bounded, but a head made of nothing but lines was not: the loop
        // ended when the server chose to send its blank line, and every header until then
        // was kept in the arena. Refused rather than truncated, because a head this long
        // is not a response worth trying to interpret.
        var lines: usize = 0;
        while (true) : (lines += 1) {
            if (lines == head_lines_max) return error.MalformedResponse;
            const line = try readLine(source, arena, head_line_bytes_max);
            if (line.len == 0) break;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                return error.MalformedResponse;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                length = std.fmt.parseInt(usize, value, 10) catch
                    return error.MalformedResponse;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                // Only `chunked` can be undone here. A coding this transport cannot
                // reverse would corrupt the body silently, so it is refused instead.
                if (std.ascii.indexOfIgnoreCase(value, "chunked") != null) {
                    chunked = true;
                } else return error.MalformedResponse;
            } else if (std.ascii.eqlIgnoreCase(name, http.header.content_type)) {
                streaming = std.ascii.indexOfIgnoreCase(value, sse.content_type) != null;
            } else if (std.ascii.eqlIgnoreCase(name, http.header.www_authenticate)) {
                // First one wins. A response with two is malformed, and preferring the
                // later copy would let an appended header override the real one.
                if (challenge == null) challenge = value;
            }
        }

        const framing: BodyReader.Framing = if (chunked)
            .chunked
        else if (length) |n| blk: {
            if (n > limit) return error.MessageTooLarge;
            break :blk .{ .length = n };
        } else .until_close;

        // Returned by value, which is safe only because `BodyReader` attaches its buffer
        // in `reader()` rather than here: nothing has been read yet, so the copy carries
        // no indices into a buffer that just moved.
        return .{
            .status = status,
            .challenge = challenge,
            .streaming = streaming,
            .spent = framing == .length and framing.length == 0,
            .body = .init(source, framing),
        };
    }

    /// The next JSON-RPC message in the body, or null when it is spent.
    pub fn next(self: *Response, arena: std.mem.Allocator, limit: usize) Error!?[]const u8 {
        if (self.spent) return null;

        if (!self.streaming) {
            // A single JSON object: the whole body is the message.
            const body = try readAll(self.body.reader(), arena, limit);
            self.spent = true;
            if (body.len == 0) return null;
            return body;
        }

        // `Decoder` handles SSE framing; what it reads from is already free of chunk
        // framing, which is `BodyReader`'s job.
        var decoder: sse.Decoder = .{ .reader = self.body.reader() };
        const message = decoder.next(arena) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.EventTooLarge => return error.MessageTooLarge,
            error.ReadFailed => {
                // A stream that ends without a terminating event is not an error: the
                // server closing the connection is how it says it is done.
                self.spent = true;
                return null;
            },
        };
        if (message == null) self.spent = true;
        return message;
    }
};

/// Reads a whole body into `arena`, refusing one that runs past `limit`.
///
/// The bound is applied while the body arrives rather than after it has all been
/// buffered, and that is the whole point of not using `streamRemaining` here. Only a
/// declared `Content-Length` can be refused up front, which `Response.read` does; the
/// other two framings have no length to check. So a `Transfer-Encoding: chunked` body, or
/// a `Connection: close` body with no length at all, was bounded by nothing but the
/// server's willingness to stop — every byte it chose to send was allocated first and
/// measured second.
///
/// One byte past `limit` is read on purpose: reaching `limit + 1` is what distinguishes a
/// body that exactly fills the bound from one that exceeds it.
fn readAll(reader: *std.Io.Reader, arena: std.mem.Allocator, limit: usize) Error![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(arena);

    reader.appendRemaining(arena, &list, .limited(limit +| 1)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.MessageTooLarge,
        // A truncated body is whatever arrived; the caller decides whether it parses.
        // `appendRemaining` hands the bytes it managed to read back either way.
        error.ReadFailed => {},
    };
    return list.items;
}

/// Upper bound on one line of a response head.
const head_line_bytes_max: usize = 8 * 1024;

/// Upper bound on how many lines a response head may have, counting the status line.
/// Generous for anything a server has reason to send, and finite, which is the point.
const head_lines_max: usize = 128;

const Target = struct {
    /// The bare host, with an IPv6 literal's brackets removed: what a resolver and a
    /// TLS handshake need. `[::1]` is a URL syntax, not a hostname, and neither
    /// `IpAddress.resolve` nor `HostName.init` accepts the brackets.
    host: []const u8,
    /// The authority exactly as the URL wrote it — brackets kept, port included when
    /// the URL gave one. This is what `Host:` must carry: a server or proxy routing on
    /// it needs the port whenever it is not the scheme's default.
    authority: []const u8,
    port: u16,
    path: []const u8,
    tls: bool,
};

/// Splits an absolute `http`/`https` URL.
pub fn parseUrl(url: []const u8) Error!Target {
    var rest: []const u8 = undefined;
    var tls = false;
    if (std.mem.startsWith(u8, url, "http://")) {
        rest = url["http://".len..];
    } else if (std.mem.startsWith(u8, url, "https://")) {
        rest = url["https://".len..];
        tls = true;
    } else return error.InvalidUrl;

    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |index| rest[0..index] else rest;
    const path = if (slash) |index| rest[index..] else "/";
    if (authority.len == 0) return error.InvalidUrl;

    var host = authority;
    var port: u16 = if (tls) 443 else 80;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        // A colon inside brackets belongs to an IPv6 literal, not to a port.
        if (std.mem.indexOfScalar(u8, authority[colon..], ']') == null) {
            host = authority[0..colon];
            port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch
                return error.InvalidUrl;
        }
    }
    // Strip an IPv6 literal's brackets: they delimit the host within the authority and
    // are not part of the address. Keeping them here is what made every `[::1]` URL
    // fail at connect while parsing cleanly.
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        host = host[1 .. host.len - 1];
    }
    if (host.len == 0) return error.InvalidUrl;
    return .{ .host = host, .authority = authority, .port = port, .path = path, .tls = tls };
}

/// Opens a TCP connection to `host`, which may be an IP literal or a name.
///
/// Both cases have to be handled explicitly because `IpAddress.resolve` is not a
/// resolver despite the name: it parses literals (and resolves an IPv6 scope id to an
/// interface index, which is the "resolve" it refers to). Names live in `HostName`,
/// which runs the actual lookup and tries every address it gets back. Calling only the
/// former is what made every URL addressed by name — that is, every URL whose TLS
/// certificate can be checked — fail with `ConnectionFailed` and nothing pointing at
/// DNS.
///
/// Literal first, so that an address never depends on the resolver being reachable.
fn connect(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |literal| {
        var address = literal;
        return std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    } else |_| {}

    const name = try std.Io.net.HostName.init(host);
    return name.connect(io, port, .{ .mode = .stream });
}

fn parseStatus(line: []const u8) Error!u16 {
    // "HTTP/1.1 200 OK"
    if (!std.mem.startsWith(u8, line, "HTTP/1.")) return error.MalformedResponse;
    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.MalformedResponse;
    const rest = line[space + 1 ..];
    if (rest.len < 3) return error.MalformedResponse;
    return std.fmt.parseInt(u16, rest[0..3], 10) catch error.MalformedResponse;
}

/// Reads one CRLF-terminated line, without the terminator.
fn readLine(reader: *std.Io.Reader, arena: std.mem.Allocator, limit: usize) Error![]const u8 {
    var allocating: std.Io.Writer.Allocating = .init(arena);
    errdefer allocating.deinit();

    _ = reader.streamDelimiterLimit(&allocating.writer, '\n', .limited(limit)) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        error.ReadFailed => return error.ConnectionFailed,
        error.StreamTooLong => return error.MalformedResponse,
    };
    _ = reader.takeByte() catch return error.MalformedResponse;
    return std.mem.trimEnd(u8, allocating.written(), "\r");
}

// ---------------------------------------------------------------------------
// Body framing
// ---------------------------------------------------------------------------

/// Presents a response body as a plain `std.Io.Reader`, with its framing removed.
///
/// This exists so that `sse.Decoder` — shared with the server side and with the tests —
/// never has to know how the body was delimited. It takes a reader rather than a
/// connection, which is what makes chunk decoding testable without a socket.
pub const BodyReader = struct {
    source: *std.Io.Reader,
    framing: Framing,
    interface: std.Io.Reader,
    /// Bytes left of a length-delimited body.
    remaining: usize = 0,
    /// Bytes left in the chunk being read. Zero means "read the next chunk header".
    chunk_remaining: usize = 0,
    /// True once the terminating chunk was seen, so a further read is end of stream
    /// rather than an attempt to parse trailers as a chunk header.
    finished: bool = false,
    buffer: [connection_buffer_bytes]u8 = undefined,

    pub const Framing = union(enum) {
        length: usize,
        chunked,
        /// The body runs to end of stream. `Connection: close` without a length.
        until_close,
    };

    pub fn init(source: *std.Io.Reader, framing: Framing) BodyReader {
        return .{
            .source = source,
            .framing = framing,
            .remaining = switch (framing) {
                .length => |n| n,
                else => 0,
            },
            .interface = .{ .vtable = &vtable, .buffer = &.{}, .seek = 0, .end = 0 },
        };
    }

    /// The reader interface.
    ///
    /// The buffer is attached here rather than in `init` so that it points into this
    /// object's final location — `init`'s result is usually copied into a field.
    pub fn reader(self: *BodyReader) *std.Io.Reader {
        self.interface.buffer = &self.buffer;
        return &self.interface;
    }

    const vtable: std.Io.Reader.VTable = .{ .stream = stream };

    fn stream(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *BodyReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.finished) return error.EndOfStream;

        return switch (self.framing) {
            .length => {
                if (self.remaining == 0) {
                    self.finished = true;
                    return error.EndOfStream;
                }
                const allowed = limit.min(.limited(self.remaining));
                const n = try self.source.stream(w, allowed);
                self.remaining -= n;
                return n;
            },
            .until_close => self.source.stream(w, limit),
            .chunked => self.streamChunked(w, limit),
        };
    }

    fn streamChunked(
        self: *BodyReader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        if (self.chunk_remaining == 0) {
            const size = try self.readChunkHeader();
            if (size == 0) {
                // The terminating chunk, followed by trailers nothing here uses.
                // Draining them is what leaves the connection in a defined state.
                self.drainTrailers();
                self.finished = true;
                return error.EndOfStream;
            }
            self.chunk_remaining = size;
        }

        const allowed = limit.min(.limited(self.chunk_remaining));
        const n = try self.source.stream(w, allowed);
        self.chunk_remaining -= n;
        if (self.chunk_remaining == 0) {
            // The CRLF that closes a chunk.
            _ = self.source.takeByte() catch return error.ReadFailed;
            _ = self.source.takeByte() catch return error.ReadFailed;
        }
        return n;
    }

    fn readChunkHeader(self: *BodyReader) std.Io.Reader.StreamError!usize {
        var line: [chunk_header_bytes_max]u8 = undefined;
        var fixed: std.Io.Writer = .fixed(&line);
        _ = self.source.streamDelimiterLimit(&fixed, '\n', .limited(line.len)) catch
            return error.ReadFailed;
        _ = self.source.takeByte() catch return error.ReadFailed;

        var text = std.mem.trimEnd(u8, fixed.buffered(), "\r");
        // Chunk extensions after a semicolon are permitted, and ignored.
        if (std.mem.indexOfScalar(u8, text, ';')) |index| text = text[0..index];
        if (text.len == 0) return error.ReadFailed;
        return std.fmt.parseInt(usize, text, 16) catch error.ReadFailed;
    }

    fn drainTrailers(self: *BodyReader) void {
        // Trailers end at a blank line. Bounded so a peer cannot keep us here.
        var lines: usize = 0;
        while (lines < trailer_lines_max) : (lines += 1) {
            var discard: [head_line_bytes_max]u8 = undefined;
            var fixed: std.Io.Writer = .fixed(&discard);
            _ = self.source.streamDelimiterLimit(&fixed, '\n', .limited(discard.len)) catch return;
            _ = self.source.takeByte() catch return;
            if (std.mem.trimEnd(u8, fixed.buffered(), "\r").len == 0) return;
        }
    }

    const chunk_header_bytes_max: usize = 64;
    const trailer_lines_max: usize = 64;
};

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// A TLS session, when Velo was built with TLS.
///
/// The whole body is comptime-gated exactly the way Velo gates its own, so a build
/// without TLS never reaches the OpenSSL import.
const TlsSession = if (velo.tls_enabled) struct {
    context: velo.tls.ClientContext,
    session: velo.tls.Session,
    host: [:0]const u8,
    read_buffer: []u8,
    write_buffer: []u8,
    session_reader: SessionReader,
    session_writer: SessionWriter,

    // Velo exports these directly; deriving them with `@TypeOf` was how the name
    // `ClientSession` went unnoticed — a wrong name inside an unanalyzed branch.
    const SessionReader = velo.tls.SessionReader;
    const SessionWriter = velo.tls.SessionWriter;

    fn connect(
        gpa: std.mem.Allocator,
        stream: std.Io.net.Stream,
        host: []const u8,
        insecure: bool,
    ) Error!TlsSession {
        const host_z = gpa.dupeZ(u8, host) catch return error.OutOfMemory;
        errdefer gpa.free(host_z);

        var context = velo.tls.ClientContext.init(!insecure, .http1_only) catch
            return error.ConnectionFailed;
        errdefer context.deinit();

        var session = context.connect(stream.socket.handle, host_z) catch
            return error.ConnectionFailed;
        errdefer session.deinit();

        const read_buffer = gpa.alloc(u8, connection_buffer_bytes) catch return error.OutOfMemory;
        errdefer gpa.free(read_buffer);
        const write_buffer = gpa.alloc(u8, connection_buffer_bytes) catch return error.OutOfMemory;

        var result: TlsSession = .{
            .context = context,
            .session = session,
            .host = host_z,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .session_reader = undefined,
            .session_writer = undefined,
        };
        result.session_reader = result.session.reader(result.read_buffer);
        result.session_writer = result.session.writer(result.write_buffer);
        return result;
    }

    fn deinit(self: *TlsSession, gpa: std.mem.Allocator) void {
        self.session.deinit();
        self.context.deinit();
        gpa.free(self.read_buffer);
        gpa.free(self.write_buffer);
        gpa.free(self.host);
    }

    fn reader(self: *TlsSession) *std.Io.Reader {
        return &self.session_reader.interface;
    }

    fn writer(self: *TlsSession) *std.Io.Writer {
        return &self.session_writer.interface;
    }
} else struct {
    fn connect(
        gpa: std.mem.Allocator,
        stream: std.Io.net.Stream,
        host: []const u8,
        insecure: bool,
    ) Error!TlsSession {
        _ = .{ gpa, stream, host, insecure };
        return error.TlsNotSupported;
    }

    fn deinit(self: *TlsSession, gpa: std.mem.Allocator) void {
        _ = .{ self, gpa };
    }

    fn reader(self: *TlsSession) *std.Io.Reader {
        _ = self;
        unreachable;
    }

    fn writer(self: *TlsSession) *std.Io.Writer {
        _ = self;
        unreachable;
    }
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const found = value orelse return null;
    return switch (found) {
        .object => |object| object,
        else => null,
    };
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseUrl splits authority, port and path" {
    const plain = try parseUrl("http://127.0.0.1:8787/mcp");
    try testing.expectEqualStrings("127.0.0.1", plain.host);
    try testing.expectEqual(@as(u16, 8787), plain.port);
    try testing.expectEqualStrings("/mcp", plain.path);
    try testing.expect(!plain.tls);

    // Default ports differ by scheme, and a missing path is the root.
    const secure = try parseUrl("https://mcp.example.com");
    try testing.expectEqual(@as(u16, 443), secure.port);
    try testing.expectEqualStrings("/", secure.path);
    try testing.expect(secure.tls);

    try testing.expectEqual(@as(u16, 80), (try parseUrl("http://a/b")).port);
}

test "parseUrl does not mistake an IPv6 literal's colons for a port" {
    const target = try parseUrl("http://[::1]:8080/mcp");
    try testing.expectEqual(@as(u16, 8080), target.port);
    // Two different strings, and the difference is load-bearing: the brackets are URL
    // syntax that no resolver accepts, while `Host:` has to keep them.
    try testing.expectEqualStrings("::1", target.host);
    try testing.expectEqualStrings("[::1]:8080", target.authority);

    const no_port = try parseUrl("http://[::1]/mcp");
    try testing.expectEqualStrings("::1", no_port.host);
    try testing.expectEqualStrings("[::1]", no_port.authority);
    try testing.expectEqual(@as(u16, 80), no_port.port);
}

test "parseUrl keeps the port in the authority a Host header carries" {
    // A non-default port belongs in `Host:`; dropping it misroutes on any server or
    // proxy that dispatches on the header.
    const target = try parseUrl("http://127.0.0.1:8787/mcp");
    try testing.expectEqualStrings("127.0.0.1", target.host);
    try testing.expectEqualStrings("127.0.0.1:8787", target.authority);

    // A default port is written as the URL gave it, which is to say not at all.
    const secure = try parseUrl("https://mcp.example.com/mcp");
    try testing.expectEqualStrings("mcp.example.com", secure.host);
    try testing.expectEqualStrings("mcp.example.com", secure.authority);
}

test "a host that is a name reaches the resolver rather than failing to parse" {
    // The regression this guards: `IpAddress.resolve` parses literals only, so a name
    // went straight to `ConnectionFailed`. `localhost` is enough to tell "the resolver
    // was consulted" from "the input was rejected as not-an-IP" — a refused connection
    // proves the lookup happened and returned an address.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 1 is reserved and nothing listens there, so the connect is expected to fail.
    // What matters is *how*: anything other than a name-validation failure means the
    // name was accepted and looked up, which is the behaviour that was missing.
    const result = connect(io, "localhost", 1);
    if (result) |stream| {
        stream.close(io);
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.InvalidHostName, error.NameTooLong => return err,
        else => {},
    }
}

test "parseUrl rejects anything that is not an absolute http URL" {
    try testing.expectError(error.InvalidUrl, parseUrl("/mcp"));
    try testing.expectError(error.InvalidUrl, parseUrl("ws://host/mcp"));
    try testing.expectError(error.InvalidUrl, parseUrl("http:///mcp"));
    try testing.expectError(error.InvalidUrl, parseUrl("http://host:notaport/mcp"));
}

test "parseStatus reads the code and rejects a non-HTTP head" {
    try testing.expectEqual(@as(u16, 200), try parseStatus("HTTP/1.1 200 OK"));
    try testing.expectEqual(@as(u16, 404), try parseStatus("HTTP/1.0 404 Not Found"));
    try testing.expectError(error.MalformedResponse, parseStatus("200 OK"));
    try testing.expectError(error.MalformedResponse, parseStatus("HTTP/1.1"));
}

/// Builds the headers a message would be sent with, without opening a connection.
fn headersOf(arena: std.mem.Allocator, message: []const u8, options: Options) ![]const [2][]const u8 {
    var transport: Transport = .init(testing.allocator, undefined, "http://localhost/mcp", options);
    return transport.headersFor(arena, message);
}

fn headerValue(headers: []const [2][]const u8, name: []const u8) ?[]const u8 {
    for (headers) |pair| {
        if (std.ascii.eqlIgnoreCase(pair[0], name)) return pair[1];
    }
    return null;
}

const request_meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientCapabilities\":{}}";

test "a request carries the headers the transport specification requires" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++ request_meta ++ "}}",
        .{},
    );

    try testing.expectEqualStrings(
        accept_value,
        headerValue(headers, http.header.accept).?,
    );
    try testing.expectEqualStrings(
        "application/json",
        headerValue(headers, http.header.content_type).?,
    );
    // Taken from the body, not from configuration: the server rejects a mismatch.
    try testing.expectEqualStrings(
        types.protocol_version,
        headerValue(headers, http.header.protocol_version).?,
    );
    try testing.expectEqualStrings("tools/list", headerValue(headers, http.header.method).?);
    // `tools/list` has no subject.
    try testing.expect(headerValue(headers, http.header.name) == null);
}

test "Mcp-Name is sent for exactly the three methods that define it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const cases = [_]struct { body: []const u8, expected: ?[]const u8 }{
        .{
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
                "\"name\":\"add\",\"arguments\":{}," ++ request_meta ++ "}}",
            .expected = "add",
        },
        .{
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{" ++
                "\"name\":\"greet\"," ++ request_meta ++ "}}",
            .expected = "greet",
        },
        .{
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{" ++
                "\"uri\":\"file:///a.md\"," ++ request_meta ++ "}}",
            .expected = "file:///a.md",
        },
        .{
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/list\",\"params\":{" ++
                request_meta ++ "}}",
            .expected = null,
        },
    };

    for (cases) |case| {
        const headers = try headersOf(arena.allocator(), case.body, .{});
        const actual = headerValue(headers, http.header.name);
        if (case.expected) |expected| {
            try testing.expectEqualStrings(expected, actual.?);
        } else {
            try testing.expect(actual == null);
        }
    }
}

test "an unsafe Mcp-Name is Base64-encoded with the sentinel" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{" ++
            "\"uri\":\"file:///caf\\u00e9.md\"," ++ request_meta ++ "}}",
        .{},
    );

    const name = headerValue(headers, http.header.name).?;
    try testing.expect(std.mem.startsWith(u8, name, "=?base64?"));
    // What the server will compare against is the decoded value.
    const decoded = try http.decodeHeaderValue(arena.allocator(), name);
    try testing.expectEqualStrings("file:///café.md", decoded);
}

test "a notification carries the version header but no method obligations" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{" ++
            "\"requestId\":1," ++ request_meta ++ "}}",
        .{},
    );
    try testing.expectEqualStrings(
        types.protocol_version,
        headerValue(headers, http.header.protocol_version).?,
    );
    try testing.expect(headerValue(headers, http.header.method) == null);
}

test "a body that does not parse is still posted, headers and all" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The server's `-32700` is more useful than a local guess about what was meant.
    const headers = try headersOf(arena.allocator(), "{not json", .{});
    try testing.expectEqualStrings(accept_value, headerValue(headers, http.header.accept).?);
    try testing.expect(headerValue(headers, http.header.method) == null);
}

/// A `tools/list` result carrying one annotated tool.
fn annotatedTools(arena: std.mem.Allocator) ![]const types.Tool {
    const schema =
        \\{"type":"object","properties":{
        \\"region":{"type":"string","x-mcp-header":"Region"},
        \\"rows":{"type":"integer","x-mcp-header":"Rows"},
        \\"dry_run":{"type":"boolean","x-mcp-header":"DryRun"},
        \\"query":{"type":"string"}}}
    ;
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, schema, .{});
    const tools = try arena.alloc(types.Tool, 2);
    tools[0] = .{ .name = "execute_sql", .inputSchema = .{ .value = parsed } };
    tools[1] = .{ .name = "plain", .inputSchema = .{ .value = .{ .object = .empty } } };
    return tools;
}

test "ParamHeaders learns the annotations from tools/list" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var known: ParamHeaders = .{};
    defer known.deinit(testing.allocator);
    try known.learn(testing.allocator, try annotatedTools(arena.allocator()));

    const mappings = known.find("execute_sql");
    try testing.expectEqual(@as(usize, 3), mappings.len);
    // A tool with no annotations is not recorded at all.
    try testing.expectEqual(@as(usize, 0), known.find("plain").len);
    try testing.expectEqual(@as(usize, 0), known.find("unknown").len);
}

test "learning again replaces what was known" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var known: ParamHeaders = .{};
    defer known.deinit(testing.allocator);
    try known.learn(testing.allocator, try annotatedTools(arena.allocator()));
    try testing.expect(known.find("execute_sql").len > 0);

    // A tool whose annotation was removed must stop being mirrored, so the list is the
    // whole answer rather than an addition to it.
    const plain = try arena.allocator().alloc(types.Tool, 1);
    plain[0] = .{ .name = "execute_sql", .inputSchema = .{ .value = .{ .object = .empty } } };
    try known.learn(testing.allocator, plain);
    try testing.expectEqual(@as(usize, 0), known.find("execute_sql").len);
}

test "Mcp-Param-* mirrors annotated arguments in the spec's formats" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var known: ParamHeaders = .{};
    defer known.deinit(testing.allocator);
    try known.learn(testing.allocator, try annotatedTools(arena.allocator()));

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"execute_sql\",\"arguments\":{\"region\":\"us-west1\",\"rows\":42," ++
            "\"dry_run\":true,\"query\":\"SELECT 1\"}," ++ request_meta ++ "}}",
        .{ .param_headers = &known },
    );

    try testing.expectEqualStrings("us-west1", headerValue(headers, "Mcp-Param-Region").?);
    try testing.expectEqualStrings("42", headerValue(headers, "Mcp-Param-Rows").?);
    // Lowercase, as the spec requires.
    try testing.expectEqualStrings("true", headerValue(headers, "Mcp-Param-DryRun").?);
    // Not annotated, so not mirrored.
    try testing.expect(headerValue(headers, "Mcp-Param-Query") == null);
}

test "an absent or null argument is not mirrored" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var known: ParamHeaders = .{};
    defer known.deinit(testing.allocator);
    try known.learn(testing.allocator, try annotatedTools(arena.allocator()));

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++
            "\"name\":\"execute_sql\",\"arguments\":{\"region\":null,\"query\":\"SELECT 1\"}," ++
            request_meta ++ "}}",
        .{ .param_headers = &known },
    );

    // The spec is explicit: for a null or absent parameter the client omits the header
    // and the server must not expect it.
    try testing.expect(headerValue(headers, "Mcp-Param-Region") == null);
    try testing.expect(headerValue(headers, "Mcp-Param-Rows") == null);
}

test "param headers are only mirrored for tools/call" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var known: ParamHeaders = .{};
    defer known.deinit(testing.allocator);
    try known.learn(testing.allocator, try annotatedTools(arena.allocator()));

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
            request_meta ++ "}}",
        .{ .param_headers = &known },
    );
    try testing.expect(headerValue(headers, "Mcp-Param-Region") == null);
}

test "extra headers are sent, which is how a token reaches the server" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const headers = try headersOf(
        arena.allocator(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{" ++
            request_meta ++ "}}",
        .{ .extra_headers = &.{.{ "Authorization", "Bearer t0ken" }} },
    );
    try testing.expectEqualStrings("Bearer t0ken", headerValue(headers, "Authorization").?);
}

test "renderHeaderValue covers the scalars and refuses the rest" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    try testing.expectEqualStrings("x", (try renderHeaderValue(gpa, .{ .string = "x" })).?);
    try testing.expectEqualStrings("-7", (try renderHeaderValue(gpa, .{ .integer = -7 })).?);
    try testing.expectEqualStrings("false", (try renderHeaderValue(gpa, .{ .bool = false })).?);
    try testing.expect(try renderHeaderValue(gpa, .null) == null);
    // A float would invite a formatting mismatch that reads as tampering; the server's
    // schema generator refuses to annotate one in the first place.
    try testing.expect(try renderHeaderValue(gpa, .{ .float = 1.5 }) == null);
    try testing.expect(try renderHeaderValue(gpa, .{ .object = .empty }) == null);
}

/// Reads a whole framed body into a buffer, for the framing tests.
fn drain(arena: std.mem.Allocator, raw: []const u8, framing: BodyReader.Framing) ![]const u8 {
    var source: std.Io.Reader = .fixed(raw);
    var body: BodyReader = .init(&source, framing);

    var allocating: std.Io.Writer.Allocating = .init(arena);
    _ = body.reader().streamRemaining(&allocating.writer) catch {};
    return allocating.written();
}

const Collected = struct {
    status: u16,
    messages: []const []const u8,
};

/// Collects every message a raw HTTP response yields.
fn messagesOf(arena: std.mem.Allocator, raw: []const u8) !Collected {
    return messagesOfLimited(arena, raw, jsonrpc.message_size_max);
}

/// The same, with the bound as a parameter, so a test can exceed it without allocating
/// 16 MiB to do it.
fn messagesOfLimited(arena: std.mem.Allocator, raw: []const u8, limit: usize) !Collected {
    var source: std.Io.Reader = .fixed(raw);
    var response: Response = try .read(&source, arena, limit);

    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    while (try response.next(arena, limit)) |message| {
        try list.append(arena, message);
    }
    return .{ .status = response.status, .messages = list.items };
}

test "a JSON response yields exactly one message" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}";
    const raw = try std.fmt.allocPrint(
        arena.allocator(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ body.len, body },
    );

    const result = try messagesOf(arena.allocator(), raw);
    try testing.expectEqual(@as(u16, 200), result.status);
    try testing.expectEqual(@as(usize, 1), result.messages.len);
    try testing.expectEqualStrings(body, result.messages[0]);
}

test "an SSE response yields its notifications then the reply" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    const notification = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}";
    const reply = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    // Each event in its own chunk, with the sizes computed rather than written out: a
    // hand-counted length that is wrong fails as "no events", which says nothing about
    // where the mistake is.
    const first = "data: " ++ notification ++ "\r\n\r\n";
    const second = "data: " ++ reply ++ "\r\n\r\n";
    const raw = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n{x}\r\n{s}\r\n0\r\n\r\n",
        .{ first.len, first, second.len, second },
    );

    const result = try messagesOf(gpa, raw);
    try testing.expectEqual(@as(usize, 2), result.messages.len);
    try testing.expectEqualStrings(notification, result.messages[0]);
    try testing.expectEqualStrings(reply, result.messages[1]);
}

test "a 400 body is delivered, because that is where the JSON-RPC error is" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The transport specification puts `-32020` and the unsupported-version error in the
    // body of a `400`. Swallowing it because of the status would turn a precise,
    // actionable failure into "the request failed".
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32020,\"message\":\"mismatch\"}}";
    const raw = try std.fmt.allocPrint(
        arena.allocator(),
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ body.len, body },
    );

    const result = try messagesOf(arena.allocator(), raw);
    try testing.expectEqual(@as(u16, 400), result.status);
    try testing.expectEqualStrings(body, result.messages[0]);
}

test "an empty body yields no messages" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // 202 for an accepted notification is the case that matters.
    const result = try messagesOf(
        arena.allocator(),
        "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n",
    );
    try testing.expectEqual(@as(u16, 202), result.status);
    try testing.expectEqual(@as(usize, 0), result.messages.len);
}

test "a body with neither length nor chunking runs to end of stream" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
    const result = try messagesOf(arena.allocator(), raw);
    try testing.expectEqualStrings("{\"a\":1}", result.messages[0]);
}

test "a 401 hands back the challenge, which is its only actionable content" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var source: std.Io.Reader = .fixed(
        "HTTP/1.1 401 Unauthorized\r\n" ++
            "WWW-Authenticate: Bearer resource_metadata=" ++
            "\"https://mcp.example.com/.well-known/oauth-protected-resource\"\r\n" ++
            "Content-Length: 0\r\n\r\n",
    );
    const response = try Response.read(&source, arena.allocator(), jsonrpc.message_size_max);
    try testing.expectEqual(@as(u16, 401), response.status);
    // Without this the client knows only that it was refused, and the specification's
    // whole discovery path starts from this parameter.
    try testing.expect(
        std.mem.indexOf(u8, response.challenge.?, "resource_metadata=") != null,
    );
}

test "the first WWW-Authenticate wins" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // A second copy must not be able to displace the real one.
    var source: std.Io.Reader = .fixed(
        "HTTP/1.1 403 Forbidden\r\n" ++
            "WWW-Authenticate: Bearer error=\"insufficient_scope\"\r\n" ++
            "WWW-Authenticate: Bearer error=\"invalid_token\"\r\n" ++
            "Content-Length: 0\r\n\r\n",
    );
    const response = try Response.read(&source, arena.allocator(), jsonrpc.message_size_max);
    try testing.expect(
        std.mem.indexOf(u8, response.challenge.?, "insufficient_scope") != null,
    );
}

test "a response with no challenge reports none rather than an empty one" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var source: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const response = try Response.read(&source, arena.allocator(), jsonrpc.message_size_max);
    try testing.expectEqual(@as(?[]const u8, null), response.challenge);
}

test "only 401 and 403 count as authorization refusals" {
    try testing.expect(authorizationRefusal(401));
    try testing.expect(authorizationRefusal(403));
    // 503 says the server could not check. A client that reauthorized here would throw
    // away a working token to fix a problem that is not its own.
    try testing.expect(!authorizationRefusal(503));
    try testing.expect(!authorizationRefusal(400));
    try testing.expect(!authorizationRefusal(200));
}

test "a transfer coding that cannot be undone is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Guessing here would corrupt the body silently.
    var source: std.Io.Reader = .fixed(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nrubbish",
    );
    try testing.expectError(
        error.MalformedResponse,
        Response.read(&source, arena.allocator(), jsonrpc.message_size_max),
    );
}

test "a declared length beyond the bound is refused before reading it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var source: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n");
    try testing.expectError(
        error.MessageTooLarge,
        Response.read(&source, arena.allocator(), 1024),
    );
}

test "a body with no declared length is still bounded" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // The two framings `Response.read` cannot refuse up front. A server sending them has
    // no obligation to stop, so the bound has to be applied to what arrives.
    const filler = try gpa.alloc(u8, 4096);
    @memset(filler, 'x');

    const closing = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{s}",
        .{filler},
    );
    try testing.expectError(error.MessageTooLarge, messagesOfLimited(gpa, closing, 1024));

    const chunked = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n0\r\n\r\n",
        .{ filler.len, filler },
    );
    try testing.expectError(error.MessageTooLarge, messagesOfLimited(gpa, chunked, 1024));

    // And a body that exactly fills the bound is accepted, which is what makes the
    // one-byte overshoot in `readAll` the right amount rather than an off-by-one.
    const exact = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{s}",
        .{filler},
    );
    const result = try messagesOfLimited(gpa, exact, filler.len);
    try testing.expectEqual(filler.len, result.messages[0].len);
}

test "a head made of nothing but headers is refused rather than buffered" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var head: std.ArrayListUnmanaged(u8) = .empty;
    try head.appendSlice(gpa, "HTTP/1.1 200 OK\r\n");
    for (0..head_lines_max + 1) |index| {
        try head.print(gpa, "X-Filler-{d}: value\r\n", .{index});
    }
    // No blank line, on purpose: a server that never sends one is exactly the case the
    // count guards against.
    var source: std.Io.Reader = .fixed(head.items);
    try testing.expectError(
        error.MalformedResponse,
        Response.read(&source, gpa, jsonrpc.message_size_max),
    );
}

test "a head that is not HTTP is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    for ([_][]const u8{
        "not a response\r\n\r\n",
        "HTTP/1.1 200 OK\r\nbroken header\r\n\r\n",
    }) |raw| {
        var source: std.Io.Reader = .fixed(raw);
        try testing.expectError(
            error.MalformedResponse,
            Response.read(&source, arena.allocator(), jsonrpc.message_size_max),
        );
    }
}

test "fuzz the response reader against arbitrary bytes" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var raw: [768]u8 = undefined;
            const len = smith.slice(&raw);

            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            // Any bytes at all must either be rejected or produce messages, without
            // crashing and without looping.
            _ = messagesOf(arena.allocator(), raw[0..len]) catch {};
        }
    }.run, .{});
}

test "a length-delimited body stops at its length" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Whatever follows belongs to the next response, not to this body.
    const decoded = try drain(arena.allocator(), "hello, world", .{ .length = 5 });
    try testing.expectEqualStrings("hello", decoded);
}

test "an empty length-delimited body reads as nothing" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("", try drain(arena.allocator(), "junk", .{ .length = 0 }));
}

test "chunk framing is removed" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const raw = "5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n";
    try testing.expectEqualStrings("hello, world", try drain(arena.allocator(), raw, .chunked));
}

test "chunk extensions and trailers are ignored" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const raw = "5;name=value\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n";
    try testing.expectEqualStrings("hello", try drain(arena.allocator(), raw, .chunked));
}

test "chunk sizes are hexadecimal" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // 0x10 is 16 bytes; reading it as decimal would truncate to ten.
    const raw = "10\r\n0123456789abcdef\r\n0\r\n\r\n";
    try testing.expectEqualStrings(
        "0123456789abcdef",
        try drain(arena.allocator(), raw, .chunked),
    );
}

test "an until-close body runs to the end of the stream" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "everything",
        try drain(arena.allocator(), "everything", .until_close),
    );
}

test "SSE events are decoded through chunk framing" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // A chunk boundary deliberately lands in the middle of an event: the two framings
    // are independent, and treating a chunk as an event boundary is the mistake this
    // guards against.
    const first = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progre";
    const second = "ss\",\"params\":{}}\r\n\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n";
    const raw = try std.fmt.allocPrint(
        arena.allocator(),
        "{x}\r\n{s}\r\n{x}\r\n{s}\r\n0\r\n\r\n",
        .{ first.len, first, second.len, second },
    );

    var source: std.Io.Reader = .fixed(raw);
    var body: BodyReader = .init(&source, .chunked);
    var decoder: sse.Decoder = .{ .reader = body.reader() };

    const notification = (try decoder.next(arena.allocator())).?;
    try testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}",
        notification,
    );
    const reply = (try decoder.next(arena.allocator())).?;
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", reply);
    try testing.expect((try decoder.next(arena.allocator())) == null);
}

test "a truncated chunked body ends rather than looping" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The declared size exceeds what arrived, which is what a dropped connection looks
    // like. Whatever was received is delivered and the stream ends.
    const decoded = try drain(arena.allocator(), "20\r\nshort", .chunked);
    try testing.expectEqualStrings("short", decoded);
}

test "fuzz the chunk decoder against arbitrary bodies" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var raw: [512]u8 = undefined;
            const len = smith.slice(&raw);

            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            // Any input at all must terminate without a crash. Correctness of the
            // decoded bytes is not the property under test here; not hanging is.
            _ = drain(arena.allocator(), raw[0..len], .chunked) catch {};
            _ = drain(arena.allocator(), raw[0..len], .until_close) catch {};
            _ = drain(arena.allocator(), raw[0..len], .{ .length = len }) catch {};
        }
    }.run, .{});
}

// --- the receive deadline, against a real socket ----------------------------

/// A server that takes the request and then answers on a schedule of its own.
///
/// Real sockets, because the deadline is the one thing here that a fixed buffer cannot
/// exercise: `Reader.fixed` never blocks, so every timing property is invisible to it.
const SlowServer = struct {
    port: u16,
    /// Milliseconds between the response's SSE events. Read as the gap *before* each one,
    /// so a server with no events waits forever, which is the failure under test.
    gap_ms: u32,
    /// How many SSE events to send. Zero means the request is accepted and never
    /// answered.
    events: usize,

    ready: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),
    /// Set by the test once it has what it needs, so a server holding a connection open
    /// on purpose still gets torn down.
    stop: std.atomic.Value(bool) = .init(false),

    fn fail(state: *SlowServer) void {
        state.failed.store(true, .release);
        state.ready.store(true, .release);
    }
};

fn slowServerThread(state: *SlowServer) void {
    // Its own allocator and runtime: this thread must not share the scheduler whose
    // blocking behaviour the test is measuring.
    const gpa = std.heap.page_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var address = std.Io.net.IpAddress.resolve(io, "127.0.0.1", state.port) catch
        return state.fail();
    var listener = address.listen(io, .{ .reuse_address = true }) catch return state.fail();
    defer listener.deinit(io);
    state.ready.store(true, .release);

    const connection = listener.accept(io) catch return state.fail();
    defer connection.close(io);

    // Read the request head to its blank line. Without this the test would prove only
    // that an unread socket blocks; the reported failure is a server that *received* the
    // request and then went quiet.
    var read_buffer: [4096]u8 = undefined;
    var request = connection.reader(io, &read_buffer);
    while (true) {
        const line = request.interface.takeDelimiterExclusive('\n') catch return state.fail();
        if (std.mem.trimEnd(u8, line, "\r").len == 0) break;
    }

    var write_buffer: [1024]u8 = undefined;
    var response = connection.writer(io, &write_buffer);
    const out = &response.interface;

    if (state.events > 0) {
        out.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n") catch return state.fail();
        out.flush() catch return state.fail();

        var sent: usize = 0;
        while (sent < state.events) : (sent += 1) {
            const gap: std.Io.Clock.Duration = .{
                .raw = .fromMilliseconds(state.gap_ms),
                .clock = .awake,
            };
            gap.sleep(io) catch return;

            const event = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\n\r\n";
            out.print("{x}\r\n{s}\r\n", .{ event.len, event }) catch return state.fail();
            out.flush() catch return state.fail();
        }
        out.writeAll("0\r\n\r\n") catch return state.fail();
        out.flush() catch return state.fail();
    }

    // Hold the connection open. Closing it would produce end-of-stream, which is the one
    // outcome that must not be confused with the deadline.
    while (!state.stop.load(.acquire)) {
        const tick: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(10), .clock = .awake };
        tick.sleep(io) catch return;
    }
}

/// Fixed ports, because `std.Io.net.Server` cannot be asked what it bound. Unusual enough
/// that a collision is a failure rather than a silent pass against something else.
const silent_test_port: u16 = 18493;
const chatty_test_port: u16 = 18494;

test "a server that takes the request and says nothing hits the deadline" {
    const state = try testing.allocator.create(SlowServer);
    defer testing.allocator.destroy(state);
    state.* = .{ .port = silent_test_port, .gap_ms = 0, .events = 0 };

    var thread = try std.Thread.spawn(.{}, slowServerThread, .{state});
    defer {
        state.stop.store(true, .release);
        thread.join();
    }
    while (!state.ready.load(.acquire)) std.Thread.yield() catch {};
    if (state.failed.load(.acquire)) return error.SkipZigTest;

    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const url = std.fmt.comptimePrint("http://127.0.0.1:{d}/mcp", .{silent_test_port});
    var transport: Transport = .init(testing.allocator, io, url, .{
        .receive_timeout_ms = 150,
    });
    defer transport.deinit();

    const started = std.Io.Clock.awake.now(io);
    // The deadline expires while the response head is being read, so `send` is where it
    // surfaces — `send` posts the body *and* reads the head. Without it this call never
    // returns, which is the whole of the reported bug.
    try testing.expectError(
        error.Timeout,
        transport.send("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"),
    );
    // Returning instantly would mean something else failed and got named `Timeout`.
    // Half the deadline, because a coarse clock may round the wait down.
    try testing.expect(started.untilNow(io, .awake).toMilliseconds() >= 75);
}

test "a server that keeps talking keeps its connection past the deadline" {
    // The property a subscription depends on: the deadline is a gap between bytes, not a
    // bound on the exchange. Three 100 ms gaps against a 400 ms deadline — each gap well
    // inside it, the total well past it — so an implementation that armed one deadline
    // for the whole response would fail here and only here.
    const state = try testing.allocator.create(SlowServer);
    defer testing.allocator.destroy(state);
    state.* = .{ .port = chatty_test_port, .gap_ms = 100, .events = 3 };

    var thread = try std.Thread.spawn(.{}, slowServerThread, .{state});
    defer {
        state.stop.store(true, .release);
        thread.join();
    }
    while (!state.ready.load(.acquire)) std.Thread.yield() catch {};
    if (state.failed.load(.acquire)) return error.SkipZigTest;

    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const url = std.fmt.comptimePrint("http://127.0.0.1:{d}/mcp", .{chatty_test_port});
    var transport: Transport = .init(testing.allocator, threaded.io(), url, .{
        .receive_timeout_ms = 400,
    });
    defer transport.deinit();

    try transport.send("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");

    var received: usize = 0;
    while (try transport.receive(arena.allocator())) |_| received += 1;
    try testing.expectEqual(@as(usize, 3), received);
}

// --- https, end to end -----------------------------------------------------

const velo_http = @import("velo_http.zig");
const registry_mod = @import("registry.zig");
const server_mod = @import("server.zig");
const context_mod = @import("context.zig");

fn tlsEchoTool(
    context: *context_mod.Context,
    args: struct { text: []const u8 },
) server_mod.Error!types.CallToolResult {
    return context.textResult(try context.print("over tls: {s}", .{args.text}));
}

const TlsServerState = struct {
    port: std.atomic.Value(u16) = .init(0),
    ready: std.atomic.Value(bool) = .init(false),
    unavailable: std.atomic.Value(bool) = .init(false),
    stop: std.atomic.Value(bool) = .init(false),
};

/// Serves the MCP endpoint over TLS on its own OS thread and runtime.
///
/// A thread, not an `io.async` task: OpenSSL's session calls block the thread they run
/// on, so a server sharing the client's runtime starves the workers the client needs.
/// Velo documents the same constraint for its own TLS tests.
fn tlsServerThread(state: *TlsServerState) void {
    if (!velo.tls_enabled) return;
    const gpa = std.heap.page_allocator;

    var registry = registry_mod.Registry.initComptime(gpa, .{
        registry_mod.tool("echo", tlsEchoTool, .{ .description = "Echoes over TLS." }),
    }) catch {
        state.unavailable.store(true, .release);
        state.ready.store(true, .release);
        return;
    };
    defer registry.deinit();

    const info: types.Implementation = .{ .name = "tls-round-trip", .version = "0.0.1" };
    const server: server_mod.Server = .init(&registry, info, .{});

    var mcp_state: velo_http.State = .init(gpa, &server, .{});
    var app: velo_http.App = undefined;
    app.init(&mcp_state);
    velo_http.mount(&app, "/mcp") catch {
        state.unavailable.store(true, .release);
        state.ready.store(true, .release);
        return;
    };

    var runtime = velo.Runtime.init(gpa, .{}) catch {
        state.unavailable.store(true, .release);
        state.ready.store(true, .release);
        return;
    };
    defer runtime.deinit();
    const io = runtime.io();

    // A fixed port rather than 0, because `serveTls` owns its listener and there is no
    // way to ask it what got bound. The client skips if it cannot connect, and the
    // number is unusual enough that a collision is a test failure rather than a
    // silent pass against something else.
    var address = velo.net.Address.parse("127.0.0.1", tls_test_port) catch return;
    state.ready.store(true, .release);
    app.serveTls(io, &address, "cert.pem", "key.pem", .{
        .listen = .{ .reuse_address = true, .connections_max = 4 },
        .serve = .{ .stop = &state.stop },
    }) catch {
        state.unavailable.store(true, .release);
    };
}

const tls_test_port: u16 = 18492;

/// Unblock a parked `accept` by connecting to it once and closing.
fn wakeAccept(io: velo.Io, port: u16) void {
    var address = std.Io.net.IpAddress.resolve(io, "127.0.0.1", port) catch return;
    const stream = std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream }) catch return;
    stream.close(io);
}

test "https: an MCP call round-trips over TLS" {
    if (!velo.tls_enabled) return error.SkipZigTest;
    // The certificate is a developer artifact, so its absence skips rather than fails.
    var probe = velo.tls.ServerContext.init("cert.pem", "key.pem") catch
        return error.SkipZigTest;
    probe.deinit();

    const state = try std.testing.allocator.create(TlsServerState);
    defer std.testing.allocator.destroy(state);
    state.* = .{};

    var runtime = try velo.Runtime.init(std.testing.allocator, .{});
    defer runtime.deinit();

    var thread = try std.Thread.spawn(.{}, tlsServerThread, .{state});
    // Teardown that works whichever way the test leaves: the accept loop parks inside
    // `accept` and cannot see the flag until it returns, so the flag is followed by one
    // throwaway connection to wake it. That is what `Listener.stopAccepting` does
    // internally, and it is not reachable here because `serveTls` owns its listener.
    //
    // An earlier version bounded the server with `accept_limit = 2` instead, matching
    // the two connections a passing run makes. It worked and it was wrong: the first
    // negative verification — a client that *rejects* the self-signed certificate —
    // then made the whole suite hang instead of fail, because the second connection
    // never came. A test that hangs on failure hides the failure it exists to report.
    defer {
        state.stop.store(true, .release);
        wakeAccept(runtime.io(), tls_test_port);
        thread.join();
    }
    while (!state.ready.load(.acquire)) std.atomic.spinLoopHint();
    if (state.unavailable.load(.acquire)) return error.SkipZigTest;

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/mcp", .{tls_test_port});

    var transport: Transport = .init(
        std.testing.allocator,
        runtime.io(),
        url,
        .{ .tls_insecure = true },
    );
    defer transport.deinit();

    var mcp_client: client_mod.Client = .init(
        transport.transport(),
        .{ .name = "tls-round-trip-client", .version = "0.0.1" },
        .{},
    );

    var arena_inst = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // `tools/list` first, because it is the request that proves the whole envelope
    // survived TLS: comptime-generated schema out, `_meta` in.
    const tools = try mcp_client.listTools(arena, .{});
    try std.testing.expectEqual(@as(usize, 1), tools.tools.len);
    try std.testing.expectEqualStrings("echo", tools.tools[0].name);

    var args: std.json.ObjectMap = .empty;
    try args.put(arena, "text", .{ .string = "hello" });
    const result = try mcp_client.callTool(arena, "echo", .{ .object = args }, .{});
    try std.testing.expect(!(result.isError orelse false));
    try std.testing.expectEqualStrings("over tls: hello", result.content[0].text.text);
}
