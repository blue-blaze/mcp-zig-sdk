//! The client: builds requests, correlates responses, decodes results.
//!
//! Like the server, it does no I/O of its own. A `Transport` moves bytes; the client
//! decides what bytes to send and what the answer means. That split is what lets the
//! same client talk over stdio to a subprocess and over HTTP to a remote endpoint.
//!
//! ## What replaces the handshake
//!
//! 2026-07-28 has no `initialize`, so there is no connected/disconnected state to
//! manage and no capabilities to remember. Instead every request carries its own
//! `_meta`: the protocol version it speaks, what the client can do, and who the
//! client is. The consequence for this type is that it holds almost nothing — an id
//! counter and configuration — and that calling `discover` is optional rather than
//! mandatory. A client that already knows what a server offers can skip it.
//!
//! ## Memory
//!
//! Every call takes an arena. The request, the reply bytes, the parsed JSON and the
//! decoded result all live in it, so a decoded `ListToolsResult` borrows from the
//! arena and stays valid exactly as long as it does. Nothing needs freeing
//! individually.

const std = @import("std");
const assert_mod = @import("assert");
const jsonrpc = @import("jsonrpc.zig");
const types = @import("types.zig");

const assert = assert_mod.assert;

/// Moves encoded messages to and from a peer.
///
/// The shape is "send one message, then read messages until the exchange is over",
/// which fits both transports without either compromising: on stdio `receive` reads
/// the next line of a long-lived duplex stream, and on Streamable HTTP it yields the
/// events of one response body. The client does not care which.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// `Unauthorized` is singled out for the same reason `UnsupportedProtocolVersion`
    /// is: it is a failure a client can act on by itself. Everything else a transport
    /// can hit is either fatal or a retry, whereas this one has a defined next step —
    /// read the challenge, obtain a token, send the same request again. Folding it into
    /// `TransportFailed` would hide the one refusal that is recoverable.
    ///
    /// A transport with no notion of authorization simply never returns it. stdio is
    /// such a transport, deliberately: the specification says a stdio server SHOULD NOT
    /// use OAuth, because the client started the process and can hand it credentials
    /// directly.
    pub const SendError = error{ TransportFailed, MessageTooLarge, Unauthorized, OutOfMemory };
    pub const ReceiveError = error{ TransportFailed, MessageTooLarge, OutOfMemory };

    pub const VTable = struct {
        /// Delivers one complete, framed message.
        send: *const fn (ptr: *anyopaque, message: []const u8) SendError!void,
        /// Reads the next inbound message, allocated in `arena`, or null when the
        /// peer has nothing more to say.
        receive: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
        ) ReceiveError!?[]const u8,
    };

    pub fn send(transport: Transport, message: []const u8) SendError!void {
        return transport.vtable.send(transport.ptr, message);
    }

    pub fn receive(
        transport: Transport,
        arena: std.mem.Allocator,
    ) ReceiveError!?[]const u8 {
        return transport.vtable.receive(transport.ptr, arena);
    }
};

/// Receives the notifications a server sends while serving a request.
///
/// A single entry point rather than one callback per kind: the set of notifications
/// grows with the protocol, and a client that switches on the method name keeps
/// working when it does.
pub const Observer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Called for each inbound notification, in arrival order.
        ///
        /// Returns nothing: a client that cannot handle a notification must still
        /// receive the response it is waiting for.
        notify: *const fn (ptr: *anyopaque, notification: jsonrpc.Notification) void,
    };

    pub fn notify(observer: Observer, notification: jsonrpc.Notification) void {
        observer.vtable.notify(observer.ptr, notification);
    }
};

/// Answers the elicitation requests a server sends inside an `InputRequiredResult`.
///
/// The application supplies this: only it knows how to reach the user. Everything the
/// spec requires of a client at this point is the application's responsibility —
/// showing which server is asking, displaying a URL in full before opening it, and
/// offering a real way to decline.
pub const Elicitor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Answers one request.
        ///
        /// Returning `decline` or `cancel` is a normal outcome, not a failure: a user
        /// who says no has answered. Returning an error means the client could not
        /// ask at all.
        elicit: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            key: []const u8,
            request: types.ElicitRequest,
        ) error{OutOfMemory}!types.ElicitResult,
    };

    pub fn elicit(
        elicitor: Elicitor,
        arena: std.mem.Allocator,
        key: []const u8,
        request: types.ElicitRequest,
    ) error{OutOfMemory}!types.ElicitResult {
        return elicitor.vtable.elicit(elicitor.ptr, arena, key, request);
    }
};

/// One round of a multi-round-trip exchange, as the server described it.
pub const InputRequired = struct {
    /// Server-assigned key -> request object. Absent when the server only wants a
    /// retry, which happens while an out-of-band interaction is still in progress.
    requests: ?std.json.ObjectMap,
    /// The state to echo back verbatim. Absent means send none.
    ///
    /// Opaque: a client must not inspect, parse or modify it. Doing so would couple
    /// it to one server's internal encoding, and tampering is exactly what the server
    /// is required to reject.
    state: ?[]const u8,

    /// Decodes it from a result payload.
    pub fn fromResult(result: std.json.Value) Error!InputRequired {
        const object = switch (result) {
            .object => |object| object,
            else => return error.Malformed,
        };

        const requests = if (object.get("inputRequests")) |value| switch (value) {
            .object => |map| map,
            else => return error.Malformed,
        } else null;

        const state = if (object.get("requestState")) |value| switch (value) {
            .string => |string| string,
            else => return error.Malformed,
        } else null;

        // The spec requires at least one. Neither would leave the client retrying an
        // unchanged request forever.
        if (requests == null and state == null) return error.Malformed;
        return .{ .requests = requests, .state = state };
    }
};

pub const Error = error{
    /// The transport could not deliver or read a message.
    TransportFailed,
    /// A message exceeded the protocol limit.
    MessageTooLarge,
    /// The peer's reply was not a well-formed JSON-RPC response.
    Malformed,
    /// The reply carries a `resultType` this SDK does not know, so the payload cannot
    /// be read. Only a server on a later revision produces one; `exchange` still
    /// returns the raw result for a caller willing to interpret it.
    UnsupportedResultType,
    /// The peer closed the exchange without answering.
    NoResponse,
    /// The server answered with a JSON-RPC error. Inspect `Call.failure` for it.
    RequestFailed,
    /// The server does not speak this revision. `Call.failure.data` carries the
    /// versions it does.
    UnsupportedProtocolVersion,
    /// The server needs more input before it can answer. Handled by the
    /// multi-round-trip flow rather than by retrying blindly.
    InputRequired,
    /// The server refused the request on authorization grounds. Ask the transport for
    /// the challenge it recorded, obtain or widen a token, and send the request again.
    Unauthorized,
    OutOfMemory,
};

/// Per-request knobs that map onto `_meta`.
pub const CallOptions = struct {
    /// Ask for `notifications/message` at this level or above.
    ///
    /// Absent means the server must not send any. There is no connection-wide
    /// setting in this revision, so this is per call by design: a client can ask for
    /// debug logging on the one tool invocation it is investigating.
    log_level: ?types.LoggingLevel = null,
    /// Ask for `notifications/progress`, tagged with this token.
    ///
    /// Absent means the server must not report progress. The client picks the token
    /// so it can correlate updates with the call that produced them.
    progress_token: ?types.ProgressToken = null,
    /// Extra `_meta` keys to pass through, for extensions and trace context.
    extra: ?std.json.ObjectMap = null,
};

/// A completed exchange, before the result is interpreted.
pub const Call = struct {
    /// The id the request went out with.
    id: jsonrpc.Id,
    /// The raw response, still in the arena.
    bytes: []const u8,
    /// The `result` member on success.
    result: ?std.json.Value,
    /// The `error` member on failure.
    failure: ?jsonrpc.ErrorObject,

    pub fn succeeded(call: Call) bool {
        return call.result != null;
    }
};

pub const Options = struct {
    /// What this client can do, sent on every request.
    ///
    /// It must describe what the client will actually honour: a server reads this to
    /// decide whether it may ask for elicitation, and answering that it can when it
    /// cannot leaves the server waiting for input that never arrives.
    capabilities: types.ClientCapabilities = .{},
    /// Who this client is. SHOULD be sent, so it defaults to on.
    include_client_info: bool = true,
    /// Where notifications received while awaiting a response are delivered.
    observer: ?Observer = null,
    /// How elicitation requests are answered.
    ///
    /// Absent means this client cannot elicit — and `capabilities` must say so, or a
    /// server will send requests that go unanswered and wait for a retry that never
    /// resolves.
    elicitor: ?Elicitor = null,
    /// Cap on how many requests one logical call may send, counting the first.
    ///
    /// The spec allows a server to ask repeatedly, so there is no protocol-level end
    /// to the loop. Without a bound, a server that always asks again would keep a
    /// client prompting the user indefinitely.
    ///
    /// The user is prompted at most `rounds_max - 1` times, since the last request is
    /// the one that gets no chance to be answered.
    rounds_max: usize = 8,
    /// Cap on how many messages may arrive before the response does.
    ///
    /// A server streaming progress is normal; a server streaming forever is not, and
    /// without a bound a client would wait for it indefinitely.
    messages_max: usize = 4096,
};

pub const Client = struct {
    transport: Transport,
    info: types.Implementation,
    options: Options,
    /// Monotonic request id. Never reused within a client's lifetime, so a late
    /// response from an abandoned request can always be told apart from a fresh one.
    next_id: i64 = 1,

    pub fn init(transport: Transport, info: types.Implementation, options: Options) Client {
        assert(info.name.len > 0);
        assert(info.version.len > 0);
        assert(options.messages_max > 0);
        return .{ .transport = transport, .info = info, .options = options };
    }

    // ---- Typed API -------------------------------------------------------

    /// Asks what the server offers.
    ///
    /// Optional in this revision — there is no handshake to complete — but it is how
    /// a client learns the server's protocol versions, capabilities and instructions,
    /// and how it discovers that it needs to speak a different revision.
    pub fn discover(
        client: *Client,
        arena: std.mem.Allocator,
        options: CallOptions,
    ) Error!types.DiscoverResult {
        return client.request(types.DiscoverResult, arena, types.method.discover, null, options);
    }

    pub const ListOptions = struct {
        /// Continue a previous listing. Pass the `nextCursor` from the last page.
        cursor: ?types.Cursor = null,
        call: CallOptions = .{},
    };

    pub fn listTools(
        client: *Client,
        arena: std.mem.Allocator,
        options: ListOptions,
    ) Error!types.ListToolsResult {
        return client.list(types.ListToolsResult, arena, types.method.tools_list, options);
    }

    pub fn listPrompts(
        client: *Client,
        arena: std.mem.Allocator,
        options: ListOptions,
    ) Error!types.ListPromptsResult {
        return client.list(types.ListPromptsResult, arena, types.method.prompts_list, options);
    }

    pub fn listResources(
        client: *Client,
        arena: std.mem.Allocator,
        options: ListOptions,
    ) Error!types.ListResourcesResult {
        return client.list(types.ListResourcesResult, arena, types.method.resources_list, options);
    }

    pub fn listResourceTemplates(
        client: *Client,
        arena: std.mem.Allocator,
        options: ListOptions,
    ) Error!types.ListResourceTemplatesResult {
        return client.list(
            types.ListResourceTemplatesResult,
            arena,
            types.method.resources_templates_list,
            options,
        );
    }

    /// Invokes a tool.
    ///
    /// `arguments` is passed through as-is, so a caller may build it with
    /// `std.json` or hand over a pre-encoded object. Note what is *not* an error
    /// here: a tool that ran and failed comes back as a successful result with
    /// `isError` set, because the model needs to see the failure.
    pub fn callTool(
        client: *Client,
        arena: std.mem.Allocator,
        name: []const u8,
        arguments: ?std.json.Value,
        options: CallOptions,
    ) Error!types.CallToolResult {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "name", .{ .string = name });
        if (arguments) |value| try params.put(arena, "arguments", value);

        return client.request(
            types.CallToolResult,
            arena,
            types.method.tools_call,
            .{ .object = params },
            options,
        );
    }

    pub fn getPrompt(
        client: *Client,
        arena: std.mem.Allocator,
        name: []const u8,
        arguments: ?std.json.Value,
        options: CallOptions,
    ) Error!types.GetPromptResult {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "name", .{ .string = name });
        if (arguments) |value| try params.put(arena, "arguments", value);

        return client.request(
            types.GetPromptResult,
            arena,
            types.method.prompts_get,
            .{ .object = params },
            options,
        );
    }

    pub fn readResource(
        client: *Client,
        arena: std.mem.Allocator,
        uri: []const u8,
        options: CallOptions,
    ) Error!types.ReadResourceResult {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "uri", .{ .string = uri });

        return client.request(
            types.ReadResourceResult,
            arena,
            types.method.resources_read,
            .{ .object = params },
            options,
        );
    }

    /// Asks for completions for one argument of a prompt or resource template.
    pub fn complete(
        client: *Client,
        arena: std.mem.Allocator,
        reference: types.CompletionReference,
        argument_name: []const u8,
        partial: []const u8,
        options: CallOptions,
    ) Error!types.CompleteResult {
        var ref: std.json.ObjectMap = .empty;
        switch (reference) {
            .prompt => |prompt| {
                try ref.put(arena, "type", .{ .string = "ref/prompt" });
                try ref.put(arena, "name", .{ .string = prompt.name });
            },
            .resource => |resource| {
                try ref.put(arena, "type", .{ .string = "ref/resource" });
                try ref.put(arena, "uri", .{ .string = resource.uri });
            },
        }

        var argument: std.json.ObjectMap = .empty;
        try argument.put(arena, "name", .{ .string = argument_name });
        try argument.put(arena, "value", .{ .string = partial });

        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "ref", .{ .object = ref });
        try params.put(arena, "argument", .{ .object = argument });

        return client.request(
            types.CompleteResult,
            arena,
            types.method.completion_complete,
            .{ .object = params },
            options,
        );
    }

    /// Sends a notification. Nothing comes back, by definition.
    pub fn notify(
        client: *Client,
        arena: std.mem.Allocator,
        method: []const u8,
        params: ?std.json.Value,
    ) Error!void {
        const notification: jsonrpc.Notification = .{ .method = method, .params = params };
        const bytes = try types.stringifyAlloc(arena, notification);
        client.transport.send(bytes) catch |err| return mapSendError(err);
    }

    /// Tells the server to stop working on a request.
    ///
    /// Advisory: the notification and the response race, so the response may already
    /// be on its way. A client that sends this must be prepared to discard a result
    /// that arrives anyway.
    pub fn cancel(
        client: *Client,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        reason: ?[]const u8,
    ) Error!void {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "requestId", switch (id) {
            .number => |number| .{ .integer = number },
            .string => |string| .{ .string = string },
        });
        if (reason) |text| try params.put(arena, "reason", .{ .string = text });

        return client.notify(
            arena,
            types.notification.cancelled,
            .{ .object = params },
        );
    }

    // ---- Request machinery -----------------------------------------------

    fn list(
        client: *Client,
        comptime T: type,
        arena: std.mem.Allocator,
        method: []const u8,
        options: ListOptions,
    ) Error!T {
        var params: std.json.ObjectMap = .empty;
        if (options.cursor) |cursor| try params.put(arena, "cursor", .{ .string = cursor });

        return client.request(T, arena, method, .{ .object = params }, options.call);
    }

    /// Sends a request and decodes the result.
    pub fn request(
        client: *Client,
        comptime T: type,
        arena: std.mem.Allocator,
        method: []const u8,
        params: ?std.json.Value,
        options: CallOptions,
    ) Error!T {
        const call = try client.exchange(arena, method, params, options);
        const result = call.result orelse return failureError(call.failure);

        // The result type has to be checked before the payload is trusted: an
        // `input_required` result shares none of the fields a complete one has, and
        // silently decoding it as complete would drop the server's request for input.
        switch (try mapDecode(types.resultTypeOf(result))) {
            .complete => {},
            .input_required => return error.InputRequired,
        }
        return mapDecode(types.decode(T, arena, result));
    }

    /// Sends a request, answering any input the server asks for, until it completes.
    ///
    /// This is the multi-round-trip flow. The server may answer with
    /// `input_required` instead of a result; when it does, this gathers the requested
    /// input, then retries *the original request* with the answers and the server's
    /// state attached. Each retry is an independent request with a fresh id, which is
    /// what the spec requires and what makes the pattern work against a stateless
    /// server behind a load balancer.
    ///
    /// Only `tools/call`, `prompts/get` and `resources/read` may take this path; the
    /// spec forbids the rest, so asking elsewhere is treated as a malformed reply.
    pub fn requestInteractive(
        client: *Client,
        comptime T: type,
        arena: std.mem.Allocator,
        method: []const u8,
        params: ?std.json.Value,
        options: CallOptions,
    ) Error!T {
        var round: usize = 0;
        var pending: ?InputRequired = null;

        while (round < client.options.rounds_max) : (round += 1) {
            // The first attempt carries the caller's params untouched; a retry adds
            // the previous round's answers to them.
            const attempt = if (pending) |required|
                try client.withInput(arena, params, required)
            else
                params;

            const call = try client.exchange(arena, method, attempt, options);
            const result = call.result orelse return failureError(call.failure);

            switch (try mapDecode(types.resultTypeOf(result))) {
                .complete => return mapDecode(types.decode(T, arena, result)),
                .input_required => {
                    if (!types.method.supportsInputRequired(method)) return error.Malformed;
                    pending = try InputRequired.fromResult(result);
                },
            }
        }
        // Out of rounds. The server is entitled to keep asking, so this is not
        // necessarily its fault — but a caller must not be left in the loop.
        return error.InputRequired;
    }

    /// Builds the params for a retry: the original ones, plus the answers and state.
    fn withInput(
        client: *Client,
        arena: std.mem.Allocator,
        params: ?std.json.Value,
        required: InputRequired,
    ) Error!std.json.Value {
        var merged: std.json.ObjectMap = .empty;

        if (params) |value| switch (value) {
            .object => |object| {
                var iterator = object.iterator();
                while (iterator.next()) |entry| {
                    // Anything left over from a previous round is replaced below.
                    if (std.mem.eql(u8, entry.key_ptr.*, "inputResponses")) continue;
                    if (std.mem.eql(u8, entry.key_ptr.*, "requestState")) continue;
                    try merged.put(arena, entry.key_ptr.*, entry.value_ptr.*);
                }
            },
            else => return error.Malformed,
        };

        if (required.requests) |requests| {
            const responses = try client.answer(arena, requests);
            try merged.put(arena, "inputResponses", .{ .object = responses });
        }
        if (required.state) |state| {
            // Echoed byte for byte. Any change is tampering as far as the server is
            // concerned, and it is required to reject it.
            try merged.put(arena, "requestState", .{ .string = state });
        }

        return .{ .object = merged };
    }

    /// Answers every request the server made.
    ///
    /// An unanswerable request is skipped rather than failing the call. The spec's
    /// guidance is for the server to ask again for what is missing, so a partial set
    /// of answers is a valid thing to send — and it is better than abandoning a flow
    /// because one of several requests used a mode this client does not implement.
    fn answer(
        client: *Client,
        arena: std.mem.Allocator,
        requests: std.json.ObjectMap,
    ) Error!std.json.ObjectMap {
        var responses: std.json.ObjectMap = .empty;

        var iterator = requests.iterator();
        while (iterator.next()) |entry| {
            const key = entry.key_ptr.*;
            const request_value = entry.value_ptr.*;

            const elicit_request = types.ElicitRequest.fromValue(request_value) catch |err| {
                switch (err) {
                    // Sampling or roots: permitted by the schema, not implemented
                    // here, and answering with a guess would be worse than silence.
                    error.Unsupported => continue,
                    error.Malformed => return error.Malformed,
                }
            };

            const elicitor = client.options.elicitor orelse continue;
            const result = try elicitor.elicit(arena, key, elicit_request);

            const encoded = try types.stringifyAlloc(arena, result);
            const parsed = std.json.parseFromSliceLeaky(
                std.json.Value,
                arena,
                encoded,
                .{},
            ) catch return error.OutOfMemory;
            try responses.put(arena, key, parsed);
        }

        return responses;
    }

    /// Invokes a tool, handling any input the server asks for along the way.
    pub fn callToolInteractive(
        client: *Client,
        arena: std.mem.Allocator,
        name: []const u8,
        arguments: ?std.json.Value,
        options: CallOptions,
    ) Error!types.CallToolResult {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "name", .{ .string = name });
        if (arguments) |value| try params.put(arena, "arguments", value);

        return client.requestInteractive(
            types.CallToolResult,
            arena,
            types.method.tools_call,
            .{ .object = params },
            options,
        );
    }

    /// Fetches a prompt, handling any input the server asks for along the way.
    pub fn getPromptInteractive(
        client: *Client,
        arena: std.mem.Allocator,
        name: []const u8,
        arguments: ?std.json.Value,
        options: CallOptions,
    ) Error!types.GetPromptResult {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "name", .{ .string = name });
        if (arguments) |value| try params.put(arena, "arguments", value);

        return client.requestInteractive(
            types.GetPromptResult,
            arena,
            types.method.prompts_get,
            .{ .object = params },
            options,
        );
    }

    /// Reads a resource, handling any input the server asks for along the way.
    pub fn readResourceInteractive(
        client: *Client,
        arena: std.mem.Allocator,
        uri: []const u8,
        options: CallOptions,
    ) Error!types.ReadResourceResult {
        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "uri", .{ .string = uri });

        return client.requestInteractive(
            types.ReadResourceResult,
            arena,
            types.method.resources_read,
            .{ .object = params },
            options,
        );
    }

    /// Sends a request and returns the raw exchange, without interpreting the result.
    ///
    /// The lower-level entry point: use it for methods this client has no typed
    /// wrapper for, and for flows that need to inspect `resultType` themselves.
    pub fn exchange(
        client: *Client,
        arena: std.mem.Allocator,
        method: []const u8,
        params: ?std.json.Value,
        options: CallOptions,
    ) Error!Call {
        const id = client.takeId();
        const bytes = try client.encodeRequest(arena, id, method, params, options);

        client.transport.send(bytes) catch |err| return mapSendError(err);
        return client.awaitResponse(arena, id);
    }

    fn takeId(client: *Client) jsonrpc.Id {
        const id = client.next_id;
        client.next_id += 1;
        return .{ .number = id };
    }

    /// Builds the request envelope, injecting the `_meta` every request must carry.
    fn encodeRequest(
        client: *const Client,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        method: []const u8,
        params: ?std.json.Value,
        options: CallOptions,
    ) Error![]const u8 {
        const meta: types.RequestMeta = .{
            .protocol_version = types.protocol_version,
            .capabilities = client.options.capabilities,
            .client_info = if (client.options.include_client_info) client.info else null,
            .log_level = options.log_level,
            .progress_token = options.progress_token,
            .extra = options.extra,
        };

        var out: std.Io.Writer.Allocating = .init(arena);
        const writer = &out.writer;

        writer.writeAll("{\"jsonrpc\":\"2.0\",\"id\":") catch return error.OutOfMemory;
        types.stringify(writer, id) catch return error.OutOfMemory;
        writer.writeAll(",\"method\":") catch return error.OutOfMemory;
        types.stringify(writer, method) catch return error.OutOfMemory;

        // `_meta` lives inside `params`, so params is always present even for methods
        // that take no arguments of their own.
        writer.writeAll(",\"params\":{\"_meta\":") catch return error.OutOfMemory;
        types.stringify(writer, meta) catch return error.OutOfMemory;

        if (params) |value| switch (value) {
            .object => |object| {
                var iterator = object.iterator();
                while (iterator.next()) |entry| {
                    // `_meta` is the client's to set; a caller-supplied one would
                    // produce a duplicate key.
                    if (std.mem.eql(u8, entry.key_ptr.*, "_meta")) continue;
                    writer.writeAll(",") catch return error.OutOfMemory;
                    types.stringify(writer, entry.key_ptr.*) catch return error.OutOfMemory;
                    writer.writeAll(":") catch return error.OutOfMemory;
                    types.stringify(writer, entry.value_ptr.*) catch return error.OutOfMemory;
                }
            },
            // JSON-RPC allows array params; MCP does not use them, and merging one
            // with `_meta` is not possible.
            else => return error.Malformed,
        };

        writer.writeAll("}}") catch return error.OutOfMemory;
        return out.written();
    }

    /// Reads messages until the response for `id` arrives, dispatching notifications
    /// along the way.
    fn awaitResponse(
        client: *const Client,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
    ) Error!Call {
        var seen: usize = 0;
        while (seen < client.options.messages_max) : (seen += 1) {
            const received = client.transport.receive(arena) catch |err| {
                return mapReceiveError(err);
            };
            const bytes = received orelse return error.NoResponse;

            const message = jsonrpc.parseLeaky(arena, bytes) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Malformed,
            };

            switch (message) {
                .notification => |notification| {
                    if (client.options.observer) |observer| observer.notify(notification);
                },
                .result_response => |response| {
                    // A response for some other id is not ours to interpret. Skipping
                    // rather than failing keeps a late reply to an abandoned request
                    // from breaking the one in progress.
                    if (!id.eql(response.id)) continue;
                    return .{
                        .id = id,
                        .bytes = bytes,
                        .result = response.result,
                        .failure = null,
                    };
                },
                .error_response => |response| {
                    const response_id = response.id orelse {
                        // An error with no id cannot be attributed, and the spec
                        // allows it only for messages that failed to parse — which
                        // means our request. Treating it as ours is the only useful
                        // reading.
                        return .{
                            .id = id,
                            .bytes = bytes,
                            .result = null,
                            .failure = response.@"error",
                        };
                    };
                    if (!id.eql(response_id)) continue;
                    return .{
                        .id = id,
                        .bytes = bytes,
                        .result = null,
                        .failure = response.@"error",
                    };
                },
                // A server has no reason to send us a request in this revision.
                .request => continue,
            }
        }
        return error.NoResponse;
    }
};

/// Maps a JSON-RPC error onto a client error, singling out the one a caller can act
/// on automatically.
fn failureError(failure: ?jsonrpc.ErrorObject) Error {
    const object = failure orelse return error.Malformed;
    if (object.code == jsonrpc.error_code.unsupported_protocol_version) {
        return error.UnsupportedProtocolVersion;
    }
    return error.RequestFailed;
}

fn mapSendError(err: Transport.SendError) Error {
    return switch (err) {
        error.TransportFailed => error.TransportFailed,
        error.MessageTooLarge => error.MessageTooLarge,
        error.Unauthorized => error.Unauthorized,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapReceiveError(err: Transport.ReceiveError) Error {
    return switch (err) {
        error.TransportFailed => error.TransportFailed,
        error.MessageTooLarge => error.MessageTooLarge,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapDecode(result: anytype) Error!@typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => error.Malformed,
        error.UnsupportedResultType => error.UnsupportedResultType,
    };
}

/// Collects notifications for inspection. Useful in tests and for a client that
/// wants to drain them after a call rather than react during it.
pub const CollectingObserver = struct {
    gpa: std.mem.Allocator,
    methods: std.ArrayListUnmanaged([]const u8) = .empty,
    payloads: std.ArrayListUnmanaged([]const u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) CollectingObserver {
        return .{ .gpa = gpa };
    }

    pub fn deinit(collector: *CollectingObserver) void {
        for (collector.methods.items) |method| collector.gpa.free(method);
        for (collector.payloads.items) |payload| collector.gpa.free(payload);
        collector.methods.deinit(collector.gpa);
        collector.payloads.deinit(collector.gpa);
    }

    pub fn observer(collector: *CollectingObserver) Observer {
        return .{ .ptr = collector, .vtable = &vtable };
    }

    const vtable: Observer.VTable = .{ .notify = notify };

    fn notify(ptr: *anyopaque, notification: jsonrpc.Notification) void {
        const collector: *CollectingObserver = @ptrCast(@alignCast(ptr));

        // Both the method and the params point into the call's arena, so they have to
        // be copied to outlive it.
        const method = collector.gpa.dupe(u8, notification.method) catch return;
        const payload = if (notification.params) |params|
            types.stringifyAlloc(collector.gpa, params) catch {
                collector.gpa.free(method);
                return;
            }
        else
            collector.gpa.dupe(u8, "null") catch {
                collector.gpa.free(method);
                return;
            };

        collector.methods.append(collector.gpa, method) catch {
            collector.gpa.free(method);
            collector.gpa.free(payload);
            return;
        };
        collector.payloads.append(collector.gpa, payload) catch {
            collector.gpa.free(payload);
            return;
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A transport backed by a scripted list of inbound messages.
const ScriptedTransport = struct {
    sent: std.ArrayListUnmanaged([]const u8) = .empty,
    inbound: []const []const u8,
    position: usize = 0,
    gpa: std.mem.Allocator,
    fail_send: bool = false,
    fail_receive: bool = false,

    fn init(gpa: std.mem.Allocator, inbound: []const []const u8) ScriptedTransport {
        return .{ .gpa = gpa, .inbound = inbound };
    }

    fn deinit(self: *ScriptedTransport) void {
        for (self.sent.items) |message| self.gpa.free(message);
        self.sent.deinit(self.gpa);
    }

    fn transport(self: *ScriptedTransport) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.VTable = .{ .send = send, .receive = receive };

    fn send(ptr: *anyopaque, message: []const u8) Transport.SendError!void {
        const self: *ScriptedTransport = @ptrCast(@alignCast(ptr));
        if (self.fail_send) return error.TransportFailed;
        const owned = try self.gpa.dupe(u8, message);
        errdefer self.gpa.free(owned);
        try self.sent.append(self.gpa, owned);
    }

    fn receive(ptr: *anyopaque, arena: std.mem.Allocator) Transport.ReceiveError!?[]const u8 {
        const self: *ScriptedTransport = @ptrCast(@alignCast(ptr));
        if (self.fail_receive) return error.TransportFailed;
        if (self.position == self.inbound.len) return null;
        defer self.position += 1;
        return try arena.dupe(u8, self.inbound[self.position]);
    }
};

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    transport: ScriptedTransport,
    client: Client,

    fn init(fixture: *Fixture, inbound: []const []const u8, options: Options) void {
        fixture.arena = .init(testing.allocator);
        fixture.transport = .init(testing.allocator, inbound);
        fixture.client = .init(
            fixture.transport.transport(),
            .{ .name = "test-client", .version = "1.0.0" },
            options,
        );
    }

    fn deinit(fixture: *Fixture) void {
        fixture.transport.deinit();
        fixture.arena.deinit();
    }

    fn allocator(fixture: *Fixture) std.mem.Allocator {
        return fixture.arena.allocator();
    }

    /// The last request the client put on the wire, parsed.
    fn lastSent(fixture: *Fixture) !std.json.ObjectMap {
        const sent = fixture.transport.sent.items;
        try testing.expect(sent.len > 0);
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            fixture.allocator(),
            sent[sent.len - 1],
            .{},
        );
        return parsed.object;
    }
};

test "every request carries the protocol version, capabilities and client identity" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":0,
        \\ "cacheScope":"private","tools":[]}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.listTools(fixture.allocator(), .{});

    const sent = try fixture.lastSent();
    try testing.expectEqualStrings("2.0", sent.get("jsonrpc").?.string);
    try testing.expectEqualStrings("tools/list", sent.get("method").?.string);

    // There is no handshake in this revision, so this `_meta` is the only place the
    // server learns any of it — on every single request.
    const meta = sent.get("params").?.object.get("_meta").?.object;
    try testing.expectEqualStrings(
        "2026-07-28",
        meta.get(types.meta_key.protocol_version).?.string,
    );
    try testing.expect(meta.get(types.meta_key.client_capabilities) != null);
    const info = meta.get(types.meta_key.client_info).?.object;
    try testing.expectEqualStrings("test-client", info.get("name").?.string);
    try testing.expectEqualStrings("1.0.0", info.get("version").?.string);
}

test "client identity can be withheld" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":0,
        \\ "cacheScope":"private","tools":[]}}
    }, .{ .include_client_info = false });
    defer fixture.deinit();

    _ = try fixture.client.listTools(fixture.allocator(), .{});

    // SHOULD, not MUST: capabilities stay because a server needs them to decide what
    // it may ask for.
    const meta = (try fixture.lastSent()).get("params").?.object.get("_meta").?.object;
    try testing.expect(meta.get(types.meta_key.client_info) == null);
    try testing.expect(meta.get(types.meta_key.client_capabilities) != null);
}

test "capabilities describe what the client will actually honour" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":0,
        \\ "cacheScope":"private","tools":[]}}
    }, .{ .capabilities = .{ .elicitation = .{ .object = .empty } } });
    defer fixture.deinit();

    _ = try fixture.client.listTools(fixture.allocator(), .{});

    const capabilities = (try fixture.lastSent()).get("params").?.object
        .get("_meta").?.object.get(types.meta_key.client_capabilities).?.object;
    try testing.expect(capabilities.get("elicitation") != null);
}

test "log level and progress token are opted into per call" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.callTool(fixture.allocator(), "x", null, .{
        .log_level = .debug,
        .progress_token = .{ .string = "tok" },
    });

    const meta = (try fixture.lastSent()).get("params").?.object.get("_meta").?.object;
    try testing.expectEqualStrings("debug", meta.get(types.meta_key.log_level).?.string);
    // Unprefixed, unlike the rest: the schema spells this one bare.
    try testing.expectEqualStrings("tok", meta.get("progressToken").?.string);
}

test "a call without opt-in asks for neither logs nor progress" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.callTool(fixture.allocator(), "x", null, .{});

    const meta = (try fixture.lastSent()).get("params").?.object.get("_meta").?.object;
    try testing.expect(meta.get(types.meta_key.log_level) == null);
    try testing.expect(meta.get("progressToken") == null);
}

test "request ids increase and are never reused" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}
        ,
        \\{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    for (0..3) |_| _ = try fixture.client.callTool(fixture.allocator(), "x", null, .{});

    // Reuse would make a late reply to an abandoned request indistinguishable from
    // the answer to a fresh one.
    for (fixture.transport.sent.items, 1..) |bytes, expected| {
        const parsed = try std.json.parseFromSliceLeaky(
            std.json.Value,
            fixture.allocator(),
            bytes,
            .{},
        );
        try testing.expectEqual(@as(i64, @intCast(expected)), parsed.object.get("id").?.integer);
    }
}

test "tool arguments are merged alongside _meta" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    var arguments: std.json.ObjectMap = .empty;
    try arguments.put(fixture.allocator(), "city", .{ .string = "Oslo" });

    _ = try fixture.client.callTool(
        fixture.allocator(),
        "get_forecast",
        .{ .object = arguments },
        .{},
    );

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("get_forecast", params.get("name").?.string);
    try testing.expectEqualStrings("Oslo", params.get("arguments").?.object.get("city").?.string);
    try testing.expect(params.get("_meta") != null);
}

test "discover decodes versions, capabilities and instructions" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":3600000,
        \\ "cacheScope":"public","supportedVersions":["2026-07-28"],
        \\ "capabilities":{"tools":{},"prompts":{"listChanged":true}},
        \\ "instructions":"Use add.",
        \\ "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"srv","version":"2"}}}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.discover(fixture.allocator(), .{});
    try testing.expectEqualStrings("2026-07-28", result.supportedVersions[0]);
    try testing.expect(result.capabilities.tools != null);
    try testing.expect(result.capabilities.prompts != null);
    try testing.expect(result.capabilities.resources == null);
    try testing.expectEqualStrings("Use add.", result.instructions.?);

    // The two wire fields fold back into one hint.
    try testing.expectEqual(@as(u64, 3_600_000), result.cache.ttl_ms);
    try testing.expectEqual(types.CacheScope.public, result.cache.scope);
    try testing.expectEqualStrings("srv", result.meta.?.server_info.?.name);
}

test "listTools decodes descriptors and their schemas" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":60000,
        \\ "cacheScope":"public","nextCursor":"add",
        \\ "tools":[{"name":"add","title":"Add","description":"Adds numbers.",
        \\  "inputSchema":{"type":"object","properties":{"a":{"type":"number"}}},
        \\  "annotations":{"readOnlyHint":true}}]}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.listTools(fixture.allocator(), .{});
    try testing.expectEqual(@as(usize, 1), result.tools.len);

    const tool = result.tools[0];
    try testing.expectEqualStrings("add", tool.name);
    try testing.expectEqualStrings("Add", tool.title.?);
    try testing.expectEqualStrings("Adds numbers.", tool.description.?);
    try testing.expectEqual(true, tool.annotations.?.readOnlyHint.?);
    try testing.expectEqualStrings(
        "object",
        tool.inputSchema.value.object.get("type").?.string,
    );
    try testing.expectEqualStrings("add", result.nextCursor.?);
}

test "a cursor is sent back to continue a listing" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":0,
        \\ "cacheScope":"private","tools":[]}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.listTools(fixture.allocator(), .{ .cursor = "add" });
    try testing.expectEqualStrings(
        "add",
        (try fixture.lastSent()).get("params").?.object.get("cursor").?.string,
    );
}

test "callTool decodes content blocks" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"42"},
        \\  {"type":"image","data":"aGk=","mimeType":"image/png"}],
        \\ "structuredContent":{"sum":42}}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.callTool(fixture.allocator(), "add", null, .{});
    try testing.expectEqual(@as(usize, 2), result.content.len);
    try testing.expectEqualStrings("42", result.content[0].text.text);
    try testing.expectEqualStrings("image/png", result.content[1].image.mimeType);
    try testing.expectEqual(@as(i64, 42), result.structuredContent.?.object.get("sum").?.integer);
    try testing.expect(result.isError == null);
}

test "a tool that failed is a successful call with isError set" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"cannot divide by zero"}],"isError":true}}
    }, .{});
    defer fixture.deinit();

    // The distinction that matters to a client: this is not an error to retry or
    // report as a transport problem, it is an answer the model needs to see.
    const result = try fixture.client.callTool(fixture.allocator(), "divide", null, .{});
    try testing.expectEqual(true, result.isError.?);
    try testing.expectEqualStrings("cannot divide by zero", result.content[0].text.text);
}

test "getPrompt decodes messages" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "description":"A greeting",
        \\ "messages":[{"role":"user","content":{"type":"text","text":"Hello"}}]}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.getPrompt(fixture.allocator(), "greet", null, .{});
    try testing.expectEqualStrings("A greeting", result.description.?);
    try testing.expectEqual(types.Role.user, result.messages[0].role);
    try testing.expectEqualStrings("Hello", result.messages[0].content.text.text);
}

test "readResource decodes text and binary contents" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":5000,
        \\ "cacheScope":"private",
        \\ "contents":[{"uri":"file:///a.md","text":"# A","mimeType":"text/markdown"},
        \\  {"uri":"file:///b.png","blob":"aGk=","mimeType":"image/png"}]}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.readResource(fixture.allocator(), "file:///a.md", .{});
    try testing.expectEqual(@as(usize, 2), result.contents.len);
    try testing.expectEqualStrings("# A", result.contents[0].text.text);
    try testing.expectEqualStrings("aGk=", result.contents[1].blob.blob);
    try testing.expectEqual(@as(u64, 5000), result.cache.ttl_ms);
}

test "complete decodes suggestions" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "completion":{"values":["zig","zsh"],"total":2,"hasMore":false}}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.complete(
        fixture.allocator(),
        .{ .prompt = .{ .name = "review" } },
        "language",
        "z",
        .{},
    );
    try testing.expectEqual(@as(usize, 2), result.completion.values.len);
    try testing.expectEqualStrings("zig", result.completion.values[0]);
    try testing.expectEqual(@as(i64, 2), result.completion.total.?);

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("ref/prompt", params.get("ref").?.object.get("type").?.string);
    try testing.expectEqualStrings("review", params.get("ref").?.object.get("name").?.string);
    try testing.expectEqualStrings("z", params.get("argument").?.object.get("value").?.string);
}

test "a resource template reference is encoded with its uri" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "completion":{"values":[]}}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.complete(
        fixture.allocator(),
        .{ .resource = .{ .uri = "file:///project/{path}" } },
        "path",
        "src/",
        .{},
    );

    const ref = (try fixture.lastSent()).get("params").?.object.get("ref").?.object;
    try testing.expectEqualStrings("ref/resource", ref.get("type").?.string);
    try testing.expectEqualStrings("file:///project/{path}", ref.get("uri").?.string);
}

test "notifications arriving before the response are dispatched in order" {
    var collector: CollectingObserver = .init(testing.allocator);
    defer collector.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","method":"notifications/progress",
        \\ "params":{"progressToken":"t","progress":1,"total":2}}
        ,
        \\{"jsonrpc":"2.0","method":"notifications/message",
        \\ "params":{"level":"info","data":"working"}}
        ,
        \\{"jsonrpc":"2.0","method":"notifications/progress",
        \\ "params":{"progressToken":"t","progress":2,"total":2}}
        ,
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"done"}]}}
    }, .{ .observer = collector.observer() });
    defer fixture.deinit();

    const result = try fixture.client.callTool(fixture.allocator(), "slow", null, .{
        .progress_token = .{ .string = "t" },
        .log_level = .info,
    });
    try testing.expectEqualStrings("done", result.content[0].text.text);

    try testing.expectEqual(@as(usize, 3), collector.methods.items.len);
    try testing.expectEqualStrings("notifications/progress", collector.methods.items[0]);
    try testing.expectEqualStrings("notifications/message", collector.methods.items[1]);
    try testing.expectEqualStrings("notifications/progress", collector.methods.items[2]);
    try testing.expect(std.mem.indexOf(u8, collector.payloads.items[0], "\"progress\":1") != null);
}

test "notifications are dropped without an observer" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","method":"notifications/message",
        \\ "params":{"level":"info","data":"nobody is listening"}}
        ,
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    // A client that does not care must still get its answer.
    _ = try fixture.client.callTool(fixture.allocator(), "x", null, .{});
}

test "a server error surfaces as a request failure" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unknown tool: nope"}}
    }, .{});
    defer fixture.deinit();

    try testing.expectError(
        error.RequestFailed,
        fixture.client.callTool(fixture.allocator(), "nope", null, .{}),
    );
}

test "a version mismatch is distinguishable from any other failure" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32022,
        \\ "message":"Unsupported protocol version",
        \\ "data":{"requested":"2026-07-28","supported":["2025-11-25"]}}}
    }, .{});
    defer fixture.deinit();

    // Its own error because it is the one failure a client can act on: read the
    // supported list and speak a different revision.
    try testing.expectError(
        error.UnsupportedProtocolVersion,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "the exchange helper exposes the error object for inspection" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32022,
        \\ "message":"Unsupported protocol version",
        \\ "data":{"requested":"2026-07-28","supported":["2025-11-25"]}}}
    }, .{});
    defer fixture.deinit();

    const call = try fixture.client.exchange(
        fixture.allocator(),
        types.method.tools_list,
        null,
        .{},
    );
    try testing.expect(!call.succeeded());
    try testing.expectEqual(@as(i32, -32022), call.failure.?.code);
    try testing.expectEqualStrings(
        "2025-11-25",
        call.failure.?.data.?.object.get("supported").?.array.items[0].string,
    );
}

test "an input_required result is not decoded as a complete one" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":[{"type":"elicitation","message":"Which city?"}],
        \\ "requestState":"opaque-state"}}
    }, .{});
    defer fixture.deinit();

    // Decoding it as complete would silently drop the server's request for input.
    try testing.expectError(
        error.InputRequired,
        fixture.client.callTool(fixture.allocator(), "forecast", null, .{}),
    );
}

test "a response for another id does not satisfy the wait" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        // A late reply to a request that was abandoned.
        \\{"jsonrpc":"2.0","id":99,"result":{"resultType":"complete","content":[]}}
        ,
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"mine"}]}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.callTool(fixture.allocator(), "x", null, .{});
    try testing.expectEqualStrings("mine", result.content[0].text.text);
}

test "a closed stream with no response is reported as such" {
    var fixture: Fixture = undefined;
    fixture.init(&.{}, .{});
    defer fixture.deinit();

    try testing.expectError(
        error.NoResponse,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "a flood of notifications cannot make a client wait forever" {
    // A hundred notifications and no response, with a limit of ten.
    const inbound = [_][]const u8{
        \\{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"x"}}
    } ** 100;

    var fixture: Fixture = undefined;
    fixture.init(&inbound, .{ .messages_max = 10 });
    defer fixture.deinit();

    try testing.expectError(
        error.NoResponse,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "a malformed reply is reported rather than misread" {
    var fixture: Fixture = undefined;
    fixture.init(&.{"{not json"}, .{});
    defer fixture.deinit();

    try testing.expectError(
        error.Malformed,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "a result missing resultType reads as complete" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","inputSchema":{"type":"object"}}]}}
    }, .{});
    defer fixture.deinit();

    // A server on an earlier revision sends no `resultType`, and the schema makes
    // reading that as `complete` a client MUST — not an option a single-revision
    // client may decline. Rejecting it here is what made this SDK unable to talk to
    // any deployed server, so the tolerance is pinned by a test rather than left to
    // the next reader's judgement.
    const listed = try fixture.client.listTools(fixture.allocator(), .{});
    try testing.expectEqual(@as(usize, 1), listed.tools.len);
    try testing.expectEqualStrings("search", listed.tools[0].name);
}

test "an unknown resultType is refused separately from a malformed one" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"partial","tools":[]}}
    }, .{});
    defer fixture.deinit();

    // Tolerating absence must not become tolerating anything: a `resultType` this SDK
    // does not know comes from a later revision, whose payload shape is unknown. The
    // separate error is what tells a caller the fix is a newer SDK rather than a
    // corrected peer.
    try testing.expectError(
        error.UnsupportedResultType,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "input_required is still explicit when resultType is absent elsewhere" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":[]}}
    }, .{});
    defer fixture.deinit();

    // The reason defaulting a missing field is safe: an interim result is only ever
    // reached by a server that named it, so the tolerant path cannot silently turn one
    // into a complete result. `listTools` cannot take that path at all, so the request
    // is refused rather than decoded as an empty listing.
    try testing.expectError(
        error.InputRequired,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "a result of the wrong shape is malformed rather than silently empty" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":"not an array"}}
    }, .{});
    defer fixture.deinit();

    try testing.expectError(
        error.Malformed,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
}

test "transport failures propagate" {
    {
        var fixture: Fixture = undefined;
        fixture.init(&.{}, .{});
        defer fixture.deinit();
        fixture.transport.fail_send = true;
        try testing.expectError(
            error.TransportFailed,
            fixture.client.listTools(fixture.allocator(), .{}),
        );
    }
    {
        var fixture: Fixture = undefined;
        fixture.init(&.{}, .{});
        defer fixture.deinit();
        fixture.transport.fail_receive = true;
        try testing.expectError(
            error.TransportFailed,
            fixture.client.listTools(fixture.allocator(), .{}),
        );
    }
}

test "unknown fields in a reply are ignored" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":0,
        \\ "cacheScope":"private","somethingNew":true,
        \\ "tools":[{"name":"add","inputSchema":{},"futureField":42}]}}
    }, .{});
    defer fixture.deinit();

    // The spec allows a server to add fields, so rejecting them would break this
    // client against the next revision.
    const result = try fixture.client.listTools(fixture.allocator(), .{});
    try testing.expectEqualStrings("add", result.tools[0].name);
}

test "cache hints missing from a reply mean do not cache" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.listTools(fixture.allocator(), .{});
    // Leniency has to fall the safe way: an omission must not be read as permission
    // to cache indefinitely.
    try testing.expectEqual(@as(u64, 0), result.cache.ttl_ms);
    try testing.expectEqual(types.CacheScope.private, result.cache.scope);
}

test "a cancellation names the request it cancels" {
    var fixture: Fixture = undefined;
    fixture.init(&.{}, .{});
    defer fixture.deinit();

    try fixture.client.cancel(fixture.allocator(), .{ .number = 7 }, "user pressed stop");

    const sent = try fixture.lastSent();
    try testing.expectEqualStrings("notifications/cancelled", sent.get("method").?.string);
    try testing.expect(sent.get("id") == null);

    const params = sent.get("params").?.object;
    try testing.expectEqual(@as(i64, 7), params.get("requestId").?.integer);
    try testing.expectEqualStrings("user pressed stop", params.get("reason").?.string);
}

test "extra _meta keys are passed through" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}
    }, .{});
    defer fixture.deinit();

    var extra: std.json.ObjectMap = .empty;
    try extra.put(fixture.allocator(), "traceparent", .{ .string = "00-abc-def-01" });

    _ = try fixture.client.listTools(fixture.allocator(), .{ .call = .{ .extra = extra } });

    const meta = (try fixture.lastSent()).get("params").?.object.get("_meta").?.object;
    try testing.expectEqualStrings("00-abc-def-01", meta.get("traceparent").?.string);
    // The protocol keys are still there.
    try testing.expect(meta.get(types.meta_key.protocol_version) != null);
}

test "a caller-supplied _meta cannot displace the protocol's" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    var params: std.json.ObjectMap = .empty;
    try params.put(fixture.allocator(), "_meta", .{ .string = "hijacked" });
    try params.put(fixture.allocator(), "name", .{ .string = "x" });

    _ = try fixture.client.request(
        types.CallToolResult,
        fixture.allocator(),
        types.method.tools_call,
        .{ .object = params },
        .{},
    );

    // Duplicating the key would produce a message no parser accepts, so the
    // caller's copy is dropped.
    const sent = try fixture.lastSent();
    try testing.expect(sent.get("params").?.object.get("_meta").? == .object);
}

test "every request the client emits is well-formed JSON-RPC" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":[],
        \\ "capabilities":{}}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[]}}
        ,
        \\{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","prompts":[]}}
        ,
        \\{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","resources":[]}}
        ,
        \\{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","resourceTemplates":[]}}
        ,
        \\{"jsonrpc":"2.0","id":6,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    const arena = fixture.allocator();
    _ = try fixture.client.discover(arena, .{});
    _ = try fixture.client.listTools(arena, .{});
    _ = try fixture.client.listPrompts(arena, .{});
    _ = try fixture.client.listResources(arena, .{});
    _ = try fixture.client.listResourceTemplates(arena, .{});
    _ = try fixture.client.callTool(arena, "x", null, .{});

    // Re-parsing as a JSON-RPC message checks the envelope, the id and the params
    // merge in one go.
    for (fixture.transport.sent.items) |bytes| {
        const message = try jsonrpc.parseLeaky(arena, bytes);
        try testing.expect(message == .request);
        // No embedded newline, so the same bytes are safe on a line-delimited
        // transport.
        try testing.expect(std.mem.indexOfScalar(u8, bytes, '\n') == null);
    }
}

test "fuzz the client against arbitrary server replies" {
    const Fuzz = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var buffer: [1024]u8 = undefined;
            const length = smith.slice(&buffer);

            var fixture: Fixture = undefined;
            fixture.init(&.{buffer[0..length]}, .{});
            defer fixture.deinit();

            // Any error is acceptable; a crash or a leak is not.
            _ = fixture.client.listTools(fixture.allocator(), .{}) catch return;
        }
    };
    try testing.fuzz(Fuzz{}, Fuzz.testOne, .{});
}

// ---------------------------------------------------------------------------
// Multi-round-trip requests
// ---------------------------------------------------------------------------

/// Answers elicitations with a scripted reply, and records what it was asked.
const ScriptedElicitor = struct {
    gpa: std.mem.Allocator,
    action: types.ElicitAction = .accept,
    /// The value to put in `content` under `answer`, for form requests.
    answer: []const u8 = "octocat",
    /// What the server asked, in order.
    seen_keys: std.ArrayListUnmanaged([]const u8) = .empty,
    seen_modes: std.ArrayListUnmanaged(types.ElicitMode) = .empty,
    seen_messages: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *ScriptedElicitor) void {
        for (self.seen_keys.items) |key| self.gpa.free(key);
        for (self.seen_messages.items) |message| self.gpa.free(message);
        self.seen_keys.deinit(self.gpa);
        self.seen_modes.deinit(self.gpa);
        self.seen_messages.deinit(self.gpa);
    }

    fn elicitor(self: *ScriptedElicitor) Elicitor {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Elicitor.VTable = .{ .elicit = elicit };

    fn elicit(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        key: []const u8,
        request: types.ElicitRequest,
    ) error{OutOfMemory}!types.ElicitResult {
        const self: *ScriptedElicitor = @ptrCast(@alignCast(ptr));

        // The request lives in the call's arena, so anything kept has to be copied.
        try self.seen_keys.append(self.gpa, try self.gpa.dupe(u8, key));
        try self.seen_modes.append(self.gpa, request.mode());
        try self.seen_messages.append(self.gpa, try self.gpa.dupe(u8, switch (request) {
            .form => |form| form.message,
            .url => |url| url.message,
        }));

        if (self.action != .accept) return .{ .action = self.action };

        // URL mode answers with consent only: the data never passes through here.
        if (request == .url) return .{ .action = .accept };

        var content: std.json.ObjectMap = .empty;
        try content.put(arena, "answer", .{ .string = self.answer });
        return .{ .action = .accept, .content = .{ .object = content } };
    }
};

/// A bare `elicitation: {}`, which the spec defines as form mode only.
const elicitation_capable: types.ClientCapabilities = .{
    .elicitation = .{ .object = .empty },
};

test "an input_required result is answered and the request retried" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        // Round one: the server asks.
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"github_login":{"method":"elicitation/create",
        \\  "params":{"mode":"form","message":"Please provide your GitHub username",
        \\   "requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},
        \\    "required":["answer"]}}}},
        \\ "requestState":"AEAD-protected blob"}}
        ,
        // Round two: it answers.
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"hello octocat"}]}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    const result = try fixture.client.callToolInteractive(
        fixture.allocator(),
        "greet_github_user",
        null,
        .{},
    );
    try testing.expectEqualStrings("hello octocat", result.content[0].text.text);

    // The elicitation reached the application with its key, mode and message intact.
    try testing.expectEqual(@as(usize, 1), elicitor.seen_keys.items.len);
    try testing.expectEqualStrings("github_login", elicitor.seen_keys.items[0]);
    try testing.expectEqual(types.ElicitMode.form, elicitor.seen_modes.items[0]);
    try testing.expectEqualStrings(
        "Please provide your GitHub username",
        elicitor.seen_messages.items[0],
    );

    // Two requests went out, and the retry is a distinct request.
    try testing.expectEqual(@as(usize, 2), fixture.transport.sent.items.len);

    const retry = try fixture.lastSent();
    // The id MUST differ: the spec treats the retry as an independent request.
    try testing.expectEqual(@as(i64, 2), retry.get("id").?.integer);

    const params = retry.get("params").?.object;
    // The original params are still there.
    try testing.expectEqualStrings("greet_github_user", params.get("name").?.string);
    // The state is echoed byte for byte.
    try testing.expectEqualStrings("AEAD-protected blob", params.get("requestState").?.string);

    const answered = params.get("inputResponses").?.object.get("github_login").?.object;
    try testing.expectEqualStrings("accept", answered.get("action").?.string);
    try testing.expectEqualStrings("octocat", answered.get("content").?.object.get("answer").?.string);
}

test "a declined elicitation is reported to the server rather than failing the call" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator, .action = .decline };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"confirm":{"method":"elicitation/create",
        \\  "params":{"mode":"form","message":"Delete everything?",
        \\   "requestedSchema":{"type":"object","properties":{}}}}}}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"cancelled"}],"isError":true}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    // A user saying no is an answer, not an error: the server needs to hear it so it
    // can stop.
    const result = try fixture.client.callToolInteractive(
        fixture.allocator(),
        "delete_all",
        null,
        .{},
    );
    try testing.expectEqual(true, result.isError.?);

    const answered = (try fixture.lastSent()).get("params").?.object
        .get("inputResponses").?.object.get("confirm").?.object;
    try testing.expectEqualStrings("decline", answered.get("action").?.string);
    // No content alongside a decline.
    try testing.expect(answered.get("content") == null);
}

test "a url elicitation answers with consent and no content" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    // Declaring url support explicitly: a bare `{}` means form only, so a client that
    // intends to open URLs has to say so or servers will never send them. Populated
    // before the capability is copied into the options.
    var url_modes: std.json.ObjectMap = .empty;
    defer url_modes.deinit(testing.allocator);
    try url_modes.put(testing.allocator, "form", .{ .object = .empty });
    try url_modes.put(testing.allocator, "url", .{ .object = .empty });

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"connect":{"method":"elicitation/create",
        \\  "params":{"mode":"url","message":"Connect your GitHub account.",
        \\   "url":"https://mcp.example.com/connect"}}},
        \\ "requestState":"state-1"}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"connected"}]}}
    }, .{
        .capabilities = .{ .elicitation = .{ .object = url_modes } },
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    _ = try fixture.client.callToolInteractive(fixture.allocator(), "connect", null, .{});

    try testing.expectEqual(types.ElicitMode.url, elicitor.seen_modes.items[0]);

    const answered = (try fixture.lastSent()).get("params").?.object
        .get("inputResponses").?.object.get("connect").?.object;
    try testing.expectEqualStrings("accept", answered.get("action").?.string);
    // The whole point of url mode: nothing the user entered comes back through the
    // client.
    try testing.expect(answered.get("content") == null);
}

test "a state-only result is retried immediately with nothing to ask" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        // No inputRequests: the server is waiting on something out of band and just
        // wants to be asked again.
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "requestState":"waiting-for-oauth"}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"done"}]}}
    }, .{});
    defer fixture.deinit();

    const result = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});
    try testing.expectEqualStrings("done", result.content[0].text.text);

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("waiting-for-oauth", params.get("requestState").?.string);
    // Nothing was asked, so nothing is answered.
    try testing.expect(params.get("inputResponses") == null);
}

test "no requestState in the result means none in the retry" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"k":{"method":"elicitation/create",
        \\  "params":{"message":"?","requestedSchema":{"type":"object","properties":{}}}}}}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    _ = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});

    // The spec is explicit: the client MUST NOT invent one.
    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expect(params.get("requestState") == null);
    try testing.expect(params.get("inputResponses") != null);
}

test "a request with no mode is treated as form mode" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        // Servers written against the revision with a single mode omit the field.
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"k":{"method":"elicitation/create",
        \\  "params":{"message":"Your name?",
        \\   "requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}}}}}}}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    _ = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});
    try testing.expectEqual(types.ElicitMode.form, elicitor.seen_modes.items[0]);
}

/// One `input_required` round, for the given request id.
///
/// The id must match the request it answers: a reply for an unknown id is skipped as a
/// late response to something abandoned, which is right in general but would desync a
/// scripted test.
fn askAgain(comptime id: []const u8) []const u8 {
    return "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"result\":{" ++
        "\"resultType\":\"input_required\",\"inputRequests\":{\"k\":{" ++
        "\"method\":\"elicitation/create\",\"params\":{\"message\":\"again?\"," ++
        "\"requestedSchema\":{\"type\":\"object\",\"properties\":{}}}}}," ++
        "\"requestState\":\"s\"}}";
}

test "several rounds are followed until the server is satisfied" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        askAgain("1"), askAgain("2"), askAgain("3"),
        \\{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete",
        \\ "content":[{"type":"text","text":"finally"}]}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    // A server may ask repeatedly; the spec allows it, so a client has to follow.
    const result = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});
    try testing.expectEqualStrings("finally", result.content[0].text.text);
    try testing.expectEqual(@as(usize, 3), elicitor.seen_keys.items.len);
}

test "a server that never stops asking cannot loop the client forever" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{ askAgain("1"), askAgain("2"), askAgain("3"), askAgain("4") }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
        .rounds_max = 3,
    });
    defer fixture.deinit();

    try testing.expectError(
        error.InputRequired,
        fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{}),
    );
    // Bounded: three requests went out and the user was prompted twice, even though
    // the server had a fourth round ready. The last request is never answered, which
    // is why prompts are one fewer than rounds.
    try testing.expectEqual(@as(usize, 3), fixture.transport.sent.items.len);
    try testing.expectEqual(@as(usize, 2), elicitor.seen_keys.items.len);
}

test "input_required on a method that may not use it is malformed" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "requestState":"s"}}
    }, .{});
    defer fixture.deinit();

    // The spec permits this on exactly three methods. Retrying a listing with extra
    // input cannot converge, so following the server here would only produce a loop.
    try testing.expectError(
        error.Malformed,
        fixture.client.requestInteractive(
            types.ListToolsResult,
            fixture.allocator(),
            types.method.tools_list,
            null,
            .{},
        ),
    );
}

test "an input_required result with neither field is malformed" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}
    }, .{});
    defer fixture.deinit();

    // With neither, the client has nothing to change and would retry the identical
    // request forever.
    try testing.expectError(
        error.Malformed,
        fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{}),
    );
}

test "an unimplementable input request is skipped rather than failing the call" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{
        \\  "sample":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}},
        \\  "ask":{"method":"elicitation/create",
        \\   "params":{"message":"?","requestedSchema":{"type":"object","properties":{}}}}}}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    _ = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});

    // Sampling is not implemented here, so it goes unanswered — and the spec says a
    // server should ask again for what is missing rather than treat it as an error.
    // Abandoning the whole flow over it would be worse.
    const responses = (try fixture.lastSent()).get("params").?.object
        .get("inputResponses").?.object;
    try testing.expect(responses.get("ask") != null);
    try testing.expect(responses.get("sample") == null);
}

test "stale input from a previous round is replaced, not accumulated" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"first":{"method":"elicitation/create",
        \\  "params":{"message":"one","requestedSchema":{"type":"object","properties":{}}}}},
        \\ "requestState":"state-one"}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"input_required",
        \\ "inputRequests":{"second":{"method":"elicitation/create",
        \\  "params":{"message":"two","requestedSchema":{"type":"object","properties":{}}}}},
        \\ "requestState":"state-two"}}
        ,
        \\{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","content":[]}}
    }, .{
        .capabilities = elicitation_capable,
        .elicitor = elicitor.elicitor(),
    });
    defer fixture.deinit();

    _ = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});

    const params = (try fixture.lastSent()).get("params").?.object;
    // Only the latest round's state and answers: carrying the first round's along
    // would present state the server already consumed.
    try testing.expectEqualStrings("state-two", params.get("requestState").?.string);
    const responses = params.get("inputResponses").?.object;
    try testing.expect(responses.get("second") != null);
    try testing.expect(responses.get("first") == null);
}

test "a client with no elicitor sends no answers" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"k":{"method":"elicitation/create",
        \\  "params":{"message":"?","requestedSchema":{"type":"object","properties":{}}}}},
        \\ "requestState":"s"}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    // Such a client should not have declared the capability in the first place — but
    // if a server asks anyway, retrying with an empty answer set is better than
    // hanging.
    _ = try fixture.client.callToolInteractive(fixture.allocator(), "x", null, .{});
    const responses = (try fixture.lastSent()).get("params").?.object
        .get("inputResponses").?.object;
    try testing.expectEqual(@as(usize, 0), responses.count());
}

test "the non-interactive path still reports that input was required" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "requestState":"s"}}
    }, .{});
    defer fixture.deinit();

    // A caller that did not opt into the interactive flow must not get a silently
    // empty result.
    try testing.expectError(
        error.InputRequired,
        fixture.client.callTool(fixture.allocator(), "x", null, .{}),
    );
}
