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
//!
//! ## Three layers, and when to drop down
//!
//! `listTools`, `callTool` and the rest are the top layer: one method each, decoded
//! into the type in `types.zig`. They are where to start, and they cover the protocol
//! as of this revision.
//!
//! Below them, `request` sends any method and decodes into any type — for a method a
//! server added that this SDK has no wrapper for, or one from a later revision.
//!
//! Below that, `exchange` sends the request and hands back `Call`: the raw bytes, the
//! `result` value, the `error` object, uninterpreted. Use it when a result does not fit
//! the types here, when `resultType` needs inspecting directly, or when a decode
//! failure needs diagnosing — a `UnexpectedResult` from either layer above means
//! `exchange` will still give you the payload that produced it.
//!
//! Params can be pre-encoded text at any of the three layers: see `Params.raw`,
//! `callToolJson`, and `Options.diagnostics` for what a refusal will tell you.

const std = @import("std");
const assert_mod = @import("assert");
const jsonrpc = @import("jsonrpc.zig");
const types = @import("types.zig");
// Named `legacy_mod` because `Options.legacy` is the knob that turns it on, and one of
// the two has to give.
const legacy_mod = @import("legacy.zig");

const assert = assert_mod.assert;

/// Moves encoded messages to and from a peer.
///
/// The shape is "send one message, then read messages until the exchange is over",
/// which fits both transports without either compromising: on stdio `receive` reads
/// the next line of a long-lived duplex stream, and on Streamable HTTP it yields the
/// events of one response body. The client does not care which.
///
/// ## No `Io` parameter, deliberately
///
/// An implementation that performs I/O captures an `Io` when it is constructed and
/// stores it. That is the intended pattern, not an oversight: a transport is built for
/// one connection and lives as long as it, so the `Io` it needs is settled before the
/// first message and threading it through every call would say otherwise. Both
/// transports in this SDK do exactly this.
///
/// ## Calls are serialized, and that is a guarantee
///
/// The question a captured `Io` raises next is which thread will use it. `Client` makes
/// one call at a time: `send`, then `receive` until the exchange is over, then the next
/// `send`. It holds mutable state — the id counter, the negotiated era — behind no lock,
/// so a `Client` must not be driven from two threads at once, and in exchange a
/// `Transport` needs no lock of its own. That is what lets both transports here keep a
/// single in-flight exchange in a plain field.
///
/// Concurrency, when it is wanted, is one `Client` and one `Transport` per connection
/// rather than one shared pair. Nothing in either type is per-process.
///
/// ## Abandoning a call is safe
///
/// A caller that stops waiting — a deadline, a cancelled task — does not corrupt the
/// client. Request ids are monotonic and never reused, and `receive` skips any response
/// whose id is not the one being awaited, so a late reply to an abandoned request is
/// discarded rather than mistaken for the next one. This is a guarantee, not an
/// accident of the implementation, and a caller building its own deadline may rely on
/// it. `Client.cancel` tells the server it may stop working, which is courtesy rather
/// than a requirement.
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
    ///
    /// `Timeout` here is not the same news as `Timeout` from `receive`, and the
    /// difference decides whether retrying is safe. On Streamable HTTP `send` posts the
    /// body *and* reads the response head, so a deadline that expires during it means
    /// the request was delivered and the server has not answered yet — it may well have
    /// run the tool. Re-sending is a second execution, not a retry. `receive` expiring
    /// says only that the answer is late.
    pub const SendError = error{ TransportFailed, MessageTooLarge, Unauthorized, Timeout, OutOfMemory };

    /// `Timeout` is how a transport says "the peer has gone quiet" as opposed to "the
    /// peer is gone". A transport with no deadline never returns it, and a caller that
    /// sees it knows the connection may still be good — which is what makes retrying,
    /// rather than reconnecting, the right next move.
    pub const ReceiveError = error{ TransportFailed, MessageTooLarge, Timeout, OutOfMemory };

    pub const VTable = struct {
        /// Delivers one complete, framed message.
        send: *const fn (ptr: *anyopaque, message: []const u8) SendError!void,
        /// Reads the next inbound message, allocated in `arena`, or null when the
        /// peer has nothing more to say.
        ///
        /// Blocks until there is something to return. An implementation that can bound
        /// that wait should, and should report expiry as `Timeout`: this is the only
        /// place a hung server can be noticed, and a client with no bound here waits
        /// forever on one. Returning `Timeout` does not invalidate the connection, and
        /// abandoning the call it belonged to is safe — see this type's documentation.
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
///
/// Takes no `Io`, for the same reason `Transport` does not: an implementation that
/// needs one captures it at construction, which is where the answer is already known.
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
            else => return error.UnexpectedResult,
        };

        const requests = if (object.get("inputRequests")) |value| switch (value) {
            .object => |map| map,
            else => return error.UnexpectedResult,
        } else null;

        const state = if (object.get("requestState")) |value| switch (value) {
            .string => |string| string,
            else => return error.UnexpectedResult,
        } else null;

        // The spec requires at least one. Neither would leave the client retrying an
        // unchanged request forever.
        if (requests == null and state == null) return error.UnexpectedResult;
        return .{ .requests = requests, .state = state };
    }
};

/// Why a call did not produce a result.
///
/// These are deliberately specific about *who* is at fault, because that is the first
/// thing a caller needs and the hardest thing to recover from an error value alone.
/// `InvalidParams` is this client's caller; `InvalidReply`, `UnexpectedResult` and
/// `UnsupportedResultType` are the peer; the rest is the connection between them.
///
/// Set `Options.diagnostics` to get the specifics — which field, which method, what
/// the bytes actually said. An error value names the category; the writer says what
/// happened.
pub const Error = error{
    /// The transport could not deliver or read a message.
    TransportFailed,
    /// A message exceeded the protocol limit.
    MessageTooLarge,
    /// The transport gave up waiting for the peer. Only a transport that has a
    /// deadline produces this; see `Transport.receive`.
    Timeout,
    /// The peer's message was not a well-formed JSON-RPC reply — not JSON at all, or
    /// JSON that is not a response, or an error response with no error object.
    InvalidReply,
    /// The reply was a well-formed JSON-RPC response whose `result` is not shaped like
    /// the type asked for.
    ///
    /// Most often a peer on a different protocol revision. `exchange` returns the raw
    /// result without decoding it, so a caller who knows what the peer meant can read
    /// it anyway.
    UnexpectedResult,
    /// The reply carries a `resultType` this SDK does not know, so the payload cannot
    /// be read. Only a server on a later revision produces one; `exchange` still
    /// returns the raw result for a caller willing to interpret it.
    UnsupportedResultType,
    /// The params handed to this client cannot be sent. MCP params are objects: a JSON
    /// array has nowhere to put `_meta`, and raw params text that is not an object
    /// cannot be spliced into one.
    ///
    /// Kept apart from the two above because it is the calling code's bug, not the
    /// peer's, and the two lead somewhere completely different.
    InvalidParams,
    /// The peer closed the exchange without answering.
    NoResponse,
    /// The server answered with a JSON-RPC error. Inspect `Call.failure` for it.
    RequestFailed,
    /// The server does not speak this revision. `Call.failure.data` carries the
    /// versions it does.
    UnsupportedProtocolVersion,
    /// The method does not exist in the revision this connection negotiated.
    ///
    /// Only reachable with `Options.legacy = .negotiate`, against a pre-2026-07-28
    /// server. Refused here rather than sent, because the `-32601` a server would answer
    /// with reads as "this server lacks a feature" when the truth is "this connection
    /// cannot express it" — and the two lead somewhere different.
    UnsupportedByRevision,
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

/// One variable of a prompt or URI template that is already filled in, for
/// `Client.complete` to pass along as `params.context.arguments`.
pub const ResolvedArgument = struct {
    name: []const u8,
    value: []const u8,
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

/// Whether this client will speak to a server from before 2026-07-28.
///
/// ## Which one to pick
///
/// The default is `.reject`, and it is the right default for a protocol library: falling
/// back is a downgrade, and one that happens without being asked for is one nobody
/// notices. But it is not the right choice for most applications today, and the reason is
/// deployment rather than principle — the managed MCP servers in service are still on the
/// 2025 revisions, so a client that refuses them fails against the common case.
///
/// So: an agent or a tool that connects to servers it does not control almost certainly
/// wants `.negotiate`, and wants to report `negotiatedVersion()` somewhere a user can see
/// it. Something that talks only to servers shipped alongside it should keep `.reject`, so
/// that a peer accidentally left on an old revision is a loud failure rather than a quiet
/// downgrade.
///
/// Worth knowing before choosing: with `.reject`, a 2025 server's refusal names the
/// version and not the cause. `Options.diagnostics` is what turns it into a sentence.
pub const LegacyMode = enum {
    /// Speak 2026-07-28 and nothing else. A server on an older revision fails, with the
    /// error it produced.
    ///
    /// The default, and it stays the default on purpose: falling back is a downgrade, and
    /// a downgrade that happens without being asked for is one nobody notices. Every
    /// interoperability leg in this repository runs against a peer configured to refuse
    /// the older protocol, so that a passing run cannot be one that quietly fell back —
    /// the same discipline applied to the option itself.
    reject,
    /// Try 2026-07-28, and fall back to the 2025 handshake if the server does not know it.
    ///
    /// See `legacy.zig` for what the older era can and cannot carry. In short: the
    /// request methods both eras share all work; `subscriptions/listen` and the
    /// multi-round-trip input flow do not exist there and are refused locally.
    negotiate,
};

pub const Options = struct {
    /// Whether to fall back to the 2025 protocol. Defaults to refusing.
    legacy: LegacyMode = .reject,
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
    // There is deliberately no timeout field here, and its absence is the one thing in
    // this struct worth explaining. A deadline needs two things a `Client` does not
    // have: an `Io` to wait on and a clock to measure with. It holds neither, which is
    // what lets the same client drive a socket, a pipe, or an in-memory pair in a test.
    // Adding `timeout_ms` here would mean either smuggling an `Io` in beside it or
    // handing the number to the transport to enforce — and the second is just the
    // transport's own option with an extra hop.
    //
    // So the knob lives on whichever transport owns the wait:
    // `http_client.Options.receive_timeout_ms` bounds a Streamable HTTP read. Expiry
    // arrives here as `error.Timeout`, and `Transport`'s documentation states why
    // abandoning the call it belonged to is safe.
    /// Where this client explains itself when it refuses something.
    ///
    /// Every error returned from here is one of a dozen names, and a name cannot say
    /// which field would not decode or what the peer actually sent. Point this at
    /// `std.Io.Writer` — stderr, a log, a buffer a test reads back — and each refusal
    /// writes one line naming the method, the cause, and the bytes it was looking at.
    ///
    /// Off by default because the bytes may carry whatever the peer put in them, and a
    /// library should not decide that belongs in a log.
    diagnostics: ?*std.Io.Writer = null,
};

/// The `params` member of a request.
///
/// A union rather than `?std.json.Value` so that pre-encoded text is a first-class
/// case. See `raw`.
pub const Params = union(enum) {
    /// The method takes no arguments of its own. `_meta` is still sent.
    none,
    /// A parsed value, merged key by key with `_meta`.
    value: std.json.Value,
    /// A JSON object, already encoded, written through byte for byte.
    ///
    /// For arguments that came from a model. Parsing and re-encoding is not
    /// shape-preserving — number formatting, key order and duplicate keys can all
    /// change — and a tool argument that differs between what the model decided and
    /// what the server ran is a bug nobody sees, because both halves look right on
    /// their own.
    ///
    /// The text must be a JSON object. That much is checked, since it has to be
    /// spliced into one alongside `_meta`; nothing inside is validated, because
    /// validating it would mean the parse this case exists to avoid. Invalid JSON in
    /// here reaches the server as invalid JSON, and the server rejects it — that is
    /// the trade, and it is the caller's to make.
    raw: []const u8,

    /// The interior of a raw object: everything between the braces, trimmed.
    ///
    /// Empty for `{}`, which merges as "nothing to add".
    fn interior(text: []const u8) error{InvalidParams}![]const u8 {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed.len < 2) return error.InvalidParams;
        if (trimmed[0] != '{' or trimmed[trimmed.len - 1] != '}') return error.InvalidParams;
        return std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t\r\n");
    }
};

pub const Client = struct {
    transport: Transport,
    info: types.Implementation,
    options: Options,
    /// Monotonic request id. Never reused within a client's lifetime, so a late
    /// response from an abandoned request can always be told apart from a fresh one.
    next_id: i64 = 1,
    /// Which protocol era this connection settled on.
    ///
    /// The only mutable state besides the id counter, and it exists because the legacy
    /// era is stateful in a way the modern one deliberately is not: a handshake happens
    /// once, and every request after it has to be shaped by what the handshake agreed.
    era: Era = .modern,

    /// The protocol era of this connection.
    pub const Era = union(enum) {
        /// Not yet settled. Only reachable with `Options.legacy = .negotiate`, and only
        /// until the first request.
        unknown,
        /// 2026-07-28: no handshake, a `_meta` envelope on every request.
        modern,
        /// Pre-2026-07-28: `initialize` completed, and what it agreed to.
        legacy: legacy_mod.Handshake,
    };

    pub fn init(transport: Transport, info: types.Implementation, options: Options) Client {
        assert(info.name.len > 0);
        assert(info.version.len > 0);
        assert(options.messages_max > 0);
        return .{
            .transport = transport,
            .info = info,
            .options = options,
            // Under `.reject` the era is settled before a byte moves, which is what keeps
            // the default path free of any probe or extra round trip.
            .era = switch (options.legacy) {
                .reject => .modern,
                .negotiate => .unknown,
            },
        };
    }

    /// The revision this connection is speaking, once it is known.
    ///
    /// Null before the first request under `.negotiate`. Worth logging: it is the one
    /// fact that explains why a method a server obviously has is being refused.
    pub fn negotiatedVersion(client: *const Client) ?[]const u8 {
        return switch (client.era) {
            .unknown => null,
            .modern => types.protocol_version,
            // Captured by reference. A by-value capture would copy the `Handshake` into
            // the switch's own temporary, and the slice this returns points into that
            // copy's buffer — a dangling slice the moment the expression ends.
            .legacy => |*negotiated| negotiated.negotiatedVersion(),
        };
    }

    // ---- Typed API -------------------------------------------------------

    /// Asks what the server offers.
    ///
    /// Optional in this revision — there is no handshake to complete — but it is how
    /// a client learns the server's protocol versions, capabilities and instructions,
    /// and how it discovers that it needs to speak a different revision.
    ///
    /// With `Options.legacy = .negotiate` this is also where negotiation naturally
    /// happens, and it answers the same shape either way: against a pre-2026-07-28 server
    /// the `InitializeResult` is reported as a `DiscoverResult`, so a caller does not have
    /// to know which era it is on to read the answer. `supportedVersions` then holds the
    /// one version the handshake agreed on, because that is all `initialize` returns — a
    /// server states its choice, not its list.
    ///
    /// Call this first if you want `instructions` from a legacy server. The handshake
    /// happens once per connection and carries them in its reply; a later `discover` has
    /// only what this client kept, and instructions are not kept — they are unbounded, and
    /// a `Client` owns no allocator to hold them in.
    pub fn discover(
        client: *Client,
        arena: std.mem.Allocator,
        options: CallOptions,
    ) Error!types.DiscoverResult {
        if (client.era == .unknown) {
            const negotiated = try client.negotiate(arena);
            if (negotiated.initialized) |result| {
                return client.era.legacy.discoverResult(
                    arena,
                    legacy_mod.instructionsOf(result),
                );
            }
            // The probe was the request, so its answer is decoded here rather than asked
            // for a second time.
            const call = negotiated.discovered.?;
            const result = call.result.?;
            switch (try client.readResultType(types.method.discover, call.bytes, result)) {
                .complete => {},
                .input_required => return error.InputRequired,
            }
            return client.decodeResult(
                types.DiscoverResult,
                arena,
                types.method.discover,
                call.bytes,
                result,
            );
        }
        if (client.era == .legacy) {
            // Handshaken on an earlier call. No round trip: `initialize` may be sent only
            // once, and a server is entitled to refuse a second one.
            return client.era.legacy.discoverResult(arena, null);
        }
        return client.request(types.DiscoverResult, arena, types.method.discover, .none, options);
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
            .{ .value = .{ .object = params } },
            options,
        );
    }

    /// Invokes a tool with arguments that are already JSON text.
    ///
    /// The same call as `callTool`, for a caller who has the arguments encoded already —
    /// from `std.json.Stringify` over its own struct, from a config file, or forwarded
    /// from somewhere else. Parsing that text only to re-encode it costs a pass over the
    /// bytes and, worse, does not round-trip: key order changes, and numbers a
    /// `std.json.Value` cannot hold exactly come back different.
    ///
    /// `arguments_json` must be one complete JSON value. It is spliced in unvalidated,
    /// so text that is not JSON produces a request the server will reject — see
    /// `Params.raw`. Empty or blank text sends no arguments at all.
    pub fn callToolJson(
        client: *Client,
        arena: std.mem.Allocator,
        name: []const u8,
        arguments_json: []const u8,
        options: CallOptions,
    ) Error!types.CallToolResult {
        return client.request(
            types.CallToolResult,
            arena,
            types.method.tools_call,
            try toolParamsJson(arena, name, arguments_json),
            options,
        );
    }

    /// `callToolJson`, handling any input the server asks for along the way.
    pub fn callToolInteractiveJson(
        client: *Client,
        arena: std.mem.Allocator,
        name: []const u8,
        arguments_json: []const u8,
        options: CallOptions,
    ) Error!types.CallToolResult {
        return client.requestInteractive(
            types.CallToolResult,
            arena,
            types.method.tools_call,
            try toolParamsJson(arena, name, arguments_json),
            options,
        );
    }

    /// Builds `tools/call` params around pre-encoded arguments.
    fn toolParamsJson(
        arena: std.mem.Allocator,
        name: []const u8,
        arguments_json: []const u8,
    ) error{OutOfMemory}!Params {
        var out: std.Io.Writer.Allocating = .init(arena);
        const writer = &out.writer;

        writer.writeAll("{") catch return error.OutOfMemory;
        var members: Members = .{ .writer = writer };
        try members.field("name", name);
        // Blank text is read as "no arguments" rather than passed through, which would
        // put a member with no value on the wire.
        try members.raw(blk: {
            const trimmed = std.mem.trim(u8, arguments_json, " \t\r\n");
            if (trimmed.len == 0) break :blk "";
            break :blk try std.fmt.allocPrint(arena, "\"arguments\":{s}", .{trimmed});
        });
        writer.writeAll("}") catch return error.OutOfMemory;

        return .{ .raw = out.written() };
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
            .{ .value = .{ .object = params } },
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
            .{ .value = .{ .object = params } },
            options,
        );
    }

    /// Asks for completions for one argument of a prompt or resource template.
    ///
    /// `resolved` carries the variables of the same prompt or template the caller has
    /// already filled in. Pass `&.{}` when there are none — but pass them when there
    /// are: completing `{table}` in `db://{schema}/{table}` is a different question for
    /// each schema, and a server given no context can only answer for all of them.
    pub fn complete(
        client: *Client,
        arena: std.mem.Allocator,
        reference: types.CompletionReference,
        argument_name: []const u8,
        partial: []const u8,
        resolved: []const ResolvedArgument,
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

        // Omitted entirely when empty rather than sent as `{}`: `context` is optional,
        // and an empty object says "I resolved nothing", which is a claim rather than a
        // silence.
        if (resolved.len > 0) {
            var arguments: std.json.ObjectMap = .empty;
            for (resolved) |entry| {
                try arguments.put(arena, entry.name, .{ .string = entry.value });
            }
            var completion_context: std.json.ObjectMap = .empty;
            try completion_context.put(arena, "arguments", .{ .object = arguments });
            try params.put(arena, "context", .{ .object = completion_context });
        }

        return client.request(
            types.CompleteResult,
            arena,
            types.method.completion_complete,
            .{ .value = .{ .object = params } },
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

        return client.request(T, arena, method, .{ .value = .{ .object = params } }, options.call);
    }

    /// Sends a request and decodes the result.
    ///
    /// For a method with no typed wrapper, or a result this client's types do not
    /// describe, use `exchange`: it performs the same exchange and hands back the raw
    /// result without interpreting it.
    pub fn request(
        client: *Client,
        comptime T: type,
        arena: std.mem.Allocator,
        method: []const u8,
        params: Params,
        options: CallOptions,
    ) Error!T {
        const call = try client.exchange(arena, method, params, options);
        const result = call.result orelse return client.failureError(method, call.failure);

        // The result type has to be checked before the payload is trusted: an
        // `input_required` result shares none of the fields a complete one has, and
        // silently decoding it as complete would drop the server's request for input.
        switch (try client.readResultType(method, call.bytes, result)) {
            .complete => {},
            .input_required => return error.InputRequired,
        }
        return client.decodeResult(T, arena, method, call.bytes, result);
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
        params: Params,
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
            const result = call.result orelse return client.failureError(method, call.failure);

            switch (try client.readResultType(method, call.bytes, result)) {
                .complete => return client.decodeResult(T, arena, method, call.bytes, result),
                .input_required => {
                    if (!types.method.supportsInputRequired(method)) {
                        client.report(
                            "mcp: {s} answered input_required, which only tools/call, " ++
                                "prompts/get and resources/read may do\n",
                            .{method},
                        );
                        return error.UnexpectedResult;
                    }
                    pending = try InputRequired.fromResult(result);
                },
            }
        }
        // Out of rounds. The server is entitled to keep asking, so this is not
        // necessarily its fault — but a caller must not be left in the loop.
        client.report(
            "mcp: {s} still asking for input after {d} rounds; giving up\n",
            .{ method, client.options.rounds_max },
        );
        return error.InputRequired;
    }

    /// Builds the params for a retry: the original ones, plus the answers and state.
    ///
    /// Raw params are spliced rather than merged. Parsing them to merge would be exactly
    /// the round trip `Params.raw` exists to avoid, so the answers are appended as text
    /// beside whatever the caller wrote. Nothing needs stripping in either branch:
    /// `withInput` always receives the caller's original params, never a previous
    /// round's, so `inputResponses` and `requestState` cannot already be there — unless
    /// the caller put them there, and then the duplicate is a fair thing to see.
    fn withInput(
        client: *Client,
        arena: std.mem.Allocator,
        params: Params,
        required: InputRequired,
    ) Error!Params {
        var added: std.json.ObjectMap = .empty;
        if (required.requests) |requests| {
            const responses = try client.answer(arena, requests);
            try added.put(arena, "inputResponses", .{ .object = responses });
        }
        if (required.state) |state| {
            // Echoed byte for byte. Any change is tampering as far as the server is
            // concerned, and it is required to reject it.
            try added.put(arena, "requestState", .{ .string = state });
        }

        switch (params) {
            .none => return .{ .value = .{ .object = added } },
            .value => |value| {
                const object = switch (value) {
                    .object => |object| object,
                    else => {
                        client.report(
                            "mcp: params must be a JSON object to answer input_required, " ++
                                "not a {s}\n",
                            .{@tagName(value)},
                        );
                        return error.InvalidParams;
                    },
                };

                var merged: std.json.ObjectMap = .empty;
                var iterator = object.iterator();
                while (iterator.next()) |entry| {
                    try merged.put(arena, entry.key_ptr.*, entry.value_ptr.*);
                }
                var extra = added.iterator();
                while (extra.next()) |entry| {
                    try merged.put(arena, entry.key_ptr.*, entry.value_ptr.*);
                }
                return .{ .value = .{ .object = merged } };
            },
            .raw => |text| {
                const inner = Params.interior(text) catch {
                    client.report(
                        "mcp: raw params must be a JSON object; got {s}\n",
                        .{preview(text)},
                    );
                    return error.InvalidParams;
                };

                var out: std.Io.Writer.Allocating = .init(arena);
                const writer = &out.writer;
                writer.writeAll("{") catch return error.OutOfMemory;
                var members: Members = .{ .writer = writer };
                try members.raw(inner);
                var extra = added.iterator();
                while (extra.next()) |entry| {
                    try members.field(entry.key_ptr.*, entry.value_ptr.*);
                }
                writer.writeAll("}") catch return error.OutOfMemory;
                return .{ .raw = out.written() };
            },
        }
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
                    error.Malformed => {
                        client.report(
                            "mcp: input request {s} is not a shape this client can read\n",
                            .{key},
                        );
                        return error.UnexpectedResult;
                    },
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
            .{ .value = .{ .object = params } },
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
            .{ .value = .{ .object = params } },
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
            .{ .value = .{ .object = params } },
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
        params: Params,
        options: CallOptions,
    ) Error!Call {
        if (client.era == .unknown) _ = try client.negotiate(arena);
        try client.checkMethodInEra(method);
        return client.send(arena, method, params, options);
    }

    /// The exchange itself, with the era taken as settled.
    ///
    /// Split out because negotiation has to send requests of its own, and routing those
    /// back through `exchange` would ask the era to be settled in order to settle it.
    fn send(
        client: *Client,
        arena: std.mem.Allocator,
        method: []const u8,
        params: Params,
        options: CallOptions,
    ) Error!Call {
        const id = client.takeId();
        const bytes = try client.encodeRequest(arena, id, method, params, options);

        client.transport.send(bytes) catch |err| return mapSendError(err);
        return client.awaitResponse(arena, id);
    }

    /// Refuses a method the negotiated revision does not define.
    fn checkMethodInEra(client: *const Client, method: []const u8) Error!void {
        switch (client.era) {
            .unknown, .modern => return,
            .legacy => |*negotiated| {
                if (legacy_mod.hasRequestMethod(method)) return;
                client.report(
                    "mcp: {s} does not exist in {s}, which is what this connection " ++
                        "negotiated; it was added in {s}\n",
                    .{ method, negotiated.negotiatedVersion(), types.protocol_version },
                );
                return error.UnsupportedByRevision;
            },
        }
    }

    /// What negotiation learned, and the reply that told it.
    ///
    /// Both replies borrow from the arena negotiation ran in, which is the arena of
    /// whichever call triggered it. That is why `discover` is the one caller that reads
    /// them: it is the call whose answer they are.
    const Negotiation = struct {
        /// The `server/discover` reply, when the probe found a modern server.
        discovered: ?Call = null,
        /// The `initialize` result, when the handshake ran.
        initialized: ?std.json.Value = null,
    };

    /// Settles which era this connection speaks, by asking.
    ///
    /// The probe is `server/discover`, which is the modern era's own negotiation entry
    /// point — so against a modern server this costs nothing extra, and its answer is the
    /// answer `discover` wanted anyway.
    ///
    /// Any JSON-RPC error from the probe is read as "not a modern server", rather than
    /// matching a code or a message. That is deliberate: the refusal differs by transport
    /// and by implementation. Over stdio a 2025 server answers `-32601 Method not found`;
    /// over Streamable HTTP it more often answers `400` with `-32000` because
    /// `MCP-Protocol-Version: 2026-07-28` is a version it does not know, or because a
    /// session it never opened is missing. Matching on any of that would be matching on
    /// prose. A transport failure is *not* treated this way — a connection that broke says
    /// nothing about which protocol was on it, so it propagates.
    fn negotiate(client: *Client, arena: std.mem.Allocator) Error!Negotiation {
        assert(client.era == .unknown);
        assert(client.options.legacy == .negotiate);

        // Encode the probe as modern, which is what it is testing for.
        client.era = .modern;
        const probe = client.send(arena, types.method.discover, .none, .{}) catch |err| {
            client.era = .unknown;
            return err;
        };
        if (probe.result != null) return .{ .discovered = probe };

        client.report(
            "mcp: server/discover was refused ([{d}] {s}); trying the {s} handshake\n",
            .{
                if (probe.failure) |failure| failure.code else 0,
                if (probe.failure) |failure| failure.message else "no error object",
                legacy_mod.version,
            },
        );

        client.era = .unknown;
        const result = try client.handshake(arena);
        return .{ .initialized = result };
    }

    /// Performs the legacy `initialize` exchange and records what it agreed.
    fn handshake(client: *Client, arena: std.mem.Allocator) Error!std.json.Value {
        var params: std.Io.Writer.Allocating = .init(arena);
        legacy_mod.writeInitializeParams(
            &params.writer,
            client.info,
            client.options.capabilities,
        ) catch return error.OutOfMemory;

        // Encoded through the legacy envelope, which is why the era is set first: this
        // request must carry no `_meta` at all, and `initialize` least of all — it is the
        // one request whose params *are* the version and the capabilities.
        client.era = .{ .legacy = .{} };
        const call = client.send(
            arena,
            legacy_mod.method.initialize,
            .{ .raw = params.written() },
            .{},
        ) catch |err| {
            client.era = .unknown;
            return err;
        };

        const result = call.result orelse {
            client.era = .unknown;
            client.report(
                "mcp: the {s} handshake was refused too; this peer speaks neither " ++
                    "revision this client knows\n",
                .{legacy_mod.version},
            );
            return client.failureError(legacy_mod.method.initialize, call.failure);
        };

        client.era = .{ .legacy = legacy_mod.Handshake.fromResult(result) catch {
            client.era = .unknown;
            client.report(
                "mcp: the {s} handshake answered with something that is not an " ++
                    "InitializeResult: {s}\n",
                .{ legacy_mod.version, preview(call.bytes) },
            );
            return error.UnexpectedResult;
        } };

        // The handshake is only complete once this is sent, and a conformant server may
        // refuse everything until it arrives. It is a notification, so there is nothing
        // to await and nothing to check — which is also why a server cannot tell this
        // client that its confirmation was malformed.
        try client.notify(arena, legacy_mod.method.initialized, null);

        client.report(
            "mcp: negotiated {s} through the legacy handshake\n",
            .{client.era.legacy.negotiatedVersion()},
        );
        return result;
    }

    /// Sets the connection-wide log level, on a legacy connection.
    ///
    /// 2026-07-28 removed `logging/setLevel` and made the level a per-request `_meta`
    /// field, which is why `CallOptions.log_level` exists and why it has no counterpart
    /// here on a modern connection — asking for one would be asking a stateless protocol
    /// to remember something.
    ///
    /// On a legacy connection the reverse holds: the level is connection state, so
    /// `CallOptions.log_level` cannot be honoured per call and this is the only way to ask
    /// for `notifications/message` at all.
    pub fn setLogLevel(
        client: *Client,
        arena: std.mem.Allocator,
        level: types.LoggingLevel,
    ) Error!void {
        if (client.era == .unknown) _ = try client.negotiate(arena);
        if (client.era == .modern) {
            client.report(
                "mcp: logging/setLevel does not exist in {s}; ask per request with " ++
                    "CallOptions.log_level\n",
                .{types.protocol_version},
            );
            return error.UnsupportedByRevision;
        }

        var params: std.json.ObjectMap = .empty;
        try params.put(arena, "level", .{ .string = @tagName(level) });
        // `exchange` rather than `request`: the result is `{}`, so there is nothing to
        // decode, and teaching the modern decode table about a method that exists only in
        // the older era would put 2025 vocabulary where it does not belong.
        const call = try client.send(
            arena,
            legacy_mod.method.set_level,
            .{ .value = .{ .object = params } },
            .{},
        );
        if (call.result == null) {
            return client.failureError(legacy_mod.method.set_level, call.failure);
        }
    }

    fn takeId(client: *Client) jsonrpc.Id {
        const id = client.next_id;
        client.next_id += 1;
        return .{ .number = id };
    }

    /// Writes the `_meta` this era's requests carry, which on one era is nothing at all.
    ///
    /// The modern envelope is required on every request: the protocol is stateless, so
    /// the version and the client's capabilities have nowhere else to live. The legacy era
    /// established both once in the handshake, and repeating them per request would be
    /// writing 2026 vocabulary onto a 2025 connection — which is the one thing the older
    /// wire format must never see, because a server that validates its params strictly
    /// rejects the request and one that does not may believe the wrong thing about the
    /// peer.
    ///
    /// `progressToken` is the exception, and it spans both eras because it predates the
    /// `io.modelcontextprotocol/` prefix convention and is spelled bare in each.
    fn writeMeta(
        client: *const Client,
        members: *Members,
        method: []const u8,
        options: CallOptions,
    ) Error!void {
        switch (client.era) {
            .unknown, .modern => {
                try members.field("_meta", types.RequestMeta{
                    .protocol_version = types.protocol_version,
                    .capabilities = client.options.capabilities,
                    .client_info = if (client.options.include_client_info) client.info else null,
                    .log_level = options.log_level,
                    .progress_token = options.progress_token,
                    .extra = options.extra,
                });
            },
            .legacy => {
                if (options.log_level != null) {
                    client.report(
                        "mcp: {s} asked for log level per request, which {s} has no field " ++
                            "for; call setLogLevel once instead\n",
                        .{ method, client.era.legacy.negotiatedVersion() },
                    );
                }
                // Omitted entirely when there is nothing to say, rather than sent empty:
                // `_meta` is optional in this era, and `{}` is a different message from
                // its absence to a server that counts keys.
                if (options.progress_token == null and options.extra == null) return;

                try members.separate();
                members.writer.writeAll("\"_meta\":{") catch return error.OutOfMemory;
                var inner: Members = .{ .writer = members.writer };
                if (options.extra) |extra| {
                    var iterator = extra.iterator();
                    while (iterator.next()) |entry| {
                        // Skipped for the same reason the modern envelope strips its own
                        // reserved keys out of `extra`: two of the same key is not a
                        // message either side can read.
                        if (std.mem.eql(u8, entry.key_ptr.*, types.meta_key.progress_token)) {
                            continue;
                        }
                        try inner.field(entry.key_ptr.*, entry.value_ptr.*);
                    }
                }
                if (options.progress_token) |token| {
                    try inner.field(types.meta_key.progress_token, token);
                }
                members.writer.writeAll("}") catch return error.OutOfMemory;
            },
        }
    }

    /// Builds the request envelope, injecting the `_meta` every request must carry.
    fn encodeRequest(
        client: *const Client,
        arena: std.mem.Allocator,
        id: jsonrpc.Id,
        method: []const u8,
        params: Params,
        options: CallOptions,
    ) Error![]const u8 {
        var out: std.Io.Writer.Allocating = .init(arena);
        const writer = &out.writer;

        writer.writeAll("{\"jsonrpc\":\"2.0\",\"id\":") catch return error.OutOfMemory;
        types.stringify(writer, id) catch return error.OutOfMemory;
        writer.writeAll(",\"method\":") catch return error.OutOfMemory;
        types.stringify(writer, method) catch return error.OutOfMemory;

        // `_meta` lives inside `params`, so params is always present even for methods
        // that take no arguments of their own.
        writer.writeAll(",\"params\":{") catch return error.OutOfMemory;
        var members: Members = .{ .writer = writer };
        try client.writeMeta(&members, method, options);

        switch (params) {
            .none => {},
            .value => |value| switch (value) {
                .object => |object| {
                    var iterator = object.iterator();
                    while (iterator.next()) |entry| {
                        // `_meta` is the client's to set; a caller-supplied one would
                        // produce a duplicate key.
                        if (std.mem.eql(u8, entry.key_ptr.*, "_meta")) continue;
                        try members.field(entry.key_ptr.*, entry.value_ptr.*);
                    }
                },
                // JSON-RPC allows array params; MCP does not use them, and merging one
                // with `_meta` is not possible.
                else => {
                    client.report(
                        "mcp: {s} params must be a JSON object, not a {s}\n",
                        .{ method, @tagName(value) },
                    );
                    return error.InvalidParams;
                },
            },
            .raw => |text| {
                const inner = Params.interior(text) catch {
                    client.report(
                        "mcp: {s} raw params must be a JSON object; got {s}\n",
                        .{ method, preview(text) },
                    );
                    return error.InvalidParams;
                };
                try members.raw(inner);
            },
        }

        writer.writeAll("}}") catch return error.OutOfMemory;
        return out.written();
    }

    // ---- Diagnostics and error mapping -----------------------------------

    /// Writes one diagnostic line, if the caller asked for them.
    ///
    /// Best-effort: a diagnostics writer that fails must not turn into a failed
    /// request, since the request itself was fine.
    fn report(client: *const Client, comptime fmt: []const u8, args: anytype) void {
        const writer = client.options.diagnostics orelse return;
        writer.print(fmt, args) catch {};
    }

    /// Maps a JSON-RPC error onto a client error, singling out the one a caller can act
    /// on automatically.
    fn failureError(
        client: *const Client,
        method: []const u8,
        failure: ?jsonrpc.ErrorObject,
    ) Error {
        const object = failure orelse {
            client.report("mcp: {s} got an error response with no error object\n", .{method});
            return error.InvalidReply;
        };
        if (object.code == jsonrpc.error_code.unsupported_protocol_version) {
            client.report(
                "mcp: {s} refused: the server does not speak {s}\n",
                .{ method, types.protocol_version },
            );
            return error.UnsupportedProtocolVersion;
        }
        client.report(
            "mcp: {s} failed: [{d}] {s}\n",
            .{ method, object.code, object.message },
        );
        return error.RequestFailed;
    }

    /// Reads the result type, which decides whether the payload can be read at all.
    fn readResultType(
        client: *const Client,
        method: []const u8,
        bytes: []const u8,
        result: std.json.Value,
    ) Error!types.ResultType {
        return types.resultTypeOf(result) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => {
                client.report(
                    "mcp: {s} result is not an object, so it is not an MCP result: {s}\n",
                    .{ method, preview(bytes) },
                );
                return error.UnexpectedResult;
            },
            error.UnsupportedResultType => {
                client.report(
                    "mcp: {s} result carries a resultType from a later revision than " ++
                        "{s}; use exchange to read it yourself: {s}\n",
                    .{ method, types.protocol_version, preview(bytes) },
                );
                return error.UnsupportedResultType;
            },
        };
    }

    /// Decodes a result into the type a typed wrapper promised.
    fn decodeResult(
        client: *const Client,
        comptime T: type,
        arena: std.mem.Allocator,
        method: []const u8,
        bytes: []const u8,
        result: std.json.Value,
    ) Error!T {
        return types.decode(T, arena, result) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnsupportedResultType => error.UnsupportedResultType,
            error.Malformed => {
                client.report(
                    "mcp: {s} result did not decode as {s}; use exchange for the raw " ++
                        "result: {s}\n",
                    .{ method, @typeName(T), preview(bytes) },
                );
                return error.UnexpectedResult;
            },
        };
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
                else => {
                    client.report(
                        "mcp: transport delivered something that is not a JSON-RPC " ++
                            "message ({s}): {s}\n",
                        .{ @errorName(err), preview(bytes) },
                    );
                    return error.InvalidReply;
                },
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
        // Every message read was somebody else's. The response may still be coming, but
        // a caller must not be held here indefinitely on the chance that it is.
        client.report(
            "mcp: no response to request {f} within {d} messages\n",
            .{ id, client.options.messages_max },
        );
        return error.NoResponse;
    }
};

/// How much of a peer's bytes a diagnostic line will quote.
///
/// Enough to recognise the payload, short enough that one bad message cannot flood a
/// log with content the peer chose.
const preview_bytes_max = 512;

fn preview(bytes: []const u8) []const u8 {
    return bytes[0..@min(bytes.len, preview_bytes_max)];
}

/// Writes object members with the commas in the right places.
///
/// The encoder emits JSON directly rather than building an `ObjectMap` first, and
/// getting a separator wrong produces bytes no server will accept. Tracking "have I
/// written one yet" in one place is what keeps that from being spread across the
/// callers.
const Members = struct {
    writer: *std.Io.Writer,
    written: bool = false,

    fn separate(members: *Members) error{OutOfMemory}!void {
        if (members.written) members.writer.writeAll(",") catch return error.OutOfMemory;
        members.written = true;
    }

    fn field(
        members: *Members,
        name: []const u8,
        value: anytype,
    ) error{OutOfMemory}!void {
        try members.separate();
        types.stringify(members.writer, name) catch return error.OutOfMemory;
        members.writer.writeAll(":") catch return error.OutOfMemory;
        types.stringify(members.writer, value) catch return error.OutOfMemory;
    }

    /// Appends already-encoded members: the interior of an object, without its braces.
    ///
    /// An empty interior writes nothing at all, and in particular does not leave behind
    /// a comma with nothing after it.
    fn raw(members: *Members, interior: []const u8) error{OutOfMemory}!void {
        if (interior.len == 0) return;
        try members.separate();
        members.writer.writeAll(interior) catch return error.OutOfMemory;
    }
};

fn mapSendError(err: Transport.SendError) Error {
    return switch (err) {
        error.TransportFailed => error.TransportFailed,
        error.MessageTooLarge => error.MessageTooLarge,
        error.Unauthorized => error.Unauthorized,
        error.Timeout => error.Timeout,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapReceiveError(err: Transport.ReceiveError) Error {
    return switch (err) {
        error.TransportFailed => error.TransportFailed,
        error.MessageTooLarge => error.MessageTooLarge,
        error.Timeout => error.Timeout,
        error.OutOfMemory => error.OutOfMemory,
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
        &.{},
        .{},
    );
    try testing.expectEqual(@as(usize, 2), result.completion.values.len);
    try testing.expectEqualStrings("zig", result.completion.values[0]);
    try testing.expectEqual(@as(i64, 2), result.completion.total.?);

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("ref/prompt", params.get("ref").?.object.get("type").?.string);
    try testing.expectEqualStrings("review", params.get("ref").?.object.get("name").?.string);
    try testing.expectEqualStrings("z", params.get("argument").?.object.get("value").?.string);
    // Nothing resolved, so no `context` at all — an empty object would be a claim.
    try testing.expect(params.get("context") == null);
}

test "resolved variables travel as the completion context" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete",
        \\ "completion":{"values":["sales.orders"]}}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.complete(
        fixture.allocator(),
        .{ .resource = .{ .uri = "db://{schema}/{table}" } },
        "table",
        "or",
        &.{.{ .name = "schema", .value = "sales" }},
        .{},
    );

    const params = (try fixture.lastSent()).get("params").?.object;
    const arguments = params.get("context").?.object.get("arguments").?.object;
    try testing.expectEqualStrings("sales", arguments.get("schema").?.string);
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
        &.{},
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
        .none,
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

test "a reply that is not JSON-RPC is the transport's fault, and says so" {
    var log: std.Io.Writer.Allocating = .init(testing.allocator);
    defer log.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{"{not json"}, .{ .diagnostics = &log.writer });
    defer fixture.deinit();

    // `InvalidReply`, not `UnexpectedResult`: the bytes never became a message, so
    // there is no result to have been unexpected.
    try testing.expectError(
        error.InvalidReply,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
    // The offending bytes are quoted, which is the whole point of the channel: an
    // error name alone leaves a caller guessing what the peer actually sent.
    try testing.expect(std.mem.indexOf(u8, log.written(), "{not json") != null);
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

test "a result of the wrong shape is reported rather than silently empty" {
    var log: std.Io.Writer.Allocating = .init(testing.allocator);
    defer log.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":"not an array"}}
    }, .{ .diagnostics = &log.writer });
    defer fixture.deinit();

    // A well-formed JSON-RPC response whose payload is not the promised type: the
    // server is at fault, and the caller has a way to read it anyway.
    try testing.expectError(
        error.UnexpectedResult,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
    try testing.expect(std.mem.indexOf(u8, log.written(), "tools/list") != null);
    try testing.expect(std.mem.indexOf(u8, log.written(), "exchange") != null);
    try testing.expect(std.mem.indexOf(u8, log.written(), "not an array") != null);
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
        .{ .value = .{ .object = params } },
        .{},
    );

    // Duplicating the key would produce a message no parser accepts, so the
    // caller's copy is dropped.
    const sent = try fixture.lastSent();
    try testing.expect(sent.get("params").?.object.get("_meta").? == .object);
}

test "pre-encoded params go out byte for byte" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}
    }, .{});
    defer fixture.deinit();

    // Every one of these survives a round trip through `std.json.Value` differently:
    // the trailing zero is dropped, the exponent is reformatted, the integer exceeds
    // i64 and becomes a float, and the key order is whatever the map iterates in.
    const raw = "{\"zebra\":1.50,\"alpha\":1e2,\"huge\":12345678901234567890123}";

    _ = try fixture.client.exchange(
        fixture.allocator(),
        types.method.tools_list,
        .{ .raw = raw },
        .{},
    );

    const sent = fixture.transport.sent.items[0];
    try testing.expect(std.mem.indexOf(u8, sent, raw[1 .. raw.len - 1]) != null);
    // Spliced into the same object as `_meta`, not appended after it.
    try testing.expect(std.mem.indexOf(u8, sent, types.meta_key.protocol_version) != null);
    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqual(@as(usize, 4), params.count());
}

test "an empty pre-encoded object adds nothing, including a stray comma" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}
    }, .{});
    defer fixture.deinit();

    // `{ }` rather than `{}`, so the whitespace trimming is exercised too. A comma
    // left behind here would make the whole message unparseable, which is why the
    // assertion is that it parses at all.
    _ = try fixture.client.exchange(
        fixture.allocator(),
        types.method.tools_list,
        .{ .raw = "{  }" },
        .{},
    );

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqual(@as(usize, 1), params.count());
    try testing.expect(params.get("_meta") != null);
}

test "params that are not an object are refused before anything is sent" {
    for ([_]Params{
        .{ .raw = "[1,2]" },
        .{ .raw = "" },
        .{ .raw = "{" },
        .{ .value = .{ .array = std.json.Array.init(testing.allocator) } },
        .{ .value = .{ .string = "name=x" } },
    }) |params| {
        var log: std.Io.Writer.Allocating = .init(testing.allocator);
        defer log.deinit();

        var fixture: Fixture = undefined;
        fixture.init(&.{}, .{ .diagnostics = &log.writer });
        defer fixture.deinit();

        try testing.expectError(error.InvalidParams, fixture.client.exchange(
            fixture.allocator(),
            types.method.tools_list,
            params,
            .{},
        ));
        // The caller's fault, so it is caught before a request goes out — a server
        // should not have to be the one to notice.
        try testing.expectEqual(@as(usize, 0), fixture.transport.sent.items.len);
        try testing.expect(std.mem.indexOf(u8, log.written(), "tools/list") != null);
    }
}

test "callToolJson passes the model's arguments through unchanged" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    _ = try fixture.client.callToolJson(
        fixture.allocator(),
        "transfer",
        "  {\"cents\":900000000000000000000,\"memo\":\"rent\"}  ",
        .{},
    );

    const sent = fixture.transport.sent.items[0];
    try testing.expect(std.mem.indexOf(u8, sent, "900000000000000000000") != null);

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("transfer", params.get("name").?.string);
    try testing.expectEqualStrings("rent", params.get("arguments").?.object.get("memo").?.string);
}

test "callToolJson with no arguments omits the member rather than sending nothing" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}
    }, .{});
    defer fixture.deinit();

    // A tool that takes no arguments. `"arguments":` with nothing after it would be
    // the failure mode here, and it would break the whole message.
    _ = try fixture.client.callToolJson(fixture.allocator(), "ping", "   ", .{});

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("ping", params.get("name").?.string);
    try testing.expect(params.get("arguments") == null);
}

test "a retry splices answers beside pre-encoded params" {
    var elicitor: ScriptedElicitor = .{ .gpa = testing.allocator };
    defer elicitor.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
        \\ "inputRequests":{"where":{"method":"elicitation/create",
        \\  "params":{"mode":"form","message":"Where?",
        \\   "requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}}}}}},
        \\ "requestState":"opaque-state"}}
        ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}
    }, .{
        .elicitor = elicitor.elicitor(),
        .capabilities = elicitation_capable,
    });
    defer fixture.deinit();

    _ = try fixture.client.callToolInteractiveJson(
        fixture.allocator(),
        "forecast",
        "{\"days\":1.0}",
        .{},
    );

    // The caller's text is still verbatim on the retry — the answers went beside it,
    // not through a parse of it.
    const retry = fixture.transport.sent.items[1];
    try testing.expect(std.mem.indexOf(u8, retry, "\"days\":1.0") != null);

    const params = (try fixture.lastSent()).get("params").?.object;
    try testing.expectEqualStrings("forecast", params.get("name").?.string);
    try testing.expectEqualStrings("opaque-state", params.get("requestState").?.string);
    try testing.expect(params.get("inputResponses").?.object.get("where") != null);
}

test "a server's error is explained, not just named" {
    var log: std.Io.Writer.Allocating = .init(testing.allocator);
    defer log.deinit();

    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,
        \\ "message":"unknown argument: regoin"}}
    }, .{ .diagnostics = &log.writer });
    defer fixture.deinit();

    try testing.expectError(
        error.RequestFailed,
        fixture.client.callTool(fixture.allocator(), "forecast", null, .{}),
    );
    // The server said what was wrong. `error.RequestFailed` cannot carry it, so the
    // channel is the only place a caller can read it.
    try testing.expect(std.mem.indexOf(u8, log.written(), "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, log.written(), "regoin") != null);
}

test "an error response with no error object is an invalid reply" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1}
    }, .{});
    defer fixture.deinit();

    // Neither `result` nor `error`: not a response at all, whatever it parsed as.
    try testing.expectError(
        error.InvalidReply,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
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
        error.UnexpectedResult,
        fixture.client.requestInteractive(
            types.ListToolsResult,
            fixture.allocator(),
            types.method.tools_list,
            .none,
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
        error.UnexpectedResult,
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

// ---------------------------------------------------------------------------
// Falling back to the 2025 protocol
// ---------------------------------------------------------------------------

/// What a pre-2026-07-28 server answers `server/discover` with over stdio. The refusal
/// differs per transport, which is why negotiation matches on none of it.
const discover_not_found =
    \\{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}
;

/// A 2025 `InitializeResult`. No `resultType`, no cache fields — the era has neither.
const initialize_ok =
    \\{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25",
    \\ "capabilities":{"tools":{},"logging":{}},
    \\ "serverInfo":{"name":"legacy-server","version":"0.9"},
    \\ "instructions":"call add for arithmetic"}}
;

test "the default refuses to fall back, and sends no probe" {
    var fixture: Fixture = undefined;
    fixture.init(&.{discover_not_found}, .{});
    defer fixture.deinit();

    // `.reject` is the default, so the era is settled before anything is sent: one
    // request goes out, it is the caller's, and its failure is reported as-is.
    try testing.expectError(
        error.RequestFailed,
        fixture.client.discover(fixture.allocator(), .{}),
    );
    try testing.expectEqual(@as(usize, 1), fixture.transport.sent.items.len);
    try testing.expectEqualStrings("2026-07-28", fixture.client.negotiatedVersion().?);
}

test "negotiate falls back to the handshake when discover is not found" {
    var fixture: Fixture = undefined;
    fixture.init(&.{ discover_not_found, initialize_ok }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    const discovered = try fixture.client.discover(fixture.allocator(), .{});

    // The answer reads like a modern one, which is the point: a caller does not branch.
    try testing.expectEqual(@as(usize, 1), discovered.supportedVersions.len);
    try testing.expectEqualStrings("2025-11-25", discovered.supportedVersions[0]);
    try testing.expect(discovered.capabilities.tools != null);
    try testing.expect(discovered.capabilities.logging != null);
    try testing.expect(discovered.capabilities.prompts == null);
    try testing.expectEqualStrings("call add for arithmetic", discovered.instructions.?);
    try testing.expectEqualStrings("2025-11-25", fixture.client.negotiatedVersion().?);

    // The reported version must point into the client's own storage. Comparing the bytes
    // does not establish that: the first version of `negotiatedVersion` captured the
    // handshake by value and returned a slice into the switch's temporary, which still
    // read as "2025-11-25" here and as binary noise in a diagnostic two frames later.
    const reported = fixture.client.negotiatedVersion().?;
    const base = @intFromPtr(&fixture.client);
    try testing.expect(@intFromPtr(reported.ptr) >= base);
    try testing.expect(@intFromPtr(reported.ptr) + reported.len <= base + @sizeOf(Client));

    // Three messages: the probe, the handshake, and the confirmation the handshake is
    // only complete with.
    const sent = fixture.transport.sent.items;
    try testing.expectEqual(@as(usize, 3), sent.len);
    try testing.expect(std.mem.indexOf(u8, sent[0], "\"server/discover\"") != null);
    try testing.expect(std.mem.indexOf(u8, sent[1], "\"initialize\"") != null);
    try testing.expect(std.mem.indexOf(u8, sent[2], "\"notifications/initialized\"") != null);
}

test "the initialize request carries no 2026 vocabulary" {
    var fixture: Fixture = undefined;
    fixture.init(&.{ discover_not_found, initialize_ok }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    _ = try fixture.client.discover(fixture.allocator(), .{});

    const initialize = fixture.transport.sent.items[1];
    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.allocator(),
        initialize,
        .{},
    );
    const params = parsed.object.get("params").?.object;

    // The version and capabilities are params members here, not `_meta` keys, and there
    // is no `_meta` at all. This is the never-stamp rule: one 2026 key on this request
    // and a strict 2025 server rejects it.
    try testing.expectEqualStrings("2025-11-25", params.get("protocolVersion").?.string);
    try testing.expect(params.get("capabilities") != null);
    try testing.expectEqualStrings("test-client", params.get("clientInfo").?.object.get("name").?.string);
    try testing.expect(params.get("_meta") == null);
    try testing.expect(std.mem.indexOf(u8, initialize, "io.modelcontextprotocol/") == null);
    try testing.expect(std.mem.indexOf(u8, initialize, "2026-07-28") == null);
}

test "requests on a legacy connection carry no envelope either" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        discover_not_found,
        initialize_ok,
        // No `resultType`, which a 2025 server does not send and this client reads as
        // `complete` — the specification's own rule for exactly this direction.
        \\{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"add","inputSchema":{}}]}}
        ,
    }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    const listed = try fixture.client.listTools(fixture.allocator(), .{});
    try testing.expectEqual(@as(usize, 1), listed.tools.len);
    try testing.expectEqualStrings("add", listed.tools[0].name);

    // Index 3: the probe, the handshake and its confirmation come first.
    const request = fixture.transport.sent.items[3];
    try testing.expect(std.mem.indexOf(u8, request, "\"tools/list\"") != null);
    try testing.expect(std.mem.indexOf(u8, request, "_meta") == null);
    try testing.expect(std.mem.indexOf(u8, request, "io.modelcontextprotocol/") == null);
}

test "a progress token still travels on a legacy connection" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        discover_not_found,
        initialize_ok,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}
        ,
    }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    _ = try fixture.client.callTool(fixture.allocator(), "add", null, .{
        .progress_token = .{ .string = "p-1" },
        // Per-request log level has no field in this era. It is reported and dropped
        // rather than invented into `logging/setLevel` behind the caller's back.
        .log_level = .debug,
    });

    const request = fixture.transport.sent.items[3];
    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        fixture.allocator(),
        request,
        .{},
    );
    const meta = parsed.object.get("params").?.object.get("_meta").?.object;
    // `progressToken` is the one key both eras spell the same, because it predates the
    // prefix convention.
    try testing.expectEqualStrings("p-1", meta.get("progressToken").?.string);
    try testing.expectEqual(@as(usize, 1), meta.count());
}

test "a method the negotiated revision lacks is refused without being sent" {
    var fixture: Fixture = undefined;
    fixture.init(&.{ discover_not_found, initialize_ok }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    _ = try fixture.client.discover(fixture.allocator(), .{});
    const before = fixture.transport.sent.items.len;

    // `subscriptions/listen` replaced `resources/subscribe` in 2026-07-28. Sending it
    // would earn a `-32601`, which reads as a server missing a feature rather than a
    // connection that cannot express one.
    try testing.expectError(error.UnsupportedByRevision, fixture.client.exchange(
        fixture.allocator(),
        types.method.subscriptions_listen,
        .none,
        .{},
    ));
    try testing.expectEqual(before, fixture.transport.sent.items.len);
}

test "discover after the handshake costs no round trip" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        discover_not_found,
        initialize_ok,
        \\{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}
        ,
    }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    _ = try fixture.client.listTools(fixture.allocator(), .{});
    const before = fixture.transport.sent.items.len;

    // `initialize` may be sent once per connection, so this is answered from what the
    // handshake established. Everything but `instructions`, which is not kept.
    const discovered = try fixture.client.discover(fixture.allocator(), .{});
    try testing.expectEqual(before, fixture.transport.sent.items.len);
    try testing.expectEqualStrings("2025-11-25", discovered.supportedVersions[0]);
    try testing.expect(discovered.capabilities.tools != null);
    try testing.expect(discovered.instructions == null);
}

test "a modern server is not made to pay for the fallback" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ttlMs":0,
        \\ "cacheScope":"private","supportedVersions":["2026-07-28"],"capabilities":{}}}
    }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    // The probe *is* the discover request, so a modern server sees exactly one message
    // and the answer is its own.
    const discovered = try fixture.client.discover(fixture.allocator(), .{});
    try testing.expectEqual(@as(usize, 1), fixture.transport.sent.items.len);
    try testing.expectEqualStrings("2026-07-28", discovered.supportedVersions[0]);
    try testing.expectEqualStrings("2026-07-28", fixture.client.negotiatedVersion().?);
}

test "a peer that refuses both revisions reports the handshake's failure" {
    var fixture: Fixture = undefined;
    fixture.init(&.{
        discover_not_found,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}
        ,
    }, .{ .legacy = .negotiate });
    defer fixture.deinit();

    try testing.expectError(
        error.RequestFailed,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
    // The era stays unsettled, so a later call tries again rather than committing to a
    // guess about a peer that answered nothing.
    try testing.expect(fixture.client.negotiatedVersion() == null);
}

test "a transport failure during the probe is not read as a legacy server" {
    var fixture: Fixture = undefined;
    // Nothing scripted: the transport ends the exchange without answering.
    fixture.init(&.{}, .{ .legacy = .negotiate });
    defer fixture.deinit();

    // A connection that broke says nothing about which protocol was on it, so no
    // handshake is attempted and the era stays unknown.
    try testing.expectError(
        error.NoResponse,
        fixture.client.listTools(fixture.allocator(), .{}),
    );
    try testing.expectEqual(@as(usize, 1), fixture.transport.sent.items.len);
    try testing.expect(fixture.client.negotiatedVersion() == null);
}

test "setLogLevel is the legacy way in, and refused on a modern connection" {
    {
        var fixture: Fixture = undefined;
        fixture.init(&.{
            discover_not_found,
            initialize_ok,
            \\{"jsonrpc":"2.0","id":3,"result":{}}
            ,
        }, .{ .legacy = .negotiate });
        defer fixture.deinit();

        try fixture.client.setLogLevel(fixture.allocator(), .debug);
        const sent = fixture.transport.sent.items[3];
        try testing.expect(std.mem.indexOf(u8, sent, "\"logging/setLevel\"") != null);
        try testing.expect(std.mem.indexOf(u8, sent, "\"level\":\"debug\"") != null);
    }
    {
        var fixture: Fixture = undefined;
        fixture.init(&.{}, .{});
        defer fixture.deinit();

        // 2026-07-28 removed the method: the level is per-request `_meta` there, and
        // asking a stateless protocol to remember one is the mistake this names.
        try testing.expectError(
            error.UnsupportedByRevision,
            fixture.client.setLogLevel(fixture.allocator(), .debug),
        );
        try testing.expectEqual(@as(usize, 0), fixture.transport.sent.items.len);
    }
}
