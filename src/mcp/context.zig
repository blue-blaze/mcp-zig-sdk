//! The context a request handler runs in.
//!
//! One of these is created per request and torn down with it. It carries the
//! request's arena, so a handler can allocate freely without tracking individual
//! frees, and the request's `_meta`, so a handler can see who is calling and what
//! they opted into.
//!
//! Progress reporting, per-request logging and cancellation attach here too; they
//! are request-scoped by definition in 2026-07-28, where a log level is set per
//! request rather than per connection.

const std = @import("std");
const assert_mod = @import("assert");
const types = @import("types.zig");

const assert = assert_mod.assert;

/// Errors a handler may return. Note what is *not* here: a tool that runs and
/// fails is not a protocol error. It returns a `CallToolResult` with `isError`
/// set, so the model can see what went wrong and react. These errors are for
/// failures of the request itself.
pub const Error = error{
    /// Params were missing, malformed, or otherwise unusable. Answered with
    /// `-32602`.
    InvalidParams,
    /// The named tool, prompt or resource does not exist. Answered with `-32602`
    /// too: 2026-07-28 moved resource-not-found from `-32002` to align with
    /// JSON-RPC.
    NotFound,
    /// The server failed. Answered with `-32603`.
    Internal,
    /// The request was cancelled; no response should be sent.
    Cancelled,
    /// The handler needs input from the user before it can answer. Answered with an
    /// `InputRequiredResult` built from what the handler recorded on its `Context`.
    ///
    /// It is an error rather than a return value on purpose: "I cannot produce a
    /// result yet" is exactly the shape an error has, and it composes with `try`, so
    /// a handler can ask for input from anywhere in its body without every
    /// intermediate step having to carry a union.
    InputRequired,
    /// The handler needs something the client did not declare support for. Answered
    /// with `-32021`, carrying what was required.
    MissingClientCapability,
    OutOfMemory,
};

/// A one-way cancellation flag, owned by the transport and observed by the handler.
///
/// One-way is the whole design: it is set at most once and never cleared, so a
/// handler that has seen it cancelled can never see it uncancelled, and no
/// ordering subtlety can resurrect a request the peer has abandoned.
///
/// It is atomic because the transport may flip it from the thread that reads the
/// connection while the handler runs on another. On a sequential transport that
/// costs a relaxed load per poll and nothing else.
pub const Cancellation = struct {
    flag: std.atomic.Value(bool) = .init(false),

    /// Marks the request cancelled. Idempotent.
    pub fn cancel(cancellation: *Cancellation) void {
        cancellation.flag.store(true, .release);
    }

    pub fn isCancelled(cancellation: *const Cancellation) bool {
        return cancellation.flag.load(.acquire);
    }
};

/// Where request-scoped notifications go. The transport supplies this: on stdio
/// they are written to the shared output stream, on Streamable HTTP to the SSE
/// stream of the request they belong to.
///
/// The sink takes an already-encoded notification rather than a typed value. A
/// vtable cannot carry a generic parameter, and pushing encoding to the caller
/// keeps the transport's job to exactly one thing: moving bytes.
pub const NotificationSink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Delivers one complete JSON-RPC notification.
        ///
        /// Returns nothing, deliberately. A notification that could not be
        /// delivered must not fail the request that produced it: progress and log
        /// messages are advisory, and losing one is not a reason to lose the
        /// result. Implementations record the failure out of band.
        send: *const fn (ptr: *anyopaque, message: []const u8) void,
    };

    pub fn send(sink: NotificationSink, message: []const u8) void {
        assert(message.len > 0);
        sink.vtable.send(sink.ptr, message);
    }
};

pub const Context = struct {
    /// Freed wholesale when the request finishes.
    arena: std.mem.Allocator,
    /// The caller's `_meta`, already decoded.
    meta: types.RequestMeta,
    /// Where notifications this handler emits are delivered. Absent when the
    /// transport cannot carry request-scoped notifications, in which case
    /// `reportProgress` and `log` are silent no-ops.
    sink: ?NotificationSink = null,
    /// Observed to see whether the peer gave up on this request.
    cancellation: ?*const Cancellation = null,
    /// The last progress value reported, used to enforce monotonicity.
    progress_last: f64 = 0,

    /// Application state, supplied once by whoever built the `Server`.
    ///
    /// Comptime-registered handlers take only a `*Context`, so without this a server
    /// needing state has to reach for a container-level `var` — which is a global with
    /// extra steps, and makes two servers in one process share it. Read it with
    /// `userAs`.
    user: ?*anyopaque = null,
    /// The `inputResponses` the client echoed back on a retry, keyed as the server
    /// keyed its requests. Absent on a first attempt.
    input_responses: ?std.json.ObjectMap = null,
    /// The `requestState` the client echoed back, exactly as issued.
    ///
    /// Untrusted: it travelled through the client. See `mcp.request_state.Sealer`
    /// for a representation whose tampering is detectable.
    incoming_state: ?[]const u8 = null,
    /// Input requests the handler has asked for, accumulated by `elicit*`.
    pending_requests: std.json.ObjectMap = .empty,
    /// State the handler wants echoed back, set by `needInput`.
    pending_state: ?[]const u8 = null,

    /// Creates a context for a request. The arena must outlive the handler call.
    pub fn init(arena: std.mem.Allocator, meta: types.RequestMeta) Context {
        return .{ .arena = arena, .meta = meta };
    }

    /// The log level the client asked for on this request, if any.
    ///
    /// Absent means the server must not emit `notifications/message` at all for
    /// this request — the client opts in by naming a level, and there is no
    /// connection-wide setting to fall back on.
    /// The application state as `T`, which must be the pointer type it was set with.
    ///
    /// Asserts it was set: a handler that reads this has been written against a server
    /// that supplies it, and a null here is a wiring mistake rather than a state a
    /// handler should carry a branch for.
    pub fn userAs(context: *const Context, comptime T: type) T {
        comptime assert(@typeInfo(T) == .pointer);
        const pointer = context.user orelse unreachable;
        return @ptrCast(@alignCast(pointer));
    }

    pub fn logLevel(context: *const Context) ?types.LoggingLevel {
        return context.meta.log_level;
    }

    /// Whether a message at `level` should be sent for this request.
    pub fn wantsLog(context: *const Context, level: types.LoggingLevel) bool {
        const minimum = context.meta.log_level orelse return false;
        return level.atLeast(minimum);
    }

    /// The progress token to tag `notifications/progress` with, if the client
    /// asked for progress.
    pub fn progressToken(context: *const Context) ?types.ProgressToken {
        return context.meta.progress_token;
    }

    // ---- Cancellation ----------------------------------------------------

    /// Whether the peer has abandoned this request.
    ///
    /// Handlers that do meaningful work should poll this between steps. A handler
    /// that ignores it is not wrong, only wasteful: the response is discarded
    /// either way.
    pub fn cancelled(context: *const Context) bool {
        const cancellation = context.cancellation orelse return false;
        return cancellation.isCancelled();
    }

    /// Returns `error.Cancelled` if the peer has abandoned this request.
    ///
    /// Returning that error is how a handler stops: the dispatcher turns it into
    /// no response at all, which is what the spec requires — the peer is not
    /// waiting, so an error response would be an unsolicited message.
    pub fn checkCancelled(context: *const Context) Error!void {
        if (context.cancelled()) return error.Cancelled;
    }

    // ---- Progress --------------------------------------------------------

    pub const Progress = struct {
        /// Total units of work, if known. A client renders a determinate bar when
        /// this is present and an indeterminate one when it is not.
        total: ?f64 = null,
        /// Human-readable description of the current step.
        message: ?[]const u8 = null,
    };

    /// Reports progress on this request.
    ///
    /// Silent unless the client supplied a progress token: the spec makes progress
    /// opt-in, and a server that notified anyway would be sending something the
    /// client has no way to correlate with a request.
    ///
    /// `progress` must not decrease across calls. A backwards progress bar is a
    /// handler bug worth failing loudly on in a debug build rather than shipping
    /// to a user's screen.
    pub fn reportProgress(context: *Context, progress: f64, options: Progress) void {
        const token = context.progressToken() orelse return;
        assert(progress >= context.progress_last);
        if (options.total) |total| assert(progress <= total);
        context.progress_last = progress;

        context.emit(types.notification.progress, types.ProgressParams{
            .progressToken = token,
            .progress = progress,
            .total = options.total,
            .message = options.message,
        });
    }

    // ---- Logging ---------------------------------------------------------

    pub const LogOptions = struct {
        /// Name of the component issuing the message, for a client that groups or
        /// filters by source.
        logger: ?[]const u8 = null,
    };

    /// Emits a structured log message, if the client opted in at this level or
    /// below.
    pub fn log(
        context: *Context,
        level: types.LoggingLevel,
        data: std.json.Value,
        options: LogOptions,
    ) void {
        if (!context.wantsLog(level)) return;
        context.emit(types.notification.message, types.LoggingMessageParams{
            .level = level,
            .data = data,
            .logger = options.logger,
        });
    }

    /// Emits a formatted text log message, if the client opted in at this level.
    ///
    /// The level check happens before formatting, so a server can leave debug
    /// logging in place and pay nothing for it when nobody asked to see it.
    pub fn logPrint(
        context: *Context,
        level: types.LoggingLevel,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (!context.wantsLog(level)) return;
        const message = std.fmt.allocPrint(context.arena, fmt, args) catch return;
        context.emit(types.notification.message, types.LoggingMessageParams{
            .level = level,
            .data = .{ .string = message },
        });
    }

    /// Encodes and delivers one notification.
    ///
    /// Every failure path here drops the notification rather than propagating it.
    /// Progress and log messages are advisory; failing a request because a progress
    /// update could not be allocated would trade away what the caller asked for to
    /// protect what it did not.
    fn emit(context: *Context, comptime method: []const u8, params: anytype) void {
        // The method names are our own constants, so this is a check on the SDK
        // rather than on input — but an unescaped quote here would produce a
        // malformed message on the wire, which is worth ruling out at compile time.
        comptime assert(std.mem.indexOfAny(u8, method, "\"\\") == null);

        const sink = context.sink orelse return;

        var out: std.Io.Writer.Allocating = .init(context.arena);
        out.writer.writeAll(
            "{\"jsonrpc\":\"2.0\",\"method\":\"" ++ method ++ "\",\"params\":",
        ) catch return;
        types.stringify(&out.writer, params) catch return;
        out.writer.writeAll("}") catch return;

        sink.send(out.written());
    }

    // ---- Multi-round-trip input ------------------------------------------

    /// Which elicitation modes the calling client declared.
    pub fn elicitationSupport(context: *const Context) types.ElicitationSupport {
        return .fromCapabilities(context.meta.capabilities);
    }

    /// Whether the client can answer an elicitation in this mode.
    ///
    /// Worth checking before doing expensive work: a handler that discovers halfway
    /// through that it cannot ask the user has wasted the effort.
    pub fn canElicit(context: *const Context, mode: types.ElicitMode) bool {
        return context.elicitationSupport().supports(mode);
    }

    /// The state the client echoed back, if this is a retry.
    ///
    /// Treat it as attacker-controlled. A server that lets it influence
    /// authorization or business logic must verify its integrity first.
    pub fn requestState(context: *const Context) ?[]const u8 {
        return context.incoming_state;
    }

    /// Whether this is a retry carrying answers to a previous round.
    pub fn isRetry(context: *const Context) bool {
        return context.input_responses != null or context.incoming_state != null;
    }

    /// The client's raw answer for one of the keys this handler asked about.
    pub fn inputResponse(context: *const Context, key: []const u8) ?std.json.Value {
        const responses = context.input_responses orelse return null;
        return responses.get(key);
    }

    /// The client's elicitation answer for one key, decoded.
    ///
    /// Null means the client did not answer that key. The spec's guidance is to ask
    /// again rather than error, since an unanswered request is not a protocol
    /// violation.
    pub fn elicited(context: *const Context, key: []const u8) ?types.ElicitResult {
        const value = context.inputResponse(key) orelse return null;
        return types.ElicitResult.fromValue(value) catch null;
    }

    /// Asks the client to collect structured data from the user.
    ///
    /// Fails with `MissingClientCapability` when the client did not declare form
    /// support, which is what stops a server from sending a request the client can
    /// only ignore — leaving the flow stuck.
    ///
    /// Never use this for secrets. Form data passes through the client and the model;
    /// passwords, API keys, tokens and payment details must go through `elicitUrl`.
    pub fn elicitForm(
        context: *Context,
        key: []const u8,
        message: []const u8,
        requested_schema: types.Json,
    ) Error!void {
        return context.elicit(key, .{ .form = .{
            .message = message,
            .requestedSchema = requested_schema,
        } });
    }

    /// Asks the client to send the user to a URL for an out-of-band interaction.
    ///
    /// This is the only correct channel for anything sensitive: the data never
    /// reaches the client. The URL must not be pre-authenticated and must not carry
    /// anything identifying about the user — a malicious client sees it, and can hand
    /// it to somebody else.
    pub fn elicitUrl(
        context: *Context,
        key: []const u8,
        message: []const u8,
        url: []const u8,
    ) Error!void {
        return context.elicit(key, .{ .url = .{ .message = message, .url = url } });
    }

    fn elicit(context: *Context, key: []const u8, request: types.ElicitRequest) Error!void {
        assert(key.len > 0);

        if (!context.canElicit(request.mode())) return error.MissingClientCapability;
        // Keys must be unique within one result; reusing one would silently discard
        // the earlier request.
        assert(context.pending_requests.get(key) == null);

        const encoded = try types.stringifyAlloc(context.arena, request);
        const parsed = std.json.parseFromSliceLeaky(
            std.json.Value,
            context.arena,
            encoded,
            .{},
        ) catch return error.OutOfMemory;

        try context.pending_requests.put(context.arena, key, parsed);
    }

    pub const NeedInput = struct {
        /// Opaque state to hand the client for echoing back. Required when nothing
        /// was elicited, because a result with neither field tells the client nothing
        /// and it would retry forever.
        state: ?[]const u8 = null,
    };

    /// Stops the handler and asks the client for another round trip.
    ///
    /// Written as `return context.needInput(.{ .state = ... });` — it returns the
    /// error value that the dispatcher turns into an `InputRequiredResult`.
    pub fn needInput(context: *Context, options: NeedInput) Error {
        // At least one of the two must reach the client.
        assert(context.pending_requests.count() > 0 or options.state != null);

        context.pending_state = options.state;
        return error.InputRequired;
    }

    /// The result the dispatcher sends after a handler asked for input.
    pub fn inputRequiredResult(context: *const Context) types.InputRequiredResult {
        return .{
            .inputRequests = if (context.pending_requests.count() > 0)
                .{ .object = context.pending_requests }
            else
                null,
            .requestState = context.pending_state,
        };
    }

    /// The capabilities to report in a `-32021`, derived from what was attempted.
    ///
    /// Both modes are named because a handler that failed on one may well need the
    /// other later, and telling the client only about this attempt would have it
    /// re-fail on the next.
    pub fn requiredCapabilities(
        context: *const Context,
        arena: std.mem.Allocator,
    ) error{OutOfMemory}!types.ClientCapabilities {
        _ = context;
        const support: types.ElicitationSupport = .{ .form = true, .url = true };
        return support.toCapabilities(arena);
    }

    // ---- Result helpers --------------------------------------------------

    /// Allocates a formatted string in the request arena.
    pub fn print(
        context: *const Context,
        comptime fmt: []const u8,
        args: anytype,
    ) error{OutOfMemory}![]u8 {
        return std.fmt.allocPrint(context.arena, fmt, args);
    }

    /// A single text content block, allocated in the request arena.
    pub fn text(context: *const Context, bytes: []const u8) error{OutOfMemory}![]types.ContentBlock {
        const blocks = try context.arena.alloc(types.ContentBlock, 1);
        blocks[0] = types.ContentBlock.fromText(bytes);
        return blocks;
    }

    /// A successful tool result carrying one text block.
    pub fn textResult(
        context: *const Context,
        bytes: []const u8,
    ) error{OutOfMemory}!types.CallToolResult {
        return .{ .content = try context.text(bytes) };
    }

    /// A tool *failure* — the tool ran and did not succeed. This is a successful
    /// protocol response with `isError` set, which is what lets the model see the
    /// failure instead of the client swallowing it.
    pub fn errorResult(
        context: *const Context,
        bytes: []const u8,
    ) error{OutOfMemory}!types.CallToolResult {
        return .{ .content = try context.text(bytes), .isError = true };
    }
};

/// Collects notifications in memory. Used by tests and by any caller that wants to
/// inspect what a handler emitted rather than deliver it.
pub const CollectingSink = struct {
    gpa: std.mem.Allocator,
    messages: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Set when a notification could not be recorded, so a test can tell "nothing
    /// was emitted" apart from "recording failed".
    dropped: usize = 0,

    pub fn init(gpa: std.mem.Allocator) CollectingSink {
        return .{ .gpa = gpa };
    }

    pub fn deinit(collector: *CollectingSink) void {
        for (collector.messages.items) |message| collector.gpa.free(message);
        collector.messages.deinit(collector.gpa);
    }

    pub fn sink(collector: *CollectingSink) NotificationSink {
        return .{ .ptr = collector, .vtable = &vtable };
    }

    const vtable: NotificationSink.VTable = .{ .send = send };

    fn send(ptr: *anyopaque, message: []const u8) void {
        const collector: *CollectingSink = @ptrCast(@alignCast(ptr));
        // The message lives in the request arena, which is reset before a test can
        // look at it, so it has to be copied out.
        const owned = collector.gpa.dupe(u8, message) catch {
            collector.dropped += 1;
            return;
        };
        collector.messages.append(collector.gpa, owned) catch {
            collector.gpa.free(owned);
            collector.dropped += 1;
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "a context with no log level wants no log messages" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const context: Context = .init(arena.allocator(), .{});
    try testing.expect(context.logLevel() == null);
    // The spec is a MUST NOT: without an opt-in, not even the most severe message
    // may be sent.
    try testing.expect(!context.wantsLog(.emergency));
    try testing.expect(!context.wantsLog(.debug));
}

test "a context filters log messages against the requested level" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const context: Context = .init(arena.allocator(), .{ .log_level = .warning });
    try testing.expect(context.wantsLog(.warning));
    try testing.expect(context.wantsLog(.@"error"));
    try testing.expect(context.wantsLog(.emergency));
    try testing.expect(!context.wantsLog(.info));
    try testing.expect(!context.wantsLog(.debug));
}

test "a context exposes the progress token when one was supplied" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const without: Context = .init(arena.allocator(), .{});
    try testing.expect(without.progressToken() == null);

    const with: Context = .init(arena.allocator(), .{ .progress_token = .{ .number = 9 } });
    try testing.expectEqual(@as(i64, 9), with.progressToken().?.number);
}

test "context helpers allocate in the request arena" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const context: Context = .init(arena.allocator(), .{});

    const message = try context.print("{d} + {d} = {d}", .{ 1, 2, 3 });
    try testing.expectEqualStrings("1 + 2 = 3", message);

    const result = try context.textResult(message);
    try testing.expectEqual(@as(usize, 1), result.content.len);
    try testing.expectEqualStrings("1 + 2 = 3", result.content[0].text.text);
    try testing.expect(result.isError == null);
}

test "an error result is a successful response with isError set" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const context: Context = .init(arena.allocator(), .{});
    const result = try context.errorResult("city not found");

    try testing.expectEqual(true, result.isError.?);
    try testing.expectEqualStrings("city not found", result.content[0].text.text);

    // Serializes as a complete result: the failure is the tool's, not the
    // protocol's.
    const bytes = try types.stringifyAlloc(testing.allocator, result);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"resultType":"complete","content":[{"type":"text","text":"city not found"}],"isError":true}
    , bytes);
}

// ---- Progress -------------------------------------------------------------

test "progress is silent without a token from the client" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{});
    context.sink = collector.sink();

    // Progress is opt-in. Without a token there is nothing for the client to
    // correlate the notification with, so sending one would be noise.
    context.reportProgress(1, .{});
    context.reportProgress(2, .{ .total = 10 });
    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
}

test "progress carries the client's token and the optional total" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .progress_token = .{ .string = "p-1" } });
    context.sink = collector.sink();

    context.reportProgress(3, .{ .total = 10, .message = "fetching" });
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p-1","progress":3,"total":10,"message":"fetching"}}
    , collector.messages.items[0]);
}

test "progress omits what the handler did not supply" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .progress_token = .{ .number = 7 } });
    context.sink = collector.sink();

    // An unknown total is an absent field, not a zero: the client renders an
    // indeterminate bar rather than one that is stuck at 100%.
    context.reportProgress(0.5, .{});
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":7,"progress":0.5}}
    , collector.messages.items[0]);
}

test "progress may be reported repeatedly" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .progress_token = .{ .number = 1 } });
    context.sink = collector.sink();

    for (0..4) |step| context.reportProgress(@floatFromInt(step), .{ .total = 3 });
    try testing.expectEqual(@as(usize, 4), collector.messages.items.len);
}

test "progress does nothing at all without a sink" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // A transport that cannot carry request-scoped notifications leaves the sink
    // unset; handlers must not have to care.
    var context: Context = .init(arena.allocator(), .{ .progress_token = .{ .number = 1 } });
    context.reportProgress(1, .{});
}

// ---- Logging --------------------------------------------------------------

test "logging is silent unless the client opted in" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{});
    context.sink = collector.sink();

    // The spec is a MUST NOT: with no level in `_meta`, not even an emergency is
    // sent.
    context.logPrint(.emergency, "the building is on fire", .{});
    context.log(.@"error", .{ .string = "x" }, .{});
    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
}

test "logging filters against the level the client asked for" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .log_level = .warning });
    context.sink = collector.sink();

    context.logPrint(.debug, "too quiet to send", .{});
    context.logPrint(.info, "also too quiet", .{});
    context.logPrint(.warning, "loud enough", .{});
    context.logPrint(.critical, "louder still", .{});

    try testing.expectEqual(@as(usize, 2), collector.messages.items.len);
    try testing.expect(std.mem.indexOf(u8, collector.messages.items[0], "loud enough") != null);
    try testing.expect(std.mem.indexOf(u8, collector.messages.items[1], "louder still") != null);
}

test "a log message encodes level, data and logger" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .log_level = .debug });
    context.sink = collector.sink();

    context.log(.notice, .{ .string = "cache warm" }, .{ .logger = "cache" });
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"notice","data":"cache warm","logger":"cache"}}
    , collector.messages.items[0]);
}

test "log data may be any JSON value" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .log_level = .debug });
    context.sink = collector.sink();

    var payload: std.json.ObjectMap = .empty;
    defer payload.deinit(testing.allocator);
    try payload.put(testing.allocator, "attempt", .{ .integer = 3 });

    context.log(.info, .{ .object = payload }, .{});
    try testing.expect(std.mem.indexOf(
        u8,
        collector.messages.items[0],
        "\"data\":{\"attempt\":3}",
    ) != null);
}

test "the error log level serializes under its wire name" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var collector: CollectingSink = .init(testing.allocator);
    defer collector.deinit();

    var context: Context = .init(arena.allocator(), .{ .log_level = .debug });
    context.sink = collector.sink();

    // `error` is a Zig keyword, so this one is the most likely to come out wrong.
    context.logPrint(.@"error", "boom", .{});
    try testing.expect(std.mem.indexOf(
        u8,
        collector.messages.items[0],
        "\"level\":\"error\"",
    ) != null);
}

// ---- Cancellation ---------------------------------------------------------

test "a context without a cancellation token is never cancelled" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const context: Context = .init(arena.allocator(), .{});
    try testing.expect(!context.cancelled());
    try context.checkCancelled();
}

test "cancellation is observed through the token" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var cancellation: Cancellation = .{};

    var context: Context = .init(arena.allocator(), .{});
    context.cancellation = &cancellation;

    try testing.expect(!context.cancelled());
    try context.checkCancelled();

    cancellation.cancel();
    try testing.expect(context.cancelled());
    try testing.expectError(error.Cancelled, context.checkCancelled());

    // Cancellation is one-way: cancelling again cannot un-cancel.
    cancellation.cancel();
    try testing.expect(context.cancelled());
}

test "userAs hands back the application state a server was built with" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    const Counter = struct { hits: usize = 0 };
    var counter: Counter = .{};

    var context: Context = .init(arena_state.allocator(), .{
        .protocol_version = types.protocol_version,
        .capabilities = .{},
    });
    context.user = &counter;

    // The round trip through `*anyopaque` is the whole point: a handler that gets this
    // wrong reads the pointer's own bits as its state, which fails far from the cause.
    context.userAs(*Counter).hits += 1;
    try std.testing.expectEqual(@as(usize, 1), counter.hits);
}
