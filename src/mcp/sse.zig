//! Server-Sent Events framing, as MCP uses it.
//!
//! Streamable HTTP carries a request's notifications and its final response over
//! SSE. Only a small part of the format is needed for that — every MCP event is an
//! unnamed `data:` event whose payload is one JSON-RPC message — but the parts that
//! are needed have to be exactly right, because a mis-framed stream desynchronises
//! everything after it rather than corrupting one message.
//!
//! ## What this deliberately does not implement
//!
//! `Last-Event-ID` and stream resumption were removed in 2026-07-28, so `id:` fields
//! are neither produced nor acted on. `retry:` is a browser-reconnect hint with no
//! meaning for a protocol that does not reconnect. Both are skipped on input rather
//! than rejected: a compliant peer will not send them, and refusing to read a stream
//! over a field we have no use for would be gratuitous.
//!
//! ## Multi-line payloads
//!
//! SSE splits a payload on newlines into several `data:` lines, which the receiver
//! rejoins with `\n`. Encoding here never needs it — every message is compact JSON —
//! but decoding must, because a conforming peer may split wherever it likes and a
//! decoder that took only the first line would silently truncate.

const std = @import("std");
const assert_mod = @import("assert");

const assert = assert_mod.assert;

/// The `Content-Type` an SSE response carries.
pub const content_type = "text/event-stream";

/// Tells reverse proxies not to buffer the response.
///
/// The spec says SHOULD, and the reason is concrete: nginx and friends accumulate a
/// response body by default, which turns a stream of progress updates into one burst
/// at the end — technically correct and useless.
pub const no_buffering_header = "X-Accel-Buffering";
pub const no_buffering_value = "no";

/// Largest event this decoder will accumulate, matching the protocol's message limit.
pub const event_size_max = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Writes one message as an SSE event and flushes it.
///
/// Flushing per event is the point of the transport: a progress notification that
/// sits in a buffer until the response is ready is worse than not sending it, because
/// the client paid for the stream and got nothing from it.
pub fn writeEvent(writer: *std.Io.Writer, message: []const u8) std.Io.Writer.Error!void {
    assert(message.len > 0);

    // A newline inside the payload would end the data line and split one message into
    // two events. Everything this SDK encodes is compact JSON, so this asserts a
    // property of our own encoder rather than validating input.
    assert(std.mem.indexOfScalar(u8, message, '\n') == null);
    assert(std.mem.indexOfScalar(u8, message, '\r') == null);

    try writer.writeAll("data: ");
    try writer.writeAll(message);
    try writer.writeAll("\r\n\r\n");
    try writer.flush();
}

/// Writes a keep-alive comment.
///
/// A quiet `subscriptions/listen` stream looks dead to an idle-timeout somewhere in
/// the middle, and the connection gets closed under both peers. A comment line is the
/// cheapest thing that keeps it open: per the SSE spec any line starting with a colon
/// carries no data and receivers must ignore it.
pub fn writeKeepAlive(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(":\r\n\r\n");
    try writer.flush();
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    /// The underlying stream failed.
    ReadFailed,
    /// An event exceeded `event_size_max`.
    EventTooLarge,
    OutOfMemory,
};

/// Reads SSE events off a stream, yielding the payload of each.
///
/// Comments, `id:`, `retry:` and unknown fields are consumed and skipped, so a caller
/// sees only messages. That keeps the SSE layer's concerns out of the JSON-RPC layer's
/// loop entirely.
pub const Decoder = struct {
    reader: *std.Io.Reader,

    pub fn init(reader: *std.Io.Reader) Decoder {
        return .{ .reader = reader };
    }

    /// Returns the next event's payload, allocated in `arena`, or null at end of
    /// stream.
    ///
    /// An event with no `data` field — a bare comment, or a lone `id:` — is not a
    /// message and is skipped rather than surfaced as an empty one.
    pub fn next(
        decoder: *Decoder,
        arena: std.mem.Allocator,
    ) DecodeError!?[]const u8 {
        var payload: std.Io.Writer.Allocating = .init(arena);
        var have_data = false;
        var total: usize = 0;

        while (true) {
            const line = try decoder.readLine(arena, &total) orelse {
                // End of stream. A complete event may still be pending if the peer
                // closed without a blank line after it; returning it is better than
                // discarding a message we fully received.
                if (have_data) return payload.written();
                return null;
            };

            if (line.len == 0) {
                // Blank line dispatches the event.
                if (have_data) return payload.written();
                // Nothing accumulated: a comment or an ignored field. Keep reading.
                payload = .init(arena);
                continue;
            }

            // A leading colon makes the whole line a comment.
            if (line[0] == ':') continue;

            const colon = std.mem.indexOfScalar(u8, line, ':');
            const field = if (colon) |index| line[0..index] else line;
            const raw = if (colon) |index| line[index + 1 ..] else "";
            // Exactly one leading space is part of the framing, not the value.
            const value = if (raw.len > 0 and raw[0] == ' ') raw[1..] else raw;

            if (!std.mem.eql(u8, field, "data")) {
                // `event`, `id`, `retry` and anything unknown. None of them carry a
                // message in this protocol, and the SSE spec says to ignore fields
                // that are not understood.
                continue;
            }

            // Several data lines join with a newline, per the SSE spec. A decoder that
            // used only the first would silently truncate a payload a conforming peer
            // is entitled to split.
            if (have_data) {
                payload.writer.writeAll("\n") catch return error.OutOfMemory;
            }
            payload.writer.writeAll(value) catch return error.OutOfMemory;
            have_data = true;
        }
    }

    /// Reads one line, handling both `\n` and `\r\n`, and returns null at end of
    /// stream. `total` accumulates the size of the event being built so that a peer
    /// cannot grow one without bound.
    fn readLine(
        decoder: *Decoder,
        arena: std.mem.Allocator,
        total: *usize,
    ) DecodeError!?[]const u8 {
        var line: std.Io.Writer.Allocating = .init(arena);
        const remaining = event_size_max - @min(total.*, event_size_max);
        if (remaining == 0) return error.EventTooLarge;

        const length = decoder.reader.streamDelimiterLimit(
            &line.writer,
            '\n',
            .limited(remaining),
        ) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => return error.OutOfMemory,
            error.StreamTooLong => return error.EventTooLarge,
        };

        const terminated = blk: {
            const byte = decoder.reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => break :blk false,
                error.ReadFailed => return error.ReadFailed,
            };
            assert(byte == '\n');
            break :blk true;
        };

        total.* += length + 1;
        if (length == 0 and !terminated) return null;
        return std.mem.trimEnd(u8, line.written(), "\r");
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "an event is framed as a single data line" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    try writeEvent(&output.writer, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    try testing.expectEqualStrings(
        "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n",
        output.written(),
    );
}

test "a keep-alive is a bare comment line" {
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();

    // Per the SSE spec a receiver must ignore this, which is what makes it usable as
    // a heartbeat that cannot be mistaken for data.
    try writeKeepAlive(&output.writer);
    try testing.expectEqualStrings(":\r\n\r\n", output.written());
}

/// Decodes every event in `stream`.
fn decodeAll(
    arena: std.mem.Allocator,
    stream: []const u8,
) ![]const []const u8 {
    var reader: std.Io.Reader = .fixed(stream);
    var decoder: Decoder = .init(&reader);

    var events: std.ArrayListUnmanaged([]const u8) = .empty;
    while (try decoder.next(arena)) |event| {
        try events.append(arena, event);
    }
    return events.items;
}

test "events are decoded in order" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const events = try decodeAll(
        arena.allocator(),
        "data: {\"a\":1}\r\n\r\ndata: {\"b\":2}\r\n\r\n",
    );
    try testing.expectEqual(@as(usize, 2), events.len);
    try testing.expectEqualStrings("{\"a\":1}", events[0]);
    try testing.expectEqualStrings("{\"b\":2}", events[1]);
}

test "bare newlines are accepted as line endings" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The SSE spec allows LF, CRLF or CR as a line terminator, and real servers use
    // LF. Rejecting it would be a pointless interoperability failure.
    const events = try decodeAll(arena.allocator(), "data: {\"a\":1}\n\ndata: {\"b\":2}\n\n");
    try testing.expectEqual(@as(usize, 2), events.len);
    try testing.expectEqualStrings("{\"a\":1}", events[0]);
}

test "a payload with no space after the colon is read intact" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Exactly one leading space is framing; anything else belongs to the value.
    const events = try decodeAll(arena.allocator(), "data:{\"a\":1}\n\n");
    try testing.expectEqualStrings("{\"a\":1}", events[0]);
}

test "only one leading space is stripped" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const events = try decodeAll(arena.allocator(), "data:  leading\n\n");
    try testing.expectEqualStrings(" leading", events[0]);
}

test "comments are ignored and do not produce events" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const events = try decodeAll(
        arena.allocator(),
        ":\r\n\r\n" ++ // a keep-alive
            ": some human-readable note\r\n\r\n" ++
            "data: {\"a\":1}\r\n\r\n" ++
            ":\r\n\r\n",
    );
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqualStrings("{\"a\":1}", events[0]);
}

test "fields this protocol does not use are skipped" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // `id` and `retry` exist for browser reconnection, which 2026-07-28 removed.
    // Skipping them rather than rejecting keeps this readable by a peer that emits
    // them out of habit.
    const events = try decodeAll(
        arena.allocator(),
        "id: 42\r\nretry: 3000\r\nevent: message\r\ndata: {\"a\":1}\r\n\r\n" ++
            "id: 43\r\n\r\n" ++
            "data: {\"b\":2}\r\n\r\n",
    );
    try testing.expectEqual(@as(usize, 2), events.len);
    try testing.expectEqualStrings("{\"a\":1}", events[0]);
    try testing.expectEqualStrings("{\"b\":2}", events[1]);
}

test "a payload split over several data lines is rejoined" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // A conforming peer may split wherever it likes. Taking only the first line would
    // silently truncate the message.
    const events = try decodeAll(arena.allocator(), "data: line one\r\ndata: line two\r\n\r\n");
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqualStrings("line one\nline two", events[0]);
}

test "an event not terminated by a blank line is still delivered" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // The peer closed straight after writing. Discarding a message we fully received
    // would lose a response.
    const events = try decodeAll(arena.allocator(), "data: {\"a\":1}");
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqualStrings("{\"a\":1}", events[0]);
}

test "an empty stream yields nothing" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    try testing.expectEqual(@as(usize, 0), (try decodeAll(arena.allocator(), "")).len);
    try testing.expectEqual(@as(usize, 0), (try decodeAll(arena.allocator(), "\r\n\r\n")).len);
    try testing.expectEqual(@as(usize, 0), (try decodeAll(arena.allocator(), ":\r\n")).len);
}

test "an empty data field produces an empty payload rather than being dropped" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // `data:` with nothing after it is a real event with an empty payload. It is not
    // valid JSON-RPC, but that is the next layer's judgement to make.
    const events = try decodeAll(arena.allocator(), "data:\r\n\r\n");
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqualStrings("", events[0]);
}

test "what is written can be read back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var stream: std.Io.Writer.Allocating = .init(testing.allocator);
    defer stream.deinit();

    const messages = [_][]const u8{
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}",
    };
    for (messages) |message| try writeEvent(&stream.writer, message);
    // Interleaved keep-alives must not disturb the message sequence.
    try writeKeepAlive(&stream.writer);

    const decoded = try decodeAll(arena.allocator(), stream.written());
    try testing.expectEqual(messages.len, decoded.len);
    for (messages, decoded) |expected, actual| {
        try testing.expectEqualStrings(expected, actual);
    }
}

test "an oversized event is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const oversized = try testing.allocator.alloc(u8, event_size_max + 32);
    defer testing.allocator.free(oversized);
    @memset(oversized, 'x');
    @memcpy(oversized[0..6], "data: ");

    var reader: std.Io.Reader = .fixed(oversized);
    var decoder: Decoder = .init(&reader);
    try testing.expectError(error.EventTooLarge, decoder.next(arena.allocator()));
}

test "fuzz the decoder against arbitrary streams" {
    const Fuzz = struct {
        fn testOne(_: @This(), smith: *std.testing.Smith) anyerror!void {
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();

            var buffer: [2048]u8 = undefined;
            const length = smith.slice(&buffer);

            var reader: std.Io.Reader = .fixed(buffer[0..length]);
            var decoder: Decoder = .init(&reader);

            // Any outcome is fine; a crash, a hang or a leak is not.
            var guard: usize = 0;
            while (guard < 4096) : (guard += 1) {
                const event = decoder.next(arena.allocator()) catch return;
                if (event == null) return;
            }
        }
    };
    try testing.fuzz(Fuzz{}, Fuzz.testOne, .{});
}
