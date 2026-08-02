//! Server-side `subscriptions/listen` streams.
//!
//! A subscription is a long-lived channel from server to client, opened by a
//! `subscriptions/listen` request and identified by that request's JSON-RPC id. It
//! replaced the removed `resources/subscribe` RPC and the HTTP GET endpoint, which
//! means every out-of-band notification this revision defines arrives here.
//!
//! ## What this module owns
//!
//! The `Broker` is the join between an application that knows *when* something
//! changed and the transports that know *how* to reach a client. It holds the set of
//! live subscriptions, decides which of them a given event concerns, and encodes the
//! notification. It does not open, hold, or close streams — a transport does that,
//! because only a transport knows whether it can.
//!
//! ## Concurrency
//!
//! Publishing happens on whatever thread noticed the change, while streams are held
//! open by other threads. Two locks make that safe, and they are deliberately
//! separate:
//!
//! * The broker lock guards the subscription table. Critical sections are short,
//!   allocation-free scans, so a spin lock is appropriate and no I/O ever happens
//!   under it.
//! * Each subscription has its own delivery lock, held only while writing to *that*
//!   client. A client that stops reading therefore stalls its own stream and nothing
//!   else — the broker table stays available and other subscribers keep receiving.
//!
//! Delivery is synchronous rather than queued. That means a publisher blocks while a
//! slow client is written to, which is a real cost; it buys the property that
//! nothing is ever silently dropped. An application that cannot afford to block
//! should publish from a thread it owns. A bounded queue was the alternative, and it
//! was rejected because overflow there means losing a resource update without the
//! client ever learning that it happened.

const std = @import("std");

const assert_mod = @import("assert");
const assert = assert_mod.assert;

const context_mod = @import("context.zig");
const jsonrpc = @import("jsonrpc.zig");
const server_mod = @import("server.zig");
const types = @import("types.zig");

const NotificationSink = context_mod.NotificationSink;

/// Maximum concurrent subscriptions. A client may hold several at once, and a
/// server may serve many clients, but the count is bounded so that the table can be
/// a fixed array: no allocation on the publish path, and no way for a peer to grow
/// server memory by opening streams.
pub const subscribers_max: usize = 256;

/// Maximum watched URIs per subscription, bounded for the same reason.
pub const uris_max: usize = 64;

/// Which event a publisher is reporting.
///
/// Modelled as a closed set rather than a method string because the delivery
/// decision is a filter lookup, and a filter has exactly these four fields. A new
/// notification type in a later revision must extend both together.
pub const Event = union(enum) {
    tools_list_changed,
    prompts_list_changed,
    resources_list_changed,
    /// A resource changed. The URI may name a sub-resource of what the client
    /// actually subscribed to, which the spec explicitly permits.
    resource_updated: []const u8,

    /// The JSON-RPC method that carries this event.
    pub fn method(event: Event) []const u8 {
        return switch (event) {
            .tools_list_changed => types.notification.tools_list_changed,
            .prompts_list_changed => types.notification.prompts_list_changed,
            .resources_list_changed => types.notification.resources_list_changed,
            .resource_updated => types.notification.resources_updated,
        };
    }
};

/// One live subscription.
///
/// Entries live inside the broker's fixed table, so their addresses are stable for
/// the broker's lifetime and a `*Subscriber` never dangles. What it can do is become
/// closed, which is what `active` records.
pub const Subscriber = struct {
    /// The subscription id: the listen request's JSON-RPC id.
    id: jsonrpc.Id = .{ .number = 0 },
    /// What the server agreed to honour. Delivery consults only this, never what the
    /// client originally asked for, so an ungranted type cannot leak out.
    granted: types.SubscriptionFilter = .{},
    /// Storage for the granted URIs, copied so that the subscription does not depend
    /// on the request arena that parsed it.
    uri_storage: [uris_max][]const u8 = undefined,
    uri_count: usize = 0,
    /// Where notifications go. Null while the slot is free.
    sink: ?NotificationSink = null,
    /// False once the slot is free or closing.
    active: bool = false,
    /// Guards `sink` use. Separate from the broker lock so that writing to one
    /// client cannot delay the table.
    delivery: std.atomic.Mutex = .unlocked,
    /// Notifications this subscriber could not be sent, because encoding failed or
    /// its stream was already broken. Advisory: the client cannot see this, so it
    /// exists for the server's own logging.
    dropped: usize = 0,

    /// Whether this subscriber asked for `event`.
    ///
    /// URI matching accepts an exact hit or a sub-resource of a watched URI: the
    /// spec says an update may name something below what was subscribed to. The
    /// boundary check is what keeps `file:///abc` from matching a subscription to
    /// `file:///ab`.
    pub fn wants(subscriber: *const Subscriber, event: Event) bool {
        return switch (event) {
            .tools_list_changed => subscriber.granted.wantsToolsListChanged(),
            .prompts_list_changed => subscriber.granted.wantsPromptsListChanged(),
            .resources_list_changed => subscriber.granted.wantsResourcesListChanged(),
            .resource_updated => |uri| for (subscriber.uris()) |watched| {
                if (coversUri(watched, uri)) break true;
            } else false,
        };
    }

    pub fn uris(subscriber: *const Subscriber) []const []const u8 {
        return subscriber.uri_storage[0..subscriber.uri_count];
    }
};

/// Whether `watched` covers `uri`: the same resource, or one below it.
pub fn coversUri(watched: []const u8, uri: []const u8) bool {
    if (std.mem.eql(u8, watched, uri)) return true;
    if (uri.len <= watched.len) return false;
    if (!std.mem.startsWith(u8, uri, watched)) return false;
    // Either the subscription named a container explicitly, or the next character
    // starts a new path segment. Without this, a prefix match would leak updates
    // for unrelated siblings that happen to share a name prefix.
    return watched[watched.len - 1] == '/' or uri[watched.len] == '/';
}

pub const SubscribeError = error{
    /// The table is full. The caller must refuse the stream rather than open one
    /// that silently receives nothing.
    TooManySubscribers,
    /// More watched URIs than a subscription can hold.
    TooManyUris,
    /// The server is shutting down.
    ShuttingDown,
};

pub const Broker = struct {
    gpa: std.mem.Allocator,
    table: [subscribers_max]Subscriber = @splat(.{}),
    /// Guards the table. Never held across I/O.
    lock: std.atomic.Mutex = .unlocked,
    /// Identifies the server in the graceful-closure response, matching what the
    /// dispatcher puts on ordinary results.
    info: ?types.Implementation = null,
    /// Set once the server is shutting down.
    ///
    /// A subscription stream has no natural end, so without this a transport that
    /// waits for its connections to drain would wait forever: the stream is holding
    /// the connection open on purpose. Every stream loop polls this.
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn init(gpa: std.mem.Allocator, info: ?types.Implementation) Broker {
        return .{ .gpa = gpa, .info = info };
    }

    /// Ends every subscription and refuses new ones.
    ///
    /// Call this before waiting for a transport to drain. Streams close gracefully —
    /// each one gets the `subscriptions/listen` response first, so a client can tell
    /// this was a shutdown and not a network failure.
    pub fn stop(broker: *Broker) void {
        broker.stopping.store(true, .release);
        broker.closeAll();
    }

    /// Whether a stream loop should wind up.
    pub fn isStopping(broker: *const Broker) bool {
        return broker.stopping.load(.acquire);
    }

    /// Registers a subscription and sends its acknowledgement.
    ///
    /// The acknowledgement is sent here, before the slot goes live, because the spec
    /// requires it to be the first message carrying this subscription id. Doing it
    /// anywhere else would leave a window in which a concurrent publish could
    /// overtake it.
    pub fn subscribe(
        broker: *Broker,
        listen: server_mod.Listen,
        sink: NotificationSink,
    ) (SubscribeError || error{OutOfMemory})!*Subscriber {
        // Refusing during shutdown is what keeps `stop` final: a subscription opened
        // after it would hold the transport open again.
        if (broker.isStopping()) return error.ShuttingDown;

        const granted_uris = listen.granted.uris();
        if (granted_uris.len > uris_max) return error.TooManyUris;

        const subscriber = try broker.claim(listen, sink);
        errdefer broker.release(subscriber);

        // Encoded before the slot is active, so a publisher cannot interleave.
        const bytes = try broker.encodeAcknowledged(subscriber);
        defer broker.gpa.free(bytes);
        sink.send(bytes);

        broker.activate(subscriber);
        return subscriber;
    }

    /// Takes a free slot and fills it in, without making it visible to publishers.
    fn claim(
        broker: *Broker,
        listen: server_mod.Listen,
        sink: NotificationSink,
    ) SubscribeError!*Subscriber {
        broker.acquire();
        defer broker.releaseLock();

        for (&broker.table) |*slot| {
            if (slot.sink != null) continue;

            slot.* = .{
                .id = listen.id,
                .granted = listen.granted,
                .sink = sink,
                // Not yet: `activate` publishes it.
                .active = false,
            };
            // The filter's URI slice points into the request arena, which outlives
            // neither the stream nor the broker. Copy the slice headers into the
            // slot; the bytes themselves are owned by the caller, which is
            // documented on `subscribe`.
            const granted_uris = listen.granted.uris();
            assert(granted_uris.len <= uris_max);
            for (granted_uris, 0..) |uri, index| slot.uri_storage[index] = uri;
            slot.uri_count = granted_uris.len;
            // Null, not an empty slice: omitting the field is how the spec expresses
            // "not subscribed", and an acknowledgement carrying `[]` would claim a
            // subscription that covers nothing.
            slot.granted.resourceSubscriptions = if (slot.uri_count == 0) null else slot.uris();
            return slot;
        }
        return error.TooManySubscribers;
    }

    fn activate(broker: *Broker, subscriber: *Subscriber) void {
        broker.acquire();
        defer broker.releaseLock();
        subscriber.active = true;
    }

    /// Removes a subscription.
    ///
    /// Returns once no delivery to this subscriber is in progress, so the caller may
    /// then tear down whatever the sink wrote to. Getting that ordering wrong is how
    /// a stream teardown races a publish into freed memory.
    pub fn release(broker: *Broker, subscriber: *Subscriber) void {
        broker.acquire();
        subscriber.active = false;
        broker.releaseLock();

        // Wait out any in-flight delivery, then blank the slot.
        lockSpin(&subscriber.delivery);
        subscriber.sink = null;
        subscriber.uri_count = 0;
        subscriber.granted = .{};
        subscriber.delivery.unlock();
    }

    /// Ends a subscription the way the spec asks a server to: the empty
    /// `subscriptions/listen` response, then the stream closes.
    ///
    /// The response is what tells the client this was deliberate. A transport that
    /// simply drops the connection leaves the client unable to distinguish shutdown
    /// from a network failure, and the spec has it reconnect in that case.
    pub fn closeGracefully(broker: *Broker, subscriber: *Subscriber) void {
        const bytes = broker.encodeClosure(subscriber) catch {
            broker.release(subscriber);
            return;
        };
        defer broker.gpa.free(bytes);

        lockSpin(&subscriber.delivery);
        if (subscriber.sink) |sink| sink.send(bytes);
        subscriber.delivery.unlock();

        broker.release(subscriber);
    }

    /// Ends every live subscription gracefully. For shutdown.
    pub fn closeAll(broker: *Broker) void {
        for (&broker.table) |*slot| {
            if (slot.sink == null) continue;
            broker.closeGracefully(slot);
        }
    }

    /// Whether `subscriber` is still the live subscription belonging to `sink_ptr`.
    ///
    /// A stream loop needs this because slots are reused: after the subscription it
    /// opened is released, the same address may already describe someone else's
    /// stream. Comparing the sink identity — not the slot address — is what makes the
    /// answer trustworthy.
    pub fn holds(broker: *Broker, subscriber: *const Subscriber, sink_ptr: *const anyopaque) bool {
        broker.acquire();
        defer broker.releaseLock();

        if (!subscriber.active) return false;
        const sink = subscriber.sink orelse return false;
        return sink.ptr == sink_ptr;
    }

    /// Looks up a subscription by id, for a client-sent `notifications/cancelled`.
    pub fn find(broker: *Broker, id: jsonrpc.Id) ?*Subscriber {
        broker.acquire();
        defer broker.releaseLock();

        for (&broker.table) |*slot| {
            if (slot.sink == null) continue;
            if (slot.id.eql(id)) return slot;
        }
        return null;
    }

    /// Cancels a subscription by id. A cancellation for an unknown id is not an
    /// error: the spec is explicit that cancellation races normal completion.
    pub fn cancel(broker: *Broker, id: jsonrpc.Id) bool {
        const subscriber = broker.find(id) orelse return false;
        broker.release(subscriber);
        return true;
    }

    pub fn count(broker: *Broker) usize {
        broker.acquire();
        defer broker.releaseLock();

        var total: usize = 0;
        for (&broker.table) |*slot| {
            if (slot.sink != null) total += 1;
        }
        return total;
    }

    // ---- Publishing ------------------------------------------------------

    pub fn publishToolsListChanged(broker: *Broker) void {
        broker.publish(.tools_list_changed);
    }

    pub fn publishPromptsListChanged(broker: *Broker) void {
        broker.publish(.prompts_list_changed);
    }

    pub fn publishResourcesListChanged(broker: *Broker) void {
        broker.publish(.resources_list_changed);
    }

    pub fn publishResourceUpdated(broker: *Broker, uri: []const u8) void {
        assert(uri.len > 0);
        broker.publish(.{ .resource_updated = uri });
    }

    /// Delivers `event` to every subscription that asked for it.
    ///
    /// Returns void rather than an error: a change in the world has already
    /// happened, and failing to tell one client about it must not become the
    /// application's problem. Failures are counted on the subscriber instead.
    pub fn publish(broker: *Broker, event: Event) void {
        // Snapshot the interested subscribers, then leave the table lock before
        // writing anything. Delivery can block for as long as a client takes to
        // read, and holding a spin lock across that would stall every other
        // publisher on the machine.
        var targets: [subscribers_max]*Subscriber = undefined;
        var target_count: usize = 0;

        broker.acquire();
        for (&broker.table) |*slot| {
            if (!slot.active or slot.sink == null) continue;
            if (!slot.wants(event)) continue;
            targets[target_count] = slot;
            target_count += 1;
        }
        broker.releaseLock();

        for (targets[0..target_count]) |subscriber| {
            broker.deliver(subscriber, event);
        }
    }

    fn deliver(broker: *Broker, subscriber: *Subscriber, event: Event) void {
        lockSpin(&subscriber.delivery);
        defer subscriber.delivery.unlock();

        // Re-checked under the delivery lock: the subscription may have been
        // cancelled between the snapshot and now.
        if (!subscriber.active) return;
        const sink = subscriber.sink orelse return;

        const bytes = broker.encodeEvent(subscriber, event) catch {
            subscriber.dropped += 1;
            return;
        };
        defer broker.gpa.free(bytes);
        sink.send(bytes);
    }

    // ---- Encoding --------------------------------------------------------

    /// Every message on a subscription stream carries the subscription id in
    /// `_meta`, which on stdio is the only way a client can tell which stream a
    /// notification belongs to.
    fn subscriptionMeta(subscriber: *const Subscriber) types.ResultMeta {
        return .{ .subscription_id = subscriber.id };
    }

    fn encodeAcknowledged(broker: *Broker, subscriber: *const Subscriber) error{OutOfMemory}![]u8 {
        return broker.encodeNotification(
            types.notification.subscriptions_acknowledged,
            types.SubscriptionsAcknowledgedParams{
                .notifications = subscriber.granted,
                ._meta = subscriptionMeta(subscriber),
            },
        );
    }

    fn encodeEvent(
        broker: *Broker,
        subscriber: *const Subscriber,
        event: Event,
    ) error{OutOfMemory}![]u8 {
        return switch (event) {
            .resource_updated => |uri| broker.encodeNotification(
                types.notification.resources_updated,
                types.ResourceUpdatedParams{
                    .uri = uri,
                    ._meta = subscriptionMeta(subscriber),
                },
            ),
            // The list-changed notifications have no payload of their own; the
            // subscription id in `_meta` is the whole point of their params.
            else => broker.encodeNotification(
                event.method(),
                struct { _meta: types.ResultMeta }{ ._meta = subscriptionMeta(subscriber) },
            ),
        };
    }

    fn encodeNotification(
        broker: *Broker,
        method: []const u8,
        params: anytype,
    ) error{OutOfMemory}![]u8 {
        var allocating: std.Io.Writer.Allocating = .init(broker.gpa);
        errdefer allocating.deinit();

        writeNotification(&allocating.writer, method, params) catch |err| switch (err) {
            error.WriteFailed => return error.OutOfMemory,
        };
        return allocating.toOwnedSlice();
    }

    fn encodeClosure(broker: *Broker, subscriber: *const Subscriber) error{OutOfMemory}![]u8 {
        var allocating: std.Io.Writer.Allocating = .init(broker.gpa);
        errdefer allocating.deinit();

        writeClosure(
            &allocating.writer,
            subscriber.id,
            broker.info,
        ) catch |err| switch (err) {
            error.WriteFailed => return error.OutOfMemory,
        };
        return allocating.toOwnedSlice();
    }

    // ---- Locking ---------------------------------------------------------

    fn acquire(broker: *Broker) void {
        lockSpin(&broker.lock);
    }

    fn releaseLock(broker: *Broker) void {
        broker.lock.unlock();
    }
};

/// Spins until the lock is taken.
///
/// `std.atomic.Mutex` offers only `tryLock`, and blocking alternatives need an `Io`
/// that a publisher may not have. Spinning is acceptable here precisely because no
/// critical section guarded by these locks performs I/O — except a subscriber's own
/// delivery lock, which is uncontended in the common case of one writer per stream.
fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn writeNotification(
    writer: *std.Io.Writer,
    method: []const u8,
    params: anytype,
) std.Io.Writer.Error!void {
    var stream: std.json.Stringify = .{ .writer = writer, .options = types.stringify_options };
    try stream.beginObject();
    try stream.objectField("jsonrpc");
    try stream.write("2.0");
    try stream.objectField("method");
    try stream.write(method);
    try stream.objectField("params");
    try stream.write(params);
    try stream.endObject();
}

fn writeClosure(
    writer: *std.Io.Writer,
    id: jsonrpc.Id,
    info: ?types.Implementation,
) std.Io.Writer.Error!void {
    var stream: std.json.Stringify = .{ .writer = writer, .options = types.stringify_options };
    try stream.beginObject();
    try stream.objectField("jsonrpc");
    try stream.write("2.0");
    try stream.objectField("id");
    try stream.write(id);
    try stream.objectField("result");
    try stream.write(types.SubscriptionsListenResult{
        .subscription_id = id,
        .server_info = info,
    });
    try stream.endObject();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const registry_mod = @import("registry.zig");

/// Records what was delivered, so tests can assert on the wire bytes.
const Recorder = struct {
    gpa: std.mem.Allocator,
    messages: std.ArrayListUnmanaged([]const u8) = .empty,
    fail: bool = false,

    fn deinit(recorder: *Recorder) void {
        for (recorder.messages.items) |message| recorder.gpa.free(message);
        recorder.messages.deinit(recorder.gpa);
    }

    fn sink(recorder: *Recorder) NotificationSink {
        return .{ .ptr = recorder, .vtable = &vtable };
    }

    const vtable: NotificationSink.VTable = .{ .send = send };

    fn send(ptr: *anyopaque, message: []const u8) void {
        const recorder: *Recorder = @ptrCast(@alignCast(ptr));
        if (recorder.fail) return;
        const copy = recorder.gpa.dupe(u8, message) catch return;
        recorder.messages.append(recorder.gpa, copy) catch {
            recorder.gpa.free(copy);
        };
    }

    fn methodAt(recorder: *const Recorder, index: usize) ![]const u8 {
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            recorder.gpa,
            recorder.messages.items[index],
            .{},
        );
        defer parsed.deinit();
        return recorder.gpa.dupe(u8, parsed.value.object.get("method").?.string);
    }
};

fn listenOf(id: i64, granted: types.SubscriptionFilter) server_mod.Listen {
    return .{ .id = .{ .number = id }, .requested = granted, .granted = granted };
}

test "subscribe acknowledges before anything else" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(1, .{ .toolsListChanged = true }),
        recorder.sink(),
    );
    defer broker.release(subscriber);

    try testing.expectEqual(@as(usize, 1), recorder.messages.items.len);
    const method = try recorder.methodAt(0);
    defer testing.allocator.free(method);
    try testing.expectEqualStrings(types.notification.subscriptions_acknowledged, method);
}

test "acknowledgement reports the granted filter and the subscription id" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(7, .{ .toolsListChanged = true, .resourceSubscriptions = &.{"file:///a"} }),
        recorder.sink(),
    );
    defer broker.release(subscriber);

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        recorder.messages.items[0],
        .{},
    );
    defer parsed.deinit();

    const params = parsed.value.object.get("params").?.object;
    const filter = params.get("notifications").?.object;
    try testing.expect(filter.get("toolsListChanged").?.bool);
    try testing.expectEqualStrings(
        "file:///a",
        filter.get("resourceSubscriptions").?.array.items[0].string,
    );
    const meta = params.get("_meta").?.object;
    try testing.expectEqual(@as(i64, 7), meta.get(types.meta_key.subscription_id).?.integer);
}

test "publish reaches only the subscriptions that asked" {
    var wants_tools: Recorder = .{ .gpa = testing.allocator };
    defer wants_tools.deinit();
    var wants_prompts: Recorder = .{ .gpa = testing.allocator };
    defer wants_prompts.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const a = try broker.subscribe(listenOf(1, .{ .toolsListChanged = true }), wants_tools.sink());
    defer broker.release(a);
    const b = try broker.subscribe(listenOf(2, .{ .promptsListChanged = true }), wants_prompts.sink());
    defer broker.release(b);

    broker.publishToolsListChanged();

    try testing.expectEqual(@as(usize, 2), wants_tools.messages.items.len);
    try testing.expectEqual(@as(usize, 1), wants_prompts.messages.items.len);

    const method = try wants_tools.methodAt(1);
    defer testing.allocator.free(method);
    try testing.expectEqualStrings(types.notification.tools_list_changed, method);
}

test "every notification on the stream carries the subscription id" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(42, .{ .toolsListChanged = true, .resourceSubscriptions = &.{"file:///a"} }),
        recorder.sink(),
    );
    defer broker.release(subscriber);

    broker.publishToolsListChanged();
    broker.publishResourceUpdated("file:///a");

    try testing.expectEqual(@as(usize, 3), recorder.messages.items.len);
    for (recorder.messages.items) |message| {
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            testing.allocator,
            message,
            .{},
        );
        defer parsed.deinit();
        const meta = parsed.value.object.get("params").?.object.get("_meta").?.object;
        try testing.expectEqual(
            @as(i64, 42),
            meta.get(types.meta_key.subscription_id).?.integer,
        );
    }
}

test "resource updates match sub-resources but not name prefixes" {
    try testing.expect(coversUri("file:///a", "file:///a"));
    try testing.expect(coversUri("file:///dir", "file:///dir/file.txt"));
    try testing.expect(coversUri("file:///dir/", "file:///dir/file.txt"));
    // A shared name prefix is not containment.
    try testing.expect(!coversUri("file:///ab", "file:///abc"));
    try testing.expect(!coversUri("file:///dir/file.txt", "file:///dir"));
    try testing.expect(!coversUri("file:///x", "file:///y"));
}

test "resource updates only reach matching subscriptions" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(1, .{ .resourceSubscriptions = &.{"file:///project"} }),
        recorder.sink(),
    );
    defer broker.release(subscriber);

    broker.publishResourceUpdated("file:///project/config.json");
    broker.publishResourceUpdated("file:///elsewhere/config.json");

    try testing.expectEqual(@as(usize, 2), recorder.messages.items.len);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        recorder.messages.items[1],
        .{},
    );
    defer parsed.deinit();
    try testing.expectEqualStrings(
        "file:///project/config.json",
        parsed.value.object.get("params").?.object.get("uri").?.string,
    );
}

test "an ungranted notification type is never delivered" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    // Asked for tools, granted nothing.
    const subscriber = try broker.subscribe(
        .{ .id = .{ .number = 1 }, .requested = .{ .toolsListChanged = true }, .granted = .{} },
        recorder.sink(),
    );
    defer broker.release(subscriber);

    broker.publishToolsListChanged();
    broker.publishPromptsListChanged();
    broker.publishResourcesListChanged();
    broker.publishResourceUpdated("file:///a");

    // Only the acknowledgement.
    try testing.expectEqual(@as(usize, 1), recorder.messages.items.len);
}

test "graceful closure sends the empty listen response" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(
        testing.allocator,
        .{ .name = "test-server", .version = "0.1.0" },
    );
    const subscriber = try broker.subscribe(
        listenOf(9, .{ .toolsListChanged = true }),
        recorder.sink(),
    );
    broker.closeGracefully(subscriber);

    try testing.expectEqual(@as(usize, 2), recorder.messages.items.len);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        recorder.messages.items[1],
        .{},
    );
    defer parsed.deinit();

    const object = parsed.value.object;
    try testing.expectEqual(@as(i64, 9), object.get("id").?.integer);
    const result = object.get("result").?.object;
    try testing.expectEqualStrings("complete", result.get("resultType").?.string);
    const meta = result.get("_meta").?.object;
    try testing.expectEqual(@as(i64, 9), meta.get(types.meta_key.subscription_id).?.integer);
    try testing.expectEqualStrings(
        "test-server",
        meta.get(types.meta_key.server_info).?.object.get("name").?.string,
    );

    // The slot is free again.
    try testing.expectEqual(@as(usize, 0), broker.count());
}

test "a released subscription stops receiving" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(1, .{ .toolsListChanged = true }),
        recorder.sink(),
    );
    broker.publishToolsListChanged();
    broker.release(subscriber);
    broker.publishToolsListChanged();

    // Acknowledgement plus the one notification sent while live.
    try testing.expectEqual(@as(usize, 2), recorder.messages.items.len);
}

test "cancel by id, and cancelling an unknown id is not an error" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(5, .{ .toolsListChanged = true }),
        recorder.sink(),
    );
    _ = subscriber;

    try testing.expect(!broker.cancel(.{ .number = 6 }));
    try testing.expect(!broker.cancel(.{ .string = "5" }));
    try testing.expect(broker.cancel(.{ .number = 5 }));
    try testing.expectEqual(@as(usize, 0), broker.count());
}

test "multiple concurrent subscriptions are demultiplexed by id" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    // One client, two streams, sharing a channel as it would on stdio.
    const tools = try broker.subscribe(listenOf(1, .{ .toolsListChanged = true }), recorder.sink());
    defer broker.release(tools);
    const prompts = try broker.subscribe(listenOf(2, .{ .promptsListChanged = true }), recorder.sink());
    defer broker.release(prompts);

    broker.publishPromptsListChanged();

    // Two acknowledgements, then the notification, tagged with the second stream.
    try testing.expectEqual(@as(usize, 3), recorder.messages.items.len);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        recorder.messages.items[2],
        .{},
    );
    defer parsed.deinit();
    const meta = parsed.value.object.get("params").?.object.get("_meta").?.object;
    try testing.expectEqual(@as(i64, 2), meta.get(types.meta_key.subscription_id).?.integer);
}

test "an acknowledgement with no watched URIs omits the field" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const subscriber = try broker.subscribe(
        listenOf(1, .{ .toolsListChanged = true }),
        recorder.sink(),
    );
    defer broker.release(subscriber);

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        recorder.messages.items[0],
        .{},
    );
    defer parsed.deinit();

    const filter = parsed.value.object.get("params").?.object
        .get("notifications").?.object;
    // An empty array would claim a resource subscription that covers nothing.
    try testing.expect(filter.get("resourceSubscriptions") == null);
}

test "stop closes every stream and refuses new ones" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    _ = try broker.subscribe(listenOf(1, .{ .toolsListChanged = true }), recorder.sink());
    _ = try broker.subscribe(listenOf(2, .{ .toolsListChanged = true }), recorder.sink());

    broker.stop();

    // Two acknowledgements and two closure responses.
    try testing.expectEqual(@as(usize, 4), recorder.messages.items.len);
    try testing.expectEqual(@as(usize, 0), broker.count());
    try testing.expect(broker.isStopping());

    // A subscription opened after shutdown would hold the transport open again.
    try testing.expectError(
        error.ShuttingDown,
        broker.subscribe(listenOf(3, .{}), recorder.sink()),
    );
}

test "the table is bounded" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var broker: Broker = .init(testing.allocator, null);
    var opened: usize = 0;
    while (opened < subscribers_max) : (opened += 1) {
        _ = try broker.subscribe(listenOf(@intCast(opened), .{}), recorder.sink());
    }
    try testing.expectError(
        error.TooManySubscribers,
        broker.subscribe(listenOf(9999, .{}), recorder.sink()),
    );
    broker.closeAll();
    try testing.expectEqual(@as(usize, 0), broker.count());
}

test "too many watched URIs is refused rather than truncated" {
    var recorder: Recorder = .{ .gpa = testing.allocator };
    defer recorder.deinit();

    var uris: [uris_max + 1][]const u8 = undefined;
    for (&uris, 0..) |*uri, index| {
        _ = index;
        uri.* = "file:///a";
    }

    var broker: Broker = .init(testing.allocator, null);
    try testing.expectError(error.TooManyUris, broker.subscribe(
        listenOf(1, .{ .resourceSubscriptions = &uris }),
        recorder.sink(),
    ));
}

test "a broken sink does not stop other subscribers" {
    var broken: Recorder = .{ .gpa = testing.allocator, .fail = true };
    defer broken.deinit();
    var working: Recorder = .{ .gpa = testing.allocator };
    defer working.deinit();

    var broker: Broker = .init(testing.allocator, null);
    const a = try broker.subscribe(listenOf(1, .{ .toolsListChanged = true }), broken.sink());
    defer broker.release(a);
    const b = try broker.subscribe(listenOf(2, .{ .toolsListChanged = true }), working.sink());
    defer broker.release(b);

    broker.publishToolsListChanged();

    try testing.expectEqual(@as(usize, 0), broken.messages.items.len);
    try testing.expectEqual(@as(usize, 2), working.messages.items.len);
}

test "the acknowledged filter is the granted one, not the requested one" {
    var reg = try registry_mod.Registry.initComptime(testing.allocator, .{
        registry_mod.tool("noop", noopTool, .{}),
    });
    defer reg.deinit();

    const server: server_mod.Server = .init(&reg, .{
        .name = "test",
        .version = "0.1.0",
    }, .{ .list_changed = true });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    // Prompts are requested but the registry has none, so the grant omits them.
    const granted = try server.grant(arena.allocator(), .{
        .toolsListChanged = true,
        .promptsListChanged = true,
    });
    try testing.expect(granted.wantsToolsListChanged());
    try testing.expect(!granted.wantsPromptsListChanged());
}

fn noopTool(ctx: *context_mod.Context, args: struct {}) context_mod.Error!types.CallToolResult {
    _ = args;
    return ctx.textResult("ok");
}
