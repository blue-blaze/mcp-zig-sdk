//! Model Context Protocol SDK for Zig — protocol revision 2026-07-28.
//!
//! This module implements the whole of MCP 2026-07-28 for both peers:
//!
//!   * `Server` — dispatches requests against a registry of tools, prompts and
//!     resources; transport-agnostic at its core.
//!   * `Client` — issues typed requests and drives the multi round-trip request
//!     (MRTR) loop.
//!   * transports — `stdio` for local servers, Streamable HTTP for remote ones.
//!
//! The revision is deliberately the only one supported. 2026-07-28 removed the
//! `initialize` handshake, protocol-level sessions and resumable streams, and
//! deprecated Roots, Sampling and Logging; supporting the older, stateful shape
//! alongside the stateless one would double the state space for no benefit to new
//! implementations.
//!
//! ## Memory
//!
//! Every entry point that allocates takes an `std.mem.Allocator` explicitly; the
//! SDK never reaches for a global one. Server request handling is arena-scoped:
//! one arena per request, reset once the response has been written, so handler
//! code may allocate freely without tracking individual frees. Types that own
//! heap memory expose `deinit`, and the whole test suite runs under
//! `std.testing.allocator` so a leak fails the build.

const std = @import("std");

pub const assert_mod = @import("assert");

pub const jsonrpc = @import("jsonrpc.zig");
pub const types = @import("types.zig");
pub const schema_gen = @import("schema_gen.zig");
pub const context = @import("context.zig");
pub const registry = @import("registry.zig");
pub const server = @import("server.zig");
pub const client = @import("client.zig");
pub const request_state = @import("request_state.zig");
pub const subscriptions = @import("subscriptions.zig");
pub const stdio = @import("stdio.zig");
pub const sse = @import("sse.zig");
pub const authorization = @import("authorization.zig");
pub const http = @import("http.zig");
pub const http_client = @import("http_client.zig");
pub const velo_http = @import("velo_http.zig");

/// The context a request handler runs in: the request arena, the caller's `_meta`,
/// and the request-scoped notification helpers.
pub const Context = context.Context;

/// Errors a handler may return.
pub const Error = context.Error;

/// What a server offers.
pub const Registry = registry.Registry;

/// The request dispatcher. Transport-agnostic: it turns one inbound message into
/// the bytes of one outbound response.
pub const Server = server.Server;

/// What a transport supplies for the duration of one request.
pub const Scope = server.Scope;

/// Applies an OAuth 2.1 resource server to inbound MCP requests: a baseline scope
/// requirement plus whatever the operation itself declares.
pub const Guard = authorization.Guard;

/// The client: builds requests, correlates responses, decodes results.
pub const Client = client.Client;

/// Moves encoded messages between a client and its peer.
pub const Transport = client.Transport;

/// Where request-scoped notifications are delivered.
pub const NotificationSink = context.NotificationSink;

/// A one-way flag a transport sets when the peer abandons a request.
pub const Cancellation = context.Cancellation;

/// Tracks in-flight requests so a cancellation can reach the handler serving them.
pub const InFlight = server.InFlight;

/// Comptime registration helpers: derive a tool or prompt from a typed handler.
pub const tool = registry.tool;
pub const prompt = registry.prompt;

/// The single protocol revision this SDK speaks.
pub const protocol_version = types.protocol_version;

/// Reserved `_meta` keys defined by the specification.
pub const meta_key = types.meta_key;

/// Request and notification method names.
pub const method = types.method;
pub const notification = types.notification;

test {
    std.testing.refAllDecls(@This());
}

test "protocol version is the 2026-07-28 revision" {
    try std.testing.expectEqualStrings("2026-07-28", protocol_version);
}
