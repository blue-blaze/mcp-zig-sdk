//! The whole OAuth 2.1 story, end to end, in one process.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/oauth-flow
//! ```
//!
//! A mock authorization server and a mock protected resource metadata endpoint run on
//! a background thread; the main thread plays the MCP client. It exercises the paths
//! that unit tests cannot reach, because they involve real sockets and real documents:
//!
//!   1. protected resource metadata discovery over the well-known URL
//!   2. authorization server metadata discovery, with the issuer check
//!   3. an authorization request with PKCE — the URL a user would open
//!   4. the authorization response, validated including the RFC 9207 `iss` check
//!   5. the code exchange, producing a real ES256-signed JWT access token
//!   6. that token validated by the *resource server* half, with keys fetched from
//!      the mock JWKS endpoint
//!   7. a 403 insufficient-scope challenge, and the step-up that unions scopes
//!
//! Step 6 is the point of the exercise: the token the client obtains is verified by
//! the same code an MCP server would use, so the two halves of the module are checked
//! against each other rather than against a fixture.
//!
//! SECURITY: the mock authorization server here mints tokens for anyone who asks and
//! keeps its signing key in a constant. It is a test fixture. Nothing about it is a
//! pattern to follow for an authorization server, which is a role this SDK
//! deliberately does not implement.

const std = @import("std");
const oauth = @import("oauth");
const velo = @import("velo");

const port = 8788;
const issuer = std.fmt.comptimePrint("http://127.0.0.1:{d}", .{port});
const resource = std.fmt.comptimePrint("http://127.0.0.1:{d}/mcp", .{port});
const client_id = "https://app.example.com/oauth/client-metadata.json";
const redirect_uri = "http://127.0.0.1:3000/callback";

/// The mock authorization server's signing key.
///
/// Deterministic so that a failing run can be reproduced. ES256 because `std.crypto`
/// can sign with it; RSA verification exists but RSA signing does not.
const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const key_seed: [Scheme.KeyPair.seed_length]u8 = @splat(0x5a);

const Mock = struct {
    gpa: std.mem.Allocator,
    pair: Scheme.KeyPair,
    /// Scopes the next minted token will carry. The flow changes this to demonstrate a
    /// token that is valid but insufficient.
    granted_scopes: []const u8 = "files:read",
    /// Set by `main` before the server starts.
    ///
    /// A request handler has no `Io` to read a clock from, and the whole run takes well
    /// under a second, so one timestamp taken up front keeps the minted `iat`/`exp`
    /// consistent with the clock the client validates against.
    now_seconds: i64 = 0,

    fn jwks(mock: *const Mock, arena: std.mem.Allocator) ![]u8 {
        const sec1 = mock.pair.public_key.toUncompressedSec1();
        return std.fmt.allocPrint(
            arena,
            "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"mock-1\",\"use\":\"sig\"," ++
                "\"alg\":\"ES256\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}",
            .{
                try oauth.base64url.encode(arena, sec1[1..33]),
                try oauth.base64url.encode(arena, sec1[33..65]),
            },
        );
    }

    fn mintToken(mock: *const Mock, arena: std.mem.Allocator, audience: []const u8) ![]u8 {
        const now = mock.now_seconds;
        const claims = try std.fmt.allocPrint(
            arena,
            "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"sub\":\"user-42\",\"client_id\":\"{s}\"," ++
                "\"scope\":\"{s}\",\"iat\":{d},\"exp\":{d}}}",
            .{ issuer, audience, client_id, mock.granted_scopes, now, now + 300 },
        );

        const header = try oauth.base64url.encode(
            arena,
            "{\"alg\":\"ES256\",\"kid\":\"mock-1\",\"typ\":\"at+jwt\"}",
        );
        const payload = try oauth.base64url.encode(arena, claims);
        const signing_input = try std.fmt.allocPrint(arena, "{s}.{s}", .{ header, payload });
        const signature = try mock.pair.sign(signing_input, null);
        return std.fmt.allocPrint(arena, "{s}.{s}", .{
            signing_input,
            try oauth.base64url.encode(arena, &signature.toBytes()),
        });
    }
};

const App = velo.App(*Mock);

fn serveResourceMetadata(ctx: *velo.Context) !void {
    const metadata: oauth.prm.ResourceMetadata = .{
        .resource = resource,
        .authorization_servers = &.{issuer},
        .scopes_supported = &.{ "files:read", "files:write" },
        .bearer_methods_supported = &.{"header"},
        .resource_name = "Mock MCP Server",
    };
    const body = try metadata.render(ctx.arena);
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, body);
}

fn serveAuthorizationServerMetadata(ctx: *velo.Context) !void {
    const body = try std.fmt.allocPrint(ctx.arena,
        \\{{"issuer":"{s}",
        \\ "authorization_endpoint":"{s}/authorize",
        \\ "token_endpoint":"{s}/token",
        \\ "jwks_uri":"{s}/jwks",
        \\ "scopes_supported":["files:read","files:write","offline_access"],
        \\ "response_types_supported":["code"],
        \\ "grant_types_supported":["authorization_code","refresh_token"],
        \\ "code_challenge_methods_supported":["S256"],
        \\ "authorization_response_iss_parameter_supported":true,
        \\ "client_id_metadata_document_supported":true}}
    , .{ issuer, issuer, issuer, issuer });
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, body);
}

fn serveJwks(ctx: *velo.Context) !void {
    const mock = ctx.stateAs(*Mock).*;
    const body = try mock.jwks(ctx.arena);
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, body);
}

fn serveToken(ctx: *velo.Context) !void {
    const mock = ctx.stateAs(*Mock).*;
    const body = try ctx.readBody(64 * 1024);

    // Read the `resource` the client sent, and mint a token whose audience is exactly
    // that. This is the RFC 8707 behaviour the resource server's audience check
    // depends on; an authorization server that ignored `resource` here would produce
    // tokens this SDK's server half correctly refuses.
    var audience: []const u8 = resource;
    var grant_type: []const u8 = "";
    var iterator: oauth.url.FormIterator = .init(body);
    while (try iterator.next(ctx.arena)) |pair| {
        if (std.mem.eql(u8, pair.name, "resource")) audience = pair.value;
        if (std.mem.eql(u8, pair.name, "grant_type")) grant_type = pair.value;
    }

    const access_token = try mock.mintToken(ctx.arena, audience);
    const response = try std.fmt.allocPrint(
        ctx.arena,
        "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":300," ++
            "\"refresh_token\":\"mock-refresh\",\"scope\":\"{s}\"}}",
        .{ access_token, mock.granted_scopes },
    );
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, response);
}

/// Stands in for the user's browser: approves the request and redirects back.
///
/// A real authorization server would authenticate the user and ask for consent. What
/// matters for this exercise is that it echoes `state` and includes `iss`, because
/// those are what the client validates.
fn serveAuthorize(ctx: *velo.Context) !void {
    try ctx.text(.ok, "this endpoint is opened by a user agent, not fetched");
}

const ServerThread = struct {
    mock: *Mock,
    ready: std.atomic.Value(bool) = .init(false),
    stop: velo.ShutdownFlag = .init(false),

    fn run(self: *ServerThread) void {
        self.serve() catch |err| {
            std.debug.print("mock authorization server failed: {s}\n", .{@errorName(err)});
        };
    }

    fn serve(self: *ServerThread) !void {
        var runtime = try velo.Runtime.init(std.heap.page_allocator, .{ .backend = .auto });
        defer runtime.deinit();
        const io = runtime.io();

        var app: App = undefined;
        app.init(self.mock);
        try app.get("/.well-known/oauth-protected-resource/mcp", serveResourceMetadata);
        try app.get("/.well-known/oauth-protected-resource", serveResourceMetadata);
        try app.get("/.well-known/oauth-authorization-server", serveAuthorizationServerMetadata);
        try app.get("/jwks", serveJwks);
        try app.get("/authorize", serveAuthorize);
        try app.post("/token", serveToken);

        var options: velo.http.server.Options = .{};
        options.serve.stop = &self.stop;

        var address = try velo.net.Address.parse("127.0.0.1", port);
        var srv = try velo.http.Server(*App).init(io, &address, App.adapter, &app, options);
        defer srv.deinit(io);

        self.ready.store(true, .release);
        try srv.run(io);
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var mock: Mock = .{
        .gpa = gpa,
        .pair = try Scheme.KeyPair.generateDeterministic(key_seed),
    };

    mock.now_seconds = std.Io.Clock.real.now(io).toSeconds();

    var thread_state: ServerThread = .{ .mock = &mock };
    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{&thread_state});
    while (!thread_state.ready.load(.acquire)) io.sleep(.{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    // `ready` flips just before the accept loop starts; give the listener a moment
    // rather than racing it.
    io.sleep(.{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout.interface;

    const fetcher: oauth.http.Fetcher = .init(io, .{});
    const auth_client: oauth.client.Client = .init(&fetcher, .{
        .resource = resource,
        .redirect_uri = redirect_uri,
        // No prior relationship with this server, which is MCP's normal case.
        .registration = .{ .client_id_metadata_document = client_id },
    });

    try out.writeAll("1. protected resource metadata\n");
    const discovered = try auth_client.discoverResource(allocator, null);
    try out.print("   document: {s}\n", .{discovered.metadata_url});
    try out.print("   resource: {s}\n", .{discovered.identifier});
    try out.print("   issuers:  {s}\n", .{discovered.issuers()[0]});

    try out.writeAll("\n2. authorization server metadata\n");
    const server = try auth_client.selectAuthorizationServer(allocator, &discovered);
    try out.print("   issuer:   {s}\n", .{server.issuer});
    try out.print("   token:    {s}\n", .{try server.metadata.tokenEndpoint()});
    // Absent PKCE support the client refuses to start a flow at all, so reaching here
    // means the server advertised S256.
    try server.metadata.requirePkce();
    try out.writeAll("   PKCE S256 confirmed\n");

    try out.writeAll("\n3. authorization request\n");
    const initial = (try oauth.client.initialScopes(null, &discovered.metadata)).?;
    const request = try auth_client.beginAuthorization(
        allocator,
        io,
        &server,
        &discovered,
        initial.value(),
    );
    try out.print("   open this: {s}\n", .{request.url});
    // The verifier never appears in that URL; only its hash does.
    try out.print("   challenge: {s}\n", .{&request.pkce.challenge});

    try out.writeAll("\n4. authorization response\n");
    // What the mock server would append to the redirect URI.
    const query = try std.fmt.allocPrint(
        allocator,
        "code=mock-authorization-code&state={s}&iss={s}",
        .{ request.state, try percentEncode(allocator, server.issuer) },
    );
    var diagnosis: oauth.client.Diagnosis = .{};
    const now = std.Io.Clock.real.now(io).toSeconds();

    try out.writeAll("\n5. code exchange\n");
    const tokens = try auth_client.completeAuthorization(
        allocator,
        &server,
        &request,
        query,
        now,
        &diagnosis,
    );
    try out.print("   granted scopes: {s}\n", .{tokens.scopes});
    try out.print("   expires in:     {d}s\n", .{tokens.expires_at.? - now});
    try out.print("   refresh token:  {s}\n", .{tokens.refresh_token orelse "(none)"});
    try out.print("   bound to:       {s}\n", .{tokens.issuer});

    try out.writeAll("\n6. the resource server half validates that token\n");
    var jwks_provider: oauth.http.JwksProvider = .init(
        gpa,
        &fetcher,
        try std.fmt.allocPrint(allocator, "{s}/jwks", .{issuer}),
    );
    defer jwks_provider.deinit();

    var verifier: oauth.resource_server.JwtVerifier = .init(jwks_provider.keyProvider(), .{
        .issuer = server.issuer,
        // The audience check: this is what makes a token minted for another service
        // useless here.
        .audience = discovered.identifier,
    });
    const protected: oauth.resource_server.ResourceServer = .init(verifier.verifier(), .{
        .resource = discovered.identifier,
        .metadata_url = discovered.metadata_url,
        .scopes_supported = "files:read",
    });

    const header = try tokens.authorizationHeader(allocator);
    switch (try protected.authorize(allocator, header, "files:read", now)) {
        .granted => |grant| {
            try out.print("   accepted for subject {s}\n", .{grant.subject.?});
            try out.print("   client_id {s}\n", .{grant.client_id.?});
            try out.print("   scopes {s}\n", .{grant.scopes});
        },
        .challenge => |challenge| {
            try out.print("   UNEXPECTED {d}: {s}\n", .{ challenge.status, challenge.header });
            return error.TokenRejected;
        },
        .unavailable => return error.KeysUnavailable,
    }

    try out.writeAll("\n7. a write operation the token does not cover\n");
    const forbidden = switch (try protected.authorize(
        allocator,
        header,
        "files:read files:write",
        now,
    )) {
        .challenge => |challenge| challenge,
        else => return error.ExpectedChallenge,
    };
    try out.print("   {d} {s}\n", .{ forbidden.status, forbidden.header });

    // The client reads its own server's challenge and computes the step-up scope set.
    const parsed = (try oauth.bearer.parseChallenge(allocator, forbidden.header)).?;
    var step_up: oauth.client.StepUp = .{};
    try step_up.record(initial.value());
    const decision = try step_up.onChallenge(&parsed);
    try out.print("   step-up will request: {s}\n", .{decision.authorize.value()});

    try out.writeAll("\n8. re-authorizing with the wider scope\n");
    mock.granted_scopes = "files:read files:write";
    const wider = try auth_client.beginAuthorization(
        allocator,
        io,
        &server,
        &discovered,
        decision.authorize.value(),
    );
    const wider_query = try std.fmt.allocPrint(
        allocator,
        "code=mock-authorization-code-2&state={s}&iss={s}",
        .{ wider.state, try percentEncode(allocator, server.issuer) },
    );
    const wider_tokens = try auth_client.completeAuthorization(
        allocator,
        &server,
        &wider,
        wider_query,
        now,
        &diagnosis,
    );
    try out.print("   granted scopes: {s}\n", .{wider_tokens.scopes});

    // The key set is cached by now, so this validation does not touch the network.
    const wider_header = try wider_tokens.authorizationHeader(allocator);
    switch (try protected.authorize(allocator, wider_header, "files:read files:write", now)) {
        .granted => try out.writeAll("   the write operation is now permitted\n"),
        else => return error.StepUpFailed,
    }

    try out.writeAll("\n9. a token minted for a different resource\n");
    // The same authorization server, the same signing key, a valid signature — and it
    // must still be refused, because it was not issued for this server.
    const foreign = try mock.mintToken(allocator, "https://other.example/api");
    const foreign_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{foreign});
    switch (try protected.authorize(allocator, foreign_header, null, now)) {
        .challenge => |challenge| try out.print("   {d} {s}\n", .{ challenge.status, challenge.header }),
        else => return error.ForeignTokenAccepted,
    }

    try out.writeAll("\ndone\n");
    try out.flush();

    // Signal the server, then make one more request so the parked accept loop wakes up
    // and notices. Velo self-connects for this internally; from out here, an ordinary
    // request is the same trick and needs no access to its internals.
    thread_state.stop.store(true, .release);
    _ = fetcher.get(allocator, try std.fmt.allocPrint(allocator, "{s}/jwks", .{issuer})) catch {};
    thread.join();
}

fn percentEncode(arena: std.mem.Allocator, value: []const u8) ![]u8 {
    var allocating: std.Io.Writer.Allocating = .init(arena);
    try oauth.url.encodeComponent(&allocating.writer, value);
    return allocating.toOwnedSlice();
}
