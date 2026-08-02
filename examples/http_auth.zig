//! Authorization end to end, over the real Streamable HTTP transport.
//!
//! Three parties in one process, talking over real sockets:
//!
//! - a mock **authorization server** (its own thread) that publishes metadata, a JWKS,
//!   and mints real ES256-signed access tokens;
//! - an **MCP server** (its own thread) that is an OAuth 2.1 protected resource: it
//!   validates those tokens against the JWKS it fetches, publishes its own protected
//!   resource metadata document, and requires a scope on one of its tools;
//! - an **MCP client** (the main thread) that starts with no credentials at all and
//!   works its way in.
//!
//! The client is the point. It walks the path the specification defines, and every step
//! is driven by what the server said rather than by configuration:
//!
//! 1. `tools/list` with no token → `error.Unauthorized`
//! 2. read the recorded challenge → `resource_metadata` → discover, pick an
//!    authorization server, PKCE, exchange a code
//! 3. `tools/list` with the token → works
//! 4. `tools/call` on a scoped tool → `403 insufficient_scope`
//! 5. union the scopes, reauthorize, retry → works
//!
//! Nothing here is mocked on the MCP side: the 401 and the 403 are produced by
//! `mcp.Guard` inside the HTTP transport, and the token is validated by
//! `oauth.JwtVerifier` against a key set fetched over HTTP.
//!
//! ```sh
//! zig build examples && ./zig-out/bin/http-auth
//! ```
//!
//! Loopback and plain HTTP because it is a self-contained example. `oauth` permits
//! `http` for loopback and refuses it everywhere else, so a deployment cannot reach
//! this configuration by accident.

const std = @import("std");
const mcp = @import("mcp");
const oauth = @import("oauth");
const velo = @import("velo");

const as_port = 8790;
const mcp_port = 8791;

const issuer = std.fmt.comptimePrint("http://127.0.0.1:{d}", .{as_port});
const resource = std.fmt.comptimePrint("http://127.0.0.1:{d}/mcp", .{mcp_port});
const metadata_url = std.fmt.comptimePrint(
    "http://127.0.0.1:{d}/.well-known/oauth-protected-resource/mcp",
    .{mcp_port},
);
const jwks_uri = issuer ++ "/jwks";
const client_id = "https://app.example.com/oauth/client-metadata.json";
const redirect_uri = "http://127.0.0.1:3000/callback";

/// The baseline every request must carry, and the extra one the write tool needs.
const scope_use = "mcp:use";
const scope_write = "notes:write";

// ---------------------------------------------------------------------------
// The MCP server's tools
// ---------------------------------------------------------------------------

fn readNotes(context: *mcp.Context, args: struct {}) mcp.Error!mcp.types.CallToolResult {
    _ = args;
    return context.textResult("remember to validate the audience");
}

const AppendArgs = struct {
    line: []const u8,

    pub const schema_docs = .{ .line = "The line to append" };
};

fn appendNote(context: *mcp.Context, args: AppendArgs) mcp.Error!mcp.types.CallToolResult {
    return context.textResult(try context.print("appended: {s}", .{args.line}));
}

// ---------------------------------------------------------------------------
// The mock authorization server
// ---------------------------------------------------------------------------

/// Deterministic so a failing run reproduces. ES256 because `std.crypto` can sign with
/// it; it can verify RSA but not sign it.
const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const key_seed: [Scheme.KeyPair.seed_length]u8 = @splat(0x7c);

const Mock = struct {
    pair: Scheme.KeyPair,
    /// Scopes the next minted token carries. Step 5 widens this.
    granted_scopes: []const u8 = scope_use,
    /// Taken once by `main`: the run is far shorter than a token lifetime, and one
    /// timestamp keeps `iat`/`exp` consistent with the clock the server validates
    /// against.
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

const AsApp = velo.App(*Mock);

fn serveAsMetadata(ctx: *velo.Context) !void {
    const body = try std.fmt.allocPrint(
        ctx.arena,
        "{{\"issuer\":\"{s}\",\"authorization_endpoint\":\"{s}/authorize\"," ++
            "\"token_endpoint\":\"{s}/token\",\"jwks_uri\":\"{s}\"," ++
            "\"scopes_supported\":[\"{s}\",\"{s}\"],\"response_types_supported\":[\"code\"]," ++
            "\"grant_types_supported\":[\"authorization_code\"]," ++
            "\"code_challenge_methods_supported\":[\"S256\"]," ++
            "\"authorization_response_iss_parameter_supported\":true," ++
            "\"client_id_metadata_document_supported\":true}}",
        .{ issuer, issuer, issuer, jwks_uri, scope_use, scope_write },
    );
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, body);
}

fn serveJwks(ctx: *velo.Context) !void {
    const mock = ctx.stateAs(*Mock).*;
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, try mock.jwks(ctx.arena));
}

fn serveToken(ctx: *velo.Context) !void {
    const mock = ctx.stateAs(*Mock).*;
    const body = try ctx.readBody(64 * 1024);

    // Mint for exactly the `resource` that was asked for. This is the RFC 8707
    // behaviour the resource server's audience check depends on: an authorization
    // server that ignored it would issue tokens with no audience restriction, and an
    // unrestricted token is precisely what a compromised MCP server needs to replay.
    var audience: []const u8 = resource;
    var iterator: oauth.url.FormIterator = .init(body);
    while (try iterator.next(ctx.arena)) |pair| {
        if (std.mem.eql(u8, pair.name, "resource")) audience = pair.value;
    }

    const access_token = try mock.mintToken(ctx.arena, audience);
    try ctx.setHeader("Content-Type", "application/json");
    try ctx.text(.ok, try std.fmt.allocPrint(
        ctx.arena,
        "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":300," ++
            "\"scope\":\"{s}\"}}",
        .{ access_token, mock.granted_scopes },
    ));
}

const AsThread = struct {
    mock: *Mock,
    ready: std.atomic.Value(bool) = .init(false),
    stop: velo.ShutdownFlag = .init(false),

    fn run(self: *AsThread) void {
        self.serve() catch |err| {
            std.debug.print("mock authorization server failed: {t}\n", .{err});
        };
    }

    fn serve(self: *AsThread) !void {
        var runtime = try velo.Runtime.init(std.heap.page_allocator, .{ .backend = .auto });
        defer runtime.deinit();
        const io = runtime.io();

        var app: AsApp = undefined;
        app.init(self.mock);
        try app.get("/.well-known/oauth-authorization-server", serveAsMetadata);
        try app.get("/jwks", serveJwks);
        try app.post("/token", serveToken);

        var options: velo.http.server.Options = .{};
        options.serve.stop = &self.stop;

        var address = try velo.net.Address.parse("127.0.0.1", as_port);
        var srv = try velo.http.Server(*AsApp).init(io, &address, AsApp.adapter, &app, options);
        defer srv.deinit(io);

        self.ready.store(true, .release);
        try srv.run(io);
    }
};

// ---------------------------------------------------------------------------
// The protected MCP server
// ---------------------------------------------------------------------------

const McpThread = struct {
    gpa: std.mem.Allocator,
    ready: std.atomic.Value(bool) = .init(false),
    stop: velo.ShutdownFlag = .init(false),

    fn run(self: *McpThread) void {
        self.serve() catch |err| {
            std.debug.print("mcp server failed: {t}\n", .{err});
        };
    }

    fn serve(self: *McpThread) !void {
        var runtime = try velo.Runtime.init(std.heap.page_allocator, .{ .backend = .auto });
        defer runtime.deinit();
        const io = runtime.io();

        var registry = try mcp.Registry.initComptime(self.gpa, .{
            mcp.tool("read_notes", readNotes, .{
                .description = "Reads the notes. Needs only the baseline scope.",
                .annotations = .{ .readOnlyHint = true },
            }),
            // The scope is declared here, beside the handler, because whoever writes
            // the tool is the only one who knows what it touches. The transport reads
            // it through `Server.requiredScopes`, using the same registry lookup
            // dispatch will use — so the scopes checked and the code run cannot come
            // from different entries.
            mcp.tool("append_note", appendNote, .{
                .description = "Appends a line. Requires " ++ scope_write ++ ".",
                .scopes = scope_write,
            }),
        });
        defer registry.deinit();

        const server: mcp.Server = .init(&registry, .{
            .name = "mcp-zig-sdk-protected-example",
            .version = "0.1.0",
        }, .{});

        // The key set is fetched over HTTP and cached, not snapshotted at startup: an
        // authorization server publishes a new key before it signs with it, and a
        // verifier holding a startup snapshot rejects every token after a rotation.
        const fetcher: oauth.Fetcher = .init(io, .{});
        var jwks_provider: oauth.JwksProvider = .init(self.gpa, &fetcher, jwks_uri);
        defer jwks_provider.deinit();

        var verifier: oauth.JwtVerifier = .init(jwks_provider.keyProvider(), .{
            .issuer = issuer,
            // Neither of these has a default. A verifier that can be built without them
            // can be used without them, and then it validates nothing.
            .audience = resource,
        });

        const protected: oauth.ResourceServer = .init(verifier.verifier(), .{
            .resource = resource,
            .metadata_url = metadata_url,
            .scopes_supported = scope_use,
        });

        var state: mcp.velo_http.State = .init(self.gpa, &server, .{
            // Not streaming, so that this example's failures are plain status codes.
            .stream_responses = false,
            .authorization = .{
                .resource_server = &protected,
                .baseline = scope_use,
            },
        });
        // Built from the resource server rather than by hand, so `resource` here and
        // the audience it validates are the same string by construction.
        state.metadata = protected.metadata(&.{issuer}, &.{ scope_use, scope_write });

        var app: mcp.velo_http.App = undefined;
        app.init(&state);
        try mcp.velo_http.mount(&app, "/mcp");
        // Path derived from the URL the challenges advertise: a document served
        // anywhere else is a document no client will look for.
        try mcp.velo_http.mountMetadata(&app, metadata_url);

        var options: velo.http.server.Options = .{};
        options.serve.stop = &self.stop;

        var address = try velo.net.Address.parse("127.0.0.1", mcp_port);
        var srv = try velo.http.Server(*mcp.velo_http.App).init(
            io,
            &address,
            mcp.velo_http.App.adapter,
            &app,
            options,
        );
        defer srv.deinit(io);

        self.ready.store(true, .release);
        try srv.run(io);
    }
};

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// One `tools/list`, reporting whether it was refused.
const Attempt = union(enum) {
    ok: usize,
    refused: mcp.http_client.Transport.Challenge,
};

fn listTools(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    authorization: ?[]const u8,
) !Attempt {
    var headers: [1][2][]const u8 = undefined;
    var count: usize = 0;
    if (authorization) |value| {
        headers[0] = .{ "Authorization", value };
        count = 1;
    }

    var transport: mcp.http_client.Transport = .init(gpa, io, resource, .{
        .extra_headers = headers[0..count],
    });
    defer transport.deinit();

    var client: mcp.Client = .init(transport.transport(), .{
        .name = "http-auth-example",
        .version = "0.1.0",
    }, .{});

    const result = client.listTools(arena, .{}) catch |err| switch (err) {
        // The challenge lives on the transport, cleared at the start of every send, so
        // what is read here can only belong to the exchange that just failed.
        // Copied, not borrowed: `transport.deinit` below frees what it recorded.
        error.Unauthorized => return .{ .refused = (try transport.copyChallenge(arena)).? },
        else => return err,
    };
    return .{ .ok = result.tools.len };
}

const CallAttempt = union(enum) {
    ok: []const u8,
    refused: mcp.http_client.Transport.Challenge,
};

fn appendNoteCall(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    authorization: []const u8,
) !CallAttempt {
    const headers = [_][2][]const u8{.{ "Authorization", authorization }};

    var transport: mcp.http_client.Transport = .init(gpa, io, resource, .{
        .extra_headers = &headers,
    });
    defer transport.deinit();

    var client: mcp.Client = .init(transport.transport(), .{
        .name = "http-auth-example",
        .version = "0.1.0",
    }, .{});

    var arguments: std.json.ObjectMap = .empty;
    try arguments.put(arena, "line", .{ .string = "authorization wired end to end" });

    const result = client.callTool(
        arena,
        "append_note",
        .{ .object = arguments },
        .{},
    ) catch |err| switch (err) {
        error.Unauthorized => return .{ .refused = (try transport.copyChallenge(arena)).? },
        else => return err,
    };
    return .{ .ok = result.content[0].text.text };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var mock: Mock = .{ .pair = try Scheme.KeyPair.generateDeterministic(key_seed) };
    mock.now_seconds = std.Io.Clock.real.now(io).toSeconds();

    var as_thread: AsThread = .{ .mock = &mock };
    var mcp_thread: McpThread = .{ .gpa = gpa };
    const as_handle = try std.Thread.spawn(.{}, AsThread.run, .{&as_thread});
    const mcp_handle = try std.Thread.spawn(.{}, McpThread.run, .{&mcp_thread});
    while (!as_thread.ready.load(.acquire) or !mcp_thread.ready.load(.acquire)) {
        io.sleep(.{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    // `ready` flips just before the accept loop starts; give both listeners a moment
    // rather than racing them.
    io.sleep(.{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake) catch {};

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout.interface;

    // ---- 1. no credentials ----
    try out.writeAll("1. tools/list with no token\n");
    const anonymous = try listTools(gpa, io, arena, null);
    const first_challenge = switch (anonymous) {
        .ok => return error.ExpectedRefusal,
        .refused => |challenge| challenge,
    };
    try out.print("   {d} {s}\n", .{ first_challenge.status, first_challenge.header.? });

    try out.flush();

    // ---- 2. read the challenge and authorize ----
    try out.writeAll("\n2. what the client should do about it\n");
    const recovery = try mcp.authorization.recoveryFor(
        arena,
        first_challenge.status,
        first_challenge.header,
    );
    const parsed = switch (recovery) {
        .authorize => |challenge| challenge,
        else => return error.ExpectedAuthorizeRecovery,
    };
    try out.print("   authorize, starting from {s}\n", .{parsed.resource_metadata.?});

    const fetcher: oauth.Fetcher = .init(io, .{});
    const auth_client: oauth.client.Client = .init(&fetcher, .{
        .resource = resource,
        .redirect_uri = redirect_uri,
        .registration = .{ .client_id_metadata_document = client_id },
    });

    // The URL comes from the challenge, not from configuration. Same-origin checking is
    // on by default: without it a server could point a client at any metadata document
    // and so at any authorization server.
    const discovered = try auth_client.discoverResource(arena, parsed.resource_metadata);
    try out.print("   resource: {s}\n", .{discovered.identifier});
    try out.print("   issuer:   {s}\n", .{discovered.issuers()[0]});

    const as = try auth_client.selectAuthorizationServer(arena, &discovered);
    try as.metadata.requirePkce();
    try out.writeAll("   PKCE S256 confirmed\n");

    const initial = (try oauth.client.initialScopes(parsed.scope, &discovered.metadata)).?;
    try out.print("   asking for: {s}\n", .{initial.value()});

    const tokens = try authorize(arena, io, &auth_client, &as, &discovered, initial.value());
    try out.print("   granted:    {s}\n", .{tokens.scopes});

    try out.flush();

    // ---- 3. the same request, with the token ----
    try out.writeAll("\n3. tools/list with the token\n");
    const header = try tokens.authorizationHeader(arena);
    switch (try listTools(gpa, io, arena, header)) {
        .ok => |n| try out.print("   {d} tools\n", .{n}),
        .refused => |challenge| {
            try out.print("   UNEXPECTED {d} {s}\n", .{ challenge.status, challenge.header.? });
            return error.TokenRejected;
        },
    }

    try out.flush();

    // ---- 4. a tool the token does not cover ----
    try out.writeAll("\n4. tools/call on a tool that declares a scope\n");
    const forbidden = switch (try appendNoteCall(gpa, io, arena, header)) {
        .ok => return error.ExpectedRefusal,
        .refused => |challenge| challenge,
    };
    try out.print("   {d} {s}\n", .{ forbidden.status, forbidden.header.? });

    try out.flush();

    // ---- 5. step up ----
    try out.writeAll("\n5. step-up\n");
    const step_up_challenge = switch (try mcp.authorization.recoveryFor(
        arena,
        forbidden.status,
        forbidden.header,
    )) {
        .step_up => |challenge| challenge,
        else => return error.ExpectedStepUpRecovery,
    };

    var step_up: oauth.client.StepUp = .{};
    try step_up.record(initial.value());
    const decision = try step_up.onChallenge(&step_up_challenge);
    // The union, not the challenge's set: asking for only what the challenge names
    // would drop the access already held.
    try out.print("   requesting: {s}\n", .{decision.authorize.value()});

    mock.granted_scopes = scope_use ++ " " ++ scope_write;
    const wider = try authorize(
        arena,
        io,
        &auth_client,
        &as,
        &discovered,
        decision.authorize.value(),
    );
    try out.print("   granted:    {s}\n", .{wider.scopes});

    const wider_header = try wider.authorizationHeader(arena);
    switch (try appendNoteCall(gpa, io, arena, wider_header)) {
        .ok => |text| try out.print("   tool said: {s}\n", .{text}),
        .refused => |challenge| {
            try out.print("   UNEXPECTED {d} {s}\n", .{ challenge.status, challenge.header.? });
            return error.StepUpFailed;
        },
    }

    try out.writeAll("\ndone\n");
    try out.flush();

    // Stop both servers, then poke each one: a parked accept loop only notices the flag
    // when something wakes it, and an ordinary request is the simplest wake-up there is.
    as_thread.stop.store(true, .release);
    mcp_thread.stop.store(true, .release);
    _ = fetcher.get(arena, jwks_uri) catch {};
    _ = fetcher.get(arena, metadata_url) catch {};
    as_handle.join();
    mcp_handle.join();
}

/// Runs an authorization code flow, standing in for the user's browser.
///
/// A real client would open `request.url` and wait for the redirect. What matters here
/// is that the response carries back `state` and `iss`, because those are what
/// `completeAuthorization` validates — and it validates `iss` before it will read an
/// `error_description`, since that text is attacker-controlled and destined for a
/// user's screen.
fn authorize(
    arena: std.mem.Allocator,
    io: std.Io,
    auth_client: *const oauth.client.Client,
    as: *const oauth.client.AuthorizationServer,
    discovered: *const oauth.client.Resource,
    scopes: []const u8,
) !oauth.TokenSet {
    const request = try auth_client.beginAuthorization(arena, io, as, discovered, scopes);

    var encoded: std.Io.Writer.Allocating = .init(arena);
    try oauth.url.encodeComponent(&encoded.writer, as.issuer);
    const query = try std.fmt.allocPrint(
        arena,
        "code=mock-code&state={s}&iss={s}",
        .{ request.state, encoded.written() },
    );

    var diagnosis: oauth.client.Diagnosis = .{};
    return auth_client.completeAuthorization(
        arena,
        as,
        &request,
        query,
        std.Io.Clock.real.now(io).toSeconds(),
        &diagnosis,
    );
}
