//! The client side, assembled: discovery, scope selection, the authorization code
//! flow, refresh, step-up, and the client credentials flow.
//!
//! Everything here composes the pure modules with `http.Fetcher`. The security
//! decisions live in those modules; what this file adds is the *order* and the
//! fallbacks, which is where a client that implements every rule individually can
//! still end up not working.
//!
//! ## Two flows, and they are not interchangeable
//!
//! `beginAuthorization` / `completeAuthorization` authorize an agent on behalf of a
//! person: a browser, a redirect, PKCE, a token carrying the user's authority. That is
//! the flow the MCP specification describes.
//!
//! `clientCredentials` authorizes a process as itself, which is what a server-to-server
//! deployment needs and what the specification does not cover. Discovery is shared;
//! everything else is skipped.
//!
//! Which one a deployment needs is not a preference. A token from the second carries the
//! *client's* authority, so using it while acting for a user gives every user of that
//! agent whatever the process is allowed to do.
//!
//! ## Discovery is a chain with a fallback at every link
//!
//!   1. Protected resource metadata: the `resource_metadata` URL from a
//!      `WWW-Authenticate` challenge if there was one, otherwise the two well-known
//!      URLs in order.
//!   2. An authorization server from `authorization_servers`. Choosing is the client's
//!      responsibility (RFC 9728 Section 7.6); this module tries them in the order
//!      published.
//!   3. That server's metadata, from up to three candidate URLs, each validated
//!      against the issuer used to build it.
//!
//! A single missing document at any link is normal — servers publish one form or the
//! other — so a failed candidate is skipped rather than fatal. A document that
//! *fails validation* is different, and stops the attempt.
//!
//! ## Scope accumulation is the client's job
//!
//! A server challenging for `files:write` is stating what the current operation needs,
//! not what the client should end up holding. Re-authorizing for the challenge alone
//! silently drops permissions other operations depend on, which surfaces later as an
//! operation that used to work. `stepUpScopes` is the union the specification
//! requires.

const std = @import("std");
const assert_mod = @import("assert");

const as_metadata = @import("as_metadata.zig");
const authorize = @import("authorize.zig");
const bearer = @import("bearer.zig");
const cimd = @import("cimd.zig");
const http = @import("http.zig");
const prm = @import("prm.zig");
const scope = @import("scope.zig");
const token = @import("token.zig");
const url = @import("url.zig");

const assert = assert_mod.assert;

/// How many times a client will re-authorize for more scope before giving up on an
/// operation.
///
/// The specification says "no more than a few times" and then treat it as permanent.
/// Without a cap, a server that keeps challenging for a scope it will never accept
/// turns into an endless sequence of user prompts.
pub const step_up_attempts_max: u8 = 2;

pub const Error = error{
    /// No protected resource metadata could be retrieved.
    ResourceMetadataUnavailable,
    /// The metadata document was retrieved but is not usable.
    ResourceMetadataInvalid,
    /// The `resource_metadata` URL from the challenge is not on the resource's origin.
    ResourceMetadataForeign,
    /// No authorization server metadata could be retrieved for any listed issuer.
    AuthorizationServerUnavailable,
    /// The authorization server does not advertise PKCE, or does not offer `S256`.
    /// Proceeding would mean an authorization code protected by nothing.
    PkceUnsupported,
    /// The authorization server does not publish the endpoint this step needs.
    EndpointMissing,
    /// The authorization server publishes its supported grants and this is not one of
    /// them.
    GrantUnsupported,
    /// No registration mechanism works with this authorization server.
    RegistrationUnavailable,
    /// The client's own configuration is not usable.
    InvalidConfiguration,
    /// The authorization response did not validate. The specific reason is reported
    /// through `Diagnosis`.
    AuthorizationRejected,
    /// The token endpoint refused the request.
    TokenRequestRejected,
    /// The token endpoint answered with something unusable.
    TokenResponseInvalid,
    /// A request could not be completed.
    RequestFailed,
    /// Entropy was unavailable, so no verifier could be generated.
    EntropyUnavailable,
    OutOfMemory,
};

/// Why a step failed, for logs and for surfacing to a user.
///
/// Separate from the error set because the useful detail — the authorization server's
/// own `error_description`, the candidate URLs that were tried — has no place in an
/// error value.
pub const Diagnosis = struct {
    authorization_failure: ?authorize.AuthorizationError = null,
    token_failure: ?token.Failure = null,
    /// The reason the last validation refused, when there was one.
    detail: ?[]const u8 = null,
};

pub const Options = struct {
    /// The canonical URI of the MCP server. Every token this client obtains is bound
    /// to it via the `resource` parameter.
    resource: []const u8,
    /// Where authorization responses are delivered. Must be loopback or HTTPS.
    redirect_uri: []const u8,
    /// How this client identifies itself.
    registration: cimd.Registration,
    /// Require the document's `resource` to equal the resource identifier exactly
    /// (RFC 9728 Section 3.3).
    ///
    /// Off by default. A server legitimately publishes a resource identifier that
    /// differs from the URL a client happened to use — `https://mcp.example.com` for
    /// an endpoint at `https://mcp.example.com/mcp` — and since the document is what
    /// *defines* the identifier, adopting it is correct. What bounds that adoption is
    /// a same-origin check on the claimed resource that runs unconditionally and no
    /// option disables; see `adoptableIdentifier`. Turn this on for a deployment where
    /// the two are known to match, which is what the RFC asks for and costs nothing
    /// when it holds.
    require_exact_resource: bool = false,
    /// Require a challenge's `resource_metadata` URL to share the resource's origin.
    ///
    /// On by default. The header is chosen by whoever answered the request, so without
    /// this a server can point a client at a metadata document of its choosing and
    /// from there at an authorization server of its choosing.
    ///
    /// This governs where a document may be *fetched from*. What the document may then
    /// claim is a separate question, bounded unconditionally — turning this off widens
    /// which documents are read, not which resources a token can be minted for.
    require_same_origin: bool = true,
    /// Ask for `offline_access` when the authorization server lists it, so that a
    /// refresh token is issued and the user is not re-prompted on every expiry.
    request_offline_access: bool = false,
    diagnostics: ?*std.Io.Writer = null,
};

/// Protected resource metadata, and the identifier it establishes.
pub const Resource = struct {
    metadata: prm.ResourceMetadata,
    /// The URL the document came from.
    metadata_url: []const u8,
    /// The canonical resource identifier to use in the `resource` parameter — the
    /// document's own `resource` value, which is what defines it.
    identifier: []const u8,

    /// The issuers this resource accepts tokens from, in published order.
    pub fn issuers(resource: *const Resource) []const []const u8 {
        return resource.metadata.authorization_servers;
    }
};

/// An authorization server this client can use.
pub const AuthorizationServer = struct {
    metadata: as_metadata.Metadata,
    /// The issuer identifier used to construct the discovery URL and validated against
    /// the document. This is the value the `iss` check compares against, so it must
    /// travel with the metadata rather than being recovered later.
    issuer: []const u8,
};

/// Drives the OAuth flows for one MCP server.
pub const Client = struct {
    fetcher: *const http.Fetcher,
    options: Options,

    pub fn init(fetcher: *const http.Fetcher, options: Options) Client {
        assert(options.resource.len > 0);
        assert(options.redirect_uri.len > 0);
        return .{ .fetcher = fetcher, .options = options };
    }

    /// Retrieves protected resource metadata.
    ///
    /// `challenge_metadata_url` is the `resource_metadata` parameter from a
    /// `WWW-Authenticate` challenge, when one was received. It takes precedence: the
    /// server named its document, and guessing would be worse information.
    pub fn discoverResource(
        client: *const Client,
        arena: std.mem.Allocator,
        challenge_metadata_url: ?[]const u8,
    ) Error!Resource {
        prm.validateResourceIdentifier(client.options.resource) catch
            return error.InvalidConfiguration;

        if (challenge_metadata_url) |metadata_url| {
            if (client.options.require_same_origin and
                !prm.sameOrigin(metadata_url, client.options.resource))
            {
                client.report("oauth: challenge names a foreign metadata url {s}\n", .{metadata_url});
                return error.ResourceMetadataForeign;
            }
            return client.fetchResource(arena, metadata_url);
        }

        const candidates = prm.wellKnownUris(arena, client.options.resource) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidResource => return error.InvalidConfiguration,
        };
        var last: ?Error = null;
        for (candidates) |candidate| {
            return client.fetchResource(arena, candidate) catch |err| {
                // A candidate that is simply absent is expected: a server publishes one
                // form or the other, not both. Keep the last reason for the caller.
                last = err;
                continue;
            };
        }
        client.report("oauth: no protected resource metadata for {s}\n", .{client.options.resource});
        return last orelse error.ResourceMetadataUnavailable;
    }

    fn fetchResource(
        client: *const Client,
        arena: std.mem.Allocator,
        metadata_url: []const u8,
    ) Error!Resource {
        const response = client.fetcher.get(arena, metadata_url) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ResourceMetadataUnavailable,
        };
        if (!response.isSuccess()) return error.ResourceMetadataUnavailable;

        const metadata = prm.parse(arena, response.body) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                client.report("oauth: metadata at {s} is invalid\n", .{metadata_url});
                return error.ResourceMetadataInvalid;
            },
        };

        const identifier = adoptableIdentifier(client.options, &metadata) catch |err| {
            client.report(
                "oauth: metadata at {s} claims resource {s}, which this client will not adopt\n",
                .{ metadata_url, metadata.resource },
            );
            return err;
        };

        return .{
            .metadata = metadata,
            .metadata_url = metadata_url,
            .identifier = identifier,
        };
    }

    /// The identifier a fetched document establishes, if this client may adopt it.
    ///
    /// The document's `resource` becomes the `resource` parameter of every
    /// authorization and token request this client makes, which is what the
    /// authorization server writes into the token's audience. Adopting it unchecked is
    /// a confused deputy: a server the user has legitimately connected to names some
    /// third party's resource, and the authorization server mints a token whose
    /// audience is that third party. The consent screen names the third party too, so
    /// consent is no defense — the user cannot tell which of the two asked.
    ///
    /// The bound is therefore unconditional and no option relaxes it: a server may
    /// redefine its own identifier and nothing else. Same-origin rather than byte
    /// equality because redefinition is legitimate and common —
    /// `https://mcp.example.com` for an endpoint at `https://mcp.example.com/mcp` — and
    /// RFC 9728 Section 3.3's byte-exact rule is available as `require_exact_resource`
    /// for a deployment that can hold to it.
    ///
    /// Pure, and separate from the fetch, so the rule is testable without a network.
    fn adoptableIdentifier(
        options: Options,
        metadata: *const prm.ResourceMetadata,
    ) error{ ResourceMetadataForeign, ResourceMetadataInvalid }![]const u8 {
        // Checked here rather than left to the token request, which would refuse it two
        // steps removed from the cause.
        prm.validateResourceIdentifier(metadata.resource) catch
            return error.ResourceMetadataInvalid;

        if (!prm.sameOrigin(metadata.resource, options.resource)) {
            return error.ResourceMetadataForeign;
        }

        if (options.require_exact_resource) {
            metadata.matchesResource(options.resource) catch
                return error.ResourceMetadataInvalid;
        }

        return metadata.resource;
    }

    /// Retrieves authorization server metadata for `issuer`.
    ///
    /// Tries the candidate URLs in the required order. The document's `issuer` is
    /// compared against `issuer` — not against anything in the document — which is
    /// what makes the result trustworthy enough to take endpoints from.
    pub fn discoverAuthorizationServer(
        client: *const Client,
        arena: std.mem.Allocator,
        issuer: []const u8,
    ) Error!AuthorizationServer {
        const candidates = as_metadata.discoveryCandidates(arena, issuer) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidIssuer => return error.AuthorizationServerUnavailable,
        };

        for (candidates.slice()) |candidate| {
            const response = client.fetcher.get(arena, candidate.url) catch continue;
            if (!response.isSuccess()) continue;

            const metadata = as_metadata.parse(arena, response.body, issuer) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // A document that fails validation is not the same as one that is
                // absent. Skipping it lets discovery continue, which is right: a
                // server may publish a broken OAuth document and a good OIDC one.
                // What must not happen is *using* it.
                else => {
                    client.report(
                        "oauth: metadata at {s} rejected: {s}\n",
                        .{ candidate.url, @errorName(err) },
                    );
                    continue;
                },
            };
            return .{ .metadata = metadata, .issuer = issuer };
        }

        client.report("oauth: no authorization server metadata for {s}\n", .{issuer});
        return error.AuthorizationServerUnavailable;
    }

    /// Discovers the first authorization server from `resource` that answers.
    ///
    /// Selection among several is the client's responsibility. Trying them in
    /// published order is the simplest defensible policy; a caller with a preference
    /// should call `discoverAuthorizationServer` directly.
    pub fn selectAuthorizationServer(
        client: *const Client,
        arena: std.mem.Allocator,
        resource: *const Resource,
    ) Error!AuthorizationServer {
        for (resource.issuers()) |issuer| {
            return client.discoverAuthorizationServer(arena, issuer) catch continue;
        }
        return error.AuthorizationServerUnavailable;
    }

    /// Starts an authorization code flow.
    ///
    /// `scopes` is what to request; use `initialScopes` or `stepUpScopes` to compute
    /// it. The returned `Request` must be kept until the response arrives — it holds
    /// the code verifier, the state, and the issuer the `iss` check needs.
    pub fn beginAuthorization(
        client: *const Client,
        arena: std.mem.Allocator,
        io: std.Io,
        server: *const AuthorizationServer,
        resource: *const Resource,
        scopes: ?[]const u8,
    ) Error!authorize.Request {
        // Before anything else: without PKCE the flow this function starts offers no
        // protection for the authorization code, so there is no point starting it.
        server.metadata.requirePkce() catch return error.PkceUnsupported;

        if (!client.options.registration.usableAt(server.issuer)) {
            client.report(
                "oauth: registration is not valid at {s}; re-register\n",
                .{server.issuer},
            );
            return error.RegistrationUnavailable;
        }

        const endpoint = server.metadata.authorizationEndpoint() catch
            return error.EndpointMissing;

        const pkce: authorize.Pkce = authorize.Pkce.generate(io) catch
            return error.EntropyUnavailable;
        const state = authorize.generateState(io) catch return error.EntropyUnavailable;

        var requested = scopes;
        if (client.options.request_offline_access and server.metadata.offersOfflineAccess()) {
            var set: scope.Set = scope.Set.parse(scopes orelse "") catch
                return error.InvalidConfiguration;
            set.add("offline_access") catch return error.InvalidConfiguration;
            requested = arena.dupe(u8, set.value()) catch return error.OutOfMemory;
        }

        return authorize.buildRequest(arena, endpoint, server.issuer, pkce, &state, .{
            .client_id = client.options.registration.clientId(),
            .redirect_uri = client.options.redirect_uri,
            .resource = resource.identifier,
            .scopes = requested,
        }) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidConfiguration,
        };
    }

    /// Validates an authorization response and exchanges the code for tokens.
    ///
    /// `query` is the redirect's query string. Validation happens first and in full —
    /// including the `iss` check — so that a code from the wrong authorization server
    /// is never sent to a token endpoint.
    pub fn completeAuthorization(
        client: *const Client,
        arena: std.mem.Allocator,
        server: *const AuthorizationServer,
        request: *const authorize.Request,
        query: []const u8,
        now: i64,
        diagnosis: *Diagnosis,
    ) Error!token.TokenSet {
        const response = authorize.validateResponse(
            arena,
            query,
            request,
            server.metadata.requiresIssParameter(),
            &diagnosis.authorization_failure,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                diagnosis.detail = @errorName(err);
                client.report("oauth: authorization response rejected: {s}\n", .{@errorName(err)});
                return error.AuthorizationRejected;
            },
        };

        const endpoint = server.metadata.tokenEndpoint() catch return error.EndpointMissing;
        const exchange = token.buildCodeExchange(arena, .{
            .code = response.code,
            .redirect_uri = request.redirect_uri,
            .client_id = client.options.registration.clientId(),
            .code_verifier = &request.pkce.verifier,
            .resource = request.resource,
            .auth = client.options.registration.auth(),
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfiguration,
        };

        return client.postToken(arena, endpoint, exchange, .{
            .issuer = server.issuer,
            .resource = request.resource,
            .requested_scopes = request.scopes orelse "",
            .now = now,
        }, diagnosis);
    }

    /// Exchanges a refresh token for a new access token.
    ///
    /// Refuses a token set bound to a different issuer or resource: continuing would
    /// present a credential to a party it was not issued for.
    pub fn refresh(
        client: *const Client,
        arena: std.mem.Allocator,
        server: *const AuthorizationServer,
        tokens: *const token.TokenSet,
        now: i64,
        diagnosis: *Diagnosis,
    ) Error!token.TokenSet {
        const refresh_token = tokens.refresh_token orelse return error.TokenRequestRejected;
        // Two conditions rather than `boundTo`, which has no argument here that would
        // make it say anything: passing `tokens.resource` as the expected resource
        // compares a value with itself, so the resource half of that check was always
        // true and only the issuer was ever tested.
        //
        // The resource is compared by origin, not bytes, because the identifier may
        // legitimately differ from the URL this client talks to — the same latitude
        // `adoptableIdentifier` grants, and the same bound. What it catches is a token
        // set restored from storage after the client was pointed somewhere else.
        if (!std.mem.eql(u8, tokens.issuer, server.issuer) or
            !prm.sameOrigin(tokens.resource, client.options.resource))
        {
            client.report("oauth: refusing to refresh a token bound elsewhere\n", .{});
            return error.RegistrationUnavailable;
        }

        const endpoint = server.metadata.tokenEndpoint() catch return error.EndpointMissing;
        const request = token.buildRefresh(arena, .{
            .refresh_token = refresh_token,
            .client_id = client.options.registration.clientId(),
            .resource = tokens.resource,
            .auth = client.options.registration.auth(),
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidConfiguration,
        };

        return client.postToken(arena, endpoint, request, .{
            .issuer = server.issuer,
            .resource = tokens.resource,
            // A refresh keeps the scopes it had unless the server says otherwise.
            .requested_scopes = tokens.scopes,
            .now = now,
        }, diagnosis);
    }

    /// Obtains a token for this process itself, with no user involved.
    ///
    /// The whole authorization code flow above — `beginAuthorization`,
    /// `completeAuthorization`, the browser, the redirect, PKCE — exists to authorize an
    /// agent on behalf of a person. This is the other deployment: one service calling
    /// another with an identity of its own. Skip straight to here; nothing above is
    /// needed, and `discoverResource` plus `discoverAuthorizationServer` still are,
    /// because the token endpoint and the resource identifier come from the same place
    /// either way.
    ///
    /// `resource` should be `Resource.identifier` from discovery. `scopes` is a request,
    /// not a narrowing — there is no prior grant here — so ask for what the deployment
    /// needs; `initialScopes` computes it from the resource's metadata as usual.
    ///
    /// The returned token set will normally have no refresh token, which is correct and
    /// nothing to work around: call this again. See `token.buildClientCredentials` for
    /// why, and for why a client acting for a user must not use this.
    pub fn clientCredentials(
        client: *const Client,
        arena: std.mem.Allocator,
        server: *const AuthorizationServer,
        resource: []const u8,
        scopes: ?[]const u8,
        now: i64,
        diagnosis: *Diagnosis,
    ) Error!token.TokenSet {
        if (!client.options.registration.usableAt(server.issuer)) {
            client.report(
                "oauth: registration is not valid at {s}; re-register\n",
                .{server.issuer},
            );
            return error.RegistrationUnavailable;
        }

        // A published list that omits the grant is the server's own answer, and this
        // request would put a client secret on the wire to be refused. An absent list
        // is not an answer — see `supportsGrantType` — so it proceeds.
        if (server.metadata.supportsGrantType("client_credentials")) |supported| {
            if (!supported) {
                client.report(
                    "oauth: {s} does not offer client_credentials\n",
                    .{server.issuer},
                );
                return error.GrantUnsupported;
            }
        }

        const endpoint = server.metadata.tokenEndpoint() catch return error.EndpointMissing;
        const request = token.buildClientCredentials(arena, .{
            .client_id = client.options.registration.clientId(),
            .resource = resource,
            .scopes = scopes,
            .auth = client.options.registration.auth(),
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ClientAuthenticationRequired => {
                client.report(
                    "oauth: client_credentials needs a client secret; this " ++
                        "registration is public\n",
                    .{},
                );
                return error.InvalidConfiguration;
            },
            else => return error.InvalidConfiguration,
        };

        return client.postToken(arena, endpoint, request, .{
            .issuer = server.issuer,
            .resource = resource,
            .requested_scopes = scopes orelse "",
            .now = now,
        }, diagnosis);
    }

    fn postToken(
        client: *const Client,
        arena: std.mem.Allocator,
        endpoint: []const u8,
        request: token.Request,
        context: token.ParseContext,
        diagnosis: *Diagnosis,
    ) Error!token.TokenSet {
        const response = client.fetcher.postForm(
            arena,
            endpoint,
            request.body,
            request.headers,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                client.report("oauth: token request to {s} failed\n", .{endpoint});
                return error.RequestFailed;
            },
        };

        // The body is parsed whatever the status: RFC 6749 puts the error code in a
        // 400 body, and discarding it because of the status turns an actionable
        // `invalid_grant` into "the request failed".
        return token.parseResponse(
            arena,
            response.body,
            context,
            &diagnosis.token_failure,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TokenRequestFailed => {
                if (diagnosis.token_failure) |failure| {
                    client.report("oauth: token endpoint refused: {s}\n", .{failure.code});
                }
                return error.TokenRequestRejected;
            },
            else => {
                diagnosis.detail = @errorName(err);
                return error.TokenResponseInvalid;
            },
        };
    }

    fn report(client: *const Client, comptime format: []const u8, args: anytype) void {
        const writer = client.options.diagnostics orelse return;
        writer.print(format, args) catch return;
        writer.flush() catch {};
    }
};

/// Chooses the scopes for a first authorization.
///
/// The priority the specification sets out:
///
///   1. the `scope` from the `WWW-Authenticate` challenge, if there was one — it is
///      authoritative for the operation being attempted
///   2. otherwise `scopes_supported` from the resource metadata, which is the minimum
///      for basic functionality
///   3. otherwise nothing, and the `scope` parameter is omitted
///
/// A client must not assume any set relationship between a challenge's scopes and
/// `scopes_supported`, which is why this picks one rather than combining them.
pub fn initialScopes(
    challenge_scope: ?[]const u8,
    metadata: *const prm.ResourceMetadata,
) scope.Error!?scope.Set {
    if (challenge_scope) |scopes| {
        if (scopes.len > 0) return try scope.Set.parse(scopes);
    }
    return metadata.supportedScopes();
}

/// Computes the scopes for a step-up authorization.
///
/// The union of what was previously requested and what the challenge names. A server
/// may challenge per operation, so replacing the set would cost the client permissions
/// it still needs elsewhere; concatenating would produce duplicates.
pub fn stepUpScopes(
    previously_requested: []const u8,
    challenge_scope: []const u8,
) scope.Error!scope.Set {
    return scope.Set.unionOf(previously_requested, challenge_scope);
}

/// Tracks step-up attempts so that a server which will never grant a scope cannot
/// produce an endless sequence of user prompts.
///
/// Keyed by nothing: one of these belongs to one operation. Sharing it across
/// operations would let an unrelated failure exhaust the budget.
pub const StepUp = struct {
    attempts: u8 = 0,
    /// The scopes requested so far, accumulated.
    requested: scope.Set = .{},

    pub const Decision = union(enum) {
        /// Re-authorize with these scopes.
        authorize: scope.Set,
        /// The attempt budget is spent. Treat the failure as permanent.
        give_up,
    };

    /// Records a challenge and decides what to do about it.
    pub fn onChallenge(
        step_up: *StepUp,
        challenge: *const bearer.ParsedChallenge,
    ) scope.Error!Decision {
        if (step_up.attempts >= step_up_attempts_max) return .give_up;

        const challenged = challenge.scope orelse "";
        const next = try scope.Set.unionOf(step_up.requested.value(), challenged);
        // No new scope means re-authorizing would ask for exactly what was just
        // refused. That is a loop, not a retry.
        if (next.count == step_up.requested.count and step_up.attempts > 0) return .give_up;

        step_up.attempts += 1;
        step_up.requested = next;
        return .{ .authorize = next };
    }

    /// Records the scopes an initial authorization asked for, so that a later step-up
    /// unions against them.
    pub fn record(step_up: *StepUp, scopes: []const u8) scope.Error!void {
        step_up.requested = try scope.Set.parse(scopes);
    }
};

// -- Tests --------------------------------------------------------------------

test "initialScopes prefers the challenge over scopes_supported" {
    const metadata: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
        .scopes_supported = &.{ "files:read", "profile" },
    };

    // The challenge is authoritative for the operation being attempted.
    const from_challenge = (try initialScopes("files:write", &metadata)).?;
    try std.testing.expectEqualStrings("files:write", from_challenge.value());

    // Absent a challenge, the advertised minimum.
    const from_metadata = (try initialScopes(null, &metadata)).?;
    try std.testing.expectEqualStrings("files:read profile", from_metadata.value());

    // An empty challenge scope is the same as none.
    const from_empty = (try initialScopes("", &metadata)).?;
    try std.testing.expectEqualStrings("files:read profile", from_empty.value());
}

test "initialScopes yields nothing when neither source says anything" {
    const metadata: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    // The `scope` parameter must then be omitted rather than sent empty.
    try std.testing.expectEqual(@as(?scope.Set, null), try initialScopes(null, &metadata));
}

test "stepUpScopes keeps what was already requested" {
    const next = try stepUpScopes("files:read profile", "files:write");
    try std.testing.expectEqualStrings("files:read profile files:write", next.value());
    // The whole point: the earlier permissions survive a per-operation challenge.
    try std.testing.expect(next.containsAll("files:read"));
    try std.testing.expect(next.containsAll("files:write"));
}

test "StepUp accumulates scopes across challenges then gives up" {
    var step_up: StepUp = .{};
    try step_up.record("files:read");

    var first: bearer.ParsedChallenge = .{
        .code = .insufficient_scope,
        .scope = "files:write",
    };
    const decision = try step_up.onChallenge(&first);
    try std.testing.expectEqualStrings("files:read files:write", decision.authorize.value());

    var second: bearer.ParsedChallenge = .{
        .code = .insufficient_scope,
        .scope = "mail:send",
    };
    const next = try step_up.onChallenge(&second);
    try std.testing.expectEqualStrings("files:read files:write mail:send", next.authorize.value());

    // Budget spent: a third challenge is treated as a permanent failure rather than
    // another user prompt.
    var third: bearer.ParsedChallenge = .{
        .code = .insufficient_scope,
        .scope = "admin",
    };
    try std.testing.expectEqual(StepUp.Decision.give_up, try step_up.onChallenge(&third));
}

test "StepUp gives up when a challenge adds no new scope" {
    var step_up: StepUp = .{};
    try step_up.record("files:read");

    var challenge: bearer.ParsedChallenge = .{
        .code = .insufficient_scope,
        .scope = "files:write",
    };
    _ = try step_up.onChallenge(&challenge);

    // The same challenge again: re-authorizing would ask for exactly what was just
    // refused, which is a loop.
    try std.testing.expectEqual(StepUp.Decision.give_up, try step_up.onChallenge(&challenge));
}

test "StepUp handles a challenge with no scope parameter" {
    var step_up: StepUp = .{};
    try step_up.record("files:read");

    var challenge: bearer.ParsedChallenge = .{ .code = .invalid_token };
    const decision = try step_up.onChallenge(&challenge);
    // Nothing new to add, but the first attempt is still allowed: the token may simply
    // have expired.
    try std.testing.expectEqualStrings("files:read", decision.authorize.value());
}

fn testClient(fetcher: *const http.Fetcher) Client {
    return .init(fetcher, .{
        .resource = "https://mcp.example.com/mcp",
        .redirect_uri = "http://127.0.0.1:3000/callback",
        .registration = .{ .client_id_metadata_document = "https://app.example.com/c.json" },
    });
}

test "discoverResource refuses a challenge pointing off-origin" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const fetcher: http.Fetcher = .{ .io = threaded.io() };
    const client = testClient(&fetcher);

    // The 401 that names the document is chosen by whoever answered, so a foreign URL
    // must be refused before it is fetched — no network access is needed to reach this.
    try std.testing.expectError(error.ResourceMetadataForeign, client.discoverResource(
        arena.allocator(),
        "https://attacker.example/.well-known/oauth-protected-resource",
    ));
}

test "a document may redefine its own resource but not name someone else's" {
    const options = testClient(undefined).options;

    // The legitimate case, and the reason this is not byte equality: the endpoint is
    // at /mcp and the identifier the document establishes is the origin.
    const redefined: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    try std.testing.expectEqualStrings(
        "https://mcp.example.com",
        try Client.adoptableIdentifier(options, &redefined),
    );

    // The attack. This document is served from the origin the client is talking to, so
    // every check that came before it passes; what it claims is that the token should
    // be minted for somebody else. The authorization server would honour that, and the
    // consent screen would name the third party rather than the server that asked —
    // so the user cannot tell the difference and consent protects nothing.
    const foreign: prm.ResourceMetadata = .{
        .resource = "https://bank.example.com/api",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    try std.testing.expectError(
        error.ResourceMetadataForeign,
        Client.adoptableIdentifier(options, &foreign),
    );

    // Origin is scheme, host, and port — each on its own is enough to be a third party.
    for ([_][]const u8{
        "http://mcp.example.com/mcp",
        "https://mcp.example.com:8443/mcp",
        "https://evil.mcp.example.com/mcp",
    }) |claimed| {
        const metadata: prm.ResourceMetadata = .{
            .resource = claimed,
            .authorization_servers = &.{"https://auth.example.com"},
        };
        try std.testing.expectError(
            error.ResourceMetadataForeign,
            Client.adoptableIdentifier(options, &metadata),
        );
    }
}

test "an adopted identifier is refused early if it is not canonical" {
    const options = testClient(undefined).options;

    // Same origin, but unusable as a `resource` parameter. Caught here rather than by
    // the token request, which would refuse it two steps removed from the cause.
    const fragment: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp#frag",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    try std.testing.expectError(
        error.ResourceMetadataInvalid,
        Client.adoptableIdentifier(options, &fragment),
    );
}

test "require_exact_resource additionally demands byte equality" {
    var options = testClient(undefined).options;
    options.require_exact_resource = true;

    const redefined: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    // Adoptable by origin, refused by the RFC 9728 Section 3.3 rule this option turns on.
    try std.testing.expectError(
        error.ResourceMetadataInvalid,
        Client.adoptableIdentifier(options, &redefined),
    );

    const exact: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
    };
    try std.testing.expectEqualStrings(
        "https://mcp.example.com/mcp",
        try Client.adoptableIdentifier(options, &exact),
    );
}

test "discoverResource rejects a resource this client cannot use" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const fetcher: http.Fetcher = .{ .io = threaded.io() };
    var client = testClient(&fetcher);
    client.options.resource = "https://mcp.example.com/mcp#frag";

    try std.testing.expectError(
        error.InvalidConfiguration,
        client.discoverResource(arena.allocator(), null),
    );
}

test "beginAuthorization refuses a server that does not advertise PKCE" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const fetcher: http.Fetcher = .{ .io = io };
    const client = testClient(&fetcher);

    const server: AuthorizationServer = .{
        .issuer = "https://auth.example.com",
        .metadata = .{
            .issuer = "https://auth.example.com",
            .authorization_endpoint = "https://auth.example.com/authorize",
            .token_endpoint = "https://auth.example.com/token",
            // No code_challenge_methods_supported.
        },
    };
    const resource: Resource = .{
        .metadata = .{
            .resource = "https://mcp.example.com/mcp",
            .authorization_servers = &.{"https://auth.example.com"},
        },
        .metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        .identifier = "https://mcp.example.com/mcp",
    };

    try std.testing.expectError(error.PkceUnsupported, client.beginAuthorization(
        arena.allocator(),
        io,
        &server,
        &resource,
        "files:read",
    ));
}

fn testServer() AuthorizationServer {
    return .{
        .issuer = "https://auth.example.com",
        .metadata = .{
            .issuer = "https://auth.example.com",
            .authorization_endpoint = "https://auth.example.com/authorize",
            .token_endpoint = "https://auth.example.com/token",
            .code_challenge_methods_supported = &.{"S256"},
            .authorization_response_iss_parameter_supported = true,
            .client_id_metadata_document_supported = true,
        },
    };
}

fn testResource() Resource {
    return .{
        .metadata = .{
            .resource = "https://mcp.example.com/mcp",
            .authorization_servers = &.{"https://auth.example.com"},
            .scopes_supported = &.{"files:read"},
        },
        .metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        .identifier = "https://mcp.example.com/mcp",
    };
}

test "beginAuthorization builds a complete request" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const fetcher: http.Fetcher = .{ .io = io };
    const client = testClient(&fetcher);

    const server = testServer();
    const resource = testResource();
    const request = try client.beginAuthorization(
        arena.allocator(),
        io,
        &server,
        &resource,
        "files:read",
    );

    try std.testing.expect(std.mem.indexOf(u8, request.url, "code_challenge_method=S256") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, request.url, "client_id=https%3A%2F%2Fapp.example.com%2Fc.json") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, request.url, "resource=https%3A%2F%2Fmcp.example.com%2Fmcp") != null,
    );
    // The issuer recorded here is what the `iss` check will compare against.
    try std.testing.expectEqualStrings("https://auth.example.com", request.issuer);
}

test "beginAuthorization refuses a registration bound to another issuer" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const fetcher: http.Fetcher = .{ .io = io };

    var client = testClient(&fetcher);
    client.options.registration = .{ .pre_registered = .{
        .client_id = "c1",
        .issuer = "https://other-auth.example",
    } };

    const server = testServer();
    const resource = testResource();
    // Silently presenting a client id this server never issued would fail in a way
    // that looks like a server problem.
    try std.testing.expectError(error.RegistrationUnavailable, client.beginAuthorization(
        arena.allocator(),
        io,
        &server,
        &resource,
        null,
    ));
}

test "request_offline_access adds the scope only when the server lists it" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const fetcher: http.Fetcher = .{ .io = io };

    var client = testClient(&fetcher);
    client.options.request_offline_access = true;

    var server = testServer();
    const resource = testResource();

    // Not advertised: asking anyway risks `invalid_scope` on a server that rejects
    // unknown scopes.
    const without = try client.beginAuthorization(arena.allocator(), io, &server, &resource, "files:read");
    try std.testing.expect(std.mem.indexOf(u8, without.url, "offline_access") == null);

    server.metadata.scopes_supported = &.{ "files:read", "offline_access" };
    const with = try client.beginAuthorization(arena.allocator(), io, &server, &resource, "files:read");
    try std.testing.expect(std.mem.indexOf(u8, with.url, "offline_access") != null);
    try std.testing.expectEqualStrings("files:read offline_access", with.scopes.?);
}

test "refresh refuses a token set bound elsewhere" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const fetcher: http.Fetcher = .{ .io = threaded.io() };
    const client = testClient(&fetcher);

    const server = testServer();
    var diagnosis: Diagnosis = .{};

    const foreign: token.TokenSet = .{
        .access_token = "at",
        .refresh_token = "rt",
        .issuer = "https://other-auth.example",
        .resource = "https://mcp.example.com/mcp",
    };
    try std.testing.expectError(error.RegistrationUnavailable, client.refresh(
        arena.allocator(),
        &server,
        &foreign,
        1_700_000_000,
        &diagnosis,
    ));

    // And a set with no refresh token has nothing to refresh with, which is a normal
    // outcome rather than a bug: the authorization server may not have issued one.
    const no_refresh: token.TokenSet = .{
        .access_token = "at",
        .issuer = "https://auth.example.com",
        .resource = "https://mcp.example.com/mcp",
    };
    try std.testing.expectError(error.TokenRequestRejected, client.refresh(
        arena.allocator(),
        &server,
        &no_refresh,
        1_700_000_000,
        &diagnosis,
    ));
}

test "clientCredentials refuses before it can put a secret on the wire" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var diagnosis: Diagnosis = .{};
    // Every refusal below happens before the token endpoint is contacted, which is the
    // point: an undefined fetcher would crash if any of them got that far.
    const fetcher: *const http.Fetcher = undefined;

    // A Client ID Metadata Document identifies a public client — the document is
    // world-readable, so it cannot hold a secret — and this grant is nothing but the
    // secret.
    {
        const client = testClient(fetcher);
        const server = testServer();
        try std.testing.expectError(error.InvalidConfiguration, client.clientCredentials(
            allocator,
            &server,
            "https://mcp.example.com/mcp",
            "mcp:invoke",
            1_700_000_000,
            &diagnosis,
        ));
    }

    const confidential: Options = .{
        .resource = "https://mcp.example.com/mcp",
        .redirect_uri = "http://127.0.0.1:3000/callback",
        .registration = .{ .pre_registered = .{
            .client_id = "gateway-caller",
            .client_secret = "s3cr3t",
            .issuer = "https://auth.example.com",
        } },
    };

    // Credentials issued by one authorization server, presented to another. The client
    // id is not a secret; the secret beside it is, and this is the request that would
    // hand it over.
    {
        const client: Client = .init(fetcher, confidential);
        var elsewhere = testServer();
        elsewhere.issuer = "https://other.example.com";
        elsewhere.metadata.issuer = "https://other.example.com";
        try std.testing.expectError(error.RegistrationUnavailable, client.clientCredentials(
            allocator,
            &elsewhere,
            "https://mcp.example.com/mcp",
            null,
            1_700_000_000,
            &diagnosis,
        ));
    }

    // The server published its grants and this is not among them, so the request is
    // known to be refused — no reason to send the secret to find that out.
    {
        const client: Client = .init(fetcher, confidential);
        var narrow = testServer();
        narrow.metadata.grant_types_supported = &.{ "authorization_code", "refresh_token" };
        try std.testing.expectError(error.GrantUnsupported, client.clientCredentials(
            allocator,
            &narrow,
            "https://mcp.example.com/mcp",
            null,
            1_700_000_000,
            &diagnosis,
        ));
    }
}

test "a challenge from a resource server drives scope selection end to end" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // The exact bytes a resource server emits for an unauthenticated request.
    const rendered = try (bearer.Challenge{
        .scope = "files:read",
        .resource_metadata = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    }).render(allocator);
    const parsed = (try bearer.parseChallenge(allocator, rendered)).?;

    const metadata: prm.ResourceMetadata = .{
        .resource = "https://mcp.example.com/mcp",
        .authorization_servers = &.{"https://auth.example.com"},
        .scopes_supported = &.{"profile"},
    };
    const initial = (try initialScopes(parsed.scope, &metadata)).?;
    // The challenge wins over the advertised minimum.
    try std.testing.expectEqualStrings("files:read", initial.value());

    // Then a 403 for a write operation.
    const forbidden = try (bearer.Challenge{
        .code = .insufficient_scope,
        .scope = "files:write",
        .resource_metadata = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    }).render(allocator);
    const escalation = (try bearer.parseChallenge(allocator, forbidden)).?;

    var step_up: StepUp = .{};
    try step_up.record(initial.value());
    const decision = try step_up.onChallenge(&escalation);
    // Both scopes, so the read access that already worked is not lost.
    try std.testing.expectEqualStrings("files:read files:write", decision.authorize.value());
}
