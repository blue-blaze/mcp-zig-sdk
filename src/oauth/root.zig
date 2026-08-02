//! OAuth 2.1 toolkit: an authorization-code client and a resource server, with no
//! dependency on MCP.
//!
//! The Model Context Protocol delegates its authorization story to a stack of
//! existing RFCs rather than inventing one, so the code that satisfies it is useful on
//! its own. Nothing in this module imports `mcp`; it can be dropped into any Zig
//! service that needs to protect an HTTP resource with bearer tokens, or into any
//! client that needs to obtain them.
//!
//! ## Layout
//!
//! Everything except `http` is pure — it builds strings and validates documents that
//! somebody else fetched. That is deliberate: it means every security-relevant
//! decision in this module is unit-testable without a network, and it is why the test
//! suite can cover algorithm confusion, issuer mismatch, and scope escalation directly
//! rather than through a mock server.
//!
//! | Module | Role |
//! |---|---|
//! | `url` | Parsing, and the three different well-known URL rules |
//! | `scope` | Scope sets, and the union that step-up authorization is defined by |
//! | `bearer` | Bearer tokens and `WWW-Authenticate` challenges, both directions |
//! | `base64url` | Unpadded base64url, the encoding JOSE uses everywhere |
//! | `jwk` | JSON Web Keys, with algorithm confusion made unrepresentable |
//! | `jwt` | Access token validation, in the order that makes it validation |
//! | `prm` | Protected resource metadata (RFC 9728) |
//! | `as_metadata` | Authorization server metadata (RFC 8414 and OIDC Discovery) |
//! | `authorize` | PKCE, the authorization request, and the RFC 9207 `iss` check |
//! | `token` | Token endpoint requests, responses, and the resulting token set |
//! | `cimd` | Client ID Metadata Documents and the registration priority rule |
//! | `resource_server` | Turning an `Authorization` header into 401/403/503/granted |
//! | `client` | The client side assembled: discovery chain, scopes, step-up |
//! | `http` | The only I/O: fetching documents, and a caching JWKS provider |
//!
//! ## Implemented
//!
//!   * OAuth 2.1 authorization code flow with PKCE (draft-ietf-oauth-v2-1)
//!   * Bearer token usage and challenges (RFC 6750)
//!   * Authorization server metadata discovery (RFC 8414) and OpenID Connect
//!     Discovery 1.0, with the issuer validation both require
//!   * Protected resource metadata (RFC 9728)
//!   * Resource indicators (RFC 8707) in both the authorization and token requests
//!   * Authorization server issuer identification (RFC 9207), all four rows of it
//!   * Client ID Metadata Documents
//!     (draft-ietf-oauth-client-id-metadata-document)
//!   * JWT access token validation with RS256/384/512 and ES256/384, over a JWKS
//!
//! ## Deliberately not implemented
//!
//!   * **Acting as an authorization server.** MCP puts that role outside its
//!     specification, and so does this module.
//!   * **`alg: none` and every HMAC algorithm.** Their absence from `jwk.Algorithm` is
//!     what turns algorithm confusion from a mistake to avoid into a parse failure.
//!   * **`signed_metadata` in protected resource metadata.** Verifying it needs a trust
//!     anchor this module cannot obtain, and accepting the field while ignoring its
//!     signature would be worse than not accepting it.
//!   * **`private_key_jwt` client authentication.** It requires signing an assertion,
//!     and `std.crypto` verifies RSA without signing it — so only EC would be
//!     available, which not every authorization server accepts. A partial
//!     implementation of client authentication is worse than none.
//!   * **URL normalization.** Two security checks here are byte-exact string
//!     comparisons that the specification says **MUST NOT** be preceded by case
//!     folding, default-port elision, trailing-slash, or percent-encoding
//!     normalization. Offering a `normalize` would invite exactly the call that defeats
//!     them.
//!
//! ## Memory
//!
//! As in the `mcp` module, allocators are always explicit, owning types expose
//! `deinit`, and tests run under `std.testing.allocator`. Documents fetched from the
//! network are parsed into a caller-supplied arena and every parser has a size bound,
//! because their size is chosen by the peer.

const std = @import("std");

pub const assert_mod = @import("assert");

pub const url = @import("url.zig");
pub const base64url = @import("base64url.zig");
pub const jwk = @import("jwk.zig");
pub const jwt = @import("jwt.zig");
pub const scope = @import("scope.zig");
pub const bearer = @import("bearer.zig");
pub const prm = @import("prm.zig");
pub const as_metadata = @import("as_metadata.zig");
pub const authorize = @import("authorize.zig");
pub const token = @import("token.zig");
pub const cimd = @import("cimd.zig");
pub const client = @import("client.zig");
pub const resource_server = @import("resource_server.zig");
pub const http = @import("http.zig");

// Convenience aliases for the types a caller reaches for first.

/// Applies a token verifier and the challenge rules to incoming requests.
pub const ResourceServer = resource_server.ResourceServer;
/// What a validated token establishes.
pub const Grant = resource_server.Grant;
/// How a token is validated. Implement this for introspection or opaque tokens.
pub const Verifier = resource_server.Verifier;
/// The built-in JWT verifier.
pub const JwtVerifier = resource_server.JwtVerifier;
/// Where a `JwtVerifier` gets its keys.
pub const KeyProvider = resource_server.KeyProvider;

/// Drives the OAuth flows for one protected resource.
pub const Client = client.Client;
/// Tokens held for one resource at one issuer.
pub const TokenSet = token.TokenSet;
/// A PKCE code verifier and its challenge.
pub const Pkce = authorize.Pkce;
/// How a client identifies itself to an authorization server.
pub const Registration = cimd.Registration;

/// Performs the HTTP requests the flows need. The only I/O in this module.
pub const Fetcher = http.Fetcher;
/// A `KeyProvider` that fetches and caches a JWKS.
pub const JwksProvider = http.JwksProvider;

/// A `WWW-Authenticate: Bearer` challenge.
pub const Challenge = bearer.Challenge;
/// A parsed challenge, as a client sees it.
pub const ParsedChallenge = bearer.ParsedChallenge;
/// A deduplicated set of scope tokens.
pub const ScopeSet = scope.Set;

/// An RFC 9728 protected resource metadata document.
pub const ResourceMetadata = prm.ResourceMetadata;
/// An RFC 8414 / OIDC authorization server metadata document.
pub const ServerMetadata = as_metadata.Metadata;
/// A Client ID Metadata Document.
pub const ClientMetadata = cimd.ClientMetadata;

test {
    std.testing.refAllDecls(@This());
}
