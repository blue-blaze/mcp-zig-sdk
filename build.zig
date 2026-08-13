const std = @import("std");
const builtin = @import("builtin");

/// Build graph for the MCP SDK. Exposes:
///   * the `oauth` module — OAuth 2.1 / RFC 9728 / RFC 8414 with zero MCP
///     coupling, importable on its own by any Zig project,
///   * the `mcp` module   — the MCP 2026-07-28 SDK (server + client, stdio +
///     Streamable HTTP), which imports `oauth` and `velo`,
///   * `zig build test`     -> the full unit-test suite,
///   * `zig build fmt`      -> formatting check,
///   * `zig build examples` -> the example programs, `zig build run-<name>`.
pub fn build(b: *std.Build) void {
    check_zig_version();

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Forwarded to Velo, because `https://` on the client transport is Velo's TLS
    // layer and nothing else. Without this option the option does not exist: the
    // `if (velo.tls_enabled)` branches are never analyzed, so the https path could
    // not even be compiled, let alone run.
    const tls = b.option(bool, "tls", "Enable TLS (links libssl/libcrypto via Velo)") orelse false;
    const tls_prefix = b.option([]const u8, "tls-prefix", "TLS library install prefix");

    const velo_dep = if (tls_prefix) |prefix| b.dependency("velo", .{
        .target = target,
        .optimize = optimize,
        .tls = tls,
        .@"tls-prefix" = prefix,
    }) else b.dependency("velo", .{
        .target = target,
        .optimize = optimize,
        .tls = tls,
    });
    const velo_mod = velo_dep.module("velo");

    // ---- Modules -----------------------------------------------------------

    // TigerStyle assertion helpers, shared by both public modules. A module root
    // file fixes the import boundary for its subtree, so code shared across
    // `src/mcp/` and `src/oauth/` has to be reached by module name rather than by
    // a relative path.
    const assert_mod = b.createModule(.{
        .root_source_file = b.path("src/assert.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The authorization module deliberately knows nothing about MCP: it is an
    // OAuth 2.1 client + resource-server toolkit that happens to satisfy the MCP
    // authorization spec. Keeping the dependency arrow pointing this way is what
    // makes it reusable outside this SDK.
    const oauth_mod = b.addModule("oauth", .{
        .root_source_file = b.path("src/oauth/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    oauth_mod.addImport("velo", velo_mod);
    oauth_mod.addImport("assert", assert_mod);

    const mcp_mod = b.addModule("mcp", .{
        .root_source_file = b.path("src/mcp/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mcp_mod.addImport("velo", velo_mod);
    mcp_mod.addImport("oauth", oauth_mod);
    mcp_mod.addImport("assert", assert_mod);

    // ---- Tests -------------------------------------------------------------

    const test_step = b.step("test", "Run the unit-test suite");

    const assert_tests = b.addTest(.{ .root_module = assert_mod });
    test_step.dependOn(&b.addRunArtifact(assert_tests).step);

    const oauth_tests = b.addTest(.{ .root_module = oauth_mod });
    test_step.dependOn(&b.addRunArtifact(oauth_tests).step);

    const mcp_tests = b.addTest(.{ .root_module = mcp_mod });
    test_step.dependOn(&b.addRunArtifact(mcp_tests).step);

    // ---- Examples ----------------------------------------------------------

    const examples_step = b.step("examples", "Build the example programs");

    for (examples) |example| {
        const exe = b.addExecutable(.{
            .name = example.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(example.path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "mcp", .module = mcp_mod },
                    .{ .name = "oauth", .module = oauth_mod },
                    .{ .name = "velo", .module = velo_mod },
                },
            }),
        });
        examples_step.dependOn(&b.addInstallArtifact(exe, .{}).step);

        const run = b.addRunArtifact(exe);
        if (b.args) |args| run.addArgs(args);
        b.step(
            b.fmt("run-{s}", .{example.name}),
            b.fmt("Run the '{s}' example", .{example.name}),
        ).dependOn(&run.step);
    }

    b.getInstallStep().dependOn(examples_step);

    // ---- Interoperability --------------------------------------------------

    // A checker rather than an example: its assertions are written against the server in
    // `interop/ts-server-common.mjs`, so it is a test that happens to need another
    // implementation running on the other end.
    const interop_check = b.addExecutable(.{
        .name = "interop-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop_check.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mcp", .module = mcp_mod }},
        }),
    });
    // ---- Fuzzing ------------------------------------------------------------

    // A plain executable rather than `std.testing.fuzz`: guided fuzzing through the test
    // runner does not build on Zig 0.16.0, and its non-fuzz fallback runs only the
    // declared corpus plus one empty input. See `tools/fuzz.zig`.
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fuzz.zig"),
            .target = target,
            // Release: the point is iterations per second, and the safety checks that
            // matter here are the ones the parsers make themselves.
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{ .name = "mcp", .module = mcp_mod },
                .{ .name = "oauth", .module = oauth_mod },
            },
        }),
    });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    if (b.args) |args| run_fuzz.addArgs(args);
    b.step("fuzz", "Fuzz the peer-facing parsers").dependOn(&run_fuzz.step);

    const interop_step = b.step("interop", "Build the interoperability checker");
    interop_step.dependOn(&b.addInstallArtifact(interop_check, .{}).step);
    b.getInstallStep().dependOn(interop_step);

    // ---- Spec conformance --------------------------------------------------

    // Emits sample payloads and validates them against `spec/schema.json`. The
    // unit tests pin the bytes this SDK produces; only the schema can say whether
    // those bytes are the ones the specification asks for.
    const spec_samples = b.addExecutable(.{
        .name = "spec-samples",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/spec_samples.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mcp", .module = mcp_mod }},
        }),
    });
    const emit_samples = b.addRunArtifact(spec_samples);
    const samples_ndjson = emit_samples.captureStdOut(.{});

    const validate = b.addSystemCommand(&.{"./tools/validate-spec.sh"});
    validate.addFileArg(samples_ndjson);
    validate.setName("validate against spec/schema.json");
    b.step("spec", "Check payloads against the published MCP schema")
        .dependOn(&validate.step);

    // ---- Formatting --------------------------------------------------------

    const fmt = b.addFmt(.{
        .paths = &.{ "build.zig", "src", "examples", "tools" },
        .check = true,
    });
    b.step("fmt", "Check source formatting").dependOn(&fmt.step);
}

const Example = struct {
    name: []const u8,
    path: []const u8,
};

/// Registered example programs. Each one is a runnable demonstration of a slice
/// of the SDK; `zig build run-<name>` starts it.
const examples = [_]Example{
    .{ .name = "smoke", .path = "examples/smoke.zig" },
    .{ .name = "hello", .path = "examples/hello.zig" },
    .{ .name = "stdio-server", .path = "examples/stdio_server.zig" },
    .{ .name = "stdio-client", .path = "examples/stdio_client.zig" },
    .{ .name = "http-server", .path = "examples/http_server.zig" },
    .{ .name = "http-client", .path = "examples/http_client.zig" },
    .{ .name = "oauth-flow", .path = "examples/oauth_flow.zig" },
    .{ .name = "http-auth", .path = "examples/http_auth.zig" },
};

/// A minor-version mismatch surfaces as confusing type errors deep inside `std`,
/// so fail loudly and early instead. The SDK tracks the same pinned compiler as
/// Velo, whose `std.Io` usage is the reason the pin is tight.
fn check_zig_version() void {
    const required = std.SemanticVersion{ .major = 0, .minor = 16, .patch = 0 };
    const actual = builtin.zig_version;
    if (actual.major != required.major or actual.minor != required.minor) {
        std.debug.panic(
            "unsupported Zig version {f}; this project requires {f}",
            .{ actual, required },
        );
    }
}
