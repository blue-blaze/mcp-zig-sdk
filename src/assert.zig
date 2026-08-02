//! TigerStyle assertion helpers, shared by the `mcp` and `oauth` modules.
//!
//! Assertions catch *programmer* errors, which are unexpected; *operating* errors
//! are expected and travel through error unions instead. A failed assertion is a
//! bug, and crashing is the only correct response: it converts a silent
//! correctness bug into a loud liveness bug.
//!
//! Aim for at least two assertions per function, and assert both the positive
//! space you expect and the negative space you do not. Prefer splitting compound
//! assertions (`assert(a); assert(b);`) over `assert(a and b)`, so that a failure
//! pinpoints the exact invariant that was violated.

const std = @import("std");
const builtin = @import("builtin");

/// Assert a runtime invariant. Compiled out in `ReleaseFast`/`ReleaseSmall`,
/// always active in `Debug` and `ReleaseSafe`.
pub inline fn assert(ok: bool) void {
    if (!ok) unreachable;
}

/// Assert an implication: if `a` holds then `b` must hold too.
pub inline fn assert_implies(a: bool, b: bool) void {
    if (a) assert(b);
}

/// Compile-time assertion, for pinning type sizes and constant relationships.
pub inline fn comptime_assert(comptime ok: bool) void {
    if (!ok) @compileError("comptime assertion failed");
}

/// Marks a branch believed to be impossible. Reaching it is a bug.
pub inline fn unreachable_branch(comptime reason: []const u8) noreturn {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
        std.debug.panic("unreachable: {s}", .{reason});
    }
    unreachable;
}

test "assertions hold for true predicates" {
    assert(true);
    assert_implies(false, false);
    assert_implies(true, 1 + 1 == 2);
    comptime_assert(@sizeOf(u32) == 4);
}
