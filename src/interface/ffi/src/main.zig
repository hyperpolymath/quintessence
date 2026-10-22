// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// QUINTESSENCE C-Compatible FFI Implementation
//
// Implements the linear handle lifecycle declared in `src/interface/Abi/`
// plus direct C-ABI entry points into the native Quintessence verifier core
// (error exit-code mapping, RFC 8785 JCS canonicalization, and SHA-256 digests).

const std = @import("std");
const core = @import("quintessence_core");

const VERSION = "0.1.0";
const ABI_VERSION: u32 = 1;
const BUILD_INFO = "QUINTESSENCE 0.1.0 built with Zig " ++ @import("builtin").zig_version_string;

threadlocal var last_error: ?[]const u8 = null;

fn setError(msg: []const u8) void {
    last_error = msg;
}

fn clearError() void {
    last_error = null;
}

fn dupeCString(alloc: std.mem.Allocator, s: []const u8) ![:0]u8 {
    const buf = try alloc.allocSentinel(u8, s.len, 0);
    @memcpy(buf, s);
    return buf;
}

/// Result codes matching `src/interface/Abi/Types.idr`
pub const Result = enum(c_int) {
    ok = 0,
    @"error" = 1,
    invalid_param = 2,
    out_of_memory = 3,
    null_pointer = 4,
};

/// Opaque linear library handle matching QTT `1 h : Handle`.
pub const Handle = struct {
    allocator: std.mem.Allocator,
    initialized: bool,
    verified_runs: u64,
};

pub export fn quintessence_abi_version() callconv(.c) u32 {
    return ABI_VERSION;
}

pub export fn quintessence_init() callconv(.c) ?*Handle {
    const allocator = std.heap.c_allocator;
    const handle = allocator.create(Handle) catch {
        setError("Failed to allocate handle");
        return null;
    };
    handle.* = .{
        .allocator = allocator,
        .initialized = true,
        .verified_runs = 0,
    };
    clearError();
    return handle;
}

pub export fn quintessence_free(handle: ?*Handle) callconv(.c) void {
    const h = handle orelse return;
    if (!h.initialized) return;
    const allocator = h.allocator;
    h.initialized = false;
    allocator.destroy(h);
    clearError();
}

pub export fn quintessence_process(handle: ?*Handle, input: u32) callconv(.c) Result {
    const h = handle orelse {
        setError("Null handle");
        return .null_pointer;
    };
    if (!h.initialized) {
        setError("Handle not initialized");
        return .@"error";
    }
    h.verified_runs += 1 + @as(u64, input & 0);
    clearError();
    return .ok;
}

/// Map a NUL-terminated Quintessence error code (e.g. "Q-401", "Q-603") to its
/// documented process exit status (`1..5`), or `255` when unknown.
export fn quintessence_lookup_exit_code(code_cstr: ?[*:0]const u8) callconv(.c) u8 {
    const ptr = code_cstr orelse return 255;
    const slice = std.mem.span(ptr);
    const spec = core.errors.lookup(slice) orelse return 255;
    return @backingInt(spec.exit_code);
}

/// Compute lowercase 64-byte hexadecimal SHA-256 of an input buffer without heap allocation.
export fn quintessence_sha256_hex(
    handle: ?*Handle,
    buffer: ?[*]const u8,
    len: u32,
    out_hex64: ?*[64]u8,
) callconv(.c) Result {
    const h = handle orelse {
        setError("Null handle");
        return .null_pointer;
    };
    if (!h.initialized) {
        setError("Handle not initialized");
        return .@"error";
    }
    const buf = buffer orelse {
        setError("Null input buffer");
        return .null_pointer;
    };
    const out = out_hex64 orelse {
        setError("Null output buffer");
        return .null_pointer;
    };
    out.* = core.jcs.sha256Hex(buf[0..len]);
    clearError();
    return .ok;
}

/// Canonicalize a JSON buffer according to RFC 8785 JCS; caller frees via `quintessence_free_string`.
export fn quintessence_canonicalize_jcs(
    handle: ?*Handle,
    raw_json: ?[*:0]const u8,
) callconv(.c) ?[*:0]const u8 {
    const h = handle orelse {
        setError("Null handle");
        return null;
    };
    if (!h.initialized) {
        setError("Handle not initialized");
        return null;
    }
    const src_ptr = raw_json orelse {
        setError("Null JSON input");
        return null;
    };
    var arena = std.heap.ArenaAllocator.init(h.allocator);
    defer arena.deinit();
    const canon = core.jcs.canonicalizeJsonText(arena.allocator(), std.mem.span(src_ptr)) catch {
        setError("Invalid I-JSON input");
        return null;
    };
    const duped = dupeCString(h.allocator, canon) catch {
        setError("Out of memory");
        return null;
    };
    clearError();
    return duped.ptr;
}

pub export fn quintessence_get_string(handle: ?*Handle) callconv(.c) ?[*:0]const u8 {
    const h = handle orelse {
        setError("Null handle");
        return null;
    };
    if (!h.initialized) {
        setError("Handle not initialized");
        return null;
    }
    const result = dupeCString(h.allocator, VERSION) catch {
        setError("Failed to allocate string");
        return null;
    };
    clearError();
    return result.ptr;
}

pub export fn quintessence_free_string(str: ?[*:0]const u8) callconv(.c) void {
    const s = str orelse return;
    const allocator = std.heap.c_allocator;
    const slice = std.mem.span(s);
    allocator.free(slice);
}

export fn quintessence_process_array(
    handle: ?*Handle,
    buffer: ?[*]const u8,
    len: u32,
) callconv(.c) Result {
    const h = handle orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const buf = buffer orelse {
        setError("Null buffer");
        return .null_pointer;
    };
    if (!h.initialized) {
        setError("Handle not initialized");
        return .@"error";
    }
    _ = core.jcs.sha256Hex(buf[0..len]);
    clearError();
    return .ok;
}

export fn quintessence_last_error() callconv(.c) ?[*:0]const u8 {
    const err = last_error orelse return null;
    const allocator = std.heap.c_allocator;
    const c_str = dupeCString(allocator, err) catch return null;
    return c_str.ptr;
}

export fn quintessence_version() callconv(.c) [*:0]const u8 {
    return VERSION.ptr;
}

export fn quintessence_build_info() callconv(.c) [*:0]const u8 {
    return BUILD_INFO.ptr;
}

pub const Callback = *const fn (u64, u32) callconv(.c) u32;

export fn quintessence_register_callback(
    handle: ?*Handle,
    callback: ?Callback,
) callconv(.c) Result {
    const h = handle orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const cb = callback orelse {
        setError("Null callback");
        return .null_pointer;
    };
    if (!h.initialized) {
        setError("Handle not initialized");
        return .@"error";
    }
    _ = cb;
    clearError();
    return .ok;
}

export fn quintessence_is_initialized(handle: ?*Handle) callconv(.c) u32 {
    const h = handle orelse return 0;
    return if (h.initialized) 1 else 0;
}

test "lifecycle and ABI version" {
    try std.testing.expectEqual(@as(u32, 1), quintessence_abi_version());
    const handle = quintessence_init() orelse return error.InitFailed;
    defer quintessence_free(handle);
    try std.testing.expectEqual(@as(u32, 1), quintessence_is_initialized(handle));
}

test "null handle rejection and exit code lookup" {
    try std.testing.expectEqual(Result.null_pointer, quintessence_process(null, 0));
    try std.testing.expectEqual(@as(u8, 1), quintessence_lookup_exit_code("Q-401"));
    try std.testing.expectEqual(@as(u8, 4), quintessence_lookup_exit_code("Q-303"));
    try std.testing.expectEqual(@as(u8, 5), quintessence_lookup_exit_code("Q-603"));
    try std.testing.expectEqual(@as(u8, 255), quintessence_lookup_exit_code("Q-999"));
}

test "JCS canonicalization and SHA-256 via C-ABI" {
    const handle = quintessence_init() orelse return error.InitFailed;
    defer quintessence_free(handle);

    const canon_ptr = quintessence_canonicalize_jcs(handle, "{ \"z\": 1, \"a\": true }") orelse return error.JcsFailed;
    defer quintessence_free_string(canon_ptr);
    try std.testing.expectEqualStrings("{\"a\":true,\"z\":1}\n", std.mem.span(canon_ptr));

    var hex: [64]u8 = undefined;
    const msg = "verisim";
    try std.testing.expectEqual(Result.ok, quintessence_sha256_hex(handle, msg.ptr, msg.len, &hex));
    try std.testing.expectEqualStrings("1a2db1167603f95db9e8059a0883e6992e0694b1a0fbbc9f77d0156af86fabf3", &hex);
}
