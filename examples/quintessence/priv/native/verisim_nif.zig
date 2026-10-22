// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Compiled and verified by `just build` / `zig build`. See README.adoc.
//
// The core is deliberately small: no allocation, no globals, no @cImport, no
// inline assembly. That keeps the ZigProve obligation set to C1-C8, C10, C12.

const std = @import("std");

pub const Error = enum(u32) {
    ok = 0,
    invalid = 1,
    too_large = 2,
    overflow = 3,
};

/// SHA-256 into a 32-byte digest.
/// Preconditions: `payload` non-null and `len <= 1 MiB`; `out` non-null.
/// Postconditions: on `ok`, `out` is fully written; no allocation.
export fn verisim_hash(
    handle: ?*anyopaque,
    payload: ?[*]const u8,
    len: u32,
    seed: u32,
    out: ?*[32]u8,
) callconv(.c) u32 {
    _ = handle orelse return @backingInt(Error.invalid);
    const p = payload orelse return @backingInt(Error.invalid);
    const o = out orelse return @backingInt(Error.invalid);

    if (len > 1_048_576) return @backingInt(Error.too_large);

    const slice = p[0..len];
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(slice);
    hasher.final(o);

    // The seed is part of the ABI for a future keyed hash; SHA-256 ignores it.
    _ = seed;
    return @backingInt(Error.ok);
}

/// Basis-point drift: popcount of the XOR of two 32-byte digests, scaled to
/// 0..10000. Max value: 256 bits * 10000 / 256 = 10000, fits u32.
export fn verisim_drift(
    a: ?*const [32]u8,
    b: ?*const [32]u8,
    out: ?*u32,
) callconv(.c) u32 {
    const x = a orelse return @backingInt(Error.invalid);
    const y = b orelse return @backingInt(Error.invalid);
    const o = out orelse return @backingInt(Error.invalid);

    var bits: u32 = 0;
    for (x.*, y.*) |xb, yb| {
        bits += @as(u32, @popCount(xb ^ yb));
    }

    o.* = (bits * 10_000) / 256;
    return @backingInt(Error.ok);
}

test "hash is the SHA-256 of the payload" {
    var out: [32]u8 = undefined;
    var handle: u8 = 0;
    const payload = "verisim";
    const expected = [_]u8{
        0x1a, 0x2d, 0xb1, 0x16, 0x76, 0x03, 0xf9, 0x5d,
        0xb9, 0xe8, 0x05, 0x9a, 0x08, 0x83, 0xe6, 0x99,
        0x2e, 0x06, 0x94, 0xb1, 0xa0, 0xfb, 0xbc, 0x9f,
        0x77, 0xd0, 0x15, 0x6a, 0xf8, 0x6f, 0xab, 0xf3,
    };
    const rc = verisim_hash(&handle, payload.ptr, payload.len, 0, &out);
    try std.testing.expectEqual(@backingInt(Error.ok), rc);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "a null handle is rejected" {
    var out: [32]u8 = undefined;
    const payload = "verisim";
    const rc = verisim_hash(null, payload.ptr, payload.len, 0, &out);
    try std.testing.expectEqual(@backingInt(Error.invalid), rc);
}

test "drift is in range" {
    const a: [32]u8 = @splat(0);
    const b: [32]u8 = @splat(0xff);
    var out: u32 = 0;
    const rc = verisim_drift(&a, &b, &out);
    try std.testing.expectEqual(@backingInt(Error.ok), rc);
    try std.testing.expectEqual(@as(u32, 10_000), out);
}
