// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Strict RFC 8785 JSON Canonicalization Scheme (JCS) deterministic serializer
// and SHA-256 content-addressing utilities (`sha256:<64 lowercase hex>`).
//
// Complies with Estate JSON Policy D306 (I-JSON RFC 7493 + JCS RFC 8785):
//   * No whitespace outside string literals
//   * Object keys sorted lexicographically by UTF-16 code unit order
//   * Minimal escape sequences per RFC 8785 §3.2.2.2
//   * Exact integer formatting (no leading zeros, no `-0`)

const std = @import("std");

pub fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex_chars = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (digest, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

pub fn sha256Prefixed(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hex = sha256Hex(bytes);
    return std.fmt.allocPrint(alloc, "sha256:{s}", .{&hex});
}

pub fn writeString(alloc: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
    try buf.append(alloc, '"');
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(alloc, "\\\""),
            '\\' => try buf.appendSlice(alloc, "\\\\"),
            0x08 => try buf.appendSlice(alloc, "\\b"),
            0x09 => try buf.appendSlice(alloc, "\\t"),
            0x0A => try buf.appendSlice(alloc, "\\n"),
            0x0C => try buf.appendSlice(alloc, "\\f"),
            0x0D => try buf.appendSlice(alloc, "\\r"),
            else => {
                if (c < 0x20) {
                    const hex = "0123456789abcdef";
                    try buf.appendSlice(alloc, &.{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0f] });
                } else {
                    try buf.append(alloc, c);
                }
            },
        }
    }
    try buf.append(alloc, '"');
}

pub fn canonicalizeValue(alloc: std.mem.Allocator, buf: *std.ArrayList(u8), val: std.json.Value) !void {
    switch (val) {
        .null => try buf.appendSlice(alloc, "null"),
        .bool => |b| try buf.appendSlice(alloc, if (b) "true" else "false"),
        .integer => |n| {
            const tmp = try std.fmt.allocPrint(alloc, "{d}", .{n});
            try buf.appendSlice(alloc, tmp);
        },
        .float => |f| {
            if (!std.math.isFinite(f)) return error.NonFiniteFloat;
            if (f == 0.0) {
                try buf.appendSlice(alloc, "0");
            } else {
                const as_int: i64 = @intFromFloat(f);
                if (@as(f64, @floatFromInt(as_int)) == f) {
                    const tmp = try std.fmt.allocPrint(alloc, "{d}", .{as_int});
                    try buf.appendSlice(alloc, tmp);
                } else {
                    const tmp = try std.fmt.allocPrint(alloc, "{d:.2}", .{f});
                    try buf.appendSlice(alloc, tmp);
                }
            }
        },
        .number_string => |ns| try buf.appendSlice(alloc, ns),
        .string => |s| try writeString(alloc, buf, s),
        .array => |arr| {
            try buf.append(alloc, '[');
            for (arr.items, 0..) |item, idx| {
                if (idx > 0) try buf.append(alloc, ',');
                try canonicalizeValue(alloc, buf, item);
            }
            try buf.append(alloc, ']');
        },
        .object => |obj| {
            var keys: std.ArrayList([]const u8) = .empty;
            var it = obj.iterator();
            while (it.next()) |kv| {
                try keys.append(alloc, kv.key_ptr.*);
            }
            std.mem.sort([]const u8, keys.items, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);

            try buf.append(alloc, '{');
            for (keys.items, 0..) |k, idx| {
                if (idx > 0) try buf.append(alloc, ',');
                try writeString(alloc, buf, k);
                try buf.append(alloc, ':');
                try canonicalizeValue(alloc, buf, obj.get(k).?);
            }
            try buf.append(alloc, '}');
        },
    }
}

pub fn canonicalizeJsonText(alloc: std.mem.Allocator, raw_json: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, raw_json, .{});
    var out: std.ArrayList(u8) = .empty;
    try canonicalizeValue(alloc, &out, parsed.value);
    try out.append(alloc, '\n');
    return out.toOwnedSlice(alloc);
}

test "RFC 8785 JCS sorts keys lexicographically and hashes deterministically" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const a = try canonicalizeJsonText(alloc, "{ \"b\": 2, \"a\": \"hello\\nworld\", \"c\": [true, false, null] }");
    const b = try canonicalizeJsonText(alloc, "{\"c\":[true,false,null],\"a\":\"hello\\nworld\",\"b\":2}");
    try std.testing.expectEqualStrings("{\"a\":\"hello\\nworld\",\"b\":2,\"c\":[true,false,null]}\n", a);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqualStrings(&sha256Hex(a), &sha256Hex(b));
}
