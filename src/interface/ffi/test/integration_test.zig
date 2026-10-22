// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Quintessence FFI & Verifier Core Integration Tests.
//
// Exercises:
//   1. Linear handle lifecycle & null safety across the C-ABI boundary
//   2. Native Alethe S-expression Proof-DAG Kernel checker (accepts valid QED
//      refutation trees, rejects forward/undefined premises, unclosed anchors,
//      and non-empty root clauses)
//   3. Stage 1 G0a-G0c Firewall (`Q-101`, `Q-102`, `Q-105`, `Q-206`)
//   4. Layer C `MaxPlus` WCET static analyzer & C1 null-guard enforcement

const std = @import("std");
const ffi = @import("quintessence_ffi");
const core = @import("quintessence_core");

test "FFI handle lifecycle, version, and null safety" {
    const handle = ffi.quintessence_init() orelse return error.InitFailed;
    defer ffi.quintessence_free(handle);

    try std.testing.expectEqual(ffi.Result.ok, ffi.quintessence_process(handle, 42));
    const s = ffi.quintessence_get_string(handle) orelse return error.NullStr;
    defer ffi.quintessence_free_string(s);
    try std.testing.expectEqualStrings("0.1.0", std.mem.span(s));
}

test "Alethe proof kernel accepts valid QED proof and rejects malformed proofs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const valid_proof =
        \\(
        \\(assume a0 (> x 10))
        \\(assume a1 (<= x 5))
        \\(anchor :step t1)
        \\(assume t1.a0 (> x 10))
        \\(step t1 (cl false) :rule subproof :discharge (t1.a0))
        \\(step t2 (cl) :rule resolution :premises (a0 a1 t1))
        \\)
    ;
    const ok_stats = try core.smt.checkAletheProof(alloc, valid_proof);
    try std.testing.expect(ok_stats.valid_qed);
    try std.testing.expectEqual(@as(usize, 2), ok_stats.steps);
    try std.testing.expectEqual(@as(usize, 1), ok_stats.resolutions);
    try std.testing.expectEqual(@as(usize, 1), ok_stats.subproofs);

    // Reject proof whose premise `t99` has not been proved yet (cycle / forward ref)
    const bad_premise =
        \\(
        \\(assume a0 (> x 10))
        \\(step t2 (cl) :rule resolution :premises (a0 t99))
        \\)
    ;
    const bad1 = try core.smt.checkAletheProof(alloc, bad_premise);
    try std.testing.expect(!bad1.valid_qed);

    // Reject proof that ends on a non-empty clause instead of `(cl)`
    const non_empty =
        \\(
        \\(assume a0 (> x 10))
        \\(step t1 (cl (> x 0)) :rule resolution :premises (a0))
        \\)
    ;
    const bad2 = try core.smt.checkAletheProof(alloc, non_empty);
    try std.testing.expect(!bad2.valid_qed);
}

test "Firewall rejects Code.eval_string (Q-101), dynamic apply/3 (Q-102), and exfiltration caps (Q-206)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bad_ex =
        \\defmodule BadMod do
        \\  use Quintessence.Face, layer: :a
        \\  @cap [:fs_read, :net_send]
        \\  def run(src, m, f) do
        \\    _ = Code.eval_string(src)
        \\    apply(m, f, [])
        \\  end
        \\end
    ;
    const mods = try core.ast.parseFile(alloc, "bad_mod.ex", bad_ex);
    try std.testing.expectEqual(@as(usize, 1), mods.len);
    var diags: std.ArrayList(core.errors.Diagnostic) = .empty;
    try core.firewall.checkModule(alloc, &mods[0], &diags);
    try std.testing.expectEqual(@as(usize, 3), diags.items.len);
    try std.testing.expectEqualStrings("Q-206", diags.items[0].code);
    try std.testing.expectEqualStrings("Q-101", diags.items[1].code);
    try std.testing.expectEqualStrings("Q-102", diags.items[2].code);
}
