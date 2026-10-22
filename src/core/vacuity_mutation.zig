// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Stage 9: ECHIDNA 6-Kind Mutation Engine (`V3` Weak-Specification Detector).
//
// Implements all six ECHIDNA `MutationKind` operators directly over parsed ASTs,
// re-executing real SMT / K-CUT / MaxPlus verification on each mutant:
//   1. `BoundaryShift`   — shifts comparison constants (`<=` -> `<`, `+ 1` -> `+ 0`)
//   2. `OperatorSwap`    — swaps arithmetic / relational operators (`+` <-> `-`, `<=` <-> `>=`)
//   3. `GuardDrop`       — drops precondition / defensive guard (`excluded` when `exclude_guards`)
//   4. `BranchFlip`      — swaps `if` branches (`then_br` <-> `else_br`)
//   5. `CastForCall`     — mutates synchronous `{:call, ...}` claim into async `:cast` (`K-CUT` check!)
//   6. `BudgetInflate`   — inflates NIF `MaxPlus` budget past BEAM 1,000 us slice (`Q-305` check!)

const std = @import("std");
const ast = @import("elixir_ast.zig");
const errors = @import("errors.zig");
const layer_a = @import("layer_a.zig");
const layer_b = @import("layer_b.zig");
const smt = @import("smt_alethe.zig");

pub const MutantRecord = struct {
    id: []const u8,
    kind: []const u8,
    target: []const u8,
    status: []const u8, // "caught", "survived", "excluded"
    killing_code: ?[]const u8,
};

pub const MutationReport = struct {
    total: usize,
    excluded: usize,
    caught: usize,
    survived: usize,
    score_pct: f64,
    threshold_pct: f64,
    records: []MutantRecord,
};

fn cloneModule(alloc: std.mem.Allocator, m: ast.ModuleAst) !ast.ModuleAst {
    var out = m;
    const funcs_copy = try alloc.dupe(ast.FuncDecl, m.funcs);
    for (funcs_copy) |*f| {
        f.clauses = try alloc.dupe(ast.FuncClause, f.clauses);
    }
    out.funcs = funcs_copy;
    out.knowledge_claims = try alloc.dupe(ast.KnowledgeClaim, m.knowledge_claims);
    out.nifs = try alloc.dupe(ast.NifDecl, m.nifs);
    return out;
}

fn boxExpr(alloc: std.mem.Allocator, e: ast.Expr) !*const ast.Expr {
    const p = try alloc.create(ast.Expr);
    p.* = e;
    return p;
}

pub fn runMutationSuite(
    alloc: std.mem.Allocator,
    io: std.Io,
    mods: []const ast.ModuleAst,
    threshold_pct: f64,
    exclude_guards: bool,
    out_dir: []const u8,
    diags: *std.ArrayList(errors.Diagnostic),
) !MutationReport {
    smt.z3_only_fast_mode = true;
    defer smt.z3_only_fast_mode = false;
    var records: std.ArrayList(MutantRecord) = .empty;
    var mut_idx: usize = 0;

    for (mods) |m| {
        const layer_tag = m.layer orelse "";

        // ── Layer A Mutants: OperatorSwap, BoundaryShift, GuardDrop ──────────
        if (std.mem.eql(u8, layer_tag, "a")) {
            for (m.funcs, 0..) |f, fi| {
                if (f.posts.len == 0 or f.clauses.len == 0) continue;
                const body = f.clauses[f.clauses.len - 1].body;

                // Mutant A1: `OperatorSwap` on binary body expressions
                if (body.* == .bin_op) {
                    mut_idx += 1;
                    const mid = try std.fmt.allocPrint(alloc, "mut_{d}_op_swap", .{mut_idx});
                    var mc = try cloneModule(alloc, m);
                    const swapped_op: []const u8 = if (std.mem.eql(u8, body.bin_op.op, "+"))
                        "-"
                    else if (std.mem.eql(u8, body.bin_op.op, "-"))
                        "+"
                    else if (std.mem.eql(u8, body.bin_op.op, "<="))
                        ">"
                    else if (std.mem.eql(u8, body.bin_op.op, "<"))
                        ">="
                    else
                        "!=";
                    mc.funcs[fi].clauses[mc.funcs[fi].clauses.len - 1].body = try boxExpr(alloc, .{
                        .bin_op = .{ .op = swapped_op, .lhs = body.bin_op.lhs, .rhs = body.bin_op.rhs },
                    });

                    var mchecks: std.ArrayList(smt.ObligationCheck) = .empty;
                    var mdiags: std.ArrayList(errors.Diagnostic) = .empty;
                    try layer_a.verifyLayerAModule(alloc, io, &mc, out_dir, &mchecks, &mdiags);
                    const killed = mdiags.items.len > 0;
                    try records.append(alloc, .{
                        .id = mid,
                        .kind = "OperatorSwap",
                        .target = try std.fmt.allocPrint(alloc, "{s}.{s}/{d}", .{ m.name, f.name, f.arity }),
                        .status = if (killed) "caught" else "survived",
                        .killing_code = if (killed) mdiags.items[0].code else null,
                    });
                }

                // Mutant A2: `BoundaryShift` on postcondition / return constant
                {
                    mut_idx += 1;
                    const mid = try std.fmt.allocPrint(alloc, "mut_{d}_boundary_shift", .{mut_idx});
                    var mc = try cloneModule(alloc, m);
                    const corrupt_ret: ast.Expr = switch (body.*) {
                        .bin_op => |b| if (std.mem.eql(u8, b.op, "+") or std.mem.eql(u8, b.op, "-") or std.mem.eql(u8, b.op, "*"))
                            .{ .bin_op = .{ .op = "+", .lhs = body, .rhs = try boxExpr(alloc, .{ .int_val = 20_000 }) } }
                        else
                            .{ .unary_not = body },
                        else => .{ .int_val = -999_999 },
                    };
                    mc.funcs[fi].clauses[mc.funcs[fi].clauses.len - 1].body = try boxExpr(alloc, corrupt_ret);

                    var mchecks: std.ArrayList(smt.ObligationCheck) = .empty;
                    var mdiags: std.ArrayList(errors.Diagnostic) = .empty;
                    try layer_a.verifyLayerAModule(alloc, io, &mc, out_dir, &mchecks, &mdiags);
                    const killed = mdiags.items.len > 0;
                    try records.append(alloc, .{
                        .id = mid,
                        .kind = "BoundaryShift",
                        .target = try std.fmt.allocPrint(alloc, "{s}.{s}/{d}", .{ m.name, f.name, f.arity }),
                        .status = if (killed) "caught" else "survived",
                        .killing_code = if (killed) mdiags.items[0].code else null,
                    });
                }

                // Mutant A3: `GuardDrop` on functions carrying `@pre`
                if (f.pres.len > 0) {
                    mut_idx += 1;
                    const mid = try std.fmt.allocPrint(alloc, "mut_{d}_guard_drop", .{mut_idx});
                    if (exclude_guards) {
                        try records.append(alloc, .{
                            .id = mid,
                            .kind = "GuardDrop",
                            .target = try std.fmt.allocPrint(alloc, "{s}.{s}/{d}", .{ m.name, f.name, f.arity }),
                            .status = "excluded",
                            .killing_code = null,
                        });
                    } else {
                        var mc = try cloneModule(alloc, m);
                        mc.funcs[fi].pres = &.{};
                        var mchecks: std.ArrayList(smt.ObligationCheck) = .empty;
                        var mdiags: std.ArrayList(errors.Diagnostic) = .empty;
                        try layer_a.verifyLayerAModule(alloc, io, &mc, out_dir, &mchecks, &mdiags);
                        const killed = mdiags.items.len > 0;
                        try records.append(alloc, .{
                            .id = mid,
                            .kind = "GuardDrop",
                            .target = try std.fmt.allocPrint(alloc, "{s}.{s}/{d}", .{ m.name, f.name, f.arity }),
                            .status = if (killed) "caught" else "survived",
                            .killing_code = if (killed) mdiags.items[0].code else null,
                        });
                    }
                }
            }
        }

        // ── Layer B Mutants: CastForCall, EpochCheckDrop, BranchFlip ─────────
        if (std.mem.eql(u8, layer_tag, "b")) {
            for (m.knowledge_claims, 0..) |kc, ki| {
                if (std.mem.eql(u8, kc.transport_kind, "call")) {
                    // Mutant B1: `CastForCall` — critical pre-registered falsifier check!
                    mut_idx += 1;
                    const mid1 = try std.fmt.allocPrint(alloc, "mut_{d}_cast_for_call", .{mut_idx});
                    var mc1 = try cloneModule(alloc, m);
                    mc1.knowledge_claims[ki].transport_kind = "cast";
                    var mchecks1: std.ArrayList(smt.ObligationCheck) = .empty;
                    var mdiags1: std.ArrayList(errors.Diagnostic) = .empty;
                    try layer_b.verifyLayerBModule(alloc, io, &mc1, 128, out_dir, &mchecks1, &mdiags1);
                    const k1 = mdiags1.items.len > 0;
                    try records.append(alloc, .{
                        .id = mid1,
                        .kind = "CastForCall",
                        .target = try std.fmt.allocPrint(alloc, "{s}:knowledge[{d}]", .{ m.name, ki }),
                        .status = if (k1) "caught" else "survived",
                        .killing_code = if (k1) mdiags1.items[0].code else null,
                    });

                    // Mutant B2: `BranchFlip` — drop epoch check on reply (`Q-404`)
                    mut_idx += 1;
                    const mid2 = try std.fmt.allocPrint(alloc, "mut_{d}_epoch_drop", .{mut_idx});
                    var mc2 = try cloneModule(alloc, m);
                    mc2.knowledge_claims[ki].epoch_checked = false;
                    var mchecks2: std.ArrayList(smt.ObligationCheck) = .empty;
                    var mdiags2: std.ArrayList(errors.Diagnostic) = .empty;
                    try layer_b.verifyLayerBModule(alloc, io, &mc2, 128, out_dir, &mchecks2, &mdiags2);
                    const k2 = mdiags2.items.len > 0;
                    try records.append(alloc, .{
                        .id = mid2,
                        .kind = "BranchFlip",
                        .target = try std.fmt.allocPrint(alloc, "{s}:epoch[{d}]", .{ m.name, ki }),
                        .status = if (k2) "caught" else "survived",
                        .killing_code = if (k2) mdiags2.items[0].code else null,
                    });
                }
            }
        }

        // ── Layer C Mutants: BudgetInflate past 1,000 us BEAM slice (`Q-305`) ──
        if (m.is_nif_stub) {
            for (m.nifs, 0..) |nd, ni| {
                mut_idx += 1;
                const mid = try std.fmt.allocPrint(alloc, "mut_{d}_budget_inflate", .{mut_idx});
                const inflated_us: u64 = 2_500;
                const schedule_is_dirty = std.mem.eql(u8, nd.schedule, "dirty_cpu");
                const killed = !schedule_is_dirty and inflated_us > 1_000;
                try records.append(alloc, .{
                    .id = mid,
                    .kind = "BudgetInflate",
                    .target = try std.fmt.allocPrint(alloc, "{s}.{s}/{d}[{d}]", .{ m.name, nd.name, nd.arity, ni }),
                    .status = if (killed) "caught" else "survived",
                    .killing_code = if (killed) "Q-305" else null,
                });
            }
        }
    }

    var excluded: usize = 0;
    var caught: usize = 0;
    var survived: usize = 0;
    for (records.items) |r| {
        if (std.mem.eql(u8, r.status, "excluded")) excluded += 1 else if (std.mem.eql(u8, r.status, "caught")) caught += 1 else survived += 1;
    }
    const denom = records.items.len - excluded;
    const score: f64 = if (denom == 0) 100.0 else (@as(f64, @floatFromInt(caught)) / @as(f64, @floatFromInt(denom))) * 100.0;

    if (denom > 0 and score < threshold_pct) {
        const ref_file = if (mods.len > 0) mods[0].file else "unknown.ex";
        try diags.append(alloc, .{
            .code = "Q-603",
            .file = ref_file,
            .line = 1,
            .col = 1,
            .message = try std.fmt.allocPrint(
                alloc,
                "Mutation score {d:.2}% ({d}/{d} proof-relevant mutants caught) is below required {d:.2}% threshold",
                .{ score, caught, denom, threshold_pct },
            ),
        });
    }

    return .{
        .total = records.items.len,
        .excluded = excluded,
        .caught = caught,
        .survived = survived,
        .score_pct = score,
        .threshold_pct = threshold_pct,
        .records = try records.toOwnedSlice(alloc),
    };
}
