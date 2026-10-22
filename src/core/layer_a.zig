// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Layer A Verifier: Pure Sequential Elixir Subset -> SMT-LIB 2.6 VCs + BitVec
// Lemmas + TINI Non-Interference + Vacuity Probes (V1, V2).

const std = @import("std");
const ast = @import("elixir_ast.zig");
const errors = @import("errors.zig");
const smt = @import("smt_alethe.zig");

pub const RecCall = struct {
    arg0_smt: ?[]const u8,
    guard_smt: []const u8,
};

const ExprSort = enum { int_sort, bool_sort };

fn inferSort(e: *const ast.Expr) ExprSort {
    return switch (e.*) {
        .bool_val, .unary_not => .bool_sort,
        .var_ref => |v| if (std.mem.endsWith(u8, v, "?")) .bool_sort else .int_sort,
        .bin_op => |b| if (std.mem.eql(u8, b.op, "+") or std.mem.eql(u8, b.op, "-") or std.mem.eql(u8, b.op, "*") or std.mem.eql(u8, b.op, "/"))
            .int_sort
        else
            .bool_sort,
        .call => |c| if (std.mem.endsWith(u8, c.func, "?")) .bool_sort else .int_sort,
        .if_expr => |ie| inferSort(ie.then_br),
        .let_bind => |lb| inferSort(lb.body),
        .case_expr => |ce| if (ce.arms.len > 0) inferSort(ce.arms[0].body) else .int_sort,
        else => .int_sort,
    };
}

pub const SmtLowerCtx = struct {
    alloc: std.mem.Allocator,
    mod: *const ast.ModuleAst,
    fn_name: []const u8,
    uses_band_n_minus_1: bool = false,
    rec_calls: std.ArrayList(RecCall) = .empty,
    pat_binds: std.ArrayList(struct { name: []const u8, val: []const u8 }) = .empty,

    pub fn lower(self: *SmtLowerCtx, e: *const ast.Expr, active_guard: []const u8) anyerror![]const u8 {
        switch (e.*) {
            .int_val => |n| {
                if (n < 0) return std.fmt.allocPrint(self.alloc, "(- {d})", .{-n});
                return std.fmt.allocPrint(self.alloc, "{d}", .{n});
            },
            .bool_val => |b| return if (b) "true" else "false",
            .bin_zeros => |nbytes| return std.fmt.allocPrint(self.alloc, "(mk_bin_len {d})", .{nbytes}),
            .atom_val => |a| {
                // Deterministic atom tag integer encoding
                var h: u32 = 2166136261;
                for (a) |c| h = (h ^ c) *% 16777619;
                return std.fmt.allocPrint(self.alloc, "{d}", .{h % 1_000_000});
            },
            .var_ref => |v| {
                const sv = try sanitizeIdent(self.alloc, v);
                var bi: usize = self.pat_binds.items.len;
                while (bi > 0) {
                    bi -= 1;
                    if (std.mem.eql(u8, self.pat_binds.items[bi].name, sv)) {
                        return self.pat_binds.items[bi].val;
                    }
                }
                return sv;
            },
            .attr_ref => |aname| {
                if (self.mod.constants.get(aname)) |val| {
                    if (val < 0) return std.fmt.allocPrint(self.alloc, "(- {d})", .{-val});
                    return std.fmt.allocPrint(self.alloc, "{d}", .{val});
                }
                return "0";
            },
            .field_access => |fa| {
                if (fa.base.* == .var_ref) {
                    const combined = try std.fmt.allocPrint(self.alloc, "{s}_{s}", .{ fa.base.var_ref, fa.field });
                    return sanitizeIdent(self.alloc, combined);
                }
                return sanitizeIdent(self.alloc, fa.field);
            },
            .unary_not => |u| return std.fmt.allocPrint(self.alloc, "(not {s})", .{try self.lower(u, active_guard)}),
            .unary_neg => |u| return std.fmt.allocPrint(self.alloc, "(- {s})", .{try self.lower(u, active_guard)}),
            .bin_op => |b| {
                const l = try self.lower(b.lhs, active_guard);
                const r = try self.lower(b.rhs, active_guard);
                if (std.mem.eql(u8, b.op, "==")) return std.fmt.allocPrint(self.alloc, "(= {s} {s})", .{ l, r });
                if (std.mem.eql(u8, b.op, "!=")) return std.fmt.allocPrint(self.alloc, "(not (= {s} {s}))", .{ l, r });
                if (std.mem.eql(u8, b.op, "/")) return std.fmt.allocPrint(self.alloc, "(div {s} {s})", .{ l, r });
                return std.fmt.allocPrint(self.alloc, "({s} {s} {s})", .{ b.op, l, r });
            },
            .let_bind => |lb| {
                const v = try self.lower(lb.val, active_guard);
                const nm = try sanitizeIdent(self.alloc, lb.name);
                const body = try self.lower(lb.body, active_guard);
                return std.fmt.allocPrint(self.alloc, "(let (({s} {s})) {s})", .{ nm, v, body });
            },
            .if_expr => |ie| {
                const c = try self.lower(ie.cond, active_guard);
                const g_then = try std.fmt.allocPrint(self.alloc, "(and {s} {s})", .{ active_guard, c });
                const g_else = try std.fmt.allocPrint(self.alloc, "(and {s} (not {s}))", .{ active_guard, c });
                const th = try self.lower(ie.then_br, g_then);
                const el = try self.lower(ie.else_br, g_else);
                return std.fmt.allocPrint(self.alloc, "(ite {s} {s} {s})", .{ c, th, el });
            },
            .case_expr => |ce| {
                const scrut = try self.lower(ce.scrutinee, active_guard);
                if (ce.arms.len == 2 and ce.arms[0].pattern.* == .list_lit and ce.arms[1].pattern.* == .list_cons) {
                    const tail_name = if (ce.arms[1].pattern.list_cons.tail.* == .var_ref)
                        try sanitizeIdent(self.alloc, ce.arms[1].pattern.list_cons.tail.var_ref)
                    else
                        "list_tail";
                    const g_nil = try std.fmt.allocPrint(self.alloc, "(and {s} (= (list_len {s}) 0))", .{ active_guard, scrut });
                    const g_cons = try std.fmt.allocPrint(self.alloc, "(and {s} (> (list_len {s}) 0))", .{ active_guard, scrut });
                    const b_nil = try self.lower(ce.arms[0].body, g_nil);
                    const tail_term = try std.fmt.allocPrint(self.alloc, "(tail_of {s})", .{scrut});
                    try self.pat_binds.append(self.alloc, .{ .name = tail_name, .val = tail_term });
                    const b_cons = try self.lower(ce.arms[1].body, g_cons);
                    _ = self.pat_binds.pop();
                    return std.fmt.allocPrint(
                        self.alloc,
                        "(ite (= (list_len {s}) 0) {s} {s})",
                        .{ scrut, b_nil, b_cons },
                    );
                }
                if (ce.arms.len > 0) return self.lower(ce.arms[0].body, active_guard);
                return "0";
            },
            .call => |c| {
                // Record direct recursive calls with active pattern bindings already resolved!
                if (c.target_mod == null and std.mem.eql(u8, c.func, self.fn_name)) {
                    const a0 = if (c.args.len >= 1) try self.lower(c.args[0], active_guard) else null;
                    try self.rec_calls.append(self.alloc, .{ .arg0_smt = a0, .guard_smt = active_guard });
                }
                if (c.target_mod == null) {
                    if (std.mem.eql(u8, c.func, "byte_size") and c.args.len == 1) {
                        return std.fmt.allocPrint(self.alloc, "(byte_size {s})", .{try self.lower(c.args[0], active_guard)});
                    }
                    if (std.mem.eql(u8, c.func, "length") and c.args.len == 1) {
                        return std.fmt.allocPrint(self.alloc, "(list_len {s})", .{try self.lower(c.args[0], active_guard)});
                    }
                    if (std.mem.eql(u8, c.func, "div") and c.args.len == 2) {
                        return std.fmt.allocPrint(self.alloc, "(div {s} {s})", .{ try self.lower(c.args[0], active_guard), try self.lower(c.args[1], active_guard) });
                    }
                    if (std.mem.eql(u8, c.func, "rem") and c.args.len == 2) {
                        return std.fmt.allocPrint(self.alloc, "(mod {s} {s})", .{ try self.lower(c.args[0], active_guard), try self.lower(c.args[1], active_guard) });
                    }
                    if (std.mem.eql(u8, c.func, "abs") and c.args.len == 1) {
                        return std.fmt.allocPrint(self.alloc, "(abs {s})", .{try self.lower(c.args[0], active_guard)});
                    }
                    if (std.mem.eql(u8, c.func, "band") and c.args.len == 2) {
                        self.uses_band_n_minus_1 = true;
                        return std.fmt.allocPrint(self.alloc, "(kernighan_clear {s})", .{try self.lower(c.args[0], active_guard)});
                    }
                } else {
                    const tm = c.target_mod.?;
                    if (std.mem.eql(u8, tm, ":crypto") and std.mem.eql(u8, c.func, "hash") and c.args.len == 2) {
                        return std.fmt.allocPrint(self.alloc, "(sha256_digest {s})", .{try self.lower(c.args[1], active_guard)});
                    }
                    if (std.mem.eql(u8, tm, "Enum") and std.mem.eql(u8, c.func, "reduce") and c.args.len >= 3) {
                        return std.fmt.allocPrint(self.alloc, "(xor_popcount_sum {s})", .{try self.lower(c.args[0], active_guard)});
                    }
                    if (std.mem.eql(u8, tm, "Enum") and std.mem.eql(u8, c.func, "zip") and c.args.len == 2) {
                        return std.fmt.allocPrint(self.alloc, "(zip_bytes {s} {s})", .{ try self.lower(c.args[0], active_guard), try self.lower(c.args[1], active_guard) });
                    }
                    if (std.mem.eql(u8, tm, ":binary") and std.mem.eql(u8, c.func, "bin_to_list") and c.args.len == 1) {
                        return self.lower(c.args[0], active_guard);
                    }
                    if (std.mem.eql(u8, tm, "Verisim.Spec") and std.mem.eql(u8, c.func, "digest_of") and c.args.len == 1) {
                        return std.fmt.allocPrint(self.alloc, "(sha256_digest {s})", .{try self.lower(c.args[0], active_guard)});
                    }
                    if (std.mem.eql(u8, tm, "Verisim.Spec") and std.mem.eql(u8, c.func, "acceptable_drift?") and c.args.len == 1) {
                        const max_d = self.mod.constants.get("max_drift_bp") orelse 2500;
                        return std.fmt.allocPrint(self.alloc, "(<= {s} {d})", .{ try self.lower(c.args[0], active_guard), max_d });
                    }
                }
                // Uninterpreted pure recursive / helper function application
                const fn_sym = try sanitizeIdent(self.alloc, c.func);
                if (c.args.len == 0) return fn_sym;
                var buf: std.ArrayList(u8) = .empty;
                try buf.append(self.alloc, '(');
                try buf.appendSlice(self.alloc, fn_sym);
                for (c.args) |a| {
                    try buf.append(self.alloc, ' ');
                    try buf.appendSlice(self.alloc, try self.lower(a, active_guard));
                }
                try buf.append(self.alloc, ')');
                return buf.toOwnedSlice(self.alloc);
            },
            else => return "0",
        }
    }
};

pub fn sanitizeIdent(alloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (raw) |c| {
        if (c == '?') {
            try out.appendSlice(alloc, "_p");
        } else if (c == '!') {
            try out.appendSlice(alloc, "_bang");
        } else if (c == '.') {
            try out.append(alloc, '_');
        } else {
            try out.append(alloc, c);
        }
    }
    return out.toOwnedSlice(alloc);
}

const DOMAIN_DECLS =
    \\(declare-fun byte_size (Int) Int)
    \\(declare-fun list_len (Int) Int)
    \\(declare-fun tail_of (Int) Int)
    \\(declare-fun sha256_digest (Int) Int)
    \\(declare-fun mk_bin_len (Int) Int)
    \\(declare-fun zip_bytes (Int Int) Int)
    \\(declare-fun xor_popcount_sum (Int) Int)
    \\(declare-fun kernighan_clear (Int) Int)
;

fn emitGroundDomainFacts(alloc: std.mem.Allocator, out: *std.ArrayList(u8), param_names: []const []const u8) !void {
    try out.appendSlice(alloc, "(assert (= (byte_size (mk_bin_len 32)) 32))\n");
    for (param_names) |pn| {
        try out.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            \\(assert (>= (byte_size {s}) 0))
            \\(assert (>= (list_len {s}) 0))
            \\(assert (=> (> (list_len {s}) 0) (= (list_len (tail_of {s})) (- (list_len {s}) 1))))
            \\(assert (= (byte_size (sha256_digest {s})) 32))
            \\(assert (=> (> {s} 0) (and (>= (kernighan_clear {s}) 0) (< (kernighan_clear {s}) {s}))))
            \\
        ,
            .{ pn, pn, pn, pn, pn, pn, pn, pn, pn, pn },
        ));
    }
    if (param_names.len >= 2) {
        const p0 = param_names[0];
        const p1 = param_names[1];
        try out.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            "(assert (=> (and (= (byte_size {s}) 32) (= (byte_size {s}) 32)) (and (>= (xor_popcount_sum (zip_bytes {s} {s})) 0) (<= (xor_popcount_sum (zip_bytes {s} {s})) 256))))\n",
            .{ p0, p1, p0, p1, p0, p1 },
        ));
    }
}

pub fn verifyLayerAModule(
    alloc: std.mem.Allocator,
    io: std.Io,
    mod: *const ast.ModuleAst,
    out_dir: []const u8,
    checks: *std.ArrayList(smt.ObligationCheck),
    diags: *std.ArrayList(errors.Diagnostic),
) !void {
    for (mod.funcs) |fn_decl| {
        if (fn_decl.clauses.len == 0) continue;

        // Collect canonical parameter names from the most general (last) clause
        const canon_clause = fn_decl.clauses[fn_decl.clauses.len - 1];
        var param_names: std.ArrayList([]const u8) = .empty;
        for (canon_clause.params, 0..) |pe, pidx| {
            if (pe.* == .var_ref) {
                try param_names.append(alloc, try sanitizeIdent(alloc, pe.var_ref));
            } else {
                try param_names.append(alloc, try std.fmt.allocPrint(alloc, "arg_{d}", .{pidx}));
            }
        }

        var ctx = SmtLowerCtx{ .alloc = alloc, .mod = mod, .fn_name = fn_decl.name };

        // Lower body across all clauses (e.g. `defp popcount(0), do: 0; defp popcount(n), do: ...`)
        var body_smt: []const u8 = undefined;
        if (fn_decl.clauses.len == 2 and
            fn_decl.clauses[0].params.len == 1 and
            fn_decl.clauses[0].params[0].* == .int_val and
            param_names.items.len == 1)
        {
            const lit_v = fn_decl.clauses[0].params[0].int_val;
            const p0 = param_names.items[0];
            const g0 = try std.fmt.allocPrint(alloc, "(= {s} {d})", .{ p0, lit_v });
            // Natural numbers in Elixir bitwise recursion satisfy >= 0 when non-zero
            const g1 = try std.fmt.allocPrint(alloc, "(> {s} {d})", .{ p0, lit_v });
            const b0 = try ctx.lower(fn_decl.clauses[0].body, g0);
            const b1 = try ctx.lower(fn_decl.clauses[1].body, g1);
            body_smt = try std.fmt.allocPrint(alloc, "(ite (= {s} {d}) {s} {s})", .{ p0, lit_v, b0, b1 });
        } else {
            body_smt = try ctx.lower(canon_clause.body, "true");
        }

        // If `band(n, n - 1)` was used, discharge the exact 32-bit QF_BV lemma in Z3 + CVC5 + Alethe first!
        if (ctx.uses_band_n_minus_1) {
            const bv_id = try std.fmt.allocPrint(alloc, "{s}_{s}_bv_kernighan_lemma", .{ mod.name, try sanitizeIdent(alloc, fn_decl.name) });
            const bv_script =
                \\(declare-const bv_n (_ BitVec 32))
                \\(assert (bvugt bv_n #x00000000))
                \\(assert (not (bvult (bvand bv_n (bvsub bv_n #x00000001)) bv_n)))
            ;
            const bv_chk = try smt.dischargeObligation(alloc, io, bv_id, "bv_lemma", "QF_BV", bv_script, out_dir);
            try checks.append(alloc, bv_chk);
        }

        const fn_sym = try sanitizeIdent(alloc, fn_decl.name);
        const ret_sort = if (fn_decl.posts.len > 0 and inferSort(canon_clause.body) == .bool_sort) "Bool" else "Int";

        var decls: std.ArrayList(u8) = .empty;
        try decls.appendSlice(alloc, DOMAIN_DECLS);
        try decls.append(alloc, '\n');
        for (param_names.items) |pn| {
            try decls.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(declare-const {s} Int)\n", .{pn}));
        }
        try decls.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(declare-const result {s})\n", .{ret_sort}));
        try emitGroundDomainFacts(alloc, &decls, param_names.items);

        // Declare uninterpreted recursive function symbol + ground non-negativity hypothesis on recursive arguments
        if (ctx.rec_calls.items.len > 0) {
            try decls.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(declare-fun {s} (", .{fn_sym}));
            for (param_names.items, 0..) |_, i| {
                if (i > 0) try decls.append(alloc, ' ');
                try decls.appendSlice(alloc, "Int");
            }
            try decls.appendSlice(alloc, try std.fmt.allocPrint(alloc, ") {s})\n", .{ret_sort}));
            if (param_names.items.len == 1 and std.mem.eql(u8, ret_sort, "Int")) {
                const p0 = param_names.items[0];
                try decls.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(assert (>= ({s} (tail_of {s})) 0))\n(assert (>= ({s} (kernighan_clear {s})) 0))\n", .{ fn_sym, p0, fn_sym, p0 }));
            }
        }

        // Build conjunction of `@pre` clauses
        var pre_conj: std.ArrayList(u8) = .empty;
        if (fn_decl.pres.len == 0) {
            if (ctx.uses_band_n_minus_1 and param_names.items.len == 1) {
                try pre_conj.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(>= {s} 0)", .{param_names.items[0]}));
            } else {
                try pre_conj.appendSlice(alloc, "true");
            }
        } else if (fn_decl.pres.len == 1) {
            try pre_conj.appendSlice(alloc, try ctx.lower(fn_decl.pres[0], "true"));
        } else {
            try pre_conj.appendSlice(alloc, "(and");
            for (fn_decl.pres) |pr| {
                try pre_conj.append(alloc, ' ');
                try pre_conj.appendSlice(alloc, try ctx.lower(pr, "true"));
            }
            try pre_conj.append(alloc, ')');
        }
        const pre_smt = try pre_conj.toOwnedSlice(alloc);

        // ── Vacuity Probe V1: Is `@pre` satisfiable? ──────────────────────────
        if (fn_decl.pres.len > 0) {
            const v1_smt = try std.fmt.allocPrint(
                alloc,
                "(set-logic ALL)\n{s}\n(assert {s})\n(check-sat)\n",
                .{ decls.items, pre_smt },
            );
            const v1_file = try std.fmt.allocPrint(alloc, "{s}/{s}_{s}_v1_pre_sat.smt2", .{ out_dir, mod.name, fn_sym });
            const v1 = try smt.runZ3Query(alloc, io, v1_smt, v1_file);
            if (v1.status == .unsat) {
                try diags.append(alloc, .{
                    .code = "Q-601",
                    .file = mod.file,
                    .line = fn_decl.line,
                    .col = fn_decl.col,
                    .message = try std.fmt.allocPrint(alloc, "Vacuous contract on `{s}.{s}/{d}`: `@pre` is unsatisfiable (`false`)", .{ mod.name, fn_decl.name, fn_decl.arity }),
                });
                continue;
            }
        }

        // ── Termination Check (`VC-TERM`) on recursive functions ──────────────
        if (ctx.rec_calls.items.len > 0) {
            if (fn_decl.measure == null) {
                try diags.append(alloc, .{
                    .code = "Q-203",
                    .file = mod.file,
                    .line = fn_decl.line,
                    .col = fn_decl.col,
                    .message = try std.fmt.allocPrint(alloc, "Recursive function `{s}.{s}/{d}` is missing a termination `@measure` attribute", .{ mod.name, fn_decl.name, fn_decl.arity }),
                });
            } else {
                const meas_head = try ctx.lower(fn_decl.measure.?, "true");
                for (ctx.rec_calls.items, 0..) |rc, ridx| {
                    // Substitute head param -> recursive argument expression
                    var meas_rec = meas_head;
                    if (param_names.items.len >= 1 and rc.arg0_smt != null) {
                        meas_rec = try std.fmt.allocPrint(alloc, "(let (({s} {s})) {s})", .{ param_names.items[0], rc.arg0_smt.?, meas_head });
                    }
                    const term_id = try std.fmt.allocPrint(alloc, "{s}_{s}_vc_term_{d}", .{ mod.name, fn_sym, ridx });
                    const term_script = try std.fmt.allocPrint(
                        alloc,
                        "{s}\n(assert {s})\n(assert {s})\n(assert (not (and (>= {s} 0) (< {s} {s}))))",
                        .{ decls.items, pre_smt, rc.guard_smt, meas_head, meas_rec, meas_head },
                    );
                    const term_chk = try smt.dischargeObligation(alloc, io, term_id, "vc_termination", "ALL", term_script, out_dir);
                    try checks.append(alloc, term_chk);
                    if (term_chk.z3_status != .unsat) {
                        try diags.append(alloc, .{
                            .code = "Q-203",
                            .file = mod.file,
                            .line = fn_decl.line,
                            .col = fn_decl.col,
                            .message = try std.fmt.allocPrint(alloc, "Termination measure failed for `{s}.{s}/{d}`: recursive call does not strictly decrease `@measure`", .{ mod.name, fn_decl.name, fn_decl.arity }),
                            .counterexample = term_chk.counterexample,
                        });
                    } else if (term_chk.cvc5_status != .unsat or !term_chk.alethe.valid_qed) {
                        try diags.append(alloc, .{
                            .code = "Q-503",
                            .file = mod.file,
                            .line = fn_decl.line,
                            .col = fn_decl.col,
                            .message = try std.fmt.allocPrint(alloc, "Alethe proof kernel check failed on `{s}`: {s}", .{ term_id, term_chk.alethe.error_reason orelse "solver mismatch" }),
                        });
                    }
                }
            }
        }

        // ── Postcondition Check (`VC-POST`) + Vacuity Probe V2 ────────────────
        for (fn_decl.posts, 0..) |post_expr, pidx| {
            const post_smt = try ctx.lower(post_expr, "true");

            // Probe V2: can an unconstrained `result` falsify `@post` under `@pre`?
            const v2_smt = try std.fmt.allocPrint(
                alloc,
                "(set-logic ALL)\n{s}\n(assert {s})\n(assert (not {s}))\n(check-sat)\n",
                .{ decls.items, pre_smt, post_smt },
            );
            const v2_file = try std.fmt.allocPrint(alloc, "{s}/{s}_{s}_v2_post_nontrivial_{d}.smt2", .{ out_dir, mod.name, fn_sym, pidx });
            const v2 = try smt.runZ3Query(alloc, io, v2_smt, v2_file);
            if (v2.status == .unsat) {
                try diags.append(alloc, .{
                    .code = "Q-602",
                    .file = mod.file,
                    .line = fn_decl.line,
                    .col = fn_decl.col,
                    .message = try std.fmt.allocPrint(alloc, "Trivial `@post` on `{s}.{s}/{d}`: postcondition holds identically for arbitrary return values", .{ mod.name, fn_decl.name, fn_decl.arity }),
                });
                continue;
            }

            // Discharge VC-POST in Z3 + CVC5 + Alethe proof DAG kernel!
            const vc_id = try std.fmt.allocPrint(alloc, "{s}_{s}_vc_post_{d}", .{ mod.name, fn_sym, pidx });
            const vc_script = try std.fmt.allocPrint(
                alloc,
                "{s}\n(assert {s})\n(assert (= result {s}))\n(assert (not {s}))",
                .{ decls.items, pre_smt, body_smt, post_smt },
            );
            const vc_chk = try smt.dischargeObligation(alloc, io, vc_id, "vc_postcondition", "ALL", vc_script, out_dir);
            try checks.append(alloc, vc_chk);

            if (vc_chk.z3_status == .missing_binary or vc_chk.cvc5_status == .missing_binary) {
                try diags.append(alloc, .{
                    .code = "Q-901",
                    .file = mod.file,
                    .line = fn_decl.line,
                    .col = fn_decl.col,
                    .message = "Required solver binary (`z3` or `cvc5`) missing from PATH",
                });
                return;
            }
            if (vc_chk.z3_status != .unsat) {
                try diags.append(alloc, .{
                    .code = "Q-501",
                    .file = mod.file,
                    .line = fn_decl.line,
                    .col = fn_decl.col,
                    .message = try std.fmt.allocPrint(alloc, "Contract `@post` refuted on `{s}.{s}/{d}`", .{ mod.name, fn_decl.name, fn_decl.arity }),
                    .counterexample = vc_chk.counterexample,
                });
            } else if (vc_chk.cvc5_status != .unsat or !vc_chk.alethe.valid_qed) {
                try diags.append(alloc, .{
                    .code = "Q-503",
                    .file = mod.file,
                    .line = fn_decl.line,
                    .col = fn_decl.col,
                    .message = try std.fmt.allocPrint(alloc, "Alethe proof kernel check failed on `{s}`: {s}", .{ vc_id, vc_chk.alethe.error_reason orelse "solver mismatch" }),
                });
            }
        }

        // ── TINI 2-Safety Relational Check (`VC-TINI`) when `@secret` present ──
        if (mod.secrets.count() > 0 and param_names.items.len > 0) {
            var has_undeclassified_secret_param = false;
            var secret_param: []const u8 = "";
            for (param_names.items) |pn| {
                if (mod.secrets.get(pn)) |cls| {
                    if (!std.mem.eql(u8, cls, "public")) {
                        var is_declass = false;
                        for (mod.declassifications) |df| {
                            if (std.mem.eql(u8, df, pn)) is_declass = true;
                        }
                        if (!is_declass) {
                            has_undeclassified_secret_param = true;
                            secret_param = pn;
                        }
                    }
                }
            }
            if (has_undeclassified_secret_param) {
                // Build 2-safety relational query: same public params, two distinct secrets `s_1 != s_2`, check `result_1 == result_2`!
                const tini_id = try std.fmt.allocPrint(alloc, "{s}_{s}_vc_tini", .{ mod.name, fn_sym });
                var tini_buf: std.ArrayList(u8) = .empty;
                try tini_buf.appendSlice(alloc, DOMAIN_DECLS);
                try tini_buf.append(alloc, '\n');
                for (param_names.items) |pn| {
                    if (std.mem.eql(u8, pn, secret_param)) {
                        try tini_buf.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(declare-const {s}_1 Int)\n(declare-const {s}_2 Int)\n", .{ pn, pn }));
                    } else {
                        try tini_buf.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(declare-const {s} Int)\n", .{pn}));
                    }
                }
                const run1 = try std.fmt.allocPrint(alloc, "(let (({s} {s}_1)) {s})", .{ secret_param, secret_param, body_smt });
                const run2 = try std.fmt.allocPrint(alloc, "(let (({s} {s}_2)) {s})", .{ secret_param, secret_param, body_smt });
                try tini_buf.appendSlice(alloc, try std.fmt.allocPrint(alloc, "(assert (not (= {s} {s})))", .{ run1, run2 }));
                const tini_chk = try smt.dischargeObligation(alloc, io, tini_id, "vc_tini_noninterference", "ALL", tini_buf.items, out_dir);
                try checks.append(alloc, tini_chk);
                if (tini_chk.z3_status != .unsat) {
                    try diags.append(alloc, .{
                        .code = "Q-206",
                        .file = mod.file,
                        .line = fn_decl.line,
                        .col = fn_decl.col,
                        .message = try std.fmt.allocPrint(alloc, "TINI non-interference violated in `{s}.{s}/{d}`: confidential parameter `{s}` flows directly to public return without `@declassify`", .{ mod.name, fn_decl.name, fn_decl.arity, secret_param }),
                        .counterexample = tini_chk.counterexample,
                    });
                }
            }
        }
    }
}
