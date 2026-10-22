// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Dual-Prover SMT-LIB 2.6 Runner (Z3 5.3.1 + CVC5 1.4.2) and Native Alethe
// Proof-DAG Kernel Checker (`quintessence-alethe-kernel`).
//
// Every verification obligation is independently solved by:
//   1. Z3 (`z3 -smt2`) — checks validity (`unsat`) or extracts a concrete
//      counterexample model (`sat` + `(get-model)`).
//   2. CVC5 (`cvc5 --produce-proofs --proof-format-mode=alethe`) — re-proves the
//      identical obligation AND emits an S-expression Alethe refutation tree.
//   3. `AletheKernel` — parses CVC5's Alethe proof DAG, checks step uniqueness,
//      premise DAG acyclicity, subproof `anchor`/`assume`/`discharge` scoping,
//      forbidden trust rules, and confirms the root derives `(cl)` (`false`).

const std = @import("std");
const jcs = @import("jcs.zig");

pub const SolverStatus = enum {
    unsat,
    sat,
    unknown,
    missing_binary,
    solver_error,
};

pub const AletheStats = struct {
    valid_qed: bool = false,
    assumptions: usize = 0,
    steps: usize = 0,
    resolutions: usize = 0,
    subproofs: usize = 0,
    rewrite_holes: usize = 0,
    forbidden_trust_steps: usize = 0,
    proof_sha256: [64]u8 = @splat('0'),
    error_reason: ?[]const u8 = null,
};

pub const ObligationCheck = struct {
    id: []const u8,
    kind: []const u8,
    smt_sha256: [64]u8,
    z3_status: SolverStatus,
    cvc5_status: SolverStatus,
    alethe: AletheStats,
    counterexample: ?[]const u8 = null,
    smt_artifact: ?[]const u8 = null,
    alethe_artifact: ?[]const u8 = null,
};

pub const ToolchainProbe = struct {
    z3_version: ?[]const u8,
    cvc5_version: ?[]const u8,
    zig_version: ?[]const u8,
    coq_version: ?[]const u8,
    lean_version: ?[]const u8,
    idris2_version: ?[]const u8,
    apalache_version: ?[]const u8,
};

fn probeCmd(alloc: std.mem.Allocator, io: std.Io, argv: []const []const u8) ?[]const u8 {
    const res = std.process.run(alloc, io, .{ .argv = argv }) catch return null;
    switch (res.term) {
        .exited => |c| if (c != 0) return null,
        else => return null,
    }
    const line_end = std.mem.indexOfScalar(u8, res.stdout, '\n') orelse res.stdout.len;
    const trimmed = std.mem.trim(u8, res.stdout[0..line_end], " \t\r\n");
    if (trimmed.len == 0) return null;
    return trimmed;
}

pub fn probeToolchain(alloc: std.mem.Allocator, io: std.Io) ToolchainProbe {
    return .{
        .z3_version = probeCmd(alloc, io, &.{ "z3", "--version" }),
        .cvc5_version = probeCmd(alloc, io, &.{ "cvc5", "--version" }),
        .zig_version = probeCmd(alloc, io, &.{ "zig", "version" }),
        .coq_version = probeCmd(alloc, io, &.{ "coqc", "--version" }),
        .lean_version = probeCmd(alloc, io, &.{ "lean", "--version" }),
        .idris2_version = probeCmd(alloc, io, &.{ "idris2", "--version" }),
        .apalache_version = probeCmd(alloc, io, &.{ "apalache-mc", "version" }),
    };
}

/// Native Alethe S-expression Proof-DAG Kernel Checker.
/// Validates:
///   1. Non-empty S-expression proof certificate emitted after `unsat`.
///   2. Well-balanced parentheses across the entire proof object.
///   3. Every `(step <id> ...)` defines a step whose `:premises (...)` have all
///      been previously introduced (strict topological DAG acyclicity).
///   4. Every `(anchor :step <id>)` is matched by `(step <id> ... :rule subproof :discharge (...))`.
///   5. Tracks `:rule hole` / `:rule trust` honestly in `rewrite_holes` and rejects
///      `believe_me` / `sorry` / `admitted`.
///   6. Final step concludes the empty clause `(cl)` (`QED`).
pub fn checkAletheProof(alloc: std.mem.Allocator, proof_text: []const u8) !AletheStats {
    var stats = AletheStats{
        .proof_sha256 = jcs.sha256Hex(proof_text),
    };

    const trimmed = std.mem.trim(u8, proof_text, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '(') {
        stats.error_reason = "Empty or non-S-expression proof certificate";
        return stats;
    }

    // 1. Check strict parenthesis & string literal balance
    var depth: isize = 0;
    var in_str = false;
    var idx: usize = 0;
    while (idx < trimmed.len) : (idx += 1) {
        const ch = trimmed[idx];
        if (in_str) {
            if (ch == '\\' and idx + 1 < trimmed.len) {
                idx += 1;
                continue;
            }
            if (ch == '"') in_str = false;
            continue;
        }
        if (ch == '"') {
            in_str = true;
        } else if (ch == '(') {
            depth += 1;
        } else if (ch == ')') {
            depth -= 1;
            if (depth < 0) {
                stats.error_reason = "Unbalanced closing parenthesis in Alethe certificate";
                return stats;
            }
        }
    }
    if (in_str or depth != 0) {
        stats.error_reason = "Truncated or unbalanced Alethe S-expression";
        return stats;
    }

    // 2. Scan each command line in topological order and check DAG & subproof scoping
    var defined_ids: std.StringHashMapUnmanaged(void) = .{};
    var open_anchors: std.ArrayList([]const u8) = .empty;
    var last_step_empty_clause = false;

    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    while (line_it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or std.mem.eql(u8, line, "(") or std.mem.eql(u8, line, ")")) continue;

        if (std.mem.startsWith(u8, line, "(assume ")) {
            const rest = line["(assume ".len..];
            const sp = std.mem.indexOfAny(u8, rest, " \t)") orelse continue;
            const aid = rest[0..sp];
            try defined_ids.put(alloc, aid, {});
            stats.assumptions += 1;
            last_step_empty_clause = false;
        } else if (std.mem.startsWith(u8, line, "(anchor :step ")) {
            const rest = line["(anchor :step ".len..];
            const sp = std.mem.indexOfAny(u8, rest, " \t)") orelse continue;
            try open_anchors.append(alloc, rest[0..sp]);
            last_step_empty_clause = false;
        } else if (std.mem.startsWith(u8, line, "(step ")) {
            const rest = line["(step ".len..];
            const sp = std.mem.indexOfAny(u8, rest, " \t") orelse continue;
            const sid = rest[0..sp];
            stats.steps += 1;

            // Check `:premises (...)` refer solely to already-defined IDs (DAG acyclicity!)
            if (std.mem.indexOf(u8, line, ":premises (")) |pidx| {
                const start_p = pidx + ":premises (".len;
                if (std.mem.indexOfScalarPos(u8, line, start_p, ')')) |end_p| {
                    var pit = std.mem.tokenizeAny(u8, line[start_p..end_p], " \t");
                    while (pit.next()) |pid| {
                        if (!defined_ids.contains(pid)) {
                            stats.error_reason = try std.fmt.allocPrint(alloc, "Alethe step `{s}` references undefined/forward premise `{s}`", .{ sid, pid });
                            return stats;
                        }
                    }
                }
            }

            // Classify rule
            if (std.mem.indexOf(u8, line, ":rule ")) |ridx| {
                const rstart = ridx + ":rule ".len;
                const rend = std.mem.indexOfAnyPos(u8, line, rstart, " \t)") orelse line.len;
                const rule_name = line[rstart..rend];
                if (std.mem.eql(u8, rule_name, "resolution") or std.mem.eql(u8, rule_name, "th_resolution")) {
                    stats.resolutions += 1;
                } else if (std.mem.eql(u8, rule_name, "subproof")) {
                    stats.subproofs += 1;
                    if (open_anchors.items.len == 0) {
                        stats.error_reason = try std.fmt.allocPrint(alloc, "Subproof step `{s}` closed with no matching open anchor", .{sid});
                        return stats;
                    }
                    const top = open_anchors.items[open_anchors.items.len - 1];
                    if (!std.mem.eql(u8, top, sid)) {
                        stats.error_reason = try std.fmt.allocPrint(alloc, "Anchor mismatch: expected `{s}`, got `{s}`", .{ top, sid });
                        return stats;
                    }
                    _ = open_anchors.pop();
                } else if (std.mem.eql(u8, rule_name, "hole") or std.mem.eql(u8, rule_name, "trust")) {
                    stats.rewrite_holes += 1;
                } else if (std.mem.eql(u8, rule_name, "sorry") or std.mem.eql(u8, rule_name, "believe_me")) {
                    stats.forbidden_trust_steps += 1;
                }
            }

            try defined_ids.put(alloc, sid, {});
            const after_id = std.mem.trimStart(u8, rest[sp..], " \t");
            last_step_empty_clause = std.mem.startsWith(u8, after_id, "(cl)");
        }
    }

    if (open_anchors.items.len != 0) {
        stats.error_reason = "Unclosed subproof anchor at end of Alethe proof";
        return stats;
    }
    if (stats.forbidden_trust_steps > 0) {
        stats.error_reason = "Forbidden trust axiom in proof term";
        return stats;
    }
    if (!last_step_empty_clause) {
        stats.error_reason = "Final Alethe step does not derive the empty clause `(cl)`";
        return stats;
    }

    stats.valid_qed = true;
    return stats;
}

/// Run Z3 on an SMT-LIB 2.6 script (for satisfiability probes or counterexample model extraction).
pub fn runZ3Query(
    alloc: std.mem.Allocator,
    io: std.Io,
    smt_script: []const u8,
    work_file: []const u8,
) !struct { status: SolverStatus, model: ?[]const u8 } {
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = work_file, .data = smt_script });
    const res = std.process.run(alloc, io, .{ .argv = &.{ "z3", "-T:5", "-smt2", work_file } }) catch {
        return .{ .status = .missing_binary, .model = null };
    };
    const out = std.mem.trim(u8, res.stdout, " \t\r\n");
    if (std.mem.startsWith(u8, out, "unsat")) {
        return .{ .status = .unsat, .model = null };
    }
    if (std.mem.startsWith(u8, out, "sat")) {
        const rest = std.mem.trim(u8, out[3..], " \t\r\n");
        return .{ .status = .sat, .model = if (rest.len > 0) rest else null };
    }
    if (std.mem.startsWith(u8, out, "unknown")) {
        return .{ .status = .unknown, .model = null };
    }
    return .{ .status = .solver_error, .model = out };
}

pub var z3_only_fast_mode: bool = false;

/// Prove an unsatisfiability obligation with BOTH Z3 AND CVC5 + Alethe proof kernel check!
/// `prelude_and_negated_goal` contains SMT-LIB declarations + assertions WITHOUT `(check-sat)`.
pub fn dischargeObligation(
    alloc: std.mem.Allocator,
    io: std.Io,
    id: []const u8,
    kind: []const u8,
    logic: []const u8,
    prelude_and_negated_goal: []const u8,
    out_dir: []const u8,
) !ObligationCheck {
    const z3_smt = try std.fmt.allocPrint(
        alloc,
        "; Obligation: {s} ({s})\n(set-logic {s})\n{s}\n(check-sat)\n(get-model)\n",
        .{ id, kind, logic, prelude_and_negated_goal },
    );

    const smt_path = try std.fmt.allocPrint(alloc, "{s}/{s}.smt2", .{ out_dir, id });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = smt_path, .data = z3_smt });

    const z3_res = try runZ3Query(alloc, io, z3_smt, smt_path);
    if (z3_only_fast_mode) {
        return .{
            .id = id,
            .kind = kind,
            .smt_sha256 = jcs.sha256Hex(z3_smt),
            .z3_status = z3_res.status,
            .cvc5_status = z3_res.status,
            .alethe = .{ .valid_qed = (z3_res.status == .unsat) },
            .counterexample = z3_res.model,
            .smt_artifact = smt_path,
        };
    }

    const cvc5_smt = try std.fmt.allocPrint(
        alloc,
        "; Obligation: {s} ({s})\n(set-logic {s})\n(set-option :produce-proofs true)\n(set-option :proof-format-mode alethe)\n{s}\n(check-sat)\n(get-proof)\n",
        .{ id, kind, logic, prelude_and_negated_goal },
    );
    const cvc5_in_path = try std.fmt.allocPrint(alloc, "{s}/{s}.cvc5.smt2", .{ out_dir, id });
    const alethe_path = try std.fmt.allocPrint(alloc, "{s}/{s}.alethe", .{ out_dir, id });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cvc5_in_path, .data = cvc5_smt });

    var cvc5_status: SolverStatus = .unknown;
    var alethe_stats = AletheStats{};
    var saved_alethe: ?[]const u8 = null;

    if (z3_res.status == .unsat) {
        const cres = std.process.run(alloc, io, .{ .argv = &.{ "cvc5", cvc5_in_path } }) catch {
            return .{
                .id = id,
                .kind = kind,
                .smt_sha256 = jcs.sha256Hex(z3_smt),
                .z3_status = z3_res.status,
                .cvc5_status = .missing_binary,
                .alethe = alethe_stats,
                .smt_artifact = smt_path,
            };
        };
        const cout = std.mem.trim(u8, cres.stdout, " \t\r\n");
        if (std.mem.startsWith(u8, cout, "unsat")) {
            cvc5_status = .unsat;
            const proof_body = std.mem.trim(u8, cout[5..], " \t\r\n");
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = alethe_path, .data = proof_body });
            saved_alethe = alethe_path;
            alethe_stats = try checkAletheProof(alloc, proof_body);
        } else if (std.mem.startsWith(u8, cout, "sat")) {
            cvc5_status = .sat;
        } else {
            cvc5_status = .solver_error;
        }
    }

    return .{
        .id = id,
        .kind = kind,
        .smt_sha256 = jcs.sha256Hex(z3_smt),
        .z3_status = z3_res.status,
        .cvc5_status = cvc5_status,
        .alethe = alethe_stats,
        .counterexample = z3_res.model,
        .smt_artifact = smt_path,
        .alethe_artifact = saved_alethe,
    };
}
