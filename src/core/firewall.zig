// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Stage 1: Deterministic Macro & Purity Firewall (G0a-G0c + MPR R5).
//
// Enforces:
//   * Q-101: Dynamic code evaluation (`Code.eval_*`, `:erl_eval`)
//   * Q-102: Dynamic call dispatch (`apply/3`, `Kernel.apply/3`, non-literal target)
//   * Q-103: Ambient side effects inside Layer A (`Process.*`, `:ets.*`, `IO.*`,
//            `File.*`, `System.cmd`, `:os.cmd`, `Port.open`, `:persistent_term.*`)
//   * Q-105: Unverified `:erlang.load_nif/2` outside `use Quintessence.Nif`
//   * Q-108: Process messaging (`send`, `receive`, `spawn`, `GenServer.cast/call`)
//            inside a sequential Layer A module
//   * Q-206: MPR R5 capability composition exfiltration corridor (`:fs_read` +
//            `:net_send` without explicit `@declassify`)

const std = @import("std");
const ast = @import("elixir_ast.zig");
const errors = @import("errors.zig");

const IMPURE_MODS = [_][]const u8{
    "Process",
    "File",
    "IO",
    "Port",
    "System",
    "Agent",
    "Task",
    ":ets",
    ":persistent_term",
    ":os",
    ":inet",
    ":gen_tcp",
    ":gen_udp",
    ":httpc",
};

fn isEvalCall(mod_opt: ?[]const u8, func: []const u8) bool {
    if (mod_opt) |m| {
        if (std.mem.eql(u8, m, "Code") and std.mem.startsWith(u8, func, "eval_")) return true;
        if (std.mem.eql(u8, m, ":erl_eval")) return true;
    }
    return false;
}

fn isDynamicApply(mod_opt: ?[]const u8, func: []const u8, arity: usize) bool {
    if (!std.mem.eql(u8, func, "apply")) return false;
    if (mod_opt == null or std.mem.eql(u8, mod_opt.?, "Kernel") or std.mem.eql(u8, mod_opt.?, ":erlang")) {
        return arity == 2 or arity == 3;
    }
    return false;
}

fn isImpureMod(m: []const u8) bool {
    for (IMPURE_MODS) |im| {
        if (std.mem.eql(u8, m, im)) return true;
    }
    return false;
}

fn walkExpr(
    alloc: std.mem.Allocator,
    mod: *const ast.ModuleAst,
    e: *const ast.Expr,
    diags: *std.ArrayList(errors.Diagnostic),
) !void {
    const is_layer_a = if (mod.layer) |l| std.mem.eql(u8, l, "a") else false;

    switch (e.*) {
        .call => |c| {
            if (isEvalCall(c.target_mod, c.func)) {
                try diags.append(alloc, .{
                    .code = "Q-101",
                    .file = mod.file,
                    .line = c.line,
                    .col = c.col,
                    .message = try std.fmt.allocPrint(alloc, "Dynamic evaluation `{s}.{s}/{d}` violates firewall rule G0a", .{ c.target_mod orelse "", c.func, c.args.len }),
                });
            } else if (isDynamicApply(c.target_mod, c.func, c.args.len)) {
                try diags.append(alloc, .{
                    .code = "Q-102",
                    .file = mod.file,
                    .line = c.line,
                    .col = c.col,
                    .message = try std.fmt.allocPrint(alloc, "Dynamic dispatch `{s}/{d}` destroys call-graph closure (rule G0c)", .{ c.func, c.args.len }),
                });
            } else if (c.target_mod != null and std.mem.eql(u8, c.target_mod.?, "dynamic")) {
                try diags.append(alloc, .{
                    .code = "Q-102",
                    .file = mod.file,
                    .line = c.line,
                    .col = c.col,
                    .message = "Computed module dispatch breaks static call-graph closure (rule G0c)",
                });
            } else if (c.target_mod != null and std.mem.eql(u8, c.target_mod.?, ":erlang") and std.mem.eql(u8, c.func, "load_nif") and !mod.is_nif_stub) {
                try diags.append(alloc, .{
                    .code = "Q-105",
                    .file = mod.file,
                    .line = c.line,
                    .col = c.col,
                    .message = "Raw `:erlang.load_nif/2` outside `use Quintessence.Nif` bypasses Layer C receipt verification",
                });
            } else if (is_layer_a) {
                if (c.target_mod == null and (std.mem.eql(u8, c.func, "send") or std.mem.eql(u8, c.func, "spawn") or std.mem.eql(u8, c.func, "spawn_link"))) {
                    try diags.append(alloc, .{
                        .code = "Q-108",
                        .file = mod.file,
                        .line = c.line,
                        .col = c.col,
                        .message = try std.fmt.allocPrint(alloc, "Process primitive `{s}/{d}` forbidden in sequential Layer A module `{s}`", .{ c.func, c.args.len, mod.name }),
                    });
                } else if (c.target_mod != null and std.mem.eql(u8, c.target_mod.?, "GenServer")) {
                    try diags.append(alloc, .{
                        .code = "Q-108",
                        .file = mod.file,
                        .line = c.line,
                        .col = c.col,
                        .message = try std.fmt.allocPrint(alloc, "`GenServer.{s}` belongs to Layer B, not pure sequential Layer A module `{s}`", .{ c.func, mod.name }),
                    });
                } else if (c.target_mod != null and isImpureMod(c.target_mod.?)) {
                    try diags.append(alloc, .{
                        .code = "Q-103",
                        .file = mod.file,
                        .line = c.line,
                        .col = c.col,
                        .message = try std.fmt.allocPrint(alloc, "Impure primitive `{s}.{s}/{d}` forbidden inside pure Layer A module `{s}`", .{ c.target_mod.?, c.func, c.args.len, mod.name }),
                    });
                }
            }
            for (c.args) |a| try walkExpr(alloc, mod, a, diags);
        },
        .receive_expr => |r| {
            if (is_layer_a) {
                try diags.append(alloc, .{
                    .code = "Q-108",
                    .file = mod.file,
                    .line = r.line,
                    .col = r.col,
                    .message = "`receive` block forbidden in sequential Layer A module; move protocol handling to Layer B",
                });
            } else if (!r.has_catch_all) {
                // Selective receive with no catch-all clause risks unbounded mailbox growth unless bounded
                if (mod.mailbox_capacity == null) {
                    try diags.append(alloc, .{
                        .code = "Q-402",
                        .file = mod.file,
                        .line = r.line,
                        .col = r.col,
                        .message = "Selective `receive` lacks a catch-all clause and certified `@mailbox_capacity` bound",
                    });
                }
            }
            for (r.arms) |arm| {
                if (arm.guard) |g| try walkExpr(alloc, mod, g, diags);
                try walkExpr(alloc, mod, arm.body, diags);
            }
        },
        .field_access => |fa| try walkExpr(alloc, mod, fa.base, diags),
        .unary_not => |u| try walkExpr(alloc, mod, u, diags),
        .unary_neg => |u| try walkExpr(alloc, mod, u, diags),
        .bin_op => |b| {
            try walkExpr(alloc, mod, b.lhs, diags);
            try walkExpr(alloc, mod, b.rhs, diags);
        },
        .tuple => |xs| for (xs) |x| try walkExpr(alloc, mod, x, diags),
        .list_lit => |xs| for (xs) |x| try walkExpr(alloc, mod, x, diags),
        .list_cons => |lc| {
            try walkExpr(alloc, mod, lc.head, diags);
            try walkExpr(alloc, mod, lc.tail, diags);
        },
        .kv_pair => |kv| try walkExpr(alloc, mod, kv.val, diags),
        .map_lit => |xs| for (xs) |x| try walkExpr(alloc, mod, x, diags),
        .map_update => |mu| {
            try walkExpr(alloc, mod, mu.base, diags);
            for (mu.updates) |u| try walkExpr(alloc, mod, u, diags);
        },
        .let_bind => |lb| {
            try walkExpr(alloc, mod, lb.val, diags);
            try walkExpr(alloc, mod, lb.body, diags);
        },
        .if_expr => |ie| {
            try walkExpr(alloc, mod, ie.cond, diags);
            try walkExpr(alloc, mod, ie.then_br, diags);
            try walkExpr(alloc, mod, ie.else_br, diags);
        },
        .case_expr => |ce| {
            try walkExpr(alloc, mod, ce.scrutinee, diags);
            for (ce.arms) |arm| {
                if (arm.guard) |g| try walkExpr(alloc, mod, g, diags);
                try walkExpr(alloc, mod, arm.body, diags);
            }
        },
        .fn_anon => |fa| try walkExpr(alloc, mod, fa.body, diags),
        else => {},
    }
}

pub fn checkModule(
    alloc: std.mem.Allocator,
    mod: *const ast.ModuleAst,
    diags: *std.ArrayList(errors.Diagnostic),
) !void {
    // Check MPR R5 capability composition: `:fs_read` + `:net_send` without `@declassify`
    var has_fs_read = false;
    var has_net_send = false;
    for (mod.caps) |cap| {
        if (std.mem.eql(u8, cap, "fs_read") or std.mem.eql(u8, cap, "fs")) has_fs_read = true;
        if (std.mem.eql(u8, cap, "net_send") or std.mem.eql(u8, cap, "net")) has_net_send = true;
    }
    if (has_fs_read and has_net_send and mod.declassifications.len == 0) {
        try diags.append(alloc, .{
            .code = "Q-206",
            .file = mod.file,
            .line = 1,
            .col = 1,
            .message = try std.fmt.allocPrint(alloc, "Capability composition violation in `{s}` (MPR Rule R5): `:fs_read` composed with `:net_send` opens an un-declassified exfiltration corridor", .{mod.name}),
        });
    }

    for (mod.funcs) |fn_decl| {
        for (fn_decl.clauses) |cl| {
            if (cl.guard) |g| try walkExpr(alloc, mod, g, diags);
            try walkExpr(alloc, mod, cl.body, diags);
        }
    }
}
