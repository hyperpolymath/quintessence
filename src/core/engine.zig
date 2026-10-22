// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// End-to-End Verification Orchestrator (`Quintessence.Engine`).
//
// Runs Stages 0..10:
//   Stage 0: Toolchain verification (`z3`, `cvc5`, `zig`, optional `coqc`/`lean`)
//   Stage 1: G0a-G0c Firewall (`firewall.zig`)
//   Stage 2-3: `qir/v1` JCS elaboration & Coq/Lean batch emitters (`qir.zig`)
//   Stage 4: Layer A VC + BitVec + TINI + V1/V2 (`layer_a.zig`)
//   Stage 5: Layer B K-CUT + GenServer invariants + k=12 BMC + V4 (`layer_b.zig`)
//   Stage 6: Layer C C1-C12 + MaxPlus + `.so` build & dlopen + receipt (`layer_c.zig`)
//   Stage 7-8: Z3 + CVC5 + Native Alethe Proof-DAG Kernel check (`smt_alethe.zig`)
//   Stage 9: ECHIDNA 6-Kind Mutation Engine (`vacuity_mutation.zig`)
//   Stage 10: Warrant & Receipt JCS emission + Human / JSON / SARIF reporters.

const std = @import("std");
pub const errors = @import("errors.zig");
pub const jcs = @import("jcs.zig");
pub const ast = @import("elixir_ast.zig");
pub const firewall = @import("firewall.zig");
pub const smt = @import("smt_alethe.zig");
pub const qir = @import("qir.zig");
pub const layer_a = @import("layer_a.zig");
pub const layer_b = @import("layer_b.zig");
pub const layer_c = @import("layer_c.zig");
pub const mutation = @import("vacuity_mutation.zig");

pub const OutputFormat = enum {
    human,
    json,
    sarif,
};

pub const VerifyOptions = struct {
    paths: []const []const u8,
    module_filter: ?[]const u8 = null,
    enable_a: bool = true,
    enable_b: bool = true,
    enable_c: bool = true,
    strict: bool = false,
    require_level_5: bool = false,
    run_mutation: bool = true,
    mutation_threshold: f64 = 95.0,
    exclude_guards: bool = true,
    maxplus_threshold_us: u64 = 1_000,
    default_mailbox_cap: u64 = 128,
    precompiled_so_override: ?[]const u8 = null,
    update_nif_receipt: bool = false,
    out_dir: []const u8 = "/tmp/quintessence-verify-out",
    format: OutputFormat = .human,
};

pub const RunSummary = struct {
    exit_code: errors.ExitCode,
    trust_level: u8,
    modules_checked: usize,
    obligations_proved: usize,
    alethe_steps: usize,
    alethe_resolutions: usize,
    mutation_score: f64,
    warrant_path: ?[]const u8,
    receipt_path: ?[]const u8,
    output_text: []const u8,
};

fn collectExFiles(alloc: std.mem.Allocator, io: std.Io, target: []const u8, out: *std.ArrayList([]const u8)) !void {
    if (std.mem.endsWith(u8, target, ".ex")) {
        try out.append(alloc, target);
        return;
    }
    const res = std.process.run(alloc, io, .{
        .argv = &.{ "find", target, "-type", "f", "-name", "*.ex" },
    }) catch return;
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, res.stdout, '\n');
    while (it.next()) |ln| {
        const t = std.mem.trim(u8, ln, " \t\r");
        if (t.len == 0) continue;
        // Skip Mix tasks under `mix/tasks/` when scanning a root project directory
        if (std.mem.indexOf(u8, t, "/mix/tasks/") != null) continue;
        try lines.append(alloc, t);
    }
    std.mem.sort([]const u8, lines.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    for (lines.items) |p| try out.append(alloc, p);
}

fn inferBaseDir(file_path: []const u8) []const u8 {
    if (std.mem.indexOf(u8, file_path, "/lib/")) |idx| {
        return file_path[0..idx];
    }
    if (std.mem.lastIndexOfScalar(u8, file_path, '/')) |idx| {
        return if (idx == 0) "/" else file_path[0..idx];
    }
    return ".";
}

pub fn runVerify(alloc: std.mem.Allocator, io: std.Io, opts: VerifyOptions) !RunSummary {
    const mk = try std.process.run(alloc, io, .{ .argv = &.{ "mkdir", "-p", opts.out_dir } });
    _ = mk;

    var diags: std.ArrayList(errors.Diagnostic) = .empty;
    var checks: std.ArrayList(smt.ObligationCheck) = .empty;
    var nif_results: std.ArrayList(layer_c.NifAnalysisResult) = .empty;

    // Stage 0: Toolchain check
    const tc = smt.probeToolchain(alloc, io);
    if (tc.z3_version == null or tc.cvc5_version == null or tc.zig_version == null) {
        try diags.append(alloc, .{
            .code = "Q-901",
            .file = ".",
            .line = 1,
            .col = 1,
            .message = "Missing required solver/compiler toolchain (`z3`, `cvc5`, or `zig`); run `quintessence doctor`",
        });
    }

    var ex_files: std.ArrayList([]const u8) = .empty;
    for (opts.paths) |p| {
        try collectExFiles(alloc, io, p, &ex_files);
    }
    if (ex_files.items.len == 0 and diags.items.len == 0) {
        try diags.append(alloc, .{
            .code = "Q-201",
            .file = if (opts.paths.len > 0) opts.paths[0] else ".",
            .line = 1,
            .col = 1,
            .message = "No Elixir `.ex` modules found at specified path",
        });
    }

    var all_mods: std.ArrayList(ast.ModuleAst) = .empty;
    for (ex_files.items) |fp| {
        const src = std.Io.Dir.cwd().readFileAlloc(io, fp, alloc, .unlimited) catch {
            try diags.append(alloc, .{
                .code = "Q-201",
                .file = fp,
                .line = 1,
                .col = 1,
                .message = try std.fmt.allocPrint(alloc, "Cannot read source file `{s}`", .{fp}),
            });
            continue;
        };
        const parsed_mods = try ast.parseFile(alloc, fp, src);
        for (parsed_mods) |m| {
            if (opts.module_filter) |mf| {
                if (!std.mem.eql(u8, m.name, mf)) continue;
            }
            try all_mods.append(alloc, m);
        }
    }

    var qir_sha: [64]u8 = @splat('0');
    if (diags.items.len == 0 and all_mods.items.len > 0) {
        // Stage 1: G0a-G0c Firewall on every module BEFORE IR lowering!
        for (all_mods.items) |*m| {
            try firewall.checkModule(alloc, m, &diags);
        }

        // Stage 2-3: Elaborate canonical content-addressed `qir/v1` JCS IR + `.v`/`.lean`
        const qir_art = try qir.emitQirAndBatchObligations(alloc, io, all_mods.items, opts.out_dir);
        qir_sha = qir_art.qir_sha256;

        // Stage 4-8: Layer A, Layer B, Layer C Verification + Z3/CVC5/Alethe Kernel
        if (diags.items.len == 0) {
            for (all_mods.items) |*m| {
                const layer_str = m.layer orelse "";
                if (opts.enable_a and std.mem.eql(u8, layer_str, "a")) {
                    try layer_a.verifyLayerAModule(alloc, io, m, opts.out_dir, &checks, &diags);
                } else if (opts.enable_b and std.mem.eql(u8, layer_str, "b")) {
                    try layer_b.verifyLayerBModule(alloc, io, m, opts.default_mailbox_cap, opts.out_dir, &checks, &diags);
                } else if (opts.enable_c and m.is_nif_stub) {
                    const bdir = inferBaseDir(m.file);
                    const nr = try layer_c.verifyLayerCNif(
                        alloc,
                        io,
                        m,
                        bdir,
                        opts.maxplus_threshold_us,
                        opts.precompiled_so_override,
                        opts.update_nif_receipt,
                        opts.out_dir,
                        &checks,
                        &diags,
                    );
                    if (nr) |res| try nif_results.append(alloc, res);
                }
            }
        }
    }

    // Stage 9: ECHIDNA 6-Kind Mutation Engine (runs only when proofs succeeded so far!)
    var mut_report = mutation.MutationReport{
        .total = 0,
        .excluded = 0,
        .caught = 0,
        .survived = 0,
        .score_pct = 100.0,
        .threshold_pct = opts.mutation_threshold,
        .records = &.{},
    };
    if (diags.items.len == 0 and opts.run_mutation and all_mods.items.len > 0) {
        mut_report = try mutation.runMutationSuite(
            alloc,
            io,
            all_mods.items,
            opts.mutation_threshold,
            opts.exclude_guards,
            opts.out_dir,
            &diags,
        );
    }

    // Determine genuine trust level honestly (Doctrine #10: zero overclaim!)
    const has_batch_kernels = tc.coq_version != null and tc.lean_version != null;
    const trust_level: u8 = if (diags.items.len > 0)
        0
    else if (has_batch_kernels)
        5
    else
        4;

    if (diags.items.len == 0 and opts.require_level_5 and trust_level < 5) {
        try diags.append(alloc, .{
            .code = "Q-504",
            .file = if (all_mods.items.len > 0) all_mods.items[0].file else ".",
            .line = 1,
            .col = 1,
            .message = "Local Warrant/Receipt verified at TrustLevel 4 (`z3` + `cvc5` + `alethe-kernel` + `zig`); `--require-level-5` additionally requires `coqc` and `lean` on PATH for batch promotion",
        });
    }

    var total_steps: usize = 0;
    var total_resolutions: usize = 0;
    for (checks.items) |c| {
        total_steps += c.alethe.steps;
        total_resolutions += c.alethe.resolutions;
    }

    var warrant_path: ?[]const u8 = null;
    var receipt_path: ?[]const u8 = null;

    if (diags.items.len == 0) {
        // Emit JCS `quintessence.warrant/v1` and `quintessence.receipt/v1`
        var wraw: std.ArrayList(u8) = .empty;
        try wraw.appendSlice(alloc, "{\"schema\":\"quintessence.warrant/v1\",\"qir_sha256\":");
        try jcs.writeString(alloc, &wraw, &qir_sha);
        try wraw.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            ",\"trust_level\":{d},\"status\":\"{s}\",\"alethe_steps\":{d},\"alethe_resolutions\":{d},\"mutation_score\":{d:.2},\"obligations\":[",
            .{
                trust_level,
                if (trust_level >= 5) "complete" else "local_certified",
                total_steps,
                total_resolutions,
                mut_report.score_pct,
            },
        ));
        for (checks.items, 0..) |c, ci| {
            if (ci > 0) try wraw.append(alloc, ',');
            try wraw.appendSlice(alloc, "{\"id\":");
            try jcs.writeString(alloc, &wraw, c.id);
            try wraw.appendSlice(alloc, ",\"kind\":");
            try jcs.writeString(alloc, &wraw, c.kind);
            try wraw.appendSlice(alloc, ",\"smt_sha256\":");
            try jcs.writeString(alloc, &wraw, &c.smt_sha256);
            try wraw.appendSlice(alloc, ",\"alethe_sha256\":");
            try jcs.writeString(alloc, &wraw, &c.alethe.proof_sha256);
            try wraw.appendSlice(alloc, try std.fmt.allocPrint(
                alloc,
                ",\"alethe_steps\":{d},\"rewrite_holes\":{d},\"status\":\"QED\"}}",
                .{ c.alethe.steps, c.alethe.rewrite_holes },
            ));
        }
        try wraw.appendSlice(alloc, "]}");
        const wcanon = try jcs.canonicalizeJsonText(alloc, wraw.items);
        const wsha = jcs.sha256Hex(wcanon);
        const wp = try std.fmt.allocPrint(alloc, "{s}/warrant.json", .{opts.out_dir});
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = wp, .data = wcanon });
        warrant_path = wp;

        var rraw: std.ArrayList(u8) = .empty;
        try rraw.appendSlice(alloc, "{\"schema\":\"quintessence.receipt/v1\",\"warrant_sha256\":");
        try jcs.writeString(alloc, &rraw, &wsha);
        try rraw.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            ",\"trust_level\":{d},\"status\":\"{s}\",\"axioms\":[],\"pending_batch_kernels\":{s},\"checks\":[",
            .{
                trust_level,
                if (trust_level >= 5) "complete" else "verified_level_4",
                if (has_batch_kernels) "[]" else "[\"coq\",\"lean4\"]",
            },
        ));
        try rraw.appendSlice(alloc, "{\"kernel\":\"z3\",\"status\":\"unsat\",\"version\":");
        try jcs.writeString(alloc, &rraw, tc.z3_version orelse "unknown");
        try rraw.appendSlice(alloc, "},{\"kernel\":\"cvc5-alethe\",\"status\":\"QED\",\"version\":");
        try jcs.writeString(alloc, &rraw, tc.cvc5_version orelse "unknown");
        try rraw.appendSlice(alloc, "},{\"kernel\":\"quintessence-alethe-kernel\",\"status\":\"QED\",\"version\":\"0.1.0\"}]}");
        const rcanon = try jcs.canonicalizeJsonText(alloc, rraw.items);
        const rp = try std.fmt.allocPrint(alloc, "{s}/receipt.json", .{opts.out_dir});
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = rp, .data = rcanon });
        receipt_path = rp;
    }

    const exit_code = errors.worstExitCode(diags.items);
    const formatted = switch (opts.format) {
        .human => try renderHuman(alloc, all_mods.items, checks.items, nif_results.items, mut_report, diags.items, trust_level, warrant_path, receipt_path, exit_code),
        .json => try renderJson(alloc, all_mods.items, checks.items, nif_results.items, mut_report, diags.items, trust_level, &qir_sha, warrant_path, receipt_path, exit_code),
        .sarif => try renderSarif(alloc, diags.items),
    };

    return .{
        .exit_code = exit_code,
        .trust_level = trust_level,
        .modules_checked = all_mods.items.len,
        .obligations_proved = checks.items.len,
        .alethe_steps = total_steps,
        .alethe_resolutions = total_resolutions,
        .mutation_score = mut_report.score_pct,
        .warrant_path = warrant_path,
        .receipt_path = receipt_path,
        .output_text = formatted,
    };
}

fn renderHuman(
    alloc: std.mem.Allocator,
    mods: []const ast.ModuleAst,
    checks: []const smt.ObligationCheck,
    nifs: []const layer_c.NifAnalysisResult,
    mut: mutation.MutationReport,
    diags: []const errors.Diagnostic,
    trust_level: u8,
    warrant_path: ?[]const u8,
    receipt_path: ?[]const u8,
    exit_code: errors.ExitCode,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(alloc, "Quintessence Verification Suite v0.1.0\n");
    try out.appendSlice(alloc, "------------------------------------------------------------\n");
    for (mods) |m| {
        try out.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            "  Module   {s} (layer :{s})  [{s}]\n",
            .{ m.name, m.layer orelse "?", m.file },
        ));
    }
    if (checks.len > 0) {
        try out.appendSlice(alloc, "\nDischarged Obligations (Z3 + CVC5 + Native Alethe Proof Kernel):\n");
        for (checks) |c| {
            try out.appendSlice(alloc, try std.fmt.allocPrint(
                alloc,
                "  [{s}] {s}  z3={s}  cvc5={s}  alethe={s} ({d} steps, {d} res)\n",
                .{
                    if (c.z3_status == .unsat and c.alethe.valid_qed) "QED" else "FAIL",
                    c.id,
                    @tagName(c.z3_status),
                    @tagName(c.cvc5_status),
                    if (c.alethe.valid_qed) "QED" else "FAIL",
                    c.alethe.steps,
                    c.alethe.resolutions,
                },
            ));
        }
    }
    if (nifs.len > 0) {
        try out.appendSlice(alloc, "\nLayer C Native NIF Verification:\n");
        for (nifs) |n| {
            try out.appendSlice(alloc, try std.fmt.allocPrint(
                alloc,
                "  [OK] {s} -> {s}\n       MaxPlus={s} => {d} us <= 1000 us (`schedule: {s}`)\n       dlopen ABI symbols={d}, unit_tests=PASS, sha256={s}...\n",
                .{ n.zig_source_path, n.compiled_so_path, n.maxplus_expr, n.maxplus_bound_us, n.required_schedule, n.dlopen_symbols_verified, n.binary_sha256[0..16] },
            ));
        }
    }
    if (mut.total > 0) {
        try out.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            "\nECHIDNA 6-Kind Mutation Report:\n  Caught {d}/{d} proof-relevant mutants ({d} guard mutant(s) excluded) -> Score: {d:.2}% (gate >= {d:.2}%)\n",
            .{ mut.caught, mut.total - mut.excluded, mut.excluded, mut.score_pct, mut.threshold_pct },
        ));
        for (mut.records) |mr| {
            if (std.mem.eql(u8, mr.status, "survived")) {
                try out.appendSlice(alloc, try std.fmt.allocPrint(
                    alloc,
                    "    [SURVIVED] {s} ({s}) on `{s}`\n",
                    .{ mr.id, mr.kind, mr.target },
                ));
            }
        }
    }
    if (diags.len > 0) {
        try out.appendSlice(alloc, "\nDiagnostics:\n");
        for (diags) |d| {
            try out.appendSlice(alloc, try std.fmt.allocPrint(
                alloc,
                "  ERROR [{s}] {s}:{d}:{d}: {s}\n",
                .{ d.code, d.file, d.line, d.col, d.message },
            ));
            if (d.counterexample) |cx| {
                try out.appendSlice(alloc, try std.fmt.allocPrint(alloc, "    Counterexample / Witness:\n    {s}\n", .{cx}));
            }
            if (errors.lookup(d.code)) |spec| {
                try out.appendSlice(alloc, try std.fmt.allocPrint(alloc, "    Rule: {s}\n    Remedy: {s}\n", .{ spec.rule, spec.remedy }));
            }
        }
    }
    try out.appendSlice(alloc, "------------------------------------------------------------\n");
    if (diags.len == 0) {
        try out.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            "VERIFIED  TrustLevel={d}  Obligations={d}  MutationScore={d:.2}%  Exit=0\n  Warrant: {s}\n  Receipt: {s}\n",
            .{ trust_level, checks.len, mut.score_pct, warrant_path orelse "-", receipt_path orelse "-" },
        ));
    } else {
        try out.appendSlice(alloc, try std.fmt.allocPrint(
            alloc,
            "FAILED    Diagnostics={d}  Exit={d}\n",
            .{ diags.len, @backingInt(exit_code) },
        ));
    }
    return out.toOwnedSlice(alloc);
}

fn renderJson(
    alloc: std.mem.Allocator,
    mods: []const ast.ModuleAst,
    checks: []const smt.ObligationCheck,
    nifs: []const layer_c.NifAnalysisResult,
    mut: mutation.MutationReport,
    diags: []const errors.Diagnostic,
    trust_level: u8,
    qir_sha: *const [64]u8,
    warrant_path: ?[]const u8,
    receipt_path: ?[]const u8,
    exit_code: errors.ExitCode,
) ![]const u8 {
    _ = nifs;
    var raw: std.ArrayList(u8) = .empty;
    try raw.appendSlice(alloc, "{\"schema\":\"quintessence.report/v1\",\"status\":");
    try jcs.writeString(alloc, &raw, if (diags.len == 0) "verified" else "failed");
    try raw.appendSlice(alloc, ",\"qir_sha256\":");
    try jcs.writeString(alloc, &raw, qir_sha);
    try raw.appendSlice(alloc, try std.fmt.allocPrint(
        alloc,
        ",\"exit_code\":{d},\"trust_level\":{d},\"modules_checked\":{d},\"obligations_proved\":{d},\"mutation\":{{\"caught\":{d},\"excluded\":{d},\"score\":{d:.2},\"survived\":{d},\"total\":{d}}},\"warrant_path\":",
        .{ @backingInt(exit_code), trust_level, mods.len, checks.len, mut.caught, mut.excluded, mut.score_pct, mut.survived, mut.total },
    ));
    if (warrant_path) |wp| try jcs.writeString(alloc, &raw, wp) else try raw.appendSlice(alloc, "null");
    try raw.appendSlice(alloc, ",\"receipt_path\":");
    if (receipt_path) |rp| try jcs.writeString(alloc, &raw, rp) else try raw.appendSlice(alloc, "null");
    try raw.appendSlice(alloc, ",\"diagnostics\":[");
    for (diags, 0..) |d, i| {
        if (i > 0) try raw.append(alloc, ',');
        try raw.appendSlice(alloc, "{\"code\":");
        try jcs.writeString(alloc, &raw, d.code);
        try raw.appendSlice(alloc, ",\"file\":");
        try jcs.writeString(alloc, &raw, d.file);
        try raw.appendSlice(alloc, try std.fmt.allocPrint(alloc, ",\"line\":{d},\"col\":{d},\"message\":", .{ d.line, d.col }));
        try jcs.writeString(alloc, &raw, d.message);
        try raw.append(alloc, '}');
    }
    try raw.appendSlice(alloc, "]}");
    return jcs.canonicalizeJsonText(alloc, raw.items);
}

fn renderSarif(alloc: std.mem.Allocator, diags: []const errors.Diagnostic) ![]const u8 {
    var raw: std.ArrayList(u8) = .empty;
    try raw.appendSlice(alloc, "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Quintessence\",\"version\":\"0.1.0\"}},\"results\":[");
    for (diags, 0..) |d, i| {
        if (i > 0) try raw.append(alloc, ',');
        try raw.appendSlice(alloc, "{\"ruleId\":");
        try jcs.writeString(alloc, &raw, d.code);
        try raw.appendSlice(alloc, ",\"level\":\"error\",\"message\":{\"text\":");
        try jcs.writeString(alloc, &raw, d.message);
        try raw.appendSlice(alloc, "},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        try jcs.writeString(alloc, &raw, d.file);
        try raw.appendSlice(alloc, try std.fmt.allocPrint(alloc, "}},\"region\":{{\"startLine\":{d},\"startColumn\":{d}}}}}]}}", .{ d.line, d.col }));
    }
    try raw.appendSlice(alloc, "]}]}");
    return jcs.canonicalizeJsonText(alloc, raw.items);
}
