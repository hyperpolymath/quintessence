// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// `quintessence` Native Command-Line Interface.
//
// Commands:
//   quintessence verify [path...] [options]
//   quintessence explain <Q-CODE | --all>
//   quintessence receipt show <receipt.json>
//   quintessence receipt verify <receipt.json> [--binary <lib.so>]
//   quintessence doctor [--format human|json]

const std = @import("std");
const core = @import("quintessence_core");
const errors = core.errors;
const jcs = core.jcs;
const smt = core.smt;

const USAGE =
    \\Quintessence Verification Suite v0.1.0
    \\
    \\Usage:
    \\  quintessence verify [path...] [options]
    \\  quintessence explain <Q-CODE | --all>
    \\  quintessence receipt show <receipt.json>
    \\  quintessence receipt verify <receipt.json> [--binary <lib.so>]
    \\  quintessence doctor [--format human|json]
    \\
    \\Verify options:
    \\  --module <Module>          Verify only the named Elixir module
    \\  --layer <a,b,c>            Comma-separated layer filter (default: a,b,c)
    \\  --strict                   Enable strict release checks
    \\  --require-level-5          Require batch Coq + Lean 4 QEDs (Exit 4 if absent)
    \\  --out-dir <dir>            Artifact output directory (IR, SMT2, Alethe, TLA+, Warrant, Receipt)
    \\  --so-override <path.so>    Verify NIF receipt against an explicit `.so` binary
    \\  --update-receipt           Write canonical JCS NIF receipt after `.so` verification
    \\  --no-mutation              Skip Stage 9 ECHIDNA mutation run
    \\  --mutation-threshold <pct> Required mutation score percentage (default: 95.0)
    \\  --format <human|json|sarif> Output format (default: human)
    \\
    \\Exit codes:
    \\  0  All proof obligations, K-CUT rules, NIF bounds, and mutation gates passed
    \\  1  Verification failure / counterexample / K-CUT / firewall / schedule violation
    \\  2  Usage, CLI, or syntax error
    \\  3  Required toolchain binary missing (`z3`, `cvc5`, `zig`)
    \\  4  Incomplete or untrusted receipt / missing Level-5 batch kernel
    \\  5  Vacuous specification or mutation score below threshold
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const alloc = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(alloc);
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 2 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        try stdout.writeStreamingAll(io, USAGE);
        return 0;
    }
    if (std.mem.eql(u8, args[1], "--version") or std.mem.eql(u8, args[1], "-v")) {
        try stdout.writeStreamingAll(io, "quintessence 0.1.0\n");
        return 0;
    }

    const sub = args[1];

    if (std.mem.eql(u8, sub, "doctor")) {
        var fmt: core.OutputFormat = .human;
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--format") and i + 1 < args.len) {
                i += 1;
                if (std.mem.eql(u8, args[i], "json")) fmt = .json;
            }
        }
        const tc = smt.probeToolchain(alloc, io);
        const ok = tc.z3_version != null and tc.cvc5_version != null and tc.zig_version != null;
        if (fmt == .json) {
            var raw: std.ArrayList(u8) = .empty;
            try raw.appendSlice(alloc, "{\"schema\":\"quintessence.doctor/v1\",\"ready\":");
            try raw.appendSlice(alloc, if (ok) "true" else "false");
            try raw.appendSlice(alloc, try std.fmt.allocPrint(alloc, ",\"max_local_trust_level\":{d},\"tools\":{{\"z3\":", .{if (tc.coq_version != null and tc.lean_version != null) @as(u8, 5) else @as(u8, 4)}));
            if (tc.z3_version) |v| try jcs.writeString(alloc, &raw, v) else try raw.appendSlice(alloc, "null");
            try raw.appendSlice(alloc, ",\"cvc5\":");
            if (tc.cvc5_version) |v| try jcs.writeString(alloc, &raw, v) else try raw.appendSlice(alloc, "null");
            try raw.appendSlice(alloc, ",\"zig\":");
            if (tc.zig_version) |v| try jcs.writeString(alloc, &raw, v) else try raw.appendSlice(alloc, "null");
            try raw.appendSlice(alloc, ",\"coqc\":");
            if (tc.coq_version) |v| try jcs.writeString(alloc, &raw, v) else try raw.appendSlice(alloc, "null");
            try raw.appendSlice(alloc, ",\"lean4\":");
            if (tc.lean_version) |v| try jcs.writeString(alloc, &raw, v) else try raw.appendSlice(alloc, "null");
            try raw.appendSlice(alloc, "}}");
            const canon = try jcs.canonicalizeJsonText(alloc, raw.items);
            try stdout.writeStreamingAll(io, canon);
        } else {
            const msg = try std.fmt.allocPrint(
                alloc,
                \\Quintessence Toolchain Doctor
                \\------------------------------------------------------------
                \\  [REQUIRED] z3            : {s}
                \\  [REQUIRED] cvc5 (Alethe) : {s}
                \\  [REQUIRED] zig           : {s}
                \\  [REQUIRED] alethe-kernel : built-in 0.1.0
                \\  [OPTIONAL] coqc (Level5) : {s}
                \\  [OPTIONAL] lean (Level5) : {s}
                \\  [OPTIONAL] idris2        : {s}
                \\  [OPTIONAL] apalache-mc   : {s}
                \\------------------------------------------------------------
                \\Status: {s} (maximum achievable local trust level: Level {d})
                \\
            ,
                .{
                    tc.z3_version orelse "MISSING",
                    tc.cvc5_version orelse "MISSING",
                    tc.zig_version orelse "MISSING",
                    tc.coq_version orelse "not installed (batch Level-5 check deferred; `.v` emitted)",
                    tc.lean_version orelse "not installed (batch Level-5 check deferred; `.lean` emitted)",
                    tc.idris2_version orelse "not installed (`qir/v1` serialized natively)",
                    tc.apalache_version orelse "not installed (`k = 12` BMC discharged via Z3+CVC5; `.tla` emitted)",
                    if (ok) "READY" else "INCOMPLETE (missing required tool)",
                    if (tc.coq_version != null and tc.lean_version != null) @as(u8, 5) else @as(u8, 4),
                },
            );
            try stdout.writeStreamingAll(io, msg);
        }
        return if (ok) 0 else @backingInt(errors.ExitCode.toolchain_missing);
    }

    if (std.mem.eql(u8, sub, "explain")) {
        if (args.len < 3) {
            try stderr.writeStreamingAll(io, "Usage: quintessence explain <Q-CODE | --all>\n");
            return @backingInt(errors.ExitCode.usage_or_syntax);
        }
        if (std.mem.eql(u8, args[2], "--all")) {
            for (errors.CATALOGUE) |sp| {
                const line = try std.fmt.allocPrint(alloc, "{s}  [{s}, exit {d}]  {s}\n", .{ sp.code, sp.layer.label(), @backingInt(sp.exit_code), sp.name });
                try stdout.writeStreamingAll(io, line);
            }
            return 0;
        }
        const sp = errors.lookup(args[2]) orelse {
            const msg = try std.fmt.allocPrint(alloc, "Unknown error code: {s}\n", .{args[2]});
            try stderr.writeStreamingAll(io, msg);
            return @backingInt(errors.ExitCode.usage_or_syntax);
        };
        const detail = try std.fmt.allocPrint(
            alloc,
            \\{s} — {s}
            \\  Layer     : {s}
            \\  Exit code : {d}
            \\  Rule      : {s}
            \\  Falsifier : {s}
            \\  Remedy    : {s}
            \\
        ,
            .{ sp.code, sp.name, sp.layer.label(), @backingInt(sp.exit_code), sp.rule, sp.falsifier, sp.remedy },
        );
        try stdout.writeStreamingAll(io, detail);
        return 0;
    }

    if (std.mem.eql(u8, sub, "receipt")) {
        if (args.len < 4) {
            try stderr.writeStreamingAll(io, "Usage: quintessence receipt <show|verify> <receipt.json> [--binary <lib.so>]\n");
            return @backingInt(errors.ExitCode.usage_or_syntax);
        }
        const action = args[2];
        const rpath = args[3];
        const rbytes = std.Io.Dir.cwd().readFileAlloc(io, rpath, alloc, .unlimited) catch {
            try stderr.writeStreamingAll(io, "ERROR [Q-301]: Receipt file not found\n");
            return @backingInt(errors.ExitCode.incomplete_evidence);
        };
        const canon = jcs.canonicalizeJsonText(alloc, rbytes) catch {
            try stderr.writeStreamingAll(io, "ERROR [Q-902]: Receipt is not valid I-JSON\n");
            return @backingInt(errors.ExitCode.usage_or_syntax);
        };
        if (std.mem.eql(u8, action, "show")) {
            const rsha = jcs.sha256Hex(canon);
            const hdr = try std.fmt.allocPrint(alloc, "Receipt JCS SHA-256: {s}\n{s}", .{ &rsha, canon });
            try stdout.writeStreamingAll(io, hdr);
            return 0;
        }
        if (std.mem.eql(u8, action, "verify")) {
            var bin_path: ?[]const u8 = null;
            var k: usize = 4;
            while (k < args.len) : (k += 1) {
                if (std.mem.eql(u8, args[k], "--binary") and k + 1 < args.len) {
                    bin_path = args[k + 1];
                    k += 1;
                }
            }
            const parsed = try std.json.parseFromSlice(std.json.Value, alloc, canon, .{});
            if (bin_path) |bp| {
                const bbytes = std.Io.Dir.cwd().readFileAlloc(io, bp, alloc, .unlimited) catch {
                    try stderr.writeStreamingAll(io, "ERROR [Q-303]: Binary shared object missing\n");
                    return @backingInt(errors.ExitCode.incomplete_evidence);
                };
                const actual_sha = jcs.sha256Hex(bbytes);
                const expected_sha = parsed.value.object.get("subject").?.object.get("binary_sha256").?.string;
                if (!std.mem.eql(u8, expected_sha, &actual_sha)) {
                    const m = try std.fmt.allocPrint(alloc, "ERROR [Q-303]: NIF binary SHA-256 mismatch (receipt={s}, actual={s})\n", .{ expected_sha, &actual_sha });
                    try stderr.writeStreamingAll(io, m);
                    return @backingInt(errors.ExitCode.incomplete_evidence);
                }
            }
            try stdout.writeStreamingAll(io, "OK: Receipt valid (RFC 8785 JCS verified)\n");
            return 0;
        }
        return @backingInt(errors.ExitCode.usage_or_syntax);
    }

    if (std.mem.eql(u8, sub, "verify")) {
        var paths: std.ArrayList([]const u8) = .empty;
        var opts = core.VerifyOptions{ .paths = &.{} };

        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (std.mem.eql(u8, a, "--module") and i + 1 < args.len) {
                i += 1;
                opts.module_filter = args[i];
            } else if (std.mem.eql(u8, a, "--layer") and i + 1 < args.len) {
                i += 1;
                const spec = args[i];
                opts.enable_a = std.mem.indexOfScalar(u8, spec, 'a') != null;
                opts.enable_b = std.mem.indexOfScalar(u8, spec, 'b') != null;
                opts.enable_c = std.mem.indexOfScalar(u8, spec, 'c') != null;
            } else if (std.mem.eql(u8, a, "--strict")) {
                opts.strict = true;
            } else if (std.mem.eql(u8, a, "--require-level-5")) {
                opts.require_level_5 = true;
            } else if (std.mem.eql(u8, a, "--out-dir") and i + 1 < args.len) {
                i += 1;
                opts.out_dir = args[i];
            } else if (std.mem.eql(u8, a, "--so-override") and i + 1 < args.len) {
                i += 1;
                opts.precompiled_so_override = args[i];
            } else if (std.mem.eql(u8, a, "--update-receipt")) {
                opts.update_nif_receipt = true;
            } else if (std.mem.eql(u8, a, "--no-mutation")) {
                opts.run_mutation = false;
            } else if (std.mem.eql(u8, a, "--mutation-threshold") and i + 1 < args.len) {
                i += 1;
                opts.mutation_threshold = std.fmt.parseFloat(f64, args[i]) catch 95.0;
            } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
                i += 1;
                if (std.mem.eql(u8, args[i], "json")) {
                    opts.format = .json;
                } else if (std.mem.eql(u8, args[i], "sarif")) {
                    opts.format = .sarif;
                } else {
                    opts.format = .human;
                }
            } else if (std.mem.startsWith(u8, a, "--")) {
                const msg = try std.fmt.allocPrint(alloc, "Unknown flag: {s}\n", .{a});
                try stderr.writeStreamingAll(io, msg);
                return @backingInt(errors.ExitCode.usage_or_syntax);
            } else {
                try paths.append(alloc, a);
            }
        }
        if (paths.items.len == 0) {
            try paths.append(alloc, "examples/quintessence");
        }
        opts.paths = try paths.toOwnedSlice(alloc);

        const summary = try core.runVerify(alloc, io, opts);
        try stdout.writeStreamingAll(io, summary.output_text);
        return @backingInt(summary.exit_code);
    }

    const msg = try std.fmt.allocPrint(alloc, "Unknown subcommand: {s}\n\n{s}", .{ sub, USAGE });
    try stderr.writeStreamingAll(io, msg);
    return @backingInt(errors.ExitCode.usage_or_syntax);
}
