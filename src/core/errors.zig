// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Canonical Quintessence error catalogue (Q-1xx..Q-9xx), deterministic exit
// codes (0..5), formal rule citations, falsifier descriptions, and remedies.

const std = @import("std");

pub const ExitCode = enum(u8) {
    ok = 0,
    verification_failed = 1,
    usage_or_syntax = 2,
    toolchain_missing = 3,
    incomplete_evidence = 4,
    vacuity_or_mutation = 5,
};

pub const Layer = enum {
    firewall,
    layer_a,
    layer_b,
    layer_c,
    evidence,
    vacuity,
    infra,

    pub fn label(self: Layer) []const u8 {
        return switch (self) {
            .firewall => "firewall",
            .layer_a => "layer_a",
            .layer_b => "layer_b",
            .layer_c => "layer_c",
            .evidence => "evidence",
            .vacuity => "vacuity",
            .infra => "infra",
        };
    }
};

pub const ErrorSpec = struct {
    code: []const u8,
    name: []const u8,
    layer: Layer,
    exit_code: ExitCode,
    rule: []const u8,
    falsifier: []const u8,
    remedy: []const u8,
};

pub const CATALOGUE = [_]ErrorSpec{
    // Q-1xx: Stage 1 G0a-G0c deterministic macro & purity firewall
    .{
        .code = "Q-101",
        .name = "DYNAMIC_EVAL_FORBIDDEN",
        .layer = .firewall,
        .exit_code = .verification_failed,
        .rule = "G0a (Dynamic Evaluation Ban)",
        .falsifier = "Runtime code evaluation (`Code.eval_string`, `Code.eval_quoted`, `Code.eval_file`, `:erl_eval`) introduces arbitrary unverified AST outside the Core Spec IR.",
        .remedy = "Replace runtime evaluation with static pattern matching, compile-time data tables, or an allowlisted deterministic macro.",
    },
    .{
        .code = "Q-102",
        .name = "DYNAMIC_APPLY_FORBIDDEN",
        .layer = .firewall,
        .exit_code = .verification_failed,
        .rule = "G0c (Closed Call-Graph Invariant)",
        .falsifier = "Dynamic `apply/3` or variable module dispatch destroys call-graph closure, allowing an unverified target to bypass contracts and capability grades.",
        .remedy = "Dispatch through an explicit closed `case` match over known module atoms or verified protocol implementations.",
    },
    .{
        .code = "Q-103",
        .name = "IMPURE_PRIMITIVE_IN_PURE_SUBSET",
        .layer = .firewall,
        .exit_code = .verification_failed,
        .rule = "G0c / Layer-A Purity",
        .falsifier = "Ambient side effects (`Process.put/get`, `:ets`, `:persistent_term`, `File.*`, `IO.*`, `System.cmd`, `Port.open`) violate referential transparency in Layer A.",
        .remedy = "Keep Layer A modules strictly pure and move effectful coordination to a Layer B `Quintessence.Face` boundary with explicit `@cap` declarations.",
    },
    .{
        .code = "Q-105",
        .name = "UNVERIFIED_NIF_LOAD",
        .layer = .firewall,
        .exit_code = .verification_failed,
        .rule = "G0c / Layer-C Boundary Seal",
        .falsifier = "Direct `:erlang.load_nif/2` without `use Quintessence.Nif` loads native machine code with no ABI proof, no binary SHA-256 check, and no `MaxPlus` slice bound.",
        .remedy = "Declare the stub with `use Quintessence.Nif, abi: ..., receipt: ...` so `@on_load` verifies the receipt and compiled `.so` hash before loading.",
    },
    .{
        .code = "Q-108",
        .name = "CONCURRENCY_IN_SEQUENTIAL_LAYER",
        .layer = .firewall,
        .exit_code = .verification_failed,
        .rule = "Layer-A / Layer-B Separation",
        .falsifier = "Process primitives (`send`, `receive`, `spawn`, `GenServer.cast`, `GenServer.call`) inside a Layer A module bypass mailbox occupancy and K-CUT epistemic checks.",
        .remedy = "Move message-passing logic into a `use Quintessence.Face, layer: :b` module with `@choreography` and pure state transitions in Layer A.",
    },

    // Q-2xx: Layer A subset, refinement, termination, and information-flow checks
    .{
        .code = "Q-201",
        .name = "UNSUPPORTED_ELIXIR_SYNTAX",
        .layer = .layer_a,
        .exit_code = .usage_or_syntax,
        .rule = "Layer-A Grammar",
        .falsifier = "Construct lies outside the decidable sequential Elixir subset.",
        .remedy = "Rewrite using total pattern matching, pure `case`/`if` expressions, immutable structs/maps, lists, binaries, and explicit `@measure` recursion.",
    },
    .{
        .code = "Q-202",
        .name = "CONTRACT_TYPE_ERROR",
        .layer = .layer_a,
        .exit_code = .verification_failed,
        .rule = "Face Elaboration",
        .falsifier = "A `@pre`, `@post`, `@invariant`, or `@measure` specification references an unbound identifier or ill-typed operator.",
        .remedy = "Ensure contract predicates reference only function parameters, `result` (in `@post`), module constants, and pure total functions.",
    },
    .{
        .code = "Q-203",
        .name = "MISSING_OR_NON_DECREASING_MEASURE",
        .layer = .layer_a,
        .exit_code = .verification_failed,
        .rule = "Total Recursion Rule (`VC-TERM`)",
        .falsifier = "A recursive function without a strictly decreasing, non-negative `@measure` can diverge, collapsing partial-correctness implications and starving BEAM reductions.",
        .remedy = "Annotate every recursive `def` with `@measure spec(...)` over a named head parameter and prove `0 <= m(args') < m(args)` on every recursive call.",
    },
    .{
        .code = "Q-206",
        .name = "SECRET_LEAK_OR_EXFILTRATION_CORRIDOR",
        .layer = .layer_a,
        .exit_code = .verification_failed,
        .rule = "TINI Non-Interference / MPR R5 Composition",
        .falsifier = "Secret-classified data flows to a low-security output without `@declassify`, or capabilities compose `:fs_read` with `:net_send` to form an exfiltration corridor.",
        .remedy = "Remove secret dependence from public return values, split `:fs_read` and `:net_send` across distinct capability boundaries, or add an explicit audited `@declassify`.",
    },
    .{
        .code = "Q-207",
        .name = "UNSUPPORTED_IR_PROJECTION",
        .layer = .layer_a,
        .exit_code = .verification_failed,
        .rule = "qir/v1 -> SMT Projection",
        .falsifier = "Goal uses an operator outside the certified `qir/v1` SMT-LIB 2.6 decidable projection fragment.",
        .remedy = "Refactor into linear integer arithmetic, algebraic constructors, fixed byte sizes, or discharge via an explicit lemma.",
    },

    // Q-3xx: Layer C Idris2 QTT ABI, Zig core, receipt, and MaxPlus slice budget
    .{
        .code = "Q-301",
        .name = "MISSING_NIF_RECEIPT",
        .layer = .layer_c,
        .exit_code = .incomplete_evidence,
        .rule = "Layer-C Receipt Gate",
        .falsifier = "NIF stub has no readable `quintessence.nif.receipt/v1` file or required proof obligation C1-C12 is missing.",
        .remedy = "Build and verify the NIF through `quintessence verify` to produce a complete signed JCS receipt.",
    },
    .{
        .code = "Q-302",
        .name = "NIF_SAFETY_OR_BUDGET_VIOLATION",
        .layer = .layer_c,
        .exit_code = .verification_failed,
        .rule = "Layer-C C1-C12 / MaxPlus Bound",
        .falsifier = "Zig NIF core violates allocation/pointer safety obligations (C1-C12), lacks a static loop bound (`+inf`), or exceeds its declared `@budget`.",
        .remedy = "Eliminate heap allocation, `@cImport`, inline `asm`, mutable globals, and unbounded loops; guard nullable handles/pointers with `orelse return`.",
    },
    .{
        .code = "Q-303",
        .name = "NIF_BINARY_HASH_MISMATCH",
        .layer = .layer_c,
        .exit_code = .incomplete_evidence,
        .rule = "Layer-C Load-Time Integrity",
        .falsifier = "SHA-256 digest of the compiled `.so` shared object does not match `binary_sha256` recorded in the verified NIF receipt.",
        .remedy = "Re-verify and regenerate the NIF receipt from the exact compiled shared library artifact.",
    },
    .{
        .code = "Q-304",
        .name = "NIF_ABI_MISMATCH",
        .layer = .layer_c,
        .exit_code = .verification_failed,
        .rule = "Idris2 QTT C-ABI Conformance",
        .falsifier = "Compiled shared library is missing a required C-ABI export symbol or rejects conformance smoke vectors (such as linear non-null handle enforcement).",
        .remedy = "Export exact `callconv(.c)` functions matching the Idris2 ABI specification and `@nif` declarations.",
    },
    .{
        .code = "Q-305",
        .name = "NIF_SCHEDULE_MISMATCH",
        .layer = .layer_c,
        .exit_code = .verification_failed,
        .rule = "MaxPlus BEAM Scheduler Slice Law (<= 1,000 us)",
        .falsifier = "NIF's `MaxPlus` worst-case execution time bound exceeds the 1,000 us BEAM scheduler timeslice while scheduled on a normal scheduler thread, blocking preemption.",
        .remedy = "Tighten the loop bound so `MaxPlus <= 1_000 us` or explicitly mark `@nif ..., schedule: :dirty_cpu`.",
    },

    // Q-4xx: Layer B K-CUT choreographic protocol, mailbox HWM, and epoch rules
    .{
        .code = "Q-401",
        .name = "UNWARRANTED_REMOTE_COMMIT_CLAIM",
        .layer = .layer_b,
        .exit_code = .verification_failed,
        .rule = "K-SEND / K-CAST / K-REPLY (`choreographic-types` Y-6 & Y-8)",
        .falsifier = "Sender claims knowledge of remote receipt or state commitment across asynchronous `cast`/`send` (or without an authenticated, post-commit, epoch-matching causal reply); a single dropped or stale message invalidates the claim.",
        .remedy = "Replace `cast`/`send` with synchronous `call -> commit -> reply` carrying correlation tag, monotonic version, and matching epoch under `K-REPLY`.",
    },
    .{
        .code = "Q-402",
        .name = "UNBOUNDED_MAILBOX_OCCUPANCY",
        .layer = .layer_b,
        .exit_code = .verification_failed,
        .rule = "Occupancy High-Water-Mark (`MailboxBound`)",
        .falsifier = "Selective `receive` or unthrottled asynchronous ingress allows mailbox occupancy to exceed the certified `HWM` capacity bound.",
        .remedy = "Handle all message shapes without unbounded selective skipping, bound in-flight requests via call backpressure, or raise certified capacity with matching memory proof.",
    },
    .{
        .code = "Q-403",
        .name = "CHOREOGRAPHY_OUTSIDE_PROVED_FRAGMENT",
        .layer = .layer_b,
        .exit_code = .verification_failed,
        .rule = "Binary-Choice Causal Reply Fragment (`choreographic-types` Y-8)",
        .falsifier = "Multi-party transitive knowledge chain (`A -> B -> C`) is not yet proved in general Agda metatheory and cannot silently inherit `K-REPLY` soundness.",
        .remedy = "Decompose into pairwise two-party request/reply cuts with explicit local commits, or mark the hop explicitly as `:assumed`.",
    },
    .{
        .code = "Q-404",
        .name = "EPOCH_ROLLBACK_HAZARD",
        .layer = .layer_b,
        .exit_code = .verification_failed,
        .rule = "Supervision Epoch Monotonicity (`EpochConsistent`)",
        .falsifier = "After supervisor restart (`epoch' = epoch + 1`), a stale pre-crash reply is accepted as evidence of state in the new incarnation.",
        .remedy = "Bind every request/reply correlation token to `(epoch, version)` and reject messages whose epoch differs from the active monitor epoch.",
    },

    // Q-5xx: Prover refutation, forbidden axioms, and kernel certificate checks
    .{
        .code = "Q-501",
        .name = "PROVER_REFUTATION",
        .layer = .evidence,
        .exit_code = .verification_failed,
        .rule = "Soundness of Verification Conditions",
        .falsifier = "SMT solver produced a concrete counterexample input satisfying `@pre` and violating `@post` or `@invariant`.",
        .remedy = "Fix the implementation bug exposed by the counterexample model or strengthen `@pre` to exclude invalid inputs.",
    },
    .{
        .code = "Q-502",
        .name = "FORBIDDEN_AXIOM_DETECTED",
        .layer = .evidence,
        .exit_code = .incomplete_evidence,
        .rule = "ECHIDNA Axiom Hygiene",
        .falsifier = "Proof term or source relies on a forbidden axiom (`believe_me`, `assert_total`, `sorry`, `Admitted`, `propext`, `classical_choice`).",
        .remedy = "Remove unsound postulates/axioms and construct a total proof.",
    },
    .{
        .code = "Q-503",
        .name = "PROOF_KERNEL_MISMATCH",
        .layer = .evidence,
        .exit_code = .incomplete_evidence,
        .rule = "Alethe / Multi-Solver Cross-Check",
        .falsifier = "Independent solvers disagreed or the emitted Alethe proof certificate failed DAG / premise / empty-clause `(cl)` kernel checking.",
        .remedy = "Inspect emitted `.smt2` and `.alethe` artifacts in the verification output directory.",
    },
    .{
        .code = "Q-504",
        .name = "INCOMPLETE_EVIDENCE_FOR_POLICY",
        .layer = .evidence,
        .exit_code = .incomplete_evidence,
        .rule = "Trust-Level Gate",
        .falsifier = "Verification reached local Warrant/Receipt TrustLevel 4, whereas `--require-level-5` requires external batch Coq + Lean 4 kernel QEDs.",
        .remedy = "Run ECHIDNA batch verification with `coqc` and `lean` installed to promote the Warrant + emitted `.v`/`.lean` obligations to Level 5.",
    },

    // Q-6xx: Vacuity probes (V1-V4), mutation score, and bounded counterexamples
    .{
        .code = "Q-601",
        .name = "VACUOUS_PRECONDITION",
        .layer = .vacuity,
        .exit_code = .vacuity_or_mutation,
        .rule = "Vacuity Probe V1 (Antecedent Satisfiability)",
        .falsifier = "Precondition `@pre` is unsatisfiable (`false`), making `@pre => @post` vacuously true for zero inputs.",
        .remedy = "Repair contradictory constraints in `@pre` so at least one valid input exists.",
    },
    .{
        .code = "Q-602",
        .name = "TRIVIAL_POSTCONDITION",
        .layer = .vacuity,
        .exit_code = .vacuity_or_mutation,
        .rule = "Vacuity Probe V2 (Postcondition Non-Triviality)",
        .falsifier = "Postcondition `@post` holds for arbitrary unconstrained `result` under `@pre` (e.g. `result == result`), constraining nothing.",
        .remedy = "Strengthen `@post` so an erroneous return value falsifies it.",
    },
    .{
        .code = "Q-603",
        .name = "WEAK_SPEC_MUTATION_SURVIVED",
        .layer = .vacuity,
        .exit_code = .vacuity_or_mutation,
        .rule = "Vacuity Probe V3 (ECHIDNA 6-Kind Mutation Gate >= 95%)",
        .falsifier = "One or more proof-relevant mutants survived verification, bringing the mutation score below the configured threshold.",
        .remedy = "Tighten `@post`, `@invariant`, or protocol assertions to kill the surviving mutants listed in the mutation report.",
    },
    .{
        .code = "Q-604",
        .name = "VACUOUS_PROTOCOL",
        .layer = .vacuity,
        .exit_code = .vacuity_or_mutation,
        .rule = "Vacuity Probe V4 (Protocol Knowledge Reachability)",
        .falsifier = "No reachable execution within bound `k = 12` ever achieves the target commitment knowledge state; safety holds only because nothing completes.",
        .remedy = "Fix deadlocked handlers, mismatched correlation tags, or unreachable transition guards so valid runs reach commitment.",
    },
    .{
        .code = "Q-605",
        .name = "BOUNDED_MODEL_COUNTEREXAMPLE",
        .layer = .layer_b,
        .exit_code = .verification_failed,
        .rule = "Symbolic Bounded Model Check (`QuintessenceKCut`, k = 12)",
        .falsifier = "Symbolic BMC found a reachable multi-step execution trace violating `MailboxBound`, `NoUnwarrantedRemoteClaim`, or `EpochConsistent`.",
        .remedy = "Inspect the emitted step-by-step witness trace and enforce causal reply / epoch validation before transitioning state.",
    },

    // Q-9xx: Toolchain, canonical JCS serialization, and policy gates
    .{
        .code = "Q-901",
        .name = "TOOLCHAIN_MISSING",
        .layer = .infra,
        .exit_code = .toolchain_missing,
        .rule = "Fail-Closed Toolchain Provisioning",
        .falsifier = "Required verification binary (`z3`, `cvc5`, or `zig`) is missing or unexecutable.",
        .remedy = "Run `quintessence doctor` / `just doctor` to check required prover and compiler binaries.",
    },
    .{
        .code = "Q-902",
        .name = "CANONICAL_SERIALIZATION_ERROR",
        .layer = .infra,
        .exit_code = .usage_or_syntax,
        .rule = "RFC 8785 JCS Content Addressing",
        .falsifier = "Artifact failed I-JSON / RFC 8785 canonical serialization (non-UTF-8 or non-finite float).",
        .remedy = "Ensure all JSON receipts and IR inputs conform to RFC 7493 I-JSON.",
    },
    .{
        .code = "Q-905",
        .name = "POLICY_GATE_REJECTED",
        .layer = .infra,
        .exit_code = .incomplete_evidence,
        .rule = "Release Policy Enforcement",
        .falsifier = "Configured receipt policy rejected evidence level, oracle flag, or assumed obligation.",
        .remedy = "Satisfy strict receipt obligations or adjust development policy explicitly.",
    },
};

pub fn lookup(code: []const u8) ?ErrorSpec {
    for (CATALOGUE) |entry| {
        if (std.mem.eql(u8, entry.code, code)) return entry;
    }
    return null;
}

pub const Diagnostic = struct {
    code: []const u8,
    file: []const u8,
    line: usize,
    col: usize,
    message: []const u8,
    counterexample: ?[]const u8 = null,
};

pub fn worstExitCode(diags: []const Diagnostic) ExitCode {
    if (diags.len == 0) return .ok;
    var chosen: ExitCode = .verification_failed;
    for (diags) |d| {
        if (lookup(d.code)) |spec| {
            // Priority order: toolchain (3) > usage (2) > verification refutation (1) > vacuity/mutation (5) > incomplete (4)
            if (spec.exit_code == .toolchain_missing) return .toolchain_missing;
            if (spec.exit_code == .usage_or_syntax) chosen = .usage_or_syntax;
            if (chosen != .usage_or_syntax and spec.exit_code == .verification_failed) chosen = .verification_failed;
            if (chosen == .verification_failed and diags.len == 1) return spec.exit_code;
            if (spec.exit_code == .vacuity_or_mutation and chosen != .usage_or_syntax) {
                // Keep verification_failed ahead of vacuity only if a real refutation also fired
                var any_refutation = false;
                for (diags) |d2| {
                    if (lookup(d2.code)) |s2| {
                        if (s2.exit_code == .verification_failed) any_refutation = true;
                    }
                }
                if (!any_refutation) chosen = .vacuity_or_mutation;
            }
            if (spec.exit_code == .incomplete_evidence) {
                var any_harder = false;
                for (diags) |d2| {
                    if (lookup(d2.code)) |s2| {
                        if (s2.exit_code != .incomplete_evidence) any_harder = true;
                    }
                }
                if (!any_harder) chosen = .incomplete_evidence;
            }
        }
    }
    return chosen;
}
