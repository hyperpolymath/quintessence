// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Quintessence Native Verifier & C-ABI FFI Build Graph (Zig 0.17+).
//
// Artifacts produced into `zig-out/`:
//   * `zig-out/bin/quintessence`         — Native verification CLI (`verify`, `explain`, `receipt`, `doctor`)
//   * `zig-out/lib/libquintessence.so`   — Shared C-ABI FFI library matching `src/interface/Abi/`
//   * `zig build test`                   — Runs core, FFI, integration, and Verisim NIF unit suites

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Core verification engine module (`src/core/engine.zig`)
    const core_mod = b.createModule(.{
        .root_source_file = b.path("../../core/engine.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Shared C-ABI FFI library (`src/interface/ffi/src/main.zig`)
    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "quintessence_core", .module = core_mod },
        },
    });

    const ffi_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "quintessence",
        .root_module = ffi_mod,
    });
    b.installArtifact(ffi_lib);

    // Native CLI binary (`zig-out/bin/quintessence`)
    const cli_exe = b.addExecutable(.{
        .name = "quintessence",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "quintessence_core", .module = core_mod },
            },
        }),
    });
    b.installArtifact(cli_exe);

    // Comprehensive unit + integration test step (`zig build test`)
    const test_step = b.step("test", "Run Quintessence core, FFI, integration, and NIF unit tests");

    const jcs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../core/jcs.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(jcs_tests).step);

    const ffi_tests = b.addTest(.{ .root_module = ffi_mod });
    test_step.dependOn(&b.addRunArtifact(ffi_tests).step);

    const integ_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "quintessence_core", .module = core_mod },
                .{ .name = "quintessence_ffi", .module = ffi_mod },
            },
        }),
    });
    test_step.dependOn(&b.addRunArtifact(integ_tests).step);

    const nif_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("../../../examples/quintessence/priv/native/verisim_nif.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(nif_tests).step);
}
