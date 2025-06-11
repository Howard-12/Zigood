const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .windows,
        }
    });

    const optimize = b.standardOptimizeOption(.{});

    const zigood_mod = b.addModule("zigood", .{
        .root_source_file = b.path("zigood.zig"),
        .target = target,
        .optimize = optimize,
    });

    // exe
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zigood",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    // win32
    const zigwin32_dep = b.dependency("zigwin32", .{
        .target = target,
        .optimize = optimize
    });
    exe.root_module.addImport("zigwin32", zigwin32_dep.module("win32"));
    zigood_mod.addImport("zigwin32", zigwin32_dep.module("win32"));


    // doc
    const install_docs = b.addInstallDirectory(.{
        .source_dir = exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);

    // run
    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);


    // testing
    const test_step = b.step("test", "Run unit tests");

    const zigood_unit_tests = b.addTest(.{
        .root_module = zigood_mod,
    });
    const run_zigood_unit_tests = b.addRunArtifact(zigood_unit_tests);
    test_step.dependOn(&run_zigood_unit_tests.step);
}
