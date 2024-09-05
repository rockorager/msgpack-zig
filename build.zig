const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("msgpack", .{
        .root_source_file = b.path("msgpack.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("msgpack.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Docs
    {
        const docs_step = b.step("docs", "Build docs");
        const docs_obj = b.addObject(.{
            .name = "msgpack",
            .root_source_file = b.path("msgpack.zig"),
            .target = target,
            .optimize = optimize,
        });
        const docs = docs_obj.getEmittedDocs();
        docs_step.dependOn(&b.addInstallDirectory(.{
            .source_dir = docs,
            .install_dir = .prefix,
            .install_subdir = "docs",
        }).step);
    }
}
