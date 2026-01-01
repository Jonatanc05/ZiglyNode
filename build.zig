const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ZiglyNode",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    exe.addIncludePath(b.path("include"));

    const sdl3 = b.dependency("sdl3", .{
        .target = target,
        .optimize = optimize,
        .c_sdl_preferred_linkage = .static,
    });
    exe.root_module.addImport("sdl3", sdl3.module("sdl3"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    // run from installation directory rather than directly from cache directory
    run_cmd.step.dependOn(b.getInstallStep());

    // allows `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // ------------ TESTS ------------

    const test_step = b.step("test", "Run unit tests");

    const files = [_][]const u8{
        "src/util.zig",
        "src/elliptic-curve.zig",
        "src/cryptography.zig",
        "src/bitcoin.zig",
        "src/network.zig",
    };

    for (files) |file| {
        const t = b.addTest(.{
            //.name = file,
            .root_module = b.createModule(.{
                .root_source_file = b.path(file),
                .target = target,
                .optimize = optimize,
            }),
            .use_llvm = true,
        });
        t.root_module.addIncludePath(b.path("include"));
        const test_artifact = b.addRunArtifact(t);
        test_step.dependOn(&test_artifact.step);
    }
}
