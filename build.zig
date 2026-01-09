const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Native SDL3 executable
    {
        const exe = b.addExecutable(.{
            .name = "ZiglyNode-gui",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main_gui.zig"),
                .target = target,
                .optimize = optimize,
            }),
            .use_llvm = true,
        });
        exe.addIncludePath(b.path("include"));

        const dvui_dep = b.dependency("dvui", .{ .target = target, .optimize = optimize, .backend = .sdl3 });
        exe.root_module.addImport("dvui", dvui_dep.module("dvui_sdl3"));

        const install_exe = b.addInstallArtifact(exe, .{});

        const run_cmd = b.addRunArtifact(exe);

        // allows `zig build run -- arg1 arg2 etc`
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        // This will evaluate the `run` step rather than the default, which is "install".
        const run_step = b.step("gui", "Run the GUI app");
        run_step.dependOn(&install_exe.step);
        run_step.dependOn(&run_cmd.step);
    }

    // CLI
    {
        const exe = b.addExecutable(.{
            .name = "ZiglyNode-cli",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main_cli.zig"),
                .target = target,
                .optimize = optimize,
            }),
            .use_llvm = true,
        });
        exe.addIncludePath(b.path("include"));

        const install_exe = b.addInstallArtifact(exe, .{});

        const run_cmd = b.addRunArtifact(exe);

        // allows `zig build run -- arg1 arg2 etc`
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        // This will evaluate the `run` step rather than the default, which is "install".
        const run_step = b.step("cli", "Run the CLI app");
        run_step.dependOn(&install_exe.step);
        run_step.dependOn(&run_cmd.step);
    }

    // WASM build
    {
        const wasm_target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        });

        const dvui_web_dep = b.dependency("dvui", .{
            .target = wasm_target,
            .optimize = optimize,
            .backend = .web
        });

        const wasm_exe = b.addExecutable(.{
            .name = "web",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main_gui.zig"),
                .target = wasm_target,
                .optimize = optimize,
                .link_libc = false,
                .strip = if (optimize == .ReleaseFast or optimize == .ReleaseSmall) true else false,
            }),
        });
        wasm_exe.entry = .disabled;
        wasm_exe.addIncludePath(b.path("include"));
        wasm_exe.root_module.addImport("dvui", dvui_web_dep.module("dvui_web"));

        const install_dir: std.Build.InstallDir = .{ .custom = "bin/web" };

        const install_wasm = b.addInstallArtifact(wasm_exe, .{
            .dest_dir = .{ .override = install_dir },
        });

        // Install web support files from DVUI dependency
        const dvui_web_src = b.dependency("dvui", .{});
        const web_html = dvui_web_src.path("src/backends/index.html");
        const web_js = dvui_web_src.path("src/backends/web.js");

        const wasm_step = b.step("wasm", "Build for WebAssembly");
        wasm_step.dependOn(&b.addInstallFileWithDir(web_html, install_dir, "index.html").step);
        wasm_step.dependOn(&b.addInstallFileWithDir(web_js, install_dir, "web.js").step);
        wasm_step.dependOn(&install_wasm.step);
    }

    // Tests
    {
        const test_step = b.step("test", "Run unit tests");

        const files = [_][]const u8{
            "src/util.zig",
            "src/elliptic-curve.zig",
            "src/cryptography.zig",
            "src/bitcoin.zig",
            "src/blockchain.zig",
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
}
