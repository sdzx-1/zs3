const std = @import("std");
const acl = @import("acl.zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const strip = b.option(bool, "strip", "Strip debug symbols") orelse (optimize != .Debug);

    const acl_list = b.option([]const u8, "acl-list", "Credential list: role:access:secret[,role:access:secret...]") orelse "admin:minioadmin:minioadmin";
    const data_dir = b.option([]const u8, "data-dir", "Default data directory") orelse "data";
    const tracy = b.option([]const u8, "tracy", "Enable Tracy integration. Supply path to Tracy source");
    const tracy_callstack = b.option(bool, "tracy-callstack", "Include callstack information with Tracy data. Does nothing if -Dtracy is not provided") orelse (tracy != null);
    const tracy_allocation = b.option(bool, "tracy-allocation", "Include allocation information with Tracy data. Does nothing if -Dtracy is not provided") orelse (tracy != null);
    const tracy_callstack_depth: u32 = b.option(u32, "tracy-callstack-depth", "Declare callstack depth for Tracy data. Does nothing if -Dtracy_callstack is not provided") orelse 10;

    const parsed = try acl.parseCredentials(b.allocator, acl_list);
    b.allocator.free(parsed);

    const options = b.addOptions();
    options.addOption([]const u8, "acl_list", acl_list);
    options.addOption([]const u8, "data_dir", data_dir);
    options.addOption(bool, "enable_tracy", tracy != null);
    options.addOption(bool, "enable_tracy_callstack", tracy_callstack);
    options.addOption(bool, "enable_tracy_allocation", tracy_allocation);
    options.addOption(u32, "tracy_callstack_depth", tracy_callstack_depth);

    const exe = b.addExecutable(.{
        .name = "zs3",
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
        }),
    });

    exe.root_module.addOptions("build_options", options);

    if (tracy) |tracy_path| {
        const client_cpp = b.pathJoin(
            &[_][]const u8{ tracy_path, "public", "TracyClient.cpp" },
        );
        const tracy_c_flags: []const []const u8 = &.{
            "-DTRACY_ENABLE=1",
            "-fno-sanitize=undefined",
        };

        exe.root_module.addIncludePath(.{ .cwd_relative = tracy_path });
        exe.root_module.addCSourceFile(.{
            .file = .{ .cwd_relative = client_cpp },
            .flags = tracy_c_flags,
        });
        exe.root_module.link_libc = true;
        exe.root_module.link_libcpp = true;
    }
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the S3 server");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);
}
