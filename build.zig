const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zbor_dep = b.dependency("zbor", .{
        .target = target,
        .optimize = optimize,
    });
    const zbor_module = zbor_dep.module("zbor");

    const uuid_dep = b.dependency("uuid", .{
        .target = target,
        .optimize = optimize,
    });
    const uuid_module = uuid_dep.module("uuid");

    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });

    const ccdb_module = b.addModule("ccdb", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    ccdb_module.addImport("zbor", zbor_module);
    ccdb_module.addImport("uuid", uuid_module);
    try b.modules.put(b.dupe("ccdb"), ccdb_module);

    const ccdb_exe = b.createModule(.{
        .root_source_file = b.path("src/cmd.zig"),
        .target = target,
        .optimize = optimize,
    });
    ccdb_exe.addImport("zbor", zbor_module);
    ccdb_exe.addImport("ccdb", ccdb_module);
    ccdb_exe.addImport("clap", clap_dep.module("clap"));

    const lib = b.addLibrary(.{
        .name = "ccdb",
        .root_module = ccdb_module,
    });
    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_module = ccdb_module,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = ccdb_exe,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    const cmd_exe = b.addExecutable(.{
        .name = "ccdb",
        .root_module = ccdb_exe,
    });
    cmd_exe.linkLibC();
    b.installArtifact(cmd_exe);
}
