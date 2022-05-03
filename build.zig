const std = @import("std");
const fastfilter = @import("libs/fastfilter/build.zig");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("sinter", "src/main.zig");
    lib.test_evented_io = true;
    lib.addPackage(fastfilter.pkg);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.test_evented_io = true;
    main_tests.addPackage(fastfilter.pkg);
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    // Benchmark: shard
    const benchmark_shard_exe = b.addExecutable("benchmark_shard", "src/shard_benchmark.zig");
    benchmark_shard_exe.addPackage(pkg);
    benchmark_shard_exe.addPackage(fastfilter.pkg);
    benchmark_shard_exe.setBuildMode(.ReleaseFast);
    benchmark_shard_exe.install();

    const benchmark_shard_run_cmd = benchmark_shard_exe.run();
    benchmark_shard_run_cmd.step.dependOn(&benchmark_shard_exe.install_step.?.step);

    const benchmark_shard_run_step = b.step("run-benchmark-shard", "Run benchmark_shard");
    benchmark_shard_run_step.dependOn(&benchmark_shard_run_cmd.step);
}

pub const pkg = std.build.Pkg{
    .name = "sinter",
    .path = .{ .path = thisDir() ++ "/src/main.zig" },
    .dependencies = &.{fastfilter.pkg},
};

fn thisDir() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}
