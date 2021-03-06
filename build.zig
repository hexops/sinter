const std = @import("std");
const fastfilter = @import("libs/fastfilter/build.zig");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("sinter", "src/libsinter.zig");
    lib.bundle_compiler_rt = true;
    lib.addPackage(fastfilter.pkg);
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.pie = true;
    lib.linkLibC();
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.test_evented_io = true;
    main_tests.addPackage(fastfilter.pkg);
    main_tests.setBuildMode(mode);
    main_tests.setTarget(target);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    // Benchmark: filter
    const benchmark_filter_exe = b.addExecutable("benchmark_filter", "src/filter_benchmark.zig");
    benchmark_filter_exe.addPackage(pkg);
    benchmark_filter_exe.addPackage(fastfilter.pkg);
    benchmark_filter_exe.setBuildMode(.ReleaseFast);
    benchmark_filter_exe.setTarget(target);
    benchmark_filter_exe.install();

    const benchmark_filter_run_cmd = benchmark_filter_exe.run();
    benchmark_filter_run_cmd.step.dependOn(&benchmark_filter_exe.install_step.?.step);

    const benchmark_filter_run_step = b.step("run-benchmark-filter", "Run benchmark_filter");
    benchmark_filter_run_step.dependOn(&benchmark_filter_run_cmd.step);

    _ = pkg;
}

pub const pkg = std.build.Pkg{
    .name = "sinter",
    .source = .{ .path = thisDir() ++ "/src/main.zig" },
    .dependencies = &.{fastfilter.pkg},
};

fn thisDir() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}
