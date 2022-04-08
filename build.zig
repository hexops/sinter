const std = @import("std");
const fastfilter = @import("libs/fastfilter/build.zig");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("sinter", "src/main.zig");
    lib.addPackage(fastfilter.pkg);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}

pub const pkg = std.build.Pkg{
    .name = "sinter",
    .path = .{ .path = thisDir() ++ "/src/main.zig" },
};

fn thisDir() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}
