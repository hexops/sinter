// zig run -O ReleaseFast ./src/shard_benchmark.zig

const sinter = @import("sinter");
const fastfilter = @import("fastfilter");
const std = @import("std");
const time = std.time;

pub const io_mode = .evented;

pub fn main() !void {
    // Create measurement allocators backend by a general purpose allocator.
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    var gpa = general_purpose_allocator.allocator();

    var buildMA = fastfilter.MeasuredAllocator.init(gpa);
    var buildAllocator = buildMA.allocator();

    // Primary benchmark numbers
    const num_results = 200; // e.g. documents we will match
    const num_keys_per_result = 500_000; // e.g. words per document, if you want "document contains word" matching only

    // Create our key set iterator. Normally there'd be one per result, but since our keys are always
    // the same and these iterators wrap around we just use the same one.
    var keys = try gpa.alloc(u64, num_keys_per_result);
    defer gpa.free(keys);
    for (keys) |_, i| {
        keys[i] = i;
    }
    const Iterator = fastfilter.SliceIterator(u64);
    var keys_iter = Iterator.init(keys);

    // Measure shard creation.
    var timer = try time.Timer.start();
    const TestShard = sinter.Shard(.{}, u64, *Iterator);

    // Create, insert (extremely cheap - not worth measuring), and index the shard.
    const estimated_keys = num_results * num_keys_per_result;
    const indexTimeStart = timer.lap();
    var shard = TestShard.init(estimated_keys);
    defer shard.deinit(buildAllocator);
    var result: u64 = 0;
    while (result < num_results) : (result += 1) {
        try shard.insert(buildAllocator, &keys_iter, result);
    }
    try shard.index(buildAllocator);
    const indexTimeEnd = timer.lap();

    // Choose random keys we will use to query.
    var rng = std.rand.DefaultPrng.init(0);
    const random = rng.random();
    var query_keys: [200]u64 = undefined;
    for (query_keys) |*i| {
        i.* = random.uintAtMost(u64, num_keys_per_result);
    }

    // Query the shard.
    const query_laps = 100_000;
    var results = std.ArrayListUnmanaged(u64){};
    defer results.deinit(gpa);

    const queryOrTimeStart = timer.lap();
    var i: usize = 0;
    while (i < query_laps) : (i += 1) {
        results.clearRetainingCapacity();
        _ = try shard.queryLogicalOr(gpa, query_keys[0..], *std.ArrayListUnmanaged(u64), &results);
    }
    const queryOrTimeEnd = timer.lap();

    const queryAndTimeStart = timer.lap();
    i = 0;
    while (i < query_laps) : (i += 1) {
        results.clearRetainingCapacity();
        _ = try shard.queryLogicalAnd(gpa, query_keys[0..], *std.ArrayListUnmanaged(u64), &results);
    }
    const queryAndTimeEnd = timer.lap();

    const writeFileTimeStart = timer.lap();
    try shard.writeFile(gpa, std.fs.cwd(), "benchmark.sinter");
    const writeFileTimeEnd = timer.lap();

    const readFileTimeStart = timer.lap();
    _ = try TestShard.readFile(gpa, "benchmark.sinter");
    const readFileTimeEnd = timer.lap();

    const stdout = std.io.getStdOut().writer();
    try stdout.print("| # keys    | # results | # keys per result | index time | OR-200 query time | AND-200 query time | writeFile time | readFile time |\n", .{});
    try stdout.print("|-----------|-----------|-------------------|------------|-------------------|--------------------|----------------|---------------|\n", .{});
    try stdout.print("| {: <9}", .{estimated_keys});
    try stdout.print(" | {: <9}", .{num_results});
    try stdout.print(" | {: <17}", .{num_keys_per_result});
    try stdout.print(" | ", .{});
    try formatTime(stdout, "{d: >7.1}{s}", indexTimeStart, indexTimeEnd, 1);
    try stdout.print(" | ", .{});
    try formatTime(stdout, "{d: >14.1}{s}", queryOrTimeStart, queryOrTimeEnd, query_laps);
    try stdout.print(" | ", .{});
    try formatTime(stdout, "{d: >15.1}{s}", queryAndTimeStart, queryAndTimeEnd, query_laps);
    try stdout.print(" | ", .{});
    try formatTime(stdout, "{d: >11.1}{s}", writeFileTimeStart, writeFileTimeEnd, 1);
    try stdout.print(" | ", .{});
    try formatTime(stdout, "{d: >10.1}{s}", readFileTimeStart, readFileTimeEnd, 1);
    try stdout.print(" |\n", .{});
}

fn formatTime(writer: anytype, comptime spec: []const u8, start: u64, end: u64, division: usize) !void {
    const ns = @intToFloat(f64, (end - start) / division);
    if (ns <= time.ns_per_ms) {
        try std.fmt.format(writer, spec, .{ ns, "ns " });
        return;
    }
    if (ns <= time.ns_per_s) {
        try std.fmt.format(writer, spec, .{ ns / @intToFloat(f64, time.ns_per_ms), "ms " });
        return;
    }
    if (ns <= time.ns_per_min) {
        try std.fmt.format(writer, spec, .{ ns / @intToFloat(f64, time.ns_per_s), "s  " });
        return;
    }
    try std.fmt.format(writer, spec, .{ ns / @intToFloat(f64, time.ns_per_min), "min" });
    return;
}

fn formatBytes(writer: anytype, comptime spec: []const u8, bytes: u64) !void {
    const kib = 1024;
    const mib = 1024 * kib;
    const gib = 1024 * mib;
    if (bytes < kib) {
        try std.fmt.format(writer, spec, .{ bytes, "B  " });
    }
    if (bytes < mib) {
        try std.fmt.format(writer, spec, .{ bytes / kib, "KiB" });
        return;
    }
    if (bytes < gib) {
        try std.fmt.format(writer, spec, .{ bytes / mib, "MiB" });
        return;
    }
    try std.fmt.format(writer, spec, .{ bytes / gib, "GiB" });
    return;
}
