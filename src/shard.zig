const fastfilter = @import("fastfilter");
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Comptime options for a shard.
const Options = struct {
    /// The binary fuse filter bit size. Either 8, 16, or 32. A higher bit size like 16 could be
    /// useful if false positive matches have a very high penalty for your use case (bitsize of 8
    /// gives 4% false positives, 16 gives 0.0015%) and you're willing to pay more memory / indexing
    /// time. See https://github.com/hexops/fastfilter#benchmarks
    filter_bit_size: u16 = 8,

    /// The number of divisions in layer1.
    layer1_divisions: usize = 8,
};

/// A shard is the smallest logical representation of a sinter filter. They are designed to be
/// relatively even in the amount of data they represent, live on a single physical machine, and be
/// operated on within a single CPU core. Multiple shards are typically used to distribute across
/// multiple cores and machines.
///
/// A shard contains keys (e.g. trigram strings to match) and results (e.g. the files those
/// trigrams came from.) It's advised that you keep shards at around ~100,000,000 keys in total.
///
/// The shard is represented in three layers (all perf measured on Ryzen 9 3900X w/ 100 million
/// keys):
///
/// - layer0: the topmost fastfilter which is capable of determining if a given key is present in
///   any result within the shard. e.g. if a trigram is present in any of the 200 files (assuming
///   200 files is about 100,000,000 trigrams/keys.)
///     - Indexing: 2 GiB / 6.9s
///     - Filter size: 107 MiB
///     - Query speed: 167ns
/// - layer1: A configurable number of fastfilters, which divide layer0 into N sets (typically 8.)
///   e.g. while layer0 says "this trigram is in one of these 200 files", layer1 says "it's in one
///   of these 25 files"
///     - Indexing: 225 MiB / 572.3ms (per set)
///     - Filter size: 10 MiB (per set)
///     - Query speed: 33ns (per set)
/// - layer2: the lowest level fastfilter which represents whether or not a given key is present in
///   a final result. e.g. layer2 says "this trigram is in this file" concretely.
///     - Indexing: <22 MiB / <44.6ms
///     - Filter size: <1 MiB
///     - Query speed: <24ns
///
/// For example, assuming you have 200 files with 100,000,000 trigrams/keys total, then performance
/// could be estimated on a single core / single shard to be:
///
/// - Indexing peak mem: ~2 GiB
/// - Indexing time: 20.4s (6.9s layer0, 4.6s layer1, 8.9s layer2)
/// - Query (best case): 224ns (167ns layer0, 33ns layer1, 24ns layer2)
/// - Query (worst case): 1031ns (167ns layer0, 33ns*8 layer1, 24ns*25 layer2)
///
pub fn Shard(comptime options: Options, comptime Result: type, comptime Iterator: type) type {
    return struct {
        /// The original estimated number of keys in this shard.
        total_keys_estimate: usize,

        /// Total number of keys within this shard.
        keys: usize = 0,

        /// null until .index() is invoked.
        layer0: ?BinaryFuseFilter = null,

        layer1: [options.layer1_divisions]Layer2,

        pub const Layer2 = struct {
            /// null until .index() is invoked.
            filter: ?BinaryFuseFilter = null,

            /// Total number of keys within this layer.
            keys: usize = 0,
            entries: std.MultiArrayList(Entry),
        };

        pub const Entry = struct {
            /// Total number of keys within the entry.
            keys: usize = 0,

            /// null until .index() is invoked.
            filter: ?BinaryFuseFilter = null,
            keys_iter: Iterator,
            result: Result,
        };

        pub const FilterType = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = options.filter_bit_size } });
        pub const BinaryFuseFilter = fastfilter.BinaryFuse(FilterType);

        const Self = @This();

        /// Initializes the shard with an approximate number of keys that the shard overall is
        /// expected to contain (e.g. 100_000_000) and estimated number of keys per entry (e.g. 500_000)
        /// which will be used to balance layer1 divisions and keep them at generally equal amounts
        /// of keys.
        pub fn init(total_keys_estimate: usize) Self {
            var layer1: [options.layer1_divisions]Layer2 = undefined;
            comptime var division = 0;
            inline while (division < layer1.len) : (division += 1) {
                layer1[division] = .{
                    .entries = std.MultiArrayList(Entry){},
                };
            }
            return Self{
                .total_keys_estimate = total_keys_estimate,
                .layer0 = null,
                .layer1 = layer1,
            };
        }

        /// Inserts the given result, computing a fastfilter to represent the result using the given
        /// keys iterator.
        ///
        /// For example, if using text files + trigrams, result could be the file name and keys
        /// would be an iterator for hashes of the files trigrams. See fastfilter.SliceIterator
        ///
        /// The iterator must remain alive at least until .index() is called.
        pub fn insert(shard: *Self, allocator: Allocator, keys_iter: Iterator, result: Result) !void {
            const keys_len = keys_iter.len();
            const entry = Entry{
                .keys = keys_len,
                .keys_iter = keys_iter,
                .result = result,
            };

            // Determine which division of layer1 this entry should be inserted into.
            // If we don't find a division with free space below, we'll place it into an evenly
            // distributed division based on number of keys.
            var target_division: usize = keys_len % options.layer1_divisions;

            const target_keys_per_division = shard.total_keys_estimate / options.layer1_divisions;
            for (shard.layer1) |division, division_index| {
                if (division.keys + entry.keys >= target_keys_per_division) continue;

                // Found a division we can place it into.
                target_division = division_index;
                break;
            }

            shard.keys += entry.keys;
            shard.layer1[target_division].keys += entry.keys;
            try shard.layer1[target_division].entries.append(allocator, entry);
        }

        /// Iterates every key in a shard.
        const AllKeysIter = struct {
            shard: *Self,
            layer2: usize = 0,
            entry: usize = 0,
            iter: ?Iterator = null,

            pub inline fn next(iter: *@This()) ?u64 {
                if (iter.iter == null) {
                    if (iter.shard.layer1[iter.layer2].entries.len == 0) return null;
                    iter.iter = iter.shard.layer1[iter.layer2].entries.get(0).keys_iter;
                }
                var final = iter.iter.?.next();
                while (final == null) {
                    if (iter.entry == iter.shard.layer1[iter.layer2].entries.len - 1) {
                        if (iter.layer2 == iter.shard.layer1.len - 1) return null; // no further layer2's
                        // Next layer2.
                        iter.layer2 += 1;
                        iter.entry = 0;
                        if (iter.shard.layer1[iter.layer2].entries.len == 0) return null;
                        iter.iter = iter.shard.layer1[iter.layer2].entries.get(iter.entry).keys_iter;
                        final = iter.iter.?.next();
                    } else {
                        iter.entry += 1;
                        iter.iter = iter.shard.layer1[iter.layer2].entries.get(iter.entry).keys_iter;
                        final = iter.iter.?.next();
                    }
                }
                return final;
            }

            pub inline fn len(iter: @This()) usize {
                return iter.shard.keys;
            }
        };

        /// Iterates every key in layer2 / a single division of layer1.
        const Layer2Iterator = struct {
            shard: *Self,
            layer2: usize,
            entry: usize = 0,
            iter: ?Iterator = null,

            pub inline fn next(iter: *@This()) ?u64 {
                if (iter.iter == null) {
                    if (iter.shard.layer1[iter.layer2].entries.len == 0) return null;
                    iter.iter = iter.shard.layer1[iter.layer2].entries.get(0).keys_iter;
                }
                var final = iter.iter.?.next();
                while (final == null) {
                    if (iter.entry == iter.shard.layer1[iter.layer2].entries.len - 1) {
                        return null;
                    } else {
                        iter.entry += 1;
                        iter.iter = iter.shard.layer1[iter.layer2].entries.get(iter.entry).keys_iter;
                        final = iter.iter.?.next();
                    }
                }
                return final;
            }

            pub inline fn len(iter: @This()) usize {
                return iter.shard.keys;
            }
        };

        /// Indexes the shard, populating all of the fastfilters using the key iterators of the
        /// entries. Must be performed once finished inserting entries. Can be called again to
        /// update the shard (although this performs a full rebuild.)
        pub fn index(shard: *Self, allocator: Allocator) !void {
            // Populate layer0 with all keys.
            var all_keys_iter = AllKeysIter{ .shard = shard };
            shard.layer0 = try BinaryFuseFilter.init(allocator, shard.keys);
            try shard.layer0.?.populateIter(allocator, &all_keys_iter);

            // Populate each layer2 filter, with their division of keys.
            for (shard.layer1) |*layer2, layer2_index| {
                var layer2_iter = Layer2Iterator{ .shard = shard, .layer2 = layer2_index };
                layer2.filter = try BinaryFuseFilter.init(allocator, layer2.keys);
                try layer2.filter.?.populateIter(allocator, &layer2_iter);
            }

            // Populate each entry filter.
            for (shard.layer1) |*layer2| {
                var i: usize = 0;
                while (i < layer2.entries.len) : (i += 1) {
                    var entry = layer2.entries.get(i);
                    entry.filter = try BinaryFuseFilter.init(allocator, entry.keys);
                    try entry.filter.?.populateIter(allocator, entry.keys_iter);
                    layer2.entries.set(i, entry);
                }
            }
        }

        pub fn deinit(shard: *Self, allocator: Allocator) void {
            if (shard.layer0) |*layer0| layer0.deinit(allocator);
            for (shard.layer1) |*layer2| {
                if (layer2.filter) |*layer2_filter| layer2_filter.deinit(allocator);
                for (layer2.entries.items(.filter)) |entry_data| {
                    if (entry_data) |*entry_filter| entry_filter.deinit(allocator);
                }
                layer2.entries.deinit(allocator);
            }
        }

        /// reports if the specified key is likely contained by the shard (within the set
        /// false-positive rate.)
        pub inline fn contains(shard: *const Self, key: u64) bool {
            return shard.layer0.?.contain(key);
        }

        /// Queries for results from the shard, returning results for entries that likely match one
        /// of the keys in `or_keys`.
        ///
        /// Returns the number of results found.
        pub inline fn queryLogicalOr(shard: *Self, allocator: Allocator, or_keys: []const u64, comptime ResultsDst: type, dst: ?ResultsDst) !usize {
            var any = blk: {
                for (or_keys) |key| {
                    if (shard.layer0.?.contain(key)) {
                        break :blk true;
                    }
                }
                break :blk false;
            };
            if (!any) return 0;

            var results: usize = 0;
            for (shard.layer1) |*layer2| {
                var layer1 = layer2.filter.?;
                any = blk: {
                    for (or_keys) |key| {
                        if (layer1.contain(key)) {
                            break :blk true;
                        }
                    }
                    break :blk false;
                };
                if (!any) continue;

                for (layer2.entries.items(.filter)) |entry_filter, i| {
                    any = blk: {
                        for (or_keys) |key| {
                            if (entry_filter.?.contain(key)) {
                                break :blk true;
                            }
                        }
                        break :blk false;
                    };
                    if (!any) continue;

                    results += 1;
                    if (dst) |d| try d.append(allocator, layer2.entries.get(i).result);
                }
            }
            return results;
        }

        /// Queries for results from the shard, returning results for entries that likely match all
        /// of the keys in `and_keys`.
        ///
        /// Returns the number of results found.
        pub inline fn queryLogicalAnd(shard: *Self, allocator: Allocator, and_keys: []const u64, comptime ResultsDst: type, dst: ?ResultsDst) !usize {
            var all = blk: {
                for (and_keys) |key| {
                    if (!shard.layer0.?.contain(key)) {
                        break :blk false;
                    }
                }
                break :blk true;
            };
            if (!all) return 0;

            var results: usize = 0;
            for (shard.layer1) |*layer2| {
                var layer1 = layer2.filter.?;
                all = blk: {
                    for (and_keys) |key| {
                        if (!layer1.contain(key)) {
                            break :blk false;
                        }
                    }
                    break :blk true;
                };
                if (!all) continue;

                for (layer2.entries.items(.filter)) |entry_filter, i| {
                    all = blk: {
                        for (and_keys) |key| {
                            if (!entry_filter.?.contain(key)) {
                                break :blk false;
                            }
                        }
                        break :blk true;
                    };
                    if (!all) continue;

                    results += 1;
                    if (dst) |d| try d.append(allocator, layer2.entries.get(i).result);
                }
            }
            return results;
        }

        pub fn sizeInBytes(shard: *const Self) usize {
            var size: usize = @sizeOf(Self);
            if (shard.layer0) |layer0_filter| size += layer0_filter.sizeInBytes();
            for (shard.layer1) |*layer2| {
                if (layer2.filter) |layer2_filter| size += layer2_filter.sizeInBytes();
                for (layer2.entries.items(.filter)) |entry_filter| {
                    if (entry_filter) |f| size += f.sizeInBytes();
                    size += @sizeOf(Entry);
                }
            }
            return size;
        }
    };
}

test "shard" {
    const allocator = testing.allocator;

    const Iterator = fastfilter.SliceIterator(u64);
    const TestShard = Shard(.{}, []const u8, *Iterator);

    const estimated_keys = 100;
    var shard = TestShard.init(estimated_keys);
    defer shard.deinit(allocator);

    // Insert files.
    var keys_iter = Iterator.init(&.{ 1, 2, 3, 4 });
    try shard.insert(allocator, &keys_iter, "1-2-3-4");

    var keys_iter_2 = Iterator.init(&.{ 3, 4, 5 });
    try shard.insert(allocator, &keys_iter_2, "3-4-5");

    var keys_iter_3 = Iterator.init(&.{ 6, 7, 8 });
    try shard.insert(allocator, &keys_iter_3, "6-7-8");

    // Index.
    try shard.index(allocator);

    // Super fast containment checks.
    try testing.expectEqual(true, shard.contains(2));
    try testing.expectEqual(true, shard.contains(4));

    // Fast queries.
    var results = std.ArrayListUnmanaged([]const u8){};
    defer results.deinit(allocator);

    // Query a single key (5).
    results.clearRetainingCapacity();
    _ = try shard.queryLogicalOr(allocator, &.{5}, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 1), results.items.len);
    try testing.expectEqualStrings("3-4-5", results.items[0]);

    // Query logical OR (2, 5)
    results.clearRetainingCapacity();
    _ = try shard.queryLogicalOr(allocator, &.{ 2, 5 }, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 2), results.items.len);
    try testing.expectEqualStrings("1-2-3-4", results.items[0]);
    try testing.expectEqualStrings("3-4-5", results.items[1]);

    // Query logical AND (2, 5)
    results.clearRetainingCapacity();
    _ = try shard.queryLogicalAnd(allocator, &.{ 2, 5 }, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 0), results.items.len);

    // Query logical AND (3, 4)
    results.clearRetainingCapacity();
    _ = try shard.queryLogicalAnd(allocator, &.{ 3, 4 }, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 2), results.items.len);
    try testing.expectEqualStrings("1-2-3-4", results.items[0]);
    try testing.expectEqualStrings("3-4-5", results.items[1]);

    try testing.expectEqual(@as(usize, 1676), shard.sizeInBytes());
}
