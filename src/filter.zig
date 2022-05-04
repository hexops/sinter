const fastfilter = @import("fastfilter");
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Comptime options for a sinter filter.
const Options = struct {
    /// The binary fuse filter bit size. Either 8, 16, or 32. A higher bit size like 16 could be
    /// useful if false positive matches have a very high penalty for your use case (bitsize of 8
    /// gives 4% false positives, 16 gives 0.0015%) and you're willing to pay more memory / indexing
    /// time. See https://github.com/hexops/fastfilter#benchmarks
    filter_bit_size: u16 = 8,

    /// The number of divisions in the mid layer.
    mid_layer_divisions: usize = 8,
};

/// A sinter filter. They are designed to represent many matching keys (integers, e.g. hashes of
/// words in a text file) which map to a smaller number of results (for example, the text files
/// themselves.) The filter is composed of a 3-layer tree of binary fuse filters, and optimized for
/// query time. Binary fuse filters are a much faster more modern variant of bloom filters by Daniel
/// Lemire and Thomas Mueller Graf, see https://github.com/hexops/fastfilter for details.
///
/// Querying results from a sinter filter is as easy as providing matching keys. Key equality is
/// exact only, you can acquire "fuzzy" matching of results by e.g. emitting a single key for every
/// string you might want to match. To query, you provide a set of keys that should logically AND/OR
/// intersect with results' keys. Due to statistical nature of fastfilters, it is possible to get
/// false-positive matches but never false-negatives.
///
/// A sinter filter is designed to be built, indexed, and queried within a single CPU core. You
/// should look at the indexing time, memory usage, query time, and based on those numbers decide
/// how much data on average to aim to pack into a single sinter filter so that you saturate about
/// half of a CPU core reasonably. A FilterGroup can then be used to operate on multiple sinter
/// filters in parallel across CPU cores. Multiple FilterGroups are typically distributed across
/// physical machines when desirable.
///
/// `zig run-benchmark-filter` shows how efficient sinter filters can be. On an original M1 Macbook
/// Pro, utilizing a single CPU:
///
/// ```
/// | # keys    | # results | # keys per result | index time | OR-200 query time | AND-200 query time | writeFile time | readFile time |
/// |-----------|-----------|-------------------|------------|-------------------|--------------------|----------------|---------------|
/// | 100000000 | 200       | 500000            |    22.4s   |         2825.0ns  |        415755.0ns  |        91.0ms  |      667.1ms  |
/// ```
///
/// That can be read as:
///
/// * We put 200 results into the filter, each with 500,000 unique matching keys.
/// * The filter contains 100,000,000 unique matching keys total.
/// * We can query "which results contain one of these 200 keys? (OR)" in 2825ns
/// * We can query "which results contain ALL 200 of these keys? (AND)" in 0.41ms (415755.0ns)
/// * Serialization and deserialization (including writing to disk) takes under a few hundred ms, 324M on disk file size.
///
/// How sinter filters are structured
///
/// The filter is represented in three layers (all perf measured on Ryzen 9 3900X w/ 100 million
/// keys):
///
/// - outer layer: the topmost fastfilter which is capable of determining if a given key is present
///   in any result within the entire filter. e.g. if a word is present in any of the 200 files
///   (assuming 200 files is about 100,000,000 words/keys.)
///     - Indexing: 2 GiB / 6.9s
///     - Filter size: 107 MiB
///     - Query speed: 167ns
/// - mid layer: A configurable number of fastfilters, which divide the outer layer into N sets
///   (typically 8.) e.g. while the outer layer says "this word is in one of these 200 files", the
///   mid layer says "it's in one of these 25 files"
///     - Indexing: 225 MiB / 572.3ms (per set)
///     - Filter size: 10 MiB (per set)
///     - Query speed: 33ns (per set)
/// - inner layer: the lowest level fastfilter which represents whether or not a given key is
///   present in a final result. e.g. the inner layer says "this word is in this file".
///     - Indexing: <22 MiB / <44.6ms
///     - Filter size: <1 MiB
///     - Query speed: <24ns
///
/// For example, assuming you have 200 files with 100,000,000 words/keys total, then performance
/// could be estimated on a single sinter filter (single CPU core) to be:
///
/// - Indexing peak mem: ~2 GiB
/// - Indexing time: 20.4s (6.9s outer, 4.6s mid, 8.9s inner)
/// - Query (best case): 224ns (167ns outer, 33ns mid, 24ns inner)
/// - Query (worst case): 1031ns (167ns outer, 33ns*8 mid, 24ns*25 inner)
///
pub fn Filter(comptime options: Options, comptime Result: type, comptime Iterator: type) type {
    return struct {
        /// The original estimated number of keys in this filter.
        total_keys_estimate: usize,

        /// Total number of keys within this filter.
        keys: usize = 0,

        /// null until .index() is invoked.
        outer_layer: ?BinaryFuseFilter = null,

        mid_layer: [options.mid_layer_divisions]Inner,

        pub const Inner = struct {
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
            keys_iter: ?Iterator = null,
            result: Result,
        };

        pub const FilterType = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = options.filter_bit_size } });
        pub const BinaryFuseFilter = fastfilter.BinaryFuse(FilterType);

        const Self = @This();

        /// Initializes the filter with an approximate number of keys that the filter overall is
        /// expected to contain (e.g. 100_000_000) and estimated number of keys per entry (e.g. 500_000)
        /// which will be used to balance mid layer divisions and keep them at generally equal amounts
        /// of keys.
        pub fn init(total_keys_estimate: usize) Self {
            var mid_layer: [options.mid_layer_divisions]Inner = undefined;
            comptime var division = 0;
            inline while (division < mid_layer.len) : (division += 1) {
                mid_layer[division] = .{
                    .entries = std.MultiArrayList(Entry){},
                };
            }
            return Self{
                .total_keys_estimate = total_keys_estimate,
                .outer_layer = null,
                .mid_layer = mid_layer,
            };
        }

        /// Inserts the given result, computing a fastfilter to represent the result using the given
        /// keys iterator.
        ///
        /// For example, if using text files + trigrams, result could be the file name and keys
        /// would be an iterator for hashes of the files trigrams. See fastfilter.SliceIterator
        ///
        /// The iterator must remain alive at least until .index() is called.
        pub fn insert(filter: *Self, allocator: Allocator, keys_iter: Iterator, result: Result) !void {
            const keys_len = keys_iter.len();
            const entry = Entry{
                .keys = keys_len,
                .keys_iter = keys_iter,
                .result = result,
            };

            // Determine which division of mid_layer this entry should be inserted into.
            // If we don't find a division with free space below, we'll place it into an evenly
            // distributed division based on number of keys.
            var target_division: usize = keys_len % options.mid_layer_divisions;

            const target_keys_per_division = filter.total_keys_estimate / options.mid_layer_divisions;
            for (filter.mid_layer) |division, division_index| {
                if (division.keys + entry.keys >= target_keys_per_division) continue;

                // Found a division we can place it into.
                target_division = division_index;
                break;
            }

            filter.keys += entry.keys;
            filter.mid_layer[target_division].keys += entry.keys;
            try filter.mid_layer[target_division].entries.append(allocator, entry);
        }

        /// Iterates every key in a filter.
        const AllKeysIter = struct {
            filter: *Self,
            inner: usize = 0,
            entry: usize = 0,
            iter: ?Iterator = null,

            pub inline fn next(iter: *@This()) ?u64 {
                if (iter.iter == null) {
                    if (iter.filter.mid_layer[iter.inner].entries.len == 0) return null;
                    iter.iter = iter.filter.mid_layer[iter.inner].entries.get(0).keys_iter.?;
                }
                var final = iter.iter.?.next();
                while (final == null) {
                    if (iter.entry == iter.filter.mid_layer[iter.inner].entries.len - 1) {
                        if (iter.inner == iter.filter.mid_layer.len - 1) return null; // no further inner layer's
                        // Next inner layer.
                        iter.inner += 1;
                        iter.entry = 0;
                        if (iter.filter.mid_layer[iter.inner].entries.len == 0) return null;
                        iter.iter = iter.filter.mid_layer[iter.inner].entries.get(iter.entry).keys_iter.?;
                        final = iter.iter.?.next();
                    } else {
                        iter.entry += 1;
                        iter.iter = iter.filter.mid_layer[iter.inner].entries.get(iter.entry).keys_iter.?;
                        final = iter.iter.?.next();
                    }
                }
                return final;
            }

            pub inline fn len(iter: @This()) usize {
                return iter.filter.keys;
            }
        };

        /// Iterates every key in inner layer / a single division of mid_layer.
        const InnerIterator = struct {
            filter: *Self,
            inner: usize,
            entry: usize = 0,
            iter: ?Iterator = null,

            pub inline fn next(iter: *@This()) ?u64 {
                if (iter.iter == null) {
                    if (iter.filter.mid_layer[iter.inner].entries.len == 0) return null;
                    iter.iter = iter.filter.mid_layer[iter.inner].entries.get(0).keys_iter.?;
                }
                var final = iter.iter.?.next();
                while (final == null) {
                    if (iter.entry == iter.filter.mid_layer[iter.inner].entries.len - 1) {
                        return null;
                    } else {
                        iter.entry += 1;
                        iter.iter = iter.filter.mid_layer[iter.inner].entries.get(iter.entry).keys_iter.?;
                        final = iter.iter.?.next();
                    }
                }
                return final;
            }

            pub inline fn len(iter: @This()) usize {
                return iter.filter.keys;
            }
        };

        /// Indexes the filter, populating all of the fastfilters using the key iterators of the
        /// entries. Must be performed once finished inserting entries. Can be called again to
        /// update the filter (although this performs a full rebuild.)
        pub fn index(filter: *Self, allocator: Allocator) !void {
            // Populate outer layer with all keys.
            var all_keys_iter = AllKeysIter{ .filter = filter };
            filter.outer_layer = try BinaryFuseFilter.init(allocator, filter.keys);
            try filter.outer_layer.?.populateIter(allocator, &all_keys_iter);

            // Populate each inner layer filter, with their division of keys.
            for (filter.mid_layer) |*inner, inner_index| {
                var inner_iter = InnerIterator{ .filter = filter, .inner = inner_index };
                inner.filter = try BinaryFuseFilter.init(allocator, inner.keys);
                try inner.filter.?.populateIter(allocator, &inner_iter);
            }

            // Populate each entry filter.
            for (filter.mid_layer) |*inner| {
                var i: usize = 0;
                while (i < inner.entries.len) : (i += 1) {
                    var entry = inner.entries.get(i);
                    entry.filter = try BinaryFuseFilter.init(allocator, entry.keys);
                    try entry.filter.?.populateIter(allocator, entry.keys_iter.?);
                    inner.entries.set(i, entry);
                }
            }
        }

        pub fn deinit(filter: *Self, allocator: Allocator) void {
            if (filter.outer_layer) |*outer_layer| outer_layer.deinit(allocator);
            for (filter.mid_layer) |*inner| {
                if (inner.filter) |*inner_filter| inner_filter.deinit(allocator);
                for (inner.entries.items(.filter)) |entry_data| {
                    if (entry_data) |*entry_filter| entry_filter.deinit(allocator);
                }
                inner.entries.deinit(allocator);
            }
        }

        /// reports if the specified key is likely contained by the filter (within the set
        /// false-positive rate.)
        pub inline fn contains(filter: *const Self, key: u64) bool {
            return filter.outer_layer.?.contain(key);
        }

        /// Queries for results from the filter, returning results for entries that likely match one
        /// of the keys in `or_keys`.
        ///
        /// Returns the number of results found.
        pub inline fn queryLogicalOr(filter: *Self, allocator: Allocator, or_keys: []const u64, comptime ResultsDst: type, dst: ?ResultsDst) !usize {
            var any = blk: {
                for (or_keys) |key| {
                    if (filter.outer_layer.?.contain(key)) {
                        break :blk true;
                    }
                }
                break :blk false;
            };
            if (!any) return 0;

            var results: usize = 0;
            for (filter.mid_layer) |*inner| {
                var mid_layer = inner.filter.?;
                any = blk: {
                    for (or_keys) |key| {
                        if (mid_layer.contain(key)) {
                            break :blk true;
                        }
                    }
                    break :blk false;
                };
                if (!any) continue;

                for (inner.entries.items(.filter)) |entry_filter, i| {
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
                    if (dst) |d| try d.append(allocator, inner.entries.get(i).result);
                }
            }
            return results;
        }

        /// Queries for results from the filter, returning results for entries that likely match all
        /// of the keys in `and_keys`.
        ///
        /// Returns the number of results found.
        pub inline fn queryLogicalAnd(filter: *Self, allocator: Allocator, and_keys: []const u64, comptime ResultsDst: type, dst: ?ResultsDst) !usize {
            var all = blk: {
                for (and_keys) |key| {
                    if (!filter.outer_layer.?.contain(key)) {
                        break :blk false;
                    }
                }
                break :blk true;
            };
            if (!all) return 0;

            var results: usize = 0;
            for (filter.mid_layer) |*inner| {
                var mid_layer = inner.filter.?;
                all = blk: {
                    for (and_keys) |key| {
                        if (!mid_layer.contain(key)) {
                            break :blk false;
                        }
                    }
                    break :blk true;
                };
                if (!all) continue;

                for (inner.entries.items(.filter)) |entry_filter, i| {
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
                    if (dst) |d| try d.append(allocator, inner.entries.get(i).result);
                }
            }
            return results;
        }

        pub fn sizeInBytes(filter: *const Self) usize {
            var size: usize = @sizeOf(Self);
            if (filter.outer_layer) |outer_filter| size += outer_filter.sizeInBytes();
            for (filter.mid_layer) |*inner| {
                if (inner.filter) |inner_filter| size += inner_filter.sizeInBytes();
                for (inner.entries.items(.filter)) |entry_filter| {
                    if (entry_filter) |f| size += f.sizeInBytes();
                    size += @sizeOf(Entry);
                }
            }
            return size;
        }

        pub fn writeFile(
            filter: *const Self,
            allocator: Allocator,
            dir: std.fs.Dir,
            dest_path: []const u8,
        ) !void {
            const baf = try std.io.BufferedAtomicFile.create(allocator, dir, dest_path, .{});
            defer baf.destroy();

            try filter.serialize(baf.writer());
            try baf.finish();
        }

        pub fn serialize(filter: *const Self, stream: anytype) !void {
            // Constants
            const version = 1;
            try stream.writeIntLittle(u16, version);
            try stream.writeIntLittle(u64, filter.total_keys_estimate);
            try stream.writeIntLittle(u16, options.filter_bit_size);
            try stream.writeIntLittle(u64, options.mid_layer_divisions);

            // Outer layer
            try stream.writeIntLittle(u64, filter.keys);
            try serializeFilter(stream, &filter.outer_layer.?);
            for (filter.mid_layer) |*inner| {
                // Mid layer
                try stream.writeIntLittle(u64, inner.keys);
                try serializeFilter(stream, &inner.filter.?);
                try stream.writeIntLittle(u32, @intCast(u32, inner.entries.len));

                var i: usize = 0;
                while (i < inner.entries.len) : (i += 1) {
                    // Inner layer
                    var entry = inner.entries.get(i);
                    try stream.writeIntLittle(u64, entry.keys);
                    try serializeFilter(stream, &entry.filter.?);

                    // TODO: generic result serialization
                    try stream.writeIntLittle(u64, entry.result);
                }
            }
        }

        fn serializeFilter(stream: anytype, filter: *const BinaryFuseFilter) !void {
            try stream.writeIntLittle(u64, filter.seed);
            try stream.writeIntLittle(u32, filter.segment_length);
            try stream.writeIntLittle(u32, filter.segment_length_mask);
            try stream.writeIntLittle(u32, filter.segment_count);
            try stream.writeIntLittle(u32, filter.segment_count_length);
            try stream.writeIntLittle(u32, @intCast(u32, filter.fingerprints.len));

            const F = std.meta.Elem(@TypeOf(filter.fingerprints));
            const fingerprint_bytes: []const u8 = filter.fingerprints.ptr[0 .. filter.fingerprints.len * @sizeOf(F)];
            try stream.writeAll(fingerprint_bytes);
        }

        pub fn readFile(
            allocator: Allocator,
            file_path: []const u8,
        ) !Self {
            var file = try std.fs.openFileAbsolute(file_path, .{ .mode = .read_only });
            defer file.close();

            var buf_stream = std.io.bufferedReader(file.reader());
            return try deserialize(allocator, buf_stream.reader());
        }

        pub fn deserialize(allocator: Allocator, stream: anytype) !Self {
            // TODO: if reads here fail, filter allocations would leak.

            // Constants
            const version = try stream.readIntLittle(u16);
            std.debug.assert(version == 1);
            const total_keys_estimate = try stream.readIntLittle(u64);
            const filter_bit_size = try stream.readIntLittle(u16);
            const mid_layer_divisions = try stream.readIntLittle(u64);
            std.debug.assert(mid_layer_divisions == options.mid_layer_divisions);
            std.debug.assert(filter_bit_size == options.filter_bit_size);

            // Outer layer
            const keys = try stream.readIntLittle(u64);
            const outer_layer = try deserializeFilter(allocator, stream);

            var mid_layer: [options.mid_layer_divisions]Inner = undefined;
            var division: usize = 0;
            while (division < options.mid_layer_divisions) : (division += 1) {
                // Mid layer
                const inner_keys = try stream.readIntLittle(u64);
                const inner_filter = try deserializeFilter(allocator, stream);
                const inner_entries = try stream.readIntLittle(u32);

                var entries = std.MultiArrayList(Entry){};
                try entries.resize(allocator, inner_entries);
                var i: usize = 0;
                while (i < entries.len) : (i += 1) {
                    // Inner Layer
                    var entry_keys = try stream.readIntLittle(u64);
                    var entry_filter = try deserializeFilter(allocator, stream);

                    // TODO: generic result deserialization
                    var result = try stream.readIntLittle(u64);

                    entries.set(i, Entry{
                        .keys = entry_keys,
                        .filter = entry_filter,
                        .keys_iter = null,
                        .result = result,
                    });
                }

                mid_layer[division] = Inner{
                    .filter = inner_filter,
                    .keys = inner_keys,
                    .entries = entries,
                };
            }

            return Self{
                .total_keys_estimate = total_keys_estimate,
                .keys = keys,
                .outer_layer = outer_layer,
                .mid_layer = mid_layer,
            };
        }

        fn deserializeFilter(allocator: Allocator, stream: anytype) !BinaryFuseFilter {
            const seed = try stream.readIntLittle(u64);
            const segment_length = try stream.readIntLittle(u32);
            const segment_length_mask = try stream.readIntLittle(u32);
            const segment_count = try stream.readIntLittle(u32);
            const segment_count_length = try stream.readIntLittle(u32);
            const fingerprints_len = try stream.readIntLittle(u32);

            const fingerprints = try allocator.alloc(FilterType, fingerprints_len);
            const fingerprint_bytes: []u8 = fingerprints.ptr[0 .. fingerprints.len * @sizeOf(FilterType)];
            const read_bytes = try stream.readAll(fingerprint_bytes);
            if (read_bytes < fingerprint_bytes.len) {
                allocator.free(fingerprints);
                return error.EndOfStream;
            }
            return BinaryFuseFilter{
                .seed = seed,
                .segment_length = segment_length,
                .segment_length_mask = segment_length_mask,
                .segment_count = segment_count,
                .segment_count_length = segment_count_length,
                .fingerprints = fingerprints,
            };
        }
    };
}

test "filter" {
    const allocator = testing.allocator;

    const Iterator = fastfilter.SliceIterator(u64);
    const TestFilter = Filter(.{}, []const u8, *Iterator);

    const estimated_keys = 100;
    var filter = TestFilter.init(estimated_keys);
    defer filter.deinit(allocator);

    // Insert files.
    var keys_iter = Iterator.init(&.{ 1, 2, 3, 4 });
    try filter.insert(allocator, &keys_iter, "1-2-3-4");

    var keys_iter_2 = Iterator.init(&.{ 3, 4, 5 });
    try filter.insert(allocator, &keys_iter_2, "3-4-5");

    var keys_iter_3 = Iterator.init(&.{ 6, 7, 8 });
    try filter.insert(allocator, &keys_iter_3, "6-7-8");

    // Index.
    try filter.index(allocator);

    // Super fast containment checks.
    try testing.expectEqual(true, filter.contains(2));
    try testing.expectEqual(true, filter.contains(4));

    // Fast queries.
    var results = std.ArrayListUnmanaged([]const u8){};
    defer results.deinit(allocator);

    // Query a single key (5).
    results.clearRetainingCapacity();
    _ = try filter.queryLogicalOr(allocator, &.{5}, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 1), results.items.len);
    try testing.expectEqualStrings("3-4-5", results.items[0]);

    // Query logical OR (2, 5)
    results.clearRetainingCapacity();
    _ = try filter.queryLogicalOr(allocator, &.{ 2, 5 }, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 2), results.items.len);
    try testing.expectEqualStrings("1-2-3-4", results.items[0]);
    try testing.expectEqualStrings("3-4-5", results.items[1]);

    // Query logical AND (2, 5)
    results.clearRetainingCapacity();
    _ = try filter.queryLogicalAnd(allocator, &.{ 2, 5 }, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 0), results.items.len);

    // Query logical AND (3, 4)
    results.clearRetainingCapacity();
    _ = try filter.queryLogicalAnd(allocator, &.{ 3, 4 }, *std.ArrayListUnmanaged([]const u8), &results);
    try testing.expectEqual(@as(usize, 2), results.items.len);
    try testing.expectEqualStrings("1-2-3-4", results.items[0]);
    try testing.expectEqualStrings("3-4-5", results.items[1]);

    try testing.expectEqual(@as(usize, 1676), filter.sizeInBytes());
}

// TODO: serialization/deserialization tests
