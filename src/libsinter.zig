const std = @import("std");
const sinter = @import("main.zig");

const SinterFilter = *anyopaque;

const SinterFilterImpl = struct {
    filter: CFilterType,
    iterator_buf: [100_000]u64 = undefined,
};

const CFilterType = sinter.Filter(.{}, []const u8, *CCallbackIterator);

const SinterIterator = fn (f: SinterFilter, out_write_max_100k: *u64, userdata: *anyopaque) callconv(.C) u64;

const CCallbackIterator = struct {
    filter: SinterFilter,
    userdata: *anyopaque,
    callback: SinterIterator,
    length: usize,
    buf: *[100_000]u64,
    remaining: []u64 = &.{},
    result: []const u8,

    pub inline fn next(iter: *CCallbackIterator) ?u64 {
        if (iter.remaining.len > 0) {
            var v = iter.remaining[0];
            iter.remaining = iter.remaining[1..];
            return v;
        }

        var written = iter.callback(iter.filter, &iter.buf[0], iter.userdata);
        if (written == 0) {
            return null;
        }
        var v = iter.buf[0];
        if (written > 1) iter.remaining = iter.buf[1..written];
        return v;
    }

    pub inline fn len(iter: *const CCallbackIterator) usize {
        return iter.length;
    }

    // TODO: call deinit on iterators
    pub inline fn deinit(iter: *CCallbackIterator) void {
        const allocator = std.heap.c_allocator;
        allocator.free(iter.result);
        allocator.destroy(iter);
    }
};

export fn sinterFilterInit(estimated_keys: u64, out: *SinterFilter) SinterError {
    const allocator = std.heap.c_allocator;
    const ptr = allocator.create(SinterFilterImpl) catch return SinterError.OutOfMemory;
    errdefer allocator.destroy(ptr);
    ptr.* = SinterFilterImpl{
        .filter = CFilterType.init(@intCast(usize, estimated_keys)),
    };
    out.* = ptr;
    return SinterError.None;
}

export fn sinterFilterDeinit(c_filter: SinterFilter) void {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));
    filter.filter.deinit(allocator);
    allocator.destroy(filter);
}

export fn sinterFilterInsert(c_filter: SinterFilter, callback: SinterIterator, len: u64, result: [*]const u8, result_len: u64, userdata: *anyopaque) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));

    const ptr = allocator.create(CCallbackIterator) catch return SinterError.OutOfMemory;
    errdefer allocator.destroy(ptr);

    // TODO: provide a non-copying API for non-Go clients?
    const result_copy = allocator.alloc(u8, result_len) catch return SinterError.OutOfMemory;
    errdefer allocator.free(result_copy);
    std.mem.copy(u8, result_copy, result[0..result_len]);

    ptr.* = CCallbackIterator{
        .filter = c_filter,
        .userdata = userdata,
        .callback = callback,
        .length = @intCast(usize, len),
        .buf = &filter.iterator_buf,
        .result = result_copy,
    };
    filter.filter.insert(allocator, ptr, result_copy) catch |err| return errorToCError(err);
    return SinterError.None;
}

export fn sinterFilterIndex(c_filter: SinterFilter) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));
    filter.filter.index(allocator) catch |err| return switch (err) {
        error.OutOfMemory => SinterError.OutOfMemory,
        error.KeysLikelyNotUnique => unreachable,
    };
    return SinterError.None;
}

export fn sinterFilterReadFile(file_path: [*:0]const u8, out: *SinterFilter) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = CFilterType.readFile(allocator, std.mem.span(file_path)) catch |err| return errorToCError(err);
    errdefer filter.deinit(allocator);
    const ptr = allocator.create(SinterFilterImpl) catch return SinterError.OutOfMemory;
    errdefer allocator.destroy(ptr);
    ptr.* = SinterFilterImpl{ .filter = filter };
    out.* = ptr;
    return SinterError.None;
}

export fn sinterFilterWriteFile(c_filter: SinterFilter, file_path: [*:0]const u8) SinterError {
    const allocator = std.heap.c_allocator;

    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));
    filter.filter.writeFile(allocator, std.fs.cwd(), std.mem.span(file_path)) catch |err| return errorToCError(err);
    return SinterError.None;
}

export fn sinterFilterContains(c_filter: SinterFilter, key: u64) bool {
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));
    return filter.filter.contains(key);
}

export fn sinterFilterSizeInBytes(c_filter: SinterFilter) u64 {
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));
    return filter.filter.sizeInBytes() + @sizeOf([100_000]u64);
}

const SinterFilterResults = *anyopaque;

export fn sinterFilterResultsLen(c_results: SinterFilterResults) u64 {
    const results = @ptrCast(*std.ArrayListUnmanaged([]const u8), @alignCast(@alignOf(std.ArrayListUnmanaged([]const u8)), c_results));
    return results.items.len;
}

export fn sinterFilterResultsIndexLen(c_results: SinterFilterResults, index: u64) u64 {
    const results = @ptrCast(*std.ArrayListUnmanaged([]const u8), @alignCast(@alignOf(std.ArrayListUnmanaged([]const u8)), c_results));
    return results.items[index].len;
}

export fn sinterFilterResultsIndexGet(c_results: SinterFilterResults, index: u64) [*]const u8 {
    const results = @ptrCast(*std.ArrayListUnmanaged([]const u8), @alignCast(@alignOf(std.ArrayListUnmanaged([]const u8)), c_results));
    return results.items[index].ptr;
}

export fn sinterFilterResultsDeinit(c_results: SinterFilterResults) void {
    const allocator = std.heap.c_allocator;
    const results = @ptrCast(*std.ArrayListUnmanaged([]const u8), @alignCast(@alignOf(std.ArrayListUnmanaged([]const u8)), c_results));
    results.deinit(allocator);
}

export fn sinterFilterQueryLogicalOr(c_filter: SinterFilter, or_keys: [*]u64, or_keys_len: u64, out_results: *SinterFilterResults) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));

    const ptr = allocator.create(std.ArrayListUnmanaged([]const u8)) catch return SinterError.OutOfMemory;
    ptr.* = std.ArrayListUnmanaged([]const u8){};
    errdefer ptr.*.deinit(allocator);
    errdefer allocator.destroy(ptr);
    out_results.* = ptr;

    _ = filter.filter.queryLogicalOr(
        allocator,
        or_keys[0..or_keys_len],
        *std.ArrayListUnmanaged([]const u8),
        ptr,
    ) catch |err| return errorToCError(err);
    return SinterError.None;
}

export fn sinterFilterQueryLogicalAnd(c_filter: SinterFilter, and_keys: [*]u64, and_keys_len: u64, out_results: *SinterFilterResults) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));

    const ptr = allocator.create(std.ArrayListUnmanaged([]const u8)) catch return SinterError.OutOfMemory;
    ptr.* = std.ArrayListUnmanaged([]const u8){};
    errdefer ptr.*.deinit(allocator);
    errdefer allocator.destroy(ptr);
    out_results.* = ptr;

    _ = filter.filter.queryLogicalAnd(
        allocator,
        and_keys[0..and_keys_len],
        *std.ArrayListUnmanaged([]const u8),
        ptr,
    ) catch |err| return errorToCError(err);
    return SinterError.None;
}

export fn sinterFilterQueryLogicalOrNumResults(c_filter: SinterFilter, or_keys: [*]u64, or_keys_len: u64, out_num_results: *u64) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));

    out_num_results.* = filter.filter.queryLogicalOr(
        allocator,
        or_keys[0..or_keys_len],
        *std.ArrayListUnmanaged([]const u8),
        null,
    ) catch |err| return errorToCError(err);
    return SinterError.None;
}

export fn sinterFilterQueryLogicalAndNumResults(c_filter: SinterFilter, and_keys: [*]u64, and_keys_len: u64, out_num_results: *u64) SinterError {
    const allocator = std.heap.c_allocator;
    const filter = @ptrCast(*SinterFilterImpl, @alignCast(@alignOf(SinterFilterImpl), c_filter));

    out_num_results.* = filter.filter.queryLogicalAnd(
        allocator,
        and_keys[0..and_keys_len],
        *std.ArrayListUnmanaged([]const u8),
        null,
    ) catch |err| return errorToCError(err);
    return SinterError.None;
}

export fn sinterErrorName(err: SinterError) [*:0]const u8 {
    return @errorName(cErrorToError(err));
}

const AnyError = std.fs.File.OpenError ||
    std.os.ReadError ||
    std.mem.Allocator.Error ||
    std.os.RealPathError ||
    std.os.WriteError ||
    std.os.RenameError ||
    error{ EndOfStream, None };

fn errorToCError(err: AnyError) SinterError {
    return switch (err) {
        error.None => SinterError.None,
        error.OutOfMemory => SinterError.OutOfMemory,
        error.EndOfStream => SinterError.IOEndOfStream,
        error.InputOutput => SinterError.IOInputOutput,
        error.SystemResources => SinterError.IOSystemResources,
        error.IsDir => SinterError.IOIsDir,
        error.OperationAborted => SinterError.IOOperationAborted,
        error.BrokenPipe => SinterError.IOBrokenPipe,
        error.ConnectionResetByPeer => SinterError.IOConnectionResetByPeer,
        error.ConnectionTimedOut => SinterError.IOConnectionTimedOut,
        error.NotOpenForReading => SinterError.IONotOpenForReading,
        error.WouldBlock => SinterError.IOWouldBlock,
        error.AccessDenied => SinterError.IOAccessDenied,
        error.Unexpected => SinterError.IOUnexpected,
        error.SharingViolation => SinterError.IOSharingViolation,
        error.PathAlreadyExists => SinterError.IOPathAlreadyExists,
        error.FileNotFound => SinterError.IOFileNotFound,
        error.PipeBusy => SinterError.IOPipeBusy,
        error.NameTooLong => SinterError.IONameTooLong,
        error.InvalidUtf8 => SinterError.IOInvalidUtf8,
        error.BadPathName => SinterError.IOBadPathName,
        error.InvalidHandle => SinterError.IOInvalidHandle,
        error.SymLinkLoop => SinterError.IOSymLinkLoop,
        error.ProcessFdQuotaExceeded => SinterError.IOProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded => SinterError.IOSystemFdQuotaExceeded,
        error.NoDevice => SinterError.IONoDevice,
        error.FileTooBig => SinterError.IOFileTooBig,
        error.NoSpaceLeft => SinterError.IONoSpaceLeft,
        error.NotDir => SinterError.IONotDir,
        error.DeviceBusy => SinterError.IODeviceBusy,
        error.FileLocksNotSupported => SinterError.IOFileLocksNotSupported,
        error.FileBusy => SinterError.IOFileBusy,
        error.NotSupported => SinterError.IONotSupported,
        error.FileSystem => SinterError.IOFileSystem,
        error.DiskQuota => SinterError.IODiskQuota,
        error.NotOpenForWriting => SinterError.IONotOpenForWriting,
        error.LinkQuotaExceeded => SinterError.IOLinkQuotaExceeded,
        error.ReadOnlyFileSystem => SinterError.IOReadOnlyFileSystem,
        error.RenameAcrossMountPoints => SinterError.IORenameAcrossMountPoints,
    };
}

fn cErrorToError(err: SinterError) AnyError {
    return switch (err) {
        SinterError.None => error.None,
        SinterError.OutOfMemory => error.OutOfMemory,
        SinterError.IOEndOfStream => error.EndOfStream,
        SinterError.IOInputOutput => error.InputOutput,
        SinterError.IOSystemResources => error.SystemResources,
        SinterError.IOIsDir => error.IsDir,
        SinterError.IOOperationAborted => error.OperationAborted,
        SinterError.IOBrokenPipe => error.BrokenPipe,
        SinterError.IOConnectionResetByPeer => error.ConnectionResetByPeer,
        SinterError.IOConnectionTimedOut => error.ConnectionTimedOut,
        SinterError.IONotOpenForReading => error.NotOpenForReading,
        SinterError.IOWouldBlock => error.WouldBlock,
        SinterError.IOAccessDenied => error.AccessDenied,
        SinterError.IOUnexpected => error.Unexpected,
        SinterError.IOSharingViolation => error.SharingViolation,
        SinterError.IOPathAlreadyExists => error.PathAlreadyExists,
        SinterError.IOFileNotFound => error.FileNotFound,
        SinterError.IOPipeBusy => error.PipeBusy,
        SinterError.IONameTooLong => error.NameTooLong,
        SinterError.IOInvalidUtf8 => error.InvalidUtf8,
        SinterError.IOBadPathName => error.BadPathName,
        SinterError.IOInvalidHandle => error.InvalidHandle,
        SinterError.IOSymLinkLoop => error.SymLinkLoop,
        SinterError.IOProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        SinterError.IOSystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        SinterError.IONoDevice => error.NoDevice,
        SinterError.IOFileTooBig => error.FileTooBig,
        SinterError.IONoSpaceLeft => error.NoSpaceLeft,
        SinterError.IONotDir => error.NotDir,
        SinterError.IODeviceBusy => error.DeviceBusy,
        SinterError.IOFileLocksNotSupported => error.FileLocksNotSupported,
        SinterError.IOFileBusy => error.FileBusy,
        SinterError.IONotSupported => error.NotSupported,
        SinterError.IOFileSystem => error.FileSystem,
        SinterError.IODiskQuota => error.DiskQuota,
        SinterError.IONotOpenForWriting => error.NotOpenForWriting,
        SinterError.IOLinkQuotaExceeded => error.LinkQuotaExceeded,
        SinterError.IOReadOnlyFileSystem => error.ReadOnlyFileSystem,
        SinterError.IORenameAcrossMountPoints => error.RenameAcrossMountPoints,
    };
}

const SinterError = enum(u32) {
    None,
    OutOfMemory,

    IOEndOfStream,
    IOInputOutput,
    IOSystemResources,
    IOIsDir,
    IOOperationAborted,
    IOBrokenPipe,
    IOConnectionResetByPeer,
    IOConnectionTimedOut,
    IONotOpenForReading,
    IOWouldBlock,
    IOAccessDenied,
    IOUnexpected,
    IOSharingViolation,
    IOPathAlreadyExists,
    IOFileNotFound,
    IOPipeBusy,
    IONameTooLong,
    IOInvalidUtf8,
    IOBadPathName,
    IOInvalidHandle,
    IOSymLinkLoop,
    IOProcessFdQuotaExceeded,
    IOSystemFdQuotaExceeded,
    IONoDevice,
    IOFileTooBig,
    IONoSpaceLeft,
    IONotDir,
    IODeviceBusy,
    IOFileLocksNotSupported,
    IOFileBusy,
    IONotSupported,
    IOFileSystem,
    IODiskQuota,
    IONotOpenForWriting,
    IOLinkQuotaExceeded,
    IOReadOnlyFileSystem,
    IORenameAcrossMountPoints,
};

test {
    _ = CCallbackIterator;
    _ = sinterFilterInit;
    _ = sinterFilterDeinit;
    _ = sinterFilterInsert;
    _ = sinterFilterIndex;
    _ = sinterFilterReadFile;
    _ = sinterFilterWriteFile;
    _ = errorToCError;
    _ = cErrorToError;
}
