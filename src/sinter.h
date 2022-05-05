#ifndef SINTER_H_
#define SINTER_H_

#if defined(SINTER_SHARED_LIBRARY)
#    if defined(_WIN32)
#        if defined(SINTER_IMPLEMENTATION)
#            define SINTER_EXPORT __declspec(dllexport)
#        else
#            define SINTER_EXPORT __declspec(dllimport)
#        endif
#    else  // defined(_WIN32)
#        if defined(SINTER_IMPLEMENTATION)
#            define SINTER_EXPORT __attribute__((visibility("default")))
#        else
#            define SINTER_EXPORT
#        endif
#    endif  // defined(_WIN32)
#else       // defined(SINTER_SHARED_LIBRARY)
#    define SINTER_EXPORT
#endif  // defined(SINTER_SHARED_LIBRARY)

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct SinterFilterImpl* SinterFilter;

typedef enum SinterError {
    /* General errors */
    SinterError_None = 0,
    SinterError_OutOfMemory = 1,

    /* IO errors, consider using sinterErrorName to deal with these */
    SinterError_IOEndOfStream = 2,
    SinterError_IOInputOutput = 3,
    SinterError_IOSystemResources = 4,
    SinterError_IOIsDir = 5,
    SinterError_IOOperationAborted = 6,
    SinterError_IOBrokenPipe = 7,
    SinterError_IOConnectionResetByPeer = 8,
    SinterError_IOConnectionTimedOut = 9,
    SinterError_IONotOpenForReading = 10,
    SinterError_IOWouldBlock = 11,
    SinterError_IOAccessDenied = 12,
    SinterError_IOUnexpected = 13,
    SinterError_IOSharingViolation = 14,
    SinterError_IOPathAlreadyExists = 15,
    SinterError_IOFileNotFound = 16,
    SinterError_IOPipeBusy = 17,
    SinterError_IONameTooLong = 18,
    SinterError_IOInvalidUtf8 = 19,
    SinterError_IOBadPathName = 20,
    SinterError_IOInvalidHandle = 21,
    SinterError_IOSymLinkLoop = 22,
    SinterError_IOProcessFdQuotaExceeded = 23,
    SinterError_IOSystemFdQuotaExceeded = 24,
    SinterError_IONoDevice = 25,
    SinterError_IOFileTooBig = 26,
    SinterError_IONoSpaceLeft = 27,
    SinterError_IONotDir = 28,
    SinterError_IODeviceBusy = 29,
    SinterError_IOFileLocksNotSupported = 30,
    SinterError_IOFileBusy = 31,
    SinterError_IONotSupported = 32,
    SinterError_IOFileSystem = 33,
    SinterError_IODiskQuota = 34,
    SinterError_IONotOpenForWriting = 35,
    SinterError_IOLinkQuotaExceeded = 36,
    SinterError_IOReadOnlyFileSystem = 37,
    SinterError_IORenameAcrossMountPoints = 38,

    SinterError_Force32 = 0x7FFFFFFF, // Force this enum to be uint32_t
} SinterError;

SINTER_EXPORT SinterError sinterFilterInit(uint64_t estimated_keys, SinterFilter* out);
SINTER_EXPORT void sinterFilterDeinit(SinterFilter f);

typedef uint64_t (*SinterIteratorCallback)(uint64_t* out_write_max_100k);
SINTER_EXPORT SinterError sinterFilterInsert(
    SinterFilter f,
    SinterIteratorCallback callback,
    uint64_t len,
    char* result,
    uint64_t result_len
);

SINTER_EXPORT SinterError sinterFilterIndex(SinterFilter f);

SINTER_EXPORT SinterError sinterFilterReadFile(char* file_path, SinterFilter* out);
SINTER_EXPORT SinterError sinterFilterWriteFile(SinterFilter f, char* file_path);

SINTER_EXPORT char* sinterErrorName(SinterError err);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // SINTER_H_