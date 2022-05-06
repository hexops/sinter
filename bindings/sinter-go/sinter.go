package sinter

/*
#cgo CFLAGS: -I${SRCDIR}/../../src/ -I.
#cgo LDFLAGS: -L${SRCDIR}/../../zig-out/lib -lsinter
#include <sinter.h>
#include <stdlib.h>

uint64_t sinterGoIteratorCallback(SinterFilter f, uint64_t* out_write_max_100k, void* userdata);
*/
import "C"

import (
	"errors"
	"unsafe"
)

var inserts = map[C.SinterFilter][]Iterator{}

type Filter struct {
	ptr C.SinterFilter
}

func FilterInit(estimatedKeys uint64) (Filter, error) {
	var f C.SinterFilter
	err := C.sinterFilterInit(C.uint64_t(estimatedKeys), &f)
	return Filter{ptr: f}, goError(err)
}

func FilterReadFile(file_path string) (Filter, error) {
	cs := C.CString(file_path)
	defer C.free(unsafe.Pointer(cs))

	var f C.SinterFilter
	err := C.sinterFilterReadFile(cs, &f)
	return Filter{ptr: f}, goError(err)
}

func (f Filter) Deinit() {
	delete(inserts, f.ptr)
	C.sinterFilterDeinit(f.ptr)
}

type SliceIterator struct {
	Slice     []uint64
	remaining []uint64
}

func (s *SliceIterator) Next() ([]uint64, bool) {
	if s.remaining == nil {
		s.remaining = s.Slice
	}
	if len(s.remaining) == 0 {
		return nil, false
	}

	// Take the first 100k elements from s.remaining.
	maxSize := 100_000
	if maxSize > len(s.remaining) {
		maxSize = len(s.remaining)
	}

	v := s.remaining[0:maxSize]
	s.remaining = s.remaining[maxSize:]
	return v, false
}

func (s *SliceIterator) Len() uint64 {
	return uint64(len(s.Slice))
}

type Iterator interface {
	// Return the next set of keys. At maximum may return 100,000 keys.
	Next() ([]uint64, bool)
	Len() uint64
}

type insert struct {
	iter   Iterator
	result []byte
}

func (f Filter) Insert(iter Iterator, result []byte) error {
	// Retain memory so Go GC does not get rid of it.
	inserts[f.ptr] = append(inserts[f.ptr], iter)
	insertIndex := len(inserts[f.ptr]) - 1

	return goError(C.sinterFilterInsert(
		(*C.struct_SinterFilterImpl)(unsafe.Pointer(f.ptr)),
		(*[0]byte)(C.sinterGoIteratorCallback),
		C.uint64_t(iter.Len()),
		(*C.char)(unsafe.Pointer(&result[0])),
		C.uint64_t(len(result)),
		unsafe.Pointer(uintptr(insertIndex)),
	))
}

//export sinterGoIteratorCallback
func sinterGoIteratorCallback(filter C.SinterFilter, outWriteMax100k *uint64, userdata unsafe.Pointer) uint64 {
	insertIndex := int(uintptr(userdata))
	iter := inserts[filter][insertIndex]

	keys, ok := iter.Next()
	if !ok {
		return 0
	}
	if len(keys) > 100_000 {
		panic("sinter: illegal sinter.Iterator returned >100,000 keys")
	}
	for _, k := range keys {
		dst := (*uint64)(unsafe.Add(unsafe.Pointer(outWriteMax100k), 1))
		*dst = k
	}
	return uint64(len(keys))
}

func (f Filter) Index() error {
	return goError(C.sinterFilterIndex(f.ptr))
}

func (f Filter) WriteFile(file_path string) error {
	cs := C.CString(file_path + "\x00")
	defer C.free(unsafe.Pointer(cs))
	return goError(C.sinterFilterWriteFile(f.ptr, cs))
}

var ErrOutOfMemory = errors.New("out of memory")

type IOError struct {
	Code C.SinterError
	Msg  string
}

func (e IOError) Error() string { return e.Msg }

func goError(err C.SinterError) error {
	switch err {
	case C.SinterError_None:
		return nil
	case C.SinterError_OutOfMemory:
		return ErrOutOfMemory
	default:
		return IOError{Code: err, Msg: C.GoString(C.sinterErrorName(err))}
	}

}
