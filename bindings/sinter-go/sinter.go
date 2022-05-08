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
	"reflect"
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
		s.remaining = s.Slice // wrap around
		return nil, false
	}

	// Take the first 100k elements from s.remaining.
	maxSize := 100_000
	if maxSize > len(s.remaining) {
		maxSize = len(s.remaining)
	}

	v := s.remaining[0:maxSize]
	s.remaining = s.remaining[maxSize:]
	return v, true
}

func (s *SliceIterator) Len() uint64 {
	return uint64(len(s.Slice))
}

type Iterator interface {
	// Return the next set of keys. At maximum may return 100,000 keys.
	Next() ([]uint64, bool)
	Len() uint64
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
	for i, k := range keys {
		dst := (*uint64)(unsafe.Add(unsafe.Pointer(outWriteMax100k), i*8))
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

func (f Filter) Contains(key uint64) bool {
	//nolint:gosimple
	return C.sinterFilterContains(f.ptr, C.uint64_t(key)) == true
}

func (f Filter) SizeinBytes() uint64 {
	return uint64(C.sinterFilterSizeInBytes(f.ptr))
}

type FilterResults struct {
	ptr C.SinterFilterResults
}

func (r FilterResults) Len() int {
	return int(C.sinterFilterResultsLen(r.ptr))
}

func (r FilterResults) Index(index int) []byte {
	header := reflect.StringHeader{
		Data: uintptr(unsafe.Pointer(C.sinterFilterResultsIndexGet(r.ptr, C.uint64_t(index)))),
		Len:  int(C.sinterFilterResultsIndexLen(r.ptr, C.uint64_t(index))),
	}
	//nolint:govet
	ptr := (*string)(unsafe.Pointer(&header))
	return []byte(*ptr)
}

func (r FilterResults) Deinit() {
	C.sinterFilterResultsDeinit(r.ptr)
}

func (f Filter) QueryLogicalOr(keys []uint64) (FilterResults, error) {
	var out C.SinterFilterResults
	err := C.sinterFilterQueryLogicalOr(
		(*C.struct_SinterFilterImpl)(unsafe.Pointer(f.ptr)),
		(*C.uint64_t)(unsafe.Pointer(&keys[0])),
		C.uint64_t(len(keys)),
		&out,
	)
	return FilterResults{ptr: out}, goError(err)
}

func (f Filter) QueryLogicalAnd(keys []uint64) (FilterResults, error) {
	var out C.SinterFilterResults
	err := C.sinterFilterQueryLogicalAnd(
		(*C.struct_SinterFilterImpl)(unsafe.Pointer(f.ptr)),
		(*C.uint64_t)(unsafe.Pointer(&keys[0])),
		C.uint64_t(len(keys)),
		&out,
	)
	return FilterResults{ptr: out}, goError(err)
}

func (f Filter) QueryLogicalOrNumResults(keys []uint64) (uint64, error) {
	var out C.uint64_t
	err := C.sinterFilterQueryLogicalOrNumResults(
		(*C.struct_SinterFilterImpl)(unsafe.Pointer(f.ptr)),
		(*C.uint64_t)(unsafe.Pointer(&keys[0])),
		C.uint64_t(len(keys)),
		&out,
	)
	return uint64(out), goError(err)
}

func (f Filter) QueryLogicalAndNumResults(keys []uint64) (uint64, error) {
	var out C.uint64_t
	err := C.sinterFilterQueryLogicalAndNumResults(
		(*C.struct_SinterFilterImpl)(unsafe.Pointer(f.ptr)),
		(*C.uint64_t)(unsafe.Pointer(&keys[0])),
		C.uint64_t(len(keys)),
		&out,
	)
	return uint64(out), goError(err)
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
