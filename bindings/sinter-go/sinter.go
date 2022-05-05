package sinter

// #cgo CFLAGS: -I${SRCDIR}/../../src/ -I.
// #cgo LDFLAGS: -L${SRCDIR}/../../zig-out/lib -lsinter
// #include <sinter.h>
import "C"

import (
	"errors"
)

type Filter struct {
	ptr C.SinterFilter
}

func FilterInit(estimatedKeys uint64) (Filter, error) {
	var f C.SinterFilter
	err := C.sinterFilterInit(C.uint64_t(estimatedKeys), &f)
	return Filter{ptr: f}, goError(err)
}

func (f Filter) Deinit() {
	C.sinterFilterDeinit(f.ptr)
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
