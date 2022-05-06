package sinter

import (
	"testing"
)

func TestFilter(t *testing.T) {
	filter, err := FilterInit(10_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Deinit()

	const num_results = 200            // e.g. documents we will match
	const num_keys_per_result = 50_000 // e.g. words per document, if you want "document contains word" matching only

	slice := make([]uint64, num_keys_per_result)
	for i := range slice {
		slice[i] = uint64(i)
	}
	keysIter := &SliceIterator{Slice: slice}

	for r := 0; r < num_results; r++ {
		filter.Insert(keysIter, []byte("Hello world!"))
	}

	filter.Index()

	path := "go-test.sinter"
	if err := filter.WriteFile(path); err != nil {
		t.Fatal(err)
	}

	read, err := FilterReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = read
}
