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

	assertEqual := func(a, b any) {
		t.Helper()
		if a != b {
			t.Fatalf("assert failed: %v == %v", a, b)
		}
	}

	assertEqual(filter.Contains(4), true)
	originalSizeinBytes := filter.SizeinBytes()

	path := "go-test.sinter"
	if err := filter.WriteFile(path); err != nil {
		t.Fatal(err)
	}

	read, err := FilterReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Deinit()

	assertEqual(read.Contains(4), true)
	assertEqual(read.SizeinBytes(), originalSizeinBytes)

	{
		results, err := read.QueryLogicalAnd([]uint64{4, 10, 15})
		if err != nil {
			t.Fatal(err)
		}
		defer results.Deinit()
		assertEqual(results.Len(), 200)
		assertEqual(string(results.Index(0)), "Hello world!")
	}

	{
		results, err := read.QueryLogicalOr([]uint64{10, 10928301982301982301})
		if err != nil {
			t.Fatal(err)
		}
		defer results.Deinit()
		assertEqual(results.Len(), 200)
		assertEqual(string(results.Index(0)), "Hello world!")
	}

	{
		numResults, err := read.QueryLogicalAndNumResults([]uint64{4, 10, 15})
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(numResults, uint64(200))
	}

	{
		numResults, err := read.QueryLogicalOrNumResults([]uint64{10, 10928301982301982301})
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(numResults, uint64(200))
	}

}
