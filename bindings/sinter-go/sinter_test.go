package sinter

import "testing"

func TestFilter(t *testing.T) {
	filter, err := FilterInit(100_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Deinit()
}
