// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"strings"
	"testing"
)

type sample struct {
	Name    string `json:"name"`
	Count   int    `json:"count"`
	Skipped string `json:"-"`
}

func TestResultFormatKV(t *testing.T) {
	got := ResultFormatKV(
		sample{Name: "alice", Count: 3, Skipped: "hidden"},
		-6, " ", "= ", "",
		"name", "count",
	)
	want := " name  = alice\n count = 3"
	if got != want {
		t.Errorf("ResultFormatKV() =\n%q\nwant\n%q", got, want)
	}
}

func TestResultFormatKVUsesTheKeyPrefixInOutputOnly(t *testing.T) {
	got := ResultFormatKV(sample{Name: "alice"}, -10, " ", "| ", "user_", "name")
	if want := " user_name | alice"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}

func TestResultFormatKVFlagsAnUnknownKey(t *testing.T) {
	got := ResultFormatKV(sample{Name: "alice"}, -6, " ", "= ", "", "nope")
	if !strings.Contains(got, "no such key: nope") {
		t.Errorf("ResultFormatKV() = %q, want it to flag the missing key", got)
	}
	// A field excluded from JSON is just as unreachable.
	got = ResultFormatKV(sample{Skipped: "hidden"}, -6, " ", "= ", "", "Skipped")
	if !strings.Contains(got, "no such key: Skipped") {
		t.Errorf("ResultFormatKV() = %q, want it to flag the missing key", got)
	}
}

func TestResultFormatKVRendersLargeNumbersLiterally(t *testing.T) {
	got := ResultFormatKV(
		struct {
			Big int64 `json:"big"`
		}{Big: 1000000},
		-4, "", "= ", "",
		"big",
	)
	if want := "big = 1000000"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}
