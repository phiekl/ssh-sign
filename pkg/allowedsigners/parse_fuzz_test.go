// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("alice@example.com " + testKey + "\n"))
	f.Add([]byte(`alice@example.com namespaces="file,!secret" ` + testKey + ` owner "laptop` + "\n"))
	f.Add([]byte(`alice@example.com namespaces="unterminated ` + testKey + "\n"))
	f.Add([]byte("# comment\n\n"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		parsed, _ := parseWithMaxLineSize(bytes.NewReader(input), 64*1024)
		if parsed == nil {
			return
		}
		for i := range parsed.Entries {
			entry := &parsed.Entries[i]
			if entry.PublicKey == nil {
				t.Fatalf("entry %d has a nil public key", i)
			}
			if entry.Principal == "" {
				t.Fatalf("entry %d has an empty principal", i)
			}
			_ = entry.PublicKey.Marshal()
		}
		// Count all skipped lines, but bound retained diagnostics.
		if len(parsed.Skipped) > maxSkippedRecorded {
			t.Fatalf("recorded %d skipped lines, want at most %d",
				len(parsed.Skipped), maxSkippedRecorded)
		}
		if parsed.SkippedCount < len(parsed.Skipped) {
			t.Fatalf("SkippedCount is %d, below the %d recorded",
				parsed.SkippedCount, len(parsed.Skipped))
		}
	})
}

// naiveWildcardMatch is a recursive oracle for wildcardMatch. Memoising suffix
// pairs avoids exponential runtime; only pattern bytes have wildcard meaning.
func naiveWildcardMatch(pattern, value string) bool {
	memo := make(map[[2]int]bool)

	var match func(p, v int) bool
	match = func(p, v int) bool {
		if p == len(pattern) {
			return v == len(value)
		}
		key := [2]int{p, v}
		if got, ok := memo[key]; ok {
			return got
		}

		var result bool
		switch pattern[p] {
		case '*':
			// The star either stops here or swallows one more byte.
			result = match(p+1, v) || (v < len(value) && match(p, v+1))
		case '?':
			result = v < len(value) && match(p+1, v+1)
		default:
			result = v < len(value) && value[v] == pattern[p] && match(p+1, v+1)
		}

		memo[key] = result
		return result
	}
	return match(0, 0)
}

func FuzzWildcardMatch(f *testing.F) {
	f.Add("*@example.com", "alice@example.com")
	f.Add("*a*a*a*b", "aaaaaaaa")
	f.Add("!", "value")
	f.Add("", "")
	f.Add("*blocked", "*xblocked")
	// Guard against exponential runtime in the oracle.
	f.Add(strings.Repeat("*", 64)+"b", strings.Repeat("a", 256))
	f.Add(strings.Repeat("*?", 64)+"*b", strings.Repeat("a", 256))

	f.Fuzz(func(t *testing.T, pattern, value string) {
		if len(pattern) > 4096 || len(value) > 4096 {
			t.Skip()
		}
		first := wildcardMatch(pattern, value)
		if second := wildcardMatch(pattern, value); second != first {
			t.Fatalf("wildcardMatch is nondeterministic: first=%v second=%v", first, second)
		}
		// Cap the cross-check's O(len(pattern)*len(value)) work.
		if len(pattern) > 256 || len(value) > 256 {
			return
		}
		if want := naiveWildcardMatch(pattern, value); first != want {
			t.Fatalf("wildcardMatch(%q, %q) = %v, want %v", pattern, value, first, want)
		}
	})
}
