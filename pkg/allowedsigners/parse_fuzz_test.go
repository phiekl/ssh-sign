// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"bytes"
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
			_ = entry.PublicKey.Marshal()
		}
	})
}

func FuzzWildcardMatch(f *testing.F) {
	f.Add("*@example.com", "alice@example.com")
	f.Add("*a*a*a*b", "aaaaaaaa")
	f.Add("!", "value")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, pattern, value string) {
		if len(pattern) > 4096 || len(value) > 4096 {
			t.Skip()
		}
		first := wildcardMatch(pattern, value)
		if second := wildcardMatch(pattern, value); second != first {
			t.Fatalf("wildcardMatch is nondeterministic: first=%v second=%v", first, second)
		}
	})
}
