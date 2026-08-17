// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"strings"
	"testing"
	"time"
)

func TestPatternListMatch(t *testing.T) {
	tests := []struct {
		name  string
		list  string
		value string
		want  bool
	}{
		{name: "exact", list: "alice@example.com", value: "alice@example.com", want: true},
		{name: "one of many", list: "alice@example.com,bob@example.com", value: "bob@example.com", want: true},
		{name: "wildcards", list: "*@example.com", value: "alice@example.com", want: true},
		{name: "question mark", list: "user?@example.com", value: "user1@example.com", want: true},
		{name: "slash is not special", list: "team/*", value: "team/release", want: true},
		{name: "negation wins", list: "*@example.com,!root@example.com", value: "root@example.com", want: false},
		{name: "negation is not positive", list: "!root@example.com", value: "alice@example.com", want: false},
		{name: "no match", list: "alice@example.com", value: "bob@example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := patternListMatch(tt.list, tt.value); got != tt.want {
				t.Fatalf("patternListMatch(%q, %q) = %v, want %v", tt.list, tt.value, got, tt.want)
			}
		})
	}
}

func TestValidatePatternList(t *testing.T) {
	for _, list := range []string{"", "alice,", ",alice", "alice,,bob", "!"} {
		if err := validatePatternList(list); err == nil {
			t.Errorf("validatePatternList(%q) unexpectedly succeeded", list)
		}
	}
}

func TestParseAndMatchPrincipalPatternList(t *testing.T) {
	const line = "alice@example.com,bob@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk\n"

	file, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	entry, err := file.MatchEntry(file.Entries[0].PublicKey, "bob@example.com", "file", time.Now())
	if err != nil {
		t.Fatalf("MatchEntry() error = %v", err)
	}
	if entry == nil {
		t.Fatal("MatchEntry() did not match a principal in the pattern-list")
	}
}

func TestParseAndMatchNamespacePatternList(t *testing.T) {
	const line = `alice@example.com NAMESPACES="file-*,!file-secret" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk` + "\n"

	file, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	publicKey := file.Entries[0].PublicKey
	entry, err := file.MatchEntry(publicKey, "alice@example.com", "file-release", time.Now())
	if err != nil {
		t.Fatalf("MatchEntry() error = %v", err)
	}
	if entry == nil {
		t.Fatal("MatchEntry() did not match a namespace pattern")
	}

	entry, err = file.MatchEntry(publicKey, "alice@example.com", "file-secret", time.Now())
	if err == nil {
		t.Fatal("MatchEntry() unexpectedly accepted a negated namespace")
	}
	if entry != nil {
		t.Fatal("MatchEntry() returned an entry for a negated namespace")
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{pattern: "", value: "", want: true},
		{pattern: "", value: "a", want: false},
		{pattern: "*", value: "", want: true},
		{pattern: "*", value: "anything", want: true},
		{pattern: "**", value: "anything", want: true},
		{pattern: "?", value: "", want: false},
		{pattern: "?", value: "a", want: true},
		{pattern: "?", value: "ab", want: false},
		{pattern: "a*b", value: "ab", want: true},
		{pattern: "a*b", value: "axxxb", want: true},
		{pattern: "a*b", value: "axxx", want: false},
		{pattern: "*b", value: "b", want: true},
		{pattern: "a*", value: "a", want: true},
		{pattern: "*@example.com", value: "@example.com", want: true},
		{pattern: "*.*", value: "a.b", want: true},
		{pattern: "a?c*", value: "abcdef", want: true},
	}

	for _, tt := range tests {
		if got := wildcardMatch(tt.pattern, tt.value); got != tt.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

// TestWildcardMatchIsNotExponential guards the matcher against patterns whose
// naive recursive form takes exponential time on a non-matching value.
func TestWildcardMatchIsNotExponential(t *testing.T) {
	pattern := strings.Repeat("*a", 24) + "*b"
	value := strings.Repeat("a", 4096)

	done := make(chan bool, 1)
	go func() { done <- wildcardMatch(pattern, value) }()

	select {
	case matched := <-done:
		if matched {
			t.Error("wildcardMatch() unexpectedly matched")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wildcardMatch() did not finish within 10s")
	}
}
