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
		{name: "negation applies to a literal star", list: "*x*,!*blocked", value: "*xblocked", want: false},
		{name: "negation applies to a leading star", list: "?*,!*blocked", value: "*xblocked", want: false},
		{name: "bare wildcard spans a literal star", list: "*", value: "*weird", want: true},
		// Also cover positive matching when the value contains '*'.
		{name: "negated literal star stays denied", list: "*,!*blocked", value: "*xblocked", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := patternListMatch(tt.list, tt.value); got != tt.want {
				t.Fatalf("patternListMatch(%q, %q) = %v, want %v", tt.list, tt.value, got, tt.want)
			}
		})
	}
}

// Empty pattern elements cannot match nonempty principals or namespaces.
func TestEmptyPatternsAreInert(t *testing.T) {
	for _, list := range []string{"alice,", ",alice", "alice,,bob"} {
		if !patternListMatch(list, "alice") {
			t.Errorf("patternListMatch(%q, %q) = false, want true", list, "alice")
		}
		if patternListMatch(list, "carol") {
			t.Errorf("patternListMatch(%q, %q) = true, want false", list, "carol")
		}
	}
	// A bare "!" negates the empty pattern, so it matches nothing either way.
	if patternListMatch("!", "alice") {
		t.Error(`patternListMatch("!", "alice") = true, want false`)
	}
}

// An empty namespaces value remains a restriction rather than leaving the
// entry unrestricted. No valid signature has an empty namespace, so the entry
// cannot match during signature verification.
func TestParseRestrictsAnEmptyNamespacesValue(t *testing.T) {
	f, err := Parse(strings.NewReader(`alice@example.com namespaces="" ` + testKey + "\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(f.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(f.Entries))
	}

	// A nil list means no restriction, which would authorise every namespace.
	got := f.Entries[0].Options.Namespaces
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("Namespaces = %#v, want [\"\"]", got)
	}

	for ns, want := range map[string]bool{"file": false, "": true} {
		entry, err := f.MatchEntry(
			f.Entries[0].PublicKey, "alice@example.com", ns, time.Now(),
		)
		if want && err != nil {
			t.Errorf("MatchEntry(%q) error = %v, want nil", ns, err)
		}
		if (entry != nil) != want {
			t.Errorf("MatchEntry(%q) matched = %v, want %v", ns, entry != nil, want)
		}
	}
}

// Accept empty elements in both principal and namespace lists.
func TestParseAcceptsEmptyPatterns(t *testing.T) {
	for name, line := range map[string]string{
		"principals": "alice@example.com,,bob@example.com " + testKey,
		"namespaces": `alice@example.com namespaces="git,,email" ` + testKey,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(strings.NewReader(line + "\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(f.Entries) != 1 {
				t.Fatalf("len(Entries) = %d, want 1", len(f.Entries))
			}
			entry, err := f.MatchEntry(
				f.Entries[0].PublicKey, "alice@example.com", "git", time.Now(),
			)
			if err != nil {
				t.Fatalf("MatchEntry() error = %v", err)
			}
			if entry == nil {
				t.Error("MatchEntry() did not match past an empty pattern")
			}
		})
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
	const line = `alice@example.com namespaces="file-*,!file-secret" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk` + "\n"

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

// A literal '*' in the namespace must not bypass a wildcard exclusion.
func TestParseAndMatchNamespaceNegationWithLiteralStar(t *testing.T) {
	const line = `alice@example.com namespaces="*x*,!*blocked" ` + testKey + "\n"

	file, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	publicKey := file.Entries[0].PublicKey

	entry, err := file.MatchEntry(publicKey, "alice@example.com", "*xblocked", time.Now())
	if err == nil {
		t.Fatal("MatchEntry() unexpectedly accepted a namespace escaping a negation")
	}
	if entry != nil {
		t.Fatal("MatchEntry() returned an entry for an excluded namespace")
	}

	entry, err = file.MatchEntry(publicKey, "alice@example.com", "*xweird", time.Now())
	if err != nil {
		t.Fatalf("MatchEntry() error = %v", err)
	}
	if entry == nil {
		t.Fatal("MatchEntry() did not match a namespace holding a literal '*'")
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
		// Only pattern bytes have wildcard meaning.
		{pattern: "*", value: "*", want: true},
		{pattern: "*", value: "*xb", want: true},
		{pattern: "*b", value: "*ab", want: true},
		{pattern: "a*b", value: "a*xb", want: true},
		{pattern: "*x", value: "**x", want: true},
		{pattern: "*blocked", value: "*xblocked", want: true},
		{pattern: "?", value: "*", want: true},
		{pattern: "a*b", value: "a*b", want: true},
		{pattern: "a*b", value: "a**xb", want: true},
		{pattern: "?*", value: "*", want: true},
		{pattern: "*?", value: "*", want: true},
		{pattern: "a*", value: "*a", want: false},
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
