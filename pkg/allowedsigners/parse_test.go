// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"strings"
	"testing"
	"time"
)

// testKey is an ssh-ed25519 public key in authorized_keys format.
const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk"

// parseLines parses the given lines, failing the test if parsing does not.
func parseLines(t *testing.T, lines ...string) *File {
	t.Helper()
	f, err := Parse(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return f
}

func TestParseSkipsBlankAndCommentLines(t *testing.T) {
	f := parseLines(t,
		"",
		"   ",
		"# a comment",
		"   # an indented comment",
		"alice@example.com "+testKey,
	)

	if len(f.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(f.Entries))
	}
	// Line numbers must count skipped lines so errors point at the real line.
	if f.Entries[0].Line != 5 {
		t.Errorf("Line = %d, want 5", f.Entries[0].Line)
	}
}

func TestParseEntryFields(t *testing.T) {
	f := parseLines(t, "alice@example.com "+testKey+"  trailing comment")

	entry := f.Entries[0]
	if entry.Principal != "alice@example.com" {
		t.Errorf("Principal = %q, want %q", entry.Principal, "alice@example.com")
	}
	if entry.KeyType != "ssh-ed25519" {
		t.Errorf("KeyType = %q, want %q", entry.KeyType, "ssh-ed25519")
	}
	if entry.Comment != "trailing comment" {
		t.Errorf("Comment = %q, want %q", entry.Comment, "trailing comment")
	}
	if entry.PublicKey == nil {
		t.Error("PublicKey = nil, want a parsed key")
	}
}

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name    string
		options string
		want    []string
	}{
		{name: "quoted list", options: `namespaces="git,email"`, want: []string{"git", "email"}},
		{name: "unquoted single", options: `namespaces=git`, want: []string{"git"}},
		{name: "uppercase key", options: `NAMESPACES="git"`, want: []string{"git"}},
		{name: "space inside quotes", options: `namespaces="a b"`, want: []string{"a b"}},
		{
			name:    "alongside other options",
			options: `namespaces="git",valid-after="20260101"`,
			want:    []string{"git"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseLines(t, "alice@example.com "+tt.options+" "+testKey)

			got := f.Entries[0].Options.Namespaces
			if len(got) != len(tt.want) {
				t.Fatalf("Namespaces = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Namespaces = %q, want %q", got, tt.want)
					break
				}
			}
		})
	}
}

func TestParseValidityOptions(t *testing.T) {
	f := parseLines(t,
		`alice@example.com valid-after="20260101",valid-before="20260201Z" `+testKey,
	)

	options := f.Entries[0].Options
	if options.ValidAfter == nil || options.ValidBefore == nil {
		t.Fatalf("ValidAfter = %v, ValidBefore = %v, want both set",
			options.ValidAfter, options.ValidBefore)
	}
	// A zoneless timestamp is local, a trailing Z makes it UTC.
	if _, offset := options.ValidAfter.Zone(); offset != localOffset(t, *options.ValidAfter) {
		t.Errorf("ValidAfter zone offset = %d, want the local offset", offset)
	}
	if _, offset := options.ValidBefore.Zone(); offset != 0 {
		t.Errorf("ValidBefore zone offset = %d, want 0 (UTC)", offset)
	}
}

// localOffset returns the local zone offset in effect at t.
func localOffset(t *testing.T, at time.Time) int {
	t.Helper()
	_, offset := at.In(time.Local).Zone()
	return offset
}

func TestParseRejectsMalformedLines(t *testing.T) {
	tests := map[string]string{
		"too few fields":          "alice@example.com",
		"missing key":             "alice@example.com ssh-ed25519",
		"options but no key":      `alice@example.com namespaces="git" ssh-ed25519`,
		"key type mismatch":       "alice@example.com ssh-rsa " + strings.Fields(testKey)[1],
		"invalid key":             "alice@example.com ssh-ed25519 not-base64!",
		"unknown option":          `alice@example.com bogus="x" ` + testKey,
		"cert-authority":          "alice@example.com cert-authority " + testKey,
		"unterminated quote":      `alice@example.com namespaces="git ` + testKey,
		"empty principal in list": "alice@example.com,, " + testKey,
		"bad valid-after":         `alice@example.com valid-after="nonsense" ` + testKey,
	}

	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(line + "\n")); err == nil {
				t.Errorf("Parse(%q) unexpectedly succeeded", line)
			}
		})
	}
}

// TestParseAcceptsAFileWithoutEntries covers a file that authorises nobody. It
// is well-formed, so it must not read as malformed input; the lookup simply
// finds no signer, as it does under ssh-keygen.
func TestParseAcceptsAFileWithoutEntries(t *testing.T) {
	for name, content := range map[string]string{
		"empty":         "",
		"blank lines":   "\n\n   \n",
		"comments only": "# nothing here\n",
	} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(strings.NewReader(content))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(f.Entries) != 0 {
				t.Fatalf("len(Entries) = %d, want 0", len(f.Entries))
			}

			key := parseLines(t, "alice@example.com "+testKey).Entries[0].PublicKey
			entry, err := f.MatchEntry(key, "alice@example.com", "git", time.Now())
			if err != nil {
				t.Errorf("MatchEntry() error = %v, want nil", err)
			}
			if entry != nil {
				t.Errorf("MatchEntry() = %v, want no entry", entry)
			}
		})
	}
}

func TestParseReportsTheOffendingLineNumber(t *testing.T) {
	_, err := Parse(strings.NewReader(
		"alice@example.com " + testKey + "\n" +
			"# comment\n" +
			"broken\n",
	))
	if err == nil {
		t.Fatal("Parse() unexpectedly succeeded")
	}

	parseErr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("Parse() error is %T, want *ParseError", err)
	}
	if parseErr.Line != 3 {
		t.Errorf("Line = %d, want 3", parseErr.Line)
	}
}

// TestParseEscapesOptionValuesLikeOpenSSH pins the escaping rule to the one
// OpenSSH implements in opt_dequote(): a backslash is only an escape when it
// precedes a quote, and is a literal character everywhere else.
func TestParseEscapesOptionValuesLikeOpenSSH(t *testing.T) {
	tests := map[string]string{
		// A backslash before a non-quote survives, so these hold two and four
		// literal backslashes respectively.
		`namespaces="a\\b"`:   `a\\b`,
		`namespaces="a\\\\b"`: `a\\\\b`,
		// Only a backslash before a quote is consumed.
		`namespaces="a\"b"`:   `a"b`,
		`namespaces="a\\\"b"`: `a\\"b`,
		`namespaces="plain"`:  "plain",
		`namespaces=unquoted`: "unquoted",
		`namespaces=a\b`:      `a\b`,
	}

	for options, want := range tests {
		t.Run(options, func(t *testing.T) {
			f := parseLines(t, "alice@example.com "+options+" "+testKey)

			got := f.Entries[0].Options.Namespaces
			if len(got) != 1 || got[0] != want {
				t.Errorf("Namespaces = %q, want [%q]", got, want)
			}
		})
	}
}

// TestParseRejectsAQuoteEscapedAtTheEndOfAValue covers the case where the
// closing quote is escaped, so OpenSSH keeps scanning and never finds one.
func TestParseRejectsAQuoteEscapedAtTheEndOfAValue(t *testing.T) {
	line := `alice@example.com namespaces="a\\" ` + testKey
	if _, err := Parse(strings.NewReader(line + "\n")); err == nil {
		t.Error("Parse() accepted a value whose closing quote is escaped")
	}
}
