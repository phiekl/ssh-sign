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

func TestParseAllowsLinesLargerThanTwoMiB(t *testing.T) {
	comment := "#" + strings.Repeat("x", 2*1024*1024)
	f := parseLines(t, comment, "alice@example.com "+testKey)
	if len(f.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(f.Entries))
	}
}

func TestParseAllowsAnUnterminatedLineAtTheLimit(t *testing.T) {
	const limit = 64
	comment := "#" + strings.Repeat("x", limit-1)
	f, err := parseWithMaxLineSize(strings.NewReader(comment), limit)
	if err != nil {
		t.Fatalf("parseWithMaxLineSize() error = %v", err)
	}
	if len(f.Entries) != 0 {
		t.Fatalf("len(Entries) = %d, want 0", len(f.Entries))
	}
	if _, err := parseWithMaxLineSize(strings.NewReader(comment+"x"), limit); err == nil {
		t.Fatal("parseWithMaxLineSize() error = nil for a line over the limit")
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

func TestParseTreatsTrailingCommentAsOpaque(t *testing.T) {
	f := parseLines(t, "alice@example.com "+testKey+` owner "unfinished comment`)

	if got, want := f.Entries[0].Comment, `owner "unfinished comment`; got != want {
		t.Errorf("Comment = %q, want %q", got, want)
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

// Record malformed lines without rejecting the whole file.
func TestParseSkipsMalformedLines(t *testing.T) {
	tests := map[string]string{
		"too few fields":     "alice@example.com",
		"missing key":        "alice@example.com ssh-ed25519",
		"options but no key": `alice@example.com namespaces="git" ssh-ed25519`,
		"key type mismatch":  "alice@example.com ssh-rsa " + strings.Fields(testKey)[1],
		"invalid key":        "alice@example.com ssh-ed25519 not-base64!",
		"unknown option":     `alice@example.com bogus="x" ` + testKey,
		"cert-authority":     "alice@example.com cert-authority " + testKey,
		"unterminated quote": `alice@example.com namespaces="git ` + testKey,
		"bad valid-after":    `alice@example.com valid-after="nonsense" ` + testKey,
	}

	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(strings.NewReader(line + "\n"))
			if err != nil {
				t.Fatalf("Parse(%q) error = %v, want nil", line, err)
			}
			if len(f.Entries) != 0 {
				t.Errorf("len(Entries) = %d, want 0", len(f.Entries))
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("len(Skipped) = %d, want 1", len(f.Skipped))
			}
			if f.Skipped[0].Line != 1 {
				t.Errorf("Skipped[0].Line = %d, want 1", f.Skipped[0].Line)
			}
		})
	}
}

// Valid entries remain usable after a malformed line.
func TestParseKeepsGoodEntriesPastABadLine(t *testing.T) {
	f, err := Parse(strings.NewReader(
		"bob@example.com cert-authority " + testKey + "\n" +
			"alice@example.com " + testKey + "\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(f.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(f.Entries))
	}
	if f.Entries[0].Principal != "alice@example.com" {
		t.Errorf("Principal = %q, want %q", f.Entries[0].Principal, "alice@example.com")
	}
	if len(f.Skipped) != 1 || f.Skipped[0].Line != 1 {
		t.Errorf("Skipped = %v, want the cert-authority line recorded", f.Skipped)
	}
}

// Bound retained diagnostics while counting every skipped line.
func TestParseBoundsRecordedSkips(t *testing.T) {
	const lines = maxSkippedRecorded * 4

	f, err := Parse(strings.NewReader(strings.Repeat("x\n", lines)))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(f.Entries) != 0 {
		t.Errorf("len(Entries) = %d, want 0", len(f.Entries))
	}
	if len(f.Skipped) != maxSkippedRecorded {
		t.Errorf("len(Skipped) = %d, want %d", len(f.Skipped), maxSkippedRecorded)
	}
	// Count skips beyond the diagnostic limit.
	if f.SkippedCount != lines {
		t.Errorf("SkippedCount = %d, want %d", f.SkippedCount, lines)
	}
}

// Read errors and oversized lines remain fatal.
func TestParseFailsOnUnreadableInput(t *testing.T) {
	const limit = 64
	line := "alice@example.com " + strings.Repeat("x", limit)
	if _, err := parseWithMaxLineSize(strings.NewReader(line), limit); err == nil {
		t.Error("parseWithMaxLineSize() accepted a line over the limit")
	}
}

func TestParseTruncatesEchoedOptionKeys(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)

	for name, line := range map[string]string{
		// Reaches the value-unquoting error path.
		"malformed value": `alice@example.com ` + huge + `="x"junk ` + testKey,
		"unknown option":  `alice@example.com ` + huge + `="x" ` + testKey,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(strings.NewReader(line + "\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("len(Skipped) = %d, want 1", len(f.Skipped))
			}
			msg := f.Skipped[0].Error()
			if len(msg) > 512 {
				t.Errorf("skipped line reason is %d bytes long, want the key truncated",
					len(msg))
			}
			if !strings.Contains(msg, "1048576 bytes total") {
				t.Errorf("skipped line reason = %v, want the full key length reported", msg)
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
	f, err := Parse(strings.NewReader(
		"alice@example.com " + testKey + "\n" +
			"# comment\n" +
			"broken\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(f.Skipped) != 1 {
		t.Fatalf("len(Skipped) = %d, want 1", len(f.Skipped))
	}
	if f.Skipped[0].Line != 3 {
		t.Errorf("Line = %d, want 3", f.Skipped[0].Line)
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
	f, err := Parse(strings.NewReader(line + "\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(f.Entries) != 0 {
		t.Error("Parse() accepted a value whose closing quote is escaped")
	}
}
