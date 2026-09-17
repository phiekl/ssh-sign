// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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

// Quoted principals must match their unquoted identities.
func TestParseUnquotesPrincipals(t *testing.T) {
	tests := map[string]struct {
		field string
		want  string
	}{
		"quoted":      {field: `"alice@example.com"`, want: "alice@example.com"},
		"quoted list": {field: `"alice@example.com,bob@example.com"`, want: "alice@example.com,bob@example.com"},
		"bare":        {field: "alice@example.com", want: "alice@example.com"},
		// Quotes must not disable exclusions.
		"quoted negation": {field: `*,!"bob@example.com"`, want: `*,!bob@example.com`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := parseLines(t, tt.field+" "+testKey)
			if len(f.Entries) != 1 {
				t.Fatalf("entries = %d, want 1 (skipped: %v)", len(f.Entries), f.Skipped)
			}
			if got := f.Entries[0].Principal; got != tt.want {
				t.Errorf("Principal = %q, want %q", got, tt.want)
			}
			entry, err := f.MatchEntry(
				f.Entries[0].PublicKey, "alice@example.com", "git", time.Now(),
			)
			if err != nil {
				t.Fatalf("MatchEntry() error = %v", err)
			}
			if entry == nil {
				t.Error("MatchEntry() did not match the quoted principal")
			}
		})
	}
}

// Quoted exclusions must still reject the named identity.
func TestParseAppliesAQuotedExclusion(t *testing.T) {
	f := parseLines(t, `*,!"alice@example.com" `+testKey)
	if len(f.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (skipped: %v)", len(f.Entries), f.Skipped)
	}
	for principal, want := range map[string]bool{
		"alice@example.com": false,
		"bob@example.com":   true,
	} {
		entry, err := f.MatchEntry(f.Entries[0].PublicKey, principal, "git", time.Now())
		if err != nil {
			t.Fatalf("MatchEntry(%q) error = %v", principal, err)
		}
		if got := entry != nil; got != want {
			t.Errorf("MatchEntry(%q) matched = %v, want %v", principal, got, want)
		}
	}
}

// Reject quoting that OpenSSH cannot parse.
func TestParseSkipsUnsupportedPrincipalQuoting(t *testing.T) {
	for name, field := range map[string]string{
		"escaped quote":            `"alice@example.com\"x"`,
		"text after closing quote": `"alice@example.com",bob@example.com`,
		"quote inside a bare word": `a"b"c`,
		"unterminated quote":       `"alice@example.com`,
		"trailing quote":           `alice@example.com"`,
	} {
		t.Run(name, func(t *testing.T) {
			f := parseLines(t, field+" "+testKey)
			if len(f.Entries) != 0 {
				t.Errorf("entries = %+v, want the line skipped", f.Entries)
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("skipped = %d, want 1", len(f.Skipped))
			}
		})
	}
}

// Trimming Unicode whitespace would change the authorised identity.
func TestParseKeepsUnicodeWhitespaceInIdentities(t *testing.T) {
	const nbsp = "\u00a0"
	for name, field := range map[string]string{
		"trailing": "alice@example.com" + nbsp,
		"leading":  nbsp + "alice@example.com",
	} {
		t.Run(name, func(t *testing.T) {
			f := parseLines(t, field+" "+testKey)
			if len(f.Entries) != 1 {
				t.Fatalf("entries = %d, want 1 (skipped: %v)", len(f.Entries), f.Skipped)
			}
			if got := f.Entries[0].Principal; got != field {
				t.Errorf("Principal = %q, want %q", got, field)
			}
			entry, err := f.MatchEntry(
				f.Entries[0].PublicKey, "alice@example.com", "git", time.Now(),
			)
			if err != nil {
				t.Fatalf("MatchEntry() error = %v", err)
			}
			if entry != nil {
				t.Error("MatchEntry() matched the trimmed identity")
			}
		})
	}
}

// Reject carriage returns except those in CRLF line endings.
func TestParseSkipsLinesHoldingACarriageReturn(t *testing.T) {
	for name, line := range map[string]string{
		"after the principal": "alice@example.com\r " + testKey,
		"before the key type": "alice@example.com\r" + testKey,
		"inside the key":      "alice@example.com " + testKey + "\rx",
		"inside a quote":      "\"alice\rbob\" " + testKey,
		"in the comment":      "alice@example.com " + testKey + " com\rment",
	} {
		t.Run(name, func(t *testing.T) {
			f := parseLines(t, line)
			if len(f.Entries) != 0 {
				t.Errorf("entries = %+v, want the line skipped", f.Entries)
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("skipped = %d, want 1", len(f.Skipped))
			}
			if !strings.Contains(f.Skipped[0].Msg, "carriage return") {
				t.Errorf("Msg = %q, want the carriage return reported", f.Skipped[0].Msg)
			}
		})
	}

	// The scanner removes the CR in CRLF line endings.
	f := parseLines(t, "alice@example.com "+testKey+"\r")
	if len(f.Entries) != 1 {
		t.Errorf("entries = %d, want CRLF line endings accepted (skipped: %v)",
			len(f.Entries), f.Skipped)
	}
}

// Reject NUL bytes anywhere in a line, including comments.
func TestParseSkipsLinesHoldingANULByte(t *testing.T) {
	for name, line := range map[string]string{
		"hiding a principal": "alice@example.com\x00,bob@example.com " + testKey,
		"in an option":       "alice@example.com namespaces=\"file,x\x00\" " + testKey,
		"in the comment":     "alice@example.com " + testKey + " comment\x00more",
	} {
		t.Run(name, func(t *testing.T) {
			f := parseLines(t, line)
			if len(f.Entries) != 0 {
				t.Errorf("entries = %+v, want the line skipped", f.Entries)
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("skipped = %d, want 1", len(f.Skipped))
			}
			if !strings.Contains(f.Skipped[0].Msg, "NUL") {
				t.Errorf("Msg = %q, want the NUL byte reported", f.Skipped[0].Msg)
			}
		})
	}
}

func TestParseSkipsNonPrintableLines(t *testing.T) {
	bad := []string{"\u200b", "\u200d", "\u202e", "\u2066", "\u2028", "\u2029", "\ufeff", "\ue000", "\uffff", "\xff", "\xc0\xaf", "\xed\xa0\x80"}
	for r := rune(0); r <= 0x9f; r++ {
		if r != '\t' && r != '\n' && (r < 0x20 || r >= 0x7f) {
			bad = append(bad, string(r))
		}
	}
	for _, value := range bad {
		for name, line := range map[string]string{
			"principal":    "\"alice" + value + "\" " + testKey,
			"namespace":    "alice namespaces=\"git" + value + "\" " + testKey,
			"key":          "alice " + testKey + value + "x",
			"comment":      "alice " + testKey + " comment" + value + "x",
			"comment line": "# comment" + value + "x",
		} {
			t.Run(fmt.Sprintf("%s/%x", name, value), func(t *testing.T) {
				f := parseLines(t, line, "bob "+testKey)
				if len(f.Entries) != 1 || f.Entries[0].Principal != "bob" || f.Entries[0].Line != 2 {
					t.Fatalf("entries = %+v, want only the following valid entry", f.Entries)
				}
				if f.SkippedCount != 1 || len(f.Skipped) != 1 || f.Skipped[0].Line != 1 {
					t.Fatalf("skips = %+v, total = %d, want line 1 skipped", f.Skipped, f.SkippedCount)
				}
			})
		}
	}
}

func TestParsePreservesGraphicUnicode(t *testing.T) {
	for _, value := range []string{"Jos\u00e9", "Jose\u0301", "\u674e\u96f7", "\u0639\u0644\u064a", "\U0001f511", "a\u00a0b", "a\u2003b", "\ufffd"} {
		t.Run(value, func(t *testing.T) {
			f := parseLines(t, "\t\""+value+"\"\tnamespaces=\""+value+"\"\t"+testKey+"\tcomment\r")
			if len(f.Entries) != 1 || f.SkippedCount != 0 {
				t.Fatalf("entries = %d, skipped = %+v", len(f.Entries), f.Skipped)
			}
			ent := &f.Entries[0]
			if ent.Principal != value || len(ent.Options.Namespaces) != 1 || ent.Options.Namespaces[0] != value {
				t.Fatalf("Unicode changed: %+v", ent)
			}
			matched, err := f.MatchEntry(ent.PublicKey, value, value, time.Now())
			if err != nil || matched == nil {
				t.Fatalf("MatchEntry() = %v, %v", matched, err)
			}
		})
	}
}

// Limit retained error messages for malformed keys.
func TestParseBoundsTheKeyParserDiagnostic(t *testing.T) {
	blob := ssh.Marshal(struct{ Name string }{Name: strings.Repeat("A", 1<<20)})
	line := "alice@example.com ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)

	f := parseLines(t, line)
	if len(f.Skipped) != 1 {
		t.Fatalf("skipped = %d, want 1", len(f.Skipped))
	}
	if got := len(f.Skipped[0].Msg); got > 1024 {
		t.Errorf("retained diagnostic is %d bytes long, want it bounded", got)
	}
}

// Reject spliced quoted fields that could authorise unintended principals.
func TestParseSkipsASplicedQuotedField(t *testing.T) {
	for name, line := range map[string]string{
		"principals": `"alice,bob","carol" ` + testKey,
		"namespaces": `alice@example.com namespaces="git","email" ` + testKey,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := Parse(strings.NewReader(line + "\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(f.Entries) != 0 {
				t.Fatalf("Entries = %+v, want the line skipped", f.Entries)
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("len(Skipped) = %d, want 1", len(f.Skipped))
			}
		})
	}
}

// A spliced principal field must not grant access.
func TestMatchEntryIgnoresASplicedPrincipal(t *testing.T) {
	f, err := Parse(strings.NewReader(`"alice,bob","carol" ` + testKey + "\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	key := parseLines(t, "someone@example.com "+testKey).Entries[0].PublicKey

	entry, err := f.MatchEntry(key, "alice", "git", time.Now())
	if err != nil {
		t.Fatalf("MatchEntry() error = %v", err)
	}
	if entry != nil {
		t.Errorf("MatchEntry() = %+v, want no entry for a spliced principal", entry)
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

// Unquoted option values must not activate entries ssh-keygen rejects.
func TestParseSkipsUnquotedOptionValues(t *testing.T) {
	for _, options := range []string{
		`namespaces=git`,
		`namespaces=*`,
		`valid-after=20200101Z`,
		`namespaces="git",valid-before=20200101Z`,
		// An even number of quotes survives splitting, but still has no
		// leading quote of its own.
		`namespaces=a"b"c`,
	} {
		t.Run(options, func(t *testing.T) {
			f, err := Parse(strings.NewReader("alice@example.com " + options + " " + testKey + "\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(f.Entries) != 0 {
				t.Errorf("len(Entries) = %d, want the line skipped", len(f.Entries))
			}
			if len(f.Skipped) != 1 {
				t.Fatalf("len(Skipped) = %d, want 1", len(f.Skipped))
			}
			if !strings.Contains(f.Skipped[0].Msg, "missing start quote") {
				t.Errorf("Skipped[0].Msg = %q, want a missing start quote", f.Skipped[0].Msg)
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
