// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"strings"
	"testing"
)

func parseNamed(t *testing.T, source string, lines ...string) *File {
	t.Helper()
	f, err := ParseSource(strings.NewReader(strings.Join(lines, "\n")+"\n"), source)
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	return f
}

func TestParseSourceNamesEntriesAndSkips(t *testing.T) {
	f := parseNamed(t, "a.conf", "bad", "alice@example.com "+testKey)

	if len(f.Entries) != 1 || f.Entries[0].Source != "a.conf" || f.Entries[0].Line != 2 {
		t.Fatalf("Entries = %+v, want one from a.conf line 2", f.Entries)
	}
	if len(f.Skipped) != 1 || f.Skipped[0].Source != "a.conf" {
		t.Fatalf("Skipped = %+v, want one from a.conf", f.Skipped)
	}
	if got, want := f.Skipped[0].Error(), `file="a.conf" line=1: `; !strings.HasPrefix(got, want) {
		t.Errorf("Skipped[0].Error() = %q, want prefix %q", got, want)
	}
	if got, want := f.Entries[0].Location(), `file="a.conf" line=2`; got != want {
		t.Errorf("Location() = %q, want %q", got, want)
	}
}

func TestLocationWithoutSource(t *testing.T) {
	f := parseLines(t, "bad", "alice@example.com "+testKey)
	if got := f.Entries[0].Location(); got != "line=2" {
		t.Errorf("Location() = %q, want %q", got, "line=2")
	}
	if got := f.Skipped[0].Error(); !strings.HasPrefix(got, "line=1: ") {
		t.Errorf("Skipped[0].Error() = %q, want prefix %q", got, "line=1: ")
	}
}

func TestAppendKeepsOrderAndSources(t *testing.T) {
	f := parseNamed(t, "a.conf", `alice@example.com namespaces="email" `+testKey)
	f.Append(parseNamed(t, "b.conf", `alice@example.com valid-before="20200101Z" `+testKey))

	if len(f.Entries) != 2 || f.Entries[1].Source != "b.conf" || f.Entries[1].Line != 1 {
		t.Fatalf("Entries = %+v, want b.conf line 1 appended", f.Entries)
	}
	_, err := f.MatchEntry(f.Entries[0].PublicKey, "", "git", at(t, "2026-01-01"))
	want := `file="a.conf" line=1: namespace mismatch, file="b.conf" line=1: expired`
	if err == nil || err.Error() != want {
		t.Errorf("MatchEntry() error = %v, want %q", err, want)
	}
}

func TestAppendBoundsRecordedSkips(t *testing.T) {
	bad := make([]string, maxSkippedRecorded-1)
	for i := range bad {
		bad[i] = "bad"
	}
	f := parseNamed(t, "a.conf", bad...)
	f.Append(parseNamed(t, "b.conf", "bad", "bad"))

	if f.SkippedCount != maxSkippedRecorded+1 {
		t.Errorf("SkippedCount = %d, want %d", f.SkippedCount, maxSkippedRecorded+1)
	}
	if len(f.Skipped) != maxSkippedRecorded || f.Skipped[len(f.Skipped)-1].Source != "b.conf" {
		t.Errorf("Skipped holds %d, want the first %d across both files", len(f.Skipped), maxSkippedRecorded)
	}
}
