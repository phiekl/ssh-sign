// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"strings"
	"testing"
	"time"
)

// otherKey is a valid ssh-ed25519 key that differs from testKey.
const otherKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+xLwvXBGWKOTvJcDkfLmZOaTRUwbHqPTLjxlKcVsRR"

// at parses a YYYY-MM-DD date as a UTC instant.
func at(t *testing.T, date string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.DateOnly, date)
	if err != nil {
		t.Fatalf("parsing %q: %v", date, err)
	}
	return parsed
}

func TestMatchEntryWithoutConstraints(t *testing.T) {
	f := parseLines(t, "alice@example.com "+testKey)
	key := f.Entries[0].PublicKey

	t.Run("no principal requested", func(t *testing.T) {
		entry, err := f.MatchEntry(key, "", "git", time.Now())
		if err != nil || entry == nil {
			t.Fatalf("MatchEntry() = %v, %v, want an entry", entry, err)
		}
	})

	t.Run("matching principal", func(t *testing.T) {
		entry, err := f.MatchEntry(key, "alice@example.com", "git", time.Now())
		if err != nil || entry == nil {
			t.Fatalf("MatchEntry() = %v, %v, want an entry", entry, err)
		}
	})

	t.Run("other principal is not an error", func(t *testing.T) {
		entry, err := f.MatchEntry(key, "bob@example.com", "git", time.Now())
		if err != nil {
			t.Fatalf("MatchEntry() error = %v, want nil", err)
		}
		if entry != nil {
			t.Error("MatchEntry() matched a principal that is not listed")
		}
	})
}

func TestMatchEntryRejectsAnUnlistedKey(t *testing.T) {
	f := parseLines(t, "alice@example.com "+testKey)
	other := parseLines(t, "alice@example.com "+otherKey)

	entry, err := f.MatchEntry(other.Entries[0].PublicKey, "alice@example.com", "git", time.Now())
	if err != nil {
		t.Fatalf("MatchEntry() error = %v, want nil", err)
	}
	if entry != nil {
		t.Error("MatchEntry() matched an entry holding a different key")
	}
}

func TestMatchEntryNamespaceConstraint(t *testing.T) {
	f := parseLines(t, `alice@example.com namespaces="git,email" `+testKey)
	key := f.Entries[0].PublicKey

	if entry, err := f.MatchEntry(key, "", "email", time.Now()); err != nil || entry == nil {
		t.Fatalf("MatchEntry() = %v, %v, want an entry for an allowed namespace", entry, err)
	}

	entry, err := f.MatchEntry(key, "", "file", time.Now())
	if entry != nil {
		t.Error("MatchEntry() matched a namespace outside the constraint")
	}
	if err == nil || !strings.Contains(err.Error(), "namespace mismatch") {
		t.Errorf("MatchEntry() error = %v, want a namespace mismatch", err)
	}
}

func TestMatchEntryIgnoringNamespace(t *testing.T) {
	f := parseLines(t,
		`alice@example.com namespaces="email",valid-before="20260201Z" `+testKey,
	)
	key := f.Entries[0].PublicKey

	entry, err := f.MatchEntryIgnoringNamespace(key, "", at(t, "2026-01-15"))
	if err != nil || entry == nil {
		t.Fatalf("MatchEntryIgnoringNamespace() = %v, %v, want an entry", entry, err)
	}

	entry, err = f.MatchEntryIgnoringNamespace(key, "", at(t, "2026-02-02"))
	if entry != nil {
		t.Error("MatchEntryIgnoringNamespace() ignored the validity window")
	}
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("MatchEntryIgnoringNamespace() error = %v, want an expiry error", err)
	}
}

func TestMatchEntryValidityWindow(t *testing.T) {
	f := parseLines(t,
		`alice@example.com valid-after="20260101Z",valid-before="20260201Z" `+testKey,
	)
	key := f.Entries[0].PublicKey

	tests := []struct {
		name    string
		when    string
		wantErr string
	}{
		{name: "inside the window", when: "2026-01-15"},
		{name: "before the window", when: "2025-12-31", wantErr: "not yet valid"},
		{name: "after the window", when: "2026-02-02", wantErr: "expired"},
		// The bounds themselves are inclusive, matching ssh-keygen.
		{name: "on valid-after", when: "2026-01-01"},
		{name: "on valid-before", when: "2026-02-01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := f.MatchEntry(key, "", "git", at(t, tt.when))
			if tt.wantErr == "" {
				if err != nil || entry == nil {
					t.Fatalf("MatchEntry() = %v, %v, want an entry", entry, err)
				}
				return
			}
			if entry != nil {
				t.Error("MatchEntry() matched outside the validity window")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("MatchEntry() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestMatchEntryPrefersALaterUsableEntry covers a key listed twice, where only
// the second listing permits the namespace in question.
func TestMatchEntryPrefersALaterUsableEntry(t *testing.T) {
	f := parseLines(t,
		`alice@example.com namespaces="email" `+testKey,
		`alice@example.com namespaces="git" `+testKey,
	)

	entry, err := f.MatchEntry(f.Entries[0].PublicKey, "", "git", time.Now())
	if err != nil {
		t.Fatalf("MatchEntry() error = %v, want nil", err)
	}
	if entry == nil {
		t.Fatal("MatchEntry() did not match, want the second entry")
	}
	if entry.Line != 2 {
		t.Errorf("matched line %d, want 2", entry.Line)
	}
}

func TestMatchEntryRestrictingNamespace(t *testing.T) {
	restrictedFirst := parseLines(t,
		`alice@example.com namespaces="git" `+testKey,
		"alice@example.com "+testKey,
	)
	unrestrictedFirst := parseLines(t,
		"alice@example.com "+testKey,
		`alice@example.com namespaces="git" `+testKey,
	)

	for name, tt := range map[string]struct {
		file     *File
		ns       string
		wantLine int
		want     bool
	}{
		"restricted listed first":  {file: restrictedFirst, ns: "git", wantLine: 1, want: true},
		"restricted listed second": {file: unrestrictedFirst, ns: "git", wantLine: 2, want: true},
		"restriction excludes it":  {file: unrestrictedFirst, ns: "email", wantLine: 1},
	} {
		t.Run(name, func(t *testing.T) {
			key := tt.file.Entries[0].PublicKey
			ent, restricted, err := tt.file.MatchEntryRestrictingNamespace(
				key, "", tt.ns, time.Now(),
			)
			if err != nil || ent == nil {
				t.Fatalf("MatchEntryRestrictingNamespace() = %v, %v, want an entry", ent, err)
			}
			if ent.Line != tt.wantLine {
				t.Errorf("matched line %d, want %d", ent.Line, tt.wantLine)
			}
			if restricted != tt.want {
				t.Errorf("restricted = %v, want %v", restricted, tt.want)
			}
		})
	}
}

func TestMatchEntryRestrictingNamespaceKeepsTimeConstraints(t *testing.T) {
	f := parseLines(t, `alice@example.com valid-before="20260201Z" `+testKey)
	key := f.Entries[0].PublicKey

	ent, restricted, err := f.MatchEntryRestrictingNamespace(key, "", "git", at(t, "2026-02-02"))
	if ent != nil || restricted {
		t.Errorf("MatchEntryRestrictingNamespace() = %v, %v, want no entry", ent, restricted)
	}
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("MatchEntryRestrictingNamespace() error = %v, want an expiry error", err)
	}
}

// TestMatchEntryReportsEveryConstraintFailure covers a key listed twice where
// neither listing is usable, so the caller learns why each one was rejected.
func TestMatchEntryReportsEveryConstraintFailure(t *testing.T) {
	f := parseLines(t,
		`alice@example.com namespaces="email" `+testKey,
		`alice@example.com valid-before="20200101Z" `+testKey,
	)

	entry, err := f.MatchEntry(f.Entries[0].PublicKey, "", "git", time.Now())
	if entry != nil {
		t.Error("MatchEntry() matched an unusable entry")
	}
	if err == nil {
		t.Fatal("MatchEntry() error = nil, want the constraint failures")
	}
	for _, want := range []string{"line=1: namespace mismatch", "line=2: expired"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("MatchEntry() error = %v, want it to contain %q", err, want)
		}
	}
}
