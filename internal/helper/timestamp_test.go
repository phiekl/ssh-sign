// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"testing"
	"time"
)

func TestParseTimestampUsesLocalTimeForZonelessValues(t *testing.T) {
	previousLocal := time.Local
	time.Local = time.FixedZone("test-local", 60*60)
	t.Cleanup(func() { time.Local = previousLocal })

	for _, input := range []string{"2026-01-15", "2026-01-15 12:30:45"} {
		parsed, err := ParseTimestamp(input)
		if err != nil {
			t.Fatalf("ParseTimestamp(%q) error = %v", input, err)
		}
		_, offset := parsed.Zone()
		if offset != 60*60 {
			t.Errorf("ParseTimestamp(%q) offset = %d, want %d", input, offset, 60*60)
		}
	}
}

func TestParseTimestampPreservesExplicitZone(t *testing.T) {
	previousLocal := time.Local
	time.Local = time.FixedZone("test-local", 60*60)
	t.Cleanup(func() { time.Local = previousLocal })

	parsed, err := ParseTimestamp("2026-01-15T00:00:00Z")
	if err != nil {
		t.Fatalf("ParseTimestamp() error = %v", err)
	}
	_, offset := parsed.Zone()
	if offset != 0 {
		t.Errorf("ParseTimestamp() offset = %d, want 0", offset)
	}
}
