// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"strings"
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

func TestParseTimestampRFC1123Zones(t *testing.T) {
	for _, input := range []string{
		"Thu, 15 Jan 2026 00:00:00 UTC",
		"Thu, 15 Jan 2026 00:00:00 GMT",
		"Thu, 15 Jan 2026 00:00:00 +0200",
	} {
		if _, err := ParseTimestamp(input); err != nil {
			t.Errorf("ParseTimestamp(%q) error = %v", input, err)
		}
	}

	const ambiguous = "Thu, 15 Jan 2026 00:00:00 EST"
	if _, err := ParseTimestamp(ambiguous); err == nil ||
		!strings.Contains(err.Error(), "ambiguous RFC1123 timezone") {
		t.Errorf("ParseTimestamp(%q) error = %v, want an ambiguous-zone error", ambiguous, err)
	}
}
