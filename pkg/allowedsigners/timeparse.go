// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"fmt"
	"strings"
	"time"
)

// ParseKeygenTimestamp parses timestamps in the formats documented by ssh-keygen:
//
// YYYYMMDD[Z]
// YYYYMMDDHHMM[SS][Z]
//
// Without Z => interpreted in local time zone, with Z => UTC.
func ParseKeygenTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}

	utc := false
	if strings.HasSuffix(s, "Z") {
		utc = true
		s = strings.TrimSuffix(s, "Z")
	}

	loc := time.Local
	if utc {
		loc = time.UTC
	}

	var format string
	switch len(s) {
	case 8:
		format = "20060102"
	case 12:
		format = "200601021504"
	case 14:
		format = "20060102150405"
	default:
		return time.Time{}, fmt.Errorf("invalid timestamp length %d", len(s))
	}

	t, err := time.ParseInLocation(format, s, loc)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", s, err)
	}
	return t, nil
}
