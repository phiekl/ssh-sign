// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

func ParseTimestamp(s string) (time.Time, error) {
	zonedFormats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
	}

	for _, format := range zonedFormats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t, nil
		}
	}
	if t, err := time.Parse(time.RFC1123, s); err == nil {
		fields := strings.Fields(s)
		zone := fields[len(fields)-1]
		if zone != "UTC" && zone != "GMT" {
			return time.Time{}, fmt.Errorf(
				"ambiguous RFC1123 timezone %q; use a numeric offset, UTC, or GMT", zone,
			)
		}
		return t, nil
	}

	localFormats := []string{time.DateTime, time.DateOnly}
	for _, format := range localFormats {
		t, err := time.ParseInLocation(format, s, time.Local)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf(
		"accepted timestamp formats: %v",
		slices.Concat(zonedFormats, []string{time.RFC1123}, localFormats),
	)
}
