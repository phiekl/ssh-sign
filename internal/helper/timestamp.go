// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"fmt"
	"slices"
	"time"
)

func ParseTimestamp(s string) (time.Time, error) {
	zonedFormats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
	}

	for _, format := range zonedFormats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t, nil
		}
	}

	localFormats := []string{time.DateTime, time.DateOnly}
	for _, format := range localFormats {
		t, err := time.ParseInLocation(format, s, time.Local)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf(
		"accepted timestamp formats: %v", slices.Concat(zonedFormats, localFormats),
	)
}
