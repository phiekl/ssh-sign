// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"fmt"
	"time"
)

func ParseTimestamp(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.DateTime,
		time.DateOnly,
		time.RFC1123Z,
		time.RFC1123,
	}

	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("accepted timestamp formats: %v", formats)
}
