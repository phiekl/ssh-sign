// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"bytes"
	"strings"
)

// ValidCString reports whether OpenSSH accepts s as a C string.
func ValidCString[T string | []byte](s T) bool {
	var i int
	switch value := any(s).(type) {
	case string:
		i = strings.IndexByte(value, 0)
	case []byte:
		i = bytes.IndexByte(value, 0)
	}
	return i < 0 || i == len(s)-1
}

// CString returns the part of s before the first NUL.
func CString(s string) string {
	s, _, _ = strings.Cut(s, "\x00")
	return s
}
