// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Field is a single result field rendered by ResultFormatKV.
type Field struct {
	Key   string
	Value any
}

// KV returns a Field for ResultFormatKV.
func KV(key string, value any) Field {
	return Field{Key: key, Value: value}
}

// ResultFormatKV renders fields as "<prefix><key><delim><value>" lines. Each
// key uses the width specified by pad. Values holding control characters or
// invalid UTF-8 are quoted.
func ResultFormatKV(pad int, prefix, delim string, fields ...Field) string {
	lineFmt := fmt.Sprintf("%s%%%ds%s%%v", prefix, pad, delim)

	lines := make([]string, 0, len(fields))
	for _, f := range fields {
		lines = append(lines, fmt.Sprintf(lineFmt, f.Key, escapeControl(f.Value)))
	}
	return strings.Join(lines, "\n")
}

// EscapeControl escapes terminal controls and replaces invalid UTF-8.
func EscapeControl(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControl(r) {
			b.WriteString(strings.Trim(strconv.QuoteRune(r), "'"))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// EscapeJSONControls losslessly escapes DEL and C1 controls left raw by
// encoding/json.
func EscapeJSONControls(encoded []byte) []byte {
	var out []byte
	last := 0
	for i := 0; i < len(encoded); i++ {
		var r rune
		switch {
		case encoded[i] == 0x7f:
			r = 0x7f
		case encoded[i] == 0xc2 && i+1 < len(encoded) &&
			encoded[i+1] >= 0x80 && encoded[i+1] <= 0x9f:
			r = rune(encoded[i+1])
		default:
			continue
		}
		out = append(out, encoded[last:i]...)
		out = append(out, fmt.Sprintf(`\u%04x`, r)...)
		if r > 0x7f {
			i++
		}
		last = i + 1
	}
	if out == nil {
		return encoded
	}
	return append(out, encoded[last:]...)
}

// escapeControl quotes strings containing terminal controls or invalid UTF-8.
// Check UTF-8 separately: invalid bytes decode as RuneError, not controls.
func escapeControl(value any) any {
	s, ok := value.(string)
	if !ok || (utf8.ValidString(s) && !strings.ContainsFunc(s, isControl)) {
		return value
	}
	return strconv.Quote(s)
}

// isControl reports whether r is a C0 or C1 control character, or DEL.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}
