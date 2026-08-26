// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

func ResultFormatKV(data any, pad int, prefix, delim, keyPrefix string, keys ...string) string {
	// Marshal to JSON first to get correct key names and type conversions.
	dataEnc, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("[INTERNAL ERROR] json.Marshal(): %v", err)
	}

	// UseNumber keeps numbers as their literal text. Decoding them into float64
	// would render 1 as "1e+06" once it gets large enough.
	dec := json.NewDecoder(bytes.NewReader(dataEnc))
	dec.UseNumber()

	var dataDec map[string]any
	if err := dec.Decode(&dataDec); err != nil {
		return fmt.Sprintf("[INTERNAL ERROR] json.Decode(): %v", err)
	}

	lineFmt := fmt.Sprintf("%s%%%ds%s%%v", prefix, pad, delim)

	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		value, ok := dataDec[k]
		if !ok {
			// A key that no longer exists would otherwise print as "<nil>",
			// which is easy to miss when a JSON tag gets renamed.
			value = fmt.Sprintf("[INTERNAL ERROR] no such key: %s", k)
		}
		lines = append(lines, fmt.Sprintf(lineFmt, keyPrefix+k, escapeControl(value)))
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

// escapeControl quotes strings containing terminal controls.
func escapeControl(value any) any {
	s, ok := value.(string)
	if !ok || !strings.ContainsFunc(s, isControl) {
		return value
	}
	return strconv.Quote(s)
}

// isControl reports whether r is a C0 or C1 control character, or DEL.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}
