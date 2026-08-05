// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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
		lines = append(lines, fmt.Sprintf(lineFmt, keyPrefix+k, value))
	}
	return strings.Join(lines, "\n")
}
