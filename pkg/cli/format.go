// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ResultFormatKV(data any, pad int, prefix, delim, key_prefix string, keys ...string) string {
	// Marshal to JSON first to get correct key names and type conversions.
	dataEnc, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("[INTERNAL ERROR] json.Marshal(): %v", err)
	}

	var dataDec map[string]any
	if err := json.Unmarshal(dataEnc, &dataDec); err != nil {
		return fmt.Sprintf("[INTERNAL ERROR] json.Unmarshal(): %v", err)
	}

	lineFmt := fmt.Sprintf("%s%%%ds%s%%s", prefix, pad, delim)

	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		line := fmt.Sprintf(lineFmt, key_prefix+k, dataDec[k])
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
