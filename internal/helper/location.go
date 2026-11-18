// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import "fmt"

// MaxLineSize limits memory use while allowing large certificates and comments
// in allowed signers and revoked keys files.
const MaxLineSize = 4 << 20

// Location names a line of a source, or only the line for an unnamed source.
func Location(source string, line int) string {
	if source == "" {
		return fmt.Sprintf("line=%d", line)
	}
	return fmt.Sprintf("file=%q line=%d", source, line)
}
