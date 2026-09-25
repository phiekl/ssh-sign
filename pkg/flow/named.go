// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import "io"

// NamedReader is a reader with a name for messages, such as a file path.
type NamedReader struct {
	Name   string
	Reader io.Reader
}
