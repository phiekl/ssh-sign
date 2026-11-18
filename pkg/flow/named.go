// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

// NamedBytes is the content of an input file with a name for messages, such
// as its path. An empty name leaves the file unnamed.
type NamedBytes struct {
	Name string
	Data []byte
}
