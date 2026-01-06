// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// File represents a parsed allowed signers file.
type File struct {
	Entries []Entry
}

// Entry represents a single non-comment line in an allowed signers file.
type Entry struct {
	// File line number.
	Line int
	// Line content (whitespace/newline trimmed).
	Raw string

	// Principals is the pattern-list for identities (USER@DOMAIN patterns).
	Principal string

	// Options are optional constraints for this key.
	Options Options

	// KeyType is the SSH public key type (e.g. "ssh-ed25519").
	KeyType string

	// KeyBase64 is the base64-encoded key material as present in the file.
	KeyBase64 string

	// Comment is any optional trailing data after the key.
	Comment string

	// PublicKey is the parsed/validated SSH public key.
	PublicKey ssh.PublicKey
}

// Options are the supported, but optional, allowed signers options.
// An unset option results in no restriction for given option.
type Options struct {
	// Namespaces restricts acceptable namespaces.
	Namespaces []string

	// ValidAfter specifies the time after which the entry is accepted.
	ValidAfter *time.Time

	// ValidBefore specifies the time before which the entry is accepted.
	ValidBefore *time.Time
}
