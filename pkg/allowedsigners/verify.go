// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type constraintError struct {
	messages            []string
	candidates          int
	namespaceMatches    int
	namespaceMismatches int
}

func (e *constraintError) Error() string {
	return strings.Join(e.messages, ", ")
}

// NamespaceConstraintResult extracts a conclusive namespace result from a
// failed MatchEntry call.
func NamespaceConstraintResult(err error) (checked, matched bool) {
	var constraintErr *constraintError
	if !errors.As(err, &constraintErr) {
		return false, false
	}
	if constraintErr.namespaceMatches > 0 {
		return true, true
	}
	if constraintErr.candidates > 0 &&
		constraintErr.namespaceMismatches == constraintErr.candidates {
		return true, false
	}
	return false, false
}

// namespaceMode controls namespace matching.
type namespaceMode int

const (
	namespaceIgnored namespaceMode = iota
	// namespaceChecked accepts unrestricted entries.
	namespaceChecked
	// namespaceRequired prefers a restricted entry anywhere in the file.
	namespaceRequired
)

// MatchEntry finds the first entry matching given pubkey and optionally a principal.
// Any namespace or time restriction defined by the entry will be validated.
func (f *File) MatchEntry(pk ssh.PublicKey, principal, ns string, ts time.Time) (*Entry, error) {
	ent, _, err := f.matchEntry(pk, principal, ns, ts, namespaceChecked)
	return ent, err
}

// MatchEntryIgnoringNamespace finds the first entry matching the given public
// key and optional principal, without applying the entry's namespace
// restriction. Time restrictions are still validated.
func (f *File) MatchEntryIgnoringNamespace(
	pk ssh.PublicKey, principal string, ts time.Time,
) (*Entry, error) {
	ent, _, err := f.matchEntry(pk, principal, "", ts, namespaceIgnored)
	return ent, err
}

// MatchEntryRestrictingNamespace prefers an entry whose namespaces= restriction
// permits ns. It returns an unrestricted fallback with restricted=false.
func (f *File) MatchEntryRestrictingNamespace(
	pk ssh.PublicKey, principal, ns string, ts time.Time,
) (ent *Entry, restricted bool, err error) {
	return f.matchEntry(pk, principal, ns, ts, namespaceRequired)
}

func (f *File) matchEntry(
	pk ssh.PublicKey, principal, ns string, ts time.Time, mode namespaceMode,
) (*Entry, bool, error) {
	var errs []string
	var candidates, namespaceMatches, namespaceMismatches int
	// First usable fallback for namespaceRequired.
	var unrestricted *Entry

	for i := range f.Entries {
		ent := &f.Entries[i]

		if principal != "" && !patternListMatch(ent.Principal, principal) {
			continue
		}
		if !sshsig.PublicKeyEqual(ent.PublicKey, pk) {
			continue
		}
		candidates++
		restricted := mode != namespaceIgnored && len(ent.Options.Namespaces) > 0
		if restricted {
			if !patternsMatch(ent.Options.Namespaces, ns) {
				namespaceMismatches++
				errs = append(errs, fmt.Sprintf("line=%d: namespace mismatch", ent.Line))
				continue
			}
			namespaceMatches++
		}
		if ent.Options.ValidAfter != nil && ts.Before(*ent.Options.ValidAfter) {
			errs = append(errs, fmt.Sprintf("line=%d: not yet valid", ent.Line))
			continue
		}
		if ent.Options.ValidBefore != nil && ts.After(*ent.Options.ValidBefore) {
			errs = append(errs, fmt.Sprintf("line=%d: expired", ent.Line))
			continue
		}
		if mode == namespaceRequired && !restricted {
			if unrestricted == nil {
				unrestricted = ent
			}
			continue
		}

		return ent, restricted, nil
	}
	if unrestricted != nil {
		return unrestricted, false, nil
	}
	if len(errs) > 0 {
		return nil, false, &constraintError{
			messages:            errs,
			candidates:          candidates,
			namespaceMatches:    namespaceMatches,
			namespaceMismatches: namespaceMismatches,
		}
	}

	return nil, false, nil
}
