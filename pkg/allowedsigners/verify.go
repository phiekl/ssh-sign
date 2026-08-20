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
	"pxy.se/go/ssh-sign/pkg/sshsigx"
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

// NamespaceConstraintResult reports a conclusive namespace-policy result from
// a failed MatchEntry call. checked is false when another matching entry had no
// namespace restriction, so the overall failure cannot be attributed to the
// namespace.
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

// MatchEntry finds the first entry matching given pubkey and optionally a principal.
// Any namespace or time restriction defined by the entry will be validated.
func (f *File) MatchEntry(pk ssh.PublicKey, principal, ns string, ts time.Time) (*Entry, error) {
	return f.matchEntry(pk, principal, ns, ts, true)
}

// MatchEntryIgnoringNamespace finds the first entry matching the given public
// key and optional principal, without applying the entry's namespace
// restriction. Time restrictions are still validated.
func (f *File) MatchEntryIgnoringNamespace(
	pk ssh.PublicKey, principal string, ts time.Time,
) (*Entry, error) {
	return f.matchEntry(pk, principal, "", ts, false)
}

func (f *File) matchEntry(
	pk ssh.PublicKey, principal, ns string, ts time.Time, checkNamespace bool,
) (*Entry, error) {
	var errs []string
	var candidates, namespaceMatches, namespaceMismatches int
	for i := range f.Entries {
		ent := &f.Entries[i]

		if principal != "" && !patternListMatch(ent.Principal, principal) {
			continue
		}
		if !sshsigx.PublicKeyEqual(ent.PublicKey, pk) {
			continue
		}
		candidates++
		if checkNamespace && len(ent.Options.Namespaces) > 0 {
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

		return ent, nil
	}
	if len(errs) > 0 {
		return nil, &constraintError{
			messages:            errs,
			candidates:          candidates,
			namespaceMatches:    namespaceMatches,
			namespaceMismatches: namespaceMismatches,
		}
	}

	// Principal/pubkey was not found => no entry, but no error either.
	return nil, nil
}
