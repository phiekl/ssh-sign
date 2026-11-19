// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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
	readCertificate := sync.OnceValue(func() *ssh.Certificate {
		cert, err := sshsig.CertificateDetails(pk)
		if err != nil {
			// Still find the CA of a malformed concrete certificate, so that
			// checkCertificate reports why its entry does not authorize it.
			cert, _ = pk.(*ssh.Certificate)
		}
		return cert
	})
	checkCertificate := sync.OnceValue(func() error {
		return sshsig.CertificateValidAt(pk, ts)
	})
	matchPublicKey := sync.OnceValue(func() func(ssh.PublicKey) bool {
		return sshsig.PublicKeyMatcher(pk)
	})

	for i := range f.Entries {
		ent := &f.Entries[i]

		if principal != "" && !patternListMatch(ent.Principal, principal) {
			continue
		}
		var authorizationErr error
		if ent.Options.CertAuthority {
			cert := readCertificate()
			if !ent.matchesCA(cert) {
				continue
			}
			authorizationErr = checkCertificate()
			if authorizationErr == nil {
				authorizationErr = ent.authorizePrincipal(cert, principal)
			}
		} else if !matchPublicKey()(ent.PublicKey) {
			continue
		}
		candidates++
		if authorizationErr != nil {
			errs = append(errs, ent.Location()+": certificate not authorized: "+authorizationErr.Error())
		}
		restricted := mode != namespaceIgnored && len(ent.Options.Namespaces) > 0
		if restricted {
			if !patternsMatch(ent.Options.Namespaces, ns) {
				namespaceMismatches++
				errs = append(errs, ent.Location()+": namespace mismatch")
				continue
			}
			namespaceMatches++
		}
		if authorizationErr != nil {
			continue
		}
		if ent.Options.ValidAfter != nil && ts.Before(*ent.Options.ValidAfter) {
			errs = append(errs, ent.Location()+": not yet valid")
			continue
		}
		if ent.Options.ValidBefore != nil && ts.After(*ent.Options.ValidBefore) {
			errs = append(errs, ent.Location()+": expired")
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

// matchesCA reports whether cert names this entry's key as its CA.
func (e *Entry) matchesCA(cert *ssh.Certificate) bool {
	return cert != nil && cert.SignatureKey != nil &&
		sshsig.PublicKeyEqual(e.PublicKey, cert.SignatureKey)
}

// authorizePrincipal checks whether a valid certificate authorizes a principal.
func (e *Entry) authorizePrincipal(cert *ssh.Certificate, principal string) error {
	switch {
	case len(cert.ValidPrincipals) == 0:
		return fmt.Errorf("certificate lacks principal list")
	case principal != "":
		// Certificate principals are literal names, not patterns.
		if !slices.Contains(sshsig.CertificatePrincipals(cert), principal) {
			return fmt.Errorf("name is not a listed principal")
		}
	case len(e.matchingPrincipals(cert)) == 0:
		return fmt.Errorf("no certificate principal matches the entry")
	}
	return nil
}

// CertificatePrincipals returns the principals that match a CA entry's
// patterns when the certificate names that entry's key as its CA. It returns
// nil for other entries and keys. Validate the certificate with
// [sshsig.CertificateValidAt] before relying on these principals.
//
// ssh-keygen stops at an empty pattern here and ignores exclusions; honour
// both, so the result is a subset of what ssh-keygen -Y find-principals finds.
func (e *Entry) CertificatePrincipals(pk ssh.PublicKey) []string {
	if !e.Options.CertAuthority {
		return nil
	}
	cert, err := sshsig.CertificateDetails(pk)
	if err != nil || !e.matchesCA(cert) {
		return nil
	}
	return e.matchingPrincipals(cert)
}

func (e *Entry) matchingPrincipals(cert *ssh.Certificate) []string {
	patterns := strings.Split(e.Principal, ",")
	beforeEmpty := patterns
	if i := slices.Index(patterns, ""); i >= 0 {
		beforeEmpty = patterns[:i]
	}
	var principals []string
	for _, p := range sshsig.CertificatePrincipals(cert) {
		if p != "" && patternsMatch(beforeEmpty, p) && patternsMatch(patterns, p) {
			principals = append(principals, p)
		}
	}
	return principals
}
