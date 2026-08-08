// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

// MatchEntry finds the first entry matching given pubkey and optionally a principal.
// Any namespace or time restriction defined by the entry will be validated.
func (f *File) MatchEntry(pk ssh.PublicKey, principal, ns string, ts time.Time) (*Entry, error) {
	var errs []string
	for i := range f.Entries {
		ent := &f.Entries[i]

		if principal != "" && !patternListMatch(ent.Principal, principal) {
			continue
		}
		if !sshsigx.PublicKeyEqual(ent.PublicKey, pk) {
			continue
		}
		if len(ent.Options.Namespaces) > 0 && !patternsMatch(ent.Options.Namespaces, ns) {
			errs = append(errs, fmt.Sprintf("line=%d: namespace mismatch", ent.Line))
			continue
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
		return nil, fmt.Errorf("%s", strings.Join(errs, ", "))
	}

	// Principal/pubkey was not found => no entry, but no error either.
	return nil, nil
}
