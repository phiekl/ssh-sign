// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package revokedkeys

import (
	"strings"
	"testing"
)

// Like ssh-keygen, fail on a certificate whose CA signature does not verify,
// rather than revoke whatever key it names.
func TestParseFailsOnAForgedCertificate(t *testing.T) {
	cert := issue(t, newSigner(t), newSigner(t).PublicKey())
	cert.Key = newSigner(t).PublicKey()

	_, err := Parse(strings.NewReader(keyLine(cert) + "\n"))
	if err == nil || !strings.Contains(err.Error(), "certificate signature") {
		t.Errorf("Parse() error = %v, want a certificate signature error", err)
	}
}
