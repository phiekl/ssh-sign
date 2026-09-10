// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"slices"
	"strings"
	"testing"

	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// Keep the output field names and order stable.
func TestInspectResultNamesEveryField(t *testing.T) {
	s := sign(t, "git")
	sig, err := sshsig.SignatureRead(strings.NewReader(s.armored))
	if err != nil {
		t.Fatalf("SignatureRead() error = %v", err)
	}

	var keys []string
	for _, line := range strings.Split(InspectResult{sshsig.NewSignatureInfo(sig)}.String(), "\n") {
		key, _, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("line %q holds no delimiter", line)
		}
		keys = append(keys, strings.TrimSpace(key))
	}

	want := []string{
		"version", "publickey_format", "publickey_blob", "publickey_fingerprint",
		"namespace", "hash_algorithm", "signature_format", "signature_blob",
	}
	if !slices.Equal(keys, want) {
		t.Errorf("InspectResult.String() keys = %v, want %v", keys, want)
	}
}
