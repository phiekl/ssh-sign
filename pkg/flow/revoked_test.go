// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

func verifyRevoked(signed certSigned, revoked ...string) (*VerifyResult, []error) {
	var files []NamedReader
	for i, content := range revoked {
		files = append(files, NamedReader{
			Name: "revoked" + strconv.Itoa(i+1), Reader: strings.NewReader(content),
		})
	}
	return Verify(&VerifyOpts{
		AllowedSignersFile: strings.NewReader("* cert-authority " + signed.caLine + "\n"),
		Namespace:          "git",
		Principal:          "alice@example.com",
		RevokedKeysFiles:   files,
		SignatureFile:      strings.NewReader(signed.armored),
		VerifyFile:         strings.NewReader(testData),
	})
}

func TestVerifyChecksRevokedKeys(t *testing.T) {
	signed := signWithCertificate(t, 0, uint64(ssh.CertTimeInfinity))
	sig, err := sshsig.SignatureRead(strings.NewReader(signed.armored))
	if err != nil {
		t.Fatalf("SignatureRead() error = %v", err)
	}
	cert, _ := sshsig.AsCertificate(sig.PublicKey)
	plainLine := sshsig.PublicKeyString(cert.Key)

	tests := []struct {
		name    string
		revoked []string
		wantErr string
	}{
		{name: "not revoked", revoked: []string{"# none\n"}},
		{name: "no files"},
		{name: "signer key", revoked: []string{"# none\n", plainLine + "\n"},
			wantErr: `signer public key is revoked: file="revoked2" line=1`},
		{name: "certificate", revoked: []string{"\n" + signed.certLine + "\n"},
			wantErr: `signer public key is revoked: file="revoked1" line=2`},
		{name: "CA key", revoked: []string{signed.caLine + "\n"},
			wantErr: `signer certificate authority is revoked: file="revoked1" line=1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, errs := verifyRevoked(signed, tt.revoked...)
			if res == nil {
				t.Fatalf("Verify() errors = %v", errs)
			}
			if tt.wantErr == "" {
				if len(errs) != 0 || res.Authentication != "valid" {
					t.Errorf("Verify() = %+v, %v, want it valid", res, errs)
				}
				return
			}
			if errorText(errs) != tt.wantErr {
				t.Errorf("Verify() errors = %q, want %q", errorText(errs), tt.wantErr)
			}
			// Other results are still reported.
			if res.Authentication != "invalid" || res.Designation != "valid" || res.Verification != "valid" {
				t.Errorf("Verify() = %+v, want only authentication invalid", res)
			}
		})
	}
}

// ssh-keygen fails verification when it cannot read the revoked keys.
func TestVerifyFailsOnAMalformedRevokedKeysFile(t *testing.T) {
	signed := signWithCertificate(t, 0, uint64(ssh.CertTimeInfinity))
	res, errs := verifyRevoked(signed, "# fine\n", "\ngarbage\n")
	if res != nil {
		t.Errorf("Verify() = %+v, want no result", res)
	}
	if want := `failed parsing revoked keys: file="revoked2" line=2: expected a key type and key`; !strings.Contains(errorText(errs), want) {
		t.Errorf("Verify() errors = %q, want %q", errorText(errs), want)
	}
}
