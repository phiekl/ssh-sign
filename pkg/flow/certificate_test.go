// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// certSigned is a signature made with a certificate identity, together with
// the certificate's and its CA's authorized_keys lines.
type certSigned struct {
	armored  string
	certLine string
	caLine   string
}

// signWithCertificate signs testData under a certificate with the given
// window, in seconds since the epoch.
func signWithCertificate(t *testing.T, validAfter, validBefore uint64) certSigned {
	t.Helper()
	return signWithPrincipals(t, validAfter, validBefore, "alice@example.com")
}

func signWithPrincipals(t *testing.T, validAfter, validBefore uint64, principals ...string) certSigned {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("creating CA signer: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: principals,
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatalf("creating certificate signer: %v", err)
	}

	sig, err := sshsig.Sign(strings.NewReader(testData), certSigner, sshsig.HashSHA512, "git")
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return certSigned{
		armored:  string(sshsig.Armor(sig)),
		certLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		caLine:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey()))),
	}
}

// An explicitly trusted certificate must still satisfy its validity window.
func TestVerifyRejectsAnExpiredCertificate(t *testing.T) {
	const day = 24 * 60 * 60
	expired := signWithCertificate(t, 0, uint64(time.Now().Unix()-day))

	opts := &VerifyOpts{
		AllowedSignersFile: strings.NewReader("alice@example.com " + expired.certLine + "\n"),
		Namespace:          "git",
		Principal:          "alice@example.com",
		SignatureFile:      strings.NewReader(expired.armored),
		VerifyFile:         strings.NewReader(testData),
	}
	res, errs := Verify(opts)
	if !strings.Contains(errorText(errs), "certificate expired") {
		t.Fatalf("Verify() errors = %v, want the certificate rejected", errs)
	}
	if res.Authentication != "invalid" {
		t.Errorf("Authentication = %q, want %q", res.Authentication, "invalid")
	}
	// The signature is valid, but the certificate has expired.
	if res.Verification != "valid" {
		t.Errorf("Verification = %q, want %q", res.Verification, "valid")
	}
}

// Use the requested verification time for certificate validity.
func TestVerifyAcceptsACertificateWithinTheRequestedTime(t *testing.T) {
	const day = 24 * 60 * 60
	validAfter := uint64(time.Now().Unix() - 10*day)
	validBefore := uint64(time.Now().Unix() - day)
	expired := signWithCertificate(t, validAfter, validBefore)

	opts := &VerifyOpts{
		AllowedSignersFile: strings.NewReader("alice@example.com " + expired.certLine + "\n"),
		Namespace:          "git",
		Principal:          "alice@example.com",
		SignatureFile:      strings.NewReader(expired.armored),
		Timestamp:          time.Unix(int64(validAfter)+day, 0),
		VerifyFile:         strings.NewReader(testData),
	}
	res, errs := Verify(opts)
	if len(errs) != 0 {
		t.Fatalf("Verify() errors = %v, want none", errs)
	}
	if res.Authentication != "valid" || res.Verification != "valid" {
		t.Errorf("Verify() = %+v, want it valid at a time inside the window", res)
	}
}

func TestCheckRejectsAnExpiredCertificate(t *testing.T) {
	const day = 24 * 60 * 60
	expired := signWithCertificate(t, 0, uint64(time.Now().Unix()-day))

	opts := &CheckOpts{
		AuthKey:       expired.certLine,
		Namespace:     "git",
		SignatureFile: strings.NewReader(expired.armored),
		VerifyFile:    strings.NewReader(testData),
	}
	res, errs := Check(opts)
	if !strings.Contains(errorText(errs), "certificate expired") {
		t.Fatalf("Check() errors = %v, want the certificate rejected", errs)
	}
	if res.Authentication != "invalid" {
		t.Errorf("Authentication = %q, want %q", res.Authentication, "invalid")
	}
}

// Report key mismatches even when the certificate is expired.
func TestCheckReportsBothAKeyMismatchAndACertificateProblem(t *testing.T) {
	const day = 24 * 60 * 60
	expired := signWithCertificate(t, 0, uint64(time.Now().Unix()-day))
	other := sign(t, "git")

	opts := &CheckOpts{
		AuthKey:       other.keyLine,
		Namespace:     "git",
		SignatureFile: strings.NewReader(expired.armored),
		VerifyFile:    strings.NewReader(testData),
	}
	res, errs := Check(opts)
	text := errorText(errs)
	if !strings.Contains(text, "certificate expired") {
		t.Errorf("Check() errors = %v, want the certificate reported", errs)
	}
	if !strings.Contains(text, "was created by public key") {
		t.Errorf("Check() errors = %v, want the key mismatch reported", errs)
	}
	if res.Authentication != "invalid" {
		t.Errorf("Authentication = %q, want %q", res.Authentication, "invalid")
	}
}

// check -K skips certificate validity along with signer authentication.
func TestCheckAcceptsAnExpiredCertificateWithoutAuthKey(t *testing.T) {
	const day = 24 * 60 * 60
	expired := signWithCertificate(t, 0, uint64(time.Now().Unix()-day))

	opts := &CheckOpts{
		NoAuthKey:     true,
		Namespace:     "git",
		SignatureFile: strings.NewReader(expired.armored),
		VerifyFile:    strings.NewReader(testData),
	}
	res, errs := Check(opts)
	if len(errs) != 0 {
		t.Fatalf("Check() errors = %v, want none", errs)
	}
	if res.Authentication != "disabled" || res.Verification != "valid" {
		t.Errorf("Check() = %+v, want authentication disabled and a valid signature", res)
	}
}

func TestCheckHonoursTheRequestedTime(t *testing.T) {
	const day = 24 * 60 * 60
	validAfter := uint64(time.Now().Unix() - 10*day)
	expired := signWithCertificate(t, validAfter, uint64(time.Now().Unix()-day))

	opts := &CheckOpts{
		AuthKey:       expired.certLine,
		Namespace:     "git",
		SignatureFile: strings.NewReader(expired.armored),
		Timestamp:     time.Unix(int64(validAfter)+day, 0),
		VerifyFile:    strings.NewReader(testData),
	}
	res, errs := Check(opts)
	if len(errs) != 0 {
		t.Fatalf("Check() errors = %v, want none", errs)
	}
	if res.Authentication != "valid" {
		t.Errorf("Authentication = %q, want %q", res.Authentication, "valid")
	}
}

// Refuse expired certificates before signing.
func TestSignRejectsAnExpiredCertificate(t *testing.T) {
	const day = 24 * 60 * 60

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("creating CA signer: %v", err)
	}
	cert := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidBefore: uint64(time.Now().Unix() - day),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatalf("creating certificate signer: %v", err)
	}

	_, err = Sign(&SignOpts{
		DataFile:  strings.NewReader(testData),
		Namespace: "git",
		Signer:    certSigner,
	})
	if err == nil || !strings.Contains(err.Error(), "signing key certificate expired") {
		t.Fatalf("Sign() error = %v, want the expired certificate refused", err)
	}
}

// Without -p, report the certificate principals the CA entry allows, as
// ssh-keygen -Y find-principals does, not the entry's pattern-list.
func TestVerifyReportsCertificatePrincipalsForACertAuthority(t *testing.T) {
	signed := signWithCertificate(t, 0, uint64(ssh.CertTimeInfinity))
	allowed := "*@example.com cert-authority " + signed.caLine + "\n"

	tests := []struct {
		principal, wantPrincipal, wantAuthentication string
	}{
		{"", "alice@example.com", "disabled"},
		{"alice@example.com", "alice@example.com", "valid"},
		{"bob@example.com", "bob@example.com", "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.principal, func(t *testing.T) {
			res, errs := Verify(&VerifyOpts{
				AllowedSignersFile: strings.NewReader(allowed),
				Namespace:          "git",
				Principal:          tt.principal,
				SignatureFile:      strings.NewReader(signed.armored),
				VerifyFile:         strings.NewReader(testData),
			})
			if res == nil {
				t.Fatalf("Verify() errors = %v", errs)
			}
			if res.Principal != tt.wantPrincipal || res.Authentication != tt.wantAuthentication {
				t.Errorf("Verify() = %+v, errors %v, want principal %q and authentication %q",
					res, errs, tt.wantPrincipal, tt.wantAuthentication)
			}
		})
	}
}

// A principal may contain the comma that separates them in principal.
func TestVerifyListsCertificatePrincipalsInJSON(t *testing.T) {
	signed := signWithPrincipals(t, 0, uint64(ssh.CertTimeInfinity), "bob@x,admin@x", "carol@x")
	res, errs := Verify(&VerifyOpts{
		AllowedSignersFile: strings.NewReader("* cert-authority " + signed.caLine + "\n"),
		Namespace:          "git",
		SignatureFile:      strings.NewReader(signed.armored),
		VerifyFile:         strings.NewReader(testData),
	})
	if res == nil {
		t.Fatalf("Verify() errors = %v", errs)
	}
	if want := []string{"bob@x,admin@x", "carol@x"}; !slices.Equal(res.Principals, want) {
		t.Errorf("Principals = %q, want %q", res.Principals, want)
	}
	if res.Principal != "bob@x,admin@x,carol@x" {
		t.Errorf("Principal = %q, want the joined principals", res.Principal)
	}
	out, err := json.Marshal(res)
	if err != nil || !strings.Contains(string(out), `"principals":["bob@x,admin@x","carol@x"]`) {
		t.Errorf("json.Marshal() = %s, %v, want the principals listed", out, err)
	}

	plain := signWithCertificate(t, 0, uint64(ssh.CertTimeInfinity))
	res, _ = Verify(&VerifyOpts{
		AllowedSignersFile: strings.NewReader("alice@example.com " + plain.certLine + "\n"),
		Namespace:          "git",
		SignatureFile:      strings.NewReader(plain.armored),
		VerifyFile:         strings.NewReader(testData),
	})
	if out, _ := json.Marshal(res); strings.Contains(string(out), "principals") {
		t.Errorf("json.Marshal() = %s, want no principals for a listed key", out)
	}
}
