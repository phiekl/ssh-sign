// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// certSigned is a signature made with a certificate identity, together with
// the certificate's own authorized_keys line.
type certSigned struct {
	armored  string
	certLine string
}

// signWithCertificate signs testData under a certificate with the given
// window, in seconds since the epoch.
func signWithCertificate(t *testing.T, validAfter, validBefore uint64) certSigned {
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
		ValidPrincipals: []string{"alice@example.com"},
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

	_, errs := Sign(&SignOpts{
		DataFile:  strings.NewReader(testData),
		Namespace: "git",
		Signer:    certSigner,
	})
	if !strings.Contains(errorText(errs), "signing key certificate expired") {
		t.Fatalf("Sign() errors = %v, want the expired certificate refused", errs)
	}
}
