// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testCertificate creates a certificate with Unix-second validity bounds.
func testCertificate(t *testing.T, certType uint32, validAfter, validBefore uint64) *ssh.Certificate {
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
		Key:         signer.PublicKey(),
		CertType:    certType,
		KeyId:       "test",
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	return cert
}

func TestCertificateValidAt(t *testing.T) {
	const day = 24 * 60 * 60
	now := time.Unix(1_000_000, 0)

	tests := map[string]struct {
		cert    *ssh.Certificate
		wantErr string
	}{
		"within window": {
			cert: testCertificate(t, ssh.UserCert, 1_000_000-day, 1_000_000+day),
		},
		"no expiry": {
			cert: testCertificate(t, ssh.UserCert, 0, uint64(ssh.CertTimeInfinity)),
		},
		"expired": {
			cert:    testCertificate(t, ssh.UserCert, 0, 1_000_000-day),
			wantErr: "certificate expired",
		},
		"not yet valid": {
			cert:    testCertificate(t, ssh.UserCert, 1_000_000+day, uint64(ssh.CertTimeInfinity)),
			wantErr: "certificate is not valid until",
		},
		// The window runs up to but not including ValidBefore, as in OpenSSH.
		"expires exactly now": {
			cert:    testCertificate(t, ssh.UserCert, 0, 1_000_000),
			wantErr: "certificate expired",
		},
		"valid from exactly now": {
			cert: testCertificate(t, ssh.UserCert, 1_000_000, uint64(ssh.CertTimeInfinity)),
		},
		// A host certificate authenticates a host, never a file signer.
		"host certificate": {
			cert:    testCertificate(t, ssh.HostCert, 0, uint64(ssh.CertTimeInfinity)),
			wantErr: "not a user certificate",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := CertificateValidAt(tt.cert, now)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CertificateValidAt() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CertificateValidAt() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("CertificateValidAt() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// wrappedKey mimics agent.Key by wrapping a public key blob.
type wrappedKey struct {
	format string
	blob   []byte
}

func (k wrappedKey) Type() string                      { return k.format }
func (k wrappedKey) Marshal() []byte                   { return k.blob }
func (wrappedKey) Verify([]byte, *ssh.Signature) error { return nil }

// Certificate validity must also be checked through agent wrappers.
func TestCertificateValidAtSeesThroughAnAgentKey(t *testing.T) {
	const day = 24 * 60 * 60
	now := time.Unix(1_000_000, 0)
	cert := testCertificate(t, ssh.UserCert, 0, 1_000_000-day)

	wrapped := wrappedKey{format: cert.Type(), blob: cert.Marshal()}
	if _, isCert := ssh.PublicKey(wrapped).(*ssh.Certificate); isCert {
		t.Fatal("wrappedKey is a *ssh.Certificate, so it does not cover the agent case")
	}

	err := CertificateValidAt(wrapped, now)
	if err == nil {
		t.Fatal("CertificateValidAt() accepted an expired certificate behind an agent key")
	}
	if !strings.Contains(err.Error(), "certificate expired") {
		t.Errorf("CertificateValidAt() error = %v, want it to report expiry", err)
	}
}

// Malformed certificate blobs must not pass as plain keys.
func TestCertificateValidAtRejectsAMalformedCertificate(t *testing.T) {
	wrapped := wrappedKey{format: "ssh-ed25519" + certificateSuffix, blob: []byte("junk")}
	if err := CertificateValidAt(wrapped, time.Now()); err == nil {
		t.Error("CertificateValidAt() accepted a malformed certificate blob")
	}
}

// Reject a nil interface; a typed nil certificate is ignored.
func TestCertificateValidAtHandlesNilKeys(t *testing.T) {
	if err := CertificateValidAt(nil, time.Now()); err == nil {
		t.Error("CertificateValidAt(nil) error = nil, want a required-key error")
	}
	if err := CertificateValidAt((*ssh.Certificate)(nil), time.Now()); err != nil {
		t.Errorf("CertificateValidAt() error = %v, want nil for a typed nil", err)
	}
}

// Plain keys have no certificate validity window.
func TestCertificateValidAtIgnoresPlainKeys(t *testing.T) {
	pk, err := PublicKeyLineParse(testKey)
	if err != nil {
		t.Fatalf("PublicKeyLineParse() error = %v", err)
	}
	if err := CertificateValidAt(pk, time.Now()); err != nil {
		t.Errorf("CertificateValidAt() error = %v, want nil for a plain key", err)
	}
}
