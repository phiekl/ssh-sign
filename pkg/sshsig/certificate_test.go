// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

func TestParsePublicKeyBlobRejectsUnknownCertificateType(t *testing.T) {
	const unknownType = 3
	cert := testCertificate(t, unknownType, 0, ssh.CertTimeInfinity)
	if _, err := ParsePublicKeyBlob(cert.Marshal()); err == nil ||
		!strings.Contains(err.Error(), "unsupported certificate type 3") {
		t.Errorf("ParsePublicKeyBlob() error = %v, want an unsupported type error", err)
	}
	host := testCertificate(t, ssh.HostCert, 0, ssh.CertTimeInfinity)
	if _, err := ParsePublicKeyBlob(host.Marshal()); err != nil {
		t.Errorf("ParsePublicKeyBlob() rejected a host certificate: %v", err)
	}
}

func TestCertificateValidAtRejectsUnsignedCertificate(t *testing.T) {
	cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
	cert.SignatureKey = nil
	cert.Signature = nil
	if err := CertificateValidAt(cert, time.Now()); err == nil || err.Error() != "certificate signature is missing" {
		t.Errorf("CertificateValidAt() error = %v, want a missing signature error", err)
	}
}

func TestCertificateRejectsDSACASignatures(t *testing.T) {
	cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
	if err := cert.SignCert(rand.Reader, newDSASigner(t)); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	const want = `unsupported certificate signature algorithm "ssh-dss"`
	if err := CertificateValidAt(cert, time.Now()); err == nil || err.Error() != want {
		t.Errorf("CertificateValidAt() error = %v, want %q", err, want)
	}
	if _, err := ParsePublicKeyLine(PublicKeyString(cert)); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("ParsePublicKeyLine() error = %v, want it to contain %q", err, want)
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
	pk, err := ParsePublicKeyLine(testKey)
	if err != nil {
		t.Fatalf("ParsePublicKeyLine() error = %v", err)
	}
	if err := CertificateValidAt(pk, time.Now()); err != nil {
		t.Errorf("CertificateValidAt() error = %v, want nil for a plain key", err)
	}
}

// ssh-keygen checks the CA signature when it parses a certificate.
func TestCertificateValidAtRejectsAForgedCertificate(t *testing.T) {
	now := time.Unix(1_000_000, 0)

	tampered := testCertificate(t, ssh.UserCert, 0, uint64(ssh.CertTimeInfinity))
	tampered.ValidPrincipals = []string{"mallory"}

	wrongCA := testCertificate(t, ssh.UserCert, 0, uint64(ssh.CertTimeInfinity))
	wrongCA.SignatureKey = testCertificate(t, ssh.UserCert, 0, 0).SignatureKey

	caIsCert := testCertificate(t, ssh.UserCert, 0, uint64(ssh.CertTimeInfinity))
	caIsCert.SignatureKey = testCertificate(t, ssh.UserCert, 0, 0)

	for name, cert := range map[string]*ssh.Certificate{
		"tampered principals": tampered,
		"wrong CA key":        wrongCA,
		"certificate CA key":  caIsCert,
	} {
		t.Run(name, func(t *testing.T) {
			err := CertificateValidAt(cert, now)
			if err == nil || !strings.Contains(err.Error(), "certificate signature") {
				t.Errorf("CertificateValidAt() error = %v, want a certificate signature error", err)
			}
			wrapped := wrappedKey{format: cert.Type(), blob: cert.Marshal()}
			if CertificateValidAt(wrapped, now) == nil {
				t.Error("CertificateValidAt() accepted a forged certificate behind an agent key")
			}
			if err := CertificateSignatureValid(wrapped); err == nil {
				t.Error("CertificateSignatureValid() accepted an invalid CA signature")
			}
		})
	}
}

// reencodedCertificate returns a certificate blob whose permit-pty extension
// payload is an encoded empty string rather than empty. Go normalises it back
// on Marshal. With resign, the CA signs the changed bytes.
func reencodedCertificate(t *testing.T, resign bool) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return reencodeCertificate(t, key.PublicKey(), resign)
}

// reencodeCertificate is reencodedCertificate for the given subject key.
func reencodeCertificate(t *testing.T, subject ssh.PublicKey, resign bool) []byte {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("creating CA signer: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             subject,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice@example.com"},
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}

	field := func(payload string) []byte {
		return ssh.Marshal(struct{ B []byte }{ssh.Marshal(struct{ N, P string }{"permit-pty", payload})})
	}
	blob := cert.Marshal()
	sigField := ssh.Marshal(struct{ B []byte }{ssh.Marshal(cert.Signature)})
	signed := bytes.Replace(blob[:len(blob)-len(sigField)], field(""), field("\x00\x00\x00\x00"), 1)
	if bytes.Equal(signed, blob[:len(blob)-len(sigField)]) {
		t.Fatal("extension field not found")
	}
	if resign {
		sig, err := ca.Sign(rand.Reader, signed)
		if err != nil {
			t.Fatalf("re-signing: %v", err)
		}
		sigField = ssh.Marshal(struct{ B []byte }{ssh.Marshal(sig)})
	}
	return append(signed, sigField...)
}

// The CA signs the received bytes, which Go's Marshal may not reproduce.
func TestCertificateSignatureCoversTheReceivedEncoding(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	for name, tt := range map[string]struct {
		resign bool
		valid  bool
	}{
		"changed without re-signing": {resign: false, valid: false},
		"changed and re-signed":      {resign: true, valid: true},
	} {
		t.Run(name, func(t *testing.T) {
			blob := reencodedCertificate(t, tt.resign)

			pk, err := ParsePublicKey(base64.StdEncoding.EncodeToString(blob))
			if (err == nil) != tt.valid {
				t.Errorf("ParsePublicKey() error = %v, want valid %v", err, tt.valid)
			}

			pk, err = parseKeyBlob(blob)
			if err != nil {
				t.Fatalf("parseKeyBlob() error = %v", err)
			}
			if !bytes.Equal(pk.Marshal(), blob) {
				t.Error("Marshal() does not return the received encoding")
			}
			if err := CertificateValidAt(pk, now); (err == nil) != tt.valid {
				t.Errorf("CertificateValidAt() error = %v, want valid %v", err, tt.valid)
			}
		})
	}
}

// Like OpenSSH, certificates are equal only if their encodings are.
func TestPublicKeyEqualComparesTheReceivedEncoding(t *testing.T) {
	blob := reencodedCertificate(t, true)
	pk, err := parseKeyBlob(blob)
	if err != nil {
		t.Fatalf("parseKeyBlob() error = %v", err)
	}
	normalised, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey() error = %v", err)
	}
	if PublicKeyEqual(pk, normalised) {
		t.Error("PublicKeyEqual() = true for differently encoded certificates")
	}
}

// Changing a certificate obtained from CertificateDetails must not change what
// the received key authorizes; only its CA-signed encoding counts.
func TestCertificateDetailsReturnsACopy(t *testing.T) {
	blob := reencodedCertificate(t, true)
	pk, err := ParsePublicKey(base64.StdEncoding.EncodeToString(blob))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	cert, err := CertificateDetails(pk)
	if err != nil {
		t.Fatalf("CertificateDetails() error = %v", err)
	}
	nonce, reserved, sig := bytes.Clone(cert.Nonce), bytes.Clone(cert.Reserved), bytes.Clone(cert.Signature.Blob)
	cert.ValidPrincipals[0] = "mallory@example.com"
	cert.ValidPrincipals = append(cert.ValidPrincipals, "mallory@example.com")
	cert.Nonce[0] ^= 1
	cert.Reserved = append(cert.Reserved, 1)
	cert.CriticalOptions["force-command"] = "true"
	cert.Extensions["permit-user-rc"] = ""
	cert.Signature.Blob[0] ^= 1

	again, err := CertificateDetails(pk)
	if err != nil {
		t.Fatalf("CertificateDetails() error = %v", err)
	}
	if len(again.ValidPrincipals) != 1 || again.ValidPrincipals[0] != "alice@example.com" {
		t.Errorf("ValidPrincipals = %q after changing a copy, want [alice@example.com]", again.ValidPrincipals)
	}
	if !bytes.Equal(again.Nonce, nonce) || !bytes.Equal(again.Reserved, reserved) ||
		len(again.CriticalOptions) != 0 || len(again.Extensions) != 1 ||
		!bytes.Equal(again.Signature.Blob, sig) {
		t.Errorf("CertificateDetails() = %+v after changing a copy", again)
	}
	if err := CertificateSignatureValid(pk); err != nil {
		t.Errorf("CertificateSignatureValid() error = %v after changing a copy", err)
	}
}

// The keys of a copy may expose their bytes, so the copy needs its own keys.
func TestCertificateDetailsCopiesTheKeys(t *testing.T) {
	pk, err := ParsePublicKey(base64.StdEncoding.EncodeToString(reencodedCertificate(t, true)))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	want, err := CertificateDetails(pk)
	if err != nil {
		t.Fatalf("CertificateDetails() error = %v", err)
	}
	subject, ca := want.Key.Marshal(), want.SignatureKey.Marshal()
	for _, key := range []ssh.PublicKey{want.Key, want.SignatureKey} {
		key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)[0] ^= 1
	}
	again, err := CertificateDetails(pk)
	if err != nil {
		t.Fatalf("CertificateDetails() error = %v", err)
	}
	if !bytes.Equal(again.Key.Marshal(), subject) || !bytes.Equal(again.SignatureKey.Marshal(), ca) {
		t.Error("changing the keys of a copy changed the certificate")
	}
	if err := CertificateSignatureValid(pk); err != nil {
		t.Errorf("CertificateSignatureValid() error = %v after changing a copy", err)
	}
}

// OpenSSH's certificate parser limits apply with either kind of CA.
func TestParsePublicKeyRejectsCertificatesOpenSSHCannotParse(t *testing.T) {
	principals := func(n int) []string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("user%d@example.com", i)
		}
		return names
	}
	tests := []struct {
		name       string
		keyID      string
		principals []string
		wantErr    string
	}{
		{name: "256 principals", principals: principals(256)},
		{name: "257 principals", principals: principals(257),
			wantErr: "certificate has more than 256 principals"},
		{name: "NUL in the key ID", keyID: "revoked\x00x",
			wantErr: "certificate key ID contains a NUL byte"},
		{name: "NUL in a principal", principals: []string{"alice@example.com", "bob\x00x"},
			wantErr: "certificate principal contains a NUL byte"},
		{name: "trailing NULs", keyID: "cert\x00", principals: []string{"alice@example.com\x00"}},
	}
	for _, ca := range []ssh.Signer{newSigner(t), newMLDSA44Ed25519Signer(t)} {
		for _, tt := range tests {
			t.Run(ca.PublicKey().Type()+" "+tt.name, func(t *testing.T) {
				cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
				cert.KeyId = tt.keyID
				cert.ValidPrincipals = tt.principals
				if err := cert.SignCert(rand.Reader, ca); err != nil {
					t.Fatalf("signing certificate: %v", err)
				}
				pk, err := ParsePublicKey(base64.StdEncoding.EncodeToString(cert.Marshal()))
				if tt.wantErr == "" {
					if err != nil {
						t.Fatalf("ParsePublicKey() error = %v", err)
					}
					parsed, err := CertificateDetails(pk)
					if err != nil {
						t.Fatalf("CertificateDetails() error = %v", err)
					}
					// The fields keep the signed bytes, which re-encoding must reproduce.
					if parsed.KeyId != tt.keyID || !slices.Equal(parsed.ValidPrincipals, tt.principals) {
						t.Errorf("key ID %q, principals %q, want %q, %q",
							parsed.KeyId, parsed.ValidPrincipals, tt.keyID, tt.principals)
					}
					if err := CertificateValidAt(pk, time.Now()); err != nil {
						t.Errorf("CertificateValidAt() error = %v", err)
					}
					keyID, principals := CertificateKeyID(parsed), CertificatePrincipals(parsed)
					if keyID != strings.TrimSuffix(tt.keyID, "\x00") || len(principals) != len(tt.principals) ||
						principals[0] != strings.TrimSuffix(tt.principals[0], "\x00") {
						t.Errorf("CertificateKeyID() = %q, CertificatePrincipals() = %q, "+
							"want them without a trailing NUL", keyID, principals)
					}
				} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParsePublicKey() error = %v, want it to contain %q", err, tt.wantErr)
				}
			})
		}
	}
}

// The immutable certificate supports ML-DSA encoding through all public APIs.
func TestAsCertificateResultWorksWithMLDSASubjects(t *testing.T) {
	line, err := os.ReadFile("testdata/mldsa44-ed25519-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePublicKeyLine(string(line))
	if err != nil {
		t.Fatalf("ParsePublicKeyLine() error = %v", err)
	}
	cert, err := AsCertificate(pk)
	if err != nil {
		t.Fatalf("AsCertificate() error = %v", err)
	}
	if err := CertificateValidAt(cert, time.Now()); err != nil {
		t.Errorf("CertificateValidAt() error = %v", err)
	}
	if !PublicKeyEqual(cert, pk) {
		t.Error("PublicKeyEqual() = false, want true")
	}
	if got, want := PublicKeyString(cert), PublicKeyString(pk); got != want {
		t.Errorf("PublicKeyString() = %q, want %q", got, want)
	}
	if got, want := NewPublicKeyInfo(cert), NewPublicKeyInfo(pk); got != want {
		t.Errorf("NewPublicKeyInfo() = %+v, want %+v", got, want)
	}
	sig := &Signature{Version: 1, PublicKey: pk, Namespace: "file", HashAlgorithm: HashSHA512,
		Signature: &ssh.Signature{Format: KeyAlgoMLDSA44Ed25519}}
	want := Armor(sig)
	sig.PublicKey = cert
	if got := Armor(sig); !bytes.Equal(got, want) {
		t.Errorf("Armor() = %q, want %q", got, want)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: other}); err != nil {
		t.Fatal(err)
	}
	const wantErr = "no key matched"
	if _, err := AgentSigner(nil, nil, keyring, cert); err == nil ||
		!strings.Contains(err.Error(), wantErr) {
		t.Errorf("AgentSigner() error = %v, want it to contain %q", err, wantErr)
	}
}

type countingKey struct {
	ssh.PublicKey
	verifications int
}

func (k *countingKey) Verify(data []byte, sig *ssh.Signature) error {
	k.verifications++
	return k.PublicKey.Verify(data, sig)
}

func TestCertificateValidAtVerifiesTheCASignatureOnce(t *testing.T) {
	cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
	blob := cert.Marshal()
	ca := &countingKey{PublicKey: cert.SignatureKey}
	cert.SignatureKey = ca
	pk := &Certificate{cert: cert, blob: blob}
	for range 3 {
		if err := CertificateValidAt(pk, time.Now()); err != nil {
			t.Fatalf("CertificateValidAt() error = %v", err)
		}
	}
	if ca.verifications != 1 {
		t.Errorf("CA signature verified %d times, want once", ca.verifications)
	}
}

func TestCertificateValidAtChecksConcreteCertificateStrings(t *testing.T) {
	for name, change := range map[string]func(*ssh.Certificate){
		"key ID":     func(c *ssh.Certificate) { c.KeyId = "cert\x00x" },
		"principal":  func(c *ssh.Certificate) { c.ValidPrincipals = []string{"alice@example.com\x00x"} },
		"principals": func(c *ssh.Certificate) { c.ValidPrincipals = make([]string, 257) },
	} {
		t.Run(name, func(t *testing.T) {
			cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
			change(cert)
			if err := cert.SignCert(rand.Reader, newSigner(t)); err != nil {
				t.Fatal(err)
			}
			if err := CertificateValidAt(cert, time.Now()); err == nil {
				t.Error("CertificateValidAt() error = nil")
			}
		})
	}
}

// AsCertificate keeps the received encoding, which x/crypto/ssh re-encodes.
func TestCertificateValidAtUsesTheEncodingAsCertificateParsed(t *testing.T) {
	pk, err := ParsePublicKey(base64.StdEncoding.EncodeToString(reencodedCertificate(t, true)))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	cert, err := AsCertificate(pk)
	if err != nil {
		t.Fatalf("AsCertificate() error = %v", err)
	}
	if err := CertificateValidAt(cert, time.Now()); err != nil {
		t.Errorf("CertificateValidAt(AsCertificate()) error = %v", err)
	}
	if !PublicKeyEqual(cert, pk) {
		t.Error("PublicKeyEqual(AsCertificate(), pk) = false")
	}
	if cert != pk {
		t.Error("AsCertificate() did not reuse the parsed certificate")
	}

	details, err := CertificateDetails(cert)
	if err != nil {
		t.Fatal(err)
	}
	details.ValidPrincipals = []string{"mallory@example.com"}
	if err := CertificateValidAt(details, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "certificate signature is invalid") {
		t.Errorf("CertificateValidAt() error = %v after changing a principal, want an invalid signature", err)
	}
}

func TestAsCertificateChecksConcreteCertificateStrings(t *testing.T) {
	cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
	cert.ValidPrincipals = []string{"alice@example.com\x00x"}
	if got, err := AsCertificate(cert); got != nil || err == nil || !strings.Contains(err.Error(), "NUL byte") {
		t.Errorf("AsCertificate() = %v, %v, want a NUL byte error", got, err)
	}
}

func TestAsCertificateLeavesCallerExtraDataIntact(t *testing.T) {
	cert := testCertificate(t, ssh.UserCert, 0, ssh.CertTimeInfinity)
	cert.ExtraData = map[any]any{"caller": "metadata"}
	key, err := AsCertificate(cert)
	if err != nil || key == nil {
		t.Fatalf("AsCertificate() = %v, %v, want an immutable certificate", key, err)
	}
	if len(cert.ExtraData) != 1 || cert.ExtraData["caller"] != "metadata" {
		t.Errorf("caller ExtraData = %v, want the original metadata", cert.ExtraData)
	}
	details, err := CertificateDetails(key)
	if err != nil || details == nil {
		t.Fatalf("CertificateDetails() = %v, %v, want certificate fields", details, err)
	}
	if len(details.ExtraData) != 0 {
		t.Errorf("decoded ExtraData = %v, want no internal encoding data", details.ExtraData)
	}
}

// A parsed certificate is checked once; validating the signature reuses it.
func TestValidateStructureDoesNotReparseCertificates(t *testing.T) {
	signer := newSigner(t)
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	for i := range 256 {
		cert.ValidPrincipals = append(cert.ValidPrincipals, fmt.Sprintf("user%d@example.com", i))
	}
	if err := cert.SignCert(rand.Reader, newSigner(t)); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatal(err)
	}
	allocs := make(map[string]float64)
	for name, s := range map[string]ssh.Signer{"plain": signer, "certificate": certSigner} {
		created, err := SignatureCreate(s, "file", strings.NewReader("data"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := ParseSignature(Marshal(created))
		if err != nil {
			t.Fatal(err)
		}
		allocs[name] = testing.AllocsPerRun(10, func() { _ = validateStructure(sig) })
	}
	if allocs["certificate"] > allocs["plain"] {
		t.Errorf("validateStructure() allocations: %v for a certificate, %v for a plain key",
			allocs["certificate"], allocs["plain"])
	}
}
