// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func goldenMLDSA44Ed25519(t *testing.T) *Signature {
	t.Helper()
	sig, err := SignatureRead(strings.NewReader(goldenMLDSA44Ed25519SHA512))
	if err != nil {
		t.Fatalf("SignatureRead() error = %v", err)
	}
	return sig
}

func TestMLDSA44Ed25519PublicKey(t *testing.T) {
	pk, err := ParsePublicKeyLine(goldenMLDSA44Ed25519Key + " comment")
	if err != nil {
		t.Fatalf("ParsePublicKeyLine() error = %v", err)
	}
	if pk.Type() != KeyAlgoMLDSA44Ed25519 {
		t.Errorf("Type() = %q, want %q", pk.Type(), KeyAlgoMLDSA44Ed25519)
	}
	if got := PublicKeyString(pk); got != goldenMLDSA44Ed25519Key {
		t.Errorf("PublicKeyString() = %.60q..., want the parsed key line", got)
	}
	// As printed by `ssh-keygen -l`.
	const fingerprint = "SHA256:EOHQn7wEb3H6tL/KKPIex2ADyYAcF5u0w8nyyjnDq1A"
	if got := ssh.FingerprintSHA256(pk); got != fingerprint {
		t.Errorf("FingerprintSHA256() = %q, want %q", got, fingerprint)
	}
}

func TestMLDSA44Ed25519RejectsMalformedKeys(t *testing.T) {
	pk, err := ParsePublicKeyLine(goldenMLDSA44Ed25519Key)
	if err != nil {
		t.Fatalf("ParsePublicKeyLine() error = %v", err)
	}
	var wire struct {
		Name string
		Key  []byte
	}
	if err := ssh.Unmarshal(pk.Marshal(), &wire); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	for name, blob := range map[string][]byte{
		"short key": ssh.Marshal(struct {
			Name string
			Key  []byte
		}{wire.Name, wire.Key[1:]}),
		"long key": ssh.Marshal(struct {
			Name string
			Key  []byte
		}{wire.Name, append(wire.Key, 0)}),
		"trailing data": append(pk.Marshal(), 0, 0, 0, 0),
		"missing key":   ssh.Marshal(struct{ Name string }{wire.Name}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString(blob)); err == nil {
				t.Error("ParsePublicKey() error = nil, want a failure")
			}
		})
	}
}

// Each half must verify on its own, or the hybrid is only as strong as the
// weaker algorithm.
func TestMLDSA44Ed25519RequiresBothSignatures(t *testing.T) {
	for name, offset := range map[string]int{
		"ml-dsa":  0,
		"ed25519": mldsa44SignatureSize,
	} {
		t.Run(name, func(t *testing.T) {
			sig := goldenMLDSA44Ed25519(t)
			sig.Signature.Blob[offset] ^= 1
			err := SignatureVerify(strings.NewReader(goldenData), sig)
			if err == nil || err.Error() != "signature did not verify" {
				t.Errorf("SignatureVerify() error = %v, want %q", err, "signature did not verify")
			}
		})
	}
}

func TestMLDSA44Ed25519RejectsMalformedSignatures(t *testing.T) {
	for name, mutate := range map[string]func(*ssh.Signature){
		"short":        func(s *ssh.Signature) { s.Blob = s.Blob[1:] },
		"long":         func(s *ssh.Signature) { s.Blob = append(s.Blob, 0) },
		"other format": func(s *ssh.Signature) { s.Format = ssh.KeyAlgoED25519 },
	} {
		t.Run(name, func(t *testing.T) {
			sig := goldenMLDSA44Ed25519(t)
			mutate(sig.Signature)
			if err := sig.PublicKey.Verify([]byte(goldenData), sig.Signature); err == nil {
				t.Error("Verify() error = nil, want a failure")
			}
		})
	}
}

// Another key's signature must not verify, even when both share the Ed25519
// half.
func TestMLDSA44Ed25519RejectsAnotherMLDSAKey(t *testing.T) {
	sig := goldenMLDSA44Ed25519(t)
	var wire struct {
		Name string
		Key  []byte
	}
	if err := ssh.Unmarshal(sig.PublicKey.Marshal(), &wire); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	wire.Key[0] ^= 1
	other, err := ParsePublicKey(base64.StdEncoding.EncodeToString(ssh.Marshal(wire)))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	sig.PublicKey = other
	if err := SignatureVerify(strings.NewReader(goldenData), sig); err == nil {
		t.Error("SignatureVerify() error = nil, want a failure")
	}
}

func TestMLDSA44Ed25519SignatureInfo(t *testing.T) {
	info := NewPublicKeyInfo(goldenMLDSA44Ed25519(t).PublicKey)
	if info.Format != KeyAlgoMLDSA44Ed25519 || info.Application != nil {
		t.Errorf("NewPublicKeyInfo() = %+v, want format %q and no application",
			info, KeyAlgoMLDSA44Ed25519)
	}
}

// mldsa44Ed25519Signer signs like OpenSSH, offering its key the way an agent
// listing does.
type mldsa44Ed25519Signer struct {
	mldsa   *mldsa.PrivateKey
	ed25519 ed25519.PrivateKey
}

func newMLDSA44Ed25519Signer(t *testing.T) mldsa44Ed25519Signer {
	t.Helper()
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generating ML-DSA key: %v", err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	return mldsa44Ed25519Signer{mldsa: mldsaKey, ed25519: ed25519Key}
}

func (s mldsa44Ed25519Signer) PublicKey() ssh.PublicKey {
	key := append(s.mldsa.PublicKey().Bytes(), s.ed25519.Public().(ed25519.PublicKey)...)
	return &agent.Key{
		Format: KeyAlgoMLDSA44Ed25519,
		Blob: ssh.Marshal(struct {
			Name string
			Key  []byte
		}{KeyAlgoMLDSA44Ed25519, key}),
	}
}

func (s mldsa44Ed25519Signer) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	digest := sha512.Sum512(data)
	message := append([]byte(compositePrefix+compositeLabel+"\x00"), digest[:]...)
	sig, err := s.mldsa.Sign(nil, message, &mldsa.Options{Context: compositeLabel})
	if err != nil {
		return nil, err
	}
	sig = append(sig, ed25519.Sign(s.ed25519, message)...)
	return &ssh.Signature{Format: KeyAlgoMLDSA44Ed25519, Blob: sig}, nil
}

func TestMLDSA44Ed25519AgentSignatureVerifies(t *testing.T) {
	sig, err := SignatureCreate(newMLDSA44Ed25519Signer(t), "file", strings.NewReader(goldenData))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	if err := SignatureVerify(strings.NewReader(goldenData), sig); err != nil {
		t.Errorf("SignatureVerify() error = %v, want nil", err)
	}
}

func TestMLDSA44Ed25519RejectsTruncatedCertificate(t *testing.T) {
	blob := ssh.Marshal(struct {
		Name  string
		Nonce []byte
	}{"ssh-mldsa44-ed25519-cert", []byte("nonce")})
	_, err := ParsePublicKey(base64.StdEncoding.EncodeToString(blob))
	const want = "invalid ML-DSA certificate"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("ParsePublicKey() error = %v, want %q", err, want)
	}
}

func TestParsePublicKeyBlobReturnsNilKeyOnError(t *testing.T) {
	blob := ssh.Marshal(struct {
		Name  string
		Nonce []byte
	}{"ssh-mldsa44-ed25519-cert", []byte("nonce")})
	if pk, err := parsePublicKeyBlob(blob); pk != nil || err == nil {
		t.Errorf("parsePublicKeyBlob() = %#v, %v, want nil and an error", pk, err)
	}
}

// certificateTestSigner signs as a certificate it presents.
type certificateTestSigner struct {
	ssh.Signer
	pk ssh.PublicKey
}

func (s certificateTestSigner) PublicKey() ssh.PublicKey { return s.pk }

// issueMLDSACertificate certifies the signer's key, which ssh.Certificate's
// SignCert cannot encode.
func issueMLDSACertificate(t *testing.T, signer ssh.Signer, principals ...string) *ssh.Certificate {
	t.Helper()
	subject, err := verifiablePublicKey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ca := newSigner(t)
	cert := &ssh.Certificate{Key: subject, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity,
		ValidPrincipals: principals, SignatureKey: ca.PublicKey()}
	unsigned, err := marshalMLDSACertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the empty signature field.
	if cert.Signature, err = ca.Sign(rand.Reader, unsigned[:len(unsigned)-4]); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestMLDSACertificateAcceptsOpaqueExtension(t *testing.T) {
	const name = "binary@example.test"
	ca := newMLDSA44Ed25519Signer(t)
	cert := &ssh.Certificate{
		Key: newSigner(t).PublicKey(), CertType: ssh.UserCert,
		ValidBefore: ssh.CertTimeInfinity, SignatureKey: ca.PublicKey(),
		Permissions: ssh.Permissions{Extensions: map[string]string{name: ""}},
	}
	field := func(data string) []byte {
		tuple := ssh.Marshal(struct{ Name, Data string }{name, data})
		return ssh.Marshal(struct{ Extension []byte }{tuple})
	}
	const payload = "\x01\x00\xff"
	unsigned := cert.Marshal()
	unsigned = bytes.Replace(unsigned[:len(unsigned)-4], field(""), field(payload), 1)
	signature, err := ca.Sign(rand.Reader, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(unsigned, ssh.Marshal(struct{ Signature []byte }{ssh.Marshal(signature)})...)
	key, err := ParsePublicKeyBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Marshal(), blob) {
		t.Error("Marshal() changed the signed certificate")
	}
	details, err := CertificateDetails(key)
	if err != nil || details.Extensions[name] != payload {
		t.Errorf("CertificateDetails() = %v, %v, want the opaque extension", details, err)
	}
}

func TestSignatureCreateWithAConcreteMLDSACertificate(t *testing.T) {
	signer := newMLDSA44Ed25519Signer(t)
	cert := issueMLDSACertificate(t, signer, "alice@example.com")
	sig, err := SignatureCreate(certificateTestSigner{signer, cert}, "file", strings.NewReader(goldenData))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	if err := SignatureVerify(strings.NewReader(goldenData), sig); err != nil {
		t.Errorf("SignatureVerify() error = %v", err)
	}
	if err := CertificateValidAt(sig.PublicKey, time.Now()); err != nil {
		t.Errorf("CertificateValidAt() error = %v", err)
	}
}

func TestVerifyRejectsAMalformedConcreteMLDSACertificate(t *testing.T) {
	signer := newMLDSA44Ed25519Signer(t)
	sig, err := SignatureCreate(signer, "file", strings.NewReader(goldenData))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	sig.PublicKey = issueMLDSACertificate(t, signer, "alice@example.com\x00x")
	for name, verify := range map[string]func(io.Reader, *Signature) error{
		"Verify": Verify, "SignatureVerify": SignatureVerify,
	} {
		if err := verify(strings.NewReader(goldenData), sig); err == nil || !strings.Contains(err.Error(), "NUL byte") {
			t.Errorf("%s() error = %v, want a NUL byte error", name, err)
		}
	}
}
