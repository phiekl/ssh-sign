// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"crypto/dsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// newSigner returns an ephemeral ed25519 signer.
func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return signer
}

func TestSignatureRoundTrip(t *testing.T) {
	const data = "round trip\n"
	signer := newSigner(t)

	sig, err := SignatureCreate(signer, "git", strings.NewReader(data))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}

	read, err := SignatureRead(strings.NewReader(string(sshsig.Armor(sig))))
	if err != nil {
		t.Fatalf("SignatureRead() error = %v", err)
	}
	if read.Namespace != "git" {
		t.Errorf("Namespace = %q, want %q", read.Namespace, "git")
	}
	if err := SignatureVerify(strings.NewReader(data), read); err != nil {
		t.Errorf("SignatureVerify() error = %v, want nil", err)
	}
}

func newRSACertificateSigner(t *testing.T) ssh.Signer {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating RSA signer: %v", err)
	}
	ca := newSigner(t)
	cert := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatalf("creating certificate signer: %v", err)
	}
	return certSigner
}

func TestSignatureCreateUsesSHA2ForRSACertificate(t *testing.T) {
	sig, err := SignatureCreate(
		newRSACertificateSigner(t), "file", strings.NewReader("data\n"),
	)
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	if sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("signature format = %q, want %q", sig.Signature.Format, ssh.KeyAlgoRSASHA512)
	}
}

func TestSignatureReadRejectsSHA1ForRSACertificate(t *testing.T) {
	sig, err := sshsig.Sign(
		strings.NewReader("data\n"), newRSACertificateSigner(t), sshsig.HashSHA512, "file",
	)
	if err != nil {
		t.Fatalf("creating legacy certificate signature: %v", err)
	}
	if sig.Signature.Format != ssh.KeyAlgoRSA {
		t.Fatalf("legacy signature format = %q, want %q", sig.Signature.Format, ssh.KeyAlgoRSA)
	}

	_, err = SignatureRead(strings.NewReader(string(sshsig.Armor(sig))))
	if err == nil || !strings.Contains(err.Error(), "invalid RSA signature format") {
		t.Fatalf("SignatureRead() error = %v, want an invalid RSA signature format error", err)
	}
}

func TestSignatureReadRejectsDSA(t *testing.T) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatalf("generating DSA parameters: %v", err)
	}
	privateKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(privateKey, rand.Reader); err != nil {
		t.Fatalf("generating DSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating DSA signer: %v", err)
	}

	// Bypass SignatureCreate, which rejects DSA.
	sig, err := sshsig.Sign(strings.NewReader("data\n"), signer, sshsig.HashSHA512, "file")
	if err != nil {
		t.Fatalf("creating DSA signature: %v", err)
	}
	if _, err := SignatureRead(strings.NewReader(string(sshsig.Armor(sig)))); err == nil ||
		!strings.Contains(err.Error(), `unsupported signature algorithm "ssh-dss"`) {
		t.Fatalf("SignatureRead() error = %v, want a rejected DSA signature", err)
	}
	if _, err := SignatureCreate(signer, "file", strings.NewReader("data\n")); err == nil {
		t.Fatal("SignatureCreate() error = nil, want a rejected DSA signature")
	}
}

func TestSignatureVerifyRejectsOtherData(t *testing.T) {
	signer := newSigner(t)

	sig, err := SignatureCreate(signer, "git", strings.NewReader("original\n"))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}

	err = SignatureVerify(strings.NewReader("tampered\n"), sig)
	if err == nil {
		t.Fatal("SignatureVerify() error = nil, want a failure")
	}
	// The library's "ssh: " prefix is stripped for readability.
	if strings.HasPrefix(err.Error(), "ssh: ") {
		t.Errorf("SignatureVerify() error = %q, want the ssh: prefix removed", err)
	}
}

func TestSignatureRead(t *testing.T) {
	signer := newSigner(t)
	sig, err := SignatureCreate(signer, "git", strings.NewReader("data\n"))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	armored := string(sshsig.Armor(sig))
	block, _ := pem.Decode([]byte(armored))
	var wire signatureWire
	if err := ssh.Unmarshal(block.Bytes, &wire); err != nil {
		t.Fatalf("unmarshaling signature wire data: %v", err)
	}
	wire.Reserved = "future use"
	nonEmptyReserved := string(pem.EncodeToMemory(&pem.Block{
		Type:  sshsig.PEMType,
		Bytes: ssh.Marshal(&wire),
	}))

	tests := map[string]struct {
		input   string
		max     int64
		wantErr string
	}{
		"empty":       {input: "", wantErr: "no data read"},
		"not armored": {input: "hello\n", wantErr: "unarmoring data failed"},
		"non-empty reserved field": {
			input: nonEmptyReserved, wantErr: "reserved field is not empty",
		},
		// Oversized input is refused rather than buffered without bound.
		"too large": {
			input:   armored + strings.Repeat("x", 8192),
			max:     8192,
			wantErr: "exceeds 8192 bytes",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var err error
			if tt.max == 0 {
				_, err = SignatureRead(strings.NewReader(tt.input))
			} else {
				_, err = signatureRead(strings.NewReader(tt.input), tt.max)
			}
			if err == nil {
				t.Fatalf("SignatureRead() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SignatureRead() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewSignatureInfo(t *testing.T) {
	signer := newSigner(t)
	sig, err := SignatureCreate(signer, "git", strings.NewReader("data\n"))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}

	info := NewSignatureInfo(sig)
	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if info.Namespace != "git" {
		t.Errorf("Namespace = %q, want %q", info.Namespace, "git")
	}
	if info.HashAlgorithm != "sha512" {
		t.Errorf("HashAlgorithm = %q, want %q", info.HashAlgorithm, "sha512")
	}
	if info.Signature.Format != "ssh-ed25519" {
		t.Errorf("Signature.Format = %q, want %q", info.Signature.Format, "ssh-ed25519")
	}
	// Empty for a plain key. A security-key signature would carry its FIDO
	// flags and counter here, which is why the field is kept.
	if info.Signature.Rest != "" {
		t.Errorf("Signature.Rest = %q, want empty for an ed25519 signature", info.Signature.Rest)
	}
	if info.PublicKey.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Errorf("PublicKey.Fingerprint = %q, want the signer's", info.PublicKey.Fingerprint)
	}
}
