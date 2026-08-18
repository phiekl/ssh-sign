// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"crypto/ed25519"
	"crypto/rand"
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
		wantErr string
	}{
		"empty":       {input: "", wantErr: "no data read"},
		"not armored": {input: "hello\n", wantErr: "unarmoring data failed"},
		"non-empty reserved field": {
			input: nonEmptyReserved, wantErr: "reserved field is not empty",
		},
		// The reader caps input well above the largest signature ssh-keygen
		// produces, so an oversized one is refused rather than buffered.
		"too large": {input: armored + strings.Repeat("x", 8192), wantErr: "exceeds 8192 bytes"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := SignatureRead(strings.NewReader(tt.input))
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
