// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentCertSigner wraps a certificate key like an agent. honourAlgorithm
// controls whether it respects RSA-SHA2 requests.
type agentCertSigner struct {
	signer           ssh.AlgorithmSigner
	honourAlgorithm  bool
	publicKeyWrapper ssh.PublicKey
}

func newAgentCertSigner(t *testing.T, honourAlgorithm bool) agentCertSigner {
	t.Helper()

	certSigner := newRSACertificateSigner(t)
	algorithmSigner, ok := certSigner.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("certificate signer does not implement ssh.AlgorithmSigner")
	}
	pk := certSigner.PublicKey()
	return agentCertSigner{
		signer:          algorithmSigner,
		honourAlgorithm: honourAlgorithm,
		publicKeyWrapper: wrappedKey{
			format: pk.Type(),
			blob:   pk.Marshal(),
		},
	}
}

func (s agentCertSigner) PublicKey() ssh.PublicKey { return s.publicKeyWrapper }

func (s agentCertSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.Sign(rand, data)
}

func (s agentCertSigner) SignWithAlgorithm(
	rand io.Reader, data []byte, algorithm string,
) (*ssh.Signature, error) {
	if !s.honourAlgorithm {
		// Some agents ignore algorithm flags for certificate keys.
		return s.signer.Sign(rand, data)
	}
	return s.signer.SignWithAlgorithm(rand, data, algorithm)
}

// Agent wrappers must not hide RSA certificates from SHA-2 selection.
func TestSignatureCreateUsesSHA2ForAnAgentHeldRSACertificate(t *testing.T) {
	signer := newAgentCertSigner(t, true)
	if _, isCert := signer.PublicKey().(*ssh.Certificate); isCert {
		t.Fatal("public key is a *ssh.Certificate, so it does not cover the agent case")
	}

	sig, err := SignatureCreate(signer, "file", strings.NewReader("data\n"))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	if sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("signature format = %q, want %q", sig.Signature.Format, ssh.KeyAlgoRSASHA512)
	}
}

// Reject SHA-1 if the agent ignores the requested SHA-2 algorithm.
func TestSignatureCreateRejectsSHA1FromAnAgent(t *testing.T) {
	signer := newAgentCertSigner(t, false)

	sig, err := SignatureCreate(signer, "file", strings.NewReader("data\n"))
	if err == nil {
		t.Fatalf("SignatureCreate() produced a %q signature, want an error",
			sig.Signature.Format)
	}
	if !strings.Contains(err.Error(), "RSA signature format") {
		t.Errorf("SignatureCreate() error = %v, want it to name the RSA format", err)
	}
}

// Signing through the agent with an RSA certificate must embed the
// certificate as received, which the CA signed.
func TestAgentSignerKeepsTheRSACertificateEncoding(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("adding key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	blob := reencodeCertificate(t, signer.PublicKey(), true)
	pk, err := ParsePublicKey(base64.StdEncoding.EncodeToString(blob))
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}

	certSigner, err := AgentSigner(nil, nil, keyring, pk)
	if err != nil {
		t.Fatalf("AgentSigner() error = %v", err)
	}
	sig, err := SignatureCreate(certSigner, "file", strings.NewReader("data\n"))
	if err != nil {
		t.Fatalf("SignatureCreate() error = %v", err)
	}
	if !bytes.Equal(sig.PublicKey.Marshal(), blob) {
		t.Error("signature public key is not the certificate as received")
	}
	if err := CertificateValidAt(sig.PublicKey, time.Now()); err != nil {
		t.Errorf("CertificateValidAt() error = %v", err)
	}
	if sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("signature format = %q, want %q", sig.Signature.Format, ssh.KeyAlgoRSASHA512)
	}
	if err := SignatureVerify(strings.NewReader("data\n"), sig); err != nil {
		t.Errorf("SignatureVerify() error = %v", err)
	}
}
