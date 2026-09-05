// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
