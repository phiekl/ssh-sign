// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

type signatureWire struct {
	MagicPreamble [6]byte
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

// maxSignatureArmorSize bounds malformed or hostile input while leaving ample
// room for certificate-backed signatures. It matches OpenSSH's hard sshbuf
// ceiling, which also bounds the armored signature buffer read by ssh-keygen.
const maxSignatureArmorSize = 0x8000000

// SignatureCreate creates a signature of the input data.
func SignatureCreate(signer ssh.Signer, ns string, in io.Reader) (*sshsig.Signature, error) {
	if isRSACertificate(signer.PublicKey()) {
		algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("signing failed: RSA signer does not support selecting a SHA-2 algorithm")
		}
		signer = rsaSHA512Signer{Signer: signer, algorithmSigner: algorithmSigner}
	}
	sig, err := sshsig.Sign(in, signer, sshsig.HashSHA512, ns)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	if err := validateSignatureAlgorithm(sig); err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig, nil
}

// SignatureRead unarmors a signature from the input data.
func SignatureRead(in io.Reader) (*sshsig.Signature, error) {
	return signatureRead(in, maxSignatureArmorSize)
}

func signatureRead(in io.Reader, max int64) (*sshsig.Signature, error) {
	data, err := io.ReadAll(io.LimitReader(in, max+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no data read")
	} else if int64(len(data)) > max {
		return nil, fmt.Errorf("read data exceeds %d bytes", max)
	}

	const armorHeader = "-----BEGIN SSH SIGNATURE-----"
	if !bytes.HasPrefix(data, []byte(armorHeader)) {
		return nil, fmt.Errorf("unarmoring data failed: signature does not start with %q", armorHeader)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("unarmoring data failed: invalid PEM block")
	}
	if block.Type != sshsig.PEMType {
		return nil, fmt.Errorf(
			"unarmoring data failed: invalid PEM type %q: expected %q",
			block.Type, sshsig.PEMType,
		)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("unarmoring data failed: PEM headers are not allowed")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unarmoring data failed: data found after signature")
	}

	sig, err := sshsig.ParseSignature(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unarmoring data failed: %v", err)
	}
	var wire signatureWire
	if err := ssh.Unmarshal(block.Bytes, &wire); err != nil {
		return nil, fmt.Errorf("unarmoring data failed: %v", err)
	}
	if wire.Reserved != "" {
		return nil, fmt.Errorf("signature reserved field is not empty")
	}
	if sig.Namespace == "" {
		return nil, fmt.Errorf("signature namespace is empty")
	}
	if err := validateSignatureAlgorithm(sig); err != nil {
		return nil, err
	}

	return sig, nil
}

func validateSignatureAlgorithm(sig *sshsig.Signature) error {
	if publicKeyType(sig.PublicKey) == ssh.KeyAlgoRSA &&
		sig.Signature.Format != ssh.KeyAlgoRSASHA256 &&
		sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		return fmt.Errorf(
			"invalid RSA signature format %q: expected %q or %q",
			sig.Signature.Format, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
		)
	}
	return nil
}

// rsaSHA512Signer preserves a certificate public key while ensuring that the
// underlying RSA signer never falls back to the legacy ssh-rsa/SHA-1 format.
type rsaSHA512Signer struct {
	ssh.Signer
	algorithmSigner ssh.AlgorithmSigner
}

func (s rsaSHA512Signer) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	return s.algorithmSigner.SignWithAlgorithm(random, data, ssh.KeyAlgoRSASHA512)
}

func publicKeyType(pk ssh.PublicKey) string {
	if cert, ok := pk.(*ssh.Certificate); ok {
		return cert.Key.Type()
	}
	return pk.Type()
}

func isRSACertificate(pk ssh.PublicKey) bool {
	cert, ok := pk.(*ssh.Certificate)
	return ok && cert.Key.Type() == ssh.KeyAlgoRSA
}

// SignatureVerify checks if a signature verifies to the input data. It does
// *not* validate the authenticity of the pubkey or namespace.
func SignatureVerify(in io.Reader, sig *sshsig.Signature) error {
	if err := sshsig.Verify(in, sig, sig.PublicKey, sig.HashAlgorithm, sig.Namespace); err != nil {
		if strings.HasPrefix(err.Error(), "ssh: ") {
			return fmt.Errorf("%s", strings.TrimPrefix(err.Error(), "ssh: "))
		}
		return fmt.Errorf("unexpected verification failure: %w", err)
	}
	return nil
}

// SignatureDataInfo is a human-readable representation of an ssh.Signature.
type SignatureDataInfo struct {
	Format string `json:"format"`
	Blob   string `json:"blob"`
	Rest   string `json:"-"`
}

// NewSignatureDataInfo populates a new SignatureDataInfo.
func NewSignatureDataInfo(sig *ssh.Signature) SignatureDataInfo {
	return SignatureDataInfo{
		Format: string(sig.Format),
		Blob:   base64.StdEncoding.EncodeToString(sig.Blob),
		Rest:   base64.StdEncoding.EncodeToString(sig.Rest),
	}
}

// SignatureInfo is a human-readable representation of an sshsig.Signature.
type SignatureInfo struct {
	Version       uint32            `json:"version,string"`
	PublicKey     PublicKeyInfo     `json:"public_key"`
	Namespace     string            `json:"namespace"`
	HashAlgorithm string            `json:"hash_algorithm"`
	Signature     SignatureDataInfo `json:"signature"`
}

// NewSignatureInfo populates a new SignatureInfo.
func NewSignatureInfo(sig *sshsig.Signature) SignatureInfo {
	return SignatureInfo{
		Version:       sig.Version,
		PublicKey:     NewPublicKeyInfo(sig.PublicKey),
		Namespace:     sig.Namespace,
		HashAlgorithm: sig.HashAlgorithm.String(),
		Signature:     NewSignatureDataInfo(sig.Signature),
	}
}
