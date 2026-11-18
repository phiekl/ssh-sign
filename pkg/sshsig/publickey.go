// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PublicKeyEqual checks if two public keys are the same.
func PublicKeyEqual(pk1, pk2 ssh.PublicKey) bool {
	return bytes.Equal(pk1.Marshal(), pk2.Marshal())
}

// PlainPublicKeyBlob returns the wire form of pk or of its certificate subject.
func PlainPublicKeyBlob(pk ssh.PublicKey) ([]byte, error) {
	if key, ok := pk.(*certificateKey); ok {
		return key.cert.Key.Marshal(), nil
	}
	cert, err := AsCertificate(pk)
	if err != nil {
		return nil, err
	}
	if cert != nil {
		pk = cert.Key
	}
	return pk.Marshal(), nil
}

// ParsePublicKeyLine parses a string like "[type] <data> [comment ...]" similar
// to ssh.ParseAuthorizedKey(), but only cares about the data field.
func ParsePublicKeyLine(pkLine string) (ssh.PublicKey, error) {
	// pkLine should contain "[type] <data> [comment ...]". If "type" was
	// required here, ssh.ParseAuthorizedKey() could have been used instead.
	tokens := strings.Fields(pkLine)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%s contains no usable non-space tokens", QuoteToken(pkLine))
	}

	pkEnc := tokens[0]
	keyType := ""
	// Every key type contains a dash (e.g. ssh-ed25519), while base64 does not.
	if strings.Contains(pkEnc, "-") {
		if len(tokens) < 2 {
			return nil, fmt.Errorf("no pubkey token found in %s", QuoteToken(pkLine))
		}
		keyType = pkEnc
		pkEnc = tokens[1]
	}

	pk, err := ParsePublicKey(pkEnc)
	if err != nil {
		return nil, err
	}
	// Require the stated key type to match, as in allowed-signers parsing.
	if keyType != "" && pk.Type() != keyType {
		return nil, fmt.Errorf(
			"key type mismatch: defined %s but parsed %q", QuoteToken(keyType), pk.Type(),
		)
	}
	return pk, nil
}

// ParsePublicKey parses the data field of a public key line into a ssh.PublicKey.
func ParsePublicKey(pkEnc string) (ssh.PublicKey, error) {
	pkDec, err := base64.StdEncoding.DecodeString(pkEnc)
	if err != nil {
		return nil, fmt.Errorf("failed decoding %s: %w", QuoteToken(pkEnc), err)
	}

	pk, err := parseKeyBlob(pkDec)
	if err != nil {
		// The parser error may repeat a large decoded algorithm name.
		// QuoteToken limits only the encoded key.
		return nil, fmt.Errorf(
			"failed parsing pubkey %s: %w", QuoteToken(pkEnc), boundedError(err),
		)
	}
	if err := certificateSigned(pk); err != nil {
		return nil, fmt.Errorf("pubkey %s: %w", QuoteToken(pkEnc), err)
	}
	return pk, nil
}

// ParsePublicKeyBlob is ParsePublicKey for a key in wire format.
func ParsePublicKeyBlob(blob []byte) (ssh.PublicKey, error) {
	pk, err := parseKeyBlob(blob)
	if err != nil {
		return nil, boundedError(err)
	}
	if err := certificateSigned(pk); err != nil {
		return nil, err
	}
	return pk, nil
}

// certificateSigned rejects a certificate the CA did not sign, like ssh-keygen.
func certificateSigned(pk ssh.PublicKey) error {
	if cert, _ := AsCertificate(pk); cert != nil {
		return certificateSignatureValid(pk, cert)
	}
	return nil
}

// PublicKeyString converts a public key to its authorized_keys format.
func PublicKeyString(pk ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// PublicKeyInfo is a human-readable representation of a ssh.PublicKey.
type PublicKeyInfo struct {
	Format      string  `json:"format"`
	Blob        string  `json:"blob"`
	Fingerprint string  `json:"fingerprint"`
	Application *string `json:"application,omitempty"`
}

// NewPublicKeyInfo populates a new PublicKeyInfo.
func NewPublicKeyInfo(pk ssh.PublicKey) PublicKeyInfo {
	return PublicKeyInfo{
		Format:      pk.Type(),
		Blob:        base64.StdEncoding.EncodeToString(pk.Marshal()),
		Fingerprint: ssh.FingerprintSHA256(pk),
		Application: securityKeyApplication(pk),
	}
}

// securityKeyApplication reads the application embedded in a FIDO public key.
func securityKeyApplication(pk ssh.PublicKey) *string {
	if cert, _ := AsCertificate(pk); cert != nil {
		pk = cert.Key
	}
	switch pk.Type() {
	case ssh.KeyAlgoSKED25519:
		var wire struct {
			Name        string
			Key         []byte
			Application string
		}
		if ssh.Unmarshal(pk.Marshal(), &wire) == nil {
			return &wire.Application
		}
	case ssh.KeyAlgoSKECDSA256:
		var wire struct {
			Name        string
			Curve       string
			Key         []byte
			Application string
		}
		if ssh.Unmarshal(pk.Marshal(), &wire) == nil {
			return &wire.Application
		}
	}
	return nil
}
