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

// PublicKeyLineParse parses a string like "[type] <data> [comment ...]" similar
// to ssh.ParseAuthorizedKey(), but only cares about the data field.
func PublicKeyLineParse(pkLine string) (ssh.PublicKey, error) {
	// pkgStr should contain "[type] <data> [comment ...]". If "type" was
	// required here, ssh.ParseAuthorizedKey() could have been used instead.
	tokens := strings.Fields(pkLine)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%s contains no usable non-space tokens", QuoteToken(pkLine))
	}

	pkEnc := tokens[0]
	// All key types contains a dash (e.g. ssh-ed25519), while base64 won't.
	if strings.Contains(pkEnc, "-") {
		if len(tokens) < 2 {
			return nil, fmt.Errorf("no pubkey token found in %s", QuoteToken(pkLine))
		}
		pkEnc = tokens[1]
	}

	return PublicKeyParse(pkEnc)
}

// PublicKeyParse parses the data field of a public key line into a ssh.PublicKey.
func PublicKeyParse(pkEnc string) (ssh.PublicKey, error) {
	pkDec, err := base64.StdEncoding.DecodeString(pkEnc)
	if err != nil {
		return nil, fmt.Errorf("failed decoding %s: %v", QuoteToken(pkEnc), err)
	}

	pk, err := ssh.ParsePublicKey(pkDec)
	if err != nil {
		return nil, fmt.Errorf("failed parsing pubkey %s: %v", QuoteToken(pkEnc), err)
	}
	return pk, nil
}

// PublicKeyString converts a public key to its authorized_keys format.
func PublicKeyString(pk ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// PublicKeyInfo is a human-readable representation of a ssh.PublicKey.
type PublicKeyInfo struct {
	Format      string `json:"format"`
	Blob        string `json:"blob"`
	Fingerprint string `json:"fingerprint"`
}

// NewPublicKeyInfo populates a new PublicKeyInfo.
func NewPublicKeyInfo(pk ssh.PublicKey) PublicKeyInfo {
	return PublicKeyInfo{
		Format:      pk.Type(),
		Blob:        base64.StdEncoding.EncodeToString(pk.Marshal()),
		Fingerprint: ssh.FingerprintSHA256(pk),
	}
}
