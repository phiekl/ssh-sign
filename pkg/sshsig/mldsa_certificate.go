// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// parseCertificateWithMLDSA handles certificates with an ML-DSA subject or CA.
func parseCertificateWithMLDSA(blob []byte) (*Certificate, error) {
	blob = bytes.Clone(blob)
	var prefix struct {
		Algorithm string
		Nonce     []byte
		Rest      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(blob, &prefix); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA certificate: %w", err)
	}
	key, rest, err := parseCertificateSubject(prefix.Algorithm, prefix.Rest)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-DSA certificate subject: %w", err)
	}
	var wire struct {
		Serial          uint64
		CertType        uint32
		KeyID           string
		Principals      []byte
		ValidAfter      uint64
		ValidBefore     uint64
		CriticalOptions []byte
		Extensions      []byte
		Reserved        []byte
		SignatureKey    []byte
		Signature       []byte
	}
	if err := ssh.Unmarshal(rest, &wire); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA certificate: %w", err)
	}
	ca, err := parseCertificateCA(wire.SignatureKey)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate CA key: %w", err)
	}
	if key.Type() != KeyAlgoMLDSA44Ed25519 && ca.Type() != KeyAlgoMLDSA44Ed25519 {
		return nil, fmt.Errorf("certificate has no ML-DSA key")
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(wire.Signature, &sig); err != nil {
		return nil, fmt.Errorf("invalid certificate signature: %w", err)
	}
	if err := validateSignatureFormat(ca, sig.Format); err != nil {
		return nil, fmt.Errorf("invalid certificate signature: %w", err)
	}
	if !isSecurityKey(sig.Format) && len(sig.Rest) != 0 {
		return nil, fmt.Errorf("invalid trailing data in certificate signature")
	}
	cert := &ssh.Certificate{
		Nonce:        prefix.Nonce,
		Key:          key,
		Serial:       wire.Serial,
		CertType:     wire.CertType,
		KeyId:        wire.KeyID,
		ValidAfter:   wire.ValidAfter,
		ValidBefore:  wire.ValidBefore,
		Reserved:     wire.Reserved,
		SignatureKey: ca,
		Signature:    &sig,
	}
	for rest := wire.Principals; len(rest) != 0; {
		var principal struct {
			Name string
			Rest []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(rest, &principal); err != nil {
			return nil, fmt.Errorf("invalid certificate principal: %w", err)
		}
		cert.ValidPrincipals = append(cert.ValidPrincipals, principal.Name)
		rest = principal.Rest
	}
	cert.CriticalOptions, err = parseCertificateOptions(wire.CriticalOptions, false)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate critical options: %w", err)
	}
	cert.Extensions, err = parseCertificateOptions(wire.Extensions, true)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate extensions: %w", err)
	}
	return &Certificate{cert: cert, blob: blob}, nil
}

// Each subject field uses an SSH length prefix, including the RSA and DSA
// integers. Leave their contents to the plain public key parser.
func parseCertificateSubject(algorithm string, fields []byte) (ssh.PublicKey, []byte, error) {
	var keyType string
	var fieldCount int
	switch algorithm {
	case mldsa44Ed25519CertAlgo:
		keyType, fieldCount = KeyAlgoMLDSA44Ed25519, 1
	case ssh.CertAlgoED25519v01:
		keyType, fieldCount = ssh.KeyAlgoED25519, 1
	case ssh.CertAlgoRSAv01:
		keyType, fieldCount = ssh.KeyAlgoRSA, 2
	case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
		keyType, fieldCount = strings.TrimSuffix(algorithm, certificateSuffix), 2
	case ssh.CertAlgoSKED25519v01:
		keyType, fieldCount = ssh.KeyAlgoSKED25519, 2
	case ssh.CertAlgoSKECDSA256v01:
		keyType, fieldCount = ssh.KeyAlgoSKECDSA256, 3
	case ssh.InsecureCertAlgoDSAv01:
		keyType, fieldCount = ssh.InsecureKeyAlgoDSA, 4
	default:
		return nil, nil, fmt.Errorf("unsupported certificate type %s", QuoteToken(algorithm))
	}
	rest := fields
	for range fieldCount {
		var field struct {
			Data []byte
			Rest []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(rest, &field); err != nil {
			return nil, nil, err
		}
		rest = field.Rest
	}
	key, err := parseAnyPublicKeyBlob(ssh.Marshal(struct {
		Algorithm string
		Fields    []byte `ssh:"rest"`
	}{keyType, fields[:len(fields)-len(rest)]}))
	return key, rest, err
}

func parseCertificateCA(blob []byte) (ssh.PublicKey, error) {
	var prefix struct {
		Algorithm string
		Rest      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(blob, &prefix); err != nil {
		return nil, err
	}
	if isCertificateType(prefix.Algorithm) {
		return nil, fmt.Errorf("certificate signature key is a certificate")
	}
	return parseAnyPublicKeyBlob(blob)
}

func parseCertificateOptions(rest []byte, allowOpaque bool) (map[string]string, error) {
	options := make(map[string]string)
	var last string
	for len(rest) != 0 {
		var option struct {
			Name  string
			Value []byte
			Rest  []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(rest, &option); err != nil {
			return nil, err
		}
		if option.Name <= last || strings.ContainsRune(option.Name, 0) {
			return nil, fmt.Errorf("invalid or out-of-order option name %s", QuoteToken(option.Name))
		}
		// Common values are a nested SSH string. Noncritical extensions may
		// also carry opaque data defined by their own extension format.
		var value struct{ Text string }
		if len(option.Value) != 0 {
			if err := ssh.Unmarshal(option.Value, &value); err != nil {
				if !allowOpaque {
					return nil, err
				}
				value.Text = string(option.Value)
			}
		}
		options[option.Name] = value.Text
		last, rest = option.Name, option.Rest
	}
	return options, nil
}

// marshalMLDSACertificate encodes a certificate with an ML-DSA subject, which
// ssh.Certificate.Marshal cannot name. It encodes the rest with a stand-in key.
func marshalMLDSACertificate(cert *ssh.Certificate) ([]byte, error) {
	standIn, _ := ssh.NewPublicKey(make(ed25519.PublicKey, ed25519.PublicKeySize))
	encoded := *cert
	encoded.Key = standIn
	var prefix struct {
		Algorithm string
		Nonce     []byte
		Key       []byte
		Rest      []byte `ssh:"rest"`
	}
	var subject struct {
		Algorithm string
		Fields    []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(encoded.Marshal(), &prefix); err != nil {
		return nil, err
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &subject); err != nil {
		return nil, err
	}
	blob := ssh.Marshal(struct {
		Algorithm string
		Nonce     []byte
	}{mldsa44Ed25519CertAlgo, prefix.Nonce})
	blob = append(blob, subject.Fields...)
	return append(blob, prefix.Rest...), nil
}
