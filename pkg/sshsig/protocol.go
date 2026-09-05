// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package sshsig implements the SSHSIG protocol as specified by OpenSSH's
// PROTOCOL.sshsig and produced by `ssh-keygen -Y sign`.
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PEMType is the armor type of an SSHSIG signature file.
const PEMType = "SSH SIGNATURE"

const (
	// magicPreamble prefixes both the signature file and the signed data.
	magicPreamble = "SSHSIG"
	// sigVersion is the only version OpenSSH accepts.
	sigVersion uint32 = 1
	// armorColumns is the base64 line width ssh-keygen writes.
	armorColumns = 70
)

// signatureWire is the signature file layout, armored as PEMType:
//
//	byte[6] magic preamble, uint32 version, string public key,
//	string namespace, string reserved, string hash algorithm,
//	string signature
type signatureWire struct {
	MagicPreamble [6]byte
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

// signedDataWire is what is actually signed, prefixed by the raw magic
// preamble rather than by a length-prefixed string.
type signedDataWire struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          string
}

// HashAlgorithm names the hash the message is reduced with before signing.
type HashAlgorithm string

// The hash algorithms OpenSSH supports. It signs with HashSHA512 unless asked
// for the other one through `ssh-keygen -O hashalg=`.
const (
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
)

func (h HashAlgorithm) String() string {
	return string(h)
}

// hash returns an implementation of the algorithm, if it is supported.
func (h HashAlgorithm) hash() (hash.Hash, error) {
	switch h {
	case HashSHA256:
		return sha256.New(), nil
	case HashSHA512:
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm %s", QuoteToken(string(h)))
}

// Signature is a parsed SSHSIG signature. Sign and ParseSignature produce
// fully populated ones; Marshal and Armor expect nothing less.
type Signature struct {
	Version       uint32
	PublicKey     ssh.PublicKey
	Namespace     string
	Reserved      string
	HashAlgorithm HashAlgorithm
	Signature     *ssh.Signature
}

// hashMessage streams input into a digest and wraps read failures in ReadError.
func hashMessage(in io.Reader, h HashAlgorithm) ([]byte, error) {
	hasher, err := h.hash()
	if err != nil {
		return nil, err
	}
	// A hash never fails to write, so a failure here is always the reader's.
	if _, err := io.Copy(hasher, in); err != nil {
		return nil, &ReadError{Err: err}
	}
	return hasher.Sum(nil), nil
}

// signedData builds the blob a signature is computed over. OpenSSH always
// signs an empty reserved field, whatever a signature file happens to carry.
func signedData(namespace string, h HashAlgorithm, digest []byte) []byte {
	return append([]byte(magicPreamble), ssh.Marshal(signedDataWire{
		Namespace:     namespace,
		HashAlgorithm: string(h),
		Hash:          string(digest),
	})...)
}

// Sign signs the input data. It applies no policy to the key type itself, so
// it can produce signatures Verify then refuses; SignatureCreate rejects those
// keys up front.
func Sign(in io.Reader, signer ssh.Signer, h HashAlgorithm, namespace string) (*Signature, error) {
	if signer == nil {
		return nil, fmt.Errorf("a signer is required")
	}
	// ssh-keygen refuses to sign without one too.
	if namespace == "" {
		return nil, fmt.Errorf("a namespace is required")
	}
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	digest, err := hashMessage(in, h)
	if err != nil {
		return nil, err
	}
	sig, err := signBlob(signer, signedData(namespace, h, digest))
	if err != nil {
		return nil, err
	}
	return &Signature{
		Version:       sigVersion,
		PublicKey:     signer.PublicKey(),
		Namespace:     namespace,
		HashAlgorithm: h,
		Signature:     sig,
	}, nil
}

// signBlob signs the blob, selecting SHA-512 for an RSA key the way ssh-keygen
// does. Both x/crypto's and the agent's signers otherwise fall back to the
// legacy ssh-rsa/SHA-1 format. A certificate hides the key type here, which is
// why SignatureCreate wraps those signers itself.
func signBlob(signer ssh.Signer, blob []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("RSA signer does not support selecting a SHA-2 algorithm")
		}
		return algorithmSigner.SignWithAlgorithm(rand.Reader, blob, ssh.KeyAlgoRSASHA512)
	}
	return signer.Sign(rand.Reader, blob)
}

// validateNamespace rejects what ssh-keygen cannot parse back: it reads the
// namespace as a C string, so an embedded NUL makes the whole signature
// unreadable to it.
func validateNamespace(namespace string) error {
	if strings.ContainsRune(namespace, 0) {
		return fmt.Errorf("namespace %s contains a NUL byte", QuoteToken(namespace))
	}
	return nil
}

// Verify checks the signature against the input data using the public key the
// signature carries. It says nothing about that key being trusted.
func Verify(in io.Reader, sig *Signature) error {
	if sig == nil || sig.PublicKey == nil || sig.Signature == nil {
		return fmt.Errorf("incomplete signature")
	}
	if sig.Version != sigVersion {
		return fmt.Errorf(
			"unsupported signature version %d: expected %d", sig.Version, sigVersion,
		)
	}
	// The reserved field is unsigned and must be empty.
	if sig.Reserved != "" {
		return fmt.Errorf("signature reserved field is not empty")
	}
	// A signature ssh-keygen refuses must never verify here either, however it
	// was obtained.
	if err := validateSignatureAlgorithm(sig); err != nil {
		return err
	}
	digest, err := hashMessage(in, sig.HashAlgorithm)
	if err != nil {
		return err
	}
	return sig.PublicKey.Verify(signedData(sig.Namespace, sig.HashAlgorithm, digest), sig.Signature)
}

// ParseSignature parses the unarmored contents of a signature file.
func ParseSignature(blob []byte) (*Signature, error) {
	var wire signatureWire
	// Unmarshal also rejects anything trailing the signature.
	if err := ssh.Unmarshal(blob, &wire); err != nil {
		return nil, fmt.Errorf("invalid signature: %v", boundedError(err))
	}
	if preamble := string(wire.MagicPreamble[:]); preamble != magicPreamble {
		return nil, fmt.Errorf(
			"invalid magic preamble %s: expected %q", QuoteToken(preamble), magicPreamble,
		)
	}
	if wire.Version != sigVersion {
		return nil, fmt.Errorf(
			"unsupported signature version %d: expected %d", wire.Version, sigVersion,
		)
	}

	pk, err := ssh.ParsePublicKey([]byte(wire.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", boundedError(err))
	}
	var sshSig ssh.Signature
	if err := ssh.Unmarshal([]byte(wire.Signature), &sshSig); err != nil {
		return nil, fmt.Errorf("invalid signature field: %v", boundedError(err))
	}
	// Unmarshal collects whatever follows the signature in Rest. Only a
	// security key puts anything there, its flags and counter; for every other
	// algorithm those bytes are unsigned padding that ssh-keygen refuses,
	// which would otherwise make a verified signature file malleable.
	if len(sshSig.Rest) != 0 && !isSecurityKey(publicKeyType(pk)) {
		return nil, fmt.Errorf("signature contains %d bytes of trailing data", len(sshSig.Rest))
	}

	// Reject unsigned reserved data to prevent malleability.
	if wire.Reserved != "" {
		return nil, fmt.Errorf("signature reserved field is not empty")
	}
	if wire.Namespace == "" {
		return nil, fmt.Errorf("signature namespace is empty")
	}
	if err := validateNamespace(wire.Namespace); err != nil {
		return nil, err
	}
	hashAlgorithm := HashAlgorithm(wire.HashAlgorithm)
	if _, err := hashAlgorithm.hash(); err != nil {
		return nil, err
	}
	if err := validateSignatureFormat(pk, sshSig.Format); err != nil {
		return nil, err
	}

	return &Signature{
		Version:       wire.Version,
		PublicKey:     pk,
		Namespace:     wire.Namespace,
		Reserved:      wire.Reserved,
		HashAlgorithm: hashAlgorithm,
		Signature:     &sshSig,
	}, nil
}

// isSecurityKey reports whether the key type is a FIDO authenticator key,
// whose signatures carry flags and a counter after the signature itself.
func isSecurityKey(keyType string) bool {
	return keyType == ssh.KeyAlgoSKED25519 || keyType == ssh.KeyAlgoSKECDSA256
}

// validateSignatureFormat checks that the public key could have produced a
// signature in the given format. Certificates sign with their own key, so the
// formats are those of the key the certificate carries.
func validateSignatureFormat(pk ssh.PublicKey, format string) error {
	expected := []string{publicKeyType(pk)}
	// An RSA key selects its hash through the signature format.
	if expected[0] == ssh.KeyAlgoRSA {
		expected = append(expected, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512)
	}
	quoted := make([]string, 0, len(expected))
	for _, e := range expected {
		if format == e {
			return nil
		}
		quoted = append(quoted, fmt.Sprintf("%q", e))
	}
	return fmt.Errorf(
		"invalid signature format %s: expected %s",
		QuoteToken(format), strings.Join(quoted, " or "),
	)
}

// Marshal renders the signature in the signature file format.
func Marshal(sig *Signature) []byte {
	wire := signatureWire{
		Version:       sig.Version,
		PublicKey:     string(sig.PublicKey.Marshal()),
		Namespace:     sig.Namespace,
		Reserved:      sig.Reserved,
		HashAlgorithm: string(sig.HashAlgorithm),
		Signature:     string(ssh.Marshal(sig.Signature)),
	}
	copy(wire.MagicPreamble[:], magicPreamble)
	return ssh.Marshal(wire)
}

// Armor renders the signature the way ssh-keygen writes a signature file.
func Armor(sig *Signature) []byte {
	encoded := base64.StdEncoding.EncodeToString(Marshal(sig))

	var out bytes.Buffer
	out.WriteString("-----BEGIN " + PEMType + "-----\n")
	for len(encoded) > armorColumns {
		out.WriteString(encoded[:armorColumns])
		out.WriteByte('\n')
		encoded = encoded[armorColumns:]
	}
	if len(encoded) != 0 {
		out.WriteString(encoded)
		out.WriteByte('\n')
	}
	out.WriteString("-----END " + PEMType + "-----\n")
	return out.Bytes()
}
