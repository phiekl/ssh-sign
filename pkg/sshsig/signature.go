// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// MaxSignatureArmorSize limits memory use while allowing certificate signatures.
const MaxSignatureArmorSize = 1 << 20

// SignatureCreate creates a signature of the input data.
func SignatureCreate(signer ssh.Signer, ns string, in io.Reader) (*Signature, error) {
	// Sign rejects this too, but PublicKey() below would panic first.
	if signer == nil {
		return nil, fmt.Errorf("signing failed: a signer is required")
	}
	if isRSACertificate(signer.PublicKey()) {
		algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("signing failed: RSA signer does not support selecting a SHA-2 algorithm")
		}
		signer = rsaSHA512Signer{Signer: signer, algorithmSigner: algorithmSigner}
	}
	sig, err := Sign(in, signer, HashSHA512, ns)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	if err := validateSignatureAlgorithm(sig); err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig, nil
}

// SignatureRead unarmors a signature from the input data.
func SignatureRead(in io.Reader) (*Signature, error) {
	return signatureRead(in, MaxSignatureArmorSize)
}

func signatureRead(in io.Reader, max int64) (*Signature, error) {
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
	// pem.Decode might skip a malformed block and read the valid one afterwards,
	// so reject a second header before the decoded block ends.
	if bytes.Contains(data[len(armorHeader):len(data)-len(rest)], []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("unarmoring data failed: data found before signature")
	}
	// The prefix does not constrain a later PEM block's type.
	if block.Type != PEMType {
		return nil, fmt.Errorf(
			"unarmoring data failed: invalid PEM type %s: expected %q",
			QuoteToken(block.Type), PEMType,
		)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("unarmoring data failed: PEM headers are not allowed")
	}
	if len(bytes.Trim(rest, " \t\r\n")) != 0 {
		return nil, fmt.Errorf("unarmoring data failed: data found after signature")
	}

	sig, err := ParseSignature(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unarmoring data failed: %w", boundedError(err))
	}
	if err := validateSignatureAlgorithm(sig); err != nil {
		return nil, err
	}

	return sig, nil
}

func validateSignatureAlgorithm(sig *Signature) error {
	// OpenSSH no longer accepts DSA signatures.
	if publicKeyType(sig.PublicKey) == ssh.InsecureKeyAlgoDSA ||
		sig.Signature.Format == ssh.InsecureKeyAlgoDSA {
		return fmt.Errorf("unsupported signature algorithm %q", ssh.InsecureKeyAlgoDSA)
	}
	if publicKeyType(sig.PublicKey) == ssh.KeyAlgoRSA &&
		sig.Signature.Format != ssh.KeyAlgoRSASHA256 &&
		sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		return fmt.Errorf(
			"invalid RSA signature format %s: expected %q or %q",
			QuoteToken(sig.Signature.Format), ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
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

// publicKeyType returns the signing key type, unwrapping certificates
// including those held by an agent.
func publicKeyType(pk ssh.PublicKey) string {
	if cert, _ := asCertificate(pk); cert != nil {
		return cert.Key.Type()
	}
	return pk.Type()
}

func isRSACertificate(pk ssh.PublicKey) bool {
	cert, _ := asCertificate(pk)
	return cert != nil && cert.Key.Type() == ssh.KeyAlgoRSA
}

// ReadError wraps a failure to read the message being signed or verified.
type ReadError struct {
	Err error
}

func (e *ReadError) Error() string {
	return e.Err.Error()
}

func (e *ReadError) Unwrap() error {
	return e.Err
}

// IsReadError reports whether err or one of its causes is a ReadError.
func IsReadError(err error) bool {
	var readErr *ReadError
	return errors.As(err, &readErr)
}

// SignatureVerify checks if a signature verifies to the input data. It does
// *not* validate the authenticity of the pubkey or namespace.
func SignatureVerify(in io.Reader, sig *Signature) error {
	if err := Verify(in, sig); err != nil {
		if IsReadError(err) {
			return err
		}
		err = boundedError(err)
		if msg := err.Error(); strings.HasPrefix(msg, "ssh: ") {
			return fmt.Errorf("%s", strings.TrimPrefix(msg, "ssh: "))
		}
		return fmt.Errorf("unexpected verification failure: %w", err)
	}
	return nil
}

// Authenticator data flags, as defined by WebAuthn.
const (
	skFlagUserPresence     = 0x01
	skFlagUserVerification = 0x04
	skFlagBackupEligible   = 0x08
	skFlagBackedUp         = 0x10
)

// SecurityKeyInfo is a human-readable representation of SecurityKeyFields.
// The booleans decode Flags so callers need not know its bit positions.
// FlagsText derives its labels from Flags even if the booleans disagree.
type SecurityKeyInfo struct {
	Flags            string `json:"flags"`
	UserPresence     bool   `json:"user_presence"`
	UserVerification bool   `json:"user_verification"`
	BackupEligible   bool   `json:"backup_eligible"`
	BackedUp         bool   `json:"backed_up"`
	Counter          uint32 `json:"counter,string"`
}

func newSecurityKeyInfo(fields *SecurityKeyFields) *SecurityKeyInfo {
	return &SecurityKeyInfo{
		Flags:            fmt.Sprintf("0x%02x", fields.Flags),
		UserPresence:     fields.Flags&skFlagUserPresence != 0,
		UserVerification: fields.Flags&skFlagUserVerification != 0,
		BackupEligible:   fields.Flags&skFlagBackupEligible != 0,
		BackedUp:         fields.Flags&skFlagBackedUp != 0,
		Counter:          fields.Counter,
	}
}

// FlagsText renders the raw flags byte and the recognized bits.
func (i SecurityKeyInfo) FlagsText() string {
	// Decode Flags here so values read from JSON render the same way.
	flags, err := strconv.ParseUint(i.Flags, 0, 8)
	if err != nil {
		return i.Flags
	}
	var names []string
	if flags&skFlagUserPresence != 0 {
		names = append(names, "presence")
	}
	if flags&skFlagUserVerification != 0 {
		names = append(names, "user-verified")
	}
	if flags&skFlagBackupEligible != 0 {
		names = append(names, "backup-eligible")
	}
	if flags&skFlagBackedUp != 0 {
		names = append(names, "backed-up")
	}
	const known = skFlagUserPresence | skFlagUserVerification |
		skFlagBackupEligible | skFlagBackedUp
	if flags&^known != 0 {
		names = append(names, "other-bits")
	}
	if len(names) == 0 {
		names = append(names, "none")
	}
	return fmt.Sprintf("%s (%s)", i.Flags, strings.Join(names, ","))
}

// SignatureDataInfo is a human-readable representation of an ssh.Signature.
type SignatureDataInfo struct {
	Format      string           `json:"format"`
	Blob        string           `json:"blob"`
	SecurityKey *SecurityKeyInfo `json:"security_key,omitempty"`
}

// NewSignatureDataInfo populates a new SignatureDataInfo.
func NewSignatureDataInfo(sig *ssh.Signature) SignatureDataInfo {
	return SignatureDataInfo{
		Format: string(sig.Format),
		Blob:   base64.StdEncoding.EncodeToString(sig.Blob),
	}
}

// SignatureInfo is a human-readable representation of a Signature.
type SignatureInfo struct {
	Version       uint32            `json:"version,string"`
	PublicKey     PublicKeyInfo     `json:"public_key"`
	Namespace     string            `json:"namespace"`
	HashAlgorithm string            `json:"hash_algorithm"`
	Signature     SignatureDataInfo `json:"signature"`
}

// NewSignatureInfo populates a new SignatureInfo, omitting malformed
// security-key fields.
func NewSignatureInfo(sig *Signature) SignatureInfo {
	info := SignatureInfo{
		Version:       sig.Version,
		PublicKey:     NewPublicKeyInfo(sig.PublicKey),
		Namespace:     sig.Namespace,
		HashAlgorithm: sig.HashAlgorithm.String(),
		Signature:     NewSignatureDataInfo(sig.Signature),
	}
	if fields, err := sig.SecurityKeyFields(); err == nil && fields != nil {
		info.Signature.SecurityKey = newSecurityKeyInfo(fields)
	}
	return info
}
