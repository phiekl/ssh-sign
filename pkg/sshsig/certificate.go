// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// certificateSuffix ends every OpenSSH certificate key type.
const certificateSuffix = "-cert-v01@openssh.com"

// CertificateValidAt requires a user certificate with a valid CA signature,
// valid at the given time, with ValidAfter inclusive and ValidBefore exclusive.
// Plain keys are ignored. It does not check the certificate principals.
func CertificateValidAt(pk ssh.PublicKey, at time.Time) error {
	if pk == nil {
		return fmt.Errorf("a public key is required")
	}
	cert, err := AsCertificate(pk)
	if err != nil {
		return err
	}
	if cert == nil {
		return nil
	}
	if err := certificateSignatureValid(pk, cert); err != nil {
		return err
	}
	if cert.CertType != ssh.UserCert {
		return fmt.Errorf(
			"certificate is not a user certificate (type %d)", cert.CertType,
		)
	}

	unix := at.Unix()
	if after := int64(cert.ValidAfter); after < 0 || unix < after {
		return fmt.Errorf(
			"certificate is not valid until %s", certificateTime(cert.ValidAfter),
		)
	}
	before := int64(cert.ValidBefore)
	if cert.ValidBefore != uint64(ssh.CertTimeInfinity) && (unix >= before || before < 0) {
		return fmt.Errorf("certificate expired %s", certificateTime(cert.ValidBefore))
	}
	return nil
}

// certificateKey keeps a certificate's received encoding, which the CA signed
// and which ssh.Certificate.Marshal may normalise. The parsed certificate is
// not exposed, so its fields cannot diverge from the encoding.
type certificateKey struct {
	cert *ssh.Certificate
	blob []byte
}

func (k *certificateKey) Type() string { return k.cert.Type() }

func (k *certificateKey) Marshal() []byte { return bytes.Clone(k.blob) }

func (k *certificateKey) Verify(data []byte, sig *ssh.Signature) error {
	return k.cert.Verify(data, sig)
}

// parseKeyBlob parses a public key and keeps the encoding of a certificate.
// It copies blob first, as x/crypto/ssh keys can alias their input.
func parseKeyBlob(blob []byte) (ssh.PublicKey, error) {
	blob = bytes.Clone(blob)
	pk, err := parsePublicKeyBlob(blob)
	if err != nil {
		return nil, err
	}
	if cert, ok := pk.(*ssh.Certificate); ok {
		return &certificateKey{cert: cert, blob: blob}, nil
	}
	return pk, nil
}

// certificateSignatureValid checks the CA signature over pk's encoding of
// cert, as ssh-keygen does when parsing a certificate. ssh.CertChecker would
// also reject critical options.
func certificateSignatureValid(pk ssh.PublicKey, cert *ssh.Certificate) error {
	if cert.Signature == nil || cert.SignatureKey == nil {
		return fmt.Errorf("certificate signature is missing")
	}
	if strings.HasSuffix(cert.SignatureKey.Type(), certificateSuffix) {
		return fmt.Errorf("certificate signature key is a certificate")
	}
	if cert.SignatureKey.Type() == ssh.InsecureKeyAlgoDSA ||
		cert.Signature.Format == ssh.InsecureKeyAlgoDSA {
		return fmt.Errorf("unsupported certificate signature algorithm %q", ssh.InsecureKeyAlgoDSA)
	}
	blob := pk.Marshal()
	// The signature is the last field. Its encoding is canonical, since the
	// parser rejects trailing data within it.
	sigField := ssh.Marshal(struct{ Signature []byte }{ssh.Marshal(cert.Signature)})
	if !bytes.HasSuffix(blob, sigField) {
		return fmt.Errorf("certificate signature is malformed")
	}
	signed := blob[:len(blob)-len(sigField)]
	if err := cert.SignatureKey.Verify(signed, cert.Signature); err != nil {
		return fmt.Errorf("certificate signature is invalid: %w", boundedError(err))
	}
	return nil
}

// AsCertificate unwraps concrete or agent-held certificates.
// It returns nil for plain keys and an error for malformed certificate blobs.
// Other than for a *ssh.Certificate, it parses a new copy of pk's encoding.
func AsCertificate(pk ssh.PublicKey) (*ssh.Certificate, error) {
	if cert, ok := pk.(*ssh.Certificate); ok {
		return cert, nil
	}
	if !strings.HasSuffix(pk.Type(), certificateSuffix) {
		return nil, nil
	}
	parsed, err := ssh.ParsePublicKey(pk.Marshal())
	if err != nil {
		return nil, fmt.Errorf("certificate is unparseable: %w", boundedError(err))
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf(
			"certificate type %s did not parse as a certificate", QuoteToken(pk.Type()),
		)
	}
	return cert, nil
}

// certificateTime renders a certificate timestamp for an error message.
func certificateTime(seconds uint64) string {
	if seconds > 1<<63-1 {
		return "never"
	}
	return time.Unix(int64(seconds), 0).UTC().Format(time.RFC3339)
}
