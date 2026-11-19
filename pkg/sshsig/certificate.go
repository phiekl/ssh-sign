// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/internal/helper"
)

// certificateSuffix ends the original OpenSSH certificate key types.
const certificateSuffix = "-cert-v01@openssh.com"

func isCertificateType(keyType string) bool {
	return keyType == mldsa44Ed25519CertAlgo || strings.HasSuffix(keyType, certificateSuffix)
}

// CertificateValidAt requires a user certificate with a valid CA signature,
// valid at the given time, with ValidAfter inclusive and ValidBefore exclusive.
// Plain keys are ignored. It does not check the certificate principals.
func CertificateValidAt(pk ssh.PublicKey, at time.Time) error {
	cert, err := signedCertificate(pk)
	if err != nil || cert == nil {
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

// CertificateSignatureValid checks the certificate's CA signature independently
// of signer trust and the certificate validity window. Plain keys are ignored.
func CertificateSignatureValid(pk ssh.PublicKey) error {
	_, err := signedCertificate(pk)
	return err
}

func signedCertificate(pk ssh.PublicKey) (*ssh.Certificate, error) {
	if pk == nil {
		return nil, fmt.Errorf("a public key is required")
	}
	if key, ok := pk.(*Certificate); ok {
		return key.cert, key.signatureValid()
	}
	cert, err := unwrapCertificate(pk)
	if err != nil || cert == nil {
		return nil, err
	}
	if _, ok := pk.(*ssh.Certificate); ok {
		if err := checkCertificateFields(cert); err != nil {
			return nil, err
		}
	}
	return cert, certificateSignatureValid(pk, cert)
}

// Certificate is an immutable SSH public key that preserves the certificate
// encoding signed by its CA. Obtain a Certificate through AsCertificate or by
// parsing a key. The zero value is invalid. Use CertificateDetails to obtain
// an editable copy.
type Certificate struct {
	cert *ssh.Certificate
	blob []byte

	checkSignature sync.Once
	signatureErr   error
}

// signatureValid checks the CA signature once, as the encoding is fixed.
func (k *Certificate) signatureValid() error {
	k.checkSignature.Do(func() { k.signatureErr = certificateSignatureValid(k, k.cert) })
	return k.signatureErr
}

func (k *Certificate) Type() string {
	if k.cert.Key.Type() == KeyAlgoMLDSA44Ed25519 {
		return mldsa44Ed25519CertAlgo
	}
	return k.cert.Type()
}

func (k *Certificate) Marshal() []byte { return bytes.Clone(k.blob) }

func (k *Certificate) Verify(data []byte, sig *ssh.Signature) error {
	return k.cert.Verify(data, sig)
}

// encodedMLDSACertificate adapts a caller-owned certificate for encoding.
type encodedMLDSACertificate struct {
	*ssh.Certificate
	blob []byte
}

func (*encodedMLDSACertificate) Type() string { return mldsa44Ed25519CertAlgo }

func (k *encodedMLDSACertificate) Marshal() []byte { return bytes.Clone(k.blob) }

// encodable wraps a concrete ML-DSA certificate, whose Type and Marshal panic.
func encodable(pk ssh.PublicKey) ssh.PublicKey {
	cert, ok := pk.(*ssh.Certificate)
	if !ok || cert == nil {
		return pk
	}
	if cert.Key == nil || cert.Key.Type() != KeyAlgoMLDSA44Ed25519 {
		return pk
	}
	blob, err := marshalMLDSACertificate(cert)
	if err != nil {
		return pk
	}
	return &encodedMLDSACertificate{Certificate: cert, blob: blob}
}

// marshalCertificate is ssh.Certificate.Marshal, extended to ML-DSA subjects.
func marshalCertificate(cert *ssh.Certificate) ([]byte, error) {
	switch {
	case cert.Key == nil:
		return nil, fmt.Errorf("certificate has no key")
	case cert.Key.Type() == KeyAlgoMLDSA44Ed25519:
		return marshalMLDSACertificate(cert)
	}
	return cert.Marshal(), nil
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
		return &Certificate{cert: cert, blob: blob}, nil
	}
	return pk, nil
}

// maxCertificatePrincipals is OpenSSH's SSHKEY_CERT_MAX_PRINCIPALS.
const maxCertificatePrincipals = 256

// checkCertificateFields applies OpenSSH's certificate type and string checks.
// A final NUL byte is kept in the signed fields; see CertificateKeyID.
func checkCertificateFields(cert *ssh.Certificate) error {
	if cert.CertType != ssh.UserCert && cert.CertType != ssh.HostCert {
		return fmt.Errorf("unsupported certificate type %d", cert.CertType)
	}
	if !helper.ValidCString(cert.KeyId) {
		return fmt.Errorf("certificate key ID contains a NUL byte")
	}
	if len(cert.ValidPrincipals) > maxCertificatePrincipals {
		return fmt.Errorf("certificate has more than %d principals", maxCertificatePrincipals)
	}
	for _, principal := range cert.ValidPrincipals {
		if !helper.ValidCString(principal) {
			return fmt.Errorf("certificate principal contains a NUL byte")
		}
	}
	return nil
}

// CertificateKeyID returns the key ID as OpenSSH reads it, up to a NUL byte.
func CertificateKeyID(cert *ssh.Certificate) string {
	return helper.CString(cert.KeyId)
}

// CertificatePrincipals returns the principals as OpenSSH reads them, each up
// to a NUL byte.
func CertificatePrincipals(cert *ssh.Certificate) []string {
	principals := make([]string, len(cert.ValidPrincipals))
	for i, principal := range cert.ValidPrincipals {
		principals[i] = helper.CString(principal)
	}
	return principals
}

// checkCertificateKeys validates the fields needed to encode and verify cert.
func checkCertificateKeys(cert *ssh.Certificate) error {
	if cert.Key == nil {
		return fmt.Errorf("certificate has no key")
	}
	if cert.Signature == nil || cert.SignatureKey == nil {
		return fmt.Errorf("certificate signature is missing")
	}
	if _, ok := cert.SignatureKey.(*ssh.Certificate); ok || isCertificateType(cert.SignatureKey.Type()) {
		return fmt.Errorf("certificate signature key is a certificate")
	}
	return nil
}

// certificateSignatureValid checks the CA signature over pk's encoding of
// cert, as ssh-keygen does when parsing a certificate. ssh.CertChecker would
// also reject critical options.
func certificateSignatureValid(pk ssh.PublicKey, cert *ssh.Certificate) error {
	if err := checkCertificateKeys(cert); err != nil {
		return err
	}
	if cert.SignatureKey.Type() == ssh.InsecureKeyAlgoDSA ||
		cert.Signature.Format == ssh.InsecureKeyAlgoDSA {
		return fmt.Errorf("unsupported certificate signature algorithm %q", ssh.InsecureKeyAlgoDSA)
	}
	blob := encodable(pk).Marshal()
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

// AsCertificate returns pk as an immutable certificate, or nil for a plain key.
// It returns an error for malformed certificate encodings.
func AsCertificate(pk ssh.PublicKey) (*Certificate, error) {
	var blob []byte
	switch key := pk.(type) {
	case *Certificate:
		return key, nil
	case *ssh.Certificate:
		if key == nil {
			return nil, nil
		}
		if err := checkCertificateKeys(key); err != nil {
			return nil, err
		}
		var err error
		blob, err = marshalCertificate(key)
		if err != nil {
			return nil, err
		}
	default:
		if pk == nil || !isCertificateType(pk.Type()) {
			return nil, nil
		}
		blob = pk.Marshal()
	}
	parsed, err := parseKeyBlob(blob)
	if err != nil {
		return nil, fmt.Errorf("certificate is unparseable: %w", boundedError(err))
	}
	if cert, ok := parsed.(*Certificate); ok {
		return cert, nil
	}
	return nil, fmt.Errorf("certificate type %s did not parse as a certificate", QuoteToken(pk.Type()))
}

// CertificateDetails returns a concrete certificate as-is, or an editable copy
// of the certificate another public key holds. It returns nil for plain keys.
// For ML-DSA subjects, use the immutable Certificate for Type and Marshal.
func CertificateDetails(pk ssh.PublicKey) (*ssh.Certificate, error) {
	if cert, ok := pk.(*ssh.Certificate); ok {
		// Parsing applies these checks to the other certificates.
		if cert != nil {
			if cert.Key == nil {
				return nil, fmt.Errorf("certificate has no key")
			}
			if err := checkCertificateFields(cert); err != nil {
				return nil, err
			}
		}
		return cert, nil
	}
	if pk == nil || !isCertificateType(pk.Type()) {
		return nil, nil
	}
	if key, ok := pk.(*Certificate); ok {
		return cloneCertificate(key.cert)
	}
	blob := bytes.Clone(pk.Marshal())
	parsed, err := parsePublicKeyBlob(blob)
	if err != nil {
		return nil, fmt.Errorf("certificate is unparseable: %w", boundedError(err))
	}
	var cert *ssh.Certificate
	switch key := parsed.(type) {
	case *ssh.Certificate:
		cert = key
	case *Certificate:
		cert = key.cert
	default:
		return nil, fmt.Errorf(
			"certificate type %s did not parse as a certificate", QuoteToken(pk.Type()),
		)
	}
	return cert, nil
}

// cloneCertificate copies the fields a caller could change in place,
// including the keys, whose CryptoPublicKey shares their data.
func cloneCertificate(cert *ssh.Certificate) (*ssh.Certificate, error) {
	clone := *cert
	var err error
	if clone.Key, err = parseAnyPublicKeyBlob(cert.Key.Marshal()); err != nil {
		return nil, err
	}
	if clone.SignatureKey, err = parseAnyPublicKeyBlob(cert.SignatureKey.Marshal()); err != nil {
		return nil, err
	}
	clone.Nonce = bytes.Clone(cert.Nonce)
	clone.ValidPrincipals = slices.Clone(cert.ValidPrincipals)
	clone.CriticalOptions = maps.Clone(cert.CriticalOptions)
	clone.Extensions = maps.Clone(cert.Extensions)
	clone.ExtraData = maps.Clone(cert.ExtraData)
	clone.Reserved = bytes.Clone(cert.Reserved)
	if cert.Signature != nil {
		sig := *cert.Signature
		sig.Blob = bytes.Clone(sig.Blob)
		sig.Rest = bytes.Clone(sig.Rest)
		clone.Signature = &sig
	}
	return &clone, nil
}

// unwrapCertificate returns the certificate pk holds, without checking the
// fields of a *ssh.Certificate, which do not affect its key types. Unlike
// CertificateDetails, it shares a parsed certificate, which must not be changed.
func unwrapCertificate(pk ssh.PublicKey) (*ssh.Certificate, error) {
	switch key := pk.(type) {
	case *ssh.Certificate:
		return key, nil
	case *Certificate:
		return key.cert, nil
	case *encodedMLDSACertificate:
		return key.Certificate, nil
	}
	return CertificateDetails(pk)
}

// checkCertificate is CertificateDetails' check, without parsing a certificate
// parsed here again.
func checkCertificate(pk ssh.PublicKey) error {
	cert, err := unwrapCertificate(pk)
	if err != nil || cert == nil {
		return err
	}
	return checkCertificateFields(cert)
}

// certificateTime renders a certificate timestamp for an error message.
func certificateTime(seconds uint64) string {
	if seconds > 1<<63-1 {
		return "never"
	}
	return time.Unix(int64(seconds), 0).UTC().Format(time.RFC3339)
}
