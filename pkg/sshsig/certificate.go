// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// certificateSuffix ends every OpenSSH certificate key type.
const certificateSuffix = "-cert-v01@openssh.com"

// CertificateValidAt requires a user certificate valid at the given time,
// with ValidAfter inclusive and ValidBefore exclusive. Plain keys are ignored.
// It does not check the CA signature or certificate principals.
func CertificateValidAt(pk ssh.PublicKey, at time.Time) error {
	if pk == nil {
		return fmt.Errorf("a public key is required")
	}
	cert, err := asCertificate(pk)
	if err != nil {
		return err
	}
	if cert == nil {
		return nil
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

// asCertificate unwraps concrete or agent-held certificates.
// It returns nil for plain keys and an error for malformed certificate blobs.
func asCertificate(pk ssh.PublicKey) (*ssh.Certificate, error) {
	if cert, ok := pk.(*ssh.Certificate); ok {
		return cert, nil
	}
	if !strings.HasSuffix(pk.Type(), certificateSuffix) {
		return nil, nil
	}
	parsed, err := ssh.ParsePublicKey(pk.Marshal())
	if err != nil {
		return nil, fmt.Errorf("certificate is unparseable: %v", boundedError(err))
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
