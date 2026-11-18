// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package revokedkeys reads revoked public key lists, as given to
// ssh-keygen -Y verify -r. KRLs are not supported.
package revokedkeys

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/internal/helper"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// krlMagic starts an OpenSSH key revocation list.
const krlMagic = "SSHKRL\n\x00"

// List holds revoked keys in file order.
type List struct {
	Keys []Key
}

// Key is a revoked key line.
type Key struct {
	// Source names the file, or is empty for an unnamed reader.
	Source string

	// File line number.
	Line int

	PublicKey ssh.PublicKey
}

// Location returns the key's line, qualified by its source if named.
func (k *Key) Location() string {
	return helper.Location(k.Source, k.Line)
}

// Parse reads a revoked key list. Like ssh-keygen, it fails on any line that
// is not blank, a comment or "type base64 [comment]", rather than skip a key.
func Parse(r io.Reader) (*List, error) {
	return ParseSource(r, "")
}

// ParseSource is Parse with source recorded on every key and error.
func ParseSource(r io.Reader, source string) (*List, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(krlMagic))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", helper.Location(source, 1), err)
	}
	if string(head) == krlMagic {
		if source == "" {
			return nil, fmt.Errorf("KRL format is not supported")
		}
		return nil, fmt.Errorf("file=%q: KRL format is not supported", source)
	}

	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), helper.MaxLineSize+1)

	var l List
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimLeft(sc.Text(), " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		pk, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", helper.Location(source, n), err)
		}
		l.Keys = append(l.Keys, Key{Source: source, Line: n, PublicKey: pk})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", helper.Location(source, n+1), err)
	}
	return &l, nil
}

// parseLine requires the key type, unlike sshsig.ParsePublicKeyLine.
func parseLine(line string) (ssh.PublicKey, error) {
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(fields) < 2 {
		return nil, fmt.Errorf("expected a key type and key")
	}
	pk, err := sshsig.ParsePublicKey(fields[1])
	if err != nil {
		return nil, fmt.Errorf("invalid ssh public key: %w", err)
	}
	if pk.Type() != fields[0] {
		return nil, fmt.Errorf("key type mismatch: defined %s but parsed %q",
			sshsig.QuoteToken(fields[0]), pk.Type())
	}
	return pk, nil
}

// Append adds m after l, as if m's lines followed l's in one file.
func (l *List) Append(m *List) {
	l.Keys = append(l.Keys, m.Keys...)
}

// Revoked returns the first key that revokes pk, or nil. Keys are compared
// without certificates, so a plain key revokes its certificates and the other
// way round. ca reports that the key matched the CA of a certificate pk.
// It returns an error if pk is a certificate that does not parse.
func (l *List) Revoked(pk ssh.PublicKey) (key *Key, ca bool, err error) {
	cert, err := sshsig.AsCertificate(pk)
	if err != nil {
		return nil, false, err
	}
	signer := plain(pk)
	var authority []byte
	if cert != nil && cert.SignatureKey != nil {
		authority = plain(cert.SignatureKey)
	}
	for i := range l.Keys {
		k := &l.Keys[i]
		revoked := plain(k.PublicKey)
		if bytes.Equal(revoked, signer) {
			return k, false, nil
		}
		if authority != nil && bytes.Equal(revoked, authority) {
			return k, true, nil
		}
	}
	return nil, false, nil
}

// plain returns the wire form of pk, or of the key a certificate certifies.
func plain(pk ssh.PublicKey) []byte {
	if blob, err := sshsig.PlainPublicKeyBlob(pk); err == nil {
		return blob
	}
	return pk.Marshal()
}
