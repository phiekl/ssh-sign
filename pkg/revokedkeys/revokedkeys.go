// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package revokedkeys reads text and binary OpenSSH revocation lists.
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

// List holds revocations in file order. Keys contains the text entries.
type List struct {
	Keys []Key
	krls []krlSource
}

type krlSource struct {
	source   string
	keyIndex int
	list     *krl
}

// Key identifies a revocation entry.
type Key struct {
	// Source names the file, or is empty for an unnamed reader.
	Source string

	// File line number, or zero for a binary KRL.
	Line int

	PublicKey ssh.PublicKey

	// ByCertificate reports a match by certificate serial number or key ID.
	ByCertificate bool
}

// Location returns the source and, for text entries, line number.
func (k *Key) Location() string {
	if k.Line == 0 {
		if k.Source == "" {
			return "KRL"
		}
		return fmt.Sprintf("file=%q", k.Source)
	}
	return helper.Location(k.Source, k.Line)
}

// Parse reads a binary KRL or a text list of "type base64 [comment]" lines.
// It returns an error if it cannot read or interpret the list.
func Parse(r io.Reader) (*List, error) {
	return ParseSource(r, "")
}

// ParseBytes parses a buffered list without making another copy of the input.
// The caller may reuse data after parsing returns.
func ParseBytes(data []byte, source string) (*List, error) {
	if bytes.HasPrefix(data, []byte(krlMagic)) {
		return parseKRLSource(data, source)
	}
	return parseText(bytes.NewReader(data), source)
}

// ParseSource is Parse with source recorded on every key and error.
func ParseSource(r io.Reader, source string) (*List, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(krlMagic))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", helper.Location(source, 1), err)
	}
	if string(head) == krlMagic {
		data, err := io.ReadAll(io.LimitReader(br, maxKRLSize+1))
		if err != nil {
			return nil, fmt.Errorf("%s: reading KRL: %w", (&Key{Source: source}).Location(), err)
		}
		return parseKRLSource(data, source)
	}
	return parseText(br, source)
}

func parseText(r io.Reader, source string) (*List, error) {
	sc := bufio.NewScanner(r)
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

func parseKRLSource(data []byte, source string) (*List, error) {
	list, err := parseKRL(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", (&Key{Source: source}).Location(), err)
	}
	return &List{krls: []krlSource{{source: source, list: list}}}, nil
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

// Append adds m after l, preserving the order of both text and binary sources.
func (l *List) Append(m *List) {
	for _, krl := range m.krls {
		krl.keyIndex += len(l.Keys)
		l.krls = append(l.krls, krl)
	}
	l.Keys = append(l.Keys, m.Keys...)
}

// KRLs returns the number of binary KRLs, whose entries are not in Keys.
func (l *List) KRLs() int {
	return len(l.krls)
}

// Revoked returns the first entry that revokes pk, or nil. Plain keys match
// their certificates. ca reports that the entry revoked the CA key itself.
// It returns an error if pk is a certificate that does not parse.
func (l *List) Revoked(pk ssh.PublicKey) (key *Key, ca bool, err error) {
	cert, err := sshsig.AsCertificate(pk)
	if err != nil {
		return nil, false, err
	}
	subject := pk
	var authority []byte
	if cert != nil {
		subject = cert.Key
		if cert.SignatureKey != nil {
			authority = plain(cert.SignatureKey)
		}
	}
	signer := subject.Marshal()
	offset := 0
	for _, binary := range l.krls {
		end := max(offset, min(binary.keyIndex, len(l.Keys)))
		if k, ca := revokedText(l.Keys[offset:end], signer, authority); k != nil {
			return k, ca, nil
		}
		switch {
		case binary.list.revokedKey(signer):
			return &Key{Source: binary.source, PublicKey: subject}, false, nil
		case cert != nil && binary.list.revokedCertificate(cert, authority):
			return &Key{Source: binary.source, PublicKey: pk, ByCertificate: true}, false, nil
		case authority != nil && binary.list.revokedKey(authority):
			return &Key{Source: binary.source, PublicKey: cert.SignatureKey}, true, nil
		}
		offset = end
	}
	key, ca = revokedText(l.Keys[offset:], signer, authority)
	return key, ca, nil
}

func revokedText(keys []Key, signer, authority []byte) (*Key, bool) {
	for i := range keys {
		k := &keys[i]
		revoked := plain(k.PublicKey)
		if bytes.Equal(revoked, signer) {
			return k, false
		}
		if authority != nil && bytes.Equal(revoked, authority) {
			return k, true
		}
	}
	return nil, false
}

// plain returns the wire form of pk, or of the key a certificate certifies.
func plain(pk ssh.PublicKey) []byte {
	if blob, err := sshsig.PlainPublicKeyBlob(pk); err == nil {
		return blob
	}
	return pk.Marshal()
}
