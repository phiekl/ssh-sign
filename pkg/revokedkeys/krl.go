// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package revokedkeys

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/internal/helper"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// See OpenSSH's PROTOCOL.krl for the version 1 wire format.
const (
	krlMagic         = "SSHKRL\n\x00"
	maxKRLSize       = 64 << 20
	maxKRLBitmapSize = 2048
	krlCertificates  = 1
	krlExplicitKeys  = 2
	krlSHA1          = 3
	krlSignature     = 4
	krlSHA256        = 5
	krlExtension     = 255
	krlSerialList    = 0x20
	krlSerialRange   = 0x21
	krlSerialBitmap  = 0x22
	krlKeyID         = 0x23
	krlCertExtension = 0x39
)

type krl struct {
	keys, sha1Hashes, sha256Hashes map[string]struct{}
	certificates                   map[string]*krlCertificatesForCA
}

type krlCertificatesForCA struct {
	serials map[uint64]struct{}
	ranges  []krlRange
	bitmaps []krlBitmap
	keyIDs  map[string]struct{}
}

type krlRange struct{ First, Last uint64 }

type krlBitmap struct {
	Offset uint64
	Bits   []byte
}

type krlSection struct {
	Type byte
	Data []byte
	Rest []byte `ssh:"rest"`
}

type krlString struct {
	Data []byte
	Rest []byte `ssh:"rest"`
}

// parseKRL does not retain data.
func parseKRL(data []byte) (*krl, error) {
	if len(data) > maxKRLSize {
		return nil, fmt.Errorf("KRL exceeds %d bytes", maxKRLSize)
	}
	var header struct {
		Format    uint32
		Version   uint64
		Generated uint64
		Flags     uint64
		Reserved  []byte
		Comment   []byte
		Rest      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data[len(krlMagic):], &header); err != nil {
		return nil, fmt.Errorf("invalid KRL header: %w", err)
	}
	// OpenSSH reads the reserved flags without interpreting them.
	if header.Format != 1 {
		return nil, fmt.Errorf("unsupported KRL format %d", header.Format)
	}
	if !helper.ValidCString(header.Comment) {
		return nil, fmt.Errorf("KRL comment contains a NUL byte")
	}
	list := &krl{
		keys:         make(map[string]struct{}),
		sha1Hashes:   make(map[string]struct{}),
		sha256Hashes: make(map[string]struct{}),
		certificates: make(map[string]*krlCertificatesForCA),
	}
	for rest := header.Rest; len(rest) != 0; {
		var section krlSection
		if err := ssh.Unmarshal(rest, &section); err != nil {
			return nil, fmt.Errorf("invalid KRL section: %w", err)
		}
		if err := list.parseSection(section); err != nil {
			return nil, fmt.Errorf("KRL section %#x: %w", section.Type, err)
		}
		rest = section.Rest
	}
	return list, nil
}

func (l *krl) parseSection(section krlSection) error {
	switch section.Type {
	case krlCertificates:
		return l.parseCertificates(section.Data)
	case krlExplicitKeys:
		return addKRLKeys(section.Data, l.keys, 0)
	case krlSHA1:
		return addKRLKeys(section.Data, l.sha1Hashes, sha1.Size)
	case krlSHA256:
		return addKRLKeys(section.Data, l.sha256Hashes, sha256.Size)
	case krlExtension:
		return readKRLExtension(section.Data)
	case krlSignature:
		return fmt.Errorf("signed KRLs are unsupported")
	default:
		return fmt.Errorf("unsupported section type")
	}
}

// size is zero for opaque public key blobs and the digest size for fingerprints.
func addKRLKeys(data []byte, keys map[string]struct{}, size int) error {
	for len(data) != 0 {
		var entry krlString
		if err := ssh.Unmarshal(data, &entry); err != nil {
			return err
		}
		if size != 0 && len(entry.Data) != size {
			return fmt.Errorf("fingerprint length is %d, expected %d", len(entry.Data), size)
		}
		keys[string(entry.Data)] = struct{}{}
		data = entry.Rest
	}
	return nil
}

// parseKRLCA returns the encoding a signing CA key matches. Like OpenSSH, it
// accepts a certificate, whose encoding never equals a plain CA key.
func parseKRLCA(blob []byte) ([]byte, error) {
	key, err := sshsig.ParsePublicKeyBlob(blob)
	if err != nil {
		return nil, fmt.Errorf("invalid KRL public key: %w", err)
	}
	cert, err := sshsig.AsCertificate(key)
	if err != nil {
		return nil, err
	}
	if cert != nil {
		return nil, fmt.Errorf("expected a plain public key in KRL")
	}
	return key.Marshal(), nil
}

func (l *krl) parseCertificates(data []byte) error {
	var section struct {
		CA       []byte
		Reserved []byte
		Rest     []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &section); err != nil {
		return err
	}
	var authority string
	if len(section.CA) != 0 {
		key, err := parseKRLCA(section.CA)
		if err != nil {
			return err
		}
		authority = string(key)
	}
	certs := l.certificates[authority]
	if certs == nil {
		certs = &krlCertificatesForCA{
			serials: make(map[uint64]struct{}),
			keyIDs:  make(map[string]struct{}),
		}
		l.certificates[authority] = certs
	}
	for rest := section.Rest; len(rest) != 0; {
		var entry krlSection
		if err := ssh.Unmarshal(rest, &entry); err != nil {
			return err
		}
		if err := certs.parseSection(entry); err != nil {
			return fmt.Errorf("certificate subsection %#x: %w", entry.Type, err)
		}
		rest = entry.Rest
	}
	return nil
}

func (c *krlCertificatesForCA) parseSection(section krlSection) error {
	data := section.Data
	switch section.Type {
	case krlSerialList:
		if len(data)%8 != 0 {
			return fmt.Errorf("invalid serial list length")
		}
		for len(data) != 0 {
			serial := binary.BigEndian.Uint64(data)
			if serial == 0 {
				return fmt.Errorf("certificate serial must be nonzero")
			}
			c.serials[serial] = struct{}{}
			data = data[8:]
		}
	case krlSerialRange:
		var rng krlRange
		if err := ssh.Unmarshal(data, &rng); err != nil {
			return err
		}
		if rng.First == 0 || rng.Last < rng.First {
			return fmt.Errorf("invalid certificate serial range")
		}
		c.ranges = append(c.ranges, rng)
	case krlSerialBitmap:
		bitmap, err := readKRLBitmap(data)
		if err != nil {
			return err
		}
		c.bitmaps = append(c.bitmaps, bitmap)
	case krlKeyID:
		for len(data) != 0 {
			var entry krlString
			if err := ssh.Unmarshal(data, &entry); err != nil {
				return err
			}
			id := string(entry.Data)
			if !helper.ValidCString(id) {
				return fmt.Errorf("key ID contains a NUL byte")
			}
			c.keyIDs[helper.CString(id)] = struct{}{}
			data = entry.Rest
		}
	case krlCertExtension:
		return readKRLExtension(data)
	default:
		return fmt.Errorf("unsupported certificate subsection type")
	}
	return nil
}

func readKRLBitmap(data []byte) (krlBitmap, error) {
	var bitmap krlBitmap
	if err := ssh.Unmarshal(data, &bitmap); err != nil {
		return bitmap, err
	}
	if len(bitmap.Bits) != 0 && bitmap.Bits[0]&0x80 != 0 {
		return bitmap, fmt.Errorf("negative serial bitmap")
	}
	// OpenSSH's SSHBUF_MAX_BIGNUM, which allows one more byte for a leading zero.
	if n := len(bitmap.Bits); n > maxKRLBitmapSize+1 || (n == maxKRLBitmapSize+1 && bitmap.Bits[0] != 0) {
		return bitmap, fmt.Errorf("serial bitmap exceeds %d bytes", maxKRLBitmapSize)
	}
	bitmap.Bits = bytes.Clone(bytes.TrimLeft(bitmap.Bits, "\x00"))
	if len(bitmap.Bits) != 0 {
		lastBit := uint64(len(bitmap.Bits)-1)*8 + uint64(bits.Len8(bitmap.Bits[0])-1)
		if lastBit > math.MaxUint64-bitmap.Offset ||
			(bitmap.Offset == 0 && bitmap.Bits[len(bitmap.Bits)-1]&1 != 0) {
			return bitmap, fmt.Errorf("serial bitmap is outside the certificate serial range")
		}
	}
	return bitmap, nil
}

func readKRLExtension(data []byte) error {
	var extension struct {
		Name     string
		Critical byte
		Data     []byte
	}
	if err := ssh.Unmarshal(data, &extension); err != nil {
		return err
	}
	if !helper.ValidCString(extension.Name) {
		return fmt.Errorf("extension name contains a NUL byte")
	}
	if extension.Critical != 0 {
		return fmt.Errorf("unsupported critical extension %s", sshsig.QuoteToken(helper.CString(extension.Name)))
	}
	return nil
}

func (l *krl) revokedKey(key []byte) bool {
	if _, ok := l.keys[string(key)]; ok {
		return true
	}
	if len(l.sha1Hashes) != 0 {
		sum := sha1.Sum(key)
		if _, ok := l.sha1Hashes[string(sum[:])]; ok {
			return true
		}
	}
	if len(l.sha256Hashes) != 0 {
		sum := sha256.Sum256(key)
		_, ok := l.sha256Hashes[string(sum[:])]
		return ok
	}
	return false
}

func (l *krl) revokedCertificate(cert *ssh.Certificate, authority []byte) bool {
	return l.certificates[""].revoked(cert) || l.certificates[string(authority)].revoked(cert)
}

func (c *krlCertificatesForCA) revoked(cert *ssh.Certificate) bool {
	if c == nil {
		return false
	}
	if _, ok := c.keyIDs[cert.KeyId]; ok {
		return true
	}
	if _, ok := c.serials[cert.Serial]; ok {
		return true
	}
	for _, rng := range c.ranges {
		if rng.First <= cert.Serial && cert.Serial <= rng.Last {
			return true
		}
	}
	for _, bitmap := range c.bitmaps {
		if cert.Serial >= bitmap.Offset {
			bit := cert.Serial - bitmap.Offset
			if bit/8 < uint64(len(bitmap.Bits)) &&
				bitmap.Bits[uint64(len(bitmap.Bits))-1-bit/8]&(1<<(bit%8)) != 0 {
				return true
			}
		}
	}
	return false
}
