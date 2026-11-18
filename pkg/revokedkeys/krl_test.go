// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package revokedkeys

import (
	"bytes"
	"encoding/base64"
	"math"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func krlDocument(sections ...[]byte) []byte {
	header := struct {
		Format               uint32
		Version, Date, Flags uint64
		Reserved, Comment    string
	}{Format: 1}
	return bytes.Join(append([][]byte{[]byte(krlMagic), ssh.Marshal(header)}, sections...), nil)
}

func krlRecord(kind byte, data []byte) []byte {
	return ssh.Marshal(struct {
		Kind byte
		Data []byte
	}{kind, data})
}

func krlCertRecord(subsections ...[]byte) []byte {
	header := ssh.Marshal(struct{ CA, Reserved []byte }{})
	return krlRecord(krlCertificates, bytes.Join(append([][]byte{header}, subsections...), nil))
}

func TestKRLSerialEncodings(t *testing.T) {
	data := krlDocument(krlCertRecord(
		krlRecord(krlSerialList, ssh.Marshal(struct{ First, Second uint64 }{1, 100})),
		krlRecord(krlSerialRange, ssh.Marshal(krlRange{50, 60})),
		krlRecord(krlSerialBitmap, ssh.Marshal(krlBitmap{1000, []byte{0x01, 0x82}})),
		krlRecord(krlKeyID, ssh.Marshal(struct{ ID string }{"retired"})),
	))
	l := parse(t, string(data))
	for _, tt := range []struct {
		serial uint64
		id     string
		want   bool
	}{
		{1, "", true}, {2, "", false}, {100, "", true},
		{49, "", false}, {50, "", true}, {60, "", true}, {61, "", false},
		{999, "", false}, {1000, "", false}, {1001, "", true},
		{1007, "", true}, {1008, "", true}, {1009, "", false},
		{0, "retired", true}, {0, "", false},
	} {
		cert := &ssh.Certificate{Serial: tt.serial, KeyId: tt.id}
		if got := l.krls[0].list.revokedCertificate(cert, []byte("any CA")); got != tt.want {
			t.Errorf("serial %d, key ID %q: revoked = %v, want %v", tt.serial, tt.id, got, tt.want)
		}
	}
}

func TestKRLSectionErrors(t *testing.T) {
	extension := func(critical bool) []byte {
		return ssh.Marshal(struct {
			Name     string
			Critical bool
			Data     []byte
		}{"test@example.test", critical, nil})
	}
	for _, tt := range []struct {
		name    string
		section []byte
	}{
		{"unknown", krlRecord(99, nil)},
		{"signed", krlRecord(krlSignature, nil)},
		{"critical extension", krlRecord(krlExtension, extension(true))},
		{"critical certificate extension", krlCertRecord(krlRecord(krlCertExtension, extension(true)))},
		{"short fingerprint", krlRecord(krlSHA256, ssh.Marshal(struct{ Hash []byte }{[]byte{1}}))},
		{"truncated serial list", krlCertRecord(krlRecord(krlSerialList, []byte{1}))},
		{"inverted serial range", krlCertRecord(krlRecord(krlSerialRange, ssh.Marshal(krlRange{10, 9})))},
		{"overflowing bitmap", krlCertRecord(krlRecord(krlSerialBitmap, ssh.Marshal(krlBitmap{math.MaxUint64, []byte{2}})))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(bytes.NewReader(krlDocument(tt.section))); err == nil {
				t.Fatal("Parse accepted an invalid or unsupported KRL section")
			}
		})
	}
	optional := krlDocument(krlRecord(krlExtension, extension(false)),
		krlCertRecord(krlRecord(krlCertExtension, extension(false))))
	if _, err := Parse(bytes.NewReader(optional)); err != nil {
		t.Errorf("Parse rejected optional extensions: %v", err)
	}
}

func TestAppendOrdersTextAndBinaryRevocations(t *testing.T) {
	key := newSigner(t).PublicKey()
	data := krlDocument(krlRecord(krlExplicitKeys, ssh.Marshal(struct{ Key []byte }{key.Marshal()})))
	binary, err := ParseSource(bytes.NewReader(data), "revoked.krl")
	if err != nil {
		t.Fatal(err)
	}
	text, err := ParseSource(strings.NewReader(keyLine(key)), "revoked.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*List{{binary, text}, {text, binary}} {
		var combined List
		combined.Append(pair[0])
		combined.Append(pair[1])
		want, _, _ := pair[0].Revoked(key)
		got, _, _ := combined.Revoked(key)
		if got == nil || got.Location() != want.Location() {
			t.Errorf("Revoked() = %+v, want %s", got, want.Location())
		}
	}
}

// OpenSSH reads the bitmap as a bignum of at most 2048 bytes, plus a zero.
func TestKRLSerialBitmapSizeLimit(t *testing.T) {
	bitmap := func(size int, first byte) []byte {
		bits := make([]byte, size)
		bits[0], bits[size-1] = first, 1
		return krlDocument(krlCertRecord(krlRecord(krlSerialBitmap, ssh.Marshal(krlBitmap{1000, bits}))))
	}
	for _, tt := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "2048 bytes", data: bitmap(2048, 1)},
		{name: "2049 bytes with a leading zero", data: bitmap(2049, 0)},
		{name: "2049 bytes", data: bitmap(2049, 1), wantErr: "serial bitmap exceeds 2048 bytes"},
		{name: "2050 bytes with a leading zero", data: bitmap(2050, 0),
			wantErr: "serial bitmap exceeds 2048 bytes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader(tt.data))
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Parse() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestKRLExplicitKeysAllowUnknownAlgorithms(t *testing.T) {
	revoked := newSigner(t).PublicKey()
	unknown := ssh.Marshal(struct{ Name, Key string }{"ssh-future@example.test", "opaque key data"})
	section := ssh.Marshal(struct{ Unknown, Revoked []byte }{unknown, revoked.Marshal()})
	l := parse(t, string(krlDocument(krlRecord(krlExplicitKeys, section))))
	if key, _, err := l.Revoked(revoked); key == nil || err != nil {
		t.Errorf("Revoked(listed key) = %v, %v, want a match", key, err)
	}
	if key, _, err := l.Revoked(newSigner(t).PublicKey()); key != nil || err != nil {
		t.Errorf("Revoked(unlisted key) = %v, %v, want no match", key, err)
	}
}

func TestKRLCAKeyErrorsOmitBase64(t *testing.T) {
	blob := ssh.Marshal(struct{ Name, Key string }{"ssh-ed25519", "short"})
	data := krlDocument(krlRecord(krlCertificates, ssh.Marshal(struct{ CA, Reserved []byte }{CA: blob})))
	_, err := Parse(bytes.NewReader(data))
	if err == nil || !strings.Contains(err.Error(), "invalid KRL public key: ") {
		t.Fatalf("Parse() error = %v, want an invalid KRL public key", err)
	}
	if encoded := base64.StdEncoding.EncodeToString(blob); strings.Contains(err.Error(), encoded[:16]) {
		t.Errorf("Parse() error = %v, want it without the base64 key", err)
	}
}

func TestParseBytesReadsKRLInPlace(t *testing.T) {
	const size = 8 << 20
	padding := ssh.Marshal(struct {
		Name     string
		Critical bool
		Data     []byte
	}{"padding@example.test", false, make([]byte, size)})
	data := krlDocument(krlRecord(krlExtension, padding))

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := ParseBytes(data, "")
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("ParseBytes() error = %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > size/2 {
		t.Errorf("ParseBytes() allocated %d bytes for a %d byte KRL", allocated, len(data))
	}
}
