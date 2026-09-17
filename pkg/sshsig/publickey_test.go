// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKey is an ssh-ed25519 public key in authorized_keys format.
const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk"

func testKeyBlob() string {
	return strings.Fields(testKey)[1]
}

func TestParsePublicKeyLine(t *testing.T) {
	blob := testKeyBlob()

	for name, line := range map[string]string{
		"blob only":         blob,
		"type and blob":     testKey,
		"trailing comment":  testKey + " user@localhost",
		"surrounding space": "  " + testKey + "  ",
	} {
		t.Run(name, func(t *testing.T) {
			pk, err := ParsePublicKeyLine(line)
			if err != nil {
				t.Fatalf("ParsePublicKeyLine(%q) error = %v", line, err)
			}
			if got := PublicKeyString(pk); got != testKey {
				t.Errorf("ParsePublicKeyLine(%q) = %q, want %q", line, got, testKey)
			}
		})
	}
}

func TestParsePublicKeyLineRejectsGarbage(t *testing.T) {
	for name, line := range map[string]string{
		"empty":            "",
		"whitespace only":  "   ",
		"type without key": "ssh-ed25519",
		"not base64":       "@@@@",
		"not a public key": "aGVsbG8=",
		// Reject a stated type that disagrees with the encoded key.
		"key type mismatch": "ssh-rsa " + testKeyBlob(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKeyLine(line); err == nil {
				t.Errorf("ParsePublicKeyLine(%q) unexpectedly succeeded", line)
			}
		})
	}
}

func TestParsePublicKeyTruncatesTheEchoedToken(t *testing.T) {
	token := strings.Repeat("A", 1<<20) + "@"

	_, err := ParsePublicKey(token)
	if err == nil {
		t.Fatal("ParsePublicKey() unexpectedly succeeded")
	}
	if len(err.Error()) > 512 {
		t.Errorf("ParsePublicKey() error is %d bytes long, want the token truncated",
			len(err.Error()))
	}
	if !strings.Contains(err.Error(), "1048577 bytes total") {
		t.Errorf("ParsePublicKey() error = %v, want the full token length reported", err)
	}
}

// Limit errors that repeat a large algorithm name from a decoded key.
func TestParsePublicKeyTruncatesTheKeyParserError(t *testing.T) {
	blob := ssh.Marshal(struct{ Name string }{Name: strings.Repeat("A", 1<<20)})

	_, err := ParsePublicKey(base64.StdEncoding.EncodeToString(blob))
	if err == nil {
		t.Fatal("ParsePublicKey() unexpectedly succeeded")
	}
	if len(err.Error()) > 1024 {
		t.Errorf("ParsePublicKey() error is %d bytes long, want it bounded",
			len(err.Error()))
	}
	if !strings.Contains(err.Error(), "bytes total") {
		t.Errorf("ParsePublicKey() error = %.120q, want the full length reported", err)
	}
}

func TestQuoteTokenLeavesShortTokensIntact(t *testing.T) {
	if got, want := QuoteToken("ssh-ed25519"), `"ssh-ed25519"`; got != want {
		t.Errorf("QuoteToken() = %s, want %s", got, want)
	}
}

func TestNewPublicKeyInfo(t *testing.T) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey() error = %v", err)
	}

	info := NewPublicKeyInfo(pk)
	if info.Format != "ssh-ed25519" {
		t.Errorf("Format = %q, want %q", info.Format, "ssh-ed25519")
	}
	if want := testKeyBlob(); info.Blob != want {
		t.Errorf("Blob = %q, want %q", info.Blob, want)
	}
	if !strings.HasPrefix(info.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want a SHA256: prefix", info.Fingerprint)
	}
}

func TestPublicKeyEqual(t *testing.T) {
	first, err := ParsePublicKeyLine(testKey)
	if err != nil {
		t.Fatalf("ParsePublicKeyLine() error = %v", err)
	}
	second, err := ParsePublicKeyLine(testKey)
	if err != nil {
		t.Fatalf("ParsePublicKeyLine() error = %v", err)
	}
	if !PublicKeyEqual(first, second) {
		t.Error("PublicKeyEqual() = false for two parses of the same key")
	}

	// Flip the last base64 character to get a different, still valid, key blob.
	blob := testKeyBlob()
	other, err := ParsePublicKey(blob[:len(blob)-2] + "aa")
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	if PublicKeyEqual(first, other) {
		t.Error("PublicKeyEqual() = true for two different keys")
	}
}
