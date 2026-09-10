// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/allowedsigners"
)

// Defer entry formatting until a log handler needs it.
func TestEntryAttrDefersItsWork(t *testing.T) {
	validAfter := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ent := &allowedsigners.Entry{
		Line:      7,
		Principal: "alice@example.com",
		KeyType:   "ssh-ed25519",
		PublicKey: testPublicKey(t),
		Options: allowedsigners.Options{
			Namespaces: []string{"file", "git"},
			ValidAfter: &validAfter,
		},
	}

	attr := entryAttr("entry", ent)
	if attr.Value.Kind() != slog.KindLogValuer {
		t.Fatalf("entryAttr() value kind = %v, want %v", attr.Value.Kind(), slog.KindLogValuer)
	}

	group := attr.Value.Resolve().Group()
	got := map[string]string{}
	for _, a := range group {
		got[a.Key] = a.Value.String()
	}
	for key, want := range map[string]string{
		"line":         "7",
		"principal":    "alice@example.com",
		"type":         "ssh-ed25519",
		"namespaces":   "file,git",
		"valid_after":  "2026-01-02T03:04:05Z",
		"valid_before": "",
	} {
		if got[key] != want {
			t.Errorf("entry.%s = %q, want %q", key, got[key], want)
		}
	}
	if got["fingerprint"] == "" {
		t.Error("entry.fingerprint is empty, want the key fingerprint")
	}
}

// testPublicKey generates an Ed25519 public key.
func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting key: %v", err)
	}
	return pk
}
