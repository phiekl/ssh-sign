// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package revokedkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/internal/helper"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return signer
}

func keyLine(pk ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func issue(t *testing.T, ca ssh.Signer, pk ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             pk,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice@example.com"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	return cert
}

func parse(t *testing.T, content string) *List {
	t.Helper()
	l, err := ParseSource(strings.NewReader(content), "revoked")
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	return l
}

func TestRevoked(t *testing.T) {
	ca := newSigner(t)
	user := newSigner(t).PublicKey()
	cert := issue(t, ca, user)
	other := newSigner(t).PublicKey()

	tests := []struct {
		name     string
		list     string
		key      ssh.PublicKey
		wantLine int
		wantCA   bool
	}{
		{name: "empty", list: "", key: user},
		{name: "plain key", list: keyLine(user), key: user, wantLine: 1},
		{name: "plain key revokes its certificates", list: keyLine(user), key: cert, wantLine: 1},
		{name: "certificate revokes its plain key", list: keyLine(cert), key: user, wantLine: 1},
		{name: "another certificate of the key",
			list: keyLine(issue(t, newSigner(t), user)), key: cert, wantLine: 1},
		{name: "CA key", list: keyLine(ca.PublicKey()), key: cert, wantLine: 1, wantCA: true},
		{name: "CA key is not revoked as a signer", list: keyLine(user), key: ca.PublicKey()},
		{name: "other key", list: keyLine(other), key: user},
		{
			name:     "comments, blank lines and whitespace",
			list:     "# revoked\n\n \t\n  # indented\n\t " + keyLine(other) + "\n  " + keyLine(user) + "  lost laptop\n",
			key:      user,
			wantLine: 6,
		},
		{name: "CRLF", list: keyLine(other) + "\r\n" + keyLine(user) + "\r\n", key: user, wantLine: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ca, err := parse(t, tt.list).Revoked(tt.key)
			if err != nil {
				t.Fatalf("Revoked() error = %v", err)
			}
			gotLine := 0
			if got != nil {
				gotLine = got.Line
			}
			if gotLine != tt.wantLine || ca != tt.wantCA {
				t.Errorf("Revoked() = line %d, CA %v, want line %d, CA %v", gotLine, ca, tt.wantLine, tt.wantCA)
			}
			if want := fmt.Sprintf(`file="revoked" line=%d`, tt.wantLine); got != nil && got.Location() != want {
				t.Errorf("Location() = %q", got.Location())
			}
		})
	}
}

// Like ssh-keygen, fail rather than skip a line that might have listed the key.
func TestParseFailsClosed(t *testing.T) {
	user := keyLine(newSigner(t).PublicKey())
	blob := strings.Fields(user)[1]

	tests := map[string]string{
		"garbage":           "garbage\n",
		"garbage after key": user + "\ngarbage\n",
		"type only":         "ssh-ed25519\n",
		"no type":           blob + "\n",
		"type mismatch":     "ssh-rsa " + blob + "\n",
		"options":           "cert-authority " + user + "\n",
		"bad base64":        "ssh-ed25519 not-base64!\n",
		"KRL":               "SSHKRL\n\x00" + strings.Repeat("\x00", 16),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSource(strings.NewReader(content), "revoked")
			if err == nil {
				t.Fatal("ParseSource() error = nil, want an error")
			}
			if !strings.HasPrefix(err.Error(), `file="revoked"`) {
				t.Errorf("ParseSource() error = %v, want it to name the line", err)
			}
		})
	}
}

func TestParseRejectsTruncatedKRL(t *testing.T) {
	_, err := Parse(strings.NewReader("SSHKRL\n\x00"))
	if err == nil || !strings.Contains(err.Error(), "KRL") {
		t.Errorf("Parse() error = %v, want a KRL error", err)
	}
}

func TestParseFailsOnAnOverlongLine(t *testing.T) {
	_, err := Parse(strings.NewReader("#\n# " + strings.Repeat("x", helper.MaxLineSize) + "\n"))
	if err == nil || !strings.HasPrefix(err.Error(), "line=2: ") {
		t.Errorf("Parse() error = %v, want it to name line 2", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestParseFailsOnUnreadableInput(t *testing.T) {
	if _, err := Parse(failingReader{}); err == nil {
		t.Error("Parse() error = nil, want an error")
	}
}

func TestAppendKeepsOrderAndSources(t *testing.T) {
	user := newSigner(t).PublicKey()
	l := parse(t, "# first\n")
	second, err := ParseSource(strings.NewReader(keyLine(user)+"\n"), "second")
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	l.Append(second)

	got, _, err := l.Revoked(user)
	if err != nil {
		t.Fatalf("Revoked() error = %v", err)
	}
	if got == nil || got.Source != "second" || got.Line != 1 {
		t.Errorf("Revoked() = %+v, want second line 1", got)
	}
}

// certificateTypedKey has a certificate type but an arbitrary encoding.
type certificateTypedKey struct{ blob []byte }

func (certificateTypedKey) Type() string                        { return ssh.CertAlgoED25519v01 }
func (k certificateTypedKey) Marshal() []byte                   { return k.blob }
func (certificateTypedKey) Verify([]byte, *ssh.Signature) error { return errors.New("not a signer") }

func TestRevokedFailsOnAnUnparseableCertificate(t *testing.T) {
	user := newSigner(t).PublicKey()
	cert := issue(t, newSigner(t), user)
	blob := cert.Marshal()
	l := parse(t, keyLine(user)+"\n")

	key, _, err := l.Revoked(certificateTypedKey{blob[:len(blob)-1]})
	if key != nil || err == nil || !strings.Contains(err.Error(), "certificate is unparseable") {
		t.Errorf("Revoked() = %+v, %v, want a certificate parse error", key, err)
	}
}
