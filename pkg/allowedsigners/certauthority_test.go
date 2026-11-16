// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
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

// issue signs a user certificate valid from 2020 up to, not including, 2040.
func issue(t *testing.T, ca ssh.Signer, principals ...string) *ssh.Certificate {
	t.Helper()
	return issueCert(t, ca, ssh.UserCert, at(t, "2020-01-01"), at(t, "2040-01-01"), principals...)
}

func issueCert(
	t *testing.T, ca ssh.Signer, certType uint32, after, before time.Time, principals ...string,
) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             newSigner(t).PublicKey(),
		CertType:        certType,
		KeyId:           "test",
		ValidPrincipals: principals,
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	return cert
}

func TestParseCertAuthority(t *testing.T) {
	ca := newSigner(t)
	f := parseLines(t,
		"alice@example.com cert-authority "+keyLine(ca.PublicKey()),
		`alice@example.com namespaces="git",cert-authority `+keyLine(ca.PublicKey()),
	)
	if len(f.Entries) != 2 {
		t.Fatalf("len(Entries) = %d, want 2 (skipped: %v)", len(f.Entries), f.Skipped)
	}
	for _, e := range f.Entries {
		if !e.Options.CertAuthority {
			t.Errorf("line %d: CertAuthority = false, want true", e.Line)
		}
	}
	if !slices.Equal(f.Entries[1].Options.Namespaces, []string{"git"}) {
		t.Errorf("Namespaces = %q, want [git]", f.Entries[1].Options.Namespaces)
	}
}

// Stricter than ssh-keygen, which would compare the certificate's plain key.
func TestParseSkipsACertificateAuthorityCertificate(t *testing.T) {
	cert := issue(t, newSigner(t), "alice@example.com")
	f := parseLines(t, "alice@example.com cert-authority "+keyLine(cert))
	if len(f.Entries) != 0 || len(f.Skipped) != 1 {
		t.Fatalf("Entries = %d, Skipped = %v, want the line skipped", len(f.Entries), f.Skipped)
	}
}

func TestMatchEntryCertAuthority(t *testing.T) {
	ca := newSigner(t)
	caLine := keyLine(ca.PublicKey())
	now := at(t, "2026-06-01")

	good := issue(t, ca, "alice@example.com", "bob@example.com")
	tests := []struct {
		name      string
		lines     []string
		key       ssh.PublicKey
		principal string
		ns        string
		wantLine  int
		wantErr   string
	}{
		{
			name: "listed principal", lines: []string{"*@example.com cert-authority " + caLine},
			key: good, principal: "bob@example.com", wantLine: 1,
		},
		{
			name: "no principal requested", lines: []string{"alice@example.com cert-authority " + caLine},
			key: good, wantLine: 1,
		},
		{
			name: "principal not in the certificate", lines: []string{"* cert-authority " + caLine},
			key: good, principal: "carol@example.com", wantErr: "name is not a listed principal",
		},
		{
			name: "certificate principals are not patterns", lines: []string{"* cert-authority " + caLine},
			key: issue(t, ca, "*@example.com"), principal: "alice@example.com",
			wantErr: "name is not a listed principal",
		},
		{
			name: "requested principal is not a pattern", lines: []string{"* cert-authority " + caLine},
			key: good, principal: "alice@*", wantErr: "name is not a listed principal",
		},
		{
			name: "principal not in the line", lines: []string{"alice@example.com cert-authority " + caLine},
			key: good, principal: "bob@example.com",
		},
		{
			name:  "no certificate principal matches the line",
			lines: []string{"carol@example.com cert-authority " + caLine},
			key:   good, wantErr: "no certificate principal matches",
		},
		{
			name: "no certificate principals", lines: []string{"* cert-authority " + caLine},
			key: issue(t, ca), principal: "alice@example.com", wantErr: "lacks principal list",
		},
		{
			name:  "no certificate principals and no principal requested",
			lines: []string{"* cert-authority " + caLine},
			key:   issue(t, ca), wantErr: "lacks principal list",
		},
		{
			name: "expired certificate", lines: []string{"* cert-authority " + caLine},
			key:       issueCert(t, ca, ssh.UserCert, at(t, "2020-01-01"), now, "alice@example.com"),
			principal: "alice@example.com", wantErr: "certificate expired",
		},
		{
			name: "certificate not yet valid", lines: []string{"* cert-authority " + caLine},
			key:       issueCert(t, ca, ssh.UserCert, now.Add(time.Second), at(t, "2040-01-01"), "alice@example.com"),
			principal: "alice@example.com", wantErr: "not valid until",
		},
		{
			name: "host certificate", lines: []string{"* cert-authority " + caLine},
			key:       issueCert(t, ca, ssh.HostCert, at(t, "2020-01-01"), at(t, "2040-01-01"), "alice@example.com"),
			principal: "alice@example.com", wantErr: "not a user certificate",
		},
		{
			name: "another CA", lines: []string{"* cert-authority " + caLine},
			key: issue(t, newSigner(t), "alice@example.com"), principal: "alice@example.com",
		},
		{
			name: "the CA's own key", lines: []string{"* cert-authority " + caLine},
			key: ca.PublicKey(), principal: "alice@example.com",
		},
		{
			name: "the certificate's plain key", lines: []string{"* cert-authority " + caLine},
			key: good.Key, principal: "alice@example.com",
		},
		{
			name: "namespace restriction", lines: []string{`* cert-authority,namespaces="git" ` + caLine},
			key: good, principal: "alice@example.com", ns: "file", wantErr: "namespace mismatch",
		},
		{
			name: "validity restriction", lines: []string{`* cert-authority,valid-before="20260101Z" ` + caLine},
			key: good, principal: "alice@example.com", wantErr: "expired",
		},
		{
			name: "falls through to a later entry",
			lines: []string{
				`* cert-authority,namespaces="file" ` + caLine,
				"alice@example.com " + keyLine(good),
			},
			key: good, principal: "alice@example.com", wantLine: 2,
		},
		{
			name: "falls through past an unauthorized certificate",
			lines: []string{
				"* cert-authority " + caLine,
				"carol@example.com " + keyLine(good),
			},
			key: good, principal: "carol@example.com", wantLine: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseLines(t, tt.lines...)
			if len(f.Skipped) > 0 {
				t.Fatalf("Skipped = %v", f.Skipped)
			}
			ns := tt.ns
			if ns == "" {
				ns = "git"
			}
			entry, err := f.MatchEntry(tt.key, tt.principal, ns, now)
			gotLine := 0
			if entry != nil {
				gotLine = entry.Line
			}
			if gotLine != tt.wantLine {
				t.Errorf("MatchEntry() line = %d, want %d (err: %v)", gotLine, tt.wantLine, err)
			}
			switch {
			case tt.wantErr == "" && err != nil && tt.wantLine != 0:
				t.Errorf("MatchEntry() error = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("MatchEntry() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestMatchEntryChecksNamespaceWhenCertificatePrincipalFails(t *testing.T) {
	ca := newSigner(t)
	file, err := Parse(strings.NewReader("alice cert-authority,namespaces=\"git\" " + keyLine(ca.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := file.MatchEntry(issue(t, ca, "bob"), "", "file", at(t, "2026-06-01"))
	if entry != nil || err == nil || !strings.Contains(err.Error(), "certificate not authorized") {
		t.Fatalf("MatchEntry() = %v, %v, want a certificate authorization error", entry, err)
	}
	if checked, matched := NamespaceConstraintResult(err); !checked || matched {
		t.Errorf("NamespaceConstraintResult() = %t, %t, want a namespace mismatch", checked, matched)
	}
}

func TestMatchEntryCertAuthorityRejectsAForgedCertificate(t *testing.T) {
	ca := newSigner(t)
	cert := issue(t, ca, "alice@example.com")
	cert.ValidPrincipals = []string{"mallory@example.com"}

	f := parseLines(t, "* cert-authority "+keyLine(ca.PublicKey()))
	entry, err := f.MatchEntry(cert, "mallory@example.com", "git", at(t, "2026-06-01"))
	if entry != nil || err == nil || !strings.Contains(err.Error(), "certificate signature") {
		t.Errorf("MatchEntry() = %v, %v, want a certificate signature error", entry, err)
	}
}

func TestCertificatePrincipals(t *testing.T) {
	ca := newSigner(t)
	cert := issue(t, ca, "alice@example.com", "bob@example.com", "carol@example.org")
	f := parseLines(t,
		"*@example.com,!bob@example.com cert-authority "+keyLine(ca.PublicKey()),
		"*@example.com "+keyLine(cert),
	)

	if got := f.Entries[0].CertificatePrincipals(cert); !slices.Equal(got, []string{"alice@example.com"}) {
		t.Errorf("CertificatePrincipals() = %q, want [alice@example.com]", got)
	}
	if got := f.Entries[0].CertificatePrincipals(cert.Key); got != nil {
		t.Errorf("CertificatePrincipals(plain key) = %q, want nil", got)
	}
	if got := f.Entries[1].CertificatePrincipals(cert); got != nil {
		t.Errorf("CertificatePrincipals() = %q, want nil for a plain entry", got)
	}
}

type countedCertificateKey struct {
	ssh.PublicKey
	marshalCalls int
}

func (k *countedCertificateKey) Marshal() []byte {
	k.marshalCalls++
	return k.PublicKey.Marshal()
}

func TestMatchEntryParsesCertificateOnceForUnrelatedCAs(t *testing.T) {
	pk := &countedCertificateKey{PublicKey: issue(t, newSigner(t), "alice@example.com")}
	f := parseLines(t,
		"* cert-authority "+keyLine(newSigner(t).PublicKey()),
		"* cert-authority "+keyLine(newSigner(t).PublicKey()),
		"* cert-authority "+keyLine(newSigner(t).PublicKey()),
	)
	if entry, err := f.MatchEntry(pk, "", "git", at(t, "2026-06-01")); entry != nil || err != nil {
		t.Fatalf("MatchEntry() = %v, %v, want no entry and no error", entry, err)
	}
	if pk.marshalCalls != 1 {
		t.Errorf("certificate encoding read %d times, want once", pk.marshalCalls)
	}
}

// ssh-keygen -Y find-principals stops at the first empty pattern.
func TestCertificatePrincipalsStopAtAnEmptyPattern(t *testing.T) {
	ca := newSigner(t)
	cert := issue(t, ca, "alice@example.com", "bob@example.com")
	f := parseLines(t, "bob@example.com,,alice@example.com cert-authority "+keyLine(ca.PublicKey()))

	if got := f.Entries[0].CertificatePrincipals(cert); !slices.Equal(got, []string{"bob@example.com"}) {
		t.Errorf("CertificatePrincipals() = %q, want [bob@example.com]", got)
	}
	f = parseLines(t, ",alice@example.com cert-authority "+keyLine(ca.PublicKey()))
	if entry, err := f.MatchEntry(cert, "", "git", at(t, "2026-06-01")); entry != nil {
		t.Errorf("MatchEntry() = %v, %v, want no entry", entry, err)
	}
}

// Changing a certificate obtained from the parsed key must not authorize
// another principal under the CA's original signature.
func TestMatchEntryIgnoresChangesToACertificateCopy(t *testing.T) {
	ca := newSigner(t)
	pk, err := sshsig.ParsePublicKey(strings.Fields(keyLine(issue(t, ca, "alice@example.com")))[1])
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	cert, err := sshsig.AsCertificate(pk)
	if err != nil {
		t.Fatalf("AsCertificate() error = %v", err)
	}
	cert.ValidPrincipals = []string{"mallory@example.com"}

	f := parseLines(t, "* cert-authority "+keyLine(ca.PublicKey()))
	if entry, err := f.MatchEntry(pk, "mallory@example.com", "git", at(t, "2026-06-01")); entry != nil {
		t.Errorf("MatchEntry() = %v, %v, want mallory not authorized", entry, err)
	}
	if entry, err := f.MatchEntry(pk, "alice@example.com", "git", at(t, "2026-06-01")); entry == nil {
		t.Errorf("MatchEntry() = nil, %v, want alice authorized", err)
	}
}
