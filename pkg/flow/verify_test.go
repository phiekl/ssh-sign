// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// signed is a signature over testData together with its signer's key line.
type signed struct {
	armored string
	keyLine string
}

const testData = "hello\n"

// sign produces a signature over testData in the given namespace.
func sign(t *testing.T, namespace string) signed {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	sig, err := sshsig.Sign(strings.NewReader(testData), signer, sshsig.HashSHA512, namespace)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	return signed{
		armored: string(sshsig.Armor(sig)),
		keyLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
	}
}

// verifyOpts builds options for a signature that should verify cleanly.
func (s signed) verifyOpts(allowed, namespace string) *VerifyOpts {
	return &VerifyOpts{
		AllowedSignersFile: strings.NewReader(allowed),
		Namespace:          namespace,
		SignatureFile:      strings.NewReader(s.armored),
		VerifyFile:         strings.NewReader(testData),
	}
}

// errorText joins a result's errors for substring matching.
func errorText(errs []error) string {
	var out []string
	for _, err := range errs {
		out = append(out, err.Error())
	}
	return strings.Join(out, "\n")
}

func TestVerifySucceeds(t *testing.T) {
	s := sign(t, "git")

	res, errs := Verify(s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git"))
	if len(errs) != 0 {
		t.Fatalf("Verify() errors = %v, want none", errs)
	}
	if res.Verification != "valid" || res.Authentication != "disabled" {
		t.Errorf("Verify() = %+v, want it valid with principal pinning disabled", res)
	}
	if res.Namespace != "git" || res.Designation != "valid" {
		t.Errorf("Verify() = %+v, want namespace git reported valid", res)
	}
}

func TestVerifyDoesNotSetDefaultTimestamp(t *testing.T) {
	s := sign(t, "git")
	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")

	if _, errs := Verify(opts); len(errs) != 0 {
		t.Fatalf("Verify() errors = %v, want none", errs)
	}
	if !opts.Timestamp.IsZero() {
		t.Errorf("Verify() set options timestamp to %v", opts.Timestamp)
	}
}

func TestVerifyRejectsAnUnconstrainedNamespace(t *testing.T) {
	s := sign(t, "git")

	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "")
	res, errs := Verify(opts)
	if !strings.Contains(errorText(errs), "left unverified") {
		t.Fatalf("Verify() errors = %v, want an unverified namespace", errs)
	}
	if res.Designation != "invalid" {
		t.Errorf("Designation = %q, want %q", res.Designation, "invalid")
	}
	if res.Verification != "valid" || res.Authentication != "disabled" {
		t.Errorf("Verify() = %+v, want the other checks to have passed", res)
	}
}

func TestVerifyReportsAllowedSignersNamespaceAsValid(t *testing.T) {
	s := sign(t, "git")
	allowed := `alice@example.com namespaces="git" ` + s.keyLine + "\n"

	res, errs := Verify(s.verifyOpts(allowed, ""))
	if len(errs) != 0 {
		t.Fatalf("Verify() errors = %v, want none", errs)
	}
	if res.Designation != "valid" {
		t.Errorf("Designation = %q, want %q", res.Designation, "valid")
	}
}

func TestVerifyFindsANamespaceRestrictionListedLater(t *testing.T) {
	s := sign(t, "git")
	allowed := "alice@example.com " + s.keyLine + "\n" +
		`alice@example.com namespaces="git" ` + s.keyLine + "\n"

	res, errs := Verify(s.verifyOpts(allowed, ""))
	if len(errs) != 0 {
		t.Fatalf("Verify() errors = %v, want none", errs)
	}
	if res.Designation != "valid" {
		t.Errorf("Designation = %q, want %q", res.Designation, "valid")
	}
}

func TestVerifyRejectsANamespaceOnlyOtherEntriesRestrict(t *testing.T) {
	s := sign(t, "email")
	allowed := "alice@example.com " + s.keyLine + "\n" +
		`alice@example.com namespaces="git" ` + s.keyLine + "\n"

	res, errs := Verify(s.verifyOpts(allowed, ""))
	if !strings.Contains(errorText(errs), "left unverified") {
		t.Fatalf("Verify() errors = %v, want an unverified namespace", errs)
	}
	if res.Designation != "invalid" || res.Authentication != "disabled" {
		t.Errorf("Verify() = %+v, want the signer listed but the namespace unverified", res)
	}
}

func TestVerifyUsesAllowedSignersNamespaceByDefault(t *testing.T) {
	s := sign(t, "git")
	allowed := `alice@example.com namespaces="email" ` + s.keyLine + "\n"

	res, errs := Verify(s.verifyOpts(allowed, ""))
	if !strings.Contains(errorText(errs), "namespace mismatch") {
		t.Fatalf("Verify() errors = %v, want an allowed signers namespace mismatch", errs)
	}
	if res.Authentication != "invalid" || res.Designation != "invalid" {
		t.Errorf("Verify() = %+v, want policy rejection without a namespace pin", res)
	}
}

func TestVerifyCombinesExplicitAndAllowedSignersNamespaces(t *testing.T) {
	s := sign(t, "git")
	allowed := `alice@example.com namespaces="email" ` + s.keyLine + "\n"

	res, errs := Verify(s.verifyOpts(allowed, "git"))
	if !strings.Contains(errorText(errs), "namespace mismatch") {
		t.Fatalf("Verify() errors = %v, want an allowed signers namespace mismatch", errs)
	}
	if res.Designation != "invalid" {
		t.Errorf("Designation = %q, want %q", res.Designation, "invalid")
	}
	if res.Verification != "valid" {
		t.Errorf("Verification = %q, want %q", res.Verification, "valid")
	}
}

func TestVerifyNoNamespaceWaivesAllowedSignersRestriction(t *testing.T) {
	s := sign(t, "git")
	allowed := `alice@example.com namespaces="email" ` + s.keyLine + "\n"
	opts := s.verifyOpts(allowed, "")
	opts.NoNamespace = true

	res, errs := Verify(opts)
	if len(errs) != 0 {
		t.Fatalf("Verify() errors = %v, want none", errs)
	}
	if res.Authentication != "disabled" || res.Designation != "disabled" ||
		res.Verification != "valid" {
		t.Errorf("Verify() = %+v, want namespace checks disabled", res)
	}
}

func TestVerifyRejectsAnotherNamespace(t *testing.T) {
	s := sign(t, "email")

	res, errs := Verify(s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git"))
	if !strings.Contains(errorText(errs), `namespace "email" (expected "git")`) {
		t.Fatalf("Verify() errors = %v, want a namespace mismatch", errs)
	}
	// The rest of the checks still ran and are reported.
	if res.Designation != "invalid" {
		t.Errorf("Designation = %q, want %q", res.Designation, "invalid")
	}
	if res.Verification != "valid" || res.Authentication != "disabled" {
		t.Errorf("Verify() = %+v, want the other checks to have passed", res)
	}
}

func TestVerifyRejectsAnUnlistedSigner(t *testing.T) {
	s := sign(t, "git")
	other := sign(t, "git")

	res, errs := Verify(s.verifyOpts("alice@example.com "+other.keyLine+"\n", "git"))
	if !strings.Contains(errorText(errs), "not found within allowed signers") {
		t.Fatalf("Verify() errors = %v, want an unknown-signer error", errs)
	}
	if res.Authentication != "invalid" {
		t.Errorf("Authentication = %q, want %q", res.Authentication, "invalid")
	}
}

func TestVerifyBlamesOnlyTheUnlistedSigner(t *testing.T) {
	s := sign(t, "git")
	other := sign(t, "git")

	res, errs := Verify(s.verifyOpts("alice@example.com "+other.keyLine+"\n", ""))
	if len(errs) != 1 || !strings.Contains(errorText(errs), "not found within allowed signers") {
		t.Fatalf("Verify() errors = %v, want only an unknown-signer error", errs)
	}
	if res.Designation != "invalid" {
		t.Errorf("Designation = %q, want %q", res.Designation, "invalid")
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	s := sign(t, "git")

	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")
	opts.VerifyFile = strings.NewReader("tampered\n")

	res, errs := Verify(opts)
	if len(errs) == 0 {
		t.Fatal("Verify() errors = none, want a verification failure")
	}
	if res.Verification != "invalid" {
		t.Errorf("Verification = %q, want %q", res.Verification, "invalid")
	}
}

func TestVerifyHonoursTheValidityWindow(t *testing.T) {
	s := sign(t, "git")
	allowed := `alice@example.com valid-after="20260101Z",valid-before="20260201Z" ` + s.keyLine + "\n"

	inside := s.verifyOpts(allowed, "git")
	inside.Timestamp = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if _, errs := Verify(inside); len(errs) != 0 {
		t.Errorf("Verify() errors = %v, want none inside the window", errs)
	}

	outside := s.verifyOpts(allowed, "git")
	outside.Timestamp = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if _, errs := Verify(outside); !strings.Contains(errorText(errs), "expired") {
		t.Errorf("Verify() errors = %v, want an expiry error", errs)
	}
}

func TestInspectReportsSignatureDetails(t *testing.T) {
	s := sign(t, "git")

	res, errs := Inspect(&InspectOpts{SignatureFile: strings.NewReader(s.armored)})
	if len(errs) != 0 {
		t.Fatalf("Inspect() errors = %v, want none", errs)
	}
	if res.Namespace != "git" {
		t.Errorf("Namespace = %q, want %q", res.Namespace, "git")
	}
	if res.HashAlgorithm != "sha512" {
		t.Errorf("HashAlgorithm = %q, want %q", res.HashAlgorithm, "sha512")
	}
	if want := strings.Fields(s.keyLine)[1]; res.PublicKey.Blob != want {
		t.Errorf("PublicKey.Blob = %q, want %q", res.PublicKey.Blob, want)
	}
	if !strings.Contains(res.String(), "namespace") {
		t.Errorf("String() = %q, want it to list the namespace", res.String())
	}
}

func TestCheck(t *testing.T) {
	s := sign(t, "git")

	t.Run("everything pinned", func(t *testing.T) {
		res, errs := Check(&CheckOpts{
			AuthKey:       s.keyLine,
			Namespace:     "git",
			SignatureFile: strings.NewReader(s.armored),
			VerifyFile:    strings.NewReader(testData),
		})
		if len(errs) != 0 {
			t.Fatalf("Check() errors = %v, want none", errs)
		}
		if res.Authentication != "valid" || res.Designation != "valid" ||
			res.Verification != "valid" {
			t.Errorf("Check() = %+v, want everything valid", res)
		}
	})

	t.Run("everything waived", func(t *testing.T) {
		res, errs := Check(&CheckOpts{
			NoAuthKey:     true,
			NoNamespace:   true,
			SignatureFile: strings.NewReader(s.armored),
			VerifyFile:    strings.NewReader(testData),
		})
		if len(errs) != 0 {
			t.Fatalf("Check() errors = %v, want none", errs)
		}
		if res.Authentication != "disabled" || res.Designation != "disabled" {
			t.Errorf("Check() = %+v, want both checks disabled", res)
		}
	})

	t.Run("wrong key and namespace", func(t *testing.T) {
		other := sign(t, "git")
		res, errs := Check(&CheckOpts{
			AuthKey:       other.keyLine,
			Namespace:     "email",
			SignatureFile: strings.NewReader(s.armored),
			VerifyFile:    strings.NewReader(testData),
		})
		// Both failures are reported, not just the first.
		text := errorText(errs)
		if !strings.Contains(text, "was created by public key") {
			t.Errorf("Check() errors = %v, want a key mismatch", errs)
		}
		if !strings.Contains(text, `namespace "git" (expected "email")`) {
			t.Errorf("Check() errors = %v, want a namespace mismatch", errs)
		}
		if res.Verification != "valid" {
			t.Errorf("Verification = %q, want %q", res.Verification, "valid")
		}
	})
}

// TestFlowsRejectMissingReaders covers both a plain nil input and a typed nil,
// which is not equal to nil once stored in an io.Reader and would otherwise
// panic on the first Read.
func TestFlowsRejectMissingReaders(t *testing.T) {
	var typedNil *bytes.Reader
	s := sign(t, "git")
	allowed := "alice@example.com " + s.keyLine + "\n"

	readers := map[string]io.Reader{"nil": nil, "typed nil": typedNil}

	for kind, missing := range readers {
		t.Run(kind+" allowed signers", func(t *testing.T) {
			opts := s.verifyOpts(allowed, "git")
			opts.AllowedSignersFile = missing
			assertMissingReader(t, func() []error { _, errs := Verify(opts); return errs })
		})
		t.Run(kind+" verify signature", func(t *testing.T) {
			opts := s.verifyOpts(allowed, "git")
			opts.SignatureFile = missing
			assertMissingReader(t, func() []error { _, errs := Verify(opts); return errs })
		})
		t.Run(kind+" verify data", func(t *testing.T) {
			opts := s.verifyOpts(allowed, "git")
			opts.VerifyFile = missing
			assertMissingReader(t, func() []error { _, errs := Verify(opts); return errs })
		})
		t.Run(kind+" check signature", func(t *testing.T) {
			assertMissingReader(t, func() []error {
				_, errs := Check(&CheckOpts{
					NoAuthKey: true, NoNamespace: true,
					SignatureFile: missing, VerifyFile: strings.NewReader(testData),
				})
				return errs
			})
		})
		t.Run(kind+" check data", func(t *testing.T) {
			assertMissingReader(t, func() []error {
				_, errs := Check(&CheckOpts{
					NoAuthKey: true, NoNamespace: true,
					SignatureFile: strings.NewReader(s.armored), VerifyFile: missing,
				})
				return errs
			})
		})
		t.Run(kind+" inspect signature", func(t *testing.T) {
			assertMissingReader(t, func() []error {
				_, errs := Inspect(&InspectOpts{SignatureFile: missing})
				return errs
			})
		})
	}
}

// assertMissingReader runs call and requires it to report a missing input
// rather than panicking.
func assertMissingReader(t *testing.T, call func() []error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on a missing reader: %v", r)
		}
	}()
	if errs := call(); len(errs) == 0 ||
		!strings.Contains(errorText(errs), "is required") {
		t.Errorf("errors = %v, want a missing-input error", errs)
	}
}

// TestChoicesRejectPinningAndWaivingTogether covers callers of this package;
// the command line makes the two flags mutually exclusive. Resolving the
// conflict in favour of the waiver would drop a check the caller configured.
func TestChoicesRejectPinningAndWaivingTogether(t *testing.T) {
	if err := CheckNamespace("git", true); err == nil {
		t.Error("CheckNamespace() accepted a namespace together with a waiver")
	}
	if err := CheckAuthKey("ssh-ed25519 AAAA", true); err == nil {
		t.Error("CheckAuthKey() accepted a key together with a waiver")
	}
	if err := CheckNamespace("git", false); err != nil {
		t.Errorf("CheckNamespace() = %v, want nil", err)
	}
	if err := CheckNamespace("", true); err != nil {
		t.Errorf("CheckNamespace() = %v, want nil", err)
	}
}

// TestVerifyRejectsPinningAndWaivingTogether checks the flow applies it, since
// the waiver is what would otherwise silently win.
func TestVerifyRejectsPinningAndWaivingTogether(t *testing.T) {
	s := sign(t, "git")
	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")
	opts.NoNamespace = true

	res, errs := Verify(opts)
	if res != nil {
		t.Errorf("Verify() result = %+v, want nil", res)
	}
	if !strings.Contains(errorText(errs), "namespace verification is disabled") {
		t.Errorf("Verify() errors = %v, want a conflicting-choice error", errs)
	}
}
