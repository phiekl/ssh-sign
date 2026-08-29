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

	"golang.org/x/crypto/ssh"
)

type typedNilSigner struct{}

func (*typedNilSigner) PublicKey() ssh.PublicKey { return nil }
func (*typedNilSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, nil
}

type nilPublicKeySigner struct {
	publicKey ssh.PublicKey
}

func (s nilPublicKeySigner) PublicKey() ssh.PublicKey { return s.publicKey }
func (nilPublicKeySigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, nil
}

type typedNilPublicKey struct{}

func (*typedNilPublicKey) Type() string                        { return "" }
func (*typedNilPublicKey) Marshal() []byte                     { return nil }
func (*typedNilPublicKey) Verify([]byte, *ssh.Signature) error { return nil }

func testSigner(t *testing.T) ssh.Signer {
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

func TestSign(t *testing.T) {
	signer := testSigner(t)
	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	res, errs := Sign(&SignOpts{
		DataFile:  strings.NewReader(testData),
		Namespace: "git",
		Signer:    signer,
	})
	if len(errs) != 0 {
		t.Fatalf("Sign() errors = %v, want none", errs)
	}

	// The signature it produced must verify against the key that made it.
	verified, errs := Check(&CheckOpts{
		AuthKey:       keyLine,
		Namespace:     "git",
		SignatureFile: strings.NewReader(res.String()),
		VerifyFile:    strings.NewReader(testData),
	})
	if len(errs) != 0 {
		t.Fatalf("Check() errors = %v, want none", errs)
	}
	if verified.Verification != "valid" || verified.Authentication != "valid" {
		t.Errorf("Check() = %+v, want it valid", verified)
	}
}

func TestSignRejectsMissingData(t *testing.T) {
	signer := testSigner(t)

	var typedNil *bytes.Reader
	// The map has to be of the interface type. Holding the cases as
	// *bytes.Reader and assigning only the non-nil ones would make both of them
	// a plain nil interface, and the typed-nil case would test nothing.
	for name, missing := range map[string]io.Reader{"nil": nil, "typed nil": typedNil} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a missing reader: %v", r)
				}
			}()
			opts := &SignOpts{DataFile: missing, Namespace: "git", Signer: signer}
			if _, errs := Sign(opts); len(errs) == 0 ||
				!strings.Contains(errorText(errs), "data file is required") {
				t.Errorf("Sign() errors = %v, want a missing-input error", errs)
			}
		})
	}
}

func TestSignRejectsMissingSigner(t *testing.T) {
	var typedNil *typedNilSigner
	for name, signer := range map[string]ssh.Signer{"nil": nil, "typed nil": typedNil} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a missing signer: %v", r)
				}
			}()
			_, errs := Sign(&SignOpts{
				DataFile:  strings.NewReader(testData),
				Namespace: "git",
				Signer:    signer,
			})
			if !strings.Contains(errorText(errs), "signer is required") {
				t.Errorf("Sign() errors = %v, want a missing-signer error", errs)
			}
		})
	}
}

func TestSignRejectsSignerWithoutPublicKey(t *testing.T) {
	var typedNil *typedNilPublicKey
	for name, publicKey := range map[string]ssh.PublicKey{"nil": nil, "typed nil": typedNil} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on a signer without a public key: %v", r)
				}
			}()
			_, errs := Sign(&SignOpts{
				DataFile:  strings.NewReader(testData),
				Namespace: "git",
				Signer:    nilPublicKeySigner{publicKey: publicKey},
			})
			if !strings.Contains(errorText(errs), "signer public key is required") {
				t.Errorf("Sign() errors = %v, want a missing-public-key error", errs)
			}
		})
	}
}
