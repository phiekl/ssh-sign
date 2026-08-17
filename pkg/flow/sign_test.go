// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startAgent serves an in-process ssh-agent holding one key over a unix socket,
// points SSH_AUTH_SOCK at it, and returns that key's authorized_keys line.
func startAgent(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("adding key to the agent: %v", err)
	}

	// macOS caps unix socket paths, and t.TempDir() can be long, but this only
	// ever runs on the short paths CI and Linux hand out.
	sock := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", sock)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func TestSign(t *testing.T) {
	keyLine := startAgent(t)

	res, errs := Sign(&SignOpts{
		DataFile:  strings.NewReader(testData),
		SignKey:   keyLine,
		Namespace: "git",
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
	keyLine := startAgent(t)

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
			opts := &SignOpts{DataFile: missing, SignKey: keyLine, Namespace: "git"}
			if _, errs := Sign(opts); len(errs) == 0 ||
				!strings.Contains(errorText(errs), "data file is required") {
				t.Errorf("Sign() errors = %v, want a missing-input error", errs)
			}
		})
	}
}

func TestSignRejectsAKeyTheAgentDoesNotHold(t *testing.T) {
	startAgent(t)
	other := sign(t, "git")

	_, errs := Sign(&SignOpts{
		DataFile:  strings.NewReader(testData),
		SignKey:   other.keyLine,
		Namespace: "git",
	})
	if !strings.Contains(errorText(errs), "no key matched") {
		t.Errorf("Sign() errors = %v, want an unmatched-key error", errs)
	}
}
