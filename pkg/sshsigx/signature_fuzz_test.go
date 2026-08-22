// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

func FuzzSignatureRead(f *testing.F) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		f.Fatalf("creating signer: %v", err)
	}
	sig, err := SignatureCreate(signer, "file", bytes.NewReader([]byte("fuzz seed\n")))
	if err != nil {
		f.Fatalf("creating signature: %v", err)
	}

	f.Add(sshsig.Armor(sig))
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n"))
	f.Add([]byte("not a signature\n"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		parsed, _ := signatureRead(bytes.NewReader(input), 1<<20)
		if parsed != nil {
			_ = NewSignatureInfo(parsed)
		}
	})
}
