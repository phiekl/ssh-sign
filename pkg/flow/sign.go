// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// SignOpts configures Sign. DataFile and Signer are required.
type SignOpts struct {
	DataFile  io.Reader
	Log       *slog.Logger
	Namespace string
	Signer    ssh.Signer
}

// SignResult holds the created signature.
type SignResult struct {
	Signature *sshsig.Signature
}

// MarshalJSON renders the armored signature.
func (r SignResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		&struct {
			ArmoredSignature string `json:"armored_signature"`
		}{
			ArmoredSignature: string(sshsig.Armor(r.Signature)),
		},
	)
}

func (r SignResult) String() string {
	return strings.TrimSpace(string(sshsig.Armor(r.Signature)))
}

// Sign signs the data in the given namespace.
func Sign(opts *SignOpts) (*SignResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("options are required")
	}

	if err := requireReader(opts.DataFile, "data file"); err != nil {
		return nil, err
	}
	if isNil(opts.Signer) {
		return nil, fmt.Errorf("signer is required")
	}
	pk := opts.Signer.PublicKey()
	if isNil(pk) {
		return nil, fmt.Errorf("signer public key is required")
	}
	// Check certificate validity before asking the agent to sign.
	if err := sshsig.CertificateValidAt(pk, time.Now()); err != nil {
		return nil, fmt.Errorf("signing key %w", err)
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "sign: signing",
		"namespace", opts.Namespace, keyAttr("key", pk),
	)

	sig, err := sshsig.SignatureCreate(opts.Signer, opts.Namespace, opts.DataFile)
	if err != nil {
		return nil, err
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "sign: signed",
		"format", sig.Signature.Format, "hash", sig.HashAlgorithm,
	)

	res := SignResult{Signature: sig}
	return &res, nil
}
