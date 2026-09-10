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

type SignOpts struct {
	DataFile  io.Reader
	Log       *slog.Logger
	Namespace string
	Signer    ssh.Signer
}

type SignResult struct {
	Signature *sshsig.Signature
}

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

func Sign(opts *SignOpts) (*SignResult, []error) {
	var errs []error
	if opts == nil {
		return nil, []error{fmt.Errorf("options are required")}
	}

	if err := requireReader(opts.DataFile, "data file"); err != nil {
		return nil, append(errs, err)
	}
	if isNil(opts.Signer) {
		return nil, append(errs, fmt.Errorf("signer is required"))
	}
	pk := opts.Signer.PublicKey()
	if isNil(pk) {
		return nil, append(errs, fmt.Errorf("signer public key is required"))
	}
	// Check certificate validity before asking the agent to sign.
	if err := sshsig.CertificateValidAt(pk, time.Now()); err != nil {
		return nil, append(errs, fmt.Errorf("signing key %w", err))
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "sign: signing",
		"namespace", opts.Namespace, keyAttr("key", pk),
	)

	sig, err := sshsig.SignatureCreate(opts.Signer, opts.Namespace, opts.DataFile)
	if err != nil {
		return nil, append(errs, err)
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "sign: signed",
		"format", sig.Signature.Format, "hash", sig.HashAlgorithm,
	)

	res := SignResult{Signature: sig}
	return &res, errs
}
