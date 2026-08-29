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

	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type SignOpts struct {
	DataFile  io.Reader
	Log       *slog.Logger
	SignKey   string
	Namespace string
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

	pk, err := sshsig.PublicKeyLineParse(opts.SignKey)
	if err != nil {
		return nil, append(errs, cli.MarkUsage(fmt.Errorf("invalid signing key: %v", err)))
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "sign: signing",
		"namespace", opts.Namespace, keyAttr("key", pk),
	)

	conn, agent, err := sshsig.AgentConnect(opts.Log)
	if err != nil {
		return nil, append(errs, fmt.Errorf("failed agent connection: %v", err))
	}
	// A failure to hand back the socket says nothing about the signature that
	// was already produced, so it is not worth aborting over.
	defer func() { _ = conn.Close() }()

	signer, err := sshsig.AgentSigner(opts.Log, conn, agent, pk)
	if err != nil {
		return nil, append(errs, fmt.Errorf("agent: %v", err))
	}

	sig, err := sshsig.SignatureCreate(signer, opts.Namespace, opts.DataFile)
	if err != nil {
		return nil, append(errs, err)
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "sign: signed",
		"format", sig.Signature.Format, "hash", sig.HashAlgorithm,
	)

	res := SignResult{Signature: sig}
	return &res, errs
}
