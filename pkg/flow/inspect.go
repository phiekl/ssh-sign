// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"
	"log/slog"

	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type InspectOpts struct {
	Log           *slog.Logger
	SignatureFile io.Reader
}

type InspectResult struct {
	sshsig.SignatureInfo
}

func (r InspectResult) String() string {
	return cli.ResultFormatKV(-22, " ", "| ",
		cli.KV("version", r.Version),
		cli.KV("publickey_format", r.PublicKey.Format),
		cli.KV("publickey_blob", r.PublicKey.Blob),
		cli.KV("publickey_fingerprint", r.PublicKey.Fingerprint),
		cli.KV("namespace", r.Namespace),
		cli.KV("hash_algorithm", r.HashAlgorithm),
		cli.KV("signature_format", r.Signature.Format),
		cli.KV("signature_blob", r.Signature.Blob),
	)
}

func Inspect(opts *InspectOpts) (*InspectResult, []error) {
	var errs []error
	if opts == nil {
		return nil, []error{fmt.Errorf("options are required")}
	}

	if err := requireReader(opts.SignatureFile, "signature file"); err != nil {
		return nil, append(errs, err)
	}

	sig, err := sshsig.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, append(errs, err)
	}
	debugSignature(opts.Log, "inspect", sig)

	res := InspectResult{sshsig.NewSignatureInfo(sig)}
	return &res, errs
}
