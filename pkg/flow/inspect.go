// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"

	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

type InspectOpts struct {
	SignatureFile io.Reader
}

type InspectResult struct {
	sshsigx.SignatureInfo
}

func (r InspectResult) String() string {
	out := ""
	out += cli.ResultFormatKV(
		r,
		-22, " ", "| ", "",
		"version",
	)
	out += "\n"
	out += cli.ResultFormatKV(
		r.PublicKey,
		-22, " ", "| ", "publickey_",
		"format", "blob", "fingerprint",
	)
	out += "\n"
	out += cli.ResultFormatKV(
		r,
		-22, " ", "| ", "",
		"namespace", "hash_algorithm",
	)
	out += "\n"
	out += cli.ResultFormatKV(
		r.Signature,
		-22, " ", "| ", "signature_",
		"format", "blob",
	)
	return out
}

func Inspect(opts *InspectOpts) (*InspectResult, []error) {
	var errs []error
	if opts == nil {
		return nil, []error{fmt.Errorf("options are required")}
	}

	if err := requireReader(opts.SignatureFile, "signature file"); err != nil {
		return nil, append(errs, err)
	}

	sig, err := sshsigx.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, append(errs, err)
	}

	res := InspectResult{sshsigx.NewSignatureInfo(sig)}
	return &res, errs
}
