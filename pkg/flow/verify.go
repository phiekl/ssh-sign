// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"
	"time"

	"pxy.se/go/ssh-sign/pkg/allowedsigners"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

type VerifyOpts struct {
	AllowedSignersFile io.Reader
	Namespace          string
	NoNamespace        bool
	Principal          string
	SignatureFile      io.Reader
	Timestamp          time.Time
	VerifyFile         io.Reader
}

type VerifyResult struct {
	Authentication string `json:"authentication"`
	Namespace      string `json:"namespace"`
	Principal      string `json:"principal"`
	Verification   string `json:"verification"`
}

func (r VerifyResult) String() string {
	return cli.ResultFormatKV(
		r,
		-15, " ", "= ", "",
		"principal", "namespace", "authentication", "verification",
	)
}

func Verify(opts *VerifyOpts) (*VerifyResult, []error) {
	var errs []error
	var err error

	if err := requireReader(opts.AllowedSignersFile, "allowed signers file"); err != nil {
		return nil, []error{err}
	}
	if err := requireReader(opts.SignatureFile, "signature file"); err != nil {
		return nil, []error{err}
	}
	if err := requireReader(opts.VerifyFile, "verify file"); err != nil {
		return nil, []error{err}
	}
	if opts.Timestamp.IsZero() {
		opts.Timestamp = time.Now()
	}

	parsed, err := allowedsigners.Parse(opts.AllowedSignersFile)
	if err != nil {
		return nil, []error{fmt.Errorf("failed parsing allowed signers file: %v", err)}
	}

	sig, err := sshsigx.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, []error{err}
	}

	res := VerifyResult{}

	ent, err := parsed.MatchEntry(sig.PublicKey, opts.Principal, sig.Namespace, opts.Timestamp)
	if opts.Principal == "" {
		if err != nil {
			e := fmt.Errorf(
				"signer public key found in allowed signers, but failed constraints: %v",
				err,
			)
			return nil, []error{e}
		}
		if ent == nil {
			e := fmt.Errorf(
				"signer public key not found within allowed signers",
			)
			return nil, []error{e}
		}
		res.Authentication = "disabled"
	} else {
		if err != nil {
			e := fmt.Errorf(
				"principal %q found in allowed signers, but failed contraints: %v",
				opts.Principal, err,
			)
			return nil, []error{e}
		}
		if ent == nil {
			e := fmt.Errorf(
				"principal %q not found within allowed signers",
				opts.Principal,
			)
			return nil, []error{e}
		}
		res.Authentication = "valid"
	}

	if err := sshsigx.SignatureVerify(opts.VerifyFile, sig); err != nil {
		return nil, []error{err}
	}

	res.Principal = ent.Principal
	res.Namespace = sig.Namespace
	res.Verification = "valid"

	return &res, errs
}
