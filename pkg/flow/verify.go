// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"os"
	"time"

	"pxy.se/go/ssh-sign/pkg/allowedsigners"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

type VerifyOpts struct {
	AllowedSignersFile *os.File
	Principal          string
	SignatureFile      *os.File
	Timestamp          time.Time
	VerifyFile         *os.File
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
	//var pk ssh.PublicKey

	if opts.AllowedSignersFile == nil {
		return nil, []error{fmt.Errorf("allowed signers file is required")}
	}
	if opts.SignatureFile == nil {
		return nil, []error{fmt.Errorf("signature file is required")}
	}
	if opts.VerifyFile == nil {
		return nil, []error{fmt.Errorf("verify file is required")}
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
