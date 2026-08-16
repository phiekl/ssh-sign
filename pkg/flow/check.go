// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

type CheckOpts struct {
	AuthKey       string
	Namespace     string
	NoAuthKey     bool
	NoNamespace   bool
	SignatureFile io.Reader
	VerifyFile    io.Reader
}

type CheckResult struct {
	Authentication string `json:"authentication"`
	Designation    string `json:"designation"`
	Verification   string `json:"verification"`
}

func (r CheckResult) String() string {
	return cli.ResultFormatKV(
		r,
		-15, " ", "= ", "",
		"authentication", "designation", "verification",
	)
}

func Check(opts *CheckOpts) (*CheckResult, []error) {
	var errs []error
	var err error
	var pk ssh.PublicKey

	if err := requireReader(opts.SignatureFile, "signature file"); err != nil {
		return nil, []error{err}
	}
	if err := requireReader(opts.VerifyFile, "verify file"); err != nil {
		return nil, []error{err}
	}

	if err := CheckAuthKey(opts.AuthKey, opts.NoAuthKey); err != nil {
		errs = append(errs, err)
	}
	if err := CheckNamespace(opts.Namespace, opts.NoNamespace); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errs
	}

	if !opts.NoAuthKey {
		pk, err = sshsigx.PublicKeyLineParse(opts.AuthKey)
		if err != nil {
			return nil, append(errs, fmt.Errorf("invalid authentication key: %v", err))
		}
	}

	sig, err := sshsigx.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, append(errs, err)
	}

	res := CheckResult{}
	if opts.NoAuthKey {
		res.Authentication = "disabled"
	} else if sshsigx.PublicKeyEqual(pk, sig.PublicKey) {
		res.Authentication = "valid"
	} else {
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf(
			"signature was created by public key %q (expected %q)",
			sshsigx.PublicKeyString(sig.PublicKey), sshsigx.PublicKeyString(pk),
		))
	}

	if opts.NoNamespace {
		res.Designation = "disabled"
	} else if opts.Namespace == sig.Namespace {
		res.Designation = "valid"
	} else {
		res.Designation = "invalid"
		errs = append(errs, fmt.Errorf(
			"signature contains namespace %q (expected %q)", sig.Namespace, opts.Namespace,
		))
	}

	if err := sshsigx.SignatureVerify(opts.VerifyFile, sig); err == nil {
		res.Verification = "valid"
	} else {
		res.Verification = "invalid"
		errs = append(errs, err)
	}

	return &res, errs
}
