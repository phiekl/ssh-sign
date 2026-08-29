// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type CheckOpts struct {
	AuthKey       string
	Log           *slog.Logger
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
	if opts == nil {
		return nil, []error{fmt.Errorf("options are required")}
	}

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
		pk, err = sshsig.PublicKeyLineParse(opts.AuthKey)
		if err != nil {
			return nil, append(errs, fmt.Errorf("invalid authentication key: %v", err))
		}
		cli.Debug(opts.Log, cli.LevelDebug2, "check: expecting", keyAttr("key", pk))
	}

	sig, err := sshsig.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, append(errs, err)
	}
	debugSignature(opts.Log, "check", sig)

	res := CheckResult{}
	if opts.NoAuthKey {
		res.Authentication = "disabled"
	} else if sshsig.PublicKeyEqual(pk, sig.PublicKey) {
		res.Authentication = "valid"
	} else {
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf(
			"signature was created by public key %q (expected %q)",
			sshsig.PublicKeyString(sig.PublicKey), sshsig.PublicKeyString(pk),
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

	if err := sshsig.SignatureVerify(opts.VerifyFile, sig); err == nil {
		res.Verification = "valid"
	} else {
		res.Verification = "invalid"
		errs = append(errs, err)
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "check: checked",
		"authentication", res.Authentication,
		"designation", res.Designation,
		"verification", res.Verification,
	)

	return &res, errs
}
