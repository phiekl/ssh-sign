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
	Designation    string `json:"designation"`
	Namespace      string `json:"namespace"`
	Principal      string `json:"principal"`
	Verification   string `json:"verification"`
}

func (r VerifyResult) String() string {
	return cli.ResultFormatKV(
		r,
		-15, " ", "= ", "",
		"principal", "authentication", "namespace", "designation", "verification",
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

	// Every check below is independent, so all of them run and report, in the
	// same way check does. That keeps a partial result available even when something fails.
	res := VerifyResult{Namespace: sig.Namespace}

	// An explicit namespace is an invocation-specific pin. Without one, the
	// namespace embedded in the signature is still checked against any policy
	// on the matched allowed signers entry below.
	if opts.Namespace == "" {
		res.Designation = "disabled"
	} else if opts.Namespace == sig.Namespace {
		res.Designation = "valid"
	} else {
		res.Designation = "invalid"
		errs = append(errs, fmt.Errorf(
			"signature contains namespace %q (expected %q)", sig.Namespace, opts.Namespace,
		))
	}

	var ent *allowedsigners.Entry
	if opts.NoNamespace {
		ent, err = parsed.MatchEntryIgnoringNamespace(
			sig.PublicKey, opts.Principal, opts.Timestamp,
		)
	} else {
		ent, err = parsed.MatchEntry(
			sig.PublicKey, opts.Principal, sig.Namespace, opts.Timestamp,
		)
	}
	// Without an invocation-specific pin, a namespace restriction on the
	// matched allowed signers entry supplies the designation policy.
	if opts.Namespace == "" && !opts.NoNamespace && ent != nil &&
		len(ent.Options.Namespaces) > 0 {
		res.Designation = "valid"
	}
	switch {
	case err != nil && opts.Principal == "":
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf(
			"signer public key found in allowed signers, but failed constraints: %v", err,
		))
	case err != nil:
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf(
			"principal %q found in allowed signers, but failed constraints: %v",
			opts.Principal, err,
		))
	case ent == nil && opts.Principal == "":
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf("signer public key not found within allowed signers"))
	case ent == nil:
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf(
			"principal %q not found within allowed signers", opts.Principal,
		))
	case opts.Principal == "":
		res.Authentication = "disabled"
		// No principal was requested, so the entry's pattern-list is the most
		// specific identity available.
		res.Principal = ent.Principal
	default:
		res.Authentication = "valid"
		// ent.Principal is the entry's pattern-list, which may be something
		// like "*@example.com". Report the identity that was authenticated.
		res.Principal = opts.Principal
	}

	if err := sshsigx.SignatureVerify(opts.VerifyFile, sig); err == nil {
		res.Verification = "valid"
	} else {
		res.Verification = "invalid"
		errs = append(errs, err)
	}

	return &res, errs
}
