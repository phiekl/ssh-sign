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
	if opts == nil {
		return nil, []error{fmt.Errorf("options are required")}
	}

	if err := requireReader(opts.AllowedSignersFile, "allowed signers file"); err != nil {
		return nil, []error{err}
	}
	if err := requireReader(opts.SignatureFile, "signature file"); err != nil {
		return nil, []error{err}
	}
	if err := requireReader(opts.VerifyFile, "verify file"); err != nil {
		return nil, []error{err}
	}
	// Allowed signers may supply the namespace when both options are unset.
	if opts.Namespace != "" || opts.NoNamespace {
		if err := CheckNamespace(opts.Namespace, opts.NoNamespace); err != nil {
			return nil, []error{err}
		}
	}
	timestamp := opts.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	parsed, err := allowedsigners.Parse(opts.AllowedSignersFile)
	if err != nil {
		return nil, []error{fmt.Errorf("failed parsing allowed signers file: %v", err)}
	}

	sig, err := sshsigx.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, []error{err}
	}

	// Run every check so failures still include a partial result.
	res := VerifyResult{Namespace: sig.Namespace}

	// Without an explicit namespace, allowed signers supplies the namespace policy.
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
	var restricted bool
	switch {
	case opts.NoNamespace:
		ent, err = parsed.MatchEntryIgnoringNamespace(
			sig.PublicKey, opts.Principal, timestamp,
		)
	case opts.Namespace == "":
		// Prefer an entry that supplies namespace policy.
		ent, restricted, err = parsed.MatchEntryRestrictingNamespace(
			sig.PublicKey, opts.Principal, sig.Namespace, timestamp,
		)
	default:
		ent, err = parsed.MatchEntry(
			sig.PublicKey, opts.Principal, sig.Namespace, timestamp,
		)
	}
	// Reject a namespace that neither the invocation nor allowed signers checked.
	if opts.Namespace == "" && !opts.NoNamespace {
		checked, matched := allowedsigners.NamespaceConstraintResult(err)
		switch {
		case restricted:
			res.Designation = "valid"
		case checked && matched:
			res.Designation = "valid"
		case checked:
			res.Designation = "invalid"
		case ent != nil:
			res.Designation = "invalid"
			errs = append(errs, fmt.Errorf(
				"signature namespace %q was left unverified: no namespace was requested "+
					"and no matching allowed signers entry restricts one "+
					"(use -n, -N or namespaces=)",
				sig.Namespace,
			))
		default:
			res.Designation = "invalid"
		}
	}
	// An explicit namespace must also satisfy allowed signers.
	if opts.Namespace != "" && !opts.NoNamespace {
		if checked, matched := allowedsigners.NamespaceConstraintResult(err); checked && !matched {
			res.Designation = "invalid"
		}
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
