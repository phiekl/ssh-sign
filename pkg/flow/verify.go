// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"pxy.se/go/ssh-sign/pkg/allowedsigners"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type VerifyOpts struct {
	AllowedSignersFile io.Reader
	Log                *slog.Logger
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
	cli.Debug(opts.Log, cli.LevelDebug1, "verify: verifying",
		"namespace", opts.Namespace,
		"no_namespace", opts.NoNamespace,
		"principal", opts.Principal,
		"timestamp", timestamp.Format(time.RFC3339),
	)

	parsed, err := allowedsigners.Parse(opts.AllowedSignersFile)
	if err != nil {
		return nil, []error{fmt.Errorf("failed parsing allowed signers file: %v", err)}
	}
	cli.Debug(opts.Log, cli.LevelDebug2, "verify: parsed allowed signers",
		"entries", len(parsed.Entries), "skipped", parsed.SkippedCount,
	)
	for i := range parsed.Skipped {
		cli.Debug(opts.Log, cli.LevelDebug1, "verify: skipped allowed signers line",
			"line", parsed.Skipped[i].Line, "reason", parsed.Skipped[i].Msg,
		)
	}
	for i := range parsed.Entries {
		cli.Debug(opts.Log, cli.LevelDebug3, "verify: allowed signers entry",
			entryAttr("entry", &parsed.Entries[i]),
		)
	}

	sig, err := sshsig.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, []error{err}
	}
	debugSignature(opts.Log, "verify", sig)

	// Run all checks and retain the requested principal on failure.
	res := VerifyResult{Namespace: sig.Namespace, Principal: opts.Principal}

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
	switch {
	case err != nil:
		cli.Debug(opts.Log, cli.LevelDebug1, "verify: allowed signers rejected the signer",
			"reason", err,
		)
	case ent == nil:
		cli.Debug(opts.Log, cli.LevelDebug1, "verify: no allowed signers entry matched")
	default:
		cli.Debug(opts.Log, cli.LevelDebug1, "verify: matched allowed signers entry",
			"line", ent.Line, "principal", ent.Principal,
			"namespace_restricted", restricted,
		)
	}
	// Only an accepted entry can validate an inferred namespace.
	if opts.Namespace == "" && !opts.NoNamespace {
		switch {
		case ent == nil:
			res.Designation = "invalid"
		case restricted:
			res.Designation = "valid"
		default:
			res.Designation = "invalid"
			errs = append(errs, fmt.Errorf(
				"signature namespace %q was left unverified: no namespace was requested "+
					"and no matching allowed signers entry restricts one "+
					"(use -n, -N or namespaces=)",
				sig.Namespace,
			))
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
		// Report the requested identity, not the entry's pattern-list.
		res.Authentication = "valid"
	}

	if err := sshsig.SignatureVerify(opts.VerifyFile, sig); err == nil {
		res.Verification = "valid"
	} else {
		res.Verification = "invalid"
		errs = append(errs, err)
	}
	cli.Debug(opts.Log, cli.LevelDebug1, "verify: verified",
		"authentication", res.Authentication,
		"designation", res.Designation,
		"verification", res.Verification,
	)

	return &res, errs
}
