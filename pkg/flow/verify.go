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

// VerifyOpts configures Verify. AllowedSignersFile, SignatureFile and
// VerifyFile are required.
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

// VerifyResult holds the results of Verify.
type VerifyResult struct {
	Authentication string `json:"authentication"`
	Designation    string `json:"designation"`
	Namespace      string `json:"namespace"`
	Principal      string `json:"principal"`
	Verification   string `json:"verification"`
}

func (r VerifyResult) String() string {
	return cli.ResultFormatKV(-15, " ", "= ",
		cli.KV("principal", r.Principal),
		cli.KV("authentication", r.Authentication),
		cli.KV("namespace", r.Namespace),
		cli.KV("designation", r.Designation),
		cli.KV("verification", r.Verification),
	)
}

// Verify checks a signature against an allowed signers file.
// It reports all independent failures and may return a result with errors.
func Verify(opts *VerifyOpts) (*VerifyResult, []error) {
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

	parsed, err := parseAllowedSigners(opts.Log, opts.AllowedSignersFile)
	if err != nil {
		return nil, []error{err}
	}

	sig, err := sshsig.SignatureRead(opts.SignatureFile)
	if err != nil {
		return nil, []error{err}
	}
	debugSignature(opts.Log, "verify", sig)

	// Run every check rather than stopping at the first failure.
	res := VerifyResult{Namespace: sig.Namespace}
	var errs []error

	ent, restricted, matchErr := matchSigner(opts, parsed, sig, timestamp)

	res.Designation, err = resolveDesignation(opts, sig, ent, restricted, matchErr)
	if err != nil {
		errs = append(errs, err)
	}

	res.Authentication, res.Principal, err = resolveAuthentication(opts, ent, matchErr)
	if err != nil {
		errs = append(errs, err)
	}

	// Enforce the certificate's own validity window too.
	if err := sshsig.CertificateValidAt(sig.PublicKey, timestamp); err != nil {
		res.Authentication = "invalid"
		errs = append(errs, fmt.Errorf("signature %w", err))
	}

	switch err := sshsig.SignatureVerify(opts.VerifyFile, sig); {
	case err == nil:
		res.Verification = "valid"
	case sshsig.IsReadError(err):
		// A read failure leaves verification undecided.
		return nil, append(errs, fmt.Errorf("failed reading data to verify: %w", err))
	default:
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

// parseAllowedSigners parses the file and logs entries and errors.
func parseAllowedSigners(log *slog.Logger, r io.Reader) (*allowedsigners.File, error) {
	parsed, err := allowedsigners.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("failed parsing allowed signers file: %w", err)
	}
	cli.Debug(log, cli.LevelDebug2, "verify: parsed allowed signers",
		"entries", len(parsed.Entries), "skipped", parsed.SkippedCount,
	)
	for i := range parsed.Skipped {
		cli.Debug(log, cli.LevelDebug1, "verify: skipped allowed signers line",
			"line", parsed.Skipped[i].Line, "reason", parsed.Skipped[i].Msg,
		)
	}
	for i := range parsed.Entries {
		cli.Debug(log, cli.LevelDebug3, "verify: allowed signers entry",
			entryAttr("entry", &parsed.Entries[i]),
		)
	}
	return parsed, nil
}

// matchSigner finds an entry matching the key and requested policy.
// restricted reports whether the selected entry limits namespaces.
func matchSigner(
	opts *VerifyOpts, parsed *allowedsigners.File,
	sig *sshsig.Signature, timestamp time.Time,
) (ent *allowedsigners.Entry, restricted bool, err error) {
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
	return ent, restricted, err
}

// resolveDesignation checks the namespace against the options and matched entry.
func resolveDesignation(
	opts *VerifyOpts, sig *sshsig.Signature,
	ent *allowedsigners.Entry, restricted bool, matchErr error,
) (string, error) {
	switch {
	case opts.NoNamespace:
		return "disabled", nil
	case opts.Namespace == "":
		// Only an accepted entry can validate an inferred namespace.
		switch {
		case ent == nil:
			// Authentication reports why nothing matched.
			return "invalid", nil
		case restricted:
			return "valid", nil
		}
		// The matched entry provides no namespace restriction.
		return "invalid", fmt.Errorf(
			"signature namespace %q was left unverified: no namespace was requested "+
				"and no matching allowed signers entry restricts one "+
				"(use -n, -N or namespaces=)",
			sig.Namespace,
		)
	case opts.Namespace != sig.Namespace:
		return "invalid", fmt.Errorf(
			"signature contains namespace %q (expected %q)", sig.Namespace, opts.Namespace,
		)
	}
	// An explicit namespace must also satisfy allowed signers.
	if checked, matched := allowedsigners.NamespaceConstraintResult(matchErr); checked && !matched {
		return "invalid", nil
	}
	return "valid", nil
}

// resolveAuthentication returns the signer's authentication status and identity.
func resolveAuthentication(
	opts *VerifyOpts, ent *allowedsigners.Entry, matchErr error,
) (status, principal string, err error) {
	switch {
	case matchErr != nil && opts.Principal == "":
		return "invalid", opts.Principal, fmt.Errorf(
			"signer public key found in allowed signers, but failed constraints: %w", matchErr,
		)
	case matchErr != nil:
		return "invalid", opts.Principal, fmt.Errorf(
			"principal %q found in allowed signers, but failed constraints: %w",
			opts.Principal, matchErr,
		)
	case ent == nil && opts.Principal == "":
		return "invalid", opts.Principal, fmt.Errorf(
			"signer public key not found within allowed signers",
		)
	case ent == nil:
		return "invalid", opts.Principal, fmt.Errorf(
			"principal %q not found within allowed signers", opts.Principal,
		)
	case opts.Principal == "":
		// No principal was requested, so the entry's pattern-list is the most
		// specific identity available.
		return "disabled", ent.Principal, nil
	}
	// Report the requested identity, not the entry's pattern-list.
	return "valid", opts.Principal, nil
}
