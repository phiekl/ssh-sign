// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"pxy.se/go/ssh-sign/internal/args"
	"pxy.se/go/ssh-sign/internal/helper"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/flow"
)

type CheckCommand struct {
	commandOpts flow.CheckOpts

	signatureFile string
	timestamp     string
	verifyFile    string
}

func (c *CheckCommand) Run(log *slog.Logger) (fmt.Stringer, []error) {
	c.commandOpts.Log = log

	if c.commandOpts.NoNamespace {
		c.commandOpts.Namespace = ""
	}

	// Report all invalid flags together.
	var errs []error
	if c.timestamp != "" {
		ts, err := helper.ParseTimestamp(c.timestamp)
		if err != nil {
			errs = append(errs, cli.MarkUsage(
				fmt.Errorf("invalid timestamp %q: %w", c.timestamp, err),
			))
		} else {
			c.commandOpts.Timestamp = ts
		}
	}
	if err := flow.CheckAuthKey(
		c.commandOpts.AuthKey, c.commandOpts.NoAuthKey,
	); err != nil {
		errs = append(errs, cli.MarkUsage(err))
	}
	if err := flow.CheckNamespace(
		c.commandOpts.Namespace, c.commandOpts.NoNamespace,
	); err != nil {
		errs = append(errs, cli.MarkUsage(err))
	}
	if len(errs) > 0 {
		return nil, errs
	}

	if c.signatureFile == "" {
		c.commandOpts.SignatureFile = &signatureStdinReader{source: os.Stdin}
	} else {
		f, err := os.Open(c.signatureFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open signature file %q: %w",
					c.signatureFile, helper.UnwrapPathError(err),
				),
			}
		}
		defer func() { _ = f.Close() }()
		c.commandOpts.SignatureFile = f
	}

	f, err := os.Open(c.verifyFile)
	if err != nil {
		return nil, []error{
			fmt.Errorf("failed to open verify file %q: %w",
				c.verifyFile, helper.UnwrapPathError(err),
			),
		}
	}
	defer func() { _ = f.Close() }()
	c.commandOpts.VerifyFile = f
	debugInput(log, "signature", c.signatureFile)
	debugInput(log, "verify", c.verifyFile)

	if err := restrict(log); err != nil {
		return nil, []error{err}
	}
	return flow.Check(&c.commandOpts)
}

func (c *CheckCommand) Flags(s *args.Set) {
	s.String(
		&c.verifyFile,
		"verify-file", "f", "",
		"read data to verify from file (required)",
	)
	s.Required("verify-file")
	s.DenyEmpty("verify-file")

	s.String(
		&c.signatureFile,
		"signature-file", "s", "",
		"read signature from file instead of stdin",
	)
	s.DenyEmpty("signature-file")

	s.String(
		&c.commandOpts.Namespace,
		"namespace", "n", "file",
		"require a signature with specified namespace",
	)
	s.Bool(
		&c.commandOpts.NoNamespace,
		"no-namespace", "N",
		"accept a signature with any namespace",
	)
	s.MutuallyExclusive("namespace", "no-namespace")

	s.String(
		&c.commandOpts.AuthKey,
		"auth-key", "k", "",
		"require a signature created by specified public key",
	)
	s.Bool(
		&c.commandOpts.NoAuthKey,
		"no-auth-key", "K",
		"accept a signature created by any public key",
	)
	s.MutuallyExclusive("auth-key", "no-auth-key")

	s.String(
		&c.timestamp,
		"timestamp", "t", "",
		"validate this RFC3339/RFC1123 timestamp rather than current time",
	)
	s.DenyEmpty("timestamp")
}
