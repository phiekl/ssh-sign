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

type VerifyCommand struct {
	commandOpts flow.VerifyOpts

	allowedSignersFile string
	signatureFile      string
	timestamp          string
	verifyFile         string
}

func (c *VerifyCommand) Run(log *slog.Logger) (fmt.Stringer, []error) {
	c.commandOpts.Log = log

	if c.timestamp != "" {
		ts, err := helper.ParseTimestamp(c.timestamp)
		if err != nil {
			return nil, []error{
				cli.MarkUsage(fmt.Errorf("invalid timestamp %q: %w", c.timestamp, err)),
			}
		}
		c.commandOpts.Timestamp = ts
	}

	allowedSignersFile, err := os.Open(c.allowedSignersFile)
	if err != nil {
		return nil, []error{
			fmt.Errorf("failed to open allowed signers file %q: %w",
				c.allowedSignersFile, helper.UnwrapPathError(err),
			),
		}
	}
	defer func() { _ = allowedSignersFile.Close() }()
	c.commandOpts.AllowedSignersFile = allowedSignersFile

	if c.signatureFile == "" {
		c.commandOpts.SignatureFile = &signatureStdinReader{source: os.Stdin}
	} else {
		signatureFile, err := os.Open(c.signatureFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open signature file %q: %w",
					c.signatureFile, helper.UnwrapPathError(err),
				),
			}
		}
		defer func() { _ = signatureFile.Close() }()
		c.commandOpts.SignatureFile = signatureFile
	}

	verifyFile, err := os.Open(c.verifyFile)
	if err != nil {
		return nil, []error{
			fmt.Errorf("failed to open verify file %q: %w",
				c.verifyFile, helper.UnwrapPathError(err),
			),
		}
	}
	defer func() { _ = verifyFile.Close() }()
	c.commandOpts.VerifyFile = verifyFile
	debugInput(log, "allowed signers", c.allowedSignersFile)
	debugInput(log, "signature", c.signatureFile)
	debugInput(log, "verify", c.verifyFile)

	if err := restrict(log); err != nil {
		return nil, []error{err}
	}
	return flow.Verify(&c.commandOpts)
}

func (c *VerifyCommand) Flags(s *args.Set) {
	s.String(
		&c.allowedSignersFile,
		"allowed-signers-file", "a", "",
		"read allowed signers, with options, from file (required)",
	)
	s.Required("allowed-signers-file")
	s.DenyEmpty("allowed-signers-file")

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
		"namespace", "n", "",
		"require a signature with specified namespace",
	)
	s.Bool(
		&c.commandOpts.NoNamespace,
		"no-namespace", "N",
		"ignore the signature namespace and allowed signers namespace restrictions",
	)
	s.MutuallyExclusive("namespace", "no-namespace")

	s.String(
		&c.commandOpts.Principal,
		"principal", "p", "",
		"allow this signer (email usually) from allowed signers file",
	)
	s.DenyEmpty("principal")

	s.String(
		&c.timestamp,
		"timestamp", "t", "",
		"validate this RFC3339/RFC1123 timestamp rather than current time",
	)
	s.DenyEmpty("timestamp")
}
