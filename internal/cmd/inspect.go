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
	"pxy.se/go/ssh-sign/pkg/flow"
)

type InspectCommand struct {
	commandOpts flow.InspectOpts

	signatureFile string
}

func (c *InspectCommand) Run(log *slog.Logger) (fmt.Stringer, []error) {
	c.commandOpts.Log = log

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
	debugInput(log, "signature", c.signatureFile)

	if err := restrict(log); err != nil {
		return nil, []error{err}
	}
	res, err := flow.Inspect(&c.commandOpts)
	if err != nil {
		return nil, []error{err}
	}
	return res, nil
}

func (c *InspectCommand) Flags(s *args.Set) {
	s.String(
		&c.signatureFile,
		"signature-file", "s", "",
		"read signature from file instead of stdin",
	)
	s.DenyEmpty("signature-file")
}
