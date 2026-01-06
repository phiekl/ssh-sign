// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"os"

	"pxy.se/go/argparse"
	"pxy.se/go/ssh-sign/internal/global"
	"pxy.se/go/ssh-sign/internal/helper"
	"pxy.se/go/ssh-sign/pkg/flow"
)

type InspectCommand struct {
	argparse.BaseCommand
	GlobalOpts  *global.GlobalOpts
	commandOpts flow.InspectOpts

	signatureFile string
}

func (c *InspectCommand) Command() (any, []error) {
	if c.signatureFile == "" {
		c.commandOpts.SignatureFile = os.Stdin
	} else {
		f, err := os.Open(c.signatureFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open signature file %q: %v",
					c.signatureFile, helper.MarshalOSError(err),
				),
			}
		}
		defer func() { _ = f.Close() }()
		c.commandOpts.SignatureFile = f
	}
	return flow.Inspect(&c.commandOpts)
}

func (c *InspectCommand) Args() {
	c.ArgP.StringVarP(
		&c.signatureFile,
		"signature-file", "s", "",
		"read signature from file instead of stdin",
	)
	c.ArgP.StringDenyEmpty(&c.signatureFile, "signature-file")
}
