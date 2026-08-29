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
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/flow"
)

type SignCommand struct {
	argparse.BaseCommand
	GlobalOpts  *global.GlobalOpts
	commandOpts flow.SignOpts

	dataFile string
}

func (c *SignCommand) Command() (any, []error) {
	log := commandLog(c.GlobalOpts)
	c.commandOpts.Log = log

	if err := flow.CheckSignKey(c.commandOpts.SignKey); err != nil {
		return nil, []error{cli.MarkUsage(err)}
	}

	if c.dataFile == "" {
		c.commandOpts.DataFile = os.Stdin
	} else {
		f, err := os.Open(c.dataFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open data file %q: %v",
					c.dataFile, helper.MarshalOSError(err),
				),
			}
		}
		defer func() { _ = f.Close() }()
		c.commandOpts.DataFile = f
	}
	debugInput(log, "data", c.dataFile)

	return flow.Sign(&c.commandOpts)
}

func (c *SignCommand) Args() {
	c.ArgP.StringVarP(
		&c.dataFile,
		"data-file", "f", "",
		"read data to sign from file instead of stdin",
	)
	c.ArgP.StringDenyEmpty(&c.dataFile, "data-file")

	c.ArgP.StringVarP(
		&c.commandOpts.Namespace,
		"namespace", "n", "file",
		"create signature with specified namespace",
	)
	c.ArgP.StringDenyEmpty(&c.commandOpts.Namespace, "namespace")

	c.ArgP.StringVarP(
		&c.commandOpts.SignKey,
		"sign-key", "k", "",
		"create signature using this pubkey reference (must exist in ssh-agent)",
	)
	c.ArgP.Required("sign-key")
	c.ArgP.StringDenyEmpty(&c.commandOpts.SignKey, "sign-key")
}
