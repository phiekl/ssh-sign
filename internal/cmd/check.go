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

type CheckCommand struct {
	argparse.BaseCommand
	GlobalOpts  *global.GlobalOpts
	commandOpts flow.CheckOpts

	signatureFile string
	verifyFile    string
}

func (c *CheckCommand) Command() (any, []error) {
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

	f, err := os.Open(c.verifyFile)
	if err != nil {
		return nil, []error{
			fmt.Errorf("failed to open verify file %q: %v",
				c.verifyFile, helper.MarshalOSError(err),
			),
		}
	}
	defer func() { _ = f.Close() }()
	c.commandOpts.VerifyFile = f

	return flow.Check(&c.commandOpts)
}

func (c *CheckCommand) Args() {
	c.ArgP.StringVarP(
		&c.verifyFile,
		"verify-file", "f", "",
		"read data to verify from file (required)",
	)
	c.ArgP.Required("verify-file")
	c.ArgP.StringDenyEmpty(&c.verifyFile, "verify-file")

	c.ArgP.StringVarP(
		&c.signatureFile,
		"signature-file", "s", "",
		"read signature from file instead of stdin",
	)
	c.ArgP.StringDenyEmpty(&c.signatureFile, "signature-file")

	c.ArgP.StringVarP(
		&c.commandOpts.Namespace,
		"namespace", "n", "",
		"require a signature with specified namespace",
	)
	c.ArgP.BoolVarP(
		&c.commandOpts.NoNamespace,
		"no-namespace", "N", false,
		"accept a signature with any namespace",
	)
	c.ArgP.MutuallyExclusive("namespace", "no-namespace")

	c.ArgP.StringVarP(
		&c.commandOpts.AuthKey,
		"auth-key", "k", "",
		"require a signature created by specified public key",
	)
	c.ArgP.BoolVarP(
		&c.commandOpts.NoAuthKey,
		"no-auth-key", "K", false,
		"accept a signature created by any public key",
	)
	c.ArgP.MutuallyExclusive("auth-key", "no-auth-key")
}
