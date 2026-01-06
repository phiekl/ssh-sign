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

type VerifyCommand struct {
	argparse.BaseCommand
	GlobalOpts  *global.GlobalOpts
	commandOpts flow.VerifyOpts

	allowedSignersFile string
	signatureFile      string
	timestamp          string
	verifyFile         string
}

func (c *VerifyCommand) Command() (any, []error) {
	allowedSignersFile, err := os.Open(c.allowedSignersFile)
	if err != nil {
		return nil, []error{
			fmt.Errorf("failed to open allowed signers file %q: %v",
				c.allowedSignersFile, helper.MarshalOSError(err),
			),
		}
	}
	defer func() { _ = allowedSignersFile.Close() }()
	c.commandOpts.AllowedSignersFile = allowedSignersFile

	if c.signatureFile == "" {
		c.commandOpts.SignatureFile = os.Stdin
	} else {
		signatureFile, err := os.Open(c.signatureFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open signature file %q: %v",
					c.signatureFile, helper.MarshalOSError(err),
				),
			}
		}
		defer func() { _ = signatureFile.Close() }()
		c.commandOpts.SignatureFile = signatureFile
	}

	verifyFile, err := os.Open(c.verifyFile)
	if err != nil {
		return nil, []error{
			fmt.Errorf("failed to open verify file %q: %v",
				c.verifyFile, helper.MarshalOSError(err),
			),
		}
	}
	defer func() { _ = verifyFile.Close() }()
	c.commandOpts.VerifyFile = verifyFile

	if c.timestamp != "" {
		ts, err := helper.ParseTimestamp(c.timestamp)
		if err != nil {
			return nil, []error{
				fmt.Errorf("invalid timestamp %q: %v", c.timestamp, err),
			}
		}
		c.commandOpts.Timestamp = ts
	}

	return flow.Verify(&c.commandOpts)
}

func (c *VerifyCommand) Args() {
	c.ArgP.StringVarP(
		&c.allowedSignersFile,
		"allowed-signers-file", "a", "",
		"read allowed signers, with options, from file (required)",
	)
	c.ArgP.Required("allowed-signers-file")
	c.ArgP.StringDenyEmpty(&c.allowedSignersFile, "allowed-signers-file")

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
		&c.commandOpts.Principal,
		"principal", "p", "",
		"allow this signer (email usually) from allowed signers file",
	)
	c.ArgP.StringDenyEmpty(&c.signatureFile, "principal")

	c.ArgP.StringVarP(
		&c.timestamp,
		"timestamp", "t", "",
		"validate this RFC3339/RFC1123 timestamp rather than current time",
	)
	c.ArgP.StringDenyEmpty(&c.signatureFile, "timestamp")
}
