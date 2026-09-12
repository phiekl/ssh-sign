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
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type SignCommand struct {
	argparse.BaseCommand
	GlobalOpts  *global.GlobalOpts
	commandOpts flow.SignOpts

	dataFile string
	signKey  string
}

func (c *SignCommand) Command() (any, []error) {
	log := commandLog(c.GlobalOpts)
	c.commandOpts.Log = log

	pk, err := sshsig.ParsePublicKeyLine(c.signKey)
	if err != nil {
		return nil, []error{cli.MarkUsage(fmt.Errorf("invalid signing key: %w", err))}
	}

	if c.dataFile == "" {
		c.commandOpts.DataFile = os.Stdin
	} else {
		f, err := os.Open(c.dataFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open data file %q: %w",
					c.dataFile, helper.MarshalOSError(err),
				),
			}
		}
		defer func() { _ = f.Close() }()
		c.commandOpts.DataFile = f
	}
	debugInput(log, "data", c.dataFile)

	// Connect to the agent before restricting pathname access. A failure to
	// hand back the socket after signing does not invalidate the signature.
	conn, agent, err := sshsig.ConnectAgent(log)
	if err != nil {
		return nil, []error{fmt.Errorf("failed agent connection: %w", err)}
	}
	defer func() { _ = conn.Close() }()

	if err := restrict(log); err != nil {
		return nil, []error{err}
	}

	signer, err := sshsig.AgentSigner(log, conn, agent, pk)
	if err != nil {
		return nil, []error{fmt.Errorf("agent: %w", err)}
	}
	c.commandOpts.Signer = signer

	res, err := flow.Sign(&c.commandOpts)
	if err != nil {
		return nil, []error{err}
	}
	return res, nil
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
		&c.signKey,
		"sign-key", "k", "",
		"create signature using this pubkey reference (must exist in ssh-agent)",
	)
	c.ArgP.Required("sign-key")
	c.ArgP.StringDenyEmpty(&c.signKey, "sign-key")
}
