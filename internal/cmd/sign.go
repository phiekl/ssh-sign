// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/internal/args"
	"pxy.se/go/ssh-sign/internal/config"
	"pxy.se/go/ssh-sign/internal/helper"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/flow"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

type SignCommand struct {
	commandOpts flow.SignOpts

	dataFile string
	signKey  string
}

func (c *SignCommand) Run(log *slog.Logger) (fmt.Stringer, []error) {
	c.commandOpts.Log = log

	// Like check, read the config only when it is needed.
	var err error
	cfg := &config.Config{}
	if c.signKey == "" || mayBeAlias(c.signKey) {
		if cfg, err = loadConfig(log); err != nil {
			return nil, []error{err}
		}
	}

	var pk ssh.PublicKey
	var alias string
	switch {
	case c.signKey != "":
		pk, alias, err = resolveKeyReference(cfg, c.signKey)
		if err != nil {
			return nil, []error{cli.MarkUsage(fmt.Errorf("invalid signing key: %w", err))}
		}
	case cfg.SignKey != "":
		pk, alias, err = resolveKeyReference(cfg, cfg.SignKey)
		if err != nil {
			return nil, []error{fmt.Errorf("invalid sign.key in config file %q: %w", cfg.Path, err)}
		}
	default:
		return nil, []error{cli.MarkUsage(errors.New("missing required flag: sign-key"))}
	}
	if alias != "" {
		cli.Debug(log, cli.LevelDebug1, "sign: resolved alias", "alias", alias)
	}

	if c.dataFile == "" {
		c.commandOpts.DataFile = os.Stdin
	} else {
		f, err := os.Open(c.dataFile)
		if err != nil {
			return nil, []error{
				fmt.Errorf("failed to open data file %q: %w",
					c.dataFile, helper.UnwrapPathError(err),
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

func (c *SignCommand) Flags(s *args.Set) {
	s.String(
		&c.dataFile,
		"data-file", "f", "",
		"read data to sign from file instead of stdin",
	)
	s.DenyEmpty("data-file")

	s.String(
		&c.commandOpts.Namespace,
		"namespace", "n", "file",
		"create signature with specified namespace",
	)
	s.DenyEmpty("namespace")

	s.String(
		&c.signKey,
		"sign-key", "k", "",
		"create signature using this pubkey reference or config alias",
	)
	s.DenyEmpty("sign-key")
}
