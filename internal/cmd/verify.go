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
	revokedKeysFile    string
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

	if c.allowedSignersFile == "" {
		paths, err := defaultSignersFiles(log)
		if err != nil {
			return nil, []error{err}
		}
		c.commandOpts.AllowedSignersFiles, err = readConfigFiles(log, signersKind, paths, maxSignersSize)
		if err != nil {
			return nil, []error{err}
		}
	} else {
		file, closeFile, err := openNamedConfigFile(signersKind, c.allowedSignersFile)
		if err != nil {
			return nil, []error{err}
		}
		defer closeFile()
		c.commandOpts.AllowedSignersFiles = []flow.NamedReader{file}
	}

	paths, err := defaultRevokedFiles(log)
	if err != nil {
		return nil, []error{err}
	}
	c.commandOpts.RevokedKeysFiles, err = readConfigFiles(log, revokedKind, paths, maxDefaultRevokedFilesSize)
	if err != nil {
		return nil, []error{err}
	}
	if c.revokedKeysFile != "" {
		file, closeFile, err := openNamedConfigFile(revokedKind, c.revokedKeysFile)
		if err != nil {
			return nil, []error{err}
		}
		defer closeFile()
		c.commandOpts.RevokedKeysFiles = append(c.commandOpts.RevokedKeysFiles, file)
	}

	c.signatureFile = signatureFileOrDefault(c.signatureFile, c.verifyFile)
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
	if c.allowedSignersFile != "" {
		debugInput(log, "allowed signers", c.allowedSignersFile)
	}
	if c.revokedKeysFile != "" {
		debugInput(log, "revoked keys", c.revokedKeysFile)
	}
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
		"read allowed signers, with options, from file",
	)
	s.DenyEmpty("allowed-signers-file")

	s.String(
		&c.revokedKeysFile,
		"revoked-keys-file", "r", "",
		"reject signers whose public key or CA is listed in file",
	)
	s.DenyEmpty("revoked-keys-file")

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
		"read signature from file (default stdin, or <verify-file>.sig when stdin=tty)",
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
