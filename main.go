// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"pxy.se/go/ssh-sign/internal/args"
	"pxy.se/go/ssh-sign/internal/cmd"
	"pxy.se/go/ssh-sign/pkg/cli"
)

var commands = []struct {
	name, description string
	command           cmd.Command
}{
	{"inspect", "Show signature details", &cmd.InspectCommand{}},
	{"sign", "Sign data with specified public key and namespace", &cmd.SignCommand{}},
	{"verify", "Verify signed data using allowed signers files", &cmd.VerifyCommand{}},
	{"check", "Check signed data, with optional public key/namespace validation", &cmd.CheckCommand{}},
	{"version", "Show version", &cmd.VersionCommand{}},
}

func main() {
	root := args.NewSet("ssh-sign")
	for _, c := range commands {
		root.Command(c.name, c.description)
	}
	name, argv, err := root.ParseCommand(os.Args[1:])
	if err != nil {
		exitOnHelpOrUsage(root, err)
		dieUsage("usage", err)
	}

	var command cmd.Command
	for _, c := range commands {
		if c.name == name {
			command = c.command
			break
		}
	}
	flags := args.NewSet("ssh-sign " + name)
	command.Flags(flags)
	var jsonOutput bool
	var verbose int
	flags.Bool(&jsonOutput, "json", "j", "enable JSON output")
	flags.Count(&verbose, "verbose", "v", "write debug output to stderr, repeatable up to -vvv")
	if err := flags.Parse(argv); err != nil {
		exitOnHelpOrUsage(flags, err)
		dieUsage(name, err)
	}

	log := cli.NewLogger(os.Stderr, verbose)
	cli.Debug(log, cli.LevelDebug1, "running command", "command", name, "json", jsonOutput)

	res := cli.NewResult(command.Run(log))
	for _, err := range res.Error {
		if cli.IsUsageError(err) {
			dieUsage(name, res.Error...)
		}
	}

	if jsonOutput {
		out, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			die(name, err)
		}
		out = cli.EscapeJSONControls(out)
		if err := writeOutput(os.Stdout, string(out)); err != nil {
			die(name, fmt.Errorf("failed writing output: %w", err))
		}
		if len(res.Error) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if len(res.Error) > 0 {
		die(name, res.Error...)
	}
	if res.Data != nil {
		if err := writeOutput(os.Stdout, res.Data.String()); err != nil {
			die(name, fmt.Errorf("failed writing output: %w", err))
		}
	}
	os.Exit(0)
}

// exitOnHelpOrUsage writes help to stdout for -h/--help and exits 0, or to
// stderr when arguments are missing and exits 2. Other errors return.
func exitOnHelpOrUsage(s *args.Set, err error) {
	switch err {
	case args.ErrHelp:
		if err := writeText(os.Stdout, s.Help()); err != nil {
			die("usage", fmt.Errorf("failed writing help: %w", err))
		}
		os.Exit(0)
	case args.ErrUsage:
		// Stderr may already be unavailable; keep the usage exit status.
		_ = writeText(os.Stderr, s.Help())
		os.Exit(2)
	}
}

func writeOutput(w io.Writer, value string) error {
	return writeText(w, value+"\n")
}

func writeText(w io.Writer, output string) error {
	n, err := io.WriteString(w, output)
	if err != nil {
		return err
	}
	if n != len(output) {
		return io.ErrShortWrite
	}
	return nil
}

func die(prefix string, errs ...error) {
	reportErrors(prefix, errs...)
	os.Exit(1)
}

func dieUsage(prefix string, errs ...error) {
	reportErrors(prefix, errs...)
	os.Exit(2)
}

func reportErrors(prefix string, errs ...error) {
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "error: %s: %s\n", prefix, cli.EscapeControl(err.Error()))
	}
}
