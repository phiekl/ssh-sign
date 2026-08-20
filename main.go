// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"pxy.se/go/argparse"
	"pxy.se/go/ssh-sign/internal/cmd"
	"pxy.se/go/ssh-sign/internal/global"
)

func main() {
	opts := global.GlobalOpts{}
	p := argparse.NewArgParser("ssh-sign")

	p.BoolVarP(
		&opts.JSON,
		"json", "j", false,
		"enable JSON output",
	)

	p.CommandInit(
		&opts.Command,
		&opts.CommandName,
		&opts.CommandOpts,
	)

	p.Command(
		"inspect",
		"Show signature details",
		&cmd.InspectCommand{GlobalOpts: &opts},
	)

	p.Command(
		"sign",
		"Sign data with specified public key and namespace",
		&cmd.SignCommand{GlobalOpts: &opts},
	)

	p.Command(
		"verify",
		"Verify signed data using allowed signers files",
		&cmd.VerifyCommand{GlobalOpts: &opts},
	)

	p.Command(
		"check",
		"Check signed data, with optional public key/namespace validation",
		&cmd.CheckCommand{GlobalOpts: &opts},
	)

	args := os.Args[1:]
	if len(args) == 0 {
		// argparse prints help and exits directly when it receives no arguments,
		// which prevents the caller from using the documented usage-error status.
		args = []string{"--"}
	}
	if err := p.ParseArgs(args); err != nil {
		dieUsage("usage", err)
	}

	commandOpts := opts.CommandOpts
	if len(commandOpts) == 0 {
		// argparse displays help before validating required flags when it gets
		// no tokens. An option terminator lets normal validation report which
		// command flags are missing instead.
		commandOpts = []string{"--"}
	}
	if err := opts.Command.Run("ssh-sign "+opts.CommandName, commandOpts); err != nil {
		if commandRunInternalError(err) {
			die(opts.CommandName, err)
		}
		dieUsage(opts.CommandName, err)
	}
	res := opts.Command.Result()

	if opts.JSON {
		out, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			die(opts.CommandName, err)
		}
		if _, err := fmt.Printf("%s\n", out); err != nil {
			die(opts.CommandName, fmt.Errorf("failed writing output: %v", err))
		}
		// With JSON output, the error key should be used instead of checking rc.
		os.Exit(0)
	}

	if len(res.Error) > 0 {
		die(opts.CommandName, res.Error...)
	}
	if res.Data != nil {
		if _, err := fmt.Printf("%s\n", res.Data); err != nil {
			die(opts.CommandName, fmt.Errorf("failed writing output: %v", err))
		}
	}
	os.Exit(0)

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
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", prefix, err)
	}
}

func commandRunInternalError(err error) bool {
	return err.Error() == "command implementation not set" ||
		strings.HasPrefix(err.Error(), "command result capture:")
}
