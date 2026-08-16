// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"

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

	if err := p.ParseCurrentArgs(); err != nil {
		die("usage", err)
	}

	commandOpts := opts.CommandOpts
	if len(commandOpts) == 0 {
		// argparse displays help before validating required flags when it gets
		// no tokens. An option terminator lets normal validation report which
		// command flags are missing instead.
		commandOpts = []string{"--"}
	}
	if err := opts.Command.Run("ssh-sign "+opts.CommandName, commandOpts); err != nil {
		die(opts.CommandName, err)
	}
	res := opts.Command.Result()

	if opts.JSON {
		out, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			die(opts.CommandName, err)
		}
		fmt.Printf("%s\n", out)
		// With JSON output, the error key should be used instead of checking rc.
		os.Exit(0)
	}

	if len(res.Error) > 0 {
		die(opts.CommandName, res.Error...)
	}
	if res.Data != nil {
		fmt.Printf("%s\n", res.Data)
	}
	os.Exit(0)

}

func die(prefix string, errs ...error) {
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", prefix, err)
	}
	os.Exit(1)
}
