// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"testing"

	"pxy.se/go/argparse"
)

func TestCheckRejectsExplicitlyEmptySignatureFile(t *testing.T) {
	command := CheckCommand{}
	command.ArgP = argparse.NewArgParser("ssh-sign check")
	command.Args()

	err := command.ArgP.ParseArgs([]string{"-f", "data", "-s", "", "-K", "-N"})
	if err == nil {
		t.Fatal("ParseArgs() unexpectedly accepted an empty signature file")
	}
	want := "flag/argument is empty: signature-file"
	if err.Error() != want {
		t.Errorf("ParseArgs() error = %q, want %q", err, want)
	}
}
