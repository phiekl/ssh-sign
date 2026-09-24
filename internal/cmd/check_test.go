// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"testing"

	"pxy.se/go/ssh-sign/internal/args"
)

func TestCheckRejectsExplicitlyEmptySignatureFile(t *testing.T) {
	command := CheckCommand{}
	s := args.NewSet("ssh-sign check")
	command.Flags(s)

	err := s.Parse([]string{"-f", "data", "-s", "", "-K", "-N"})
	if err == nil {
		t.Fatal("Parse() unexpectedly accepted an empty signature file")
	}
	want := "flag/argument is empty: signature-file"
	if err.Error() != want {
		t.Errorf("Parse() error = %q, want %q", err, want)
	}
}
