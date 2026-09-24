// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"log/slog"

	"pxy.se/go/ssh-sign/internal/args"
)

// Command defines a subcommand's flags and execution.
type Command interface {
	Flags(s *args.Set)
	Run(log *slog.Logger) (fmt.Stringer, []error)
}
