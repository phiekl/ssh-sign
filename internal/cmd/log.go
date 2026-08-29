// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"log/slog"

	"pxy.se/go/ssh-sign/internal/global"
	"pxy.se/go/ssh-sign/pkg/cli"
)

// commandLog returns the global logger, or nil.
func commandLog(opts *global.GlobalOpts) *slog.Logger {
	if opts == nil {
		return nil
	}
	return opts.Log
}

// debugInput reports an input's source. An empty path means stdin.
func debugInput(log *slog.Logger, role, path string) {
	if path == "" {
		cli.Debug(log, cli.LevelDebug2, "reading input", "role", role, "source", "stdin")
		return
	}
	cli.Debug(log, cli.LevelDebug2, "reading input", "role", role, "path", path)
}
