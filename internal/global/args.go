// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package global

import (
	"log/slog"

	"pxy.se/go/argparse"
)

type GlobalOpts struct {
	JSON        bool
	Verbose     int
	Log         *slog.Logger
	Command     argparse.Command
	CommandName string
	CommandOpts []string
}
