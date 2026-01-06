// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package global

import (
	"pxy.se/go/argparse"
)

type GlobalOpts struct {
	JSON        bool
	Command     argparse.Command
	CommandName string
	CommandOpts []string
}
