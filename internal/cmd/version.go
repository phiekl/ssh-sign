// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"log/slog"
	"runtime/debug"

	"pxy.se/go/ssh-sign/internal/args"
)

// version is set by make from git describe.
var version string

type VersionCommand struct{}

type versionResult struct {
	Version string `json:"version"`
}

func (r versionResult) String() string {
	return r.Version
}

func (c *VersionCommand) Run(log *slog.Logger) (fmt.Stringer, []error) {
	info, ok := debug.ReadBuildInfo()
	return &versionResult{Version: resolveVersion(version, info, ok)}, nil
}

func (c *VersionCommand) Flags(s *args.Set) {}

// resolveVersion falls back to the module version Go embeds from VCS data.
func resolveVersion(set string, info *debug.BuildInfo, ok bool) string {
	if set != "" {
		return set
	}
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "unknown"
}
