// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"log/slog"
	"testing"

	"pxy.se/go/ssh-sign/pkg/cli"
)

// Keep the package-local levels aligned with CLI verbosity.
func TestDebugLevelsMirrorTheCLI(t *testing.T) {
	for name, tt := range map[string]struct{ got, want slog.Level }{
		"debug1": {got: levelDebug1, want: cli.LevelDebug1},
		"debug2": {got: levelDebug2, want: cli.LevelDebug2},
		"debug3": {got: levelDebug3, want: cli.LevelDebug3},
	} {
		t.Run(name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("level = %v, want %v", tt.got, tt.want)
			}
		})
	}
}
