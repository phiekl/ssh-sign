// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"context"
	"log/slog"
)

// Debug levels match the CLI's -v flags.
const (
	levelDebug1 = slog.LevelDebug
	levelDebug2 = slog.LevelDebug - 4
	levelDebug3 = slog.LevelDebug - 8
)

// debug logs at level if log is non-nil.
func debug(log *slog.Logger, level slog.Level, msg string, args ...any) {
	if log == nil {
		return
	}
	log.Log(context.Background(), level, msg, args...)
}
