// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"log/slog"

	"pxy.se/go/ssh-sign/internal/landlock"
)

// restrict must run after opening every command input.
func restrict(log *slog.Logger) error {
	if err := landlock.Restrict(log); err != nil {
		return fmt.Errorf("failed enabling landlock: %w", err)
	}
	return nil
}
