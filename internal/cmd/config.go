// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"log/slog"

	"pxy.se/go/ssh-sign/internal/config"
	"pxy.se/go/ssh-sign/pkg/cli"
)

// loadConfig reads the config before restrict blocks filesystem access.
// If there is no home or config directory, it returns an empty config.
func loadConfig(log *slog.Logger) (*config.Config, error) {
	dir, err := config.Dir()
	if err != nil {
		cli.Debug(log, cli.LevelDebug2, "config: no directory", "error", err)
		return &config.Config{}, nil
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	if cfg.Path == "" {
		cli.Debug(log, cli.LevelDebug2, "config: none", "dir", dir)
	} else {
		cli.Debug(log, cli.LevelDebug2, "config: read", "path", cfg.Path)
	}
	return cfg, nil
}
