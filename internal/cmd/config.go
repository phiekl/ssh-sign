// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/internal/config"
	"pxy.se/go/ssh-sign/internal/helper"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/flow"
	"pxy.se/go/ssh-sign/pkg/sshsig"
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

// mayBeAlias reports whether resolving ref needs the config: it is not a
// public key, but is a valid alias name.
func mayBeAlias(ref string) bool {
	_, err := sshsig.ParsePublicKeyLine(ref)
	return err != nil && config.ValidAliasName(ref)
}

// resolveKeyReference parses ref as a public key, or looks it up as an alias.
// It returns the alias name when one was used.
func resolveKeyReference(cfg *config.Config, ref string) (ssh.PublicKey, string, error) {
	pk, err := sshsig.ParsePublicKeyLine(ref)
	if err == nil || !config.ValidAliasName(ref) {
		return pk, "", err
	}
	line, ok := cfg.Aliases[ref]
	if !ok {
		return nil, "", fmt.Errorf("%q is neither a public key (%w) nor an alias in config", ref, err)
	}
	pk, err = sshsig.ParsePublicKeyLine(line)
	if err != nil {
		return nil, "", fmt.Errorf("alias %q: %w", ref, err)
	}
	return pk, ref, nil
}

// defaultSignersFiles returns the files that stand in for a missing
// --allowed-signers-file.
func defaultSignersFiles(log *slog.Logger) ([]string, error) {
	dir, err := config.Dir()
	if err != nil {
		cli.Debug(log, cli.LevelDebug2, "config: no directory", "error", err)
		return nil, cli.MarkUsage(fmt.Errorf(
			"missing allowed signers: use -a or set %s (%w)", config.DirEnv, err,
		))
	}
	paths, err := config.SignersFiles(dir)
	if err != nil {
		return nil, err
	}
	if paths == nil {
		signers := filepath.Join(dir, config.SignersDirName)
		return nil, cli.MarkUsage(fmt.Errorf(
			"missing allowed signers: use -a or add *.conf files to %q", signers,
		))
	}
	return paths, nil
}

// maxSignersSize bounds the signers files held in memory until parsing.
const maxSignersSize = 64 << 20

// readSignersFiles reads the files one at a time, so that they need not stay
// open until parsing after restrict. Together they may hold at most limit bytes.
func readSignersFiles(log *slog.Logger, paths []string, limit int64) ([]flow.NamedReader, error) {
	var files []flow.NamedReader
	remaining := limit
	for _, path := range paths {
		debugInput(log, "allowed signers", path)
		data, err := readSignersFile(path, remaining)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > remaining {
			return nil, fmt.Errorf(
				"signers files exceed %d bytes in total at %q", limit, path,
			)
		}
		remaining -= int64(len(data))
		files = append(files, flow.NamedReader{Name: path, Reader: bytes.NewReader(data)})
	}
	return files, nil
}

// readSignersFile reads at most one byte beyond limit.
func readSignersFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowed signers file %q: %w",
			path, helper.UnwrapPathError(err),
		)
	}
	defer func() { _ = f.Close() }()
	if err := config.CheckOpenFile(f); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading allowed signers file %q: %w",
			path, helper.UnwrapPathError(err),
		)
	}
	return data, nil
}
