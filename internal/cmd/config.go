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

// defaultRevokedFiles returns the configured revocation lists.
func defaultRevokedFiles(log *slog.Logger) ([]string, error) {
	dir, err := config.Dir()
	if err != nil {
		cli.Debug(log, cli.LevelDebug2, "config: no directory", "error", err)
		return nil, nil
	}
	return config.RevokedFiles(dir)
}

// maxSignersSize bounds the signers files held in memory until parsing.
const maxSignersSize = 64 << 20

// maxDefaultRevokedFilesSize bounds the combined size of the files preloaded
// from the config directory.
const maxDefaultRevokedFilesSize = 64 << 20

// fileKind names a kind of config file in messages.
type fileKind struct {
	file, files string
}

var (
	signersKind = fileKind{file: "allowed signers", files: "signers"}
	revokedKind = fileKind{file: "revoked keys", files: "revoked keys"}
)

// readConfigFiles reads the files one at a time, so that they need not stay
// open until parsing after restrict. Together they may hold at most limit bytes.
func readConfigFiles(
	log *slog.Logger, kind fileKind, paths []string, limit int64,
) ([]flow.NamedReader, error) {
	var files []flow.NamedReader
	remaining := limit
	for _, path := range paths {
		debugInput(log, kind.file, path)
		data, err := readConfigFile(kind, path, remaining)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > remaining {
			return nil, fmt.Errorf(
				"%s files exceed %d bytes in total at %q", kind.files, limit, path,
			)
		}
		remaining -= int64(len(data))
		files = append(files, flow.NamedReader{Name: path, Reader: bytes.NewReader(data)})
	}
	return files, nil
}

func openConfigFile(kind fileKind, path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file %q: %w",
			kind.file, path, helper.UnwrapPathError(err),
		)
	}
	return f, nil
}

func openNamedConfigFile(kind fileKind, path string) (flow.NamedReader, func(), error) {
	f, err := openConfigFile(kind, path)
	if err != nil {
		return flow.NamedReader{}, nil, err
	}
	return flow.NamedReader{Name: path, Reader: f}, func() { _ = f.Close() }, nil
}

// readConfigFile reads at most one byte beyond limit.
func readConfigFile(kind fileKind, path string, limit int64) ([]byte, error) {
	f, err := openConfigFile(kind, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := config.CheckOpenFile(f); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading %s file %q: %w",
			kind.file, path, helper.UnwrapPathError(err),
		)
	}
	return data, nil
}
