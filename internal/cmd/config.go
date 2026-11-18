// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
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
func defaultRevokedFiles(log *slog.Logger) ([]flow.NamedBytes, error) {
	dir, err := config.Dir()
	if err != nil {
		cli.Debug(log, cli.LevelDebug2, "config: no directory", "error", err)
		return nil, nil
	}
	paths, err := config.RevokedFiles(dir)
	var files []flow.NamedBytes
	if err == nil {
		files, err = readConfigFiles(log, revokedKind, paths, maxPolicyFilesSize)
	}
	// Configured revocations apply with -a and -r too.
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, config.ErrUnsafePermissions) {
		return nil, fmt.Errorf("%w (set %s to use another config directory)", err, config.DirEnv)
	}
	return files, err
}

// maxPolicyFilesSize bounds the policy files held in memory until parsing,
// for the config directory and each of -a and -r.
const maxPolicyFilesSize = 64 << 20

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
) ([]flow.NamedBytes, error) {
	return readFiles(log, kind, paths, limit, true)
}

// readExplicitFile reads a file named on the command line. Like ssh-keygen,
// it does not check who can write to the file.
func readExplicitFile(log *slog.Logger, kind fileKind, path string) ([]flow.NamedBytes, error) {
	return readFiles(log, kind, []string{path}, maxPolicyFilesSize, false)
}

func readFiles(
	log *slog.Logger, kind fileKind, paths []string, limit int64, checkPerms bool,
) ([]flow.NamedBytes, error) {
	files := make([]flow.NamedBytes, 0, len(paths))
	remaining := limit
	for _, path := range paths {
		data, err := readFile(log, kind, path, remaining, checkPerms)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > remaining {
			return nil, fmt.Errorf(
				"%s files exceed %d bytes in total at %q", kind.files, limit, path,
			)
		}
		remaining -= int64(len(data))
		files = append(files, flow.NamedBytes{Name: path, Data: data})
	}
	return files, nil
}

// readFile reads up to limit+1 bytes, so that the caller can detect overflow.
func readFile(
	log *slog.Logger, kind fileKind, path string, limit int64, checkPerms bool,
) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file %q: %w",
			kind.file, path, helper.UnwrapPathError(err),
		)
	}
	defer func() { _ = f.Close() }()
	if checkPerms {
		if err := config.CheckOpenFile(f); err != nil {
			return nil, err
		}
	}
	debugInput(log, kind.file, path)
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading %s file %q: %w",
			kind.file, path, helper.UnwrapPathError(err),
		)
	}
	return data, nil
}
