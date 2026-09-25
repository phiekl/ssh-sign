// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package config reads ssh-sign's INI configuration.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"pxy.se/go/ssh-sign/internal/helper"
)

// DirEnv names the environment variable that overrides ~/.ssh/sign.
const DirEnv = "SSH_SIGN_CONFIG_DIR"

// FileName is the name of the file in the config directory.
const FileName = "config"

// Config holds the parsed options and the path of the file they came from.
type Config struct {
	// Path is empty when no config file was found.
	Path    string
	SignKey string
}

// Dir returns the config directory. An empty DirEnv uses the default.
func Dir() (string, error) {
	if dir := os.Getenv(DirEnv); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "sign"), nil
}

// Load reads the config file in dir. A missing file returns an empty config.
func Load(dir string) (*Config, error) {
	path := filepath.Join(dir, FileName)
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config file %q: %w", path, helper.UnwrapPathError(err))
	}
	defer func() { _ = f.Close() }()

	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("config file %q: %w", path, helper.UnwrapPathError(err))
	}
	cfg.Path = path
	return cfg, nil
}

// Parse reads INI with section headers, name = value options, and full-line
// comments starting with #. Names are case-sensitive and values are unquoted.
func Parse(r io.Reader) (*Config, error) {
	cfg := &Config{}
	seen := map[string]bool{}
	section := ""
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: invalid section header", n)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section != "sign" {
				return nil, fmt.Errorf("line %d: unknown section %q", n, section)
			}
			continue
		}

		name, value, ok := strings.Cut(line, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf(`line %d: expected "name = value"`, n)
		}
		if section == "" {
			return nil, fmt.Errorf("line %d: option %q outside a section", n, name)
		}
		option := section + "." + name
		if option != "sign.key" {
			return nil, fmt.Errorf("line %d: unknown option %q", n, option)
		}
		if value == "" {
			return nil, fmt.Errorf("line %d: option %q has an empty value", n, option)
		}
		if seen[option] {
			return nil, fmt.Errorf("line %d: duplicate option %q", n, option)
		}
		seen[option] = true
		cfg.SignKey = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}
