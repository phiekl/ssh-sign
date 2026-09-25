// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Config
	}{
		{"empty", "", Config{}},
		{"comments and blank lines", "# comment\n\n  \n", Config{}},
		{"sign key", "[sign]\nkey = ssh-ed25519 AAAA comment\n", Config{SignKey: "ssh-ed25519 AAAA comment"}},
		{"surrounding whitespace", "  [ sign ]  \n\tkey\t=\tAAAA  \n", Config{SignKey: "AAAA"}},
		{"crlf", "[sign]\r\nkey=AAAA\r\n", Config{SignKey: "AAAA"}},
		{"no trailing newline", "[sign]\nkey=AAAA", Config{SignKey: "AAAA"}},
		{"equals in value", "[sign]\nkey = a=b\n", Config{SignKey: "a=b"}},
		{"empty section", "[sign]\n", Config{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if *got != tt.want {
				t.Errorf("Parse() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"option outside section", "key = AAAA\n", `line 1: option "key" outside a section`},
		{"unknown section", "[other]\n", `line 1: unknown section "other"`},
		{"uppercase section", "[Sign]\n", `line 1: unknown section "Sign"`},
		{"unterminated section", "[sign\n", "line 1: invalid section header"},
		{"unknown option", "[sign]\nkeys = AAAA\n", `line 2: unknown option "sign.keys"`},
		{"uppercase option", "[sign]\nKey = AAAA\n", `line 2: unknown option "sign.Key"`},
		{"missing equals", "[sign]\nkey AAAA\n", `line 2: expected "name = value"`},
		{"empty name", "[sign]\n= AAAA\n", `line 2: expected "name = value"`},
		{"empty value", "[sign]\nkey =\n", `line 2: option "sign.key" has an empty value`},
		{"duplicate option", "[sign]\nkey = A\n[sign]\nkey = B\n", `line 4: duplicate option "sign.key"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.input))
			if err == nil || err.Error() != tt.want {
				t.Errorf("Parse() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestDir(t *testing.T) {
	t.Setenv("HOME", "/home/test")

	t.Setenv(DirEnv, "/etc/ssh-sign")
	if got, err := Dir(); err != nil || got != "/etc/ssh-sign" {
		t.Errorf("Dir() = %q, %v, want the environment value", got, err)
	}

	t.Setenv(DirEnv, "")
	if got, err := Dir(); err != nil || got != "/home/test/.ssh/sign" {
		t.Errorf("Dir() = %q, %v, want the default under HOME", got, err)
	}

	t.Setenv("HOME", "")
	if _, err := Dir(); err == nil {
		t.Errorf("Dir() error = nil without HOME, want an error")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	cfg, err := Load(filepath.Join(dir, "missing"))
	if err != nil || *cfg != (Config{}) {
		t.Errorf("Load() of a missing directory = %+v, %v, want an empty config", cfg, err)
	}

	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("[sign]\nkey = AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(dir)
	if err != nil || *cfg != (Config{Path: path, SignKey: "AAAA"}) {
		t.Errorf("Load() = %+v, %v, want sign.key read", cfg, err)
	}

	if err := os.WriteFile(path, []byte("bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(dir)
	if want := `config file "` + path + `": line 1: expected "name = value"`; err == nil || err.Error() != want {
		t.Errorf("Load() error = %v, want %q", err, want)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Errorf("Load() error = nil when config is a directory, want an error")
	}
}

func TestSignersFiles(t *testing.T) {
	dir := t.TempDir()

	if got, err := SignersFiles(dir); got != nil || err != nil {
		t.Errorf("SignersFiles() = %q, %v without a signers directory, want nothing", got, err)
	}

	signers := filepath.Join(dir, SignersDirName)
	if err := os.Mkdir(signers, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := SignersFiles(dir); got != nil || err != nil {
		t.Errorf("SignersFiles() = %q, %v for an empty directory, want nothing", got, err)
	}

	// Dotfiles are never examined, so a hidden directory is no error.
	if err := os.Mkdir(filepath.Join(signers, ".dir.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"b.conf", "A.conf", "a.conf", "10.conf", "9.conf", "c.conf.bak", "d.txt", ".hidden.conf"} {
		if err := os.WriteFile(filepath.Join(signers, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("b.conf", filepath.Join(signers, "e.conf")); err != nil {
		t.Fatal(err)
	}
	got, err := SignersFiles(dir)
	if err != nil {
		t.Fatalf("SignersFiles() error = %v", err)
	}
	var want []string
	for _, name := range []string{"10.conf", "9.conf", "A.conf", "a.conf", "b.conf", "e.conf"} {
		want = append(want, filepath.Join(signers, name))
	}
	if !slices.Equal(got, want) {
		t.Errorf("SignersFiles() = %q, want %q", got, want)
	}

	if err := os.Mkdir(filepath.Join(signers, "f.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := SignersFiles(dir); err == nil || !strings.Contains(err.Error(), "f.conf") {
		t.Errorf("SignersFiles() error = %v with a directory named *.conf, want it reported", err)
	}
	if err := os.Remove(filepath.Join(signers, "f.conf")); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("missing", filepath.Join(signers, "g.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := SignersFiles(dir); err == nil || !strings.Contains(err.Error(), "g.conf") {
		t.Errorf("SignersFiles() error = %v with a dangling symlink, want it reported", err)
	}
}
