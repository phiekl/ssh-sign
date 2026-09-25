// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package config

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk"

// aliasLikeKeyBlob returns a key blob made only of alias name characters.
func aliasLikeKeyBlob(t *testing.T) string {
	t.Helper()
	for i := range 256 {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i)
		pk, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
		if err != nil {
			t.Fatal(err)
		}
		blob := strings.Fields(string(ssh.MarshalAuthorizedKey(pk)))[1]
		if !strings.ContainsAny(blob, "+/=") {
			return blob
		}
	}
	t.Fatal("no key blob without + / =")
	return ""
}

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
		{
			"aliases",
			"[alias]\nwork = " + testKey + " work\nfirst.last+tag@example.com=" + testKey + "\nWork_2%x-y = " + testKey + "\n",
			Config{Aliases: map[string]string{
				"work":                       testKey + " work",
				"first.last+tag@example.com": testKey,
				"Work_2%x-y":                 testKey,
			}},
		},
		{"sign key naming an alias", "[sign]\nkey = work\n[alias]\nwork = " + testKey + "\n", Config{
			SignKey: "work",
			Aliases: map[string]string{"work": testKey},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("Parse() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func invalidKeyError(line string) string {
	_, err := sshsig.ParsePublicKeyLine(line)
	if err == nil {
		panic("valid key " + line)
	}
	return err.Error()
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
		{"duplicate alias", "[alias]\nwork = " + testKey + "\nwork = " + testKey + "\n", `line 3: duplicate option "alias.work"`},
		{"alias with space", "[alias]\nmy work = " + testKey + "\n", `line 2: invalid alias name "my work": use letters, digits and . _ % + - @`},
		{"alias with slash", "[alias]\na/b = " + testKey + "\n", `line 2: invalid alias name "a/b": use letters, digits and . _ % + - @`},
		{"alias with non-ASCII", "[alias]\nwörk = " + testKey + "\n", `line 2: invalid alias name "wörk": use letters, digits and . _ % + - @`},
		{"alias with invalid key", "[alias]\nwork = nonsense\n", `line 2: alias "work": ` + invalidKeyError("nonsense")},
		{"alias with empty value", "[alias]\nwork =\n", `line 2: option "alias.work" has an empty value`},
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

func TestParseRejectsAnAliasNamedLikeAKey(t *testing.T) {
	blob := aliasLikeKeyBlob(t)
	_, err := Parse(strings.NewReader("[alias]\n" + blob + " = " + testKey + "\n"))
	if want := `line 2: alias name "` + blob + `" is a public key`; err == nil || err.Error() != want {
		t.Errorf("Parse() error = %v, want %q", err, want)
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
	if err != nil || !reflect.DeepEqual(*cfg, Config{}) {
		t.Errorf("Load() of a missing directory = %+v, %v, want an empty config", cfg, err)
	}

	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("[sign]\nkey = AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(dir)
	if err != nil || !reflect.DeepEqual(*cfg, Config{Path: path, SignKey: "AAAA"}) {
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
