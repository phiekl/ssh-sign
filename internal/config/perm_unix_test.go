// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

//go:build unix

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Like the signers, revocations do not depend on the config directory's parents.
func TestRevokedFilesIgnoresWritableAncestors(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o775); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".ssh", "sign")
	if got, err := RevokedFiles(dir); got != nil || err != nil {
		t.Errorf("RevokedFiles() = %q, %v without a config directory", got, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, RevokedDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := RevokedFiles(dir); got != nil || err != nil {
		t.Errorf("RevokedFiles() = %q, %v with an empty revoked directory", got, err)
	}
	path := filepath.Join(dir, RevokedDirName, "a.conf")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := RevokedFiles(dir); !slices.Equal(got, []string{path}) || err != nil {
		t.Errorf("RevokedFiles() = %q, %v, want %q", got, err, path)
	}
}

func TestCheckOwnerAndMode(t *testing.T) {
	const self = 1000
	tests := []struct {
		name string
		mode fs.FileMode
		uid  uint32
		want string
	}{
		{"own file", 0o644, self, ""},
		{"own directory", fs.ModeDir | 0o755, self, ""},
		{"root", 0o644, 0, ""},
		{"sticky world-writable", fs.ModeDir | fs.ModeSticky | 0o777, self, "writable by group or others"},
		{"group-writable", 0o664, self, "writable by group or others"},
		{"world-writable", 0o666, self, "writable by group or others"},
		{"another user", 0o644, 1001, "owned by uid 1001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkOwnerAndMode("p", tt.mode, tt.uid, self)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("checkOwnerAndMode() = %v, want nil", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("checkOwnerAndMode() = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPolicyFilesRejectUnsafePermissions(t *testing.T) {
	for _, list := range []struct {
		dirName string
		files   func(string) ([]string, error)
	}{
		{SignersDirName, SignersFiles},
		{RevokedDirName, RevokedFiles},
	} {
		t.Run(list.dirName, func(t *testing.T) {
			testPolicyFilesRejectUnsafePermissions(t, list.dirName, list.files)
		})
	}
}

func testPolicyFilesRejectUnsafePermissions(t *testing.T, dirName string, files func(string) ([]string, error)) {
	setup := func(t *testing.T) (dir, sub, file string) {
		dir = t.TempDir()
		sub = filepath.Join(dir, dirName)
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		file = filepath.Join(sub, "a.conf")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, sub, file
	}
	chmod := func(t *testing.T, path string, mode fs.FileMode) {
		// Chmod ignores the umask.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("safe", func(t *testing.T) {
		dir, _, _ := setup(t)
		if _, err := files(dir); err != nil {
			t.Errorf("files() error = %v", err)
		}
	})
	for name, pick := range map[string]func(dir, sub, file string) string{
		"config directory": func(dir, _, _ string) string { return dir },
		"directory":        func(_, sub, _ string) string { return sub },
		"file":             func(_, _, file string) string { return file },
	} {
		t.Run(name, func(t *testing.T) {
			dir, sub, file := setup(t)
			path := pick(dir, sub, file)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			chmod(t, path, info.Mode().Perm()|0o002)
			_, err = files(dir)
			if err == nil || !strings.Contains(err.Error(), `"`+path+`" is writable by group or others`) {
				t.Errorf("files() error = %v, want %s rejected", err, path)
			}
		})
	}

	t.Run("symlink target", func(t *testing.T) {
		dir, sub, _ := setup(t)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		chmod(t, target, 0o666)
		if err := os.Symlink(target, filepath.Join(sub, "b.conf")); err != nil {
			t.Fatal(err)
		}
		if _, err := files(dir); err == nil || !strings.Contains(err.Error(), "b.conf") {
			t.Errorf("files() error = %v, want the symlinked file rejected", err)
		}
	})
}

func TestCheckOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.conf")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if err := CheckOpenFile(f); err != nil {
		t.Errorf("CheckOpenFile() = %v, want nil", err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := CheckOpenFile(f); err == nil {
		t.Errorf("CheckOpenFile() = nil for a group-writable file, want an error")
	}
}

func TestLoadRejectsUnsafePermissions(t *testing.T) {
	setup := func(t *testing.T) (dir, file string) {
		dir = t.TempDir()
		file = filepath.Join(dir, FileName)
		if err := os.WriteFile(file, []byte("[alias]\nwork = "+testKey+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, file
	}

	t.Run("safe", func(t *testing.T) {
		dir, _ := setup(t)
		if _, err := Load(dir); err != nil {
			t.Errorf("Load() error = %v", err)
		}
	})
	for name, mode := range map[string]fs.FileMode{"group-writable": 0o620, "world-writable": 0o606} {
		t.Run(name+" file", func(t *testing.T) {
			dir, file := setup(t)
			if err := os.Chmod(file, mode); err != nil {
				t.Fatal(err)
			}
			_, err := Load(dir)
			if err == nil || !strings.Contains(err.Error(), `unsafe permissions: "`+file+`" is writable by group or others`) {
				t.Errorf("Load() error = %v, want the file rejected", err)
			}
		})
	}
	t.Run("writable directory", func(t *testing.T) {
		dir, _ := setup(t)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := Load(dir)
		if err == nil || !strings.Contains(err.Error(), `unsafe permissions: "`+dir+`" is writable by group or others`) {
			t.Errorf("Load() error = %v, want the directory rejected", err)
		}
	})
	t.Run("symlink target", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
			t.Errorf("Load() error = %v, want the symlink target rejected", err)
		}
	})
	t.Run("missing file in writable directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err != nil {
			t.Errorf("Load() error = %v, want no config and no error", err)
		}
	})
}
