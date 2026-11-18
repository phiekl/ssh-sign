// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadConfigFilesBoundsTheTotalSize(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a.conf", "b.conf"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}

	files, err := readConfigFiles(nil, signersKind, paths, 20)
	if err != nil {
		t.Fatalf("readConfigFiles() error = %v at the limit", err)
	}
	for i, f := range files {
		if f.Name != paths[i] || string(f.Data) != "0123456789" {
			t.Errorf("files[%d] = %q with %q, want %q in full", i, f.Name, f.Data, paths[i])
		}
	}

	_, err = readConfigFiles(nil, signersKind, paths, 19)
	want := `signers files exceed 19 bytes in total at "` + paths[1] + `"`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("readConfigFiles() error = %v, want %q", err, want)
	}
}

func TestReadConfigFilesReturnsBinaryData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.conf")
	if err := os.WriteFile(path, []byte("SSHKRL\n\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := readConfigFiles(nil, revokedKind, []string{path}, 64)
	if err != nil {
		t.Fatalf("readConfigFiles() error = %v", err)
	}
	if files[0].Name != path || string(files[0].Data) != "SSHKRL\n\x00" {
		t.Errorf("file = %q with %q, want the complete binary data", files[0].Name, files[0].Data)
	}
}
