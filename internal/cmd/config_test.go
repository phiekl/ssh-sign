// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSignersFilesBoundsTheTotalSize(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a.conf", "b.conf"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}

	files, err := readSignersFiles(nil, paths, 20)
	if err != nil {
		t.Fatalf("readSignersFiles() error = %v at the limit", err)
	}
	for i, f := range files {
		data, _ := io.ReadAll(f.Reader)
		if f.Name != paths[i] || string(data) != "0123456789" {
			t.Errorf("files[%d] = %q with %q, want %q in full", i, f.Name, data, paths[i])
		}
	}

	_, err = readSignersFiles(nil, paths, 19)
	want := `signers files exceed 19 bytes in total at "` + paths[1] + `"`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("readSignersFiles() error = %v, want %q", err, want)
	}
}
