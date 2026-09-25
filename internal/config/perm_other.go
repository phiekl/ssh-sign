// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

//go:build !unix

package config

import (
	"io/fs"
	"os"
)

// CheckOpenFile accepts any file, as there are no Unix owners and modes.
func CheckOpenFile(f *os.File) error {
	return nil
}

func checkInfo(path string, info fs.FileInfo) error {
	return nil
}
