// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

//go:build unix

package config

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// CheckOpenFile is checkInfo for an open file, which cannot be swapped
// between the check and reading it.
func CheckOpenFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	return checkInfo(f.Name(), info)
}

// checkInfo rejects files other users could write to, as ssh does for its
// config: owned by another user than the current one or root, or writable
// by group or others.
func checkInfo(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unsafe permissions: %q has no known owner", path)
	}
	return checkOwnerAndMode(path, info.Mode(), st.Uid, uint32(os.Getuid()))
}

func checkOwnerAndMode(path string, mode fs.FileMode, uid, self uint32) error {
	if uid != self && uid != 0 {
		return fmt.Errorf("unsafe permissions: %q is owned by uid %d, not the current user or root", path, uid)
	}
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe permissions: %q is writable by group or others (mode %04o)", path, mode.Perm())
	}
	return nil
}
