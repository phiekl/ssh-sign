// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"pxy.se/go/ssh-sign/internal/helper"
)

// RevokedFiles is SignersFiles for the revoked directory. Unlike a missing directory, a dangling symlink is an error, as
// it would silently drop configured revocations.
func RevokedFiles(dir string) ([]string, error) {
	revoked := filepath.Join(dir, RevokedDirName)
	if _, err := os.Stat(revoked); errors.Is(err, fs.ErrNotExist) {
		if err := checkBrokenSymlinks(revoked); err != nil {
			return nil, fmt.Errorf("revoked directory %q: %w", revoked, err)
		}
		return nil, nil
	}
	return listFiles(dir, RevokedDirName, "revoked", ".conf")
}

// checkBrokenSymlinks looks for a broken symlink among the components of a
// path that could not be found. Lstat can see the link but not its children.
func checkBrokenSymlinks(path string) error {
	for {
		_, err := os.Lstat(path)
		if err == nil {
			_, err = os.Stat(path)
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%q is a broken symlink", path)
			}
		}
		parent := filepath.Dir(path)
		if !errors.Is(err, fs.ErrNotExist) || parent == path {
			if err != nil {
				return fmt.Errorf("%q: %w", path, helper.UnwrapPathError(err))
			}
			return nil
		}
		path = parent
	}
}
