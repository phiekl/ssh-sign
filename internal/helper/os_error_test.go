// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestUnwrapPathErrorDropsThePathPrefix(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := os.Open(missing)
	if err == nil {
		t.Fatal("opening a missing file unexpectedly succeeded")
	}

	got := UnwrapPathError(err)
	if want := "no such file or directory"; got.Error() != want {
		t.Errorf("UnwrapPathError() = %q, want %q", got, want)
	}
	// The cause is preserved, so callers can still match on it.
	if !errors.Is(got, fs.ErrNotExist) {
		t.Errorf("UnwrapPathError() = %v, want it to still match fs.ErrNotExist", got)
	}
}

func TestUnwrapPathErrorPassesOtherErrorsThrough(t *testing.T) {
	if got := UnwrapPathError(nil); got != nil {
		t.Errorf("UnwrapPathError(nil) = %v, want nil", got)
	}

	plain := errors.New("something else")
	if got := UnwrapPathError(plain); got != plain {
		t.Errorf("UnwrapPathError() = %v, want the error unchanged", got)
	}
}

func TestUnwrapPathErrorUnwrapsAWrappedPathError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := os.Open(missing)
	if err == nil {
		t.Fatal("opening a missing file unexpectedly succeeded")
	}

	got := UnwrapPathError(fmt.Errorf("reading config: %w", err))
	if want := "no such file or directory"; got.Error() != want {
		t.Errorf("UnwrapPathError() = %q, want %q", got, want)
	}
}
