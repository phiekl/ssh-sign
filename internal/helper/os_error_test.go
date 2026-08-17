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

func TestMarshalOSErrorDropsThePathPrefix(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := os.Open(missing)
	if err == nil {
		t.Fatal("opening a missing file unexpectedly succeeded")
	}

	got := MarshalOSError(err)
	if want := "no such file or directory"; got.Error() != want {
		t.Errorf("MarshalOSError() = %q, want %q", got, want)
	}
	// The cause is preserved, so callers can still match on it.
	if !errors.Is(got, fs.ErrNotExist) {
		t.Errorf("MarshalOSError() = %v, want it to still match fs.ErrNotExist", got)
	}
}

func TestMarshalOSErrorPassesOtherErrorsThrough(t *testing.T) {
	if got := MarshalOSError(nil); got != nil {
		t.Errorf("MarshalOSError(nil) = %v, want nil", got)
	}

	plain := errors.New("something else")
	if got := MarshalOSError(plain); got != plain {
		t.Errorf("MarshalOSError() = %v, want the error unchanged", got)
	}
}

func TestMarshalOSErrorUnwrapsAWrappedPathError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := os.Open(missing)
	if err == nil {
		t.Fatal("opening a missing file unexpectedly succeeded")
	}

	got := MarshalOSError(fmt.Errorf("reading config: %w", err))
	if want := "no such file or directory"; got.Error() != want {
		t.Errorf("MarshalOSError() = %q, want %q", got, want)
	}
}
