// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns a terminal that stays open until the test ends.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("cannot open pty: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlocking pty: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("getting pty number: %v", err)
	}
	tty, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("opening pty: %v", err)
	}
	t.Cleanup(func() { _ = tty.Close() })
	return tty
}

func runWithTTY(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	tty := openPTY(t)

	// Reading a terminal would block.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	c := exec.CommandContext(ctx, binary, args...)
	c.Stdin = tty
	c.Stdout = &outBuf
	c.Stderr = &errBuf

	err := c.Run()
	if ctx.Err() != nil {
		t.Fatalf("running %v: timed out reading stdin", args)
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running %v: %v", args, err)
	}
	return outBuf.String(), errBuf.String(), code
}

func TestDefaultSignatureFileOnTTY(t *testing.T) {
	f := newFixture(t, "file")
	for name, args := range map[string][]string{
		"check":  {"check", "-f", f.data, "-K"},
		"verify": {"verify", "-a", f.allowed, "-f", f.data, "-p", f.principal, "-n", "file"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, code := runWithTTY(t, append(args, "-vv")...)
			if code != 0 || !strings.Contains(stdout, "verification   = valid") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if !strings.Contains(stderr, "role=signature path="+f.signature) {
				t.Errorf("stderr=%q, want signature path %s", stderr, f.signature)
			}
		})
	}
}

func TestMissingDefaultSignatureFileOnTTY(t *testing.T) {
	f := newFixture(t, "file")
	if err := os.Remove(f.signature); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("failed to open signature file %q: no such file or directory", f.signature)
	for name, args := range map[string][]string{
		"check":  {"check", "-f", f.data, "-K"},
		"verify": {"verify", "-a", f.allowed, "-f", f.data, "-p", f.principal, "-n", "file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, stderr, code := runWithTTY(t, args...)
			if code != 1 || !strings.Contains(stderr, want) {
				t.Errorf("code=%d stderr=%q, want %q", code, stderr, want)
			}
		})
	}
}

func TestExplicitSignatureFileOnTTY(t *testing.T) {
	f := newFixture(t, "file")
	other := newFixture(t, "file")
	f.writeAllowed(t, other.principal+" "+other.keyLine())
	for name, args := range map[string][]string{
		"check":  {"check", "-f", f.data, "-s", other.signature, "-k", other.keyLine()},
		"verify": {"verify", "-a", f.allowed, "-f", f.data, "-s", other.signature, "-n", "file"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, code := runWithTTY(t, args...)
			if code != 0 || !strings.Contains(stdout, "verification   = valid") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}
