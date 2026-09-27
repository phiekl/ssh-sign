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
	_, tty := openPTYPair(t)
	return tty
}

// openPTYPair returns a pty master and its terminal.
func openPTYPair(t *testing.T) (*os.File, *os.File) {
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
	return master, tty
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

// runOnTTY runs ssh-sign with stdout and stderr on a terminal, unless changed
// by setup, and returns what the terminal received.
func runOnTTY(t *testing.T, setup func(*exec.Cmd), args ...string) (output string, code int) {
	t.Helper()
	master, tty := openPTYPair(t)

	c := exec.Command(binary, args...)
	c.Stdout = tty
	c.Stderr = tty
	if setup != nil {
		setup(c)
	}
	done := make(chan []byte)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(master)
		done <- buf.Bytes()
	}()

	err := c.Run()
	// The master reads EIO once no terminal descriptor is left open.
	_ = tty.Close()
	out := <-done
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running %v: %v", args, err)
	}
	return strings.ReplaceAll(string(out), "\r\n", "\n"), code
}

func TestColorOnTTY(t *testing.T) {
	f := newFixture(t, "file")
	f.writeAllowed(t, f.principal+" "+f.keyLine())

	out, code := runOnTTY(t, nil, "check", "-f", f.data, "-s", f.signature, "-K")
	want := " authentication = \x1b[33mdisabled\x1b[0m\n" +
		" designation    = \x1b[32mvalid\x1b[0m\n" +
		" verification   = \x1b[32mvalid\x1b[0m\n"
	if code != 0 || out != want {
		t.Errorf("check: code=%d output=%q, want %q", code, out, want)
	}

	out, code = runOnTTY(t, nil,
		"verify", "-a", f.allowed, "-f", f.data, "-s", f.signature, "-p", f.principal, "-n", "file",
	)
	want = " principal      = " + f.principal + "\n" +
		" authentication = \x1b[32mvalid\x1b[0m\n" +
		" namespace      = file\n" +
		" designation    = \x1b[32mvalid\x1b[0m\n" +
		" verification   = \x1b[32mvalid\x1b[0m\n" +
		" entry          = " + f.allowed + ":1\n"
	if code != 0 || out != want {
		t.Errorf("verify: code=%d output=%q, want %q", code, out, want)
	}

	out, code = runOnTTY(t, nil, "check", "-f", f.data, "-s", f.signature, "-K", "-n", "abc")
	want = "\x1b[31merror: check: signature contains namespace \"file\" (expected \"abc\")\x1b[0m\n"
	if code != 1 || out != want {
		t.Errorf("check error: code=%d output=%q, want %q", code, out, want)
	}
}

func TestNoColor(t *testing.T) {
	f := newFixture(t, "file")
	args := []string{"check", "-f", f.data, "-s", f.signature, "-K", "-n", "abc"}
	for name, tt := range map[string]struct {
		setup func(*exec.Cmd)
		args  []string
	}{
		"NO_COLOR": {setup: func(c *exec.Cmd) { c.Env = append(os.Environ(), "NO_COLOR=1") }},
		"json":     {args: []string{"-j"}},
		"help":     {args: []string{"-h"}},
	} {
		t.Run(name, func(t *testing.T) {
			out, _ := runOnTTY(t, tt.setup, append(args, tt.args...)...)
			if strings.Contains(out, "\x1b") {
				t.Errorf("output=%q, want no color", out)
			}
		})
	}

	t.Run("stdout piped", func(t *testing.T) {
		var stdout bytes.Buffer
		stderr, _ := runOnTTY(t, func(c *exec.Cmd) { c.Stdout = &stdout }, args...)
		if strings.Contains(stdout.String(), "\x1b") {
			t.Errorf("stdout=%q, want no color", stdout.String())
		}
		if !strings.HasPrefix(stderr, "\x1b[31merror: ") {
			t.Errorf("stderr=%q, want red error", stderr)
		}
	})
}

func TestColorEmptyNoColor(t *testing.T) {
	f := newFixture(t, "file")
	out, _ := runOnTTY(t, func(c *exec.Cmd) { c.Env = append(os.Environ(), "NO_COLOR=") },
		"check", "-f", f.data, "-s", f.signature, "-K",
	)
	if !strings.Contains(out, "\x1b[32mvalid") {
		t.Errorf("output=%q, want color with empty NO_COLOR", out)
	}
}
