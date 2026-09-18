// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package landlock

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Run irreversible restrictions in re-executed test processes.
const (
	childActionEnv = "SSH_SIGN_LANDLOCK_TEST_ACTION"
	childTargetEnv = "SSH_SIGN_LANDLOCK_TEST_TARGET"
	childData      = "landlock\n"
	childTimeout   = 30 * time.Second
)

func TestMain(m *testing.M) {
	action, ok := os.LookupEnv(childActionEnv)
	if !ok {
		os.Exit(m.Run())
	}
	os.Exit(runChildAction(action, os.Getenv(childTargetEnv)))
}

// Each action restricts itself, attempts one operation, and returns its result.
var childActions = map[string]func(target string) error{
	"read-preopened": func(target string) error {
		f, err := os.Open(target)
		if err != nil {
			childFatal("opening the target: %v", err)
		}
		defer func() { _ = f.Close() }()
		mustRestrict()

		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		if string(b) != childData {
			return fmt.Errorf("read %q, want %q", b, childData)
		}
		return nil
	},

	"open": func(target string) error {
		mustRestrict()
		f, err := os.Open(target)
		if err == nil {
			_ = f.Close()
		}
		return err
	},

	"best-effort-open": func(target string) error {
		if err := Restrict(nil); err != nil {
			return err
		}
		f, err := os.Open(target)
		if err == nil {
			_ = f.Close()
		}
		return err
	},

	"create": func(target string) error {
		mustRestrict()
		f, err := os.Create(filepath.Join(target, "created"))
		if err == nil {
			_ = f.Close()
		}
		return err
	},

	"write": func(target string) error {
		mustRestrict()
		return os.WriteFile(target, []byte("overwritten\n"), 0o600)
	},

	"mkdir": func(target string) error {
		mustRestrict()
		return os.Mkdir(filepath.Join(target, "created"), 0o700)
	},

	"readdir": func(target string) error {
		mustRestrict()
		_, err := os.ReadDir(target)
		return err
	},

	"exec": func(target string) error {
		mustRestrict()
		return exec.Command(target).Run()
	},

	// Signing needs a socket connected before restriction.
	"unix-preconnected": func(target string) error {
		conn, err := net.Dial("unix", target)
		if err != nil {
			childFatal("connecting to the agent socket: %v", err)
		}
		defer func() { _ = conn.Close() }()
		mustRestrict()

		if _, err := io.WriteString(conn, childData); err != nil {
			return err
		}
		b := make([]byte, len(childData))
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		if string(b) != childData {
			return fmt.Errorf("echoed %q, want %q", b, childData)
		}
		return nil
	},

	"unix-connect": func(target string) error {
		mustRestrict()
		conn, err := net.Dial("unix", target)
		if err == nil {
			_ = conn.Close()
		}
		return err
	},

	// Probe a thread created before restriction.
	"sibling-thread": func(target string) error {
		locked, restricted := make(chan struct{}), make(chan struct{})
		outcome := make(chan error, 1)
		go func() {
			// Keep the goroutine on this pre-existing thread.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			close(locked)
			<-restricted
			f, err := os.Open(target)
			if err == nil {
				_ = f.Close()
			}
			outcome <- err
		}()

		<-locked
		mustRestrict()
		close(restricted)
		return <-outcome
	},

	// Go must retain the ability to signal sibling threads.
	"signal-sibling": func(_ string) error {
		sibling, done := make(chan int, 1), make(chan struct{})
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			sibling <- unix.Gettid()
			<-done
		}()

		tid := <-sibling
		mustRestrict()
		defer close(done)

		// Signal 0 only checks permission.
		return unix.Tgkill(unix.Getpid(), tid, 0)
	},

	// EPERM on the ABI query makes Landlock unavailable.
	"seccomp-query-eperm": func(target string) error {
		blockSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, unix.EPERM)
		if err := Restrict(nil); err != nil {
			return err
		}

		// Confirm that restriction was waived.
		f, err := os.Open(target)
		if err != nil {
			return fmt.Errorf("restricting was waived, yet: %v", err)
		}
		_ = f.Close()
		return nil
	},

	// Best-effort setup waives unexpected ABI query errors too.
	"seccomp-query-eio": func(_ string) error {
		blockSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, unix.EIO)
		return Restrict(nil)
	},

	// Enforcement errors remain fatal.
	"seccomp-restrict-eperm": func(_ string) error {
		blockSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, unix.EPERM)
		return Restrict(nil)
	},

	"tcp-connect": func(target string) error {
		mustRestrict()
		conn, err := net.DialTimeout("tcp", target, childTimeout)
		if err == nil {
			_ = conn.Close()
		}
		return err
	},

	"udp-connect": func(target string) error {
		mustRestrict()
		conn, err := net.Dial("udp", target)
		if err == nil {
			_ = conn.Close()
		}
		return err
	},
}

func runChildAction(action, target string) int {
	fn, ok := childActions[action]
	if !ok {
		childFatal("unknown action %q", action)
	}
	if err := fn(target); err != nil {
		fmt.Printf("error: %v\n", err)
		return 0
	}
	fmt.Println("ok")
	return 0
}

func mustRestrict() {
	// Tests requiring enforcement must not accept a best-effort no-op.
	if !available() {
		childFatal("landlock is unavailable")
	}
	if err := Restrict(nil); err != nil {
		childFatal("restricting: %v", err)
	}
}

// blockSyscall makes one syscall return errno through seccomp.
func blockSyscall(nr int, errno unix.Errno) {
	filter := []unix.SockFilter{
		// Load seccomp_data.nr.
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		// Reject the target and allow everything else.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(nr), Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(errno)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}

	// Unprivileged seccomp requires no_new_privs.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		childSkip("no_new_privs: %v", err)
	}
	if err := unix.Prctl(
		unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)), 0, 0,
	); err != nil {
		childSkip("seccomp: %v", err)
	}
	runtime.KeepAlive(filter)
}

func childSkip(format string, args ...any) {
	fmt.Printf("skip: "+format+"\n", args...)
	os.Exit(0)
}

func childFatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func runChild(t *testing.T, action, target string) string {
	t.Helper()

	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(),
		childActionEnv+"="+action,
		childTargetEnv+"="+target,
	)
	var stderr strings.Builder
	c.Stderr = &stderr

	out, err := c.Output()
	if err != nil {
		t.Fatalf("child %q: %v: %s", action, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

func requireLandlock(t *testing.T) {
	t.Helper()
	if !available() {
		t.Skip("landlock is unavailable on this kernel")
	}
}

func childOutcome(t *testing.T, action, target string) string {
	t.Helper()

	outcome := runChild(t, action, target)
	if reason, ok := strings.CutPrefix(outcome, "skip: "); ok {
		t.Skipf("child %q could not run: %s", action, reason)
	}
	return outcome
}

func targetFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte(childData), 0o600); err != nil {
		t.Fatalf("writing the target file: %v", err)
	}
	return path
}

func TestRestrictKeepsOpenFilesReadable(t *testing.T) {
	requireLandlock(t)

	if got := runChild(t, "read-preopened", targetFile(t)); got != "ok" {
		t.Errorf("reading a pre-opened file = %q, want %q", got, "ok")
	}
}

func TestRestrictDeniesFilesystemAccess(t *testing.T) {
	requireLandlock(t)

	for _, action := range []string{"open", "write"} {
		t.Run(action, func(t *testing.T) {
			assertDenied(t, action, targetFile(t))
		})
	}
	for _, action := range []string{"create", "mkdir", "readdir"} {
		t.Run(action, func(t *testing.T) {
			assertDenied(t, action, t.TempDir())
		})
	}
}

func TestRestrictDeniesExecution(t *testing.T) {
	requireLandlock(t)

	binary, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no executable to try: %v", err)
	}
	assertDenied(t, "exec", binary)
}

func TestRestrictKeepsConnectedSocketsUsable(t *testing.T) {
	requireLandlock(t)

	socket := filepath.Join(t.TempDir(), "echo.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go serveEcho(listener)

	if got := runChild(t, "unix-preconnected", socket); got != "ok" {
		t.Errorf("using a pre-connected socket = %q, want %q", got, "ok")
	}
}

func TestRestrictDeniesPathnameUnixSocketConnections(t *testing.T) {
	requireLandlock(t)

	abi, err := kernelABI()
	if err != nil {
		t.Fatalf("kernelABI() error = %v, want none", err)
	}
	if abi < 9 {
		t.Skipf("landlock ABI %d does not restrict pathname unix sockets", abi)
	}

	socket := filepath.Join(t.TempDir(), "echo.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	assertDenied(t, "unix-connect", socket)
}

func TestRestrictDeniesTCP(t *testing.T) {
	requireLandlock(t)

	abi, err := kernelABI()
	if err != nil {
		t.Fatalf("kernelABI() error = %v, want none", err)
	}
	if abi < 4 {
		t.Skipf("landlock ABI %d does not restrict the network", abi)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on tcp: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go serveEcho(listener)

	assertDenied(t, "tcp-connect", listener.Addr().String())
}

func TestRestrictDeniesUDP(t *testing.T) {
	requireLandlock(t)

	abi, err := kernelABI()
	if err != nil {
		t.Fatalf("kernelABI() error = %v, want none", err)
	}
	if abi < 10 {
		t.Skipf("landlock ABI %d does not restrict UDP", abi)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	assertDenied(t, "udp-connect", conn.LocalAddr().String())
}

// TestRestrictAndOlderThreads checks that pre-existing Go threads are covered.
func TestRestrictAndOlderThreads(t *testing.T) {
	requireLandlock(t)

	outcome := runChild(t, "sibling-thread", targetFile(t))
	if !strings.Contains(outcome, "permission denied") {
		t.Errorf("an older thread = %q, want it denied thread group wide", outcome)
	}
}

// TestRestrictKeepsSignallingSiblingThreads checks the all-thread signal policy.
func TestRestrictKeepsSignallingSiblingThreads(t *testing.T) {
	requireLandlock(t)

	outcome := runChild(t, "signal-sibling", "")
	if outcome != "ok" {
		t.Errorf("signalling a sibling thread = %q, want %q", outcome, "ok")
	}
}

// TestRestrictWaivesAFilteredABIQuery checks best-effort query failures.
func TestRestrictWaivesAFilteredABIQuery(t *testing.T) {
	requireLandlock(t)

	for _, action := range []string{"seccomp-query-eperm", "seccomp-query-eio"} {
		if got := childOutcome(t, action, targetFile(t)); got != "ok" {
			t.Errorf("a filtered ABI query with %s = %q, want it waived", action, got)
		}
	}
}

// TestRestrictReportsAFilteredEnforcement keeps later failures fatal.
func TestRestrictReportsAFilteredEnforcement(t *testing.T) {
	requireLandlock(t)

	got := childOutcome(t, "seccomp-restrict-eperm", "")
	if !strings.HasPrefix(got, "error:") {
		t.Errorf("a filtered enforcement = %q, want it reported", got)
	}
}

func assertDenied(t *testing.T, action, target string) {
	t.Helper()

	got := runChild(t, action, target)
	if !strings.HasPrefix(got, "error:") {
		t.Fatalf("%s = %q, want it denied", action, got)
	}
	if !strings.Contains(got, "permission denied") {
		t.Errorf("%s = %q, want a permission denied error", action, got)
	}
}

func serveEcho(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(conn, conn)
		}()
	}
}
