// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// otherKeyLine is a valid ssh-ed25519 key that no fixture ever signs with.
const otherKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+xLwvXBGWKOTvJcDkfLmZOaTRUwbHqPTLjxlKcVsRR"

// binary is the ssh-sign executable built once for the whole test binary.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ssh-sign-test")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	binary = filepath.Join(dir, "ssh-sign")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("go build: " + err.Error() + ": " + string(out))
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// run executes ssh-sign with the given arguments and empty stdin.
func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	return runWithInput(t, "", args...)
}

func runWithInput(t *testing.T, input string, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	var outBuf, errBuf bytes.Buffer
	c := exec.Command(binary, args...)
	c.Stdin = strings.NewReader(input)
	c.Stdout = &outBuf
	c.Stderr = &errBuf

	err := c.Run()
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

// startAgent serves an in-process ssh-agent and returns its public key.
func startAgent(t *testing.T) string {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("adding key to agent: %v", err)
	}

	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = connection.Close() }()
				_ = agent.ServeAgent(keyring, connection)
			}()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", socket)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// fixture is a signed-data scenario written to a temporary directory.
type fixture struct {
	dir       string
	data      string
	signature string
	allowed   string
	principal string
	publicKey ssh.PublicKey
}

// newFixture signs "hello\n" under the given namespace and writes an allowed
// signers file listing the signing key for principal "signer@example.com".
func newFixture(t *testing.T, namespace string) *fixture {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	f := &fixture{
		dir:       t.TempDir(),
		principal: "signer@example.com",
		publicKey: signer.PublicKey(),
	}
	f.data = filepath.Join(f.dir, "data")
	f.signature = filepath.Join(f.dir, "data.sig")
	f.allowed = filepath.Join(f.dir, "allowed_signers")

	if err := os.WriteFile(f.data, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}

	sig, err := sshsig.Sign(strings.NewReader("hello\n"), signer, sshsig.HashSHA512, namespace)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := os.WriteFile(f.signature, sshsig.Armor(sig), 0o600); err != nil {
		t.Fatalf("writing signature: %v", err)
	}

	f.writeAllowed(t, f.principal+" "+f.keyLine())
	return f
}

// keyLine returns the "<type> <base64>" representation of the signing key.
func (f *fixture) keyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.publicKey)))
}

// writeAllowed replaces the allowed signers file with the given lines.
func (f *fixture) writeAllowed(t *testing.T, lines ...string) {
	t.Helper()
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(f.allowed, []byte(content), 0o600); err != nil {
		t.Fatalf("writing allowed signers: %v", err)
	}
}

// decodeJSON unmarshals ssh-sign JSON output.
func decodeJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decoding %q: %v", out, err)
	}
	return decoded
}

func TestHelpListsPublicCommands(t *testing.T) {
	stdout, stderr, code := run(t, "--help")
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	for _, command := range []string{"inspect", "sign", "verify", "check"} {
		if !strings.Contains(stdout, "\n  "+command+" ") {
			t.Errorf("help output is missing command %q:\n%s", command, stdout)
		}
	}
	if strings.Contains(stdout, "pure-verify") {
		t.Errorf("help output still contains pure-verify:\n%s", stdout)
	}
}

func TestMissingCommandShowsUsage(t *testing.T) {
	stdout, stderr, code := run(t)
	if code != 2 {
		t.Fatalf("exit status = %d, want 2 (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want it empty", stdout)
	}
	if !strings.Contains(stderr, "usage: ssh-sign") {
		t.Errorf("stderr = %q, want command usage", stderr)
	}
	if strings.Contains(stderr, "missing arguments") {
		t.Errorf("stderr = %q, want no parser sentinel", stderr)
	}
}

func TestCommandHelpExitsSuccessfully(t *testing.T) {
	stdout, stderr, code := run(t, "sign", "--help")
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "usage: ssh-sign sign") {
		t.Errorf("stdout = %q, want sign usage", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want it empty", stderr)
	}
}

func TestSignProducesAVerifiableSignature(t *testing.T) {
	key := startAgent(t)
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	signature := filepath.Join(dir, "data.sig")
	if err := os.WriteFile(data, []byte("signed by the CLI\n"), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}

	stdout, stderr, code := run(t, "sign", "-f", data, "-k", key, "-n", "git")
	if code != 0 {
		t.Fatalf("sign exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	if err := os.WriteFile(signature, []byte(stdout), 0o600); err != nil {
		t.Fatalf("writing signature: %v", err)
	}

	stdout, stderr, code = run(t,
		"check", "-f", data, "-s", signature, "-k", key, "-n", "git",
	)
	if code != 0 {
		t.Fatalf("check exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "verification   = valid") {
		t.Errorf("check output = %q, want a valid verification", stdout)
	}
}

func TestJSONFailureExitsNonZero(t *testing.T) {
	f := newFixture(t, "file")
	tampered := filepath.Join(f.dir, "tampered")
	if err := os.WriteFile(tampered, []byte("goodbye\n"), 0o600); err != nil {
		t.Fatalf("writing tampered data: %v", err)
	}

	stdout, stderr, code := run(t,
		"-j", "verify", "-a", f.allowed, "-f", tampered, "-s", f.signature, "-n", "file",
	)
	if code != 1 {
		t.Fatalf("exit status = %d, want 1 (stderr: %s)", code, stderr)
	}
	if decoded := decodeJSON(t, stdout); decoded["error"] == nil {
		t.Errorf("output %q is missing the error key", stdout)
	}
}

func TestJSONExitStatusZeroOnSuccess(t *testing.T) {
	f := newFixture(t, "file")

	stdout, stderr, code := run(t,
		"-j", "verify", "-a", f.allowed, "-f", f.data, "-s", f.signature, "-n", "file",
	)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	if decoded := decodeJSON(t, stdout); decoded["error"] != nil {
		t.Errorf("output %q unexpectedly contains an error key", stdout)
	}
}

func TestVerifyRejectsSignatureFromAnotherNamespace(t *testing.T) {
	f := newFixture(t, "email")

	_, stderr, code := run(t,
		"verify", "-a", f.allowed, "-f", f.data, "-s", f.signature, "-n", "git",
	)
	if code == 0 {
		t.Errorf("exit status = 0 for a signature made in another namespace, want non-zero")
	}
	if !strings.Contains(stderr, `namespace "email" (expected "git")`) {
		t.Errorf("stderr = %q, want a namespace mismatch", stderr)
	}
}

func TestVerifyRejectsAnUnconstrainedNamespace(t *testing.T) {
	f := newFixture(t, "email")

	_, stderr, code := run(t, "verify", "-a", f.allowed, "-f", f.data, "-s", f.signature)
	if code == 0 {
		t.Errorf("exit status = 0 for an unconstrained namespace, want non-zero")
	}
	if !strings.Contains(stderr, `namespace "email" was left unverified`) {
		t.Errorf("stderr = %q, want an unverified namespace", stderr)
	}
}

func TestVerifyAcceptsAnUnpinnedNamespaceAllowedByPolicy(t *testing.T) {
	f := newFixture(t, "email")
	f.writeAllowed(t, f.principal+` namespaces="email" `+f.keyLine())

	stdout, stderr, code := run(t, "verify", "-a", f.allowed, "-f", f.data, "-s", f.signature)
	if code != 0 {
		t.Fatalf("exit status = %d for an unpinned namespace, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "designation    = valid") {
		t.Errorf("stdout = %q, want the allowed signers policy to have designated it", stdout)
	}
}

func TestVerifyEnforcesAllowedSignersNamespaceByDefault(t *testing.T) {
	f := newFixture(t, "email")
	f.writeAllowed(t, f.principal+` namespaces="file" `+f.keyLine())

	_, stderr, code := run(t, "verify", "-a", f.allowed, "-f", f.data, "-s", f.signature)
	if code == 0 {
		t.Error("exit status = 0 for a namespace forbidden by allowed signers, want non-zero")
	}
	if !strings.Contains(stderr, "namespace mismatch") {
		t.Errorf("stderr = %q, want an allowed signers namespace mismatch", stderr)
	}
}

func TestVerifyReportsAllowedSignersNamespaceAsValid(t *testing.T) {
	f := newFixture(t, "file")
	f.writeAllowed(t, f.principal+` namespaces="file" `+f.keyLine())

	stdout, stderr, code := run(t, "-j", "verify",
		"-a", f.allowed, "-f", f.data, "-s", f.signature, "-p", f.principal,
	)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	result, ok := decodeJSON(t, stdout)["result"].(map[string]any)
	if !ok {
		t.Fatalf("output %q is missing the result key", stdout)
	}
	if result["designation"] != "valid" {
		t.Errorf("designation = %v, want %q", result["designation"], "valid")
	}
}

func TestVerifyIgnoresNamespaceWhenDisabled(t *testing.T) {
	f := newFixture(t, "email")
	f.writeAllowed(t, f.principal+` namespaces="file" `+f.keyLine())

	stdout, stderr, code := run(t, "verify", "-a", f.allowed, "-f", f.data, "-s", f.signature, "-N")
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "verification   = valid") {
		t.Errorf("stdout = %q, want a valid verification", stdout)
	}
}

func TestVerifyReportsRequestedPrincipalNotPattern(t *testing.T) {
	f := newFixture(t, "file")
	f.writeAllowed(t, "*@example.com "+f.keyLine())

	stdout, stderr, code := run(t, "-j", "verify",
		"-a", f.allowed, "-f", f.data, "-s", f.signature, "-n", "file", "-p", f.principal,
	)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}

	result, ok := decodeJSON(t, stdout)["result"].(map[string]any)
	if !ok {
		t.Fatalf("output %q is missing the result key", stdout)
	}
	if result["principal"] != f.principal {
		t.Errorf("principal = %v, want %q", result["principal"], f.principal)
	}
	if result["authentication"] != "valid" {
		t.Errorf("authentication = %v, want %q", result["authentication"], "valid")
	}
}

func TestCommandsWithoutOptionsReportMissingFlags(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "sign", want: "missing required flag: sign-key"},
		{command: "check", want: "missing required flag: verify-file"},
		{
			command: "verify",
			want:    "missing required flags: allowed-signers-file, verify-file",
		},
	}
	for _, tt := range tests {
		for _, jsonMode := range []bool{false, true} {
			name := "text"
			args := []string{tt.command}
			if jsonMode {
				name = "json"
				args = []string{"-j", tt.command}
			}
			t.Run(tt.command+"/"+name, func(t *testing.T) {
				stdout, stderr, code := run(t, args...)
				if code == 0 {
					t.Errorf("exit status = 0 for missing required flags, want non-zero")
				}
				if stdout != "" {
					t.Errorf("stdout = %q, want it empty", stdout)
				}
				if !strings.Contains(stderr, tt.want) {
					t.Errorf("stderr = %q, want %q", stderr, tt.want)
				}
				if strings.Contains(stderr, "usage:") {
					t.Errorf("stderr = %q, want no usage text", stderr)
				}
			})
		}
	}
}

func TestUsageErrorsAreNotLabelledInternal(t *testing.T) {
	_, stderr, code := run(t, "verify", "--bogus")
	if code == 0 {
		t.Errorf("exit status = 0 for an unknown flag, want non-zero")
	}
	if !strings.Contains(stderr, "unknown flag: --bogus") {
		t.Fatalf("stderr = %q, want it to mention the unknown flag", stderr)
	}
	if strings.Contains(stderr, "internal error") {
		t.Errorf("stderr = %q, want no \"internal error\" label on a usage error", stderr)
	}
}

func TestSemanticUsageErrorsExitTwo(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "invalid timestamp",
			args: []string{"verify", "-a", "/missing", "-f", "/missing", "-t", "nonsense"},
			want: "invalid timestamp",
		},
		{
			name: "missing authentication decision",
			args: []string{"check", "-f", "/missing", "-N"},
			want: "no auth key provided",
		},
		{
			name: "invalid signing key",
			args: []string{"sign", "-k", "nonsense"},
			want: "invalid signing key",
		},
	}

	for _, tt := range tests {
		for _, jsonMode := range []bool{false, true} {
			name := "text"
			args := tt.args
			if jsonMode {
				name = "json"
				args = append([]string{"-j"}, args...)
			}
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				stdout, stderr, code := run(t, args...)
				if code != 2 {
					t.Errorf("exit status = %d, want 2", code)
				}
				if stdout != "" {
					t.Errorf("stdout = %q, want empty", stdout)
				}
				if !strings.Contains(stderr, tt.want) {
					t.Errorf("stderr = %q, want %q", stderr, tt.want)
				}
			})
		}
	}
}

func TestSignValidatesKeyBeforeOpeningDataFile(t *testing.T) {
	_, stderr, code := run(t,
		"sign", "-k", "nonsense", "-f", filepath.Join(t.TempDir(), "missing"),
	)
	if code != 2 {
		t.Errorf("exit status = %d, want 2", code)
	}
	if !strings.Contains(stderr, "invalid signing key") {
		t.Errorf("stderr = %q, want an invalid signing key error", stderr)
	}
	if strings.Contains(stderr, "failed to open data file") {
		t.Errorf("stderr = %q, input was opened before validating the key", stderr)
	}
}

func TestVerifyReportsPartialResultOnFailure(t *testing.T) {
	f := newFixture(t, "file")
	tampered := filepath.Join(f.dir, "tampered")
	if err := os.WriteFile(tampered, []byte("goodbye\n"), 0o600); err != nil {
		t.Fatalf("writing tampered data: %v", err)
	}

	stdout, stderr, code := run(t, "-j", "verify",
		"-a", f.allowed, "-f", tampered, "-s", f.signature, "-n", "git",
	)
	if code != 1 {
		t.Fatalf("exit status = %d, want 1 (stderr: %s)", code, stderr)
	}

	result, ok := decodeJSON(t, stdout)["result"].(map[string]any)
	if !ok {
		t.Fatalf("output %q is missing the result key", stdout)
	}
	for key, want := range map[string]string{
		"namespace":      "file",
		"designation":    "invalid",
		"authentication": "disabled",
		"verification":   "invalid",
	} {
		if result[key] != want {
			t.Errorf("result[%q] = %v, want %q", key, result[key], want)
		}
	}
}

// craftedKeyAlgorithm creates a signature with the given key algorithm.
func craftedKeyAlgorithm(t *testing.T, algorithm string) string {
	t.Helper()

	wire := struct {
		MagicPreamble [6]byte
		Version       uint32
		PublicKey     string
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Signature     string
	}{
		MagicPreamble: [6]byte{'S', 'S', 'H', 'S', 'I', 'G'},
		Version:       1,
		PublicKey:     string(ssh.Marshal(struct{ Algorithm string }{algorithm})),
		Namespace:     "file",
		HashAlgorithm: "sha512",
		Signature:     string(ssh.Marshal(ssh.Signature{Format: "x", Blob: []byte("x")})),
	}
	armored := pem.EncodeToMemory(&pem.Block{
		Type:  sshsig.PEMType,
		Bytes: ssh.Marshal(wire),
	})
	signature := filepath.Join(t.TempDir(), "crafted.sig")
	if err := os.WriteFile(signature, armored, 0o600); err != nil {
		t.Fatalf("writing signature: %v", err)
	}
	return signature
}

// hasRawControl permits newlines but rejects other controls and invalid UTF-8.
func hasRawControl(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	return strings.ContainsFunc(s, func(r rune) bool {
		return r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f))
	})
}

func TestErrorsCarryNoTerminalEscapes(t *testing.T) {
	for name, algorithm := range map[string]string{
		"C0":        "ssh-x" + string(rune(0x1b)) + "]0;PWNED" + string(rune(0x07)),
		"C1":        "ssh-x" + string(rune(0x9b)) + "31m",
		"lone byte": "ssh-x" + string([]byte{0x9b}),
	} {
		t.Run(name, func(t *testing.T) {
			signature := craftedKeyAlgorithm(t, algorithm)

			_, stderr, code := run(t, "inspect", "-s", signature)
			if code == 0 {
				t.Fatal("exit status = 0 for a crafted signature, want non-zero")
			}
			if !strings.Contains(stderr, "unknown key algorithm") {
				t.Fatalf("stderr = %q, want the parse failure reported", stderr)
			}
			if hasRawControl(stderr) {
				t.Errorf("stderr = %q, want no raw control characters", stderr)
			}

			stdout, _, code := run(t, "-j", "inspect", "-s", signature)
			if code == 0 {
				t.Fatal("exit status = 0 for a crafted signature, want non-zero")
			}
			if hasRawControl(stdout) {
				t.Errorf("stdout = %q, want no raw control characters", stdout)
			}
			// JSON preserves valid input; its encoder replaces invalid UTF-8.
			reported, ok := decodeJSON(t, stdout)["error"].([]any)
			if !ok || len(reported) != 1 {
				t.Fatalf("output %q is missing the error key", stdout)
			}
			message, _ := reported[0].(string)
			if utf8.ValidString(algorithm) && !strings.Contains(message, algorithm) {
				t.Errorf("decoded error = %q, want it to hold the algorithm verbatim", message)
			}
		})
	}
}

func TestInspectTextAndJSONAgreeOnFields(t *testing.T) {
	f := newFixture(t, "file")

	text, stderr, code := run(t, "inspect", "-s", f.signature)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	encoded, _, code := run(t, "-j", "inspect", "-s", f.signature)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0", code)
	}

	result, ok := decodeJSON(t, encoded)["result"].(map[string]any)
	if !ok {
		t.Fatalf("output %q is missing the result key", encoded)
	}
	for _, key := range []string{"version", "namespace", "hash_algorithm"} {
		if _, ok := result[key]; !ok {
			t.Errorf("JSON result is missing %q", key)
		}
		if !strings.Contains(text, key+" ") {
			t.Errorf("text output %q is missing %q", text, key)
		}
	}
}

func TestOutputWriteFailureIsReported(t *testing.T) {
	f := newFixture(t, "file")

	for _, jsonMode := range []bool{false, true} {
		name := "text"
		args := []string{"inspect", "-s", f.signature}
		if jsonMode {
			name = "json"
			args = append([]string{"-j"}, args...)
		}
		t.Run(name, func(t *testing.T) {
			full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
			if err != nil {
				t.Skipf("cannot open /dev/full: %v", err)
			}
			defer func() { _ = full.Close() }()

			var stderr bytes.Buffer
			command := exec.Command(binary, args...)
			command.Stdout = full
			command.Stderr = &stderr
			err = command.Run()

			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("exit error = %v, want status 1", err)
			}
			if !strings.Contains(stderr.String(), "failed writing output") {
				t.Errorf("stderr = %q, want an output-write error", stderr.String())
			}
		})
	}
}

func TestBrokenPipeDoesNotExitSuccessfully(t *testing.T) {
	f := newFixture(t, "file")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	_ = reader.Close()
	defer func() { _ = writer.Close() }()

	command := exec.Command(binary, "inspect", "-s", f.signature)
	command.Stdout = writer
	if err := command.Run(); err == nil {
		t.Fatal("inspect exited successfully after writing to a broken pipe")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	return len(p) / 2, nil
}

func TestWriteOutputRejectsShortWrite(t *testing.T) {
	if err := writeOutput(shortWriter{}, "result"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeOutput() error = %v, want io.ErrShortWrite", err)
	}
}

func TestCommandStdinPaths(t *testing.T) {
	key := startAgent(t)
	f := newFixture(t, "file")
	const data = "data supplied through stdin\n"

	armored, stderr, code := runWithInput(t, data, "sign", "-k", key, "-n", "file")
	if code != 0 {
		t.Fatalf("sign from stdin: code=%d stderr=%q", code, stderr)
	}
	if stdout, stderr, code := runWithInput(t, armored, "inspect"); code != 0 ||
		!strings.Contains(stdout, "namespace             | file") {
		t.Fatalf("inspect from stdin: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	dataPath := filepath.Join(f.dir, "stdin-data")
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	if stdout, stderr, code := runWithInput(t, armored,
		"check", "-f", dataPath, "-k", key, "-n", "file",
	); code != 0 || !strings.Contains(stdout, "verification   = valid") {
		t.Fatalf("check signature from stdin: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	writeAllowedSigner(t, f.allowed, f.principal, key)
	if stdout, stderr, code := runWithInput(t, armored,
		"verify", "-a", f.allowed, "-f", dataPath, "-p", f.principal, "-n", "file",
	); code != 0 || !strings.Contains(stdout, "verification   = valid") {
		t.Fatalf("verify signature from stdin: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestSignValidatesKeyBeforeOpeningFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "data.fifo")
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo is not installed")
	}
	if out, err := exec.Command(mkfifo, "-m", "600", fifo).CombinedOutput(); err != nil {
		t.Skipf("cannot create FIFO: %v: %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "sign", "-k", "nonsense", "-f", fifo)
	out, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("sign blocked opening the FIFO before validating its key")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("exit error = %v, output=%q, want status 2", err, out)
	}
	if !strings.Contains(string(out), "invalid signing key") {
		t.Errorf("output = %q, want an invalid signing key error", out)
	}
}

func TestLargeInputRoundTrip(t *testing.T) {
	key := startAgent(t)
	data := strings.Repeat("0123456789abcdef", 256*1024)
	armored, stderr, code := runWithInput(t, data, "sign", "-k", key, "-n", "file")
	if code != 0 {
		t.Fatalf("signing large stdin: code=%d stderr=%q", code, stderr)
	}
	dataPath := filepath.Join(t.TempDir(), "large-data")
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing large data: %v", err)
	}
	if stdout, stderr, code := runWithInput(t, armored,
		"check", "-f", dataPath, "-k", key, "-n", "file",
	); code != 0 || !strings.Contains(stdout, "verification   = valid") {
		t.Fatalf("checking large data: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestVerifyReportsPrincipalPinningAsDisabledWithoutAPrincipal(t *testing.T) {
	f := newFixture(t, "file")

	stdout, stderr, code := run(t, "-j", "verify",
		"-a", f.allowed, "-f", f.data, "-s", f.signature, "-n", "file",
	)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}

	result, ok := decodeJSON(t, stdout)["result"].(map[string]any)
	if !ok {
		t.Fatalf("output %q is missing the result key", stdout)
	}
	// No -p was given, so principal pinning was not requested. The key still
	// had to be listed, which the absence of an error shows.
	if result["authentication"] != "disabled" {
		t.Errorf("authentication = %v, want %q", result["authentication"], "disabled")
	}
	if result["principal"] != f.principal {
		t.Errorf("principal = %v, want %q", result["principal"], f.principal)
	}
}

func TestCheck(t *testing.T) {
	f := newFixture(t, "file")
	key := f.keyLine()

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{name: "everything waived", args: []string{"-K", "-N"}},
		{name: "namespace pinned", args: []string{"-K", "-n", "file"}},
		{name: "key pinned", args: []string{"-k", key, "-N"}},
		{name: "both pinned", args: []string{"-k", key, "-n", "file"}},
		{
			name:     "wrong namespace",
			args:     []string{"-K", "-n", "git"},
			wantCode: 1,
			wantErr:  `namespace "file" (expected "git")`,
		},
		{
			name:     "wrong key",
			args:     []string{"-k", otherKeyLine, "-N"},
			wantCode: 1,
			wantErr:  "signature was created by public key",
		},
		{name: "namespace defaulted", args: []string{"-K"}},
		{
			name:     "no key decision",
			args:     []string{"-N"},
			wantCode: 2,
			wantErr:  "no auth key provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"check", "-f", f.data, "-s", f.signature}, tt.args...)
			stdout, stderr, code := run(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exit status = %d, want %d (stdout: %s, stderr: %s)",
					code, tt.wantCode, stdout, stderr)
			}
			if tt.wantErr != "" && !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
			if tt.wantErr == "" && !strings.Contains(stdout, "verification   = valid") {
				t.Errorf("stdout = %q, want a valid verification", stdout)
			}
		})
	}
}

// TestVerifiesSignaturesFromSSHKeygen checks the interoperability the tool
// exists for: signatures produced by `ssh-keygen -Y sign` must verify here.
func TestVerifiesSignaturesFromSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}

	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	data := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")

	if err := os.WriteFile(data, []byte("interop\n"), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	mustRun := func(args ...string) {
		t.Helper()
		c := exec.Command(keygen, args...)
		c.Stdin = strings.NewReader("")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v: %s", args, err, out)
		}
	}
	mustRun("-q", "-t", "ed25519", "-N", "", "-C", "interop@example.com", "-f", key)
	mustRun("-Y", "sign", "-f", key, "-n", "file", data)

	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatalf("reading public key: %v", err)
	}
	fields := strings.Fields(string(pub))
	line := "interop@example.com " + fields[0] + " " + fields[1] + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
		t.Fatalf("writing allowed signers: %v", err)
	}

	stdout, stderr, code := run(t, "verify",
		"-a", allowed, "-f", data, "-s", data+".sig",
		"-n", "file", "-p", "interop@example.com",
	)
	if code != 0 {
		t.Fatalf("exit status = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "verification   = valid") {
		t.Errorf("stdout = %q, want a valid verification", stdout)
	}
}

// TestArgumentErrorsAreReportedBeforeOpeningInputs covers arguments that can be
// judged on their own. Left until the flow runs, they are masked by whichever
// file error comes first, and lost entirely when an input blocks on open.
func TestArgumentErrorsAreReportedBeforeOpeningInputs(t *testing.T) {
	f := newFixture(t, "file")
	missing := filepath.Join(f.dir, "missing")

	tests := map[string]struct {
		args []string
		want string
	}{
		"invalid timestamp": {
			args: []string{
				"verify", "-a", missing, "-f", missing, "-s", f.signature,
				"-n", "file", "-t", "nonsense",
			},
			want: `invalid timestamp "nonsense"`,
		},
		"missing auth key decision": {
			args: []string{"check", "-f", missing, "-s", f.signature, "-N"},
			want: "no auth key provided",
		},
		"unparseable auth key": {
			args: []string{"check", "-f", missing, "-s", missing, "-k", "not-a-key", "-N"},
			want: "invalid authentication key",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, stderr, code := run(t, tt.args...)
			if code == 0 {
				t.Fatalf("exit status = 0, want non-zero")
			}
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.want)
			}
			if strings.Contains(stderr, "failed to open") {
				t.Errorf("stderr = %q, want the argument error, not a file error", stderr)
			}
		})
	}
}

// TestArgumentErrorsIgnoreJSONFormat covers both spellings of the JSON option.
// Argument errors always use the ordinary stderr path.
func TestArgumentErrorsIgnoreJSONFormat(t *testing.T) {
	for _, args := range [][]string{
		{"-j", "--bogus"},
		{"--json", "--bogus"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := run(t, args...)
			if code == 0 {
				t.Errorf("exit status = 0 for an unknown flag, want non-zero")
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want it empty", stdout)
			}
			if !strings.Contains(stderr, "unknown flag: --bogus") {
				t.Errorf("stderr = %q, want a plain-text error", stderr)
			}
		})
	}
}

// TestCheckDoesNotReuseTheNamespaceKey guards the one change a consumer
// cannot notice: v0.1.0 reported the check outcome under .result.namespace, so
// that key must not come back holding the namespace itself.
func TestCheckDoesNotReuseTheNamespaceKey(t *testing.T) {
	f := newFixture(t, "file")

	stdout, _, _ := run(t, "-j", "check", "-f", f.data, "-s", f.signature, "-K", "-N")
	result, ok := decodeJSON(t, stdout)["result"].(map[string]any)
	if !ok {
		t.Fatalf("output %q is missing the result key", stdout)
	}
	if _, present := result["namespace"]; present {
		t.Errorf("result carries a namespace key again: %v", result["namespace"])
	}
	if result["designation"] != "disabled" {
		t.Errorf("designation = %v, want %q", result["designation"], "disabled")
	}
}
