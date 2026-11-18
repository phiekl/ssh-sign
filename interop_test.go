// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

func requireProgram(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return path
}

// requireKeyType skips unless ssh-keygen can generate keyType.
func requireKeyType(t *testing.T, keygen, keyType string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe")
	out, err := exec.Command(keygen, "-q", "-t", keyType, "-N", "", "-f", path).CombinedOutput()
	if err != nil {
		t.Skipf("%s cannot generate %s keys: %s", keygen, keyType, strings.TrimSpace(string(out)))
	}
}

func runProgram(t *testing.T, stdin string, program string, args ...string) string {
	t.Helper()
	command := exec.Command(program, args...)
	command.Stdin = strings.NewReader(stdin)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", program, args, err, out)
	}
	return string(out)
}

func runProgramStatus(t *testing.T, stdin string, program string, args ...string) (string, int) {
	t.Helper()
	command := exec.Command(program, args...)
	command.Stdin = strings.NewReader(stdin)
	out, err := command.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("%s %v: %v: %s", program, args, err, out)
	}
	return string(out), exitErr.ExitCode()
}

func generateOpenSSHKey(t *testing.T, keygen, keyType, path string) string {
	t.Helper()
	args := []string{"-q", "-t", keyType, "-N", "", "-C", "interop@example.com", "-f", path}
	if keyType == "rsa" {
		args = append(args[:3], append([]string{"-b", "2048"}, args[3:]...)...)
	}
	runProgram(t, "", keygen, args...)
	publicKey, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatalf("reading public key: %v", err)
	}
	fields := strings.Fields(string(publicKey))
	if len(fields) < 2 {
		t.Fatalf("public key = %q, want type and blob", publicKey)
	}
	return fields[0] + " " + fields[1]
}

func writeAllowedSigner(t *testing.T, path, principal, keyLine string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(principal+" "+keyLine+"\n"), 0o600); err != nil {
		t.Fatalf("writing allowed signers: %v", err)
	}
}

func startRealSSHAgent(t *testing.T) {
	t.Helper()
	agent := requireProgram(t, "ssh-agent")
	socket := filepath.Join(t.TempDir(), "agent.sock")
	out := runProgram(t, "", agent, "-a", socket, "-s")

	var pid string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "SSH_AGENT_PID=") {
			pid, _, _ = strings.Cut(strings.TrimPrefix(line, "SSH_AGENT_PID="), ";")
			break
		}
	}
	if pid == "" {
		t.Fatalf("ssh-agent output did not contain a PID: %q", out)
	}
	t.Setenv("SSH_AUTH_SOCK", socket)
	t.Setenv("SSH_AGENT_PID", pid)
	t.Cleanup(func() {
		command := exec.Command(agent, "-k")
		command.Env = os.Environ()
		_ = command.Run()
	})
}

func verifyWithOpenSSH(
	t *testing.T, keygen, allowed, signature, namespace, principal, data string,
) {
	t.Helper()
	runProgram(t, data, keygen,
		"-Y", "verify", "-f", allowed, "-I", principal, "-n", namespace, "-s", signature,
	)
}

func TestBidirectionalOpenSSHInterop(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	// OpenSSH 10.6 added mldsa44-ed25519.
	for _, keyType := range []string{"ed25519", "rsa", "ecdsa", "mldsa44-ed25519"} {
		t.Run(keyType, func(t *testing.T) {
			if keyType == "mldsa44-ed25519" {
				requireKeyType(t, keygen, keyType)
			}
			dir := t.TempDir()
			key := filepath.Join(dir, "key")
			dataPath := filepath.Join(dir, "data")
			allowed := filepath.Join(dir, "allowed_signers")
			const data = "bidirectional interoperability\n"
			if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
				t.Fatalf("writing data: %v", err)
			}
			keyLine := generateOpenSSHKey(t, keygen, keyType, key)
			writeAllowedSigner(t, allowed, "interop@example.com", keyLine)

			runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", dataPath)
			stdout, stderr, code := run(t, "verify",
				"-a", allowed, "-f", dataPath, "-s", dataPath+".sig",
				"-n", "file", "-p", "interop@example.com",
			)
			if code != 0 || !strings.Contains(stdout, "verification   = valid") {
				t.Fatalf("verifying OpenSSH signature: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}

			runProgram(t, "", sshAdd, key)
			armored, stderr, code := run(t, "sign", "-f", dataPath, "-k", keyLine, "-n", "file")
			if code != 0 {
				t.Fatalf("signing through ssh-agent: code=%d stderr=%q", code, stderr)
			}
			ourSignature := filepath.Join(dir, "ours.sig")
			if err := os.WriteFile(ourSignature, []byte(armored), 0o600); err != nil {
				t.Fatalf("writing signature: %v", err)
			}
			verifyWithOpenSSH(t, keygen, allowed, ourSignature, "file", "interop@example.com", data)
		})
	}
}

func TestRSACertificateOpenSSHInterop(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	ca := filepath.Join(dir, "ca")
	dataPath := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")
	const data = "certificate interoperability\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	generateOpenSSHKey(t, keygen, "rsa", key)
	generateOpenSSHKey(t, keygen, "ed25519", ca)
	runProgram(t, "", keygen,
		"-q", "-s", ca, "-I", "interop", "-n", "interop@example.com", "-V", "-1m:+1h", key+".pub",
	)
	certificate, err := os.ReadFile(key + "-cert.pub")
	if err != nil {
		t.Fatalf("reading certificate: %v", err)
	}
	fields := strings.Fields(string(certificate))
	certificateLine := fields[0] + " " + fields[1]
	writeAllowedSigner(t, allowed, "interop@example.com", certificateLine)
	runProgram(t, "", sshAdd, key)

	armored, stderr, code := run(t, "sign", "-f", dataPath, "-k", certificateLine, "-n", "file")
	if code != 0 {
		t.Fatalf("certificate signing: code=%d stderr=%q", code, stderr)
	}
	signature := filepath.Join(dir, "ours.sig")
	if err := os.WriteFile(signature, []byte(armored), 0o600); err != nil {
		t.Fatalf("writing signature: %v", err)
	}
	if inspected, stderr, code := run(t, "inspect", "-s", signature); code != 0 ||
		!strings.Contains(inspected, "ssh-rsa-cert-v01@openssh.com") ||
		!strings.Contains(inspected, "rsa-sha2-512") {
		t.Fatalf("certificate signature metadata: code=%d stdout=%q stderr=%q", code, inspected, stderr)
	}
	verifyWithOpenSSH(t, keygen, allowed, signature, "file", "interop@example.com", data)

	openSSHSignature := dataPath + ".sig"
	runProgram(t, "", keygen,
		"-Y", "sign", "-f", key+"-cert.pub", "-n", "file", dataPath,
	)
	stdout, stderr, code := run(t, "verify",
		"-a", allowed, "-f", dataPath, "-s", openSSHSignature,
		"-n", "file", "-p", "interop@example.com",
	)
	if code != 0 || !strings.Contains(stdout, "verification   = valid") {
		t.Fatalf("verifying OpenSSH certificate signature: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestSecurityKeyOpenSSHInterop(t *testing.T) {
	if os.Getenv("SSH_SIGN_TEST_SECURITY_KEY") == "" {
		t.Skip("set SSH_SIGN_TEST_SECURITY_KEY=1 with a FIDO authenticator attached")
	}
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	for _, keyType := range []string{"ed25519-sk", "ecdsa-sk"} {
		t.Run(keyType, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "key")
			dataPath := filepath.Join(dir, "data")
			allowed := filepath.Join(dir, "allowed_signers")
			const data = "security-key interoperability\n"
			runProgram(t, "", keygen,
				"-q", "-t", keyType, "-O", "no-touch-required", "-N", "", "-f", key,
			)
			publicKey, err := os.ReadFile(key + ".pub")
			if err != nil {
				t.Fatalf("reading public key: %v", err)
			}
			fields := strings.Fields(string(publicKey))
			keyLine := fields[0] + " " + fields[1]
			writeAllowedSigner(t, allowed, "interop@example.com", keyLine)
			if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
				t.Fatalf("writing data: %v", err)
			}

			runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", dataPath)
			if _, stderr, code := run(t, "verify",
				"-a", allowed, "-f", dataPath, "-s", dataPath+".sig",
				"-n", "file", "-p", "interop@example.com",
			); code != 0 {
				t.Fatalf("verifying OpenSSH security-key signature: code=%d stderr=%q", code, stderr)
			}

			runProgram(t, "", sshAdd, key)
			armored, stderr, code := run(t, "sign", "-f", dataPath, "-k", keyLine, "-n", "file")
			if code != 0 {
				t.Fatalf("security-key signing: code=%d stderr=%q", code, stderr)
			}
			signature := filepath.Join(dir, "ours.sig")
			if err := os.WriteFile(signature, []byte(armored), 0o600); err != nil {
				t.Fatalf("writing signature: %v", err)
			}
			verifyWithOpenSSH(t, keygen, allowed, signature, "file", "interop@example.com", data)
		})
	}
}

func TestAllowedSignersUnicodeAndControls(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	keyLine := generateOpenSSHKey(t, keygen, "ed25519", key)
	const data = "Unicode policy verification\n"
	for _, tt := range []struct {
		name     string
		value    string
		accepted bool
	}{
		{"accent", "Jos\u00e9", true},
		{"combining accent", "Jose\u0301", true},
		{"Chinese", "\u674e\u96f7", true},
		{"Arabic", "\u0639\u0644\u064a", true},
		{"symbol", "\U0001f511", true},
		{"nonbreaking space", "alice\u00a0smith", true},
		{"em space", "alice\u2003smith", true},
		{"escape", "alice\x1bsmith", false},
		{"DEL", "alice\x7fsmith", false},
		{"C1 control", "alice\u0085smith", false},
		{"direction override", "alice\u202esmith", false},
		{"zero width joiner", "alice\u200dsmith", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			caseDir := t.TempDir()
			dataPath := filepath.Join(caseDir, "data")
			allowed := filepath.Join(caseDir, "allowed_signers")
			if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", tt.value, dataPath)
			line := "\"" + tt.value + "\" namespaces=\"" + tt.value + "\" " + keyLine + "\n"
			if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}
			verifyWithOpenSSH(t, keygen, allowed, dataPath+".sig", tt.value, tt.value, data)
			_, stderr, code := run(t, "verify", "-a", allowed, "-f", dataPath,
				"-s", dataPath+".sig", "-n", tt.value, "-p", tt.value)
			if (code == 0) != tt.accepted {
				t.Fatalf("accepted = %v, want %v: %s", code == 0, tt.accepted, stderr)
			}
		})
	}
}

func TestAllowedSignersMatchesOpenSSH(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	dataPath := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")
	const data = "allowed-signers differential test\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	keyLine := generateOpenSSHKey(t, keygen, "ed25519", key)
	runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", dataPath)

	// The signer controls the namespace; metacharacters are special only in the pattern.
	const starNamespace = "*xblocked"
	starData := filepath.Join(dir, "star-data")
	if err := os.WriteFile(starData, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", starNamespace, starData)

	tests := []struct {
		name         string
		line         string
		principal    string
		namespace    string
		ourTime      string
		openSSHTime  string
		wantAccepted bool
		// stricter marks an entry that only ssh-keygen should accept.
		stricter bool
	}{
		{
			name: "plain", line: "alice@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "tabs", line: "alice@example.com\t" + strings.Replace(keyLine, " ", "\t", 1),
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name:      "opaque quote and escapes in comment",
			line:      `alice@example.com ` + keyLine + ` owner "unfinished\\comment`,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "principal wildcard", line: "*@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "principal negation", line: "*@example.com,!alice@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "namespace wildcard", line: `alice@example.com namespaces="f*" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "namespace negation", line: `alice@example.com namespaces="*,!file" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "namespace negation over a literal star", namespace: starNamespace,
			line:      `alice@example.com namespaces="*x*,!*blocked" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "namespace wildcard spans a literal star", namespace: starNamespace,
			line:      `alice@example.com namespaces="*blocked" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name:      "inside validity window",
			line:      `alice@example.com valid-after="20260101Z",valid-before="20260201Z" ` + keyLine,
			principal: "alice@example.com", ourTime: "2026-01-15T00:00:00Z",
			openSSHTime: "20260115Z", wantAccepted: true,
		},
		{
			name: "before validity window", line: `alice@example.com valid-after="20260201Z" ` + keyLine,
			principal: "alice@example.com", ourTime: "2026-01-15T00:00:00Z",
			openSSHTime: "20260115Z", wantAccepted: false,
		},
		{
			name: "after validity window", line: `alice@example.com valid-before="20260101Z" ` + keyLine,
			principal: "alice@example.com", ourTime: "2026-01-15T00:00:00Z",
			openSSHTime: "20260115Z", wantAccepted: false,
		},

		// ssh-keygen rejects unquoted option values, including namespaces=*.
		{
			name: "unquoted option value", line: `alice@example.com namespaces=file ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "unquoted wildcard option value", line: `alice@example.com namespaces=* ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "unquoted validity option", line: `alice@example.com valid-after=20200101Z ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "empty unquoted option value", line: `alice@example.com namespaces= ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name: "empty quoted option value", line: `alice@example.com namespaces="" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},

		// ssh-keygen ends the field at the first closing quote.
		{
			name: "quoted principal", line: `"alice@example.com" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "quoted principal list", line: `"alice@example.com,bob@example.com" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "spliced quoted principals", line: `"alice@example.com,bob","carol" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},

		// Quotes must not disable exclusions.
		{
			name: "quoted negation", line: `*,!"alice@example.com" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name:      "quoted negation of another principal",
			line:      `*,!"bob@example.com" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "quoted principal escaping a quote", line: `"alice@example.com\"x" ` + keyLine,
			principal: `alice@example.com"x`, wantAccepted: false,
		},
		{
			name: "text after the closing quote", line: `"alice@example.com",bob ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},

		// Only OpenSSH's whitespace separates fields; U+00A0 stays in the field.
		{
			name:      "nonbreaking space after the principal",
			line:      "alice@example.com\u00a0 " + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name:      "nonbreaking space before the principal",
			line:      "\u00a0alice@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name:      "nonbreaking space in a validity option",
			line:      "alice@example.com valid-after=\"20200101\u00a0\" " + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},

		// ssh-keygen ignores option name case; ssh-sign requires lowercase.
		{
			name:      "uppercase option name",
			line:      `alice@example.com NAMESPACES="file" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false, stricter: true,
		},

		// Reject stray CR and NUL bytes, even where ssh-keygen accepts the line.
		{
			name:      "carriage return after the principal",
			line:      "alice@example.com\r " + keyLine,
			principal: "alice@example.com", wantAccepted: false, stricter: true,
		},
		{
			name:      "carriage return before the key type",
			line:      "alice@example.com\r" + keyLine,
			principal: "alice@example.com", wantAccepted: false, stricter: true,
		},
		{
			name:      "carriage return inside the key",
			line:      "alice@example.com " + keyLine + "\rcomment",
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name:      "NUL hides a second principal",
			line:      "alice@example.com\x00,bob@example.com " + keyLine,
			principal: "bob@example.com", wantAccepted: false,
		},
		{
			name:      "NUL in an option value",
			line:      "alice@example.com namespaces=\"file,other\x00\" " + keyLine,
			principal: "alice@example.com", wantAccepted: false,
		},
		{
			name:      "NUL in the key comment",
			line:      "alice@example.com " + keyLine + " comment\x00more",
			principal: "alice@example.com", wantAccepted: false, stricter: true,
		},

		// Empty pattern elements match only empty values.
		{
			name: "empty pattern in principals", line: "alice@example.com,,bob@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "empty pattern in namespaces", line: `alice@example.com namespaces="file,,x" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},

		// Malformed lines must not prevent later entries from matching.
		{
			name: "cert-authority line before a usable one",
			line: "bob@example.com cert-authority " + keyLine + "\n" +
				"alice@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "unparseable line before a usable one",
			line: "this is not an entry\n" +
				"alice@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "unknown option before a usable one",
			line: `bob@example.com unknownopt="x" ` + keyLine + "\n" +
				"alice@example.com " + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(allowed, []byte(tt.line+"\n"), 0o600); err != nil {
				t.Fatalf("writing allowed signers: %v", err)
			}
			namespace, signed := "file", dataPath
			if tt.namespace != "" {
				namespace, signed = tt.namespace, starData
			}
			ourArgs := []string{
				"verify", "-a", allowed, "-f", signed, "-s", signed + ".sig",
				"-n", namespace, "-p", tt.principal,
			}
			if tt.ourTime != "" {
				ourArgs = append(ourArgs, "-t", tt.ourTime)
			}
			_, _, ourCode := run(t, ourArgs...)

			openSSHArgs := []string{
				"-Y", "verify", "-f", allowed, "-I", tt.principal,
				"-n", namespace, "-s", signed + ".sig",
			}
			if tt.openSSHTime != "" {
				openSSHArgs = append(openSSHArgs, "-O", "verify-time="+tt.openSSHTime)
			}
			openSSHOutput, openSSHCode := runProgramStatus(t, data, keygen, openSSHArgs...)
			ourAccepted := ourCode == 0
			openSSHAccepted := openSSHCode == 0
			// Only cases marked stricter may differ from ssh-keygen.
			if wantOpenSSH := tt.wantAccepted || tt.stricter; openSSHAccepted != wantOpenSSH {
				t.Errorf("OpenSSH accepted = %v, want %v (OpenSSH output: %q)",
					openSSHAccepted, wantOpenSSH, openSSHOutput)
			}
			if ourAccepted != tt.wantAccepted {
				t.Errorf("accepted = %v, want %v", ourAccepted, tt.wantAccepted)
			}
		})
	}
}

// TestArmorMatchesOpenSSHByteForByte pins the signature file format itself:
// ed25519 signatures are deterministic, so signing the same data with the same
// key must produce exactly the bytes ssh-keygen writes.
func TestArmorMatchesOpenSSHByteForByte(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	dataPath := filepath.Join(dir, "data")
	const data = "byte-for-byte interoperability\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	keyLine := generateOpenSSHKey(t, keygen, "ed25519", key)

	runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", dataPath)
	want, err := os.ReadFile(dataPath + ".sig")
	if err != nil {
		t.Fatalf("reading OpenSSH signature: %v", err)
	}

	runProgram(t, "", sshAdd, key)
	stdout, stderr, code := run(t, "sign", "-f", dataPath, "-k", keyLine, "-n", "file")
	if code != 0 {
		t.Fatalf("signing through ssh-agent: code=%d stderr=%q", code, stderr)
	}
	if stdout != string(want) {
		t.Errorf("signature =\n%s\nwant ssh-keygen's\n%s", stdout, want)
	}
}

// TestSHA256OpenSSHInterop covers the hash algorithm ssh-keygen only uses when
// asked for it.
func TestSHA256OpenSSHInterop(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")

	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	dataPath := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")
	const data = "sha256 interoperability\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	keyLine := generateOpenSSHKey(t, keygen, "ed25519", key)
	writeAllowedSigner(t, allowed, "interop@example.com", keyLine)

	runProgram(t, "", keygen,
		"-Y", "sign", "-f", key, "-n", "file", "-O", "hashalg=sha256", dataPath,
	)
	signature := dataPath + ".sig"

	stdout, stderr, code := run(t, "verify",
		"-a", allowed, "-f", dataPath, "-s", signature, "-n", "file", "-p", "interop@example.com",
	)
	if code != 0 || !strings.Contains(stdout, "verification   = valid") {
		t.Fatalf("verifying sha256 signature: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if inspected, stderr, code := run(t, "inspect", "-s", signature); code != 0 ||
		!strings.Contains(inspected, "sha256") {
		t.Fatalf("sha256 signature metadata: code=%d stdout=%q stderr=%q", code, inspected, stderr)
	}
}

// signWithOpenSSHCertificate issues a certificate for key and signs dataPath
// with it through the agent, returning the certificate's key line and the
// signature path. Extra arguments go to ssh-keygen -s, e.g. -n and -V.
func signWithOpenSSHCertificate(
	t *testing.T, keygen, sshAdd, ca, key, dataPath, name string, extra ...string,
) (string, string) {
	t.Helper()
	args := append([]string{"-q", "-s", ca, "-I", name}, extra...)
	runProgram(t, "", keygen, append(args, key+".pub")...)
	certificate, err := os.ReadFile(key + "-cert.pub")
	if err != nil {
		t.Fatalf("reading certificate: %v", err)
	}
	fields := strings.Fields(string(certificate))
	// ssh-add loads key-cert.pub with the key, so the agent can sign with it.
	runProgram(t, "", sshAdd, "-q", key)
	signed := dataPath + "." + name
	if err := os.Link(dataPath, signed); err != nil {
		t.Fatalf("linking data: %v", err)
	}
	runProgram(t, "", keygen, "-Y", "sign", "-f", key+"-cert.pub", "-n", "file", signed)
	return fields[0] + " " + fields[1], signed + ".sig"
}

func TestCertAuthorityMatchesOpenSSH(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	ca := filepath.Join(dir, "ca")
	otherCA := filepath.Join(dir, "other-ca")
	dataPath := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")
	const data = "cert-authority differential test\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	generateOpenSSHKey(t, keygen, "ed25519", key)
	caLine := generateOpenSSHKey(t, keygen, "ed25519", ca)
	generateOpenSSHKey(t, keygen, "ed25519", otherCA)

	const principals = "alice@example.com,bob@example.com"
	sign := func(name string, extra ...string) (string, string) {
		return signWithOpenSSHCertificate(t, keygen, sshAdd, ca, key, dataPath, name, extra...)
	}
	goodLine, good := sign("good", "-n", principals, "-V", "-1d:+1d")
	// The agent can refuse to sign with an expired or not-yet-valid certificate.
	// Exercise both cases by changing the verification time instead.
	now := time.Now().UTC()
	_, noPrincipals := sign("no-principals", "-V", "-1d:+1d")
	_, host := sign("host", "-h", "-n", principals, "-V", "-1d:+1d")
	_, starPrincipal := sign("star", "-n", "*", "-V", "-1d:+1d")
	_, foreign := signWithOpenSSHCertificate(t, keygen, sshAdd, otherCA, key, dataPath,
		"foreign", "-n", principals, "-V", "-1d:+1d")
	plain := filepath.Join(dir, "data.plain")
	if err := os.Link(dataPath, plain); err != nil {
		t.Fatalf("linking data: %v", err)
	}
	runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", plain)
	plain += ".sig"
	byCA := filepath.Join(dir, "data.ca")
	if err := os.Link(dataPath, byCA); err != nil {
		t.Fatalf("linking data: %v", err)
	}
	runProgram(t, "", keygen, "-Y", "sign", "-f", ca, "-n", "file", byCA)
	byCA += ".sig"

	tests := []struct {
		name, line, principal, signature string
		wantAccepted                     bool
		verifyTime                       time.Time
		// stricter marks an entry that only ssh-keygen should accept.
		stricter bool
	}{
		{name: "listed principal", line: "alice@example.com cert-authority " + caLine,
			principal: "alice@example.com", signature: good, wantAccepted: true},
		{name: "wildcard line", line: "*@example.com cert-authority " + caLine,
			principal: "bob@example.com", signature: good, wantAccepted: true},
		{name: "principal not in the line", line: "alice@example.com cert-authority " + caLine,
			principal: "bob@example.com", signature: good},
		{name: "principal not in the certificate", line: "* cert-authority " + caLine,
			principal: "carol@example.com", signature: good},
		{name: "requested principal is not a pattern", line: "* cert-authority " + caLine,
			principal: "alice@*", signature: good},
		{name: "certificate principal is not a pattern", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: starPrincipal},
		{name: "expired certificate", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: good, verifyTime: now.Add(48 * time.Hour)},
		{name: "future certificate", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: good, verifyTime: now.Add(-48 * time.Hour)},
		{name: "no certificate principals", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: noPrincipals},
		{name: "host certificate", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: host},
		{name: "another CA", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: foreign},
		{name: "plain key signature", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: plain},
		{name: "signed by the CA key", line: "* cert-authority " + caLine,
			principal: "alice@example.com", signature: byCA},
		{name: "namespace allowed", line: `* cert-authority,namespaces="file" ` + caLine,
			principal: "alice@example.com", signature: good, wantAccepted: true},
		{name: "namespace denied", line: `* namespaces="git",cert-authority ` + caLine,
			principal: "alice@example.com", signature: good},
		{name: "entry expired", line: `* cert-authority,valid-before="20200101Z" ` + caLine,
			principal: "alice@example.com", signature: good},
		{name: "falls through to the certificate",
			line:      `* cert-authority,namespaces="git" ` + caLine + "\nalice@example.com " + goodLine,
			principal: "alice@example.com", signature: good, wantAccepted: true},
		{name: "falls through to the CA",
			line:      "carol@example.com cert-authority " + caLine + "\n* cert-authority " + caLine,
			principal: "alice@example.com", signature: good, wantAccepted: true},
		{name: "uppercase option", line: "* CERT-AUTHORITY " + caLine,
			principal: "alice@example.com", signature: good, stricter: true},
		{name: "repeated option", line: "* cert-authority,cert-authority " + caLine,
			principal: "alice@example.com", signature: good, stricter: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(allowed, []byte(tt.line+"\n"), 0o600); err != nil {
				t.Fatalf("writing allowed signers: %v", err)
			}
			ourArgs := []string{"verify", "-a", allowed, "-f", dataPath, "-s", tt.signature,
				"-n", "file", "-p", tt.principal}
			openSSHArgs := []string{"-Y", "verify", "-f", allowed, "-I", tt.principal,
				"-n", "file", "-s", tt.signature}
			if !tt.verifyTime.IsZero() {
				ourArgs = append(ourArgs, "-t", tt.verifyTime.Format(time.RFC3339))
				openSSHArgs = append(openSSHArgs, "-O", "verify-time="+tt.verifyTime.Format("20060102150405Z"))
			}
			_, _, ourCode := run(t, ourArgs...)
			openSSHOutput, openSSHCode := runProgramStatus(t, data, keygen, openSSHArgs...)
			if wantOpenSSH := tt.wantAccepted || tt.stricter; (openSSHCode == 0) != wantOpenSSH {
				t.Errorf("OpenSSH accepted = %v, want %v (OpenSSH output: %q)",
					openSSHCode == 0, wantOpenSSH, openSSHOutput)
			}
			if (ourCode == 0) != tt.wantAccepted {
				t.Errorf("accepted = %v, want %v", ourCode == 0, tt.wantAccepted)
			}
		})
	}

	// Without -p, report what ssh-keygen -Y find-principals prints, except
	// that ssh-keygen ignores exclusions there.
	for _, tt := range []struct {
		principals, want string
		stricter         bool
	}{
		{principals: "*", want: principals},
		{principals: "alice@example.com,carol@example.com", want: "alice@example.com"},
		{principals: "alice@example.com,*", want: principals},
		{principals: "carol@example.com"},
		{principals: "carol@example.com,,alice@example.com"},
		{principals: "!alice@example.com"},
		{principals: "!alice@example.com,*", want: "bob@example.com", stricter: true},
		{principals: "!alice@example.com,!bob@example.com,*", stricter: true},
	} {
		t.Run("find-principals "+tt.principals, func(t *testing.T) {
			line := tt.principals + " cert-authority " + caLine + "\n"
			if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
				t.Fatalf("writing allowed signers: %v", err)
			}
			stdout, _, ourCode := run(t, "verify", "-j", "-a", allowed, "-f", dataPath, "-s", good,
				"-n", "file")
			openSSHOutput, openSSHCode := runProgramStatus(t, "", keygen, "-Y", "find-principals",
				"-f", allowed, "-s", good)
			var got, found []string
			if ourCode == 0 {
				result, _ := decodeJSON(t, stdout)["result"].(map[string]any)
				principal, _ := result["principal"].(string)
				got = strings.Split(principal, ",")
			}
			if openSSHCode == 0 {
				found = strings.Fields(openSSHOutput)
				slices.Sort(found)
				found = slices.Compact(found)
			}
			if strings.Join(got, ",") != tt.want {
				t.Errorf("principals = %q, want %q", got, tt.want)
			}
			if !tt.stricter && !slices.Equal(got, found) {
				t.Errorf("principals = %q, OpenSSH found %q", got, found)
			}
			for _, p := range got {
				if !slices.Contains(found, p) {
					t.Errorf("principal %q not found by OpenSSH (output: %q)", p, openSSHOutput)
				}
			}
		})
	}
}

func TestRevokedKeysMatchOpenSSH(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	ca := filepath.Join(dir, "ca")
	other := filepath.Join(dir, "other")
	dataPath := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")
	revoked := filepath.Join(dir, "revoked")
	const data = "revoked keys differential test\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	keyLine := generateOpenSSHKey(t, keygen, "ed25519", key)
	caLine := generateOpenSSHKey(t, keygen, "ed25519", ca)
	otherLine := generateOpenSSHKey(t, keygen, "ed25519", other)
	certLine, certSig := signWithOpenSSHCertificate(t, keygen, sshAdd, ca, key, dataPath,
		"cert", "-n", "alice@example.com", "-V", "-1d:+1d", "-z", "40")
	_, renewedSig := signWithOpenSSHCertificate(t, keygen, sshAdd, ca, key, dataPath,
		"renewed", "-n", "alice@example.com", "-V", "-1d:+1d", "-z", "41")
	runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", dataPath)
	plainSig := dataPath + ".sig"
	writeAllowedSigner(t, allowed, "alice@example.com", keyLine+"\n* cert-authority "+caLine)

	tests := []struct {
		name, content string
		// revokedPlain and revokedCert report which signatures are rejected.
		revokedPlain, revokedCert bool
		// stricter marks content that only ssh-sign rejects.
		stricter bool
	}{
		{name: "empty"},
		{name: "signer key", content: keyLine + "\n", revokedPlain: true, revokedCert: true},
		{name: "certificate", content: certLine + "\n", revokedPlain: true, revokedCert: true},
		{name: "CA key", content: caLine + "\n", revokedCert: true},
		{name: "other key", content: otherLine + "\n"},
		{name: "comments and whitespace",
			content: "# revoked\n\n \t\n  # indented\n\t " + otherLine + "  lost laptop\n"},
		{name: "CRLF", content: otherLine + "\r\n" + keyLine + "\r\n", revokedPlain: true, revokedCert: true},
		{name: "no final newline", content: keyLine, revokedPlain: true, revokedCert: true},
		{name: "garbage", content: "garbage\n", revokedPlain: true, revokedCert: true},
		{name: "garbage after other key", content: otherLine + "\ngarbage\n",
			revokedPlain: true, revokedCert: true},
		{name: "type only", content: "ssh-ed25519\n", revokedPlain: true, revokedCert: true},
		{name: "no type", content: strings.Fields(otherLine)[1] + "\n",
			revokedPlain: true, revokedCert: true},
		{name: "type mismatch", content: "ssh-rsa " + strings.Fields(otherLine)[1] + "\n",
			revokedPlain: true, revokedCert: true},
		{name: "options", content: "cert-authority " + otherLine + "\n",
			revokedPlain: true, revokedCert: true},
		{name: "NUL starts a line", content: "\x00" + otherLine + "\n",
			revokedPlain: true, revokedCert: true, stricter: true},
	}

	check := func(t *testing.T, path string, signature string, wantRevoked, stricter bool) {
		t.Helper()
		_, _, ourCode := run(t, "verify", "-a", allowed, "-r", path, "-f", dataPath, "-s", signature,
			"-n", "file", "-p", "alice@example.com")
		openSSHOutput, openSSHCode := runProgramStatus(t, data, keygen, "-Y", "verify",
			"-f", allowed, "-r", path, "-I", "alice@example.com", "-n", "file", "-s", signature)
		if wantOpenSSH := !wantRevoked || stricter; (openSSHCode == 0) != wantOpenSSH {
			t.Errorf("OpenSSH accepted = %v, want %v (OpenSSH output: %q)",
				openSSHCode == 0, wantOpenSSH, openSSHOutput)
		}
		if (ourCode == 0) != !wantRevoked {
			t.Errorf("accepted = %v, want %v", ourCode == 0, !wantRevoked)
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(revoked, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("writing revoked keys: %v", err)
			}
			check(t, revoked, plainSig, tt.revokedPlain, tt.stricter)
			check(t, revoked, certSig, tt.revokedCert, tt.stricter)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		check(t, filepath.Join(dir, "missing"), plainSig, true, false)
	})
	for _, tt := range []struct {
		name, spec, authority              string
		revokePlain, revokeCert, revokeNew bool
	}{
		{name: "KRL unrelated key", spec: otherLine},
		{name: "KRL signer key", spec: keyLine, revokePlain: true, revokeCert: true, revokeNew: true},
		{name: "KRL CA key", spec: caLine, revokeCert: true, revokeNew: true},
		{name: "KRL signer SHA1", spec: "sha1: " + keyLine, revokePlain: true, revokeCert: true, revokeNew: true},
		{name: "KRL CA SHA256", spec: "sha256: " + caLine, revokeCert: true, revokeNew: true},
		{name: "KRL certificate serial", spec: "serial: 40", authority: ca + ".pub", revokeCert: true},
		{name: "KRL certificate range", spec: "serial: 40-41", authority: ca + ".pub", revokeCert: true, revokeNew: true},
		{name: "KRL certificate key ID", spec: "id: cert", authority: ca + ".pub", revokeCert: true},
		{name: "KRL serial from another CA", spec: "serial: 40", authority: other + ".pub"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec := filepath.Join(t.TempDir(), "spec")
			krl := filepath.Join(filepath.Dir(spec), "revoked.krl")
			if err := os.WriteFile(spec, []byte(tt.spec+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-q", "-k", "-f", krl}
			if tt.authority != "" {
				args = append(args, "-s", tt.authority)
			}
			runProgram(t, "", keygen, append(args, spec)...)
			check(t, krl, plainSig, tt.revokePlain, false)
			check(t, krl, certSig, tt.revokeCert, false)
			check(t, krl, renewedSig, tt.revokeNew, false)
		})
	}
	t.Run("KRL with reserved flags, empty sections and NUL terminators", func(t *testing.T) {
		record := func(kind byte, data []byte) []byte {
			return ssh.Marshal(struct {
				Type byte
				Data []byte
			}{kind, data})
		}
		extension := ssh.Marshal(struct {
			Name     string
			Critical bool
			Data     []byte
		}{Name: "optional@example.test\x00"})
		certificates := ssh.Marshal(struct{ CA, Reserved []byte }{})
		certificates = append(certificates, record(0x23, nil)...)
		certificates = append(certificates, record(0x23, ssh.Marshal(struct{ ID string }{"cert\x00"}))...)
		certificates = append(certificates, record(0x39, extension)...)
		header := ssh.Marshal(struct {
			Format                    uint32
			Version, Generated, Flags uint64
			Reserved, Comment         string
		}{Format: 1, Flags: 1, Comment: "comment\x00"})
		data := append([]byte("SSHKRL\n\x00"), header...)
		for _, kind := range []byte{2, 3, 5} {
			data = append(data, record(kind, nil)...)
		}
		data = append(data, record(255, extension)...)
		data = append(data, record(1, certificates)...)

		krl := filepath.Join(t.TempDir(), "revoked.krl")
		if err := os.WriteFile(krl, data, 0o600); err != nil {
			t.Fatal(err)
		}
		check(t, krl, plainSig, false, false)
		check(t, krl, certSig, true, false)
		check(t, krl, renewedSig, false, false)
	})
	// OpenSSH fails to load a KRL whose serial bitmap exceeds 2048 bytes.
	for _, tt := range []struct {
		name    string
		size    int
		revoked bool
	}{
		{name: "KRL largest serial bitmap", size: 2048},
		{name: "KRL oversized serial bitmap", size: 3000, revoked: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bits := make([]byte, tt.size)
			bits[0] = 1
			bitmap := ssh.Marshal(struct {
				Offset uint64
				Bits   []byte
			}{1000, bits})
			section := ssh.Marshal(struct {
				CA, Reserved []byte
				Type         byte
				Data         []byte
			}{Type: 0x22, Data: bitmap})
			header := ssh.Marshal(struct {
				Format                    uint32
				Version, Generated, Flags uint64
				Reserved, Comment         []byte
				Type                      byte
				Data                      []byte
			}{Format: 1, Type: 1, Data: section})
			krl := filepath.Join(t.TempDir(), "revoked.krl")
			if err := os.WriteFile(krl, append([]byte("SSHKRL\n\x00"), header...), 0o600); err != nil {
				t.Fatal(err)
			}
			check(t, krl, plainSig, tt.revoked, false)
			check(t, krl, certSig, tt.revoked, false)
		})
	}
}

// rawKey is a public key with a fixed encoding.
type rawKey struct {
	keyType string
	blob    []byte
}

func (k rawKey) Type() string                      { return k.keyType }
func (k rawKey) Marshal() []byte                   { return k.blob }
func (rawKey) Verify([]byte, *ssh.Signature) error { return errors.New("not a signer") }

// TestCertificateEncodingMatchesOpenSSH swaps re-encoded and forged
// certificates into an OpenSSH signature; the signed data does not cover the
// public key.
func TestCertificateEncodingMatchesOpenSSH(t *testing.T) {
	keygen := requireProgram(t, "ssh-keygen")
	sshAdd := requireProgram(t, "ssh-add")
	startRealSSHAgent(t)

	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	ca := filepath.Join(dir, "ca")
	dataPath := filepath.Join(dir, "data")
	allowed := filepath.Join(dir, "allowed_signers")
	revoked := filepath.Join(dir, "revoked")
	const data = "certificate encoding differential test\n"
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	keyLine := generateOpenSSHKey(t, keygen, "ed25519", key)
	caLine := generateOpenSSHKey(t, keygen, "ed25519", ca)
	certLine, certSig := signWithOpenSSHCertificate(t, keygen, sshAdd, ca, key, dataPath,
		"cert", "-n", "alice@example.com", "-V", "-1d:+1d")

	caPEM, err := os.ReadFile(ca)
	if err != nil {
		t.Fatalf("reading CA key: %v", err)
	}
	caSigner, err := ssh.ParsePrivateKey(caPEM)
	if err != nil {
		t.Fatalf("parsing CA key: %v", err)
	}
	armored, err := os.ReadFile(certSig)
	if err != nil {
		t.Fatalf("reading signature: %v", err)
	}
	sig, err := sshsig.SignatureRead(bytes.NewReader(armored))
	if err != nil {
		t.Fatalf("reading signature: %v", err)
	}
	original := sig.PublicKey.Marshal()
	cert, err := sshsig.AsCertificate(sig.PublicKey)
	if err != nil || cert == nil {
		t.Fatalf("AsCertificate() = %v, %v", cert, err)
	}

	// Encode the empty permit-pty payload as an encoded empty string.
	extensions := func(ptyPayload string) []byte {
		var tuples []byte
		for _, name := range slices.Sorted(maps.Keys(cert.Extensions)) {
			payload := cert.Extensions[name]
			if name == "permit-pty" {
				payload = ptyPayload
			}
			tuples = append(tuples, ssh.Marshal(struct{ N, P string }{name, payload})...)
		}
		return ssh.Marshal(struct{ B []byte }{tuples})
	}
	sigField := ssh.Marshal(struct{ B []byte }{ssh.Marshal(cert.Signature)})
	signed := original[:len(original)-len(sigField)]
	reencoded := bytes.Replace(signed, extensions(""), extensions("\x00\x00\x00\x00"), 1)
	if bytes.Equal(reencoded, signed) {
		t.Fatal("permit-pty extension not found")
	}
	tampered := append(slices.Clone(reencoded), sigField...)
	resig, err := caSigner.Sign(rand.Reader, reencoded)
	if err != nil {
		t.Fatalf("re-signing: %v", err)
	}
	resigned := append(slices.Clone(reencoded), ssh.Marshal(struct{ B []byte }{ssh.Marshal(resig)})...)

	writeSig := func(name string, blob []byte) string {
		sig.PublicKey = rawKey{keyType: cert.Type(), blob: blob}
		path := filepath.Join(dir, name+".sig")
		if err := os.WriteFile(path, sshsig.Armor(sig), 0o600); err != nil {
			t.Fatalf("writing signature: %v", err)
		}
		return path
	}
	lineOf := func(blob []byte) string {
		return cert.Type() + " " + base64.StdEncoding.EncodeToString(blob)
	}
	tamperedSig := writeSig("tampered", tampered)
	resignedSig := writeSig("resigned", resigned)

	// A forged revoked certificate names another key under the CA's signature.
	forged := *cert
	forged.Key, _, _, _, err = ssh.ParseAuthorizedKey(
		[]byte(generateOpenSSHKey(t, keygen, "ed25519", filepath.Join(dir, "other"))))
	if err != nil {
		t.Fatalf("parsing other key: %v", err)
	}
	forgedLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(&forged)))

	tests := []struct {
		name, allowed, revoked, signature string
		wantAccepted                      bool
	}{
		{name: "original", allowed: "* cert-authority " + caLine, signature: certSig, wantAccepted: true},
		{name: "re-encoded without re-signing", allowed: "* cert-authority " + caLine,
			signature: tamperedSig},
		{name: "re-encoded and re-signed", allowed: "* cert-authority " + caLine,
			signature: resignedSig, wantAccepted: true},
		{name: "re-encoded entry matches itself", allowed: "alice@example.com " + lineOf(resigned),
			signature: resignedSig, wantAccepted: true},
		{name: "re-encoded entry differs from the original",
			allowed: "alice@example.com " + certLine, signature: resignedSig},
		{name: "forged revoked certificate", allowed: "* cert-authority " + caLine,
			revoked: forgedLine + "\n", signature: certSig},
		{name: "forged revoked certificate, plain key", allowed: "alice@example.com " + keyLine,
			revoked: forgedLine + "\n", signature: filepath.Join(dir, "plain.sig")},
	}
	plainData := filepath.Join(dir, "plain")
	if err := os.WriteFile(plainData, []byte(data), 0o600); err != nil {
		t.Fatalf("writing data: %v", err)
	}
	runProgram(t, "", keygen, "-Y", "sign", "-f", key, "-n", "file", plainData)
	if err := os.Rename(plainData+".sig", filepath.Join(dir, "plain.sig")); err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(allowed, []byte(tt.allowed+"\n"), 0o600); err != nil {
				t.Fatalf("writing allowed signers: %v", err)
			}
			ourArgs := []string{"verify", "-a", allowed, "-f", dataPath, "-s", tt.signature,
				"-n", "file", "-p", "alice@example.com"}
			openSSHArgs := []string{"-Y", "verify", "-f", allowed, "-I", "alice@example.com",
				"-n", "file", "-s", tt.signature}
			if tt.revoked != "" {
				if err := os.WriteFile(revoked, []byte(tt.revoked), 0o600); err != nil {
					t.Fatalf("writing revoked keys: %v", err)
				}
				ourArgs = append(ourArgs, "-r", revoked)
				openSSHArgs = append(openSSHArgs, "-r", revoked)
			}
			_, ourErr, ourCode := run(t, ourArgs...)
			openSSHOutput, openSSHCode := runProgramStatus(t, data, keygen, openSSHArgs...)
			if (openSSHCode == 0) != tt.wantAccepted {
				t.Errorf("OpenSSH accepted = %v, want %v (OpenSSH output: %q)",
					openSSHCode == 0, tt.wantAccepted, openSSHOutput)
			}
			if (ourCode == 0) != tt.wantAccepted {
				t.Errorf("accepted = %v, want %v (stderr: %q)", ourCode == 0, tt.wantAccepted, ourErr)
			}
		})
	}
}
