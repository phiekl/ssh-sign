// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireProgram(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return path
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

	for _, keyType := range []string{"ed25519", "rsa", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
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

	tests := []struct {
		name         string
		line         string
		principal    string
		ourTime      string
		openSSHTime  string
		wantAccepted bool
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
			name: "namespace wildcard", line: `alice@example.com NAMESPACES="f*" ` + keyLine,
			principal: "alice@example.com", wantAccepted: true,
		},
		{
			name: "namespace negation", line: `alice@example.com namespaces="*,!file" ` + keyLine,
			principal: "alice@example.com", wantAccepted: false,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(allowed, []byte(tt.line+"\n"), 0o600); err != nil {
				t.Fatalf("writing allowed signers: %v", err)
			}
			ourArgs := []string{
				"verify", "-a", allowed, "-f", dataPath, "-s", dataPath + ".sig",
				"-n", "file", "-p", tt.principal,
			}
			if tt.ourTime != "" {
				ourArgs = append(ourArgs, "-t", tt.ourTime)
			}
			_, _, ourCode := run(t, ourArgs...)

			openSSHArgs := []string{
				"-Y", "verify", "-f", allowed, "-I", tt.principal,
				"-n", "file", "-s", dataPath + ".sig",
			}
			if tt.openSSHTime != "" {
				openSSHArgs = append(openSSHArgs, "-O", "verify-time="+tt.openSSHTime)
			}
			openSSHOutput, openSSHCode := runProgramStatus(t, data, keygen, openSSHArgs...)
			ourAccepted := ourCode == 0
			openSSHAccepted := openSSHCode == 0
			if ourAccepted != openSSHAccepted {
				t.Errorf("acceptance differs: ssh-sign=%v OpenSSH=%v (OpenSSH output: %q)",
					ourAccepted, openSSHAccepted, openSSHOutput)
			}
			if ourAccepted != tt.wantAccepted {
				t.Errorf("accepted = %v, want %v", ourAccepted, tt.wantAccepted)
			}
		})
	}
}
