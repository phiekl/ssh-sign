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
			name: "namespace wildcard", line: `alice@example.com NAMESPACES="f*" ` + keyLine,
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
