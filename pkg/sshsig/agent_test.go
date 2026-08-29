// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newEd25519Key() (ssh.PublicKey, ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return signer.PublicKey(), privateKey, nil
}

type failingListAgent struct {
	agent.Agent
}

func (f failingListAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("list failed")
}

type failingSignAgent struct {
	agent.Agent
}

func (f failingSignAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, errors.New("sign failed")
}

func listenAgent(t *testing.T, served agent.Agent) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(served, conn)
			}()
		}
	}()
	return socket
}

func TestAgentConnectFailures(t *testing.T) {
	t.Run("missing environment", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", "")
		if _, _, err := AgentConnect(nil); err == nil || !strings.Contains(err.Error(), "not set") {
			t.Fatalf("AgentConnect() error = %v, want SSH_AUTH_SOCK error", err)
		}
	})

	t.Run("missing socket", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing.sock"))
		if _, _, err := AgentConnect(nil); err == nil || !strings.Contains(err.Error(), "failed to connect") {
			t.Fatalf("AgentConnect() error = %v, want connection error", err)
		}
	})
}

func TestAgentSignerFailures(t *testing.T) {
	key := newSigner(t).PublicKey()

	t.Run("listing", func(t *testing.T) {
		if _, err := AgentSigner(nil, nil, failingListAgent{}, key); err == nil ||
			!strings.Contains(err.Error(), "failed listing keys") {
			t.Fatalf("AgentSigner() error = %v, want listing error", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := AgentSigner(nil, nil, agent.NewKeyring(), key); err == nil ||
			!strings.Contains(err.Error(), "no keys found") {
			t.Fatalf("AgentSigner() error = %v, want empty-agent error", err)
		}
	})

	t.Run("unmatched", func(t *testing.T) {
		keyring := agent.NewKeyring()
		_, privateKey, err := newEd25519Key()
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
			t.Fatalf("adding key: %v", err)
		}
		if _, err := AgentSigner(nil, nil, keyring, key); err == nil || !strings.Contains(err.Error(), "no key matched") {
			t.Fatalf("AgentSigner() error = %v, want unmatched-key error", err)
		}
	})
}

func TestAgentDisconnectDuringListing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", socket)
	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := AgentSigner(nil, conn, client, newSigner(t).PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "failed listing keys") {
		t.Fatalf("AgentSigner() error = %v, want disconnect error", err)
	}
}

func TestAgentMalformedReplyDuringListing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte{0, 0, 0, 1, 0xff})
	}()

	t.Setenv("SSH_AUTH_SOCK", socket)
	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := AgentSigner(nil, conn, client, newSigner(t).PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "failed listing keys") {
		t.Fatalf("AgentSigner() error = %v, want malformed-reply error", err)
	}
}

func TestNonresponsiveAgentCanBeInterruptedByClosingConnection(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", socket)
	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	serverConn := <-accepted
	defer func() { _ = serverConn.Close() }()

	done := make(chan error, 1)
	go func() {
		_, err := AgentSigner(nil, conn, client, newSigner(t).PublicKey())
		done <- err
	}()
	_ = conn.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AgentSigner() returned nil after its connection was closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AgentSigner() remained blocked after its connection was closed")
	}
}

func TestWedgedAgentTimesOutWhileListing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("cannot listen on a unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", socket)
	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	serverConn := <-accepted
	defer func() { _ = serverConn.Close() }()

	done := make(chan error, 1)
	go func() {
		_, err := agentSigner(nil, conn, client, newSigner(t).PublicKey(), 100*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "no reply while listing keys") {
			t.Fatalf("agentSigner() error = %v, want a timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agentSigner() remained blocked on an agent that answers nothing")
	}
}

func TestAgentSignerClearsTheDeadline(t *testing.T) {
	publicKey, privateKey, err := newEd25519Key()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("adding key: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", listenAgent(t, keyring))

	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	signer, err := agentSigner(nil, conn, client, publicKey, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("agentSigner() error = %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := SignatureCreate(signer, "file", strings.NewReader("data\n")); err != nil {
		t.Errorf("SignatureCreate() error = %v, want the deadline cleared", err)
	}
}

func TestAgentSigningFailureIsReturned(t *testing.T) {
	publicKey, privateKey, err := newEd25519Key()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("adding key: %v", err)
	}
	socket := listenAgent(t, failingSignAgent{Agent: keyring})
	t.Setenv("SSH_AUTH_SOCK", socket)

	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	signer, err := AgentSigner(nil, conn, client, publicKey)
	if err != nil {
		t.Fatalf("AgentSigner() error = %v", err)
	}
	if _, err := SignatureCreate(signer, "file", strings.NewReader("data\n")); err == nil ||
		!strings.Contains(err.Error(), "failed to sign challenge") {
		t.Fatalf("SignatureCreate() error = %v, want signing error", err)
	}
}

func TestAgentLogsItsProgress(t *testing.T) {
	publicKey, privateKey, err := newEd25519Key()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("adding key: %v", err)
	}
	socket := listenAgent(t, keyring)
	t.Setenv("SSH_AUTH_SOCK", socket)

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: levelDebug3}))

	conn, client, err := AgentConnect(log)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := AgentSigner(log, conn, client, publicKey); err != nil {
		t.Fatalf("AgentSigner() error = %v", err)
	}

	for _, want := range []string{socket, "keys=1", ssh.FingerprintSHA256(publicKey)} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("agent logged %q, want it to mention %q", buf.String(), want)
		}
	}
}

func TestAgentAcceptsNoLogger(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", listenAgent(t, agent.NewKeyring()))
	conn, client, err := AgentConnect(nil)
	if err != nil {
		t.Fatalf("AgentConnect() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := AgentSigner(nil, conn, client, newSigner(t).PublicKey()); err == nil {
		t.Fatal("AgentSigner() error = nil, want an empty-agent error")
	}
}
