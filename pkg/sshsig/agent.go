// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Bound noninteractive agent operations. Signing may wait for user input.
const agentTimeout = 30 * time.Second

// ConnectAgent connects to SSH_AUTH_SOCK. log may be nil.
func ConnectAgent(log *slog.Logger) (net.Conn, agent.Agent, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK is not set, an ssh-agent is required for signing")
	}
	debug(log, levelDebug1, "agent: connecting", "socket", sock, "timeout", agentTimeout)

	conn, err := net.DialTimeout("unix", sock, agentTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %q: %w", sock, err)
	}
	debug(log, levelDebug1, "agent: connected", "socket", sock)

	return conn, agent.NewClient(conn), nil
}

// AgentSigner finds pk, timing out key listing but not signing.
// A nil conn disables the deadline; log may also be nil.
func AgentSigner(
	log *slog.Logger, conn net.Conn, a agent.Agent, pk ssh.PublicKey,
) (ssh.Signer, error) {
	return agentSigner(log, conn, a, pk, agentTimeout)
}

func agentSigner(
	log *slog.Logger, conn net.Conn, a agent.Agent, pk ssh.PublicKey, timeout time.Duration,
) (ssh.Signer, error) {
	var deadline time.Time
	if conn != nil {
		deadline = time.Now().Add(timeout)
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed setting agent deadline: %w", err)
		}
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}

	debug(log, levelDebug2, "agent: listing keys", "timeout", timeout)
	signers, err := a.Signers()
	if err != nil {
		// The client does not preserve the underlying timeout error.
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, fmt.Errorf("no reply while listing keys within %s", timeout)
		}
		return nil, fmt.Errorf("failed listing keys: %w", err)
	}
	debug(log, levelDebug2, "agent: listed keys", "keys", len(signers))
	for i, s := range signers {
		debug(log, levelDebug3, "agent: offered key",
			"index", i,
			"type", s.PublicKey().Type(),
			"fingerprint", ssh.FingerprintSHA256(s.PublicKey()),
		)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no keys found")
	}

	// OpenSSH agents may ignore RSA-SHA2 flags when asked to sign using a
	// certificate key blob. Rebuild the certificate signer over the listed
	// underlying RSA key so algorithm selection is sent for that plain key.
	if cert, ok := pk.(*ssh.Certificate); ok && cert.Key.Type() == ssh.KeyAlgoRSA {
		for _, s := range signers {
			if !PublicKeyEqual(cert.Key, s.PublicKey()) {
				continue
			}
			certSigner, err := ssh.NewCertSigner(cert, s)
			if err != nil {
				return nil, fmt.Errorf("failed constructing RSA certificate signer: %w", err)
			}
			debug(log, levelDebug1, "agent: matched certificate key",
				"type", cert.Type(), "fingerprint", ssh.FingerprintSHA256(cert.Key),
			)
			return certSigner, nil
		}
	}

	for _, s := range signers {
		if PublicKeyEqual(pk, s.PublicKey()) {
			debug(log, levelDebug1, "agent: matched key",
				"type", pk.Type(), "fingerprint", ssh.FingerprintSHA256(pk),
			)
			return s, nil
		}
	}

	return nil, fmt.Errorf(
		"no key matched %q", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))),
	)
}
