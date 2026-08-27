// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Bound noninteractive agent operations. Signing may wait for user input.
const agentTimeout = 30 * time.Second

// AgentConnect connects to the SSH agent provided via the `SSH_AUTH_SOCK`
// environment variable.
func AgentConnect() (net.Conn, agent.Agent, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK is not set, an ssh-agent is required for signing")
	}

	conn, err := net.DialTimeout("unix", sock, agentTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %q: %v", sock, err)
	}

	return conn, agent.NewClient(conn), nil
}

// AgentSigner gets a signer, bounding key listing but not signing.
// conn may be nil when no deadline can be set.
func AgentSigner(conn net.Conn, a agent.Agent, pk ssh.PublicKey) (ssh.Signer, error) {
	return agentSigner(conn, a, pk, agentTimeout)
}

func agentSigner(
	conn net.Conn, a agent.Agent, pk ssh.PublicKey, timeout time.Duration,
) (ssh.Signer, error) {
	var deadline time.Time
	if conn != nil {
		deadline = time.Now().Add(timeout)
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed setting agent deadline: %v", err)
		}
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}

	signers, err := a.Signers()
	if err != nil {
		// The client does not preserve the underlying timeout error.
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, fmt.Errorf("no reply while listing keys within %s", timeout)
		}
		return nil, fmt.Errorf("failed listing keys: %v", err)
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
				return nil, fmt.Errorf("failed constructing RSA certificate signer: %v", err)
			}
			return certSigner, nil
		}
	}

	for _, s := range signers {
		if PublicKeyEqual(pk, s.PublicKey()) {
			return s, nil
		}
	}

	return nil, fmt.Errorf(
		"no key matched %q", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))),
	)
}
