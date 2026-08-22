// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentConnect connects to the SSH agent provided via the `SSH_AUTH_SOCK`
// environment variable.
func AgentConnect() (net.Conn, agent.Agent, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK is not set, an ssh-agent is required for signing")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %q: %v", sock, err)
	}

	return conn, agent.NewClient(conn), nil
}

// AgentSigner gets a specific signer from the agent.
func AgentSigner(a agent.Agent, pk ssh.PublicKey) (ssh.Signer, error) {
	signers, err := a.Signers()
	if err != nil {
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
