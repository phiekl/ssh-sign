// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hiddeco/sshsig"
	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

type SignOpts struct {
	DataFile  *os.File
	SignKey   string
	Namespace string
}

type SignResult struct {
	Signature *sshsig.Signature
}

func (r SignResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		&struct {
			ArmoredSignature string `json:"armored_signature"`
		}{
			ArmoredSignature: string(sshsig.Armor(r.Signature)),
		},
	)
}

func (r SignResult) String() string {
	return strings.TrimSpace(string(sshsig.Armor(r.Signature)))
}

func Sign(opts *SignOpts) (*SignResult, []error) {
	var errs []error

	pk, err := sshsigx.PublicKeyLineParse(opts.SignKey)
	if err != nil {
		return nil, append(errs, fmt.Errorf("invalid signing key: %v", err))
	}

	conn, agent, err := sshsigx.AgentConnect()
	if err != nil {
		return nil, append(errs, fmt.Errorf("failed agent connection: %v", err))
	}
	defer func() {
		if err := conn.Close(); err != nil {
			panic(fmt.Sprintf("failed closing agent connection: %v", err))
		}
	}()

	signer, err := sshsigx.AgentSigner(agent, pk)
	if err != nil {
		return nil, append(errs, fmt.Errorf("agent: %v", err))
	}

	sig, err := sshsigx.SignatureCreate(signer, opts.Namespace, opts.DataFile)
	if err != nil {
		return nil, append(errs, err)
	}

	res := SignResult{Signature: sig}
	return &res, errs
}
