// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"

	"pxy.se/go/ssh-sign/pkg/sshsig"
)

func CheckNamespace(namespace string, noNamespace bool) error {
	switch {
	case namespace != "" && noNamespace:
		return fmt.Errorf("a namespace was provided, but namespace verification is disabled")
	case namespace == "" && !noNamespace:
		return fmt.Errorf("namespace verification enabled, but no namespace provided")
	}
	return nil
}

func CheckAuthKey(authKey string, noAuthKey bool) error {
	switch {
	case authKey != "" && noAuthKey:
		return fmt.Errorf("an auth key was provided, but signer authentication is disabled")
	case authKey == "" && !noAuthKey:
		return fmt.Errorf("signer authentication enabled, but no auth key provided")
	}

	if authKey != "" {
		if _, err := sshsig.ParsePublicKeyLine(authKey); err != nil {
			return fmt.Errorf("invalid authentication key: %v", err)
		}
	}
	return nil
}
