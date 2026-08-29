// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"pxy.se/go/ssh-sign/pkg/allowedsigners"
	"pxy.se/go/ssh-sign/pkg/cli"
	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// debugSignature reports parsed signature metadata.
func debugSignature(log *slog.Logger, command string, sig *sshsig.Signature) {
	cli.Debug(log, cli.LevelDebug1, command+": read signature",
		"namespace", sig.Namespace,
		"hash", sig.HashAlgorithm,
		"format", sig.Signature.Format,
		keyAttr("key", sig.PublicKey),
	)
}

func keyAttr(key string, pk ssh.PublicKey) slog.Attr {
	return slog.Group(key,
		"type", pk.Type(),
		"fingerprint", ssh.FingerprintSHA256(pk),
	)
}

func entryAttr(key string, ent *allowedsigners.Entry) slog.Attr {
	return slog.Group(key,
		"line", ent.Line,
		"principal", ent.Principal,
		"type", ent.KeyType,
		"fingerprint", ssh.FingerprintSHA256(ent.PublicKey),
		"namespaces", strings.Join(ent.Options.Namespaces, ","),
		"valid_after", timeText(ent.Options.ValidAfter),
		"valid_before", timeText(ent.Options.ValidBefore),
	)
}

func timeText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
