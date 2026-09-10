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

// entryAttr defers fingerprinting until a log handler needs the entry.
func entryAttr(key string, ent *allowedsigners.Entry) slog.Attr {
	return slog.Any(key, entryValue{ent: ent})
}

type entryValue struct {
	ent *allowedsigners.Entry
}

func (v entryValue) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("line", v.ent.Line),
		slog.String("principal", v.ent.Principal),
		slog.String("type", v.ent.KeyType),
		slog.String("fingerprint", ssh.FingerprintSHA256(v.ent.PublicKey)),
		slog.String("namespaces", strings.Join(v.ent.Options.Namespaces, ",")),
		slog.String("valid_after", timeText(v.ent.Options.ValidAfter)),
		slog.String("valid_before", timeText(v.ent.Options.ValidBefore)),
	)
}

func timeText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
