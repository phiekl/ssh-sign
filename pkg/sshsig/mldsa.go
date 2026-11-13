// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// KeyAlgoMLDSA44Ed25519 is the hybrid post-quantum key type added in OpenSSH
// 10.6. It follows OpenSSH's ssh-mldsa-eddsa.c, which implements:
//
//   - https://datatracker.ietf.org/doc/html/draft-miller-sshm-mldsa44-ed25519-composite-sigs-00
//   - https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-18
//   - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf (ML-DSA)
const KeyAlgoMLDSA44Ed25519 = "ssh-mldsa44-ed25519"

// OpenSSH names this certificate without the usual -cert-v01@openssh.com.
const mldsa44Ed25519CertAlgo = KeyAlgoMLDSA44Ed25519 + "-cert"

const (
	mldsa44PublicKeySize = mldsa.MLDSA44PublicKeySize
	mldsa44SignatureSize = mldsa.MLDSA44SignatureSize

	// The composite prefix and label of draft-ietf-lamps-pq-composite-sigs-18.
	compositePrefix = "CompositeAlgorithmSignatures2025"
	compositeLabel  = "COMPSIG-MLDSA44-Ed25519-SHA512"
)

// mldsa44Ed25519Key holds the ML-DSA-44 key followed by the Ed25519 key, as
// both the wire format and the composite scheme concatenate them.
type mldsa44Ed25519Key struct {
	mldsa   *mldsa.PublicKey
	ed25519 ed25519.PublicKey
	blob    []byte
}

func parseMLDSA44Ed25519Key(in []byte) (ssh.PublicKey, error) {
	// Unmarshal aliases its input, which the caller may reuse.
	in = bytes.Clone(in)
	var wire struct {
		Name string
		Key  []byte
	}
	if err := ssh.Unmarshal(in, &wire); err != nil {
		return nil, err
	}
	if len(wire.Key) != mldsa44PublicKeySize+ed25519.PublicKeySize {
		return nil, fmt.Errorf("ssh: invalid %s key size %d", KeyAlgoMLDSA44Ed25519, len(wire.Key))
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), wire.Key[:mldsa44PublicKeySize])
	if err != nil {
		return nil, fmt.Errorf("ssh: invalid %s key: %w", KeyAlgoMLDSA44Ed25519, err)
	}
	return &mldsa44Ed25519Key{
		mldsa:   pk,
		ed25519: ed25519.PublicKey(wire.Key[mldsa44PublicKeySize:]),
		blob:    in,
	}, nil
}

func (k *mldsa44Ed25519Key) Type() string {
	return KeyAlgoMLDSA44Ed25519
}

func (k *mldsa44Ed25519Key) Marshal() []byte {
	return bytes.Clone(k.blob)
}

// Verify requires both signatures over the composite message representative.
func (k *mldsa44Ed25519Key) Verify(data []byte, sig *ssh.Signature) error {
	if sig.Format != KeyAlgoMLDSA44Ed25519 {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, KeyAlgoMLDSA44Ed25519)
	}
	if len(sig.Blob) != mldsa44SignatureSize+ed25519.SignatureSize {
		return fmt.Errorf("ssh: invalid %s signature size %d", KeyAlgoMLDSA44Ed25519, len(sig.Blob))
	}
	digest := sha512.Sum512(data)
	message := make([]byte, 0, len(compositePrefix)+len(compositeLabel)+1+len(digest))
	message = append(message, compositePrefix...)
	message = append(message, compositeLabel...)
	message = append(message, 0) // empty context, as OpenSSH passes none
	message = append(message, digest[:]...)

	mldsaOK := mldsa.Verify(k.mldsa, message, sig.Blob[:mldsa44SignatureSize],
		&mldsa.Options{Context: compositeLabel}) == nil
	ed25519OK := ed25519.Verify(k.ed25519, message, sig.Blob[mldsa44SignatureSize:])
	if !mldsaOK || !ed25519OK {
		return errors.New("ssh: signature did not verify")
	}
	return nil
}

// parsePublicKeyBlob extends ssh.ParsePublicKey with the key types x/crypto
// does not know.
func parsePublicKeyBlob(in []byte) (ssh.PublicKey, error) {
	var name struct {
		Name string
		Rest []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(in, &name) == nil {
		switch name.Name {
		case KeyAlgoMLDSA44Ed25519:
			return parseMLDSA44Ed25519Key(in)
		case mldsa44Ed25519CertAlgo:
			return nil, fmt.Errorf("ssh: %s certificates are not supported", KeyAlgoMLDSA44Ed25519)
		}
	}
	return ssh.ParsePublicKey(in)
}

// verifiablePublicKey swaps a key x/crypto cannot verify with, such as an
// agent listing, for the parsed one. Other keys stay as received, since
// re-encoding a certificate may change its bytes.
func verifiablePublicKey(pk ssh.PublicKey) (ssh.PublicKey, error) {
	if _, ok := pk.(*mldsa44Ed25519Key); ok || pk.Type() != KeyAlgoMLDSA44Ed25519 {
		return pk, nil
	}
	return parseMLDSA44Ed25519Key(pk.Marshal())
}
