// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsig

import (
	"crypto/dsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Vectors produced by OpenSSH 10.0p2:
//
//	ssh-keygen -Y sign -f key -n file data
//
// over goldenData, so parsing, verification and armoring are pinned to what
// ssh-keygen actually emits rather than to this implementation. The
// security-key vectors came from a FIDO authenticator the same way.
const goldenData = "hello\n"

const goldenED25519Key = "ssh-ed25519 " +
	"AAAAC3NzaC1lZDI1NTE5AAAAIM2ndUBrO7pEkZJPLmKPbJoOD++UWQT+HCxbZZWkMjy/"

const goldenED25519SHA512 = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgzad1QGs7ukSRkk8uYo9smg4P75
RZBP4cLFtllaQyPL8AAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECxv+Ha6rGCD1193eQ3Gv0nXkeZIfN9dx4vMuglWlgp6Y/naTHoIT42wZZlPbjKp0
RTVLSQ43dKHHn+GtIiIbAE
-----END SSH SIGNATURE-----
`

// Written with "-O hashalg=sha256"; ssh-keygen defaults to sha512.
const goldenED25519SHA256 = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgzad1QGs7ukSRkk8uYo9smg4P75
RZBP4cLFtllaQyPL8AAAAEZmlsZQAAAAAAAAAGc2hhMjU2AAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEA4C7I7U3c+DllHQHLzdYlLPtmdfOB7WGL0ccXpbnJLQS9+iuMvZXbf2tJncwYtCd
cwdp/kBMCJIWzqzvE89CgD
-----END SSH SIGNATURE-----
`

const goldenRSAKey = "ssh-rsa " +
	"AAAAB3NzaC1yc2EAAAADAQABAAABAQCzgWD0GOZjAY65W1OUYX2og2nLOfvRan7l/KmHSJu" +
	"nNrMHbLkqo5xfCGMsR99+hfW9qbGiJKhhhz77d9jkBBgJCjKCoWpcn5CpdZHMF3yDrNcGzx" +
	"/pRVdygjXdYwgXzCJPAzsigkGOWPI9kufGgt070k26imJ3YrjOFLRRe1Y4axov2mXyC/eYs" +
	"QhPQoYHPYA67PzKdq9GYnsjWBt1FQG9iPBa6iUt4Dvwq17Q+dL7nclMDmLxP/wQxnZ9NWQx" +
	"MgqKb23MoHqZ1Spk9LoJgOe/+6T2CjxCMM+Ls5fXCcovMuEKlT+ZE9eGe8Ud1k9Dh6w+3Et" +
	"D5fhjjiKthFFqPiLT"

const goldenRSASHA512 = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBALOBYPQY5mMBjrlbU5Rhfa
iDacs5+9FqfuX8qYdIm6c2swdsuSqjnF8IYyxH336F9b2psaIkqGGHPvt32OQEGAkKMoKh
alyfkKl1kcwXfIOs1wbPH+lFV3KCNd1jCBfMIk8DOyKCQY5Y8j2S58aC3TvSTbqKYndiuM
4UtFF7VjhrGi/aZfIL95ixCE9Chgc9gDrs/Mp2r0ZieyNYG3UVAb2I8FrqJS3gO/CrXtD5
0vudyUwOYvE//BDGdn01ZDEyCopvbcygepnVKmT0ugmA57/7pPYKPEIwz4uzl9cJyi8y4Q
qVP5kT14Z7xR3WT0OHrD7cS0Pl+GOOIq2EUWo+ItMAAAAEZmlsZQAAAAAAAAAGc2hhNTEy
AAABFAAAAAxyc2Etc2hhMi01MTIAAAEAUlS6o0WvY8+oteQzVP0+AGplLZDLL7kyrpvqvf
DXhcFGs8JQvuaPvMP6FX4SBw0pkLnO08poOzsbKgSqy0ZulY96vpHfdSIQR26eWSN28s+8
jBQCQLkcrV/KoDsx6BlzMvzqcnLzwrx8Wq1velUkW+MsnBR9/P4hpyTY1CHxdtj05yyeDp
83nhtojAqOETiYFf98dQlLi7p+JAc8GcQvCJpUd4klCQ+UfWMqCRhHHxG9yfs6HY52XvuE
D9D+ARff8tI/SVgG8crFIumDk0ViYxeM4kDUyNBi1AeTg3Wd2ZYCCqxMLEUO0DSL/5+tJL
CcV2IjKuxQdRK5qXdvbHOGNg==
-----END SSH SIGNATURE-----
`

// Security-key vectors, from a FIDO authenticator via ssh-keygen. Their
// flags and counter are what real hardware emitted, which no software
// reconstruction of PROTOCOL.u2f can vouch for.
const goldenSKED25519Key = "sk-ssh-ed25519@openssh.com " +
	"AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIP06KgHs0lgFvL0kYb+QW+ESP9kSbEgkCIJfxvU+z2hMAAAABHNzaDo="

const goldenSKED25519 = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAg/ToqAe
zSWAW8vSRhv5Bb4RI/2RJsSCQIgl/G9T7PaEwAAAAEc3NoOgAAAARmaWxlAAAAAAAAAAZz
aGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQJs+G1okDsoJer
quxzNgIYQcxIYrm3LSl1EXXKJNoAltnWNCeLTsnMPxZgqgbtN4UkhIwvzAK+0iVaTbiamp
IgoBAAAABQ==
-----END SSH SIGNATURE-----
`

const goldenSKECDSAKey = "sk-ecdsa-sha2-nistp256@openssh.com " +
	"AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBKOuREYRSHdnliD20P1okArnAknOMVctI6csc/QP4BfVCua8KaRnHB1n109wJC9tIMTgpbmEcUuCM3RYXMqyaWIAAAAEc3NoOg=="

const goldenSKECDSA = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAH8AAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQ
AAAAhuaXN0cDI1NgAAAEEEo65ERhFId2eWIPbQ/WiQCucCSc4xVy0jpyxz9A/gF9UK5rwp
pGccHWfXT3AkL20gxOCluYRxS4IzdFhcyrJpYgAAAARzc2g6AAAABGZpbGUAAAAAAAAABn
NoYTUxMgAAAHkAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQAAAEoA
AAAhAOjcxOhO9vNv3/WK6+RWMDcSPritCAw/BW/5fTVCg8zqAAAAIQCFPAEbad+cBDvanv
2YKZgZ+B7+KLXRta1SV0FPRXGaUgEAAAAM
-----END SSH SIGNATURE-----
`

// The same authenticator with -O verify-required, which sets user
// verification, and with -O no-touch-required, which clears user presence.
const goldenSKVerifiedKey = "sk-ssh-ed25519@openssh.com " +
	"AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEGEkdGc3K66P+0r51/OZbYup3TUXIv0E3ndo3lunBIYAAAABHNzaDo="

const goldenSKVerified = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgQYSR0Z
zcrro/7SvnX85lti6ndNRci/QTed2jeW6cEhgAAAAEc3NoOgAAAARmaWxlAAAAAAAAAAZz
aGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQHokh8iKa9Kg5e
Y5ATRFEmafGGcAIP73iEVG1oBpCOmXY2ydEexu0nKP89JJ8q2d93r9RhymmXMF+6+aFiGN
xAkFAAAADQ==
-----END SSH SIGNATURE-----
`

const goldenSKNoTouchKey = "sk-ssh-ed25519@openssh.com " +
	"AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIKZmHo3e5KOcW8CKLDoBDQ1z456vmsUM7FTuOnuC3PoqAAAABHNzaDo="

const goldenSKNoTouch = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgpmYejd
7ko5xbwIosOgENDXPjnq+axQzsVO46e4Lc+ioAAAAEc3NoOgAAAARmaWxlAAAAAAAAAAZz
aGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQOMkSyJR9CZW0y
lYaFdVQDkTqNCL+CYkHdnUxTR4AIna0/VtEsIOMG7RZkmOaZzVCGFTB0SA6MvDG9B0q3Er
NQgAAAAADA==
-----END SSH SIGNATURE-----
`

// goldenBlob strips the armor of a vector without going through the code under
// test.
func goldenBlob(t *testing.T, armored string) []byte {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(armored), "\n")
	blob, err := base64.StdEncoding.DecodeString(strings.Join(lines[1:len(lines)-1], ""))
	if err != nil {
		t.Fatalf("decoding vector: %v", err)
	}
	return blob
}

func TestParseSignatureOpenSSHVectors(t *testing.T) {
	tests := map[string]struct {
		armored   string
		keyLine   string
		hash      HashAlgorithm
		sigFormat string
	}{
		"ed25519 sha512": {
			armored:   goldenED25519SHA512,
			keyLine:   goldenED25519Key,
			hash:      HashSHA512,
			sigFormat: ssh.KeyAlgoED25519,
		},
		"ed25519 sha256": {
			armored:   goldenED25519SHA256,
			keyLine:   goldenED25519Key,
			hash:      HashSHA256,
			sigFormat: ssh.KeyAlgoED25519,
		},
		"rsa sha512": {
			armored:   goldenRSASHA512,
			keyLine:   goldenRSAKey,
			hash:      HashSHA512,
			sigFormat: ssh.KeyAlgoRSASHA512,
		},
		"security key ed25519": {
			armored:   goldenSKED25519,
			keyLine:   goldenSKED25519Key,
			hash:      HashSHA512,
			sigFormat: ssh.KeyAlgoSKED25519,
		},
		"security key ecdsa": {
			armored:   goldenSKECDSA,
			keyLine:   goldenSKECDSAKey,
			hash:      HashSHA512,
			sigFormat: ssh.KeyAlgoSKECDSA256,
		},
		"security key verify-required": {
			armored:   goldenSKVerified,
			keyLine:   goldenSKVerifiedKey,
			hash:      HashSHA512,
			sigFormat: ssh.KeyAlgoSKED25519,
		},
		"security key no-touch-required": {
			armored:   goldenSKNoTouch,
			keyLine:   goldenSKNoTouchKey,
			hash:      HashSHA512,
			sigFormat: ssh.KeyAlgoSKED25519,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			blob := goldenBlob(t, tt.armored)
			sig, err := ParseSignature(blob)
			if err != nil {
				t.Fatalf("ParseSignature() error = %v", err)
			}

			if sig.Version != sigVersion {
				t.Errorf("Version = %d, want %d", sig.Version, sigVersion)
			}
			if sig.Namespace != "file" {
				t.Errorf("Namespace = %q, want %q", sig.Namespace, "file")
			}
			if sig.Reserved != "" {
				t.Errorf("Reserved = %q, want empty", sig.Reserved)
			}
			if sig.HashAlgorithm != tt.hash {
				t.Errorf("HashAlgorithm = %q, want %q", sig.HashAlgorithm, tt.hash)
			}
			if sig.Signature.Format != tt.sigFormat {
				t.Errorf("Signature.Format = %q, want %q", sig.Signature.Format, tt.sigFormat)
			}

			want, err := ParsePublicKeyLine(tt.keyLine)
			if err != nil {
				t.Fatalf("parsing vector key: %v", err)
			}
			if !PublicKeyEqual(sig.PublicKey, want) {
				t.Errorf("PublicKey = %q, want the vector's signer",
					PublicKeyString(sig.PublicKey))
			}

			// The signature must verify over the exact signed data, and only
			// over that data.
			if err := Verify(strings.NewReader(goldenData), sig); err != nil {
				t.Errorf("Verify() error = %v, want nil", err)
			}
			if err := Verify(strings.NewReader("tampered\n"), sig); err == nil {
				t.Error("Verify() error = nil for other data, want a failure")
			}

			// Marshal and Armor must reproduce ssh-keygen's bytes exactly.
			if got := Marshal(sig); string(got) != string(blob) {
				t.Errorf("Marshal() = %d bytes, want the vector's %d identical bytes",
					len(got), len(blob))
			}
			if got := string(Armor(sig)); got != tt.armored {
				t.Errorf("Armor() =\n%s\nwant\n%s", got, tt.armored)
			}
		})
	}
}

// TestSignSignsTheSpecifiedBlob rebuilds the signed data by hand and checks it
// with crypto/ed25519 directly, so the framing is confirmed without trusting
// this package's own verification path.
func TestSignSignsTheSpecifiedBlob(t *testing.T) {
	const data = "framing\n"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	sig, err := Sign(strings.NewReader(data), signer, HashSHA512, "git")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	digest := sha512.Sum512([]byte(data))
	want := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Hash          string
	}{
		Namespace:     "git",
		HashAlgorithm: "sha512",
		Hash:          string(digest[:]),
	})...)

	if !ed25519.Verify(publicKey, want, sig.Signature.Blob) {
		t.Error("the signature does not cover the SSHSIG signed data blob")
	}
	if sig.Version != 1 {
		t.Errorf("Version = %d, want 1", sig.Version)
	}
	if sig.Signature.Format != ssh.KeyAlgoED25519 {
		t.Errorf("Signature.Format = %q, want %q", sig.Signature.Format, ssh.KeyAlgoED25519)
	}
	if err := Verify(strings.NewReader(data), sig); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestSignRoundTripsEveryHashAlgorithm(t *testing.T) {
	const data = "hash algorithms\n"
	for _, h := range []HashAlgorithm{HashSHA256, HashSHA512} {
		t.Run(h.String(), func(t *testing.T) {
			sig, err := Sign(strings.NewReader(data), newSigner(t), h, "file")
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			parsed, err := ParseSignature(Marshal(sig))
			if err != nil {
				t.Fatalf("ParseSignature() error = %v", err)
			}
			if parsed.HashAlgorithm != h {
				t.Errorf("HashAlgorithm = %q, want %q", parsed.HashAlgorithm, h)
			}
			if err := Verify(strings.NewReader(data), parsed); err != nil {
				t.Errorf("Verify() error = %v, want nil", err)
			}
			if err := Verify(strings.NewReader("other\n"), parsed); err == nil {
				t.Error("Verify() error = nil for other data, want a failure")
			}
		})
	}
}

func TestSignRejectsUnusableArguments(t *testing.T) {
	tests := map[string]struct {
		hash      HashAlgorithm
		namespace string
		wantErr   string
	}{
		"unsupported hash": {hash: "sha1", namespace: "file", wantErr: "unsupported hash algorithm"},
		"empty hash":       {hash: "", namespace: "file", wantErr: "unsupported hash algorithm"},
		"empty namespace":  {hash: HashSHA512, namespace: "", wantErr: "namespace is required"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Sign(strings.NewReader("data\n"), newSigner(t), tt.hash, tt.namespace)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Sign() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// craftedWire marshals a signature blob with a valid preamble unless the test
// overrides it.
func craftedWire(t *testing.T, wire signatureWire) []byte {
	t.Helper()
	if wire.MagicPreamble == [6]byte{} {
		copy(wire.MagicPreamble[:], magicPreamble)
	}
	return ssh.Marshal(wire)
}

func TestParseSignatureRejectsMalformedBlobs(t *testing.T) {
	signer := newSigner(t)
	sig, err := Sign(strings.NewReader("data\n"), signer, HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	valid := Marshal(sig)
	publicKey := string(signer.PublicKey().Marshal())
	signature := string(ssh.Marshal(sig.Signature))

	tests := map[string]struct {
		blob    []byte
		wantErr string
	}{
		"empty": {blob: nil, wantErr: "invalid signature"},
		"truncated": {
			blob: valid[:len(valid)-1], wantErr: "invalid signature",
		},
		"trailing data": {
			blob: append(append([]byte{}, valid...), 'x'), wantErr: "invalid signature",
		},
		"bad preamble": {
			blob: craftedWire(t, signatureWire{
				MagicPreamble: [6]byte{'S', 'S', 'H', 'S', 'I', 'X'},
				Version:       1,
				PublicKey:     publicKey,
				Namespace:     "file",
				HashAlgorithm: "sha512",
				Signature:     signature,
			}),
			wantErr: `invalid magic preamble "SSHSIX"`,
		},
		"unsupported version": {
			blob: craftedWire(t, signatureWire{
				Version:       2,
				PublicKey:     publicKey,
				Namespace:     "file",
				HashAlgorithm: "sha512",
				Signature:     signature,
			}),
			wantErr: "unsupported signature version 2",
		},
		"unparsable public key": {
			blob: craftedWire(t, signatureWire{
				Version:       1,
				PublicKey:     "not a public key",
				Namespace:     "file",
				HashAlgorithm: "sha512",
				Signature:     signature,
			}),
			wantErr: "invalid public key",
		},
		"unsupported hash algorithm": {
			blob: craftedWire(t, signatureWire{
				Version:       1,
				PublicKey:     publicKey,
				Namespace:     "file",
				HashAlgorithm: "sha1",
				Signature:     signature,
			}),
			wantErr: `unsupported hash algorithm "sha1"`,
		},
		"unparsable signature field": {
			blob: craftedWire(t, signatureWire{
				Version:       1,
				PublicKey:     publicKey,
				Namespace:     "file",
				HashAlgorithm: "sha512",
				Signature:     "not a signature",
			}),
			wantErr: "invalid signature field",
		},
		// An ed25519 key cannot have produced an RSA signature.
		"signature format the key cannot produce": {
			blob: craftedWire(t, signatureWire{
				Version:       1,
				PublicKey:     publicKey,
				Namespace:     "file",
				HashAlgorithm: "sha512",
				Signature: string(ssh.Marshal(ssh.Signature{
					Format: ssh.KeyAlgoRSASHA512, Blob: []byte("x"),
				})),
			}),
			wantErr: `invalid signature format "rsa-sha2-512": expected "ssh-ed25519"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSignature(tt.blob)
			if err == nil {
				t.Fatalf("ParseSignature() = %+v, want error %q", parsed, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseSignature() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// RSA keys pick their hash through the signature format, so all three formats
// have to survive a round trip.
func TestParseSignatureAcceptsEveryRSAFormat(t *testing.T) {
	for _, format := range []string{
		ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
	} {
		t.Run(format, func(t *testing.T) {
			blob := craftedWire(t, signatureWire{
				Version:       1,
				PublicKey:     string(newRSASigner(t).PublicKey().Marshal()),
				Namespace:     "file",
				HashAlgorithm: "sha512",
				Signature:     string(ssh.Marshal(ssh.Signature{Format: format, Blob: []byte("x")})),
			})
			if _, err := ParseSignature(blob); err != nil {
				t.Fatalf("ParseSignature() error = %v, want nil", err)
			}
		})
	}
}

// Both parsing and verification must reject unsigned reserved data.
func TestReservedFieldIsRejected(t *testing.T) {
	sig, err := Sign(strings.NewReader("data\n"), newSigner(t), HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if sig.Reserved != "" {
		t.Errorf("Reserved = %q, want empty for a new signature", sig.Reserved)
	}

	// Marshal preserves fields; parsing and verification enforce policy.
	sig.Reserved = "future use"
	if _, err := ParseSignature(Marshal(sig)); err == nil {
		t.Error("ParseSignature() accepted a non-empty reserved field")
	}
	if err := Verify(strings.NewReader("data\n"), sig); err == nil {
		t.Error("Verify() accepted a non-empty reserved field")
	}
}

// ParseSignature must reject empty namespaces without relying on SignatureRead.
func TestParseSignatureRejectsAnEmptyNamespace(t *testing.T) {
	sig, err := Sign(strings.NewReader("data\n"), newSigner(t), HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	sig.Namespace = ""
	if _, err := ParseSignature(Marshal(sig)); err == nil {
		t.Error("ParseSignature() accepted an empty namespace")
	}
}

func TestArmorWrapsLikeSSHKeygen(t *testing.T) {
	// An RSA signature is long enough to be wrapped over several lines.
	sig, err := Sign(strings.NewReader("armor\n"), newRSASigner(t), HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	armored := string(Armor(sig))
	if !strings.HasPrefix(armored, "-----BEGIN SSH SIGNATURE-----\n") ||
		!strings.HasSuffix(armored, "\n-----END SSH SIGNATURE-----\n") {
		t.Fatalf("Armor() = %q, want it wrapped in the SSH SIGNATURE armor", armored)
	}

	lines := strings.Split(strings.TrimSuffix(armored, "\n"), "\n")
	payload := lines[1 : len(lines)-1]
	if len(payload) < 2 {
		t.Fatalf("Armor() payload = %d lines, want it wrapped over several", len(payload))
	}
	for i, line := range payload {
		if len(line) > armorColumns || (i < len(payload)-1 && len(line) != armorColumns) {
			t.Errorf("payload line %d is %d bytes, want %d", i, len(line), armorColumns)
		}
	}

	// SignatureRead accepts what Armor writes.
	read, err := SignatureRead(strings.NewReader(armored))
	if err != nil {
		t.Fatalf("SignatureRead() error = %v", err)
	}
	if string(Marshal(read)) != string(Marshal(sig)) {
		t.Error("SignatureRead() did not reproduce the armored signature")
	}
}

// newRSASigner returns an ephemeral RSA signer.
func newRSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating RSA signer: %v", err)
	}
	return signer
}

// ssh-keygen signs with rsa-sha2-512 for RSA keys, and both x/crypto's and the
// agent's signers fall back to SHA-1 unless the algorithm is selected.
func TestSignSelectsSHA2ForRSAKeys(t *testing.T) {
	sig, err := Sign(strings.NewReader("data\n"), newRSASigner(t), HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if sig.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("Signature.Format = %q, want %q", sig.Signature.Format, ssh.KeyAlgoRSASHA512)
	}
	if err := Verify(strings.NewReader("data\n"), sig); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

// sha1RSASigner produces the legacy ssh-rsa/SHA-1 signatures OpenSSH refuses.
type sha1RSASigner struct {
	ssh.AlgorithmSigner
}

func (s sha1RSASigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.AlgorithmSigner.SignWithAlgorithm(rand, data, ssh.KeyAlgoRSA)
}

func (s sha1RSASigner) SignWithAlgorithm(
	rand io.Reader, data []byte, _ string,
) (*ssh.Signature, error) {
	return s.AlgorithmSigner.SignWithAlgorithm(rand, data, ssh.KeyAlgoRSA)
}

// ssh-keygen refuses to verify these: "unsupported RSA signature algorithm
// ssh-rsa". Parsing stays structural, but nothing in this package may treat
// such a signature as valid.
func TestVerifyRejectsAlgorithmsOpenSSHRefuses(t *testing.T) {
	rsaSigner, ok := newRSASigner(t).(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("the RSA signer cannot select an algorithm")
	}

	tests := map[string]struct {
		signer  ssh.Signer
		wantErr string
	}{
		"rsa sha1": {
			signer:  sha1RSASigner{AlgorithmSigner: rsaSigner},
			wantErr: `invalid RSA signature format "ssh-rsa"`,
		},
		"rsa certificate sha1": {
			signer:  newRSACertificateSigner(t),
			wantErr: `invalid RSA signature format "ssh-rsa"`,
		},
		"dsa": {
			signer:  newDSASigner(t),
			wantErr: `unsupported signature algorithm "ssh-dss"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sig, err := Sign(strings.NewReader("data\n"), tt.signer, HashSHA512, "file")
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			// The signature is cryptographically sound; only its algorithm is
			// unacceptable.
			if err := Verify(strings.NewReader("data\n"), sig); err == nil ||
				!strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Verify() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// ssh-keygen refuses these too: "unexpected bytes remain after decoding".
// Accepting them would let anyone mutate a signature file that still verifies.
func TestParseSignatureRejectsTrailingSignatureBytes(t *testing.T) {
	signer := newSigner(t)
	sig, err := Sign(strings.NewReader("data\n"), signer, HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	blob := craftedWire(t, signatureWire{
		Version:       1,
		PublicKey:     string(signer.PublicKey().Marshal()),
		Namespace:     "file",
		HashAlgorithm: "sha512",
		Signature:     string(ssh.Marshal(sig.Signature)) + "TRAILING",
	})

	parsed, err := ParseSignature(blob)
	if err == nil {
		t.Fatalf("ParseSignature() = %+v, want a rejected signature", parsed)
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("ParseSignature() error = %q, want it to report trailing data", err)
	}
}

// ssh-keygen parses the namespace as a C string and rejects an embedded NUL
// with "parse signature object: invalid format".
func TestNamespaceRejectsNULBytes(t *testing.T) {
	signer := newSigner(t)
	sig, err := Sign(strings.NewReader("data\n"), signer, HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	blob := craftedWire(t, signatureWire{
		Version:       1,
		PublicKey:     string(signer.PublicKey().Marshal()),
		Namespace:     "file\x00evil",
		HashAlgorithm: "sha512",
		Signature:     string(ssh.Marshal(sig.Signature)),
	})
	if parsed, err := ParseSignature(blob); err == nil {
		t.Errorf("ParseSignature() = %+v, want a rejected namespace", parsed)
	} else if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("ParseSignature() error = %q, want the NUL byte reported", err)
	}

	// Nor may such a signature be produced.
	if _, err := Sign(strings.NewReader("data\n"), signer, HashSHA512, "file\x00evil"); err == nil ||
		!strings.Contains(err.Error(), "NUL") {
		t.Errorf("Sign() error = %v, want the NUL byte reported", err)
	}
}

// An RSA signer that cannot select SHA-2 would otherwise silently produce a
// SHA-1 signature that nothing accepts.
func TestSignRejectsRSASignersWithoutAlgorithmSelection(t *testing.T) {
	_, err := Sign(strings.NewReader("data\n"), plainSigner{newRSASigner(t)}, HashSHA512, "file")
	if err == nil || !strings.Contains(err.Error(), "SHA-2") {
		t.Fatalf("Sign() error = %v, want a rejected RSA signer", err)
	}
}

// plainSigner hides any algorithm selection the wrapped signer offers.
type plainSigner struct {
	signer ssh.Signer
}

func (s plainSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func (s plainSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.Sign(rand, data)
}

func TestVerifyRejectsUnsupportedVersions(t *testing.T) {
	sig, err := Sign(strings.NewReader("data\n"), newSigner(t), HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	sig.Version = 2
	if err := Verify(strings.NewReader("data\n"), sig); err == nil ||
		!strings.Contains(err.Error(), "unsupported signature version") {
		t.Fatalf("Verify() error = %v, want a rejected version", err)
	}
}

// newDSASigner returns an ephemeral DSA signer, an algorithm OpenSSH dropped.
func newDSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatalf("generating DSA parameters: %v", err)
	}
	privateKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(privateKey, rand.Reader); err != nil {
		t.Fatalf("generating DSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("creating DSA signer: %v", err)
	}
	return signer
}

// Verify must reject malformed signatures even when the caller builds them.
func TestVerifyRejectsWhatParsingRejects(t *testing.T) {
	signer := newSigner(t)
	tests := map[string]struct {
		mutate  func(*Signature)
		wantErr string
	}{
		"trailing signature bytes": {
			mutate:  func(s *Signature) { s.Signature.Rest = []byte("TRAILING") },
			wantErr: "trailing data",
		},
		"empty namespace": {
			mutate:  func(s *Signature) { s.Namespace = "" },
			wantErr: "namespace is empty",
		},
		"namespace NUL byte": {
			mutate:  func(s *Signature) { s.Namespace = "file\x00evil" },
			wantErr: "NUL",
		},
		"unsupported hash algorithm": {
			mutate:  func(s *Signature) { s.HashAlgorithm = "sha1" },
			wantErr: `unsupported hash algorithm "sha1"`,
		},
		"signature format the key cannot produce": {
			mutate:  func(s *Signature) { s.Signature.Format = ssh.KeyAlgoRSASHA512 },
			wantErr: `invalid signature format "rsa-sha2-512"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sig, err := Sign(strings.NewReader("data\n"), signer, HashSHA512, "file")
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			tt.mutate(sig)
			if _, err := ParseSignature(Marshal(sig)); err == nil {
				t.Fatal("ParseSignature() accepted the signature, adjust this test")
			}
			if err := Verify(strings.NewReader("data\n"), sig); err == nil ||
				!strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Verify() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// newSKSignature builds a security-key signature the way an authenticator
// would, so the SK paths can be covered without one attached.
func newSKSignature(t *testing.T, message string, flags byte, counter uint32) *Signature {
	t.Helper()
	const application, namespace = "ssh:", "file"

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pk, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, publicKey, application}))
	if err != nil {
		t.Fatalf("parsing security key: %v", err)
	}

	digest := sha512.Sum512([]byte(message))
	applicationDigest := sha256.Sum256([]byte(application))
	dataDigest := sha256.Sum256(signedData(namespace, HashSHA512, digest[:]))
	// What the authenticator signs, per OpenSSH's PROTOCOL.u2f.
	signed := ssh.Marshal(struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{applicationDigest[:], flags, counter, dataDigest[:]})

	return &Signature{
		Version:       sigVersion,
		PublicKey:     pk,
		Namespace:     namespace,
		HashAlgorithm: HashSHA512,
		Signature: &ssh.Signature{
			Format: ssh.KeyAlgoSKED25519,
			Blob: ssh.Marshal(struct {
				Signature []byte `ssh:"rest"`
			}{ed25519.Sign(privateKey, signed)}),
			Rest: ssh.Marshal(SecurityKeyFields{Flags: flags, Counter: counter}),
		},
	}
}

func TestSecurityKeyFields(t *testing.T) {
	const data = "data\n"
	sig := newSKSignature(t, data, 0x01, 42)
	if err := Verify(strings.NewReader(data), sig); err != nil {
		t.Fatalf("Verify() error = %v, want a usable signature", err)
	}

	// The fields survive a round trip through the signature file.
	read, err := SignatureRead(strings.NewReader(string(Armor(sig))))
	if err != nil {
		t.Fatalf("SignatureRead() error = %v", err)
	}
	fields, err := read.SecurityKeyFields()
	if err != nil {
		t.Fatalf("SecurityKeyFields() error = %v", err)
	}
	if fields == nil {
		t.Fatal("SecurityKeyFields() = nil, want the fields of a security key")
	}
	if fields.Flags != 0x01 || fields.Counter != 42 {
		t.Errorf("SecurityKeyFields() = %+v, want {Flags:1 Counter:42}", *fields)
	}
}

// ssh-keygen also rejects missing, truncated, or extra security-key fields.
func TestParseSignatureRejectsMalformedSecurityKeyFields(t *testing.T) {
	for name, rest := range map[string][]byte{
		"empty":          nil,
		"truncated":      {0x01, 0x00},
		"trailing bytes": {0x01, 0x00, 0x00, 0x00, 0x05, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			sig := newSKSignature(t, goldenData, 0x01, 5)
			sig.Signature.Rest = rest

			parsed, err := ParseSignature(Marshal(sig))
			if err == nil {
				t.Fatalf("ParseSignature() = %+v, want a rejected signature", parsed)
			}
			if !strings.Contains(err.Error(), "security key fields") {
				t.Errorf("ParseSignature() error = %v, want the fields reported", err)
			}
		})
	}
}

// The vectors pin the fields to what a FIDO authenticator emitted, so this
// does not rest on newSKSignature's reconstruction of the wire format.
func TestSecurityKeyFieldsFromOpenSSHVectors(t *testing.T) {
	tests := map[string]struct {
		armored string
		flags   byte
		counter uint32
	}{
		"ed25519":           {armored: goldenSKED25519, flags: 0x01, counter: 5},
		"ecdsa":             {armored: goldenSKECDSA, flags: 0x01, counter: 12},
		"verify-required":   {armored: goldenSKVerified, flags: 0x05, counter: 13},
		"no-touch-required": {armored: goldenSKNoTouch, flags: 0x00, counter: 12},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sig, err := ParseSignature(goldenBlob(t, tt.armored))
			if err != nil {
				t.Fatalf("ParseSignature() error = %v", err)
			}
			fields, err := sig.SecurityKeyFields()
			if err != nil {
				t.Fatalf("SecurityKeyFields() error = %v", err)
			}
			if fields == nil {
				t.Fatal("SecurityKeyFields() = nil, want the fields of a security key")
			}
			if fields.Flags != tt.flags || fields.Counter != tt.counter {
				t.Errorf("SecurityKeyFields() = %+v, want {Flags:%d Counter:%d}",
					*fields, tt.flags, tt.counter)
			}
		})
	}
}

func TestSecurityKeyFieldsAreAbsentForPlainKeys(t *testing.T) {
	sig, err := Sign(strings.NewReader("data\n"), newSigner(t), HashSHA512, "file")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	fields, err := sig.SecurityKeyFields()
	if err != nil {
		t.Fatalf("SecurityKeyFields() error = %v, want nil", err)
	}
	if fields != nil {
		t.Errorf("SecurityKeyFields() = %+v, want nil for an ed25519 signature", *fields)
	}
}

// A signature claiming to be from a security key must not yield fields that
// were never there, whatever it carries.
func TestSecurityKeyFieldsRejectsMalformedRest(t *testing.T) {
	for name, rest := range map[string][]byte{
		"empty":          nil,
		"truncated":      {0x01, 0x00},
		"trailing bytes": {0x01, 0x00, 0x00, 0x00, 0x2a, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			sig := newSKSignature(t, "data\n", 0x01, 42)
			sig.Signature.Rest = rest
			fields, err := sig.SecurityKeyFields()
			if err == nil {
				t.Fatalf("SecurityKeyFields() = %+v, want an error", fields)
			}
			if fields != nil {
				t.Errorf("SecurityKeyFields() = %+v, want nil alongside the error", *fields)
			}
		})
	}
}
