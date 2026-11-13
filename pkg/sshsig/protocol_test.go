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

// Produced the same way by OpenSSH 10.6p2, which added ssh-mldsa44-ed25519.
const goldenMLDSA44Ed25519Key = "ssh-mldsa44-ed25519 " +
	"AAAAE3NzaC1tbGRzYTQ0LWVkMjU1MTkAAAVATTvYcgcD+OmoK52DENQ30Xua3AZ34GDK" +
	"Hp1vcpeJ+ougzD+qOUOf/gQbH4ec94WrXbBQ5RAG7+tGXXg+8QBjo5Mewo/veRYki0Pt" +
	"61Qczlk5V8x9bhZe/todk82AkZ4vqh3l2GjU5nvibs+FcNrcrRdSc7qjm2IcJaMNQTwt" +
	"0JeJJLsjfg10gBoYwoVPme0AOG3knesOvIRViy3PdaLr8b6tT3SgMkaYJxg9At5Yodk7" +
	"Kf9RXlX7DC63FOe1JmiAzzZi140sfPdrV/GX7K0OM4DQQW4EkQWsURHjhyfUpfLUGvgt" +
	"gm8L+BIMQ3XOmkiitY3na/menIkNLG55NB2EZGFS5mL1Ro6vmUSzVTPmyg+Z52Llp7xB" +
	"6wiIx/UhUuomP29Q3qVqwilAtrv2jFjjieJ0LX2yE/gSDgx7LEVVzaWB0Sz0r8zVoPsG" +
	"dcEUCAJVQFseWssXX77iEkvX0EInZnsMxw7nKmlmZkFv3nZbS2H1Qe22E4uOMlR/B0kp" +
	"ZV0qID8vjyOmcnUY3v+Fe5U3jz4S5aMGWAb4gyqbXvudWUxg6s96bwlC1ygVMsz1R8JR" +
	"NHOSzR+/wa766ZdyfISeK5vIy/iWtEiLbFm9UGVNd/4MNa6A0OzJRiPoE2mVIM93pKhu" +
	"QoEOFhRUY45MHYKr1DK2xjuIVvYViC/LLNq/3aQED2ow0HNez+2vtEQ29uRX1cE62/8k" +
	"zLAEe7HrlyUCNP42E+ErhyDfVTr6edpZgEYE9WZTAhFh+ySjCr+DsLeyJrbWr3SX7BkG" +
	"58Sv4LIsEYW4zY9ZIHSdSPJCVYyFAWg0E3raEDwTVX+j16ORsth4FFH1XtgPy/zjZind" +
	"SyhHBArLOVcDC7xUnjH+t38BD6sDJCN+R9NKBZOBObMvMii7jg1cfL/PLAGX95NTD+xB" +
	"Bn14e4dZuO2Li6MDv0qxA2PVk4xA4I8cIL3mfeF53pTuanSM3SHSNO5eMhQ0V5VCvHtS" +
	"6zYTU/3kbgqA5zQuz+TpxcNAfKxr81RT3C4uSgcf1FQ/imtA2JVh3OdxdDhS4VYeiUlC" +
	"PanFahdotIpNdm5qWou2qHseHbjXEP3GwbZAZUgflCmxCJL3FqwtShT/1muoI1SdFwTS" +
	"h8AlV9mGxQW1BJC3gQ0M6s5dmbIVelc2f2dVZU5D4uKikGja+OPCScOaoJmaUeZV7ejZ" +
	"Lk95JECjtV7roAw6qdEIkKSZMA6aAi6bwQsgYIBrGjIMpflsj3j6jUWSTRnYYmFYfohH" +
	"soqsfQycUr41QxA7enjk6aC2G1lfWn/QMgzjPOUnQycd/rkubSyfxZ5NXUNH7QF25V3x" +
	"ks9BrbyULs0TagvzNfQoSWm13UnuHuSOexPyy3j99MwBip9gE3qsPTH7O+b/dov1K9m4" +
	"12IDg8bkcCmSpTiaC6A5lEP4omatgTUT6Q+KlaWJrdu5wugvh2VAq7en36QZoF9CD6f1" +
	"V1H1yP+r+KMn3Lgg5u4uIGlihK1pcabKV1BuoHu+Vxs/HjZGWmtQym5VgEZPgfH4BTGE" +
	"AsW5kz86lJtafL19D8rKISkUB4WjbhK5pqFarUkAJyiyrsFw0K0Jwa4OnLYyAo4Vi/UP" +
	"uV6WQtXgNj2Q7BSHEWB0JqDwPTi8xal1WBkokTZtKx7BY0lW9nzVVF41qkq1tlLVwO7e" +
	"kVBPexBLaUQP0dyS/FDzyeVEjlfs1NWPXbQT6MYkhBlQmWjZA1Quw+vaO269o7pFNBNU" +
	"xIAaSUqjiJyvE0CwHji/e7t2DoghRbtVKKt5X+1R2xx6FulIG4UVEBQcaEF3"

const goldenMLDSA44Ed25519SHA512 = `-----BEGIN SSH SIGNATURE-----
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
-----END SSH SIGNATURE-----
`

const goldenMLDSA44Ed25519SHA256 = `-----BEGIN SSH SIGNATURE-----
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
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
		"mldsa44-ed25519 sha512": {
			armored:   goldenMLDSA44Ed25519SHA512,
			keyLine:   goldenMLDSA44Ed25519Key,
			hash:      HashSHA512,
			sigFormat: KeyAlgoMLDSA44Ed25519,
		},
		"mldsa44-ed25519 sha256": {
			armored:   goldenMLDSA44Ed25519SHA256,
			keyLine:   goldenMLDSA44Ed25519Key,
			hash:      HashSHA256,
			sigFormat: KeyAlgoMLDSA44Ed25519,
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
