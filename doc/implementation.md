<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# Implementation notes

The [SSHSIG protocol](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/PROTOCOL.sshsig)
is implemented in [pkg/sshsig](../pkg/sshsig) using the Go standard library
and `golang.org/x/crypto/ssh`. The [interoperability tests](../interop_test.go)
sign and verify in both directions with `ssh-keygen` and compare allowed
signers behavior.

## Differences from ssh-keygen

Allowed signers files are parsed more strictly, as listed in
[ssh-sign-allowed-signers(5)](ssh-sign-allowed-signers.5.md#differences-from-ssh-keygen).
The aim is one-way compatibility: `ssh-sign` may skip entries that
`ssh-keygen` accepts, but should not accept an entry that `ssh-keygen`
rejects. `TestAllowedSignersMatchesOpenSSH` runs a fixed set of entries
through both tools and requires them to agree, except on cases marked as
deliberate differences, where only `ssh-keygen` may accept. These include
uppercase option names, stray carriage returns and NUL bytes.
`TestAllowedSignersUnicodeAndControls` runs a set of Unicode and control
characters through both tools and checks that `ssh-keygen` accepts each line.
`TestCertAuthorityMatchesOpenSSH` does the same for `cert-authority` entries
and compares the principals reported without `-p` with
`ssh-keygen -Y find-principals`. Invalid UTF-8 and entries outside these sets
are not compared.

Armored signatures differ in both directions. Both accept trailing ASCII
whitespace, such as an extra newline from pasting. `ssh-keygen` ignores any
other text after the END line, while `ssh-sign` rejects it. When a signature
is read from stdin, `ssh-sign` skips up to 1024 bytes of whitespace-only lines
before the header. This goes beyond the SSHSIG format, and `ssh-keygen`
rejects such lines. A signature file must still start with the header.

## Landlock

On Linux, each command opens its inputs, and `sign` connects to
`SSH_AUTH_SOCK`, before calling `Restrict` in
[internal/landlock](../internal/landlock). It applies the go-landlock V10
policy in best-effort mode, which denies new filesystem access, execution, TCP
and UDP networking, and access to external pathname and abstract Unix
sockets. Existing file descriptors remain usable. The local time zone is
loaded beforehand, since timestamps may need it after filesystem access is
denied.

Older kernels get the subset their ABI supports. With an unsupported kernel
or disabled Landlock, the command runs unrestricted. go-landlock treats a
failed ABI query the same way. With the `landlocktsync` build tag,
go-landlock requires ABI 8 to restrict all threads, so lower ABIs also run
unrestricted.

After the policy is applied, ssh-sign queries the ABI again, only for `-v`.
It logs the effective ABI after go-landlock's errata adjustments. If this
second query fails, ssh-sign cannot report the effective ABI.

## ML-DSA

The `ssh-mldsa44-ed25519` implementation uses `crypto/mldsa` and
`crypto/ed25519`, following [OpenSSH's implementation](https://github.com/openssh/openssh-portable/blob/V_10_6_P2/ssh-mldsa-eddsa.c),
the [SSH composite signature draft](https://datatracker.ietf.org/doc/html/draft-miller-sshm-mldsa44-ed25519-composite-sigs-00)
and the [LAMPS composite signature draft](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-18).
