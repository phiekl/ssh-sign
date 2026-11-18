<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# ssh-sign

`ssh-sign` signs and verifies data using SSH keys and the SSHSIG format used by
`ssh-keygen -Y sign` and `ssh-keygen -Y verify`.

Compared to `ssh-keygen`, which has *a lot* of features, most of which are not
related to SSHSIG itself, `ssh-sign` is dedicated to SSHSIG. Its main goal is
to provide a simpler user interface, more informative output/error messages,
including optional JSON output for scripting purposes.

## Features

### Signing with an SSH agent

`sign` reads data to sign from a file or stdin and writes an armored SSHSIG
signature to stdout. The public key line or blob you pass to `-k` identifies a
key in the agent at `$SSH_AUTH_SOCK`. Any agent that implements the OpenSSH
agent protocol works, including those backed by hardware tokens. `ssh-sign`
never reads private key files.

### Verification by identity or public key

Each signature carries a namespace that describes what the signed data is for,
set with `sign -n` (the default is `file`). Verification can require a
particular namespace, so that a signature made for one purpose is not accepted
for another.

An allowed signers file tells `verify` which keys to trust and which principals
they can sign for. Principals are usually email addresses. An entry can also
trust a certificate authority to vouch for user certificates, and limit a key
to certain namespaces or a time window.

Pass `-n` to require a specific namespace. Any `namespaces=` restriction in
the matching entry still applies. Use `-N` to skip namespace checks entirely.

`check` verifies a signature without an allowed signers file. Use `-k` to
require a particular signing key or `-K` to verify with whichever key is
embedded in the signature.

### OpenSSH compatibility

You can sign with `ssh-sign` and verify with `ssh-keygen`, or the other way
around. `ssh-sign` supports the plain form of the `ssh-mldsa44-ed25519` hybrid
key introduced in OpenSSH 10.6.

### Signature inspection and JSON output

`inspect` shows the public key fingerprint, namespace, hash algorithm and
signature format. For FIDO signatures, it also shows the key's application, the
raw and decoded flags, and the signer's counter. It reads these fields without
verifying the signature.

Use `-j` for JSON output. For example, a signature can verify against the data
while failing a key or namespace check. The JSON response can show which checks
passed alongside the errors.

### Configuration and default signers

Set a default signing key with `sign.key` in `~/.ssh/sign/config`. You can also
give public keys aliases in that file and use those names with `sign -k` or
`check -k`.

By default, all non-hidden `*.conf` files in `~/.ssh/sign/signers/` are loaded
in lexical order, as if they were concatenated into a single allowed signers
file. Use `-a` to read a specific file instead.

`verify` rejects signers whose key or CA is listed in a revocation list in
`~/.ssh/sign/revoked/`, either a text list or an OpenSSH KRL. Use `-r` to add
another list.

### Landlock sandbox

On Linux, once its inputs are open, `ssh-sign` uses Landlock to deny itself
further file access, program execution and networking. How much is enforced
depends on the kernel. Run with `-v` to see the effective Landlock ABI.

## Examples

Sign `data` with a key already available in your SSH agent. Use
`ssh-add -L` to list the available public keys.

```sh
ssh-sign sign -k "$(cat key.pub)" -f data > data.sig
```

Inspect the signature or check it against a trusted copy of the public key.

```sh
ssh-sign inspect -s data.sig
ssh-sign check -k "$(cat key.pub)" -f data -s data.sig
```

Associate the trusted key with a principal and verify a signature for that
principal in the default signing namespace, `file`.

```sh
printf 'alice@example.com %s\n' "$(cat key.pub)" > allowed_signers
ssh-sign verify -a allowed_signers -p alice@example.com -n file -f data -s data.sig
```

Run `ssh-sign --help` to list commands or `ssh-sign verify --help` for a
command's options. [ssh-sign(1)](doc/ssh-sign.1.md) covers configuration and
all command options.
[ssh-sign-allowed-signers(5)](doc/ssh-sign-allowed-signers.5.md) covers the
trusted signer file format and how entries are matched.

See [more examples](doc/examples.md) for JSON output, verification failures,
time restrictions, certificate authorities, revocation, configuration and
OpenSSH interoperability.

## Building and testing

Building requires Go 1.27. On x86-64, the default target is x86-64-v3. Use
`make build GOAMD64=v1` for older CPUs.

```sh
make build      # build/ssh-sign
make test       # unit and end-to-end tests
make vet        # go vet
make fuzz       # fuzz targets, FUZZTIME=10s by default
make man        # man pages in build/man/
```

`make man` requires [go-md2man](https://github.com/cpuguy83/go-md2man). Read
the generated pages with `man -l build/man/ssh-sign.1` and `man -l
build/man/ssh-sign-allowed-signers.5`. The footer date defaults to the last
commit date of each Markdown source. To override it, run `make -B man
MAN_DATE=YYYY-MM-DD`.

See the [implementation notes](doc/implementation.md) for protocol references
and interoperability tests.
