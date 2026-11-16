<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# Examples

The examples use `ssh-sign` on your PATH and an OpenSSH agent. Run them in a
scratch directory. If you want to use a separate agent for the walkthrough,
start a shell with `ssh-agent bash` and type `exit` when finished.

```sh
ssh-keygen -q -t ed25519 -N '' -f key
ssh-keygen -q -t ed25519 -N '' -f other
ssh-add key
ssh-add -L
printf 'test\n' > data
```

The second key is used to demonstrate a key mismatch. For real verification,
obtain the expected public key through a trusted channel.

## Sign a file or a stream

Pass the public key line to select the signing key in the agent. Both commands
sign the same bytes under the default namespace, `file`.

```sh
ssh-sign sign -k "$(cat key.pub)" -f data > data.sig
printf 'test\n' | ssh-sign sign -k "$(cat key.pub)" > stream.sig
cmp data.sig stream.sig
```

The output is an armored signature beginning with
`-----BEGIN SSH SIGNATURE-----` and ending with
`-----END SSH SIGNATURE-----`. You can also pass just the base64 key blob.

```sh
ssh-sign sign -k "$(awk '{print $2}' key.pub)" -f data > data.sig
```

## Inspect a signature

Read the signature from stdin for text output, or use `-j` for JSON.

```sh
ssh-sign inspect < data.sig
ssh-sign inspect -j -s data.sig
```

The example text output abbreviates the key and signature blobs.

```text
 version               | 1
 publickey_format      | ssh-ed25519
 publickey_blob        | AAAAC3Nza...
 publickey_fingerprint | SHA256:7f4G0lT+fU/dDnPDfQd1wmQVPUxYvZm+ZNQqVJtlqNk
 namespace             | file
 hash_algorithm        | sha512
 signature_format      | ssh-ed25519
 signature_blob        | uCCNMOazi...
```

JSON groups the same fields under `result`.

```json
{
  "result": {
    "version": "1",
    "public_key": {
      "format": "ssh-ed25519",
      "blob": "AAAAC3Nza...",
      "fingerprint": "SHA256:7f4G0lT+fU/dDnPDfQd1wmQVPUxYvZm+ZNQqVJtlqNk"
    },
    "namespace": "file",
    "hash_algorithm": "sha512",
    "signature": {
      "format": "ssh-ed25519",
      "blob": "uCCNMOazi..."
    }
  }
}
```

A FIDO signature can include the application, flags and counter.

```text
 publickey_application | ssh:
 securitykey_flags     | 0x05 (presence,user-verified)
 securitykey_counter   | 13
```

In JSON, the application is under `result.public_key.application` and the
flags and counter are under `result.signature.security_key`. `inspect`
reports the signer's claimed flags without verifying the signature. See
[ssh-sign(1)](ssh-sign.1.md#inspect) for what those flags mean.

## Check a signature with or without a trusted key

Use `-k` to check against a trusted public key. If you only want the
cryptographic check, use `-K` to accept the key in the signature. Add `-N`
to skip namespace checking as well.

```sh
ssh-sign check -f data -s data.sig -k "$(cat key.pub)" -n file
ssh-sign check -f data -s data.sig -K -n file
ssh-sign check -f data -s data.sig -KN
```

The last command reports `authentication = disabled`,
`designation = disabled` and `verification = valid`.

Give both the wrong key and the wrong namespace to see independent failures.
This command exits with status 1 and returns JSON on stdout.

```sh
ssh-sign check -j -f data -s data.sig -k "$(cat other.pub)" -n release
```

The example response abbreviates both key blobs.

```json
{
  "error": [
    "signature was created by public key \"ssh-ed25519 AAAAC3Nza...\" (expected \"ssh-ed25519 AAAAC3Nza...\")",
    "signature contains namespace \"file\" (expected \"release\")"
  ],
  "result": {
    "authentication": "invalid",
    "designation": "invalid",
    "verification": "valid"
  }
}
```

## Verify a principal and namespace

Create an allowed signers entry and provide the expected principal and
namespace. The signature is read from stdin in this example.

```sh
printf 'alice@example.com %s\n' "$(cat key.pub)" > allowed_signers
ssh-sign verify -j -a allowed_signers -p alice@example.com -n file \
    -f data < data.sig
```

```json
{
  "result": {
    "authentication": "valid",
    "designation": "valid",
    "namespace": "file",
    "principal": "alice@example.com",
    "verification": "valid",
    "entry": {
      "file": "allowed_signers",
      "line": 1
    }
  }
}
```

The entry has no namespace restriction, so omitting `-n file` fails. Asking
for a different principal also fails.

```sh
ssh-sign verify -a allowed_signers -p alice@example.com -f data -s data.sig
ssh-sign verify -a allowed_signers -p bob@example.com -n file -f data -s data.sig
```

To see how a missing key is reported, make a file that trusts only the second
key. Omit `-p` here to look for the key independently of the principal.

```sh
printf 'alice@example.com %s\n' "$(cat other.pub)" > other_signers
ssh-sign verify -a other_signers -n file -f data -s data.sig
```

An entry can supply the namespace policy. The first verification below
succeeds with `namespaces="file"`. The second fails with a namespace mismatch
because the entry requires `release`.

```sh
printf 'alice@example.com namespaces="file" %s\n' "$(cat key.pub)" > file_signers
ssh-sign verify -a file_signers -p alice@example.com -f data -s data.sig
printf 'alice@example.com namespaces="release" %s\n' "$(cat key.pub)" > release_signers
ssh-sign verify -a release_signers -p alice@example.com -f data -s data.sig
```

## Verify at a specific time

Use UTC in both the allowed signers entry and the command to get the same
result in any time zone. The first verification succeeds. The second reports
an expired entry, and the third reports an entry that is not yet valid.

```sh
printf 'alice@example.com namespaces="file",valid-after="20260101Z",valid-before="20260201Z" %s\n' \
    "$(cat key.pub)" > dated_signers
ssh-sign verify -a dated_signers -p alice@example.com -f data -s data.sig -t 2026-01-15T12:00:00Z
ssh-sign verify -a dated_signers -p alice@example.com -f data -s data.sig -t 2026-02-02T00:00:00Z
ssh-sign verify -a dated_signers -p alice@example.com -f data -s data.sig -t 2025-12-31T00:00:00Z
```

The time supplied with `-t` controls when the entry is evaluated. The
signature does not establish when signing took place. The format and
inclusive time bounds are described in
[ssh-sign-allowed-signers(5)](ssh-sign-allowed-signers.5.md#timestamps).

## Capture debug output

Redirect stderr to keep diagnostics separate from the signature.

```sh
ssh-sign sign -vv -k "$(cat key.pub)" -f data > data.sig 2> sign.log
cat sign.log
```

The log shows the input path, agent connection, sandbox status, key listing
and selected key. Socket paths, Landlock ABIs and fingerprints depend on your
environment. This run had one key in the agent, and the fingerprints are
abbreviated.

```text
debug1: running command command=sign json=false
debug2: reading input role=data path=data
debug1: agent: connecting socket=/run/user/1000/ssh-agent.socket timeout=30s
debug1: agent: connected socket=/run/user/1000/ssh-agent.socket
debug2: landlock: configuring policy_abi=10 best_effort=true
debug1: landlock: enabled effective_abi=9 kernel_abi=9 threads=all best_effort=true
debug2: agent: listing keys timeout=30s
debug2: agent: listed keys keys=1
debug1: agent: matched key type=ssh-ed25519 fingerprint=SHA256:VYez2F...
debug1: sign: signing namespace=file key.type=ssh-ed25519 key.fingerprint=SHA256:VYez2F...
debug1: sign: signed format=ssh-ed25519 hash=sha512
```

For verification, `-v` shows malformed allowed signers entries while leaving
the result on stdout.

```sh
printf 'broken-entry\n' > signers_with_error
cat allowed_signers >> signers_with_error
ssh-sign verify -v -j -a signers_with_error -p alice@example.com -n file \
    -f data -s data.sig > result.json 2> verify.log
cat result.json
cat verify.log
```

## Trust a certificate authority

Create a CA key and issue a user certificate for `key`, valid for the
principal `alice@example.com`. Add the key to the agent again so that it also
loads the certificate, then sign with the certificate.

```sh
ssh-keygen -q -t ed25519 -N '' -f ca
ssh-keygen -q -s ca -I alice -n alice@example.com -z 1 key.pub
ssh-add key
ssh-sign sign -k "$(cat key-cert.pub)" -f data > cert.sig
```

A `cert-authority` entry trusts the user certificates the CA signs. The
requested principal must match the entry and be listed in the certificate, so
the first verification succeeds and the second fails. A signature made with
the plain key, without the certificate, does not match the entry either.

```sh
printf '*@example.com cert-authority %s\n' "$(cat ca.pub)" > ca_signers
ssh-sign verify -a ca_signers -p alice@example.com -n file -f data -s cert.sig
ssh-sign verify -a ca_signers -p bob@example.com -n file -f data -s cert.sig
ssh-sign verify -a ca_signers -p alice@example.com -n file -f data -s data.sig
```

Without `-p`, the certificate principals that match the entry are reported.
JSON lists them separately, as a certificate principal may contain a comma.

```sh
ssh-sign verify -j -a ca_signers -n file -f data -s cert.sig
```

```json
{
  "result": {
    "authentication": "disabled",
    "designation": "valid",
    "namespace": "file",
    "principal": "alice@example.com",
    "principals": [
      "alice@example.com"
    ],
    "verification": "valid",
    "entry": {
      "file": "ca_signers",
      "line": 1
    }
  }
}
```

## Use an alias and a default signers directory

Use a configuration directory inside the scratch directory. The `work`
alias lets `sign` use its configured default key and lets `check` refer to
the same public key by name. `verify` reads `signers/local.conf` when
`-a` is omitted.

```sh
mkdir -m 700 demo-config demo-config/signers
export SSH_SIGN_CONFIG_DIR="$PWD/demo-config"
printf '[sign]\nkey = work\n\n[alias]\nwork = %s\n' "$(cat key.pub)" > "$SSH_SIGN_CONFIG_DIR/config"
cp file_signers "$SSH_SIGN_CONFIG_DIR/signers/local.conf"
chmod 600 "$SSH_SIGN_CONFIG_DIR/config" "$SSH_SIGN_CONFIG_DIR/signers/local.conf"

ssh-sign sign -f data > configured.sig
ssh-sign check -k work -f data -s configured.sig
ssh-sign verify -p alice@example.com -f data -s configured.sig
```

## Exchange signatures with OpenSSH

Verify a signature produced by `ssh-sign` with OpenSSH, then sign using
OpenSSH and verify with `ssh-sign`. OpenSSH takes the data on stdin and
requires the expected principal and namespace for verification.

```sh
ssh-keygen -Y verify -f allowed_signers -I alice@example.com -n file -s data.sig < data
ssh-keygen -Y sign -f key.pub -n file < data > openssh.sig
ssh-sign verify -a allowed_signers -p alice@example.com -n file -f data -s openssh.sig
```
