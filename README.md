<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# ssh-sign

This tool signs and verifies data using the
[SSHSIG](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/PROTOCOL.sshsig)
protocol, as implemented by `ssh-keygen -Y sign` and `ssh-keygen -Y verify`.

Compared to `ssh-keygen`, which has *a lot* of features, most of which are not
related to SSHSIG itself, `ssh-sign` is dedicated to SSHSIG. It attempts to
provide a simpler user interface, informative output/error messages, including
optional JSON output for scripting purposes.

[hiddeco/sshsig](https://github.com/hiddeco/sshsig) is used for the protocol
itself (thanks!), since SSHSIG is not supported by `golang.org/x/crypto` yet.


## Disclaimer

> [!WARNING]
> This is currently just a proof of concept, and very much a work in progress.
>
> You should probably not use it for anything important.


## Exit status

`ssh-sign` exits `0` when the command succeeds, `1` on runtime errors and `2`
on user errors such as bad usage.

In JSON mode, runtime errors are written to stdout under `error` before exiting
`1`.


## Result fields

`verify` and `check` report each checked value next to the outcome of
checking it.

| field | meaning |
| --- | --- |
| `principal` | the identity the signer was pinned to with `-p` (`verify` only) |
| `authentication` | outcome of that pinning: `valid`, `invalid` or `disabled` |
| `namespace` | the namespace the signature carries (`verify` only; use `inspect` under `check`) |
| `designation` | outcome of checking the namespace against `-n` or allowed signers: `valid`, `invalid` or `disabled` |
| `verification` | outcome of the cryptographic check: `valid` or `invalid` |

`disabled` means that the corresponding check was not requested. With `check`,
`-K` disables `authentication` and `-N` disables `designation`. With `verify`,
`authentication` is disabled when `-p` is omitted, although the key must still
match an allowed signers entry. `designation` is disabled only with `-N`; a
matching `namespaces=` restriction instead makes it `valid`.

## Main command

```
$ ssh-sign --help
usage: ssh-sign [option].. <command> [command option]..

commands:
  inspect       Show signature details
  sign          Sign data with specified public key and namespace
  verify        Verify signed data using allowed signers files
  check         Verify signed data, with optional public key/namespace validation

options:
  -h, --help   display this help text and exit
  -j, --json   enable JSON output
```


## Sub commands

### Sign

`sign` creates an SSHSIG digital signature of given data.

#### Options
```
  -f, --data-file string   read data to sign from file instead of stdin
  -n, --namespace string   create signature with specified namespace (default "file")
  -k, --sign-key string    create signature using this pubkey reference (must exist in ssh-agent)
```

#### Example
```
$ ssh-add -L
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk user@localhost
$ echo test | ssh-sign sign -k 'AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk'
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAggLk2JJEthHz9x97Tprql
YfE157k0fPtVv76pglLTq6QAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtz
c2gtZWQyNTUxOQAAAEC4II0w5rOL2caBB33l3482sbG7fCkfG5yHWAFNl+hRTLVz
ErHRKw6biwpo2ZeYpEvmFQAxqn5iFWczak8drGAM
-----END SSH SIGNATURE-----
$ echo test > data
$ ssh-sign sign -k 'AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk' -f data > data.sig
$ cat data.sig
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAggLk2JJEthHz9x97Tprql
YfE157k0fPtVv76pglLTq6QAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtz
c2gtZWQyNTUxOQAAAEC4II0w5rOL2caBB33l3482sbG7fCkfG5yHWAFNl+hRTLVz
ErHRKw6biwpo2ZeYpEvmFQAxqn5iFWczak8drGAM
-----END SSH SIGNATURE-----
```

> [!NOTE]
> The public key specified on the command line is a reference to a pubkey that
> will be searched for in the SSH agent (env `SSH_AUTH_SOCK`). Make sure that
> the pubkey shows up in `ssh-add -L`.
>
> **Specifying keyfiles directly is not supported.** After all, you should be
> using a hardware token for your SSH key anyway, and therefore an agent of
> some kind.
>
> Agent connection and key listing time out after 30 seconds. Signing has no
> timeout because hardware keys may wait for a touch or PIN.


### Inspect

`inspect` generates signature metadata.

#### Options
```
  -s, --signature-file string   read signature from file instead of stdin
```

#### Example

```
$ ssh-sign inspect < data.sig
 version               | 1
 publickey_format      | ssh-ed25519
 publickey_blob        | AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk
 publickey_fingerprint | SHA256:7f4G0lT+fU/dDnPDfQd1wmQVPUxYvZm+ZNQqVJtlqNk
 namespace             | file
 hash_algorithm        | sha512
 signature_format      | ssh-ed25519
 signature_blob        | uCCNMOazi9nGgQd95d+PNrGxu3wpHxuch1gBTZfoUUy1cxKx0SsOm4sKaNmXmKRL5hUAMap+YhVnM2pPHaxgDA==
```

Alternatively with JSON output via e.g. `ssh-sign -j inspect -s data.sig`:
```json
{
  "result": {
    "version": "1",
    "public_key": {
      "format": "ssh-ed25519",
      "blob": "AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk",
      "fingerprint": "SHA256:7f4G0lT+fU/dDnPDfQd1wmQVPUxYvZm+ZNQqVJtlqNk"
    },
    "namespace": "file",
    "hash_algorithm": "sha512",
    "signature": {
      "format": "ssh-ed25519",
      "blob": "uCCNMOazi9nGgQd95d+PNrGxu3wpHxuch1gBTZfoUUy1cxKx0SsOm4sKaNmXmKRL5hUAMap+YhVnM2pPHaxgDA=="
    }
  }
}
```


### Check

`check` verifies signatures without requiring an allowed signers file.

#### Options

```
  -f, --verify-file string      read data to verify from file (required)
  -s, --signature-file string   read signature from file instead of stdin
  -n, --namespace string        require a signature with specified namespace (default "file")
  -N, --no-namespace            accept a signature with any namespace
  -k, --auth-key string         require a signature created by specified public key
  -K, --no-auth-key             accept a signature created by any public key
```

#### Example

```
ssh-sign check -f data -s data.sig -KN
 authentication = disabled
 designation    = disabled
 verification   = valid
$ ssh-sign check -f data -s data.sig -Kn file
 authentication = disabled
 designation    = valid
 verification   = valid
$ ssh-sign check -f data -s data.sig -k AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk -n file
 authentication = valid
 designation    = valid
 verification   = valid
$ ssh-sign check -f data -s data.sig -k AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS0abc -n abc
error: check: signature was created by public key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk" (expected "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS0abc")
error: check: signature contains namespace "file" (expected "abc")
```

Enabling JSON output for the last one gives:
```json
{
  "error": [
    "signature was created by public key \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk\" (expected \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS0abc\")",
    "signature contains namespace \"file\" (expected \"abc\")"
  ],
  "result": {
    "authentication": "invalid",
    "designation": "invalid",
    "verification": "valid"
  }
}
```


### Verify

`verify` verifies signatures by parsing an allowed signers file.


#### Options
```
  -a, --allowed-signers-file string   read allowed signers, with options, from file (required)
  -f, --verify-file string            read data to verify from file (required)
  -s, --signature-file string         read signature from file instead of stdin
  -n, --namespace string              require a signature with specified namespace
  -N, --no-namespace                  ignore the signature namespace and allowed signers namespace restrictions
  -p, --principal string              allow this signer (email usually) from allowed signers file
  -t, --timestamp string              validate this RFC3339/RFC1123 timestamp rather than current time
```

> [!IMPORTANT]
> If neither `-n` nor `-N` is given, the signature's namespace must match a
> `namespaces=` restriction in an applicable allowed signers entry. Entries
> with namespace restrictions take precedence over unrestricted entries,
> regardless of their order. Verification fails if no restriction matches.
>
> Use `-n` when the expected namespace is known independently. `-N` disables
> all namespace checks, including restrictions in the allowed signers file.
> Key, principal and time checks still apply.

> [!NOTE]
> `authentication` indicates whether the signer is authorized for the
> principal specified with `-p`. If `-p` is omitted, `authentication` is
> `disabled` and `principal` contains the pattern-list from the matching allowed
> signers entry. The signer's key must still appear in the allowed signers file.

#### Example

```
$ echo 'test1@localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk' > allowed_signers
$ ssh-sign verify -a allowed_signers -f data < data.sig
error: verify: signature namespace "file" was left unverified: no namespace was requested and no matching allowed signers entry restricts one (use -n, -N or namespaces=)
$ ssh-sign verify -a allowed_signers -f data -n file -p test1@localhost < data.sig
 principal      = test1@localhost
 authentication = valid
 namespace      = file
 designation    = valid
 verification   = valid
$ ssh-sign verify -a allowed_signers -f data -n file -p test2@localhost < data.sig
error: verify: principal "test2@localhost" not found within allowed signers
```

```
$ echo 'test1@localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS0abc' > allowed_signers
$ ssh-sign verify -a allowed_signers -f data < data.sig
error: verify: signer public key not found within allowed signers
```

```
$ echo 'test1@localhost namespaces="abc" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk' > allowed_signers
$ ssh-sign verify -a allowed_signers -f data -p test1@localhost < data.sig
error: verify: principal "test1@localhost" found in allowed signers, but failed constraints: line=1: namespace mismatch
```

```
$ echo 'test1@localhost namespaces="file",valid-after="20260101",valid-before="20260201" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk' > allowed_signers
$ date
Tue Feb  3 22:49:14 UTC 2026
$ ssh-sign verify -a allowed_signers -f data -p test1@localhost < data.sig
error: verify: principal "test1@localhost" found in allowed signers, but failed constraints: line=1: expired
$ ssh-sign verify -a allowed_signers -f data -p test1@localhost -t 2026-01-15 < data.sig
 principal      = test1@localhost
 authentication = valid
 namespace      = file
 designation    = valid
 verification   = valid
$ ssh-sign verify -a allowed_signers -f data -p test1@localhost -t 2025-12-31 < data.sig
error: verify: principal "test1@localhost" found in allowed signers, but failed constraints: line=1: not yet valid
```

JSON output for a successful verification with `-n file`:
```json
{
  "result": {
    "principal": "test1@localhost",
    "authentication": "valid",
    "namespace": "file",
    "designation": "valid",
    "verification": "valid"
  }
}
```
