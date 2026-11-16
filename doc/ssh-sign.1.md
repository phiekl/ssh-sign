<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# ssh-sign(1)

Sign and verify data using SSH keys.

```
ssh-sign -h
ssh-sign sign [options]
ssh-sign verify -f data [options]
ssh-sign check -f data (-k key | -K) [options]
ssh-sign inspect [options]
ssh-sign version [options]
```

**ssh-sign** creates, verifies and inspects SSHSIG signatures, the format used
by **ssh-keygen -Y sign** and **ssh-keygen -Y verify**. Signatures include the
signer's public key and a namespace that identifies the purpose of the signed
data. **verify** uses an allowed signers file to decide which keys to trust.
**check** can instead take a trusted key directly.

The OpenSSH **ssh-mldsa44-ed25519** hybrid key type is supported, but not yet
in certificates.

## Common options

Command options follow the command name.

- **-h**, **--help**: Show help and exit. Before the command name, list the
  commands. After the command name, list its options.
- **-j**, **--json**: Write the command's output as JSON. See [OUTPUT](#output).
- **-v**, **--verbose**: Write debug output to stderr. Repeat for more detail,
  up to **-vvv**. See [DEBUG OUTPUT](#debug-output).

## Commands

### sign

Sign data through the SSH agent at **SSH_AUTH_SOCK** and write an armored
signature to stdout. The key reference identifies a key listed by
**ssh-add -L**. It may be the base64 key blob alone, an OpenSSH public key
line, or a configuration alias. To read a public key from a file, pass its
contents with **-k "$(cat key.pub)"**. **ssh-sign** never reads private key
files, so the key must be available through the agent.

Connecting to the agent and listing its keys each have a 30-second timeout.
The signing request can wait indefinitely for hardware interaction such as a
touch or PIN. A signing certificate must be a currently valid user certificate
with a valid CA signature.

- **-f**, **--data-file** *file*: Read the data from *file*. Default is stdin.
- **-k**, **--sign-key** *key*: Select the agent key. Defaults to **sign.key**
  in the configuration, if set. A key is required.
- **-n**, **--namespace** *name*: Set the signature namespace. Default is
  **file**.

### verify

Verify the data and authorize the signer against
[**ssh-sign-allowed-signers**(5)](ssh-sign-allowed-signers.5.md). With **-n**,
the signature must match the expected namespace and satisfy any
**namespaces=** restriction in the entry. Without **-n** or **-N**, a matching
entry with a **namespaces=** restriction is required. Restricted entries take
precedence over unrestricted entries in this mode. **-N** skips both
namespace checks. Key, principal and time checks still apply.

- **-a**, **--allowed-signers-file** *file*: Read allowed signers from *file*.
  Defaults to the files in the signers directory described under
  [FILES](#files).
- **-n**, **--namespace** *name*: Require this namespace. Incompatible with
  **-N**.
- **-N**, **--no-namespace**: Skip namespace checks.
- **-p**, **--principal** *identity*: Require an allowed signers entry that
  matches this identity, typically an email address. With **-p** omitted,
  the signer must still match an entry, and the entry's principal patterns
  are reported. For a **cert-authority** entry, the matching certificate
  principals are reported instead.

The **-f**, **-s** and **-t** options are described under
[VERIFICATION INPUTS](#verification-inputs).

### check

Verify the data using the key in the signature. Require a specific key with
**-k**, or explicitly accept any key with **-K**. Use **-K** to check
integrity when the signer's identity is irrelevant.

- **-k**, **--auth-key** *key*: Require the given public key. The same key
  reference forms as **sign -k** are accepted. Use exactly one of **-k** and
  **-K**.
- **-K**, **--no-auth-key**: Accept any key and skip certificate validity
  checks.
- **-n**, **--namespace** *name*: Require this namespace. Default is **file**.
  Incompatible with **-N**.
- **-N**, **--no-namespace**: Accept any namespace.

The **-f**, **-s** and **-t** options are described under
[VERIFICATION INPUTS](#verification-inputs).

### inspect

Show the signature metadata, including the public key, its SHA-256 fingerprint,
the namespace, the hash algorithm and the signature blob. This command reads
the metadata without verifying the signature.

- **-s**, **--signature-file** *file*: Read the signature from *file*.
  Default is stdin.

For a FIDO security key, the text fields **publickey_application**,
**securitykey_flags** and **securitykey_counter** show the key's application,
the raw flag byte with decoded names, and the counter. In JSON the application
is **public_key.application**, and **signature.security_key** contains
**flags**, **user_presence**, **user_verification**, **backup_eligible**,
**backed_up** and **counter**. A valid signature authenticates the flags and
counter as reported by the signer. It does not establish that genuine hardware
produced the signature or that a person touched the key. A key created with
**no-touch-required** may report **0x00 (none)**.

### version

Show the version. Builds made with **make** use the version from
**git describe** by default. Other builds use the module version recorded by
Go, or **unknown** when it is unavailable.

## Verification inputs

**verify** and **check** accept these options.

- **-f**, **--verify-file** *file*: Read the signed data from *file*. Required.
- **-s**, **--signature-file** *file*: Read the signature from *file*.
  Defaults to stdin when redirected or piped. When stdin is a terminal, the
  default is the data filename with **.sig** appended.
- **-t**, **--timestamp** *time*: Use this time for validity checks. Default
  is the current time. For **verify**, it applies to allowed signers entries
  and certificates. For **check**, it applies only to certificate validity
  when key authentication is enabled.

**-t** accepts RFC3339 with optional fractional seconds, RFC1123 with a
numeric offset, **UTC** or **GMT**, and local-time values in the forms
**YYYY-MM-DD** and **YYYY-MM-DD HH:MM:SS**. For results that do not depend on
the local time zone, give **-t** an explicit offset and end allowed signers
timestamps with **Z**.

**inspect**, **verify** and **check** accept whitespace after the signature's
END line and reject any other trailing text, unlike **ssh-keygen**, which
ignores it. A signature read from stdin may also be preceded by up to 1024
bytes of blank lines, as left by pasting into a terminal. A signature file
must start with the header.

When a certificate is checked, it must be a user certificate valid at the
chosen time, with a valid CA signature. Authentication compares the full
certificate against the expected key or allowed signers entry, or, for a
**cert-authority** entry, the CA key. Embedded principals are checked only
for **cert-authority** entries.

## Files

### ~/.ssh/sign/config

Optional configuration file. Use **SSH_SIGN_CONFIG_DIR** to change the
directory. The file uses case-sensitive section and option names, unquoted
values, and full-line comments starting with **#**. Empty lines are ignored.

- **sign.key**: Default public key or alias for **sign**.
- **alias.***name*: Public key referenced by **sign.key**, **--sign-key** or
  **--auth-key**. Alias names may contain ASCII letters, digits and
  **. _ % + - @**.

For example, this configuration selects the **work** key by default.

```ini
[sign]
key = work

[alias]
work = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk
```

### ~/.ssh/sign/signers/

Default source of allowed signers for **verify** when **-a** is omitted.
Non-hidden regular **\*.conf** files are read in lexical order, with a
combined limit of 64 MiB. The format is described in
[**ssh-sign-allowed-signers**(5)](ssh-sign-allowed-signers.5.md).

On Unix, the config directory, the config file, the signers directory and its
selected files must be owned by the current user or root. Group and other
write permissions are rejected.

## Environment

- **SSH_AUTH_SOCK**: Path to the SSH agent socket used by **sign**.
- **SSH_SIGN_CONFIG_DIR**: Directory containing **config** and **signers/**.
  Defaults to **~/.ssh/sign** when unset or empty.
- **NO_COLOR**: Disable colored output when set to a nonempty value.

## Output

**verify** and **check** report the following fields.

- **authentication**: Whether the signer met the key or principal policy.
  Can be **valid**, **invalid** or **disabled**. **check -K** disables key
  authentication. A successful **verify** without **-p** reports
  **disabled** because no principal was requested.
- **designation**: Whether the signature met the namespace requirement.
  Can be **valid**, **invalid** or **disabled**. **-N** disables this check.
- **verification**: Whether the signature matches the data. Can be
  **valid** or **invalid**.
- **principal**: With **verify**, the identity requested by **-p**. Without
  **-p**, the pattern list from the matching entry or, for a
  **cert-authority** entry, the matching certificate principals separated by
  commas.
- **principals**: With **verify** in JSON, the matching certificate
  principals as a list when a **cert-authority** entry matched without
  **-p**. A certificate principal may itself contain a comma.
- **namespace**: With **verify**, the namespace in the signature. Use
  **inspect** to see the namespace when using **check**.
- **entry**: With **verify**, the matched allowed signers entry, shown as
  *file:line* in text and as an object with **file** and **line** in JSON.

Plain-text results go to stdout on success and errors go to stderr on failure.
On terminals, **valid** is green, **disabled** is yellow and errors are red.

In JSON mode, command data is written to stdout under **result**, and runtime
errors appear as an array of strings under **error**. Verification may
include both **result** and **error** when some checks complete and others
fail. **sign** puts its armored signature in **result.armored_signature**.
JSON output has no colors.

## Debug output

Debug output goes to stderr in both text and JSON modes.

- **-v**: Report the operation, agent connection, sandbox status, skipped
  allowed signers lines and the outcome of each check.
- **-vv**: Include input paths, the allowed signers counts and the agent key
  listing summary.
- **-vvv**: Include each allowed signers entry with its constraints and each
  key offered by the agent.

## Sandboxing

On Linux, **ssh-sign** uses Landlock once it has opened its inputs and, for
**sign**, connected to the agent. From then on it cannot open files, run
programs, use the network or connect to other Unix sockets. Files already
open remain usable.

The sandbox is best effort. Older kernels enforce fewer restrictions, and
without Landlock support the command runs unrestricted. Use **-v** to see the
effective Landlock ABI, or that Landlock is unavailable.

## Exit status

- **0**: The command succeeded or displayed help.
- **1**: A runtime error occurred, including failed verification.
- **2**: A usage error occurred. Diagnostics go to stderr even with **-j**.

## Examples

Sign a file with a key already available in the agent and inspect the result.

```sh
ssh-sign sign -k "$(cat key.pub)" -f data > data.sig
ssh-sign inspect -s data.sig
```

Verify the signature for a known principal and namespace, using a trusted
copy of the public key.

```sh
printf 'alice@example.com %s\n' "$(cat key.pub)" > allowed_signers
ssh-sign verify -a allowed_signers -p alice@example.com -n file \
    -f data -s data.sig
```

Check against a trusted public key directly and return JSON.

```sh
ssh-sign check -j -k "$(cat key.pub)" -f data -s data.sig
```

```json
{
  "result": {
    "authentication": "valid",
    "designation": "valid",
    "verification": "valid"
  }
}
```

Check entry and certificate validity at an explicit UTC time. The timestamp
sets the policy evaluation time and does not establish when the data was
signed.

```sh
ssh-sign verify -a allowed_signers -p alice@example.com -n file \
    -t 2026-01-15T12:00:00Z -f data < data.sig
```

## See also

[**ssh-sign-allowed-signers**(5)](ssh-sign-allowed-signers.5.md),
**ssh-add**(1), **ssh-agent**(1) and **ssh-keygen**(1).
