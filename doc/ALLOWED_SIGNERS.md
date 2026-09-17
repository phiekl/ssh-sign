<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# Allowed signers format

An allowed signers file lists trusted public keys, the identities they may sign
as, and any namespace or time restrictions. The format can be parsed by both
`ssh-sign verify -a <file>` and `ssh-keygen -Y verify -f <file>`.

This document describes the format supported by `ssh-sign`, including its
[differences from ssh-keygen](#differences-from-ssh-keygen).


## Line format

```
principals [options] keytype keyblob [comment...]
```

| parameter | required | description |
| --- | --- | --- |
| `principals` | true | a list of identity patterns, e.g. an email address |
| `options` | false | restrictions such as allowed namespaces or validity window |
| `keytype` | true | public key type, e.g. `ssh-ed25519` |
| `keyblob` | true | base64 encoded public key (`authorized_keys` format) |
| `comment` | false | descriptive text (ignored and not used) |

Blank lines are ignored. So are lines that start with `#` after any leading
spaces or tabs.

Malformed entries are skipped, so later entries can still match. Run
`ssh-sign -v verify` to see the recorded errors. Read failures and lines over
the [size limit](#limits) stop verification.

### Example

Without any options and without a comment:
```
alice@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIC5NiSRLYR8/cfe06a6pWHxNee5NHz7Vb++qYJS06uk
```
From here on, the keyblob will be abbreviated in the examples.

With a namespace configuration and a comment:
```
alice@example.com namespaces="git" ssh-ed25519 AAAAC3Nza... laptop
```

## Field separators

Separate fields with one or more spaces or tabs. Leading and trailing spaces
and tabs are ignored.

Other whitespace, such as a non-breaking space (U+00A0) or an em space
(U+2003), is part of the field. For example, `alice@example.com` with a
non-breaking space at the end does not match plain `alice@example.com`.

Lines must be valid UTF-8. Unicode letters, accents, numbers, punctuation,
symbols and spaces are allowed. Non-printable characters are rejected,
including C0/C1 controls, DEL, invisible formatting characters, Unicode line
and paragraph separators, and private-use or unassigned code points. This also
rejects zero-width joiners, including those used in some emoji sequences.

LF and CRLF line endings are accepted. A CR anywhere else is rejected.

## Principals

Principals are a comma-separated list of identity patterns. With `verify -p`,
the requested identity must match this list.

| syntax | meaning |
| --- | --- |
| `alice@example.com` | exact match |
| `*` | matches zero or more bytes |
| `?` | matches exactly one byte |
| `!pattern` | excludes matching identities, overriding any positive match in the list |
| `a,b` | matches either `a` or `b` |

Matching is case-sensitive and compares bytes, so `ALICE` does not match
`alice`. Empty list elements do not match any requested identity.

```
*@example.com,!bob@example.com ssh-ed25519 AAAAC3Nza...
```

### Quoting

Double quotes are only required to include spaces within a principal.

```
"alice smith,bob jones" ssh-ed25519 AAAAC3Nza...
```

This matches either `alice smith` or `bob jones`. Do not add spaces around the
comma unless they are part of the identities.

Neither `ssh-sign` nor `ssh-keygen` supports literal commas in principal
patterns. A comma always separates patterns, even inside quotes, and cannot be
escaped. For example, `"smith, alice"` means two patterns: `smith` and
` alice`. A wildcard such as `"smith? alice"` can match an identity containing
a comma, but also matches other identities; it is not an exact match.

Backslashes do not escape quotes in principals. The first quote opens the
quoted text and the next quote closes it. No text may follow the closing quote
within the field. These examples are rejected:

- `"alice",bob`: text follows the closing quote
- `"alice\"bob"`: no escaping, so the field ends at the second quote
- `"alice` and `alice"`: unterminated


## Options

Write options in one field, separated by commas without spaces between them.
Values must be quoted, and option names must be lowercase. Spaces are allowed
inside values: `namespaces="a b"` is valid, but `namespaces="a", "b"` is not.

| option | description |
| --- | --- |
| `namespaces="LIST"` | limits the signature namespaces accepted for this key |
| `valid-after="TIME"` | the entry applies from this time onwards, inclusive |
| `valid-before="TIME"` | the entry applies up to this time, inclusive |

```
alice@example.com namespaces="git,file",valid-after="20260101Z" ssh-ed25519 AAAAC3Nza...
```

The line is skipped if an option is repeated, an option is unsupported, or
`valid-before` is at or before `valid-after`. `cert-authority` is unsupported.

Namespace patterns use the same syntax as principal patterns. For example,
`namespaces="file-*,!file-secret"` allows names starting with `file-`, except
`file-secret`. `namespaces=""` matches no signature namespace.

Within an option value, `\"` represents a literal quote. Other backslashes are
kept as written. The closing quote must not be escaped.

### Timestamps

`valid-after` and `valid-before` use these date and time formats. Parts in
brackets are optional:

```
YYYYMMDD[Z]
YYYYMMDDHHMM[SS][Z]
```

Add `Z` to use UTC; otherwise the local time zone applies. Using `Z` gives the
same result across time zones.


## Key

The key type and base64-encoded key are separate fields, in `authorized_keys`
form. The type must match the encoded key. For example, a line with `ssh-rsa`
before an Ed25519 key is skipped.

To trust a certificate, give its type and encoded data. It must be a user
certificate valid at verification time. `ssh-sign` does not check its CA
signature or its own principals.


## Comment

Text after the key is ignored. Quotes, `=`, commas and backslashes have no
special meaning there. UTF-8 and character checks still apply to the whole
line, including comments.


## How an entry is selected

`verify` searches entries in file order. An entry must meet all these
conditions:

1. The entry's public key equals the signature's key.
2. If `-p` was given, the requested identity matches the principal list.
   Without `-p`, principal patterns are ignored.
3. The entry's `namespaces=` restriction, if any, permits the signature's
   namespace. `-N` skips this.
4. The verification time falls within the entry's validity window. Use `-t`
   to set this time; the default is the current time.

With `-n` or `-N`, the first matching entry is used. Without either flag, a
matching entry with a namespace restriction is required. It takes precedence
over entries without one, even if they appear earlier. See
[verify in the README](../README.md#verify) for details.


## Differences from ssh-keygen

`ssh-sign` rejects some entries that `ssh-keygen` accepts. These differences
are deliberate; accepting an entry that `ssh-keygen` rejects is not. Tests in
`interop_test.go` compare the two implementations.

| case | ssh-keygen | ssh-sign |
| --- | --- | --- |
| `NAMESPACES="git"` and other option names with uppercase letters | ignores case and applies the option | skips the line |
| a line containing a NUL byte | reads the line up to the NUL | skips the line |
| a line containing a stray carriage return | treats it as a separator in the principals field | skips the line |
| other non-printable characters or invalid UTF-8 | may accept them as literal bytes | skips the line |
| `cert-authority` | marks the key as a CA | skips the line, unsupported |

NUL bytes and stray carriage returns can change how fields are read. Other
non-printable characters can hide or distort an entry. `ssh-sign` skips these
lines while preserving ordinary Unicode identities and namespaces.


## Limits

A line may be up to 4 MiB. A longer line stops verification.

Errors are recorded for the first 64 skipped lines. Use `ssh-sign -v verify` to
see them, or `ssh-sign -vv verify` to also see the total number skipped.
