<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# TODO

- [ ] Config file support.
- [ ] sign: Support aliased pubkey references via config file.
- [ ] verify: Support a default allowed signers path via config file.
- [ ] verify: JSON output should include path to allowed signers file and line number etc.
- [ ] verify: Support allowed signers *directories*?
- [ ] verify: Support checking revoked keys.
- [ ] verify: Default -s to <file>.sig if stdin is a tty.
- [ ] verify: Specify custom fd's for file args?
- [ ] verify: JSON input?
- [ ] verify: Colorized output?
- [ ] verify: agent/daemon mode that could be run isolated?
- [ ] verify: Support `cert-authority` entries, currently a hard parse error.
- [ ] Report whether the process got sandboxed, in JSON output at least.
