<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Security

Report vulnerabilities privately through GitHub's **Security → Report a vulnerability** on
this repository. The organisation-wide policy is
[`.github/SECURITY.md`](https://github.com/EON-Extensible-Open-Network/.github/blob/main/SECURITY.md).

## What this library has to get right

- **The password stays here.** OPAQUE sends blinded values only. CI fails on a password
  field in any request body.
- **A box opens in one place only.** Every sealed box names in its associated data what
  it is and whose it is. A box therefore cannot be moved into another entry, another
  account or another role without failing to open.
- **The recovery key is shown once and never written.** It is not printed by `Debug`.
- **The server address is HTTPS, or plain HTTP to this machine only.** Redirects are not
  followed.

## Known

- `opaque-ke` was audited by NCC Group in 2021. Version 4, the one used here, has not
  been audited since (plan madde 46, costs).
- The on-device `account.json` is protected only by the operating system's file
  permissions, like a browser profile. Anyone who can read it can use the session until
  it is signed out.
