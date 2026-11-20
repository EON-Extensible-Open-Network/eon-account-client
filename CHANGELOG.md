<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Changelog

## 0.1.0 — 20 November 2026

The first version, against `eon-account-spec` v0 (plan madde 46).

- **Sign-up and sign-in** use OPAQUE with the suite
  `opaque-3dh-ristretto255-sha512-argon2id-v0`. Argon2id runs on the device with
  64 MiB, t = 3, p = 1.
- **Recovery and other account actions:**
  - password change;
  - recovery with the recovery key, which keeps the vault;
  - reset with a code sent to a verified e-mail address or phone, which starts a new vault.
- **Contacts:** add, verify and remove an e-mail address or phone number.
- **Sessions:** list them and end one.
- **The vault:**
  - entries are padded to 4 KiB and sealed under the vault key;
  - writes are versioned, so a stale write is refused;
  - `vault_sync` reads, merges and retries.
- **Assertions:** request one for another service, and check one with
  `assertion::verify`.
- **Export and deletion** of the account.
- **The `http` feature.** Turning it off leaves only the suite, the sealed box and
  assertion checking, for servers.
