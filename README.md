<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 EON contributors
-->

# eon-account-client

The Rust library every EON application links for **EON Account**: one account for all of
EON, built so the person reveals as little as possible
([eon-account-spec](https://github.com/EON-Extensible-Open-Network/eon-account-spec),
plan madde 46).

- **Sign-up and sign-in use OPAQUE** (RFC 9807, through
  [`opaque-ke`](https://crates.io/crates/opaque-ke)). The password never leaves this
  process, not even as a hash.
- **Encrypted vault.** Each vault entry is sealed on the device with XChaCha20-Poly1305
  under a key that only the person can unlock: either with the password or with a
  recovery key they are shown once. The server stores boxes it cannot open.
- **Assertions for other services.** [`assertion::verify`] lets a service, such as a
  community server, accept a signed-in person without ever seeing their password or
  session. The service learns a pseudonym of its own and, only if the person chose, the
  username.

```rust
use eon_account_client::Account;

let account = Account::open(&data_dir.join("account"));
account.set_server(Some("https://account.example.org"))?;
let recovery = account.register("deniz", "a long password", "EON Stream on Windows")?;
println!("Keep this somewhere safe: {}", recovery.display()); // shown once, never stored

account.vault_put("stream", "history", 0, br#"{"…":"…"}"#)?;
let merged = account.vault_sync("stream", "history", &local, |mine, theirs| merge(mine, theirs))?;
```

**Nothing is sent until the application sets a server address.** The project runs no
server until the plan's legal gate (madde 30) is met.

## On the device

`account.json` in the folder the application chooses holds the following:

- the server address;
- while someone is signed in, the session token and the vault key, sealed under a key
  derived from that token.

The file is as sensitive as a signed-in browser profile, and signing out deletes both.
The password and the recovery key are never written.

## Features

- **`http`** (default) is the account itself, over HTTPS with `ureq` and rustls.
- **Without it** (`default-features = false`) you get only the suite, the sealed box and
  assertion checking. That is what a server links.

## Build and test

```
cargo test        # the cryptography, the formats, and OPAQUE against an in-process server half
```

The whole contract is tested against the reference server in
[eon-account-server](https://github.com/EON-Extensible-Open-Network/eon-account-server).

Licence: [MIT](LICENSE). A library every application links should never raise a
licensing question.
