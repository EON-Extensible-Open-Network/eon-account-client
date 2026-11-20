<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 EON contributors
-->

# Contributing to eon-account-client

The organisation-wide guide —
[`.github/CONTRIBUTING.md`](https://github.com/EON-Extensible-Open-Network/.github/blob/main/CONTRIBUTING.md)
— applies: Code of Conduct, DCO sign-off (`git commit -s`), Conventional Commits with the
`client` scope.

- **The cryptography follows the spec.** Change
  [eon-account-spec](https://github.com/EON-Extensible-Open-Network/eon-account-spec)
  first. A new constant means a new suite.
- **Justify every new dependency** where it is declared (madde 37).
- Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test`. Repeat
  the clippy run with `--no-default-features`.
- Contributions are licensed MIT.
