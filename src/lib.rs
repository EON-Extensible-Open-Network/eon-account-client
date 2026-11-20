// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 EON contributors

//! The EON Account client (`eon-account-spec` v0, plan madde 46).
//!
//! One [`Account`] per application, over a folder of its own. The password
//! never leaves this process: sign-up and sign-in are OPAQUE, and the key
//! that opens the vault is derived from what only the person knows. The
//! server stores the vault as sealed boxes it cannot open.
//!
//! Nothing here contacts anything until the application gives it a server
//! address; until madde 30's L1 gate no server is run by the project.

#![forbid(unsafe_code)]

#[cfg(feature = "http")]
mod account;
pub mod assertion;
pub mod crypto;
#[cfg(feature = "http")]
mod wire;

#[cfg(feature = "http")]
pub use account::{
    Account, Contact, Info, Me, PutOutcome, ResetTicket, Session, VaultEntry, DEVICE_MAX,
};
pub use crypto::RecoveryKey;

/// What can go wrong, by kind. Applications localise by [`Error::code`]; the
/// `Display` text is English and meant for a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The request was malformed or a value was refused (`invalid`).
    Invalid(String),
    /// The username, e-mail or phone is already someone's (`taken`).
    Taken,
    /// Wrong password, unknown login, or a session that has ended (`unauthorised`).
    Unauthorised,
    Forbidden,
    NotFound,
    /// The vault entry changed since it was read; this is its current version.
    Conflict(u64),
    TooLarge,
    RateLimited,
    /// The server does not accept new accounts.
    Closed,
    /// The server cannot do this (for example, it cannot send e-mail).
    Unavailable,
    /// No server address has been set.
    NoServer,
    NotSignedIn,
    /// The server could not be reached, or answered something that is not the API.
    Network(String),
    /// A cryptographic or format step failed.
    Protocol(String),
    /// The recovery key is not 32 base32 characters.
    BadRecoveryKey,
    /// The password is shorter than the spec's minimum.
    WeakPassword,
    Io(String),
}

impl Error {
    /// A stable code for an application's message catalogue.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid",
            Self::Taken => "taken",
            Self::Unauthorised => "unauthorised",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::Closed => "closed",
            Self::Unavailable => "unavailable",
            Self::NoServer => "no_server",
            Self::NotSignedIn => "not_signed_in",
            Self::Network(_) => "network",
            Self::Protocol(_) => "protocol",
            Self::BadRecoveryKey => "bad_recovery_key",
            Self::WeakPassword => "weak_password",
            Self::Io(_) => "io",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "refused: {m}"),
            Self::Conflict(v) => write!(f, "the entry changed (now version {v})"),
            Self::Network(m) => write!(f, "network: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::Io(m) => write!(f, "storage: {m}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for Error {}

/// The shortest password any EON client accepts (the server cannot check it).
pub const MIN_PASSWORD: usize = 10;

/// Lower-cases and checks a username against the spec's pattern.
pub fn normalise_username(raw: &str) -> Result<String, Error> {
    let name = raw.trim().to_lowercase();
    let ok = (3..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
    if ok {
        Ok(name)
    } else {
        Err(Error::Invalid("username".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_follow_the_spec() {
        assert_eq!(normalise_username(" Deniz.K ").as_deref(), Ok("deniz.k"));
        for bad in [
            "ab",
            "-abc",
            "abc_",
            "a b c",
            "çiçek",
            "x@y.z",
            &"a".repeat(33),
        ] {
            assert!(normalise_username(bad).is_err(), "{bad}");
        }
        assert!(normalise_username(&"a".repeat(32)).is_ok());
    }
}
